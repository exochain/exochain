// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Escalation MCP tools — threat evaluation, case escalation, triage,
//! and feedback recording for the detection-to-response pipeline.

use exo_core::hash::hash_structured;
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MAX_ESCALATION_SIGNALS: usize = 256;
const MAX_ESCALATION_SIGNAL_TEXT_BYTES: usize = 256;
const MAX_ESCALATION_ID_BYTES: usize = 128;
const MAX_ESCALATION_ENUM_BYTES: usize = 16;
const MAX_ESCALATION_TEXT_BYTES: usize = 4096;

fn input_too_large_error(field: &str, max_bytes: usize) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_escalation_input_too_large",
            "message": format!("{field} may contain at most {max_bytes} bytes"),
            "field": field,
            "max_bytes": max_bytes,
        })
        .to_string(),
    )
}

fn too_many_items_error(field: &str, max_items: usize) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_escalation_too_many_items",
            "message": format!("{field} may contain at most {max_items} items"),
            "field": field,
            "max_items": max_items,
        })
        .to_string(),
    )
}

fn missing_required_error(field: &str) -> ToolResult {
    ToolResult::error(json!({"error": format!("missing required parameter: {field}")}).to_string())
}

fn invalid_string_error(field: &str) -> ToolResult {
    ToolResult::error(json!({"error": format!("{field} must be a string")}).to_string())
}

fn invalid_enum_error(field: &str, allowed: &[&str]) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_escalation_invalid_enum",
            "message": format!("{field} must be one of: {}", allowed.join(", ")),
            "field": field,
            "allowed": allowed,
        })
        .to_string(),
    )
}

fn validate_string_bytes(raw: &str, field: &str, max_bytes: usize) -> Result<(), ToolResult> {
    if raw.len() > max_bytes {
        return Err(input_too_large_error(field, max_bytes));
    }
    Ok(())
}

fn required_bounded_str<'a>(
    params: &'a Value,
    field: &str,
    max_bytes: usize,
) -> Result<&'a str, ToolResult> {
    let raw = match params.get(field) {
        Some(Value::String(raw)) => raw.as_str(),
        Some(_) => return Err(invalid_string_error(field)),
        None => return Err(missing_required_error(field)),
    };
    validate_string_bytes(raw, field, max_bytes)?;
    Ok(raw)
}

fn optional_bounded_str<'a>(
    params: &'a Value,
    field: &str,
    max_bytes: usize,
) -> Result<&'a str, ToolResult> {
    let Some(value) = params.get(field) else {
        return Ok("");
    };
    let Some(raw) = value.as_str() else {
        return Err(invalid_string_error(field));
    };
    validate_string_bytes(raw, field, max_bytes)?;
    Ok(raw)
}

fn escalation_runtime_unavailable(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP escalation tool: no live escalation store or response reactor is attached"
    );
    ToolResult::error(
        json!({
            "error": "mcp_escalation_runtime_unavailable",
            "tool": tool_name,
            "message": "This MCP escalation tool has no live escalation store \
                        or response reactor attached, so it cannot create \
                        cases, triage decisions, or record feedback. The \
                        `unaudited-mcp-simulation-tools` feature does not \
                        enable synthetic escalation writes.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": "Initiatives/fix-mcp-simulation-tools.md",
            "refusal_source": format!("exo-node/mcp/tools/escalation.rs::{tool_name}"),
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// exochain_evaluate_threat
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_evaluate_threat`.
#[must_use]
pub fn evaluate_threat_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_evaluate_threat".to_owned(),
        description: "Evaluate detection signals and produce an aggregate threat assessment with severity scoring.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "signals": {
                    "type": "array",
                    "maxItems": MAX_ESCALATION_SIGNALS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {
                                "type": "string",
                                "maxLength": MAX_ESCALATION_SIGNAL_TEXT_BYTES
                            },
                            "severity": { "type": "integer", "minimum": 0, "maximum": 10 },
                            "source": {
                                "type": "string",
                                "maxLength": MAX_ESCALATION_SIGNAL_TEXT_BYTES
                            }
                        }
                    },
                    "description": "Array of detection signals, each with type, integer severity (0-10), and source."
                }
            },
            "required": ["signals"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_evaluate_threat` tool.
///
/// Severity is treated as an integer on a 0-10 scale. Non-integer JSON
/// numbers are rejected — the workspace denies floating-point arithmetic,
/// so we keep all math in `i64` for determinism.
#[must_use]
pub fn execute_evaluate_threat(params: &Value, _context: &NodeContext) -> ToolResult {
    let signals = match params.get("signals").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: signals (must be an array)"})
                    .to_string(),
            );
        }
    };

    if signals.is_empty() {
        return ToolResult::error(
            json!({"error": "signals array must contain at least one signal"}).to_string(),
        );
    }
    if signals.len() > MAX_ESCALATION_SIGNALS {
        return too_many_items_error("signals", MAX_ESCALATION_SIGNALS);
    }

    // Validate and collect signals. Severity is 0-10 as an integer.
    let mut total_severity: i64 = 0;
    let mut max_severity: i64 = 0;
    let mut signal_summaries: Vec<Value> = Vec::with_capacity(signals.len());
    let mut signal_inputs: Vec<(String, i64, String)> = Vec::with_capacity(signals.len());

    for (i, signal) in signals.iter().enumerate() {
        let signal_type = match signal.get("type").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": format!("signal[{i}]: missing 'type' field")}).to_string(),
                );
            }
        };
        if let Err(result) = validate_string_bytes(
            signal_type,
            &format!("signals[{i}].type"),
            MAX_ESCALATION_SIGNAL_TEXT_BYTES,
        ) {
            return result;
        }
        let severity = match signal.get("severity").and_then(Value::as_i64) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": format!("signal[{i}]: missing or invalid 'severity' field (must be an integer 0-10)")})
                        .to_string(),
                );
            }
        };
        let source = match signal.get("source").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": format!("signal[{i}]: missing 'source' field")}).to_string(),
                );
            }
        };
        if let Err(result) = validate_string_bytes(
            source,
            &format!("signals[{i}].source"),
            MAX_ESCALATION_SIGNAL_TEXT_BYTES,
        ) {
            return result;
        }

        if !(0..=10).contains(&severity) {
            return ToolResult::error(
                json!({"error": format!("signal[{i}]: severity must be between 0 and 10")})
                    .to_string(),
            );
        }

        total_severity = total_severity.saturating_add(severity);
        if severity > max_severity {
            max_severity = severity;
        }
        signal_summaries.push(json!({
            "type": signal_type,
            "severity": severity,
            "source": source,
        }));
        signal_inputs.push((signal_type.to_owned(), severity, source.to_owned()));
    }

    // Integer average: truncated division is fine for a threat bucket.
    let signal_count = match i64::try_from(signals.len()) {
        Ok(count) => count,
        Err(_) => {
            return ToolResult::error(
                json!({"error": "signals array is too large to evaluate deterministically"})
                    .to_string(),
            );
        }
    };
    let avg_severity = total_severity / signal_count;

    // Aggregate threat level based on max and average severity.
    let threat_level = if max_severity >= 8 {
        "critical"
    } else if max_severity >= 6 || avg_severity >= 5 {
        "high"
    } else if max_severity >= 4 || avg_severity >= 3 {
        "medium"
    } else {
        "low"
    };

    let assessment_id = match hash_structured(&(
        "exo.mcp.escalation.threat.v1",
        &signal_inputs,
        avg_severity,
        max_severity,
        threat_level,
    )) {
        Ok(hash) => hash,
        Err(e) => {
            return ToolResult::error(
                json!({"error": format!("assessment ID serialization failed: {e}")}).to_string(),
            );
        }
    };

    let response = json!({
        "assessment_id": assessment_id.to_string(),
        "signal_count": signals.len(),
        "signals": signal_summaries,
        "aggregate_severity": avg_severity,
        "max_severity": max_severity,
        "threat_level": threat_level,
        "assessed_at": Value::Null,
        "assessed_at_source": "unavailable_no_escalation_store",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_escalate_case
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_escalate_case`.
#[must_use]
pub fn escalate_case_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_escalate_case".to_owned(),
        description:
            "Escalate a threat assessment to create a case for investigation and response."
                .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "threat_assessment_id": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_ID_BYTES,
                    "description": "ID of the threat assessment being escalated."
                },
                "escalation_reason": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_TEXT_BYTES,
                    "description": "Reason for escalation."
                },
                "priority": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_ENUM_BYTES,
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Priority level for the case."
                }
            },
            "required": ["threat_assessment_id", "escalation_reason", "priority"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_escalate_case` tool.
#[must_use]
pub fn execute_escalate_case(params: &Value, _context: &NodeContext) -> ToolResult {
    let _threat_assessment_id =
        match required_bounded_str(params, "threat_assessment_id", MAX_ESCALATION_ID_BYTES) {
            Ok(value) => value,
            Err(result) => return result,
        };
    let _escalation_reason =
        match required_bounded_str(params, "escalation_reason", MAX_ESCALATION_TEXT_BYTES) {
            Ok(value) => value,
            Err(result) => return result,
        };
    let priority = match required_bounded_str(params, "priority", MAX_ESCALATION_ENUM_BYTES) {
        Ok(value) => value,
        Err(result) => return result,
    };

    let valid_priorities = ["low", "medium", "high", "critical"];
    if !valid_priorities.contains(&priority) {
        return invalid_enum_error("priority", &valid_priorities);
    }

    escalation_runtime_unavailable("exochain_escalate_case")
}

// ---------------------------------------------------------------------------
// exochain_triage
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_triage`.
#[must_use]
pub fn triage_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_triage".to_owned(),
        description:
            "Triage a threat assessment to produce a response decision with recommended actions."
                .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_ID_BYTES,
                    "description": "ID of the case to triage."
                },
                "assessment": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_TEXT_BYTES,
                    "description": "Analyst assessment of the case."
                },
                "recommended_action": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_TEXT_BYTES,
                    "description": "Recommended response action."
                }
            },
            "required": ["case_id", "assessment", "recommended_action"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_triage` tool.
#[must_use]
pub fn execute_triage(params: &Value, _context: &NodeContext) -> ToolResult {
    let _case_id = match required_bounded_str(params, "case_id", MAX_ESCALATION_ID_BYTES) {
        Ok(value) => value,
        Err(result) => return result,
    };
    let _assessment = match required_bounded_str(params, "assessment", MAX_ESCALATION_TEXT_BYTES) {
        Ok(value) => value,
        Err(result) => return result,
    };
    let _recommended_action =
        match required_bounded_str(params, "recommended_action", MAX_ESCALATION_TEXT_BYTES) {
            Ok(value) => value,
            Err(result) => return result,
        };

    escalation_runtime_unavailable("exochain_triage")
}

// ---------------------------------------------------------------------------
// exochain_record_feedback
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_record_feedback`.
#[must_use]
pub fn record_feedback_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_record_feedback".to_owned(),
        description: "Record feedback on an escalation case outcome for the learning loop."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_ID_BYTES,
                    "description": "ID of the case to record feedback for."
                },
                "outcome": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_ENUM_BYTES,
                    "enum": ["true_positive", "false_positive", "inconclusive"],
                    "description": "Outcome classification of the case."
                },
                "notes": {
                    "type": "string",
                    "maxLength": MAX_ESCALATION_TEXT_BYTES,
                    "description": "Optional analyst notes."
                }
            },
            "required": ["case_id", "outcome"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_record_feedback` tool.
#[must_use]
pub fn execute_record_feedback(params: &Value, _context: &NodeContext) -> ToolResult {
    let _case_id = match required_bounded_str(params, "case_id", MAX_ESCALATION_ID_BYTES) {
        Ok(value) => value,
        Err(result) => return result,
    };
    let outcome = match required_bounded_str(params, "outcome", MAX_ESCALATION_ENUM_BYTES) {
        Ok(value) => value,
        Err(result) => return result,
    };

    let valid_outcomes = ["true_positive", "false_positive", "inconclusive"];
    if !valid_outcomes.contains(&outcome) {
        return invalid_enum_error("outcome", &valid_outcomes);
    }

    let _notes = match optional_bounded_str(params, "notes", MAX_ESCALATION_TEXT_BYTES) {
        Ok(value) => value,
        Err(result) => return result,
    };

    escalation_runtime_unavailable("exochain_record_feedback")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn assert_escalation_runtime_unavailable(result: &ToolResult, tool_name: &str) {
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(
            text.contains("mcp_escalation_runtime_unavailable"),
            "refusal body must carry escalation runtime error tag, got: {text}"
        );
        assert!(
            text.contains(tool_name),
            "refusal body must name the specific tool, got: {text}"
        );
        assert!(
            text.contains("unaudited-mcp-simulation-tools"),
            "refusal body must name the simulation feature flag, got: {text}"
        );
    }

    // -- evaluate_threat ------------------------------------------------------

    #[test]
    fn evaluate_threat_definition_valid() {
        let def = evaluate_threat_definition();
        assert_eq!(def.name, "exochain_evaluate_threat");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_evaluate_threat_success() {
        let params = json!({
            "signals": [
                {"type": "anomaly", "severity": 7, "source": "ids"},
                {"type": "policy_violation", "severity": 3, "source": "audit_log"},
            ],
        });
        let result = execute_evaluate_threat(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["signal_count"], 2);
        assert_eq!(v["max_severity"], 7);
        assert_eq!(v["threat_level"], "high");
        assert!(v["assessment_id"].as_str().is_some());
        assert!(v["assessed_at"].is_null());
    }

    #[test]
    fn execute_evaluate_threat_critical() {
        let params = json!({
            "signals": [
                {"type": "breach", "severity": 9, "source": "firewall"},
            ],
        });
        let result = execute_evaluate_threat(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["threat_level"], "critical");
    }

    #[test]
    fn execute_evaluate_threat_is_deterministic() {
        let params = json!({
            "signals": [
                {"type": "anomaly", "severity": 7, "source": "ids"},
                {"type": "policy_violation", "severity": 3, "source": "audit_log"},
            ],
        });
        let first = execute_evaluate_threat(&params, &NodeContext::empty());
        let second = execute_evaluate_threat(&params, &NodeContext::empty());
        assert!(!first.is_error);
        assert!(!second.is_error);
        let first_json: Value = serde_json::from_str(first.content[0].text()).expect("valid JSON");
        let second_json: Value =
            serde_json::from_str(second.content[0].text()).expect("valid JSON");
        assert_eq!(first_json["assessment_id"], second_json["assessment_id"]);
        assert_eq!(first_json["assessed_at"], second_json["assessed_at"]);
    }

    #[test]
    fn execute_evaluate_threat_empty_signals() {
        let result = execute_evaluate_threat(&json!({"signals": []}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_evaluate_threat_missing_signals() {
        let result = execute_evaluate_threat(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn evaluate_threat_definition_bounds_untrusted_signal_input() {
        let def = evaluate_threat_definition();
        let signals = &def.input_schema["properties"]["signals"];
        assert_eq!(signals["maxItems"], 256);
        assert_eq!(signals["items"]["properties"]["type"]["maxLength"], 256);
        assert_eq!(signals["items"]["properties"]["source"]["maxLength"], 256);
    }

    #[test]
    fn execute_evaluate_threat_rejects_oversized_signal_array() {
        let signals: Vec<Value> = (0..257)
            .map(|idx| {
                json!({
                    "type": format!("signal-{idx}"),
                    "severity": 1,
                    "source": "detector",
                })
            })
            .collect();

        let result = execute_evaluate_threat(&json!({"signals": signals}), &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("signals may contain at most"));
    }

    #[test]
    fn execute_evaluate_threat_rejects_oversized_signal_text_without_echoing_it() {
        let oversized = "A".repeat(257);
        let result = execute_evaluate_threat(
            &json!({
                "signals": [
                    {"type": oversized, "severity": 1, "source": "detector"},
                ],
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("signals[0].type may contain at most"));
        assert!(
            !text.contains("AAAA"),
            "oversized signal text must not be reflected in the error response"
        );
    }

    // -- escalate_case --------------------------------------------------------

    #[test]
    fn escalate_case_definition_valid() {
        let def = escalate_case_definition();
        assert_eq!(def.name, "exochain_escalate_case");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn escalate_case_definition_bounds_untrusted_strings() {
        let def = escalate_case_definition();
        let properties = &def.input_schema["properties"];
        assert_eq!(properties["threat_assessment_id"]["maxLength"], 128);
        assert_eq!(properties["escalation_reason"]["maxLength"], 4096);
        assert_eq!(properties["priority"]["maxLength"], 16);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_escalate_case_refuses_without_escalation_runtime_even_with_simulation_feature() {
        let params = json!({
            "threat_assessment_id": "ta_abc123",
            "escalation_reason": "Multiple high-severity signals detected",
            "priority": "high",
        });
        let result = execute_escalate_case(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_escalate_case");
        let text = result.content[0].text();
        assert!(!text.contains("case_id"));
        assert!(!text.contains("\"status\""));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_escalate_case_refuses_without_escalation_runtime_by_default() {
        let params = json!({
            "threat_assessment_id": "ta_abc123",
            "escalation_reason": "Multiple high-severity signals detected",
            "priority": "high",
        });
        let result = execute_escalate_case(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_escalate_case");
        let text = result.content[0].text();
        assert!(text.contains("fix-mcp-simulation-tools.md"));
        assert!(!text.contains("case_id"));
        assert!(!text.contains("\"status\""));
    }

    #[test]
    fn execute_escalate_case_invalid_priority() {
        let params = json!({
            "threat_assessment_id": "ta_abc",
            "escalation_reason": "test",
            "priority": "urgent",
        });
        let result = execute_escalate_case(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_escalate_case_rejects_oversized_reason_without_echoing_it() {
        let oversized = "B".repeat(4097);
        let result = execute_escalate_case(
            &json!({
                "threat_assessment_id": "ta_abc",
                "escalation_reason": oversized,
                "priority": "high",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("escalation_reason may contain at most"));
        assert!(
            !text.contains("BBBB"),
            "oversized escalation reason must not be reflected in the error response"
        );
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_escalate_case_invalid_priority_does_not_echo_input() {
        let result = execute_escalate_case(
            &json!({
                "threat_assessment_id": "ta_abc",
                "escalation_reason": "test",
                "priority": "urgent<script>",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("priority must be one of"));
        assert!(
            !text.contains("<script>"),
            "invalid priority must not be reflected in the error response"
        );
    }

    #[test]
    fn execute_escalate_case_missing_reason() {
        let result = execute_escalate_case(
            &json!({"threat_assessment_id": "ta_abc", "priority": "high"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- triage ---------------------------------------------------------------

    #[test]
    fn triage_definition_valid() {
        let def = triage_definition();
        assert_eq!(def.name, "exochain_triage");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn triage_definition_bounds_untrusted_strings() {
        let def = triage_definition();
        let properties = &def.input_schema["properties"];
        assert_eq!(properties["case_id"]["maxLength"], 128);
        assert_eq!(properties["assessment"]["maxLength"], 4096);
        assert_eq!(properties["recommended_action"]["maxLength"], 4096);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_triage_refuses_without_escalation_runtime_even_with_simulation_feature() {
        let params = json!({
            "case_id": "case_abc",
            "assessment": "Confirmed unauthorized access attempt",
            "recommended_action": "block_source_ip",
        });
        let result = execute_triage(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_triage");
        let text = result.content[0].text();
        assert!(!text.contains("triage_id"));
        assert!(!text.contains("action_approved"));
        assert!(!text.contains("\"status\""));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_triage_refuses_without_escalation_runtime_by_default() {
        let params = json!({
            "case_id": "case_abc",
            "assessment": "Confirmed unauthorized access attempt",
            "recommended_action": "block_source_ip",
        });
        let result = execute_triage(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_triage");
        let text = result.content[0].text();
        assert!(text.contains("fix-mcp-simulation-tools.md"));
        assert!(!text.contains("triage_id"));
        assert!(!text.contains("action_approved"));
        assert!(!text.contains("\"status\""));
    }

    #[test]
    fn execute_triage_missing_case_id() {
        let result = execute_triage(
            &json!({"assessment": "test", "recommended_action": "block"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_triage_rejects_oversized_assessment_without_echoing_it() {
        let oversized = "C".repeat(4097);
        let result = execute_triage(
            &json!({
                "case_id": "case_abc",
                "assessment": oversized,
                "recommended_action": "block_source_ip",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("assessment may contain at most"));
        assert!(
            !text.contains("CCCC"),
            "oversized assessment must not be reflected in the error response"
        );
    }

    // -- record_feedback ------------------------------------------------------

    #[test]
    fn record_feedback_definition_valid() {
        let def = record_feedback_definition();
        assert_eq!(def.name, "exochain_record_feedback");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn record_feedback_definition_bounds_untrusted_strings() {
        let def = record_feedback_definition();
        let properties = &def.input_schema["properties"];
        assert_eq!(properties["case_id"]["maxLength"], 128);
        assert_eq!(properties["outcome"]["maxLength"], 16);
        assert_eq!(properties["notes"]["maxLength"], 4096);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_record_feedback_refuses_without_escalation_runtime_even_with_simulation_feature() {
        let params = json!({
            "case_id": "case_abc",
            "outcome": "true_positive",
            "notes": "Confirmed breach via log analysis",
        });
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_record_feedback");
        let text = result.content[0].text();
        assert!(!text.contains("feedback_id"));
        assert!(!text.contains("\"status\""));
        assert!(!text.contains("\"recorded\""));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_record_feedback_refuses_without_escalation_runtime_by_default() {
        let params = json!({
            "case_id": "case_abc",
            "outcome": "true_positive",
            "notes": "Confirmed breach via log analysis",
        });
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_record_feedback");
        let text = result.content[0].text();
        assert!(text.contains("fix-mcp-simulation-tools.md"));
        assert!(!text.contains("feedback_id"));
        assert!(!text.contains("\"status\""));
        assert!(!text.contains("\"recorded\""));
    }

    #[test]
    fn execute_record_feedback_invalid_outcome() {
        let params = json!({"case_id": "case_abc", "outcome": "maybe"});
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_record_feedback_invalid_outcome_does_not_echo_input() {
        let params = json!({"case_id": "case_abc", "outcome": "maybe<script>"});
        let result = execute_record_feedback(&params, &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("outcome must be one of"));
        assert!(
            !text.contains("<script>"),
            "invalid outcome must not be reflected in the error response"
        );
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_record_feedback_rejects_oversized_notes_without_echoing_it() {
        let oversized = "D".repeat(4097);
        let result = execute_record_feedback(
            &json!({
                "case_id": "case_abc",
                "outcome": "true_positive",
                "notes": oversized,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("notes may contain at most"));
        assert!(
            !text.contains("DDDD"),
            "oversized feedback notes must not be reflected in the error response"
        );
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_record_feedback_no_notes_still_refuses_without_escalation_runtime() {
        let params = json!({"case_id": "case_abc", "outcome": "false_positive"});
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert_escalation_runtime_unavailable(&result, "exochain_record_feedback");
        let text = result.content[0].text();
        assert!(!text.contains("\"notes\""));
    }
}
