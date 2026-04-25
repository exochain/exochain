//! Escalation MCP tools — threat evaluation, case escalation, triage,
//! and feedback recording for the detection-to-response pipeline.

use exo_core::{Hash256, Timestamp};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

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
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": { "type": "string" },
                            "severity": { "type": "integer", "minimum": 0, "maximum": 10 },
                            "source": { "type": "string" }
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

    // Validate and collect signals. Severity is 0-10 as an integer.
    let mut total_severity: i64 = 0;
    let mut max_severity: i64 = 0;
    let mut signal_summaries: Vec<Value> = Vec::new();

    for (i, signal) in signals.iter().enumerate() {
        let signal_type = match signal.get("type").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": format!("signal[{i}]: missing 'type' field")}).to_string(),
                );
            }
        };
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
    }

    // Integer average: truncated division is fine for a threat bucket.
    let signal_count = signals.len() as i64;
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

    let now = Timestamp::now_utc();
    let assessment_id = Hash256::digest(
        format!(
            "threat:{}:{}:{}:{}",
            signals.len(),
            max_severity,
            now.physical_ms,
            now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "assessment_id": assessment_id.to_string(),
        "signal_count": signals.len(),
        "signals": signal_summaries,
        "aggregate_severity": avg_severity,
        "max_severity": max_severity,
        "threat_level": threat_level,
        "assessed_at": format!("{}:{}", now.physical_ms, now.logical),
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
                    "description": "ID of the threat assessment being escalated."
                },
                "escalation_reason": {
                    "type": "string",
                    "description": "Reason for escalation."
                },
                "priority": {
                    "type": "string",
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
    let threat_assessment_id = match params.get("threat_assessment_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: threat_assessment_id"}).to_string(),
            );
        }
    };
    let escalation_reason = match params.get("escalation_reason").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: escalation_reason"}).to_string(),
            );
        }
    };
    let priority = match params.get("priority").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: priority"}).to_string(),
            );
        }
    };

    let valid_priorities = ["low", "medium", "high", "critical"];
    if !valid_priorities.contains(&priority) {
        return ToolResult::error(
            json!({"error": format!(
                "invalid priority '{}': must be one of {:?}",
                priority, valid_priorities
            )})
            .to_string(),
        );
    }

    let now = Timestamp::now_utc();
    let case_id = Hash256::digest(
        format!(
            "case:{}:{}:{}:{}",
            threat_assessment_id, priority, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "case_id": case_id.to_string(),
        "threat_assessment_id": threat_assessment_id,
        "escalation_reason": escalation_reason,
        "priority": priority,
        "status": "open",
        "escalated_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
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
                    "description": "ID of the case to triage."
                },
                "assessment": {
                    "type": "string",
                    "description": "Analyst assessment of the case."
                },
                "recommended_action": {
                    "type": "string",
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
    let case_id = match params.get("case_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: case_id"}).to_string(),
            );
        }
    };
    let assessment = match params.get("assessment").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: assessment"}).to_string(),
            );
        }
    };
    let recommended_action = match params.get("recommended_action").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: recommended_action"}).to_string(),
            );
        }
    };

    let now = Timestamp::now_utc();
    let triage_id = Hash256::digest(
        format!(
            "triage:{}:{}:{}:{}",
            case_id, recommended_action, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "triage_id": triage_id.to_string(),
        "case_id": case_id,
        "assessment": assessment,
        "recommended_action": recommended_action,
        "decision": "action_approved",
        "status": "triaged",
        "triaged_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
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
                    "description": "ID of the case to record feedback for."
                },
                "outcome": {
                    "type": "string",
                    "enum": ["true_positive", "false_positive", "inconclusive"],
                    "description": "Outcome classification of the case."
                },
                "notes": {
                    "type": "string",
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
    let case_id = match params.get("case_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: case_id"}).to_string(),
            );
        }
    };
    let outcome = match params.get("outcome").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: outcome"}).to_string(),
            );
        }
    };

    let valid_outcomes = ["true_positive", "false_positive", "inconclusive"];
    if !valid_outcomes.contains(&outcome) {
        return ToolResult::error(
            json!({"error": format!(
                "invalid outcome '{}': must be one of {:?}",
                outcome, valid_outcomes
            )})
            .to_string(),
        );
    }

    let notes = params.get("notes").and_then(Value::as_str).unwrap_or("");

    let now = Timestamp::now_utc();
    let feedback_id = Hash256::digest(
        format!(
            "feedback:{}:{}:{}:{}",
            case_id, outcome, now.physical_ms, now.logical
        )
        .as_bytes(),
    );

    let response = json!({
        "feedback_id": feedback_id.to_string(),
        "case_id": case_id,
        "outcome": outcome,
        "notes": notes,
        "status": "recorded",
        "recorded_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
    fn execute_evaluate_threat_empty_signals() {
        let result = execute_evaluate_threat(&json!({"signals": []}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_evaluate_threat_missing_signals() {
        let result = execute_evaluate_threat(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- escalate_case --------------------------------------------------------

    #[test]
    fn escalate_case_definition_valid() {
        let def = escalate_case_definition();
        assert_eq!(def.name, "exochain_escalate_case");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_escalate_case_success() {
        let params = json!({
            "threat_assessment_id": "ta_abc123",
            "escalation_reason": "Multiple high-severity signals detected",
            "priority": "high",
        });
        let result = execute_escalate_case(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["priority"], "high");
        assert_eq!(v["status"], "open");
        assert!(v["case_id"].as_str().is_some());
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
    fn execute_triage_success() {
        let params = json!({
            "case_id": "case_abc",
            "assessment": "Confirmed unauthorized access attempt",
            "recommended_action": "block_source_ip",
        });
        let result = execute_triage(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["case_id"], "case_abc");
        assert_eq!(v["decision"], "action_approved");
        assert_eq!(v["status"], "triaged");
        assert!(v["triage_id"].as_str().is_some());
    }

    #[test]
    fn execute_triage_missing_case_id() {
        let result = execute_triage(
            &json!({"assessment": "test", "recommended_action": "block"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- record_feedback ------------------------------------------------------

    #[test]
    fn record_feedback_definition_valid() {
        let def = record_feedback_definition();
        assert_eq!(def.name, "exochain_record_feedback");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_record_feedback_success() {
        let params = json!({
            "case_id": "case_abc",
            "outcome": "true_positive",
            "notes": "Confirmed breach via log analysis",
        });
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["outcome"], "true_positive");
        assert_eq!(v["status"], "recorded");
        assert!(v["feedback_id"].as_str().is_some());
    }

    #[test]
    fn execute_record_feedback_invalid_outcome() {
        let params = json!({"case_id": "case_abc", "outcome": "maybe"});
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_record_feedback_no_notes() {
        let params = json!({"case_id": "case_abc", "outcome": "false_positive"});
        let result = execute_record_feedback(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["notes"], "");
    }
}
