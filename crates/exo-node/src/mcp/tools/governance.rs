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

//! Governance MCP tools — decision creation, voting, quorum checking, decision
//! status, and constitutional amendment proposals.
//!
//! # Fail-closed governance runtime boundary
//!
//! These MCP tools are not wired to a live governance store or reactor. They
//! validate request shape where useful, then fail closed for all builds. The
//! `unaudited-mcp-simulation-tools` feature does not enable fabricated
//! governance writes or reads.

use exo_core::Did;
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MAX_GOVERNANCE_MCP_TITLE_BYTES: usize = 512;
const MAX_GOVERNANCE_MCP_DESCRIPTION_BYTES: usize = 16 * 1024;
const MAX_GOVERNANCE_MCP_RATIONALE_BYTES: usize = 4 * 1024;
const MAX_GOVERNANCE_MCP_ID_BYTES: usize = 256;
const MAX_GOVERNANCE_MCP_DID_BYTES: usize = 512;

fn input_too_large_error(field: &str, max_bytes: usize) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_governance_input_too_large",
            "field": field,
            "max_bytes": max_bytes,
        })
        .to_string(),
    )
}

fn validate_string_bytes(value: &str, field: &str, max_bytes: usize) -> Result<(), ToolResult> {
    if value.len() > max_bytes {
        return Err(input_too_large_error(field, max_bytes));
    }
    Ok(())
}

fn invalid_parameter_error(field: &str, message: &str) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_governance_invalid_parameter",
            "field": field,
            "message": message,
        })
        .to_string(),
    )
}

fn governance_runtime_unavailable(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP governance tool: no live governance store or reactor is attached"
    );
    ToolResult::error(
        json!({
            "error": "mcp_governance_runtime_unavailable",
            "tool": tool_name,
            "message": "This MCP governance tool has no live governance store \
                        or reactor attached, so it cannot create decisions, \
                        record votes, check quorum, query status, or propose \
                        amendments. The `unaudited-mcp-simulation-tools` \
                        feature does not enable synthetic governance writes \
                        or fabricated governance reads.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": "Initiatives/fix-mcp-simulation-tools.md",
            "refusal_source": format!("exo-node/mcp/tools/governance.rs::{tool_name}"),
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// exochain_create_decision
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_create_decision`.
#[must_use]
pub fn create_decision_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_create_decision".to_owned(),
        description: "Create a new governance decision with BCTS lifecycle. Decisions start in 'Proposed' state and proceed through deliberation to resolution.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_TITLE_BYTES,
                    "description": "Title of the governance decision."
                },
                "description": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_DESCRIPTION_BYTES,
                    "description": "Detailed description of the decision."
                },
                "proposer_did": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_DID_BYTES,
                    "description": "DID of the proposer."
                },
                "decision_class": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_ID_BYTES,
                    "description": "Classification of the decision (default: standard)."
                }
            },
            "required": ["title", "description", "proposer_did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_create_decision` tool.
#[must_use]
pub fn execute_create_decision(params: &Value, _context: &NodeContext) -> ToolResult {
    let title = match params.get("title").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: title"}).to_string(),
            );
        }
    };
    let description = match params.get("description").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: description"}).to_string(),
            );
        }
    };
    let proposer_str = match params.get("proposer_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: proposer_did"}).to_string(),
            );
        }
    };

    if let Err(result) = validate_string_bytes(title, "title", MAX_GOVERNANCE_MCP_TITLE_BYTES) {
        return result;
    }
    if let Err(result) = validate_string_bytes(
        description,
        "description",
        MAX_GOVERNANCE_MCP_DESCRIPTION_BYTES,
    ) {
        return result;
    }
    if let Err(result) =
        validate_string_bytes(proposer_str, "proposer_did", MAX_GOVERNANCE_MCP_DID_BYTES)
    {
        return result;
    }

    if Did::new(proposer_str).is_err() {
        return invalid_parameter_error("proposer_did", "must be a syntactically valid EXO DID");
    }

    let decision_class = params
        .get("decision_class")
        .and_then(Value::as_str)
        .unwrap_or("standard");
    if let Err(result) = validate_string_bytes(
        decision_class,
        "decision_class",
        MAX_GOVERNANCE_MCP_ID_BYTES,
    ) {
        return result;
    }

    governance_runtime_unavailable("exochain_create_decision")
}

// ---------------------------------------------------------------------------
// exochain_cast_vote
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_cast_vote`.
#[must_use]
pub fn cast_vote_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_cast_vote".to_owned(),
        description: "Cast a vote on a governance decision. Votes are constitutionally verified \u{2014} synthetic votes cannot count as human votes per CR-001 \u{00a7}8.3.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "decision_id": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_ID_BYTES,
                    "description": "The ID of the decision to vote on."
                },
                "voter_did": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_DID_BYTES,
                    "description": "DID of the voter."
                },
                "choice": {
                    "type": "string",
                    "enum": ["approve", "reject", "abstain"],
                    "description": "Vote choice."
                },
                "rationale": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_RATIONALE_BYTES,
                    "description": "Optional rationale for the vote."
                }
            },
            "required": ["decision_id", "voter_did", "choice"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_cast_vote` tool.
#[must_use]
pub fn execute_cast_vote(params: &Value, _context: &NodeContext) -> ToolResult {
    let decision_id = match params.get("decision_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: decision_id"}).to_string(),
            );
        }
    };
    let voter_str = match params.get("voter_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: voter_did"}).to_string(),
            );
        }
    };
    let choice = match params.get("choice").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: choice"}).to_string(),
            );
        }
    };

    if let Err(result) =
        validate_string_bytes(decision_id, "decision_id", MAX_GOVERNANCE_MCP_ID_BYTES)
    {
        return result;
    }
    if let Err(result) = validate_string_bytes(voter_str, "voter_did", MAX_GOVERNANCE_MCP_DID_BYTES)
    {
        return result;
    }

    if Did::new(voter_str).is_err() {
        return invalid_parameter_error("voter_did", "must be a syntactically valid EXO DID");
    }

    let valid_choices = ["approve", "reject", "abstain"];
    if !valid_choices.contains(&choice) {
        return invalid_parameter_error("choice", "must be approve, reject, or abstain");
    }

    if decision_id.is_empty() {
        return ToolResult::error(json!({"error": "decision_id must not be empty"}).to_string());
    }

    let rationale = params
        .get("rationale")
        .and_then(Value::as_str)
        .unwrap_or("");
    if let Err(result) =
        validate_string_bytes(rationale, "rationale", MAX_GOVERNANCE_MCP_RATIONALE_BYTES)
    {
        return result;
    }

    governance_runtime_unavailable("exochain_cast_vote")
}

// ---------------------------------------------------------------------------
// exochain_check_quorum
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_check_quorum`.
#[must_use]
pub fn check_quorum_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_check_quorum".to_owned(),
        description: "Check whether a governance decision has reached quorum. Applies CR-001 \u{00a7}8.3 synthetic voice exclusion.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "decision_id": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_ID_BYTES,
                    "description": "The ID of the decision to check."
                },
                "threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Required number of authentic approvals for quorum."
                }
            },
            "required": ["decision_id", "threshold"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_check_quorum` tool.
#[must_use]
pub fn execute_check_quorum(params: &Value, _context: &NodeContext) -> ToolResult {
    let decision_id = match params.get("decision_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: decision_id"}).to_string(),
            );
        }
    };
    let threshold = match params.get("threshold").and_then(Value::as_u64) {
        Some(n) => n,
        None => {
            return ToolResult::error(
                json!({"error": "missing or invalid required parameter: threshold (must be a positive integer)"}).to_string(),
            );
        }
    };

    if let Err(result) =
        validate_string_bytes(decision_id, "decision_id", MAX_GOVERNANCE_MCP_ID_BYTES)
    {
        return result;
    }

    if decision_id.is_empty() {
        return ToolResult::error(json!({"error": "decision_id must not be empty"}).to_string());
    }
    if threshold == 0 {
        return invalid_parameter_error("threshold", "must be a positive integer");
    }

    governance_runtime_unavailable("exochain_check_quorum")
}

// ---------------------------------------------------------------------------
// exochain_get_decision_status
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_get_decision_status`.
#[must_use]
pub fn get_decision_status_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_get_decision_status".to_owned(),
        description: "Get the current status of a governance decision including vote tally, deliberation state, and challenge status.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "decision_id": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_ID_BYTES,
                    "description": "The ID of the decision."
                }
            },
            "required": ["decision_id"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_get_decision_status` tool.
#[must_use]
pub fn execute_get_decision_status(params: &Value, _context: &NodeContext) -> ToolResult {
    let decision_id = match params.get("decision_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: decision_id"}).to_string(),
            );
        }
    };

    if let Err(result) =
        validate_string_bytes(decision_id, "decision_id", MAX_GOVERNANCE_MCP_ID_BYTES)
    {
        return result;
    }

    if decision_id.is_empty() {
        return ToolResult::error(json!({"error": "decision_id must not be empty"}).to_string());
    }

    governance_runtime_unavailable("exochain_get_decision_status")
}

// ---------------------------------------------------------------------------
// exochain_propose_amendment
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_propose_amendment`.
#[must_use]
pub fn propose_amendment_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_propose_amendment".to_owned(),
        description: "Propose a constitutional amendment. This is the most consequential governance action \u{2014} amendments to the CGR Kernel require unanimous validator consent and supermajority AI-IRB approval.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_TITLE_BYTES,
                    "description": "Title of the proposed amendment."
                },
                "description": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_DESCRIPTION_BYTES,
                    "description": "Full description of the proposed amendment."
                },
                "proposer_did": {
                    "type": "string",
                    "maxLength": MAX_GOVERNANCE_MCP_DID_BYTES,
                    "description": "DID of the proposer."
                },
                "target": {
                    "type": "string",
                    "enum": ["constitution", "invariant_registry", "kernel_binary"],
                    "description": "What the amendment targets."
                }
            },
            "required": ["title", "description", "proposer_did", "target"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_propose_amendment` tool.
#[must_use]
pub fn execute_propose_amendment(params: &Value, _context: &NodeContext) -> ToolResult {
    let title = match params.get("title").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: title"}).to_string(),
            );
        }
    };
    let description = match params.get("description").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: description"}).to_string(),
            );
        }
    };
    let proposer_str = match params.get("proposer_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: proposer_did"}).to_string(),
            );
        }
    };
    let target = match params.get("target").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: target"}).to_string(),
            );
        }
    };

    if let Err(result) = validate_string_bytes(title, "title", MAX_GOVERNANCE_MCP_TITLE_BYTES) {
        return result;
    }
    if let Err(result) = validate_string_bytes(
        description,
        "description",
        MAX_GOVERNANCE_MCP_DESCRIPTION_BYTES,
    ) {
        return result;
    }
    if let Err(result) =
        validate_string_bytes(proposer_str, "proposer_did", MAX_GOVERNANCE_MCP_DID_BYTES)
    {
        return result;
    }

    if Did::new(proposer_str).is_err() {
        return invalid_parameter_error("proposer_did", "must be a syntactically valid EXO DID");
    }

    let valid_targets = ["constitution", "invariant_registry", "kernel_binary"];
    if !valid_targets.contains(&target) {
        return invalid_parameter_error(
            "target",
            "must be constitution, invariant_registry, or kernel_binary",
        );
    }

    governance_runtime_unavailable("exochain_propose_amendment")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_governance_runtime_unavailable(result: &ToolResult, tool_name: &str) {
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(
            text.contains("mcp_governance_runtime_unavailable"),
            "refusal body must carry governance runtime error tag, got: {text}"
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

    // -- create_decision ---------------------------------------------------

    #[test]
    fn create_decision_definition_valid() {
        let def = create_decision_definition();
        assert_eq!(def.name, "exochain_create_decision");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_create_decision_refuses_without_governance_runtime_even_with_simulation_feature() {
        let params = json!({
                "title": "Approve data sharing policy",
                "description": "Allow cross-org medical data sharing under bailment.",
                "proposer_did": "did:exo:alice",
        });
        let result = execute_create_decision(&params, &NodeContext::empty());
        assert_governance_runtime_unavailable(&result, "exochain_create_decision");
        let text = result.content[0].text();
        assert!(!text.contains("decision_id"));
        assert!(!text.contains("\"status\""));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
    }

    #[test]
    fn execute_create_decision_invalid_proposer() {
        let result = execute_create_decision(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": "bad",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_create_decision_invalid_proposer_does_not_echo_input() {
        let attacker_input = "bad-forged-log-line";
        let result = execute_create_decision(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": attacker_input,
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        assert!(
            !result.content[0].text().contains(attacker_input),
            "governance MCP errors must not echo user-controlled proposer DIDs"
        );
    }

    #[test]
    fn execute_create_decision_rejects_oversized_title_and_description() {
        let oversized_title = "T".repeat(65_537);
        let result = execute_create_decision(
            &json!({
                "title": oversized_title,
                "description": "Test",
                "proposer_did": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);

        let oversized_description = "D".repeat(65_537);
        let result = execute_create_decision(
            &json!({
                "title": "Test",
                "description": oversized_description,
                "proposer_did": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_create_decision_missing_title() {
        let result = execute_create_decision(
            &json!({
                "description": "Test",
                "proposer_did": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- cast_vote ---------------------------------------------------------

    #[test]
    fn cast_vote_definition_valid() {
        let def = cast_vote_definition();
        assert_eq!(def.name, "exochain_cast_vote");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_cast_vote_refuses_without_governance_runtime_even_with_simulation_feature() {
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc123",
                "voter_did": "did:exo:bob",
                "choice": "approve",
                "rationale": "Looks good to me.",
            }),
            &NodeContext::empty(),
        );
        assert_governance_runtime_unavailable(&result, "exochain_cast_vote");
        let text = result.content[0].text();
        assert!(!text.contains("\"recorded\""));
        assert!(!text.contains("voice_kind"));
    }

    #[test]
    fn execute_cast_vote_invalid_choice() {
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc123",
                "voter_did": "did:exo:bob",
                "choice": "maybe",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_cast_vote_invalid_choice_does_not_echo_input() {
        let attacker_input = "maybe-forged-log-line";
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc123",
                "voter_did": "did:exo:bob",
                "choice": attacker_input,
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        assert!(
            !result.content[0].text().contains(attacker_input),
            "governance MCP errors must not echo user-controlled vote choices"
        );
    }

    #[test]
    fn execute_cast_vote_rejects_oversized_rationale() {
        let oversized_rationale = "R".repeat(65_537);
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc123",
                "voter_did": "did:exo:bob",
                "choice": "approve",
                "rationale": oversized_rationale,
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_cast_vote_invalid_voter() {
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc123",
                "voter_did": "bad",
                "choice": "approve",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- check_quorum ------------------------------------------------------

    #[test]
    fn check_quorum_definition_valid() {
        let def = check_quorum_definition();
        assert_eq!(def.name, "exochain_check_quorum");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_check_quorum_refuses_without_governance_runtime_even_with_simulation_feature() {
        let result = execute_check_quorum(
            &json!({
                "decision_id": "abc123",
                "threshold": 3,
            }),
            &NodeContext::empty(),
        );
        assert_governance_runtime_unavailable(&result, "exochain_check_quorum");
        let text = result.content[0].text();
        assert!(!text.contains("quorum_met"));
        assert!(!text.contains("total_votes"));
        let synthetic_tally_field = ["synthetic", "_excluded"].concat();
        assert!(!text.contains(&synthetic_tally_field));
    }

    #[test]
    fn execute_check_quorum_missing_threshold() {
        let result = execute_check_quorum(&json!({"decision_id": "abc123"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_check_quorum_rejects_empty_id_and_zero_threshold() {
        let empty_id = execute_check_quorum(
            &json!({
                "decision_id": "",
                "threshold": 1,
            }),
            &NodeContext::empty(),
        );
        assert!(empty_id.is_error);
        assert!(empty_id.content[0].text().contains("must not be empty"));

        let zero_threshold = execute_check_quorum(
            &json!({
                "decision_id": "abc123",
                "threshold": 0,
            }),
            &NodeContext::empty(),
        );
        assert!(zero_threshold.is_error);
        let text = zero_threshold.content[0].text();
        assert!(text.contains("mcp_governance_invalid_parameter"));
        assert!(text.contains("threshold"));
    }

    #[test]
    fn execute_check_quorum_rejects_oversized_id() {
        let oversized_id = "D".repeat(MAX_GOVERNANCE_MCP_ID_BYTES + 1);
        let result = execute_check_quorum(
            &json!({
                "decision_id": oversized_id,
                "threshold": 1,
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_governance_input_too_large"));
        assert!(text.contains("decision_id"));
    }

    // -- get_decision_status -----------------------------------------------

    #[test]
    fn get_decision_status_definition_valid() {
        let def = get_decision_status_definition();
        assert_eq!(def.name, "exochain_get_decision_status");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_get_decision_status_refuses_without_governance_runtime_even_with_simulation_feature()
    {
        let result =
            execute_get_decision_status(&json!({"decision_id": "abc123"}), &NodeContext::empty());
        assert_governance_runtime_unavailable(&result, "exochain_get_decision_status");
        let text = result.content[0].text();
        assert!(!text.contains("\"status\""));
        assert!(!text.contains("Decision not found"));
    }

    #[test]
    fn execute_get_decision_status_empty_id() {
        let result =
            execute_get_decision_status(&json!({"decision_id": ""}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_get_decision_status_rejects_oversized_id() {
        let oversized_id = "D".repeat(MAX_GOVERNANCE_MCP_ID_BYTES + 1);
        let result = execute_get_decision_status(
            &json!({"decision_id": oversized_id}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_governance_input_too_large"));
        assert!(text.contains("decision_id"));
    }

    // -- propose_amendment -------------------------------------------------

    #[test]
    fn propose_amendment_definition_valid() {
        let def = propose_amendment_definition();
        assert_eq!(def.name, "exochain_propose_amendment");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_propose_amendment_refuses_without_governance_runtime_even_with_simulation_feature() {
        let params = json!({
                "title": "Add quantum-safe threshold signatures",
                "description": "Extend the constitutional invariant set to require ML-DSA-65 for kernel modification quorum.",
                "proposer_did": "did:exo:alice",
                "target": "constitution",
        });
        let result = execute_propose_amendment(&params, &NodeContext::empty());
        assert_governance_runtime_unavailable(&result, "exochain_propose_amendment");
        let text = result.content[0].text();
        assert!(!text.contains("amendment_id"));
        assert!(!text.contains("\"requirements\""));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
    }

    #[test]
    fn execute_propose_amendment_invalid_target() {
        let result = execute_propose_amendment(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": "did:exo:alice",
                "target": "invalid_target",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_propose_amendment_invalid_target_does_not_echo_input() {
        let attacker_input = "invalid-target-forged-log-line";
        let result = execute_propose_amendment(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": "did:exo:alice",
                "target": attacker_input,
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        assert!(
            !result.content[0].text().contains(attacker_input),
            "governance MCP errors must not echo user-controlled amendment targets"
        );
    }

    #[test]
    fn execute_propose_amendment_rejects_oversized_title_and_description() {
        let oversized_title = "T".repeat(65_537);
        let result = execute_propose_amendment(
            &json!({
                "title": oversized_title,
                "description": "Test",
                "proposer_did": "did:exo:alice",
                "target": "constitution",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);

        let oversized_description = "D".repeat(65_537);
        let result = execute_propose_amendment(
            &json!({
                "title": "Test",
                "description": oversized_description,
                "proposer_did": "did:exo:alice",
                "target": "constitution",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_propose_amendment_invalid_proposer() {
        let result = execute_propose_amendment(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": "bad",
                "target": "constitution",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // ==================================================================
    // Default-build runtime-boundary refusal tests.
    // ==================================================================

    /// Default builds must return the same live-runtime refusal as feature
    /// builds, not a synthesized success response.
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_create_decision_refuses_without_governance_runtime_by_default() {
        let result = execute_create_decision(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert_governance_runtime_unavailable(&result, "exochain_create_decision");
        let text = result.content[0].text();
        assert!(!text.contains("decision_id"));
        assert!(!text.contains("\"status\""));
    }

    /// Same refusal for cast_vote: no synthesized persistence claim.
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_cast_vote_refuses_without_governance_runtime_by_default() {
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc",
                "voter_did": "did:exo:bob",
                "choice": "approve",
            }),
            &NodeContext::empty(),
        );
        assert_governance_runtime_unavailable(&result, "exochain_cast_vote");
        let text = result.content[0].text();
        assert!(!text.contains("\"recorded\""));
        assert!(!text.contains("voice_kind"));
    }

    /// Same refusal for check_quorum — no synthesized zero-vote tally.
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_check_quorum_refuses_without_governance_runtime_by_default() {
        let result = execute_check_quorum(
            &json!({
                "decision_id": "abc",
                "threshold": 3,
            }),
            &NodeContext::empty(),
        );
        assert_governance_runtime_unavailable(&result, "exochain_check_quorum");
        let text = result.content[0].text();
        assert!(text.contains("Initiatives/fix-mcp-simulation-tools.md"));
        assert!(
            text.contains("governance store"),
            "refusal body must explain the missing backing store, got: {text}"
        );
        assert!(!text.contains("quorum_met"));
        assert!(!text.contains("total_votes"));
    }

    /// Same refusal for get_decision_status — no synthesized unknown status.
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_get_decision_status_refuses_without_governance_runtime_by_default() {
        let result =
            execute_get_decision_status(&json!({"decision_id": "abc"}), &NodeContext::empty());
        assert_governance_runtime_unavailable(&result, "exochain_get_decision_status");
        let text = result.content[0].text();
        assert!(text.contains("Initiatives/fix-mcp-simulation-tools.md"));
        assert!(
            text.contains("governance store"),
            "refusal body must explain the missing backing store, got: {text}"
        );
        assert!(!text.contains("\"status\""));
        assert!(!text.contains("Decision not found"));
    }

    /// Same refusal for propose_amendment — no synthesized amendment_id.
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_propose_amendment_refuses_without_governance_runtime_by_default() {
        let result = execute_propose_amendment(
            &json!({
                "title": "Test",
                "description": "Test",
                "proposer_did": "did:exo:alice",
                "target": "constitution",
            }),
            &NodeContext::empty(),
        );
        assert_governance_runtime_unavailable(&result, "exochain_propose_amendment");
        let text = result.content[0].text();
        assert!(!text.contains("amendment_id"));
        assert!(!text.contains("\"requirements\""));
    }

    // ==================================================================
    // VCG-004b RED: mutation-effect wiring
    //
    // These tests pin the NodeContext shape and dispatch contract that
    // GREEN must implement. See GAP-REGISTRY.md VCG-004, ratified D2
    // (2026-07-02): `exochain mcp` remains a standalone process behind an
    // authenticated, read-scoped RPC bridge as the committed end state;
    // any interim node-attached mode runs under a NAMED capability
    // profile, and the MCP caller never adjudicates its own governance
    // proposal — mutations route through `reactor::submit_proposal`,
    // which is independently adjudicated by BFT consensus, never applied
    // directly by the MCP dispatch path.
    //
    // Assumed shape (GREEN must match):
    //   - `NodeContext.net_handle: Option<Arc<crate::network::NetworkHandle>>`
    //   - `NodeContext.capability_profile: Option<McpCapabilityProfile>`
    //     where `McpCapabilityProfile::NodeAttachedInterim { name: String }`
    //     is the interim, explicitly-named profile documented as interim
    //     pending the D2 standalone RPC bridge.
    //   - `NodeContext::is_node_attached(&self) -> bool` is true only when
    //     `reactor_state`, `store`, `net_handle`, AND a
    //     `NodeAttachedInterim` `capability_profile` are ALL present.
    //   - A governance mutation tool (`exochain_create_decision` here)
    //     routes through `reactor::submit_proposal` when
    //     `context.is_node_attached()`, and keeps refusing via
    //     `governance_runtime_unavailable` otherwise.
    // ==================================================================

    #[cfg(test)]
    mod mutation_effect_red {
        use std::sync::{Arc, Mutex};

        use exo_core::crypto::KeyPair;
        use tokio::sync::mpsc;

        use super::*;
        use crate::{
            mcp::context::{McpCapabilityProfile, NodeContext},
            network::{NetworkCommand, NetworkHandle},
            reactor::{self, ReactorConfig, create_reactor_state},
            store::SqliteDagStore,
            wire::{ValidatorChange, WireMessage, topics},
        };

        /// Deterministic per-index validator keypair, mirroring
        /// `reactor::tests::validator_keypair` (private to that module, so
        /// this RED test module carries its own copy rather than reaching
        /// across a private `mod tests` boundary).
        fn validator_keypair(index: usize) -> KeyPair {
            let seed = u8::try_from(index + 1).expect("test validator index fits in u8");
            KeyPair::from_secret_bytes([seed; 32]).expect("deterministic validator keypair")
        }

        fn make_validators(n: usize) -> std::collections::BTreeSet<Did> {
            (0..n)
                .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid DID"))
                .collect()
        }

        fn make_validator_public_keys(
            validators: &std::collections::BTreeSet<Did>,
        ) -> std::collections::BTreeMap<Did, exo_core::types::PublicKey> {
            validators
                .iter()
                .cloned()
                .enumerate()
                .map(|(idx, did)| (did, *validator_keypair(idx).public_key()))
                .collect()
        }

        /// A node-attached `NodeContext`: real reactor state, a real
        /// on-disk DAG store, a `NetworkHandle` whose command channel the
        /// test can drain, and the interim node-attached capability
        /// profile — matching the D2 "named capability profile" gate.
        ///
        /// Returns the context, the leaked temp-dir (kept alive for the
        /// store's lifetime), and the command receiver so the test can
        /// assert a `Publish` was actually sent.
        fn node_attached_context() -> (
            NodeContext,
            tempfile::TempDir,
            mpsc::Receiver<NetworkCommand>,
        ) {
            let validators = make_validators(4);
            let config = ReactorConfig {
                node_did: Did::new("did:exo:v0").expect("valid DID"),
                is_validator: true,
                validator_public_keys: make_validator_public_keys(&validators),
                validators,
                round_timeout_ms: 5000,
            };
            let sign_fn: Arc<dyn Fn(&[u8]) -> exo_core::types::Signature + Send + Sync> = {
                let keypair = validator_keypair(0);
                Arc::new(move |data: &[u8]| keypair.sign(data))
            };
            let reactor_state = create_reactor_state(&config, sign_fn, None);

            let dir = tempfile::tempdir().expect("temp dir");
            let store = Arc::new(Mutex::new(
                SqliteDagStore::open(dir.path()).expect("open store"),
            ));

            let (cmd_tx, cmd_rx) = mpsc::channel(32);
            let net_handle = NetworkHandle::new(cmd_tx);

            let context = NodeContext {
                reactor_state: Some(reactor_state),
                store: Some(store),
                net_handle: Some(Arc::new(net_handle)),
                node_did: Some("did:exo:v0".to_string()),
                capability_profile: Some(McpCapabilityProfile::NodeAttachedInterim {
                    name: "vcg-004b-node-attached-interim".to_string(),
                }),
                ..NodeContext::empty()
            };

            (context, dir, cmd_rx)
        }

        /// A NON-node-attached context: no reactor state, no store, no
        /// network handle, no capability profile — the same shape the
        /// standalone `exochain mcp` command builds via
        /// `mcp_node_context_from_env()` in `main.rs` today.
        fn standalone_context() -> NodeContext {
            NodeContext::empty()
        }

        /// RED (a): `mcp_mutation_effect` — a node-attached context under
        /// the interim capability profile must produce a REAL effect when
        /// a governance mutation tool is dispatched: a DAG node appended
        /// via `reactor::submit_proposal`, with the acting DID bound, and
        /// (given a live network command channel) a `ConsensusProposal`
        /// `Publish` observed on `topics::CONSENSUS`.
        ///
        /// Fails today: `NodeContext` has no `net_handle` or
        /// `capability_profile` field (compile error), and even once those
        /// exist, `execute_create_decision` unconditionally calls
        /// `governance_runtime_unavailable` regardless of context.
        #[tokio::test]
        async fn mcp_mutation_effect() {
            let (context, _dir, mut cmd_rx) = node_attached_context();
            assert!(
                context.is_node_attached(),
                "fixture must build a fully node-attached context"
            );

            let params = json!({
                "title": "Approve data sharing policy",
                "description": "Allow cross-org medical data sharing under bailment.",
                "proposer_did": "did:exo:v0",
            });

            let result = execute_create_decision(&params, &context);

            assert!(
                !result.is_error,
                "node-attached governance mutation tool must succeed, got error: {}",
                result.content[0].text()
            );
            let text = result.content[0].text();
            assert!(
                text.contains("did:exo:v0"),
                "mutation effect response must bind the acting DID, got: {text}"
            );

            // Real effect #1: a DAG node was actually appended (submit_proposal's
            // local effect), independent of whether the network broadcast
            // below is also observed.
            {
                let reactor_state = context
                    .reactor_state
                    .as_ref()
                    .expect("node-attached context carries reactor_state");
                let s = reactor_state.lock().expect("reactor state lock");
                assert_eq!(
                    s.dag.len(),
                    1,
                    "submit_proposal must append exactly one DAG node for this mutation"
                );
            }

            // Real effect #2: a governance-event Publish was emitted on the
            // network command channel for the submitted proposal.
            let command = cmd_rx
                .try_recv()
                .expect("expected a NetworkCommand::Publish from submit_proposal's broadcast");
            match command {
                NetworkCommand::Publish { topic, message, .. } => {
                    assert_eq!(
                        topic,
                        topics::CONSENSUS,
                        "governance mutation proposal must broadcast on the consensus topic"
                    );
                    assert!(
                        matches!(message, WireMessage::ConsensusProposal(_)),
                        "expected a ConsensusProposal wire message, got: {message:?}"
                    );
                }
                other => panic!("expected NetworkCommand::Publish, got: {other:?}"),
            }

            // The MCP caller must never adjudicate its own proposal: the
            // node's own consensus round must still be unresolved pending
            // quorum, not unilaterally committed by the tool call.
            {
                let reactor_state = context
                    .reactor_state
                    .as_ref()
                    .expect("node-attached context carries reactor_state");
                let s = reactor_state.lock().expect("reactor state lock");
                assert_eq!(
                    s.consensus.current_round, 0,
                    "the MCP caller's own proposal submission must not itself advance/commit \
                     the round — consensus adjudicates independently"
                );
            }
        }

        /// RED (b): `mcp_mutation_refused_without_node_attachment` —
        /// regression guard proving the capability profile actually gates.
        /// A non-node-attached (standalone-style) context must refuse the
        /// identical mutation fail-closed, exactly as it does today.
        ///
        /// This must keep passing after GREEN lands — it is the proof
        /// that `is_node_attached()` actually gates the mutation path
        /// rather than routing unconditionally.
        #[test]
        fn mcp_mutation_refused_without_node_attachment() {
            let context = standalone_context();
            assert!(
                !context.is_node_attached(),
                "fixture must build a NON-node-attached (standalone-style) context"
            );

            let params = json!({
                "title": "Approve data sharing policy",
                "description": "Allow cross-org medical data sharing under bailment.",
                "proposer_did": "did:exo:v0",
            });

            let result = execute_create_decision(&params, &context);

            assert_governance_runtime_unavailable(&result, "exochain_create_decision");
        }

        /// Sanity check on the CBOR payload shape `submit_proposal`
        /// expects, so GREEN's payload construction has an unambiguous
        /// reference: a decision-creation mutation must encode as a
        /// canonical `ValidatorChange`-compatible governance proposal
        /// payload today (VCG-004b's minimal wiring may reuse the existing
        /// validator-change payload envelope, or introduce a new decision
        /// payload variant — either way `submit_proposal`'s
        /// `validate_governance_proposal_payload` gate must accept
        /// whatever shape GREEN emits). This test only documents that the
        /// reactor's existing typed-payload gate is reachable from this
        /// module for GREEN to target; it does not assert a specific
        /// payload encoding.
        #[test]
        fn reactor_governance_payload_gate_is_reachable_from_mcp_module() {
            let change = ValidatorChange::RemoveValidator {
                did: Did::new("did:exo:v4").expect("valid DID"),
            };
            let mut payload = Vec::new();
            ciborium::into_writer(&change, &mut payload).expect("encode ValidatorChange");
            assert!(!payload.is_empty());
            // `reactor::submit_proposal` is the real mutation sink GREEN
            // must call; referencing it here (without invoking it) keeps
            // this module's `use reactor::{self, ...}` import meaningful
            // and documents the call site GREEN wires into.
            let _ = reactor::submit_proposal;
        }
    }
}
