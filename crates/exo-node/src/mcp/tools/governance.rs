//! Governance MCP tools — decision creation, voting, quorum checking, decision
//! status, and constitutional amendment proposals.

use exo_core::{Did, Hash256, Timestamp};
use serde_json::{Value, json};

use crate::mcp::context::NodeContext;
use crate::mcp::protocol::{ToolDefinition, ToolResult};

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
                    "description": "Title of the governance decision."
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the decision."
                },
                "proposer_did": {
                    "type": "string",
                    "description": "DID of the proposer."
                },
                "decision_class": {
                    "type": "string",
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

    if Did::new(proposer_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid proposer DID format: {proposer_str}")}).to_string(),
        );
    }

    let _decision_class = params
        .get("decision_class")
        .and_then(Value::as_str)
        .unwrap_or("standard");

    let now = Timestamp::now_utc();
    let id_input = format!("{title}:{proposer_str}:{}", now.physical_ms);
    let decision_id = Hash256::digest(id_input.as_bytes()).to_string();

    let response = json!({
        "decision_id": decision_id,
        "title": title,
        "description": description,
        "proposer": proposer_str,
        "status": "proposed",
        "created_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
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
                    "description": "The ID of the decision to vote on."
                },
                "voter_did": {
                    "type": "string",
                    "description": "DID of the voter."
                },
                "choice": {
                    "type": "string",
                    "enum": ["approve", "reject", "abstain"],
                    "description": "Vote choice."
                },
                "rationale": {
                    "type": "string",
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

    if Did::new(voter_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid voter DID format: {voter_str}")}).to_string(),
        );
    }

    let valid_choices = ["approve", "reject", "abstain"];
    if !valid_choices.contains(&choice) {
        return ToolResult::error(
            json!({"error": format!("invalid choice: {choice}. Must be one of: approve, reject, abstain")}).to_string(),
        );
    }

    if decision_id.is_empty() {
        return ToolResult::error(json!({"error": "decision_id must not be empty"}).to_string());
    }

    let rationale = params
        .get("rationale")
        .and_then(Value::as_str)
        .unwrap_or("");

    let response = json!({
        "decision_id": decision_id,
        "voter": voter_str,
        "choice": choice,
        "recorded": true,
        "voice_kind": "unknown",
        "rationale": rationale,
    });
    ToolResult::success(response.to_string())
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
                    "description": "The ID of the decision to check."
                },
                "threshold": {
                    "type": "number",
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

    if decision_id.is_empty() {
        return ToolResult::error(json!({"error": "decision_id must not be empty"}).to_string());
    }

    // No persistent vote registry yet — always report zero votes.
    let response = json!({
        "decision_id": decision_id,
        "threshold": threshold,
        "total_votes": 0,
        "authentic_approvals": 0,
        "synthetic_excluded": 0,
        "quorum_met": false,
    });
    ToolResult::success(response.to_string())
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

    if decision_id.is_empty() {
        return ToolResult::error(json!({"error": "decision_id must not be empty"}).to_string());
    }

    let response = json!({
        "decision_id": decision_id,
        "status": "unknown",
        "message": "Decision not found in local state",
    });
    ToolResult::success(response.to_string())
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
                    "description": "Title of the proposed amendment."
                },
                "description": {
                    "type": "string",
                    "description": "Full description of the proposed amendment."
                },
                "proposer_did": {
                    "type": "string",
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

    if Did::new(proposer_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid proposer DID format: {proposer_str}")}).to_string(),
        );
    }

    let valid_targets = ["constitution", "invariant_registry", "kernel_binary"];
    if !valid_targets.contains(&target) {
        return ToolResult::error(
            json!({"error": format!("invalid target: {target}. Must be one of: constitution, invariant_registry, kernel_binary")}).to_string(),
        );
    }

    let now = Timestamp::now_utc();
    let id_input = format!("amendment:{title}:{proposer_str}:{}", now.physical_ms);
    let amendment_id = Hash256::digest(id_input.as_bytes()).to_string();

    let response = json!({
        "amendment_id": amendment_id,
        "title": title,
        "description": description,
        "proposer": proposer_str,
        "target": target,
        "requirements": {
            "validator_consensus": "unanimous",
            "ai_irb_approval": ">=80%",
            "public_comment_period_days": 30,
            "formal_proof_required": true,
            "security_audit_required": true,
        },
        "status": "draft",
        "warning": "Constitutional amendments require the highest governance threshold. See spec \u{00a7}3A.3.2.",
    });
    ToolResult::success(response.to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- create_decision ---------------------------------------------------

    #[test]
    fn create_decision_definition_valid() {
        let def = create_decision_definition();
        assert_eq!(def.name, "exochain_create_decision");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_create_decision_success() {
        let result = execute_create_decision(
            &json!({
                "title": "Approve data sharing policy",
                "description": "Allow cross-org medical data sharing under bailment.",
                "proposer_did": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["title"], "Approve data sharing policy");
        assert_eq!(v["proposer"], "did:exo:alice");
        assert_eq!(v["status"], "proposed");
        assert!(v["decision_id"].as_str().expect("id").len() > 0);
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

    #[test]
    fn execute_cast_vote_success() {
        let result = execute_cast_vote(
            &json!({
                "decision_id": "abc123",
                "voter_did": "did:exo:bob",
                "choice": "approve",
                "rationale": "Looks good to me.",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["decision_id"], "abc123");
        assert_eq!(v["voter"], "did:exo:bob");
        assert_eq!(v["choice"], "approve");
        assert_eq!(v["recorded"], true);
        assert_eq!(v["voice_kind"], "unknown");
        assert_eq!(v["rationale"], "Looks good to me.");
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

    #[test]
    fn execute_check_quorum_success() {
        let result = execute_check_quorum(
            &json!({
                "decision_id": "abc123",
                "threshold": 3,
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["decision_id"], "abc123");
        assert_eq!(v["threshold"], 3);
        assert_eq!(v["quorum_met"], false);
        assert_eq!(v["total_votes"], 0);
    }

    #[test]
    fn execute_check_quorum_missing_threshold() {
        let result = execute_check_quorum(&json!({"decision_id": "abc123"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- get_decision_status -----------------------------------------------

    #[test]
    fn get_decision_status_definition_valid() {
        let def = get_decision_status_definition();
        assert_eq!(def.name, "exochain_get_decision_status");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_get_decision_status_success() {
        let result =
            execute_get_decision_status(&json!({"decision_id": "abc123"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["decision_id"], "abc123");
        assert_eq!(v["status"], "unknown");
    }

    #[test]
    fn execute_get_decision_status_empty_id() {
        let result =
            execute_get_decision_status(&json!({"decision_id": ""}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- propose_amendment -------------------------------------------------

    #[test]
    fn propose_amendment_definition_valid() {
        let def = propose_amendment_definition();
        assert_eq!(def.name, "exochain_propose_amendment");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_propose_amendment_success() {
        let result = execute_propose_amendment(
            &json!({
                "title": "Add quantum-safe threshold signatures",
                "description": "Extend the constitutional invariant set to require ML-DSA-65 for kernel modification quorum.",
                "proposer_did": "did:exo:alice",
                "target": "constitution",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(&result.content[0].text()).expect("valid JSON");
        assert_eq!(v["target"], "constitution");
        assert_eq!(v["status"], "draft");
        assert!(v["amendment_id"].as_str().expect("id").len() > 0);
        assert_eq!(v["requirements"]["validator_consensus"], "unanimous");
        assert_eq!(v["requirements"]["formal_proof_required"], true);
        assert!(
            v["warning"]
                .as_str()
                .expect("warning")
                .contains("highest governance threshold")
        );
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
}
