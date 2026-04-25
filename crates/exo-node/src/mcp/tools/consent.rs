//! Consent MCP tools — bailment proposal, consent checking, bailment listing,
//! and bailment termination.

use exo_core::{Did, Hash256, Timestamp};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

// ---------------------------------------------------------------------------
// exochain_propose_bailment
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_propose_bailment`.
#[must_use]
pub fn propose_bailment_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_propose_bailment".to_owned(),
        description: "Propose a new bailment (consent-conditioned data sharing agreement) between a bailor (data owner) and bailee (data accessor).".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "bailor_did": {
                    "type": "string",
                    "description": "DID of the data owner (bailor)."
                },
                "bailee_did": {
                    "type": "string",
                    "description": "DID of the data accessor (bailee)."
                },
                "scope": {
                    "type": "string",
                    "description": "Data scope for the bailment (e.g. \"data:medical:records\")."
                },
                "duration_hours": {
                    "type": "number",
                    "description": "Duration in hours before the bailment expires (default: 24)."
                }
            },
            "required": ["bailor_did", "bailee_did", "scope"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_propose_bailment` tool.
#[must_use]
pub fn execute_propose_bailment(params: &Value, _context: &NodeContext) -> ToolResult {
    let bailor_str = match params.get("bailor_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: bailor_did"}).to_string(),
            );
        }
    };
    let bailee_str = match params.get("bailee_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: bailee_did"}).to_string(),
            );
        }
    };
    let scope = match params.get("scope").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: scope"}).to_string(),
            );
        }
    };

    if Did::new(bailor_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid bailor DID format: {bailor_str}")}).to_string(),
        );
    }
    if Did::new(bailee_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid bailee DID format: {bailee_str}")}).to_string(),
        );
    }

    let duration_hours = params
        .get("duration_hours")
        .and_then(Value::as_f64)
        .unwrap_or(24.0) as u64;

    let now = Timestamp::now_utc();

    // Generate a deterministic proposal ID from the inputs.
    let id_input = format!("{bailor_str}:{bailee_str}:{scope}:{}", now.physical_ms);
    let proposal_id = Hash256::digest(id_input.as_bytes()).to_string();

    let expires_ms = now
        .physical_ms
        .saturating_add(duration_hours.saturating_mul(3_600_000));

    let response = json!({
        "proposal_id": proposal_id,
        "bailor": bailor_str,
        "bailee": bailee_str,
        "scope": scope,
        "status": "proposed",
        "expires_at": format!("{expires_ms}:0"),
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_check_consent
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_check_consent`.
#[must_use]
pub fn check_consent_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_check_consent".to_owned(),
        description: "Check whether active consent exists for a specific actor and scope. Returns consent status and details.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "actor_did": {
                    "type": "string",
                    "description": "DID of the actor to check consent for."
                },
                "scope": {
                    "type": "string",
                    "description": "Data scope to check (e.g. \"data:medical\")."
                }
            },
            "required": ["actor_did", "scope"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_check_consent` tool.
#[must_use]
pub fn execute_check_consent(params: &Value, _context: &NodeContext) -> ToolResult {
    let actor_str = match params.get("actor_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: actor_did"}).to_string(),
            );
        }
    };
    let scope = match params.get("scope").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: scope"}).to_string(),
            );
        }
    };

    if Did::new(actor_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid actor DID format: {actor_str}")}).to_string(),
        );
    }

    // No persistent consent registry yet — report no active consent.
    let response = json!({
        "actor": actor_str,
        "scope": scope,
        "consent_active": false,
        "bailment_state": "none",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_list_bailments
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_list_bailments`.
#[must_use]
pub fn list_bailments_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_list_bailments".to_owned(),
        description: "List all bailments (active, proposed, terminated) for a given DID."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "did": {
                    "type": "string",
                    "description": "The DID to list bailments for."
                },
                "status_filter": {
                    "type": "string",
                    "enum": ["all", "active", "proposed", "terminated"],
                    "description": "Filter bailments by status (default: all)."
                }
            },
            "required": ["did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_list_bailments` tool.
#[must_use]
pub fn execute_list_bailments(params: &Value, _context: &NodeContext) -> ToolResult {
    let did_str = match params.get("did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: did"}).to_string(),
            );
        }
    };

    if Did::new(did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {did_str}")}).to_string(),
        );
    }

    let filter = params
        .get("status_filter")
        .and_then(Value::as_str)
        .unwrap_or("all");

    let valid_filters = ["all", "active", "proposed", "terminated"];
    if !valid_filters.contains(&filter) {
        return ToolResult::error(
            json!({"error": format!("invalid status_filter: {filter}. Must be one of: all, active, proposed, terminated")}).to_string(),
        );
    }

    let response = json!({
        "did": did_str,
        "filter": filter,
        "bailments": [],
        "count": 0,
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_terminate_bailment
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_terminate_bailment`.
#[must_use]
pub fn terminate_bailment_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_terminate_bailment".to_owned(),
        description: "Terminate an active bailment, revoking the bailee's data access consent."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "bailment_id": {
                    "type": "string",
                    "description": "The ID of the bailment to terminate."
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for termination."
                }
            },
            "required": ["bailment_id", "reason"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_terminate_bailment` tool.
#[must_use]
pub fn execute_terminate_bailment(params: &Value, _context: &NodeContext) -> ToolResult {
    let bailment_id = match params.get("bailment_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: bailment_id"}).to_string(),
            );
        }
    };
    let reason = match params.get("reason").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: reason"}).to_string(),
            );
        }
    };

    if bailment_id.is_empty() {
        return ToolResult::error(json!({"error": "bailment_id must not be empty"}).to_string());
    }
    if reason.is_empty() {
        return ToolResult::error(json!({"error": "reason must not be empty"}).to_string());
    }

    let now = Timestamp::now_utc();

    let response = json!({
        "bailment_id": bailment_id,
        "status": "terminated",
        "reason": reason,
        "terminated_at": format!("{}:{}", now.physical_ms, now.logical),
    });
    ToolResult::success(response.to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- propose_bailment --------------------------------------------------

    #[test]
    fn propose_bailment_definition_valid() {
        let def = propose_bailment_definition();
        assert_eq!(def.name, "exochain_propose_bailment");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_propose_bailment_success() {
        let result = execute_propose_bailment(
            &json!({
                "bailor_did": "did:exo:alice",
                "bailee_did": "did:exo:bob",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["bailor"], "did:exo:alice");
        assert_eq!(v["bailee"], "did:exo:bob");
        assert_eq!(v["scope"], "data:medical");
        assert_eq!(v["status"], "proposed");
        assert!(!v["proposal_id"].as_str().expect("id").is_empty());
        assert!(v["expires_at"].as_str().is_some());
    }

    #[test]
    fn execute_propose_bailment_invalid_bailor() {
        let result = execute_propose_bailment(
            &json!({
                "bailor_did": "bad",
                "bailee_did": "did:exo:bob",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_propose_bailment_missing_scope() {
        let result = execute_propose_bailment(
            &json!({
                "bailor_did": "did:exo:alice",
                "bailee_did": "did:exo:bob",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- check_consent -----------------------------------------------------

    #[test]
    fn check_consent_definition_valid() {
        let def = check_consent_definition();
        assert_eq!(def.name, "exochain_check_consent");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_check_consent_success() {
        let result = execute_check_consent(
            &json!({
                "actor_did": "did:exo:alice",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["consent_active"], false);
        assert_eq!(v["bailment_state"], "none");
    }

    #[test]
    fn execute_check_consent_invalid_did() {
        let result = execute_check_consent(
            &json!({
                "actor_did": "bad",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_check_consent_missing_scope() {
        let result = execute_check_consent(
            &json!({
                "actor_did": "did:exo:alice",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- list_bailments ----------------------------------------------------

    #[test]
    fn list_bailments_definition_valid() {
        let def = list_bailments_definition();
        assert_eq!(def.name, "exochain_list_bailments");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_list_bailments_success() {
        let result =
            execute_list_bailments(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["count"], 0);
        assert_eq!(v["filter"], "all");
        assert!(v["bailments"].as_array().expect("arr").is_empty());
    }

    #[test]
    fn execute_list_bailments_with_filter() {
        let result = execute_list_bailments(
            &json!({"did": "did:exo:alice", "status_filter": "active"}),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["filter"], "active");
    }

    #[test]
    fn execute_list_bailments_invalid_did() {
        let result = execute_list_bailments(&json!({"did": "bad"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_list_bailments_invalid_filter() {
        let result = execute_list_bailments(
            &json!({"did": "did:exo:alice", "status_filter": "invalid_filter"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- terminate_bailment ------------------------------------------------

    #[test]
    fn terminate_bailment_definition_valid() {
        let def = terminate_bailment_definition();
        assert_eq!(def.name, "exochain_terminate_bailment");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_terminate_bailment_success() {
        let result = execute_terminate_bailment(
            &json!({
                "bailment_id": "abc123",
                "reason": "data access no longer needed",
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["bailment_id"], "abc123");
        assert_eq!(v["status"], "terminated");
        assert_eq!(v["reason"], "data access no longer needed");
        assert!(v["terminated_at"].as_str().is_some());
    }

    #[test]
    fn execute_terminate_bailment_missing_reason() {
        let result =
            execute_terminate_bailment(&json!({"bailment_id": "abc123"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_terminate_bailment_empty_id() {
        let result = execute_terminate_bailment(
            &json!({
                "bailment_id": "",
                "reason": "test",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }
}
