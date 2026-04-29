//! Consent MCP tools — bailment proposal, consent checking, bailment listing,
//! and bailment termination.

use exo_core::Did;
#[cfg(feature = "unaudited-mcp-simulation-tools")]
use exo_core::hash::hash_structured;
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

#[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
const MCP_CONSENT_READ_INITIATIVE: &str = "Initiatives/fix-mcp-consent-read-store-refusal.md";

#[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
fn consent_registry_unavailable(tool_name: &str) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_consent_registry_unavailable",
            "tool": tool_name,
            "message": "This MCP consent read has no live consent registry attached, so it cannot prove active consent or enumerate bailments. Build with `unaudited-mcp-simulation-tools` only for explicit dev simulation.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": MCP_CONSENT_READ_INITIATIVE,
        })
        .to_string(),
    )
}

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
                    "type": "integer",
                    "minimum": 1,
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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        super::simulation_tool_refused(
            "exochain_propose_bailment",
            "Initiatives/fix-mcp-default-simulation-gates.md",
            "This MCP tool currently returns a simulated bailment proposal without \
             persisting consent state. Build with `unaudited-mcp-simulation-tools` \
             only for explicit dev simulation.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
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

        let duration_hours = match params.get("duration_hours") {
            Some(value) => match value.as_u64() {
                Some(hours) if hours > 0 => hours,
                _ => {
                    return ToolResult::error(
                        json!({"error": "duration_hours must be a positive integer"}).to_string(),
                    );
                }
            },
            None => 24,
        };

        let proposal_id = match hash_structured(&(
            "exo.mcp.consent.proposal.v1",
            bailor_str,
            bailee_str,
            scope,
            duration_hours,
        )) {
            Ok(hash) => hash.to_string(),
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("proposal ID serialization failed: {e}")}).to_string(),
                );
            }
        };

        let response = json!({
            "proposal_id": proposal_id,
            "bailor": bailor_str,
            "bailee": bailee_str,
            "scope": scope,
            "status": "proposed",
            "expires_at": Value::Null,
            "expires_at_source": "simulation_no_start_timestamp",
            "expires_after_hours": duration_hours,
        });
        ToolResult::success(response.to_string())
    }
}

// ---------------------------------------------------------------------------
// exochain_check_consent
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_check_consent`.
#[must_use]
pub fn check_consent_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_check_consent".to_owned(),
        description: "Check whether active consent can be proven for a specific actor and scope. The default MCP context has no consent registry and refuses rather than fabricating absence.".to_owned(),
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

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = scope;
        consent_registry_unavailable("exochain_check_consent")
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let response = json!({
            "actor": actor_str,
            "scope": scope,
            "consent_active": false,
            "bailment_state": "none",
            "source": "simulation_no_consent_registry",
        });
        ToolResult::success(response.to_string())
    }
}

// ---------------------------------------------------------------------------
// exochain_list_bailments
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_list_bailments`.
#[must_use]
pub fn list_bailments_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_list_bailments".to_owned(),
        description: "List bailments for a given DID when a live consent registry is wired. The default MCP context refuses rather than returning a fabricated empty registry."
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

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = filter;
        consent_registry_unavailable("exochain_list_bailments")
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let response = json!({
            "did": did_str,
            "filter": filter,
            "bailments": [],
            "count": 0,
            "source": "simulation_no_consent_registry",
        });
        ToolResult::success(response.to_string())
    }
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
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        super::simulation_tool_refused(
            "exochain_terminate_bailment",
            "Initiatives/fix-mcp-default-simulation-gates.md",
            "This MCP tool currently returns a simulated bailment termination \
             without mutating consent state. Build with \
             `unaudited-mcp-simulation-tools` only for explicit dev simulation.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
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
            return ToolResult::error(
                json!({"error": "bailment_id must not be empty"}).to_string(),
            );
        }
        if reason.is_empty() {
            return ToolResult::error(json!({"error": "reason must not be empty"}).to_string());
        }

        let response = json!({
            "bailment_id": bailment_id,
            "status": "terminated",
            "reason": reason,
            "terminated_at": Value::Null,
            "terminated_at_source": "simulation_no_persistence_timestamp",
        });
        ToolResult::success(response.to_string())
    }
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

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
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
        assert!(v["expires_at"].is_null());
        assert_eq!(v["expires_after_hours"], 24);
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_propose_bailment_refuses_by_default() {
        let result = execute_propose_bailment(
            &json!({
                "bailor_did": "did:exo:alice",
                "bailee_did": "did:exo:bob",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_simulation_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-default-simulation-gates.md"));
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

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_check_consent_refuses_without_live_registry() {
        let result = execute_check_consent(
            &json!({
                "actor_did": "did:exo:alice",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_consent_registry_unavailable"));
        assert!(text.contains("fix-mcp-consent-read-store-refusal.md"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_check_consent_simulation_success() {
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
        assert_eq!(v["source"], "simulation_no_consent_registry");
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

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_list_bailments_refuses_without_live_registry() {
        let result =
            execute_list_bailments(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_consent_registry_unavailable"));
        assert!(text.contains("fix-mcp-consent-read-store-refusal.md"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_list_bailments_simulation_success() {
        let result =
            execute_list_bailments(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["count"], 0);
        assert_eq!(v["filter"], "all");
        assert!(v["bailments"].as_array().expect("arr").is_empty());
        assert_eq!(v["source"], "simulation_no_consent_registry");
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
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

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
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
        assert!(v["terminated_at"].is_null());
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_terminate_bailment_refuses_by_default() {
        let result = execute_terminate_bailment(
            &json!({
                "bailment_id": "abc123",
                "reason": "data access no longer needed",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_simulation_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-default-simulation-gates.md"));
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
