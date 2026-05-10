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

//! Consent MCP tools — bailment proposal, consent checking, bailment listing,
//! and bailment termination.

use exo_core::Did;
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MCP_CONSENT_READ_INITIATIVE: &str = "Initiatives/fix-mcp-consent-read-store-refusal.md";
const MAX_CONSENT_DID_BYTES: usize = 512;
const MAX_CONSENT_SCOPE_BYTES: usize = 4 * 1024;
const MAX_CONSENT_ID_BYTES: usize = 256;
const MAX_CONSENT_REASON_BYTES: usize = 4 * 1024;
const MAX_CONSENT_STATUS_FILTER_BYTES: usize = 32;

fn consent_registry_unavailable(tool_name: &str) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_consent_registry_unavailable",
            "tool": tool_name,
            "message": "This MCP consent read has no live consent registry attached, so it cannot prove active consent or enumerate bailments. The `unaudited-mcp-simulation-tools` feature does not enable fabricated consent registry reads.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": MCP_CONSENT_READ_INITIATIVE,
        })
        .to_string(),
    )
}

fn consent_store_unavailable(tool_name: &str) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_consent_store_unavailable",
            "tool": tool_name,
            "message": "This MCP consent mutation has no live signed consent store attached, so it cannot create or terminate bailments. The `unaudited-mcp-simulation-tools` feature does not enable synthetic consent writes.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": MCP_CONSENT_READ_INITIATIVE,
        })
        .to_string(),
    )
}

fn validate_string_bytes(raw: &str, field: &str, max_bytes: usize) -> Result<(), String> {
    if raw.len() > max_bytes {
        return Err(format!("{field} may contain at most {max_bytes} bytes"));
    }
    Ok(())
}

fn invalid_did_message(field: &str) -> String {
    if field == "did" {
        "invalid DID format".to_owned()
    } else {
        format!("invalid {field} DID format")
    }
}

fn parse_did_str(raw: &str, field: &str) -> Result<Did, String> {
    validate_string_bytes(raw, field, MAX_CONSENT_DID_BYTES)?;
    Did::new(raw).map_err(|_| invalid_did_message(field))
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
                    "maxLength": MAX_CONSENT_DID_BYTES,
                    "description": "DID of the data owner (bailor)."
                },
                "bailee_did": {
                    "type": "string",
                    "maxLength": MAX_CONSENT_DID_BYTES,
                    "description": "DID of the data accessor (bailee)."
                },
                "scope": {
                    "type": "string",
                    "maxLength": MAX_CONSENT_SCOPE_BYTES,
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
    let _ = params;
    consent_store_unavailable("exochain_propose_bailment")
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
                    "maxLength": MAX_CONSENT_DID_BYTES,
                    "description": "DID of the actor to check consent for."
                },
                "scope": {
                    "type": "string",
                    "maxLength": MAX_CONSENT_SCOPE_BYTES,
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

    if let Err(err) = parse_did_str(actor_str, "actor") {
        return ToolResult::error(json!({"error": err}).to_string());
    }
    if scope.is_empty() {
        return ToolResult::error(json!({"error": "scope must not be empty"}).to_string());
    }
    if let Err(err) = validate_string_bytes(scope, "scope", MAX_CONSENT_SCOPE_BYTES) {
        return ToolResult::error(json!({"error": err}).to_string());
    }

    let _ = (actor_str, scope);
    consent_registry_unavailable("exochain_check_consent")
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
                    "maxLength": MAX_CONSENT_DID_BYTES,
                    "description": "The DID to list bailments for."
                },
                "status_filter": {
                    "type": "string",
                    "maxLength": MAX_CONSENT_STATUS_FILTER_BYTES,
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

    if let Err(err) = parse_did_str(did_str, "did") {
        return ToolResult::error(json!({"error": err}).to_string());
    }

    let filter = params
        .get("status_filter")
        .and_then(Value::as_str)
        .unwrap_or("all");

    let valid_filters = ["all", "active", "proposed", "terminated"];
    if let Err(err) =
        validate_string_bytes(filter, "status_filter", MAX_CONSENT_STATUS_FILTER_BYTES)
    {
        return ToolResult::error(json!({"error": err}).to_string());
    }
    if !valid_filters.contains(&filter) {
        return ToolResult::error(
            json!({"error": "invalid status_filter. Must be one of: all, active, proposed, terminated"}).to_string(),
        );
    }

    let _ = (did_str, filter);
    consent_registry_unavailable("exochain_list_bailments")
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
                    "maxLength": MAX_CONSENT_ID_BYTES,
                    "description": "The ID of the bailment to terminate."
                },
                "reason": {
                    "type": "string",
                    "maxLength": MAX_CONSENT_REASON_BYTES,
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
    let _ = params;
    consent_store_unavailable("exochain_terminate_bailment")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_text_omits_raw_input(text: &str, raw_input: &str) {
        assert!(
            !text.contains(raw_input),
            "MCP error output must not reflect raw caller input: {text}"
        );
    }

    // -- propose_bailment --------------------------------------------------

    #[test]
    fn propose_bailment_definition_valid() {
        let def = propose_bailment_definition();
        assert_eq!(def.name, "exochain_propose_bailment");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_propose_bailment_refuses_without_signed_store_even_with_simulation_feature() {
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
        assert!(text.contains("mcp_consent_store_unavailable"));
        assert!(!text.contains("proposal_id"));
        let synthetic_timestamp = ["simulation", "_no_", "start", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
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
        assert!(text.contains("mcp_consent_store_unavailable"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-consent-read-store-refusal.md"));
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

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_propose_bailment_invalid_bailor_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-bailor-{attacker_marker}");
        let result = execute_propose_bailment(
            &json!({
                "bailor_did": attacker_input,
                "bailee_did": "did:exo:bob",
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("mcp_consent_store_unavailable"));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_propose_bailment_invalid_bailee_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-bailee-{attacker_marker}");
        let result = execute_propose_bailment(
            &json!({
                "bailor_did": "did:exo:alice",
                "bailee_did": attacker_input,
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("mcp_consent_store_unavailable"));
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
    fn execute_check_consent_refuses_without_live_registry_even_with_simulation_feature() {
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
        assert!(!text.contains("consent_active"));
        let synthetic_registry = ["simulation", "_no_", "consent", "_registry"].concat();
        assert!(!text.contains(&synthetic_registry));
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
    fn execute_check_consent_invalid_actor_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-actor-{attacker_marker}");
        let result = execute_check_consent(
            &json!({
                "actor_did": attacker_input,
                "scope": "data:medical",
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("actor"));
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
    fn execute_list_bailments_refuses_without_live_registry_even_with_simulation_feature() {
        let result =
            execute_list_bailments(&json!({"did": "did:exo:alice"}), &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_consent_registry_unavailable"));
        assert!(!text.contains("\"bailments\""));
        assert!(!text.contains("\"count\""));
        let synthetic_registry = ["simulation", "_no_", "consent", "_registry"].concat();
        assert!(!text.contains(&synthetic_registry));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_list_bailments_with_filter_refuses_without_live_registry() {
        let result = execute_list_bailments(
            &json!({"did": "did:exo:alice", "status_filter": "active"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_consent_registry_unavailable"));
        assert!(!text.contains("\"bailments\""));
        assert!(!text.contains("\"count\""));
    }

    #[test]
    fn execute_list_bailments_invalid_did() {
        let result = execute_list_bailments(&json!({"did": "bad"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_list_bailments_invalid_did_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-did-{attacker_marker}");
        let result = execute_list_bailments(
            &json!({
                "did": attacker_input,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("DID"));
    }

    #[test]
    fn execute_list_bailments_invalid_filter() {
        let result = execute_list_bailments(
            &json!({"did": "did:exo:alice", "status_filter": "invalid_filter"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_list_bailments_invalid_filter_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("invalid-{attacker_marker}");
        let result = execute_list_bailments(
            &json!({"did": "did:exo:alice", "status_filter": attacker_input}),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("status_filter"));
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
    fn execute_terminate_bailment_refuses_without_signed_store_even_with_simulation_feature() {
        let result = execute_terminate_bailment(
            &json!({
                "bailment_id": "abc123",
                "reason": "data access no longer needed",
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_consent_store_unavailable"));
        assert!(!text.contains("terminated_at"));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
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
        assert!(text.contains("mcp_consent_store_unavailable"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-consent-read-store-refusal.md"));
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
