//! Messaging MCP tools — encrypted message sending, receiving, and
//! afterlife (death trigger) message configuration.

use exo_core::Did;
#[cfg(feature = "unaudited-mcp-simulation-tools")]
use exo_core::{Hash256, hash::hash_structured};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

// ---------------------------------------------------------------------------
// exochain_send_encrypted
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_send_encrypted`.
#[must_use]
pub fn send_encrypted_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_send_encrypted".to_owned(),
        description: "Send an end-to-end encrypted message from one DID to another. Returns the envelope ID and encryption metadata.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "sender_did": {
                    "type": "string",
                    "description": "DID of the message sender."
                },
                "recipient_did": {
                    "type": "string",
                    "description": "DID of the message recipient."
                },
                "content_type": {
                    "type": "string",
                    "description": "MIME type of the message content (default: text/plain)."
                },
                "plaintext": {
                    "type": "string",
                    "description": "The plaintext message content to encrypt and send."
                }
            },
            "required": ["sender_did", "recipient_did", "plaintext"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_send_encrypted` tool.
#[must_use]
pub fn execute_send_encrypted(params: &Value, _context: &NodeContext) -> ToolResult {
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        super::simulation_tool_refused(
            "exochain_send_encrypted",
            "Initiatives/fix-mcp-default-simulation-gates.md",
            "This MCP tool currently simulates encrypted delivery by hashing \
             plaintext without sending or storing an envelope. Build with \
             `unaudited-mcp-simulation-tools` only for explicit dev simulation.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let sender_did_str = match params.get("sender_did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: sender_did"}).to_string(),
                );
            }
        };
        let recipient_did_str = match params.get("recipient_did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: recipient_did"}).to_string(),
                );
            }
        };
        let plaintext = match params.get("plaintext").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: plaintext"}).to_string(),
                );
            }
        };

        let content_type = params
            .get("content_type")
            .and_then(Value::as_str)
            .unwrap_or("text/plain");

        // Validate DIDs.
        if Did::new(sender_did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {sender_did_str}")}).to_string(),
            );
        }
        if Did::new(recipient_did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {recipient_did_str}")}).to_string(),
            );
        }

        let envelope_id = match hash_structured(&(
            "exo.mcp.messaging.envelope.v1",
            sender_did_str,
            recipient_did_str,
            content_type,
            plaintext,
        )) {
            Ok(hash) => hash,
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("envelope ID serialization failed: {e}")}).to_string(),
                );
            }
        };

        // Simulate encryption by hashing the plaintext (not real encryption).
        let ciphertext_hash = Hash256::digest(plaintext.as_bytes());

        let response = json!({
            "envelope_id": envelope_id.to_string(),
            "sender_did": sender_did_str,
            "recipient_did": recipient_did_str,
            "content_type": content_type,
            "encryption": {
                "algorithm": "X25519-XSalsa20-Poly1305",
                "ciphertext_hash": ciphertext_hash.to_string(),
                "plaintext_length": plaintext.len(),
            },
            "status": "sent",
            "sent_at": Value::Null,
            "sent_at_source": "simulation_no_delivery_timestamp",
        });
        ToolResult::success(response.to_string())
    }
}

// ---------------------------------------------------------------------------
// exochain_receive_encrypted
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_receive_encrypted`.
#[must_use]
pub fn receive_encrypted_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_receive_encrypted".to_owned(),
        description: "Decrypt and verify a received encrypted message by envelope ID.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "envelope_id": {
                    "type": "string",
                    "description": "ID of the message envelope to decrypt."
                },
                "recipient_did": {
                    "type": "string",
                    "description": "DID of the recipient attempting decryption."
                }
            },
            "required": ["envelope_id", "recipient_did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_receive_encrypted` tool.
#[must_use]
pub fn execute_receive_encrypted(params: &Value, _context: &NodeContext) -> ToolResult {
    let envelope_id = match params.get("envelope_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: envelope_id"}).to_string(),
            );
        }
    };
    let recipient_did_str = match params.get("recipient_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: recipient_did"}).to_string(),
            );
        }
    };

    // Validate DID.
    if Did::new(recipient_did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {recipient_did_str}")}).to_string(),
        );
    }

    // In the current state we don't have a message store, so return a
    // structured "not found" response.
    let response = json!({
        "envelope_id": envelope_id,
        "recipient_did": recipient_did_str,
        "decryption_status": "envelope_not_found",
        "verified": false,
        "checked_at": Value::Null,
        "checked_at_source": "unavailable_no_message_store",
        "note": "No message store is available in this node instance.",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_configure_death_trigger
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_configure_death_trigger`.
#[must_use]
pub fn configure_death_trigger_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_configure_death_trigger".to_owned(),
        description: "Configure an afterlife message release trigger. The message will be delivered to the recipient when the trigger condition is met.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "owner_did": {
                    "type": "string",
                    "description": "DID of the trigger owner."
                },
                "recipient_did": {
                    "type": "string",
                    "description": "DID of the message recipient."
                },
                "message": {
                    "type": "string",
                    "description": "The message to be released upon trigger activation."
                },
                "trigger_type": {
                    "type": "string",
                    "enum": ["inactivity", "explicit", "date"],
                    "description": "Type of trigger: inactivity timeout, explicit activation, or fixed date."
                },
                "trigger_params": {
                    "type": "object",
                    "description": "Optional trigger-specific parameters (e.g. inactivity_days, target_date)."
                }
            },
            "required": ["owner_did", "recipient_did", "message", "trigger_type"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_configure_death_trigger` tool.
#[must_use]
pub fn execute_configure_death_trigger(params: &Value, _context: &NodeContext) -> ToolResult {
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        super::simulation_tool_refused(
            "exochain_configure_death_trigger",
            "Initiatives/fix-mcp-default-simulation-gates.md",
            "This MCP tool currently returns simulated death-trigger configuration \
             without storing a trigger or sealed envelope. Build with \
             `unaudited-mcp-simulation-tools` only for explicit dev simulation.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let owner_did_str = match params.get("owner_did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: owner_did"}).to_string(),
                );
            }
        };
        let recipient_did_str = match params.get("recipient_did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: recipient_did"}).to_string(),
                );
            }
        };
        let message = match params.get("message").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: message"}).to_string(),
                );
            }
        };
        let trigger_type = match params.get("trigger_type").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: trigger_type"}).to_string(),
                );
            }
        };

        // Validate trigger type.
        let valid_types = ["inactivity", "explicit", "date"];
        if !valid_types.contains(&trigger_type) {
            return ToolResult::error(
                json!({"error": format!(
                    "invalid trigger_type '{}': must be one of {:?}",
                    trigger_type, valid_types
                )})
                .to_string(),
            );
        }

        // Validate DIDs.
        if Did::new(owner_did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {owner_did_str}")}).to_string(),
            );
        }
        if Did::new(recipient_did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {recipient_did_str}")}).to_string(),
            );
        }

        let trigger_params = params.get("trigger_params").cloned().unwrap_or(json!({}));

        let trigger_id = match hash_structured(&(
            "exo.mcp.messaging.death_trigger.v1",
            owner_did_str,
            recipient_did_str,
            trigger_type,
            &trigger_params,
            message,
        )) {
            Ok(hash) => hash,
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("trigger ID serialization failed: {e}")}).to_string(),
                );
            }
        };

        // Hash the message for the sealed envelope.
        let message_hash = Hash256::digest(message.as_bytes());

        let response = json!({
            "trigger_id": trigger_id.to_string(),
            "owner_did": owner_did_str,
            "recipient_did": recipient_did_str,
            "trigger_type": trigger_type,
            "trigger_params": trigger_params,
            "message_hash": message_hash.to_string(),
            "message_length": message.len(),
            "status": "configured",
            "configured_at": Value::Null,
            "configured_at_source": "simulation_no_persistence_timestamp",
        });
        ToolResult::success(response.to_string())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- send_encrypted -------------------------------------------------------

    #[test]
    fn send_encrypted_definition_valid() {
        let def = send_encrypted_definition();
        assert_eq!(def.name, "exochain_send_encrypted");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_send_encrypted_success() {
        let params = json!({
            "sender_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "plaintext": "Hello, Bob!",
        });
        let result = execute_send_encrypted(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["sender_did"], "did:exo:alice");
        assert_eq!(v["recipient_did"], "did:exo:bob");
        assert_eq!(v["content_type"], "text/plain");
        assert_eq!(v["status"], "sent");
        assert!(v["envelope_id"].as_str().is_some());
        assert_eq!(v["encryption"]["algorithm"], "X25519-XSalsa20-Poly1305");
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_send_encrypted_refuses_by_default() {
        let params = json!({
            "sender_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "plaintext": "Hello, Bob!",
        });
        let result = execute_send_encrypted(&params, &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_simulation_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-default-simulation-gates.md"));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_send_encrypted_with_content_type() {
        let params = json!({
            "sender_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "content_type": "application/json",
            "plaintext": "{}",
        });
        let result = execute_send_encrypted(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["content_type"], "application/json");
    }

    #[test]
    fn execute_send_encrypted_invalid_sender() {
        let params = json!({
            "sender_did": "bad",
            "recipient_did": "did:exo:bob",
            "plaintext": "hello",
        });
        let result = execute_send_encrypted(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_send_encrypted_missing_plaintext() {
        let result = execute_send_encrypted(
            &json!({"sender_did": "did:exo:a", "recipient_did": "did:exo:b"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- receive_encrypted ----------------------------------------------------

    #[test]
    fn receive_encrypted_definition_valid() {
        let def = receive_encrypted_definition();
        assert_eq!(def.name, "exochain_receive_encrypted");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_receive_encrypted_success() {
        let params = json!({
            "envelope_id": "env_abc123",
            "recipient_did": "did:exo:bob",
        });
        let result = execute_receive_encrypted(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["envelope_id"], "env_abc123");
        assert_eq!(v["decryption_status"], "envelope_not_found");
        assert!(v["checked_at"].is_null());
        assert_eq!(v["checked_at_source"], "unavailable_no_message_store");
    }

    #[test]
    fn execute_receive_encrypted_invalid_did() {
        let params = json!({
            "envelope_id": "env_abc",
            "recipient_did": "bad",
        });
        let result = execute_receive_encrypted(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_receive_encrypted_missing_envelope() {
        let result = execute_receive_encrypted(
            &json!({"recipient_did": "did:exo:bob"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- configure_death_trigger ----------------------------------------------

    #[test]
    fn configure_death_trigger_definition_valid() {
        let def = configure_death_trigger_definition();
        assert_eq!(def.name, "exochain_configure_death_trigger");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_configure_death_trigger_success() {
        let params = json!({
            "owner_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "message": "If you are reading this, I am gone.",
            "trigger_type": "inactivity",
            "trigger_params": {"inactivity_days": 365},
        });
        let result = execute_configure_death_trigger(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["trigger_type"], "inactivity");
        assert_eq!(v["status"], "configured");
        assert!(v["trigger_id"].as_str().is_some());
        assert!(v["message_hash"].as_str().is_some());
        assert_eq!(v["trigger_params"]["inactivity_days"], 365);
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_configure_death_trigger_refuses_by_default() {
        let params = json!({
            "owner_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "message": "If you are reading this, I am gone.",
            "trigger_type": "inactivity",
            "trigger_params": {"inactivity_days": 365},
        });
        let result = execute_configure_death_trigger(&params, &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_simulation_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-default-simulation-gates.md"));
    }

    #[test]
    fn execute_configure_death_trigger_invalid_type() {
        let params = json!({
            "owner_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "message": "test",
            "trigger_type": "unknown",
        });
        let result = execute_configure_death_trigger(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_configure_death_trigger_invalid_owner() {
        let params = json!({
            "owner_did": "bad",
            "recipient_did": "did:exo:bob",
            "message": "test",
            "trigger_type": "explicit",
        });
        let result = execute_configure_death_trigger(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_configure_death_trigger_no_params() {
        let params = json!({
            "owner_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "message": "test",
            "trigger_type": "date",
        });
        let result = execute_configure_death_trigger(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["trigger_params"], json!({}));
    }
}
