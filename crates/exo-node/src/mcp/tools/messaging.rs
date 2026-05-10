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

//! Messaging MCP tools.
//!
//! These endpoints intentionally fail closed until the node has a real
//! encrypted-message backend with key resolution, storage, and transport.

use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

fn messaging_delivery_unavailable(tool_name: &str) -> ToolResult {
    ToolResult::error(
        json!({
            "error": "mcp_messaging_delivery_unavailable",
            "tool": tool_name,
            "message": "Encrypted MCP messaging requires a real message store, sender signing-key resolver, recipient X25519 key resolver, and delivery transport. This node fails closed instead of simulating encryption, hashing plaintext, or returning delivery-shaped success.",
            "status": "refused",
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// exochain_send_encrypted
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_send_encrypted`.
#[must_use]
pub fn send_encrypted_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_send_encrypted".to_owned(),
        description: "Fail-closed encrypted message delivery entry point. Current node builds reject this tool until a real message store, key resolver, and delivery transport are attached.".to_owned(),
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
                    "description": "Plaintext requested for encrypted delivery. Current node builds reject this input before hashing, storing, or transmitting it."
                }
            },
            "required": ["sender_did", "recipient_did", "plaintext"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_send_encrypted` tool.
#[must_use]
pub fn execute_send_encrypted(_params: &Value, _context: &NodeContext) -> ToolResult {
    messaging_delivery_unavailable("exochain_send_encrypted")
}

// ---------------------------------------------------------------------------
// exochain_receive_encrypted
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_receive_encrypted`.
#[must_use]
pub fn receive_encrypted_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_receive_encrypted".to_owned(),
        description: "Fail-closed encrypted message receive entry point. Current node builds reject this tool until a real message store and recipient key resolver are attached.".to_owned(),
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
pub fn execute_receive_encrypted(_params: &Value, _context: &NodeContext) -> ToolResult {
    messaging_delivery_unavailable("exochain_receive_encrypted")
}

// ---------------------------------------------------------------------------
// exochain_configure_death_trigger
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_configure_death_trigger`.
#[must_use]
pub fn configure_death_trigger_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_configure_death_trigger".to_owned(),
        description: "Fail-closed afterlife message trigger entry point. Current node builds reject this tool until real sealed-envelope storage and release transport are attached.".to_owned(),
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
pub fn execute_configure_death_trigger(_params: &Value, _context: &NodeContext) -> ToolResult {
    messaging_delivery_unavailable("exochain_configure_death_trigger")
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
    fn execute_send_encrypted_refuses_even_with_simulation_feature_enabled() {
        let params = json!({
            "sender_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "plaintext": "Hello, Bob!",
        });
        let result = execute_send_encrypted(&params, &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_messaging_delivery_unavailable"));
        assert!(!text.contains("X25519-XSalsa20-Poly1305"));
        assert!(!text.contains("ciphertext_hash"));
        assert!(!text.contains("Hello, Bob!"));
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
        assert!(text.contains("mcp_messaging_delivery_unavailable"));
        assert!(text.contains("exochain_send_encrypted"));
        assert!(!text.contains("Hello, Bob!"));
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_send_encrypted_with_content_type_refuses_without_real_delivery() {
        let params = json!({
            "sender_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "content_type": "application/json",
            "plaintext": "{}",
        });
        let result = execute_send_encrypted(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0]
                .text()
                .contains("mcp_messaging_delivery_unavailable")
        );
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
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_messaging_delivery_unavailable"));
        assert!(!text.contains("env_abc123"));
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
    fn execute_receive_encrypted_invalid_did_does_not_reflect_input() {
        let malicious_did = "bad\n<script>alert(1)</script>";
        let params = json!({
            "envelope_id": "env_abc",
            "recipient_did": malicious_did,
        });
        let result = execute_receive_encrypted(&params, &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(!text.contains(malicious_did));
        assert!(!text.contains("<script>"));
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
    fn execute_configure_death_trigger_refuses_even_with_simulation_feature_enabled() {
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
        assert!(text.contains("mcp_messaging_delivery_unavailable"));
        assert!(!text.contains("trigger_id"));
        assert!(!text.contains("message_hash"));
        assert!(!text.contains("If you are reading this"));
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
        assert!(text.contains("mcp_messaging_delivery_unavailable"));
        assert!(text.contains("exochain_configure_death_trigger"));
        assert!(!text.contains("If you are reading this"));
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
    fn execute_configure_death_trigger_no_params_refuses_without_real_delivery() {
        let params = json!({
            "owner_did": "did:exo:alice",
            "recipient_did": "did:exo:bob",
            "message": "test",
            "trigger_type": "date",
        });
        let result = execute_configure_death_trigger(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0]
                .text()
                .contains("mcp_messaging_delivery_unavailable")
        );
    }
}
