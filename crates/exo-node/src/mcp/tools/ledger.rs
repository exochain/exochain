//! Ledger MCP tools — event submission, retrieval, Merkle inclusion
//! verification, and checkpoint queries against the DAG.

use exo_core::Hash256;
#[cfg(feature = "unaudited-mcp-simulation-tools")]
use exo_core::{Did, hash::hash_structured};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

// ---------------------------------------------------------------------------
// exochain_submit_event
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_submit_event`.
#[must_use]
pub fn submit_event_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_submit_event".to_owned(),
        description: "Submit a signed event to the DAG. Returns the generated event ID and submission status.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "event_type": {
                    "type": "string",
                    "description": "The type/category of the event (e.g. \"transfer\", \"attestation\")."
                },
                "payload_hex": {
                    "type": "string",
                    "description": "Hex-encoded event payload bytes."
                },
                "author_did": {
                    "type": "string",
                    "description": "DID of the event author."
                }
            },
            "required": ["event_type", "payload_hex", "author_did"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_submit_event` tool.
#[must_use]
pub fn execute_submit_event(params: &Value, _context: &NodeContext) -> ToolResult {
    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    {
        let _ = params;
        super::simulation_tool_refused(
            "exochain_submit_event",
            "Initiatives/fix-mcp-default-simulation-gates.md",
            "This MCP tool currently returns simulated DAG acceptance without \
             appending an event to a live store. Build with \
             `unaudited-mcp-simulation-tools` only for explicit dev simulation.",
        )
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    {
        let event_type = match params.get("event_type").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: event_type"}).to_string(),
                );
            }
        };
        let payload_hex = match params.get("payload_hex").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: payload_hex"}).to_string(),
                );
            }
        };
        let author_did_str = match params.get("author_did").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                return ToolResult::error(
                    json!({"error": "missing required parameter: author_did"}).to_string(),
                );
            }
        };

        // Validate DID format.
        if Did::new(author_did_str).is_err() {
            return ToolResult::error(
                json!({"error": format!("invalid DID format: {author_did_str}")}).to_string(),
            );
        }

        // Validate hex payload.
        if hex::decode(payload_hex).is_err() {
            return ToolResult::error(
                json!({"error": "invalid payload_hex: not valid hexadecimal"}).to_string(),
            );
        }

        let event_id = match hash_structured(&(
            "exo.mcp.ledger.submit_event.v1",
            event_type,
            payload_hex,
            author_did_str,
        )) {
            Ok(hash) => hash,
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("event ID serialization failed: {e}")}).to_string(),
                );
            }
        };

        let response = json!({
            "event_id": event_id.to_string(),
            "event_type": event_type,
            "author_did": author_did_str,
            "status": "accepted",
            "submitted_at": Value::Null,
            "submitted_at_source": "simulation_no_persistence_timestamp",
        });
        ToolResult::success(response.to_string())
    }
}

// ---------------------------------------------------------------------------
// exochain_get_event
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_get_event`.
#[must_use]
pub fn get_event_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_get_event".to_owned(),
        description: "Retrieve an event from the DAG by its hash. Returns structured event info or a not-found status.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "event_hash": {
                    "type": "string",
                    "description": "Hex-encoded BLAKE3 hash of the event to retrieve."
                }
            },
            "required": ["event_hash"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_get_event` tool.
#[must_use]
pub fn execute_get_event(params: &Value, context: &NodeContext) -> ToolResult {
    let event_hash = match params.get("event_hash").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: event_hash"}).to_string(),
            );
        }
    };

    // Validate hex format.
    if hex::decode(event_hash).is_err() {
        return ToolResult::error(
            json!({"error": "invalid event_hash: not valid hexadecimal"}).to_string(),
        );
    }

    // When a DAG store is attached, we differentiate the response so
    // callers know the lookup was attempted against real state.
    if context.has_store() {
        let response = json!({
            "event_hash": event_hash,
            "found": false,
            "status": "known_store_but_lookup_not_yet_implemented",
            "suggestion": "Store is attached; this MCP tool cannot retrieve event bodies.",
        });
        return ToolResult::success(response.to_string());
    }

    let response = json!({
        "event_hash": event_hash,
        "found": false,
        "status": "not_found_no_store",
        "suggestion": "No DAG store is attached to this MCP server; run within a live node to query events.",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_verify_inclusion
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_verify_inclusion`.
#[must_use]
pub fn verify_inclusion_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_verify_inclusion".to_owned(),
        description: "Verify a Merkle inclusion proof for a given event hash against a root hash."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "event_hash": {
                    "type": "string",
                    "description": "Hex-encoded hash of the event whose inclusion is being proven."
                },
                "proof_hashes": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Ordered array of hex-encoded sibling hashes forming the proof path."
                },
                "root_hash": {
                    "type": "string",
                    "description": "Hex-encoded expected Merkle root hash."
                }
            },
            "required": ["event_hash", "proof_hashes", "root_hash"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_verify_inclusion` tool.
#[must_use]
pub fn execute_verify_inclusion(params: &Value, _context: &NodeContext) -> ToolResult {
    let event_hash = match params.get("event_hash").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: event_hash"}).to_string(),
            );
        }
    };
    let proof_hashes = match params.get("proof_hashes").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: proof_hashes (must be an array)"})
                    .to_string(),
            );
        }
    };
    let root_hash = match params.get("root_hash").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: root_hash"}).to_string(),
            );
        }
    };

    // Validate all hex values.
    if hex::decode(event_hash).is_err() {
        return ToolResult::error(
            json!({"error": "invalid event_hash: not valid hexadecimal"}).to_string(),
        );
    }
    if hex::decode(root_hash).is_err() {
        return ToolResult::error(
            json!({"error": "invalid root_hash: not valid hexadecimal"}).to_string(),
        );
    }

    let mut proof_strings: Vec<String> = Vec::new();
    for (i, ph) in proof_hashes.iter().enumerate() {
        match ph.as_str() {
            Some(s) => {
                if hex::decode(s).is_err() {
                    return ToolResult::error(
                        json!({"error": format!("invalid proof_hash at index {i}: not valid hexadecimal")}).to_string(),
                    );
                }
                proof_strings.push(s.to_owned());
            }
            None => {
                return ToolResult::error(
                    json!({"error": format!("proof_hash at index {i} is not a string")})
                        .to_string(),
                );
            }
        }
    }

    // Walk the Merkle path: start with event_hash, combine with each proof
    // hash in order to compute the derived root.
    let mut current = Hash256::digest(&hex::decode(event_hash).unwrap_or_default());
    for sibling_hex in &proof_strings {
        let sibling_bytes = hex::decode(sibling_hex).unwrap_or_default();
        let mut combined = current.as_bytes().to_vec();
        combined.extend_from_slice(&sibling_bytes);
        current = Hash256::digest(&combined);
    }

    let computed_root = current.to_string();
    let verified = computed_root == root_hash;

    let response = json!({
        "event_hash": event_hash,
        "root_hash": root_hash,
        "computed_root": computed_root,
        "verified": verified,
        "proof_depth": proof_strings.len(),
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_get_checkpoint
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_get_checkpoint`.
#[must_use]
pub fn get_checkpoint_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_get_checkpoint".to_owned(),
        description:
            "Get the latest checkpoint information including height, round, and validator count."
                .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_get_checkpoint` tool.
#[must_use]
pub fn execute_get_checkpoint(params: &Value, context: &NodeContext) -> ToolResult {
    let _ = params; // No required params.

    // Prefer live store-reported height if we have one.
    if let Some(store) = context.store.as_ref() {
        let height = match store.lock() {
            Ok(guard) => guard.committed_height_value(),
            Err(_) => {
                return ToolResult::error(json!({"error": "store mutex poisoned"}).to_string());
            }
        };

        // Consensus round and validator count come from the reactor state
        // when available; otherwise we only report the height.
        let (round, validator_count) = if let Some(reactor) = context.reactor_state.as_ref() {
            match reactor.lock() {
                Ok(state) => (
                    state.consensus.current_round,
                    state.consensus.config.validators.len(),
                ),
                Err(_) => {
                    return ToolResult::error(
                        json!({"error": "reactor state mutex poisoned"}).to_string(),
                    );
                }
            }
        } else {
            (0, 0)
        };

        let response = json!({
            "checkpoint_height": height,
            "round": round,
            "validator_count": validator_count,
            "status": "live",
            "last_finalized_at": Value::Null,
            "last_finalized_at_source": "unavailable_from_attached_store",
        });
        return ToolResult::success(response.to_string());
    }

    let response = json!({
        "checkpoint_height": 0,
        "round": 0,
        "validator_count": 0,
        "status": "no_store_available",
        "last_finalized_at": Value::Null,
        "last_finalized_at_source": "unavailable_no_store",
        "note": "No DAG store attached to this MCP server. Returning non-finalized status.",
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

    // -- submit_event ---------------------------------------------------------

    #[test]
    fn submit_event_definition_valid() {
        let def = submit_event_definition();
        assert_eq!(def.name, "exochain_submit_event");
        assert!(!def.description.is_empty());
    }

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_submit_event_success() {
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "deadbeef",
            "author_did": "did:exo:alice",
        });
        let result = execute_submit_event(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert!(v["event_id"].as_str().is_some());
        assert_eq!(v["event_type"], "transfer");
        assert_eq!(v["author_did"], "did:exo:alice");
        assert_eq!(v["status"], "accepted");
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_submit_event_refuses_by_default() {
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "deadbeef",
            "author_did": "did:exo:alice",
        });
        let result = execute_submit_event(&params, &NodeContext::empty());
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("mcp_simulation_tool_disabled"));
        assert!(text.contains("unaudited-mcp-simulation-tools"));
        assert!(text.contains("fix-mcp-default-simulation-gates.md"));
    }

    #[test]
    fn execute_submit_event_invalid_did() {
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "deadbeef",
            "author_did": "bad",
        });
        let result = execute_submit_event(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_submit_event_invalid_hex() {
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "not-hex!!",
            "author_did": "did:exo:alice",
        });
        let result = execute_submit_event(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_submit_event_missing_type() {
        let result = execute_submit_event(
            &json!({"payload_hex": "aa", "author_did": "did:exo:a"}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    // -- get_event ------------------------------------------------------------

    #[test]
    fn get_event_definition_valid() {
        let def = get_event_definition();
        assert_eq!(def.name, "exochain_get_event");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_get_event_not_found() {
        let params = json!({"event_hash": "abcdef0123456789"});
        let result = execute_get_event(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["found"], false);
        assert_eq!(v["status"], "not_found_no_store");
    }

    #[test]
    fn execute_get_event_invalid_hex() {
        let result = execute_get_event(&json!({"event_hash": "zzzz"}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_get_event_missing_hash() {
        let result = execute_get_event(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- verify_inclusion -----------------------------------------------------

    #[test]
    fn verify_inclusion_definition_valid() {
        let def = verify_inclusion_definition();
        assert_eq!(def.name, "exochain_verify_inclusion");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_verify_inclusion_valid_proof() {
        // Compute the expected root manually.
        let event_hash_bytes = hex::decode("abcd").unwrap();
        let h0 = Hash256::digest(&event_hash_bytes);
        let sibling_hex = "1234";
        let sibling_bytes = hex::decode(sibling_hex).unwrap();
        let mut combined = h0.as_bytes().to_vec();
        combined.extend_from_slice(&sibling_bytes);
        let expected_root = Hash256::digest(&combined);

        let params = json!({
            "event_hash": "abcd",
            "proof_hashes": [sibling_hex],
            "root_hash": expected_root.to_string(),
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verified"], true);
    }

    #[test]
    fn execute_verify_inclusion_invalid_proof() {
        let params = json!({
            "event_hash": "abcd",
            "proof_hashes": ["1234"],
            "root_hash": "0000",
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verified"], false);
    }

    #[test]
    fn execute_verify_inclusion_bad_hex() {
        let params = json!({
            "event_hash": "zzzz",
            "proof_hashes": [],
            "root_hash": "0000",
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- get_checkpoint -------------------------------------------------------

    #[test]
    fn get_checkpoint_definition_valid() {
        let def = get_checkpoint_definition();
        assert_eq!(def.name, "exochain_get_checkpoint");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_get_checkpoint_success() {
        let result = execute_get_checkpoint(&json!({}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["checkpoint_height"], 0);
        assert_eq!(v["round"], 0);
        assert_eq!(v["validator_count"], 0);
        assert_eq!(v["status"], "no_store_available");
    }

    #[test]
    fn execute_get_checkpoint_no_store_does_not_fabricate_timestamp() {
        let result = execute_get_checkpoint(&json!({}), &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert!(v["last_finalized_at"].is_null());
        assert_eq!(v["last_finalized_at_source"], "unavailable_no_store");
    }
}
