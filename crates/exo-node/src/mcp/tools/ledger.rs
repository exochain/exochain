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
    let event_hash_raw = match params.get("event_hash").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: event_hash"}).to_string(),
            );
        }
    };

    let event_hash = match decode_hash256_hex("event_hash", event_hash_raw) {
        Ok(hash) => hash,
        Err(error) => return ToolResult::error(json!({"error": error}).to_string()),
    };

    if let Some(store) = context.store.as_ref() {
        let guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("MCP ledger get_event store mutex poisoned");
                return ToolResult::error(
                    json!({"error": "ledger store is temporarily unavailable"}).to_string(),
                );
            }
        };

        let node = match guard.get_sync(&event_hash) {
            Ok(node) => node,
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("store event lookup failed: {e}")}).to_string(),
                );
            }
        };

        let Some(node) = node else {
            let response = json!({
                "event_hash": event_hash.to_string(),
                "found": false,
                "status": "not_found",
                "source": "attached_store",
            });
            return ToolResult::success(response.to_string());
        };

        let children = match guard.children(&event_hash) {
            Ok(children) => children,
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("store child lookup failed: {e}")}).to_string(),
                );
            }
        };
        let committed_height = match guard.committed_height_for(&event_hash) {
            Ok(height) => height,
            Err(e) => {
                return ToolResult::error(
                    json!({"error": format!("store commit lookup failed: {e}")}).to_string(),
                );
            }
        };

        let parents: Vec<String> = node.parents.iter().map(ToString::to_string).collect();
        let children_hex: Vec<String> = children.iter().map(ToString::to_string).collect();
        let response = json!({
            "event_hash": node.hash.to_string(),
            "found": true,
            "status": "found",
            "source": "attached_store",
            "payload_hash": node.payload_hash.to_string(),
            "payload_hash_size": node.payload_hash.as_bytes().len(),
            "creator_did": node.creator_did.to_string(),
            "parents": parents,
            "parent_count": node.parents.len(),
            "children": children_hex,
            "child_count": children.len(),
            "committed": committed_height.is_some(),
            "committed_height": committed_height,
            "timestamp": node.timestamp.to_string(),
            "timestamp_physical_ms": node.timestamp.physical_ms,
            "timestamp_logical": node.timestamp.logical,
            "signature_algorithm": node.signature.algorithm(),
            "signature_hex": node.signature.to_string(),
        });
        return ToolResult::success(response.to_string());
    }

    let response = json!({
        "event_hash": event_hash.to_string(),
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
                },
                "target_index": {
                    "type": "integer",
                    "description": "Zero-based index of the event hash in the original Merkle tree."
                }
            },
            "required": ["event_hash", "proof_hashes", "root_hash", "target_index"],
            "additionalProperties": false,
        }),
    }
}

fn decode_hash256_hex(field: &str, value: &str) -> Result<Hash256, String> {
    let bytes =
        hex::decode(value).map_err(|_| format!("invalid {field}: not valid hexadecimal"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid {field}: expected 32-byte hash (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(hash_bytes))
}

fn hash_merkle_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left.as_bytes());
    combined[32..].copy_from_slice(right.as_bytes());
    Hash256::digest(&combined)
}

fn derive_merkle_root_from_proof(leaf: &Hash256, proof: &[Hash256], index: usize) -> Hash256 {
    let mut current = *leaf;
    let mut idx = index;

    for sibling in proof {
        current = if idx % 2 == 0 {
            hash_merkle_pair(&current, sibling)
        } else {
            hash_merkle_pair(sibling, &current)
        };
        idx /= 2;
    }

    current
}

/// Execute the `exochain_verify_inclusion` tool.
#[must_use]
pub fn execute_verify_inclusion(params: &Value, _context: &NodeContext) -> ToolResult {
    let event_hash_raw = match params.get("event_hash").and_then(Value::as_str) {
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
    let root_hash_raw = match params.get("root_hash").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: root_hash"}).to_string(),
            );
        }
    };
    let target_index = match params.get("target_index").and_then(Value::as_u64) {
        Some(n) => match usize::try_from(n) {
            Ok(index) => index,
            Err(_) => {
                return ToolResult::error(
                    json!({"error": "invalid target_index: value does not fit usize"}).to_string(),
                );
            }
        },
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: target_index"}).to_string(),
            );
        }
    };

    let event_hash = match decode_hash256_hex("event_hash", event_hash_raw) {
        Ok(hash) => hash,
        Err(error) => return ToolResult::error(json!({"error": error}).to_string()),
    };
    let root_hash = match decode_hash256_hex("root_hash", root_hash_raw) {
        Ok(hash) => hash,
        Err(error) => return ToolResult::error(json!({"error": error}).to_string()),
    };

    let mut proof: Vec<Hash256> = Vec::new();
    for (i, ph) in proof_hashes.iter().enumerate() {
        match ph.as_str() {
            Some(s) => match decode_hash256_hex(&format!("proof_hash at index {i}"), s) {
                Ok(hash) => proof.push(hash),
                Err(error) => {
                    return ToolResult::error(json!({"error": error}).to_string());
                }
            },
            None => {
                return ToolResult::error(
                    json!({"error": format!("proof_hash at index {i} is not a string")})
                        .to_string(),
                );
            }
        }
    }

    let computed_root = derive_merkle_root_from_proof(&event_hash, &proof, target_index);
    let verified = computed_root == root_hash;

    let response = json!({
        "event_hash": event_hash.to_string(),
        "root_hash": root_hash.to_string(),
        "computed_root": computed_root.to_string(),
        "verified": verified,
        "proof_depth": proof.len(),
        "target_index": target_index,
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
            Ok(guard) => match guard.committed_height_value() {
                Ok(height) => height,
                Err(e) => {
                    return ToolResult::error(
                        json!({"error": format!("store committed height unavailable: {e}")})
                            .to_string(),
                    );
                }
            },
            Err(_) => {
                tracing::error!("MCP ledger checkpoint store mutex poisoned");
                return ToolResult::error(
                    json!({"error": "ledger store is temporarily unavailable"}).to_string(),
                );
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
                    tracing::error!("MCP ledger checkpoint reactor state mutex poisoned");
                    return ToolResult::error(
                        json!({"error": "node state is temporarily unavailable"}).to_string(),
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
    use std::sync::{Arc, Mutex};

    use exo_core::{
        hash::{merkle_proof, merkle_root},
        types::{Did, Signature},
    };
    use exo_dag::dag::{Dag, DeterministicDagClock, append};

    use super::*;

    fn make_sign_fn() -> Box<dyn Fn(&[u8]) -> Signature> {
        Box::new(|data: &[u8]| {
            let digest = blake3::hash(data);
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(digest.as_bytes());
            Signature::from_bytes(signature)
        })
    }

    fn context_with_store_node() -> (NodeContext, tempfile::TempDir, Hash256, Hash256) {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut store = crate::store::SqliteDagStore::open(dir.path()).expect("store");

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:mcp-ledger-test").expect("valid DID");
        let sign_fn = make_sign_fn();

        let genesis =
            append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).expect("genesis");
        let child = append(
            &mut dag,
            &[genesis.hash],
            b"child",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .expect("child");

        store.put_sync(genesis.clone()).expect("put genesis");
        store.put_sync(child.clone()).expect("put child");
        store
            .mark_committed_sync(&genesis.hash, 1)
            .expect("commit genesis");

        (
            NodeContext {
                store: Some(Arc::new(Mutex::new(store))),
                ..NodeContext::empty()
            },
            dir,
            genesis.hash,
            child.hash,
        )
    }

    fn test_hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(left.as_bytes());
        combined[32..].copy_from_slice(right.as_bytes());
        Hash256::digest(&combined)
    }

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
        let params = json!({"event_hash": Hash256::digest(b"missing-event").to_string()});
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
    fn execute_get_event_rejects_short_event_hash() {
        let result = execute_get_event(
            &json!({"event_hash": "abcdef0123456789"}),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        assert!(result.content[0].text().contains("32-byte"));
        assert!(result.content[0].text().contains("event_hash"));
    }

    #[test]
    fn execute_get_event_missing_hash() {
        let result = execute_get_event(&json!({}), &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_get_event_reads_attached_store_node() {
        let (context, _dir, genesis_hash, child_hash) = context_with_store_node();

        let result = execute_get_event(&json!({"event_hash": child_hash.to_string()}), &context);

        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["found"], true);
        assert_eq!(v["status"], "found");
        assert_eq!(v["event_hash"], child_hash.to_string());
        assert_eq!(v["creator_did"], "did:exo:mcp-ledger-test");
        assert_eq!(v["parent_count"], 1);
        assert_eq!(v["parents"][0], genesis_hash.to_string());
        assert_eq!(v["child_count"], 0);
        assert_eq!(v["committed"], false);
        assert!(v["committed_height"].is_null());
        assert_eq!(v["payload_hash_size"], 32);
        assert_eq!(v["timestamp"], "0:2");
        assert_eq!(v["timestamp_physical_ms"], 0);
        assert_eq!(v["timestamp_logical"], 2);
        assert_eq!(v["signature_algorithm"], "Ed25519");
        assert_eq!(
            v["signature_hex"].as_str().expect("signature hex").len(),
            128
        );
    }

    #[test]
    fn execute_get_event_reports_committed_height_from_attached_store() {
        let (context, _dir, genesis_hash, _child_hash) = context_with_store_node();

        let result = execute_get_event(&json!({"event_hash": genesis_hash.to_string()}), &context);

        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["found"], true);
        assert_eq!(v["status"], "found");
        assert_eq!(v["committed"], true);
        assert_eq!(v["committed_height"], 1);
        assert_eq!(v["parent_count"], 0);
        assert_eq!(v["child_count"], 1);
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
        let event_hash = Hash256::digest(b"event-left");
        let sibling = Hash256::digest(b"event-right");
        let expected_root = test_hash_pair(&event_hash, &sibling);

        let params = json!({
            "event_hash": event_hash.to_string(),
            "proof_hashes": [sibling.to_string()],
            "root_hash": expected_root.to_string(),
            "target_index": 0,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verified"], true);
    }

    #[test]
    fn execute_verify_inclusion_valid_right_hand_proof() {
        let left_hash = Hash256::digest(b"event-left");
        let right_hash = Hash256::digest(b"event-right");
        let expected_root = test_hash_pair(&left_hash, &right_hash);

        let params = json!({
            "event_hash": right_hash.to_string(),
            "proof_hashes": [left_hash.to_string()],
            "root_hash": expected_root.to_string(),
            "target_index": 1,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verified"], true);
        assert_eq!(v["target_index"], 1);
    }

    #[test]
    fn execute_verify_inclusion_accepts_core_merkle_proof() {
        let leaves = [
            Hash256::digest(b"event-0"),
            Hash256::digest(b"event-1"),
            Hash256::digest(b"event-2"),
        ];
        let target_index = 2;
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, target_index).expect("core proof");
        let proof_hashes: Vec<String> = proof.iter().map(ToString::to_string).collect();

        let params = json!({
            "event_hash": leaves[target_index].to_string(),
            "proof_hashes": proof_hashes,
            "root_hash": root.to_string(),
            "target_index": target_index,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verified"], true);
        assert_eq!(v["computed_root"], root.to_string());
    }

    #[test]
    fn execute_verify_inclusion_invalid_proof() {
        let event_hash = Hash256::digest(b"event-left");
        let sibling = Hash256::digest(b"event-right");
        let params = json!({
            "event_hash": event_hash.to_string(),
            "proof_hashes": [sibling.to_string()],
            "root_hash": Hash256::digest(b"wrong-root").to_string(),
            "target_index": 0,
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
            "target_index": 0,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_verify_inclusion_rejects_short_event_hash() {
        let params = json!({
            "event_hash": "abcd",
            "proof_hashes": [],
            "root_hash": Hash256::digest(b"root").to_string(),
            "target_index": 0,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(result.content[0].text().contains("event_hash"));
        assert!(result.content[0].text().contains("32-byte"));
    }

    #[test]
    fn execute_verify_inclusion_rejects_short_root_hash() {
        let params = json!({
            "event_hash": Hash256::digest(b"event").to_string(),
            "proof_hashes": [],
            "root_hash": "0000",
            "target_index": 0,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(result.content[0].text().contains("root_hash"));
        assert!(result.content[0].text().contains("32-byte"));
    }

    #[test]
    fn execute_verify_inclusion_rejects_short_proof_hash() {
        let params = json!({
            "event_hash": Hash256::digest(b"event").to_string(),
            "proof_hashes": ["1234"],
            "root_hash": Hash256::digest(b"root").to_string(),
            "target_index": 0,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(result.content[0].text().contains("proof_hash at index 0"));
        assert!(result.content[0].text().contains("32-byte"));
    }

    #[test]
    fn execute_verify_inclusion_requires_target_index() {
        let params = json!({
            "event_hash": Hash256::digest(b"event").to_string(),
            "proof_hashes": [],
            "root_hash": Hash256::digest(b"root").to_string(),
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(result.content[0].text().contains("target_index"));
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

    #[test]
    fn execute_get_checkpoint_fails_closed_on_store_height_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::SqliteDagStore::open(dir.path()).unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("dag.db")).unwrap();
        let hash = [0xA5u8; 32];
        conn.execute(
            "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
            rusqlite::params![hash.as_slice(), -1_i64],
        )
        .unwrap();
        let context = NodeContext {
            store: Some(std::sync::Arc::new(std::sync::Mutex::new(store))),
            ..NodeContext::empty()
        };

        let result = execute_get_checkpoint(&json!({}), &context);

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("store committed height unavailable"));
        assert!(text.contains("committed.height"));
    }

    #[test]
    fn get_checkpoint_does_not_expose_mutex_poisoning_to_clients() {
        let src = include_str!("ledger.rs");
        assert!(!src.contains("json!({\"error\": \"store mutex poisoned\"}"));
        assert!(!src.contains("json!({\"error\": \"reactor state mutex poisoned\"}"));
    }
}
