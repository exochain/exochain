//! Ledger MCP tools — event submission, retrieval, Merkle inclusion
//! verification, and checkpoint queries against the DAG.

use std::fmt::Display;

use exo_core::{
    Did, Hash256,
    hash::{merkle_root_from_proof, verify_merkle_proof},
};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MAX_MERKLE_PROOF_HASHES: usize = 64;
const MAX_LEDGER_DID_BYTES: usize = 512;

fn validate_string_bytes(raw: &str, field: &str, max_bytes: usize) -> Result<(), String> {
    if raw.len() > max_bytes {
        return Err(format!("{field} may contain at most {max_bytes} bytes"));
    }
    Ok(())
}

fn parse_did_str(raw: &str, field: &str) -> Result<Did, String> {
    validate_string_bytes(raw, field, MAX_LEDGER_DID_BYTES)?;
    Did::new(raw).map_err(|_| format!("invalid {field} DID format"))
}

fn ledger_runtime_unavailable(tool_name: &str) -> ToolResult {
    tracing::warn!(
        tool = %tool_name,
        "refusing MCP ledger mutation: no live DAG append store is attached"
    );
    ToolResult::error(
        json!({
            "error": "mcp_ledger_runtime_unavailable",
            "tool": tool_name,
            "message": "This MCP ledger mutation has no live DAG append store \
                        attached, so it cannot submit events or return durable \
                        event IDs. The `unaudited-mcp-simulation-tools` feature \
                        does not enable synthetic ledger writes.",
            "feature_flag": "unaudited-mcp-simulation-tools",
            "initiative": "Initiatives/fix-mcp-simulation-tools.md",
            "refusal_source": format!("exo-node/mcp/tools/ledger.rs::{tool_name}"),
        })
        .to_string(),
    )
}

fn ledger_store_unavailable_error(operation: &str, error: impl Display) -> ToolResult {
    tracing::error!(
        operation,
        error = %error,
        "MCP ledger store operation failed"
    );
    ToolResult::error(
        json!({
            "error": "ledger store is temporarily unavailable",
            "operation": operation,
        })
        .to_string(),
    )
}

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
                    "maxLength": MAX_LEDGER_DID_BYTES,
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
    let _event_type = match params.get("event_type").and_then(Value::as_str) {
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

    if let Err(err) = parse_did_str(author_did_str, "author_did") {
        return ToolResult::error(json!({"error": err}).to_string());
    }

    // Validate hex payload.
    if hex::decode(payload_hex).is_err() {
        return ToolResult::error(
            json!({"error": "invalid payload_hex: not valid hexadecimal"}).to_string(),
        );
    }

    ledger_runtime_unavailable("exochain_submit_event")
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
                return ledger_store_unavailable_error("event_lookup", e);
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
                return ledger_store_unavailable_error("child_lookup", e);
            }
        };
        let committed_height = match guard.committed_height_for(&event_hash) {
            Ok(height) => height,
            Err(e) => {
                return ledger_store_unavailable_error("commit_lookup", e);
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
                    "maxItems": MAX_MERKLE_PROOF_HASHES,
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
    if proof_hashes.len() > MAX_MERKLE_PROOF_HASHES {
        return ToolResult::error(
            json!({
                "error": format!(
                    "proof_hashes may contain at most {MAX_MERKLE_PROOF_HASHES} hashes"
                )
            })
            .to_string(),
        );
    }
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

    let mut proof: Vec<Hash256> = Vec::with_capacity(proof_hashes.len());
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

    let computed_root = merkle_root_from_proof(&event_hash, &proof, target_index);
    let verified = verify_merkle_proof(&root_hash, &event_hash, &proof, target_index);

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
                    return ledger_store_unavailable_error("committed_height", e);
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

    fn assert_ledger_runtime_unavailable(result: &ToolResult, tool_name: &str) {
        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(
            text.contains("mcp_ledger_runtime_unavailable"),
            "refusal body must carry ledger runtime error tag, got: {text}"
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

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    fn assert_text_omits_raw_input(text: &str, raw_input: &str) {
        assert!(
            !text.contains(raw_input),
            "MCP error output must not reflect raw caller input: {text}"
        );
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
    fn execute_submit_event_refuses_without_ledger_runtime_even_with_simulation_feature() {
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "deadbeef",
            "author_did": "did:exo:alice",
        });
        let result = execute_submit_event(&params, &NodeContext::empty());
        assert_ledger_runtime_unavailable(&result, "exochain_submit_event");
        let text = result.content[0].text();
        assert!(!text.contains("event_id"));
        assert!(!text.contains("\"status\""));
        assert!(!text.contains("\"accepted\""));
        let synthetic_timestamp = ["simulation", "_no_", "persistence", "_timestamp"].concat();
        assert!(!text.contains(&synthetic_timestamp));
    }

    #[cfg(not(feature = "unaudited-mcp-simulation-tools"))]
    #[test]
    fn execute_submit_event_refuses_without_ledger_runtime_by_default() {
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "deadbeef",
            "author_did": "did:exo:alice",
        });
        let result = execute_submit_event(&params, &NodeContext::empty());
        assert_ledger_runtime_unavailable(&result, "exochain_submit_event");
        let text = result.content[0].text();
        assert!(text.contains("fix-mcp-simulation-tools.md"));
        assert!(!text.contains("event_id"));
        assert!(!text.contains("\"status\""));
        assert!(!text.contains("\"accepted\""));
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

    #[cfg(feature = "unaudited-mcp-simulation-tools")]
    #[test]
    fn execute_submit_event_invalid_author_omits_raw_input() {
        let attacker_marker = "<script>alert(1)</script>";
        let attacker_input = format!("bad-author-{attacker_marker}");
        let params = json!({
            "event_type": "transfer",
            "payload_hex": "deadbeef",
            "author_did": attacker_input,
        });

        let result = execute_submit_event(&params, &NodeContext::empty());

        assert!(result.is_error);
        let text = result.content[0].text();
        assert_text_omits_raw_input(text, attacker_marker);
        assert!(text.contains("author_did"));
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

    #[test]
    fn execute_get_event_redacts_store_commit_lookup_errors() {
        let (context, dir, genesis_hash, _child_hash) = context_with_store_node();
        let conn = rusqlite::Connection::open(dir.path().join("dag.db")).unwrap();
        conn.execute(
            "UPDATE committed SET height = ?1 WHERE hash = ?2",
            rusqlite::params![-1_i64, genesis_hash.as_bytes().as_slice()],
        )
        .unwrap();

        let result = execute_get_event(&json!({"event_hash": genesis_hash.to_string()}), &context);

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("ledger store is temporarily unavailable"));
        assert!(
            !text.contains("committed.height"),
            "ledger MCP errors must not expose internal store column names: {text}"
        );
    }

    #[test]
    fn ledger_store_errors_do_not_format_internal_details_for_clients() {
        let src = include_str!("ledger.rs");
        let production = src
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production source section");
        assert!(!production.contains("store event lookup failed: {e}"));
        assert!(!production.contains("store child lookup failed: {e}"));
        assert!(!production.contains("store commit lookup failed: {e}"));
        assert!(!production.contains("store committed height unavailable: {e}"));
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
        let leaves = [
            Hash256::digest(b"event-left"),
            Hash256::digest(b"event-right"),
        ];
        let target_index = 0;
        let expected_root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, target_index).expect("core proof");
        let proof_hashes: Vec<String> = proof.iter().map(ToString::to_string).collect();

        let params = json!({
            "event_hash": leaves[target_index].to_string(),
            "proof_hashes": proof_hashes,
            "root_hash": expected_root.to_string(),
            "target_index": target_index,
        });
        let result = execute_verify_inclusion(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verified"], true);
    }

    #[test]
    fn execute_verify_inclusion_valid_right_hand_proof() {
        let leaves = [
            Hash256::digest(b"event-left"),
            Hash256::digest(b"event-right"),
        ];
        let target_index = 1;
        let expected_root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, target_index).expect("core proof");
        let proof_hashes: Vec<String> = proof.iter().map(ToString::to_string).collect();

        let params = json!({
            "event_hash": leaves[target_index].to_string(),
            "proof_hashes": proof_hashes,
            "root_hash": expected_root.to_string(),
            "target_index": target_index,
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
    fn verify_inclusion_uses_core_merkle_verifier_not_local_hashing() {
        let source = include_str!("ledger.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production section");
        let verifier = production
            .split("pub fn execute_verify_inclusion")
            .nth(1)
            .expect("execute_verify_inclusion source")
            .split("// ---------------------------------------------------------------------------\n// exochain_get_checkpoint")
            .next()
            .expect("execute_verify_inclusion section");

        assert!(
            verifier.contains("verify_merkle_proof("),
            "MCP inclusion verification must delegate to exo_core's canonical Merkle verifier"
        );
        assert!(
            !production.contains("fn hash_merkle_pair"),
            "MCP ledger must not maintain a second Merkle hash-combination algorithm"
        );
        assert!(
            !production.contains("fn derive_merkle_root_from_proof"),
            "MCP ledger must not maintain a second Merkle proof-folding algorithm"
        );
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
    fn execute_verify_inclusion_rejects_excessive_proof_hashes() {
        let proof_hashes: Vec<String> = (0..=MAX_MERKLE_PROOF_HASHES)
            .map(|idx| Hash256::digest(format!("proof:{idx}").as_bytes()).to_string())
            .collect();
        let params = json!({
            "event_hash": Hash256::digest(b"event").to_string(),
            "proof_hashes": proof_hashes,
            "root_hash": Hash256::digest(b"root").to_string(),
            "target_index": 0,
        });

        let result = execute_verify_inclusion(&params, &NodeContext::empty());

        assert!(result.is_error);
        assert!(result.content[0].text().contains(&format!(
            "proof_hashes may contain at most {MAX_MERKLE_PROOF_HASHES} hashes"
        )));
    }

    #[test]
    fn verify_inclusion_definition_bounds_proof_hashes() {
        let def = verify_inclusion_definition();

        assert_eq!(
            def.input_schema["properties"]["proof_hashes"]["maxItems"],
            MAX_MERKLE_PROOF_HASHES
        );
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
        assert!(text.contains("ledger store is temporarily unavailable"));
        assert!(
            !text.contains("committed.height"),
            "ledger MCP errors must not expose internal store column names: {text}"
        );
    }

    #[test]
    fn get_checkpoint_does_not_expose_mutex_poisoning_to_clients() {
        let src = include_str!("ledger.rs");
        assert!(!src.contains("json!({\"error\": \"store mutex poisoned\"}"));
        assert!(!src.contains("json!({\"error\": \"reactor state mutex poisoned\"}"));
    }
}
