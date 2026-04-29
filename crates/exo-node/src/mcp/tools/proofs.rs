//! Proofs MCP tools — evidence creation, chain of custody verification,
//! Merkle proof generation, and CGR kernel proof verification.

use exo_core::{Did, Hash256, Timestamp};
use exo_legal::evidence::{
    create_evidence_from_hash, custody_chain_digest, transfer_custody, verify_chain_of_custody,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

const MCP_CGR_PROOF_INITIATIVE: &str = "Initiatives/fix-mcp-cgr-proof-verification-stub.md";

fn tool_error(message: impl Into<String>) -> ToolResult {
    let message = message.into();
    ToolResult::error(json!({"error": message}).to_string())
}

fn required_nonzero_u64(params: &Value, name: &str) -> std::result::Result<u64, ToolResult> {
    match params.get(name).and_then(Value::as_u64) {
        Some(value) if value > 0 => Ok(value),
        Some(_) => Err(tool_error(format!("{name} must be a nonzero integer"))),
        None => Err(tool_error(format!("missing required parameter: {name}"))),
    }
}

fn required_u32(params: &Value, name: &str) -> std::result::Result<u32, ToolResult> {
    match params.get(name).and_then(Value::as_u64) {
        Some(value) if value <= u64::from(u32::MAX) => Ok(value as u32),
        Some(_) => Err(tool_error(format!("{name} must fit in u32"))),
        None => Err(tool_error(format!("missing required parameter: {name}"))),
    }
}

fn required_nonempty_str<'a>(
    params: &'a Value,
    name: &str,
) -> std::result::Result<&'a str, ToolResult> {
    match params.get(name).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) => Err(tool_error(format!("{name} must not be empty"))),
        None => Err(tool_error(format!("missing required parameter: {name}"))),
    }
}

fn required_transfer_nonempty_str<'a>(
    transfer: &'a Value,
    index: usize,
    name: &str,
) -> std::result::Result<&'a str, ToolResult> {
    match transfer.get(name).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) => Err(tool_error(format!(
            "chain entry {index}: {name} must not be empty"
        ))),
        None => Err(tool_error(format!(
            "chain entry {index}: missing required field: {name}"
        ))),
    }
}

fn required_transfer_nonzero_u64(
    transfer: &Value,
    index: usize,
    name: &str,
) -> std::result::Result<u64, ToolResult> {
    match transfer.get(name).and_then(Value::as_u64) {
        Some(value) if value > 0 => Ok(value),
        Some(_) => Err(tool_error(format!(
            "chain entry {index}: {name} must be a nonzero integer"
        ))),
        None => Err(tool_error(format!(
            "chain entry {index}: missing required field: {name}"
        ))),
    }
}

fn required_transfer_u32(
    transfer: &Value,
    index: usize,
    name: &str,
) -> std::result::Result<u32, ToolResult> {
    match transfer.get(name).and_then(Value::as_u64) {
        Some(value) if value <= u64::from(u32::MAX) => Ok(value as u32),
        Some(_) => Err(tool_error(format!(
            "chain entry {index}: {name} must fit in u32"
        ))),
        None => Err(tool_error(format!(
            "chain entry {index}: missing required field: {name}"
        ))),
    }
}

fn parse_uuid(value: &str, name: &str) -> std::result::Result<Uuid, ToolResult> {
    Uuid::parse_str(value).map_err(|err| tool_error(format!("{name} must be a valid UUID: {err}")))
}

fn parse_did(value: &str, name: &str) -> std::result::Result<Did, ToolResult> {
    Did::new(value).map_err(|err| tool_error(format!("{name} must be a valid DID: {err}")))
}

fn parse_hash256_hex(value: &str, name: &str) -> std::result::Result<Hash256, ToolResult> {
    let decoded =
        hex::decode(value).map_err(|err| tool_error(format!("{name} must be hex: {err}")))?;
    if decoded.len() != 32 {
        return Err(tool_error(format!(
            "{name} must decode to exactly 32 bytes, got {}",
            decoded.len()
        )));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(Hash256::from_bytes(bytes))
}

fn final_custodian(evidence: &exo_legal::evidence::Evidence) -> &Did {
    evidence
        .chain_of_custody
        .last()
        .map(|transfer| &transfer.to)
        .unwrap_or(&evidence.creator)
}

// ---------------------------------------------------------------------------
// exochain_create_evidence
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_create_evidence`.
#[must_use]
pub fn create_evidence_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_create_evidence".to_owned(),
        description: "Create evidence with an initial chain of custody entry. Returns the evidence ID and custody record.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Human-readable description of the evidence."
                },
                "evidence_type": {
                    "type": "string",
                    "description": "Type of evidence (e.g. \"document\", \"digital_artifact\", \"testimony\")."
                },
                "source_did": {
                    "type": "string",
                    "description": "DID of the evidence source/creator."
                },
                "evidence_id": {
                    "type": "string",
                    "description": "Caller-supplied non-placeholder evidence ID."
                },
                "created_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for creation."
                }
            },
            "required": ["description", "evidence_type", "source_did", "evidence_id", "created_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_create_evidence` tool.
#[must_use]
pub fn execute_create_evidence(params: &Value, _context: &NodeContext) -> ToolResult {
    let description = match params.get("description").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: description"}).to_string(),
            );
        }
    };
    let evidence_type = match params.get("evidence_type").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: evidence_type"}).to_string(),
            );
        }
    };
    let source_did_str = match params.get("source_did").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: source_did"}).to_string(),
            );
        }
    };
    let evidence_id = match params.get("evidence_id").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => s,
        Some(_) => {
            return ToolResult::error(
                json!({"error": "evidence_id must not be empty"}).to_string(),
            );
        }
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: evidence_id"}).to_string(),
            );
        }
    };
    let created_at_ms = match required_nonzero_u64(params, "created_at_ms") {
        Ok(value) => value,
        Err(result) => return result,
    };

    if Did::new(source_did_str).is_err() {
        return ToolResult::error(
            json!({"error": format!("invalid DID format: {source_did_str}")}).to_string(),
        );
    }

    let response = json!({
        "evidence_id": evidence_id,
        "description": description,
        "evidence_type": evidence_type,
        "source_did": source_did_str,
        "chain_of_custody": [
            {
                "custodian": source_did_str,
                "action": "created",
                "timestamp": format!("{}:0", created_at_ms),
            }
        ],
        "status": "created",
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_verify_chain_of_custody
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_verify_chain_of_custody`.
#[must_use]
pub fn verify_chain_of_custody_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_verify_chain_of_custody".to_owned(),
        description: "Verify the integrity of an evidence chain of custody using EXOCHAIN legal evidence rules, checking UUID/DID/hash metadata, transfer continuity, reasons, and monotonic HLC timestamps.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "evidence_id": {
                    "type": "string",
                    "description": "UUID of the evidence record to verify."
                },
                "evidence_type": {
                    "type": "string",
                    "description": "Evidence type tag recorded at creation."
                },
                "content_hash": {
                    "type": "string",
                    "description": "64-character hex-encoded Hash256 of the evidence content."
                },
                "creator_did": {
                    "type": "string",
                    "description": "DID of the original evidence creator."
                },
                "created_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for evidence creation."
                },
                "created_at_logical": {
                    "type": "integer",
                    "description": "Caller-supplied HLC logical counter for evidence creation."
                },
                "chain": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from_did": { "type": "string" },
                            "to_did": { "type": "string" },
                            "transferred_at_ms": { "type": "integer" },
                            "transferred_at_logical": { "type": "integer" },
                            "reason": { "type": "string" }
                        },
                        "required": [
                            "from_did",
                            "to_did",
                            "transferred_at_ms",
                            "transferred_at_logical",
                            "reason"
                        ],
                        "additionalProperties": false
                    },
                    "description": "Array of custody transfer records. The original creator is supplied separately; an empty transfer chain means the creator still has custody."
                },
                "verified_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for verification."
                },
                "verified_at_logical": {
                    "type": "integer",
                    "description": "Caller-supplied HLC logical counter for verification."
                }
            },
            "required": [
                "evidence_id",
                "evidence_type",
                "content_hash",
                "creator_did",
                "created_at_ms",
                "created_at_logical",
                "chain",
                "verified_at_ms",
                "verified_at_logical"
            ],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_verify_chain_of_custody` tool.
#[must_use]
pub fn execute_verify_chain_of_custody(params: &Value, _context: &NodeContext) -> ToolResult {
    let evidence_id_str = match required_nonempty_str(params, "evidence_id") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let evidence_id = match parse_uuid(evidence_id_str, "evidence_id") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let evidence_type = match required_nonempty_str(params, "evidence_type") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let content_hash_str = match required_nonempty_str(params, "content_hash") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let content_hash = match parse_hash256_hex(content_hash_str, "content_hash") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let creator_did_str = match required_nonempty_str(params, "creator_did") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let creator_did = match parse_did(creator_did_str, "creator_did") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let created_at_ms = match required_nonzero_u64(params, "created_at_ms") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let created_at_logical = match required_u32(params, "created_at_logical") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let chain = match params.get("chain").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return tool_error("missing required parameter: chain (must be an array)");
        }
    };
    let verified_at_ms = match required_nonzero_u64(params, "verified_at_ms") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let verified_at_logical = match required_u32(params, "verified_at_logical") {
        Ok(value) => value,
        Err(result) => return result,
    };

    let mut evidence = match create_evidence_from_hash(
        evidence_id,
        content_hash,
        &creator_did,
        evidence_type,
        Timestamp::new(created_at_ms, created_at_logical),
    ) {
        Ok(value) => value,
        Err(err) => return tool_error(err.to_string()),
    };

    for (i, entry) in chain.iter().enumerate() {
        let from_did_str = match required_transfer_nonempty_str(entry, i, "from_did") {
            Ok(value) => value,
            Err(result) => return result,
        };
        let to_did_str = match required_transfer_nonempty_str(entry, i, "to_did") {
            Ok(value) => value,
            Err(result) => return result,
        };
        let transferred_at_ms = match required_transfer_nonzero_u64(entry, i, "transferred_at_ms") {
            Ok(value) => value,
            Err(result) => return result,
        };
        let transferred_at_logical = match required_transfer_u32(entry, i, "transferred_at_logical")
        {
            Ok(value) => value,
            Err(result) => return result,
        };
        let reason = match required_transfer_nonempty_str(entry, i, "reason") {
            Ok(value) => value,
            Err(result) => return result,
        };
        let from_did = match parse_did(from_did_str, &format!("chain entry {i} from_did")) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let to_did = match parse_did(to_did_str, &format!("chain entry {i} to_did")) {
            Ok(value) => value,
            Err(result) => return result,
        };

        if let Err(err) = transfer_custody(
            &mut evidence,
            &from_did,
            &to_did,
            Timestamp::new(transferred_at_ms, transferred_at_logical),
            reason,
        ) {
            return ToolResult::success(
                json!({
                    "evidence_id": evidence_id_str,
                    "chain_length": chain.len(),
                    "valid": false,
                    "issues": [err.to_string()],
                    "verified_at": Timestamp::new(verified_at_ms, verified_at_logical).to_string(),
                })
                .to_string(),
            );
        }
    }

    if let Err(err) = verify_chain_of_custody(&evidence) {
        return ToolResult::success(
            json!({
                "evidence_id": evidence_id_str,
                "chain_length": chain.len(),
                "valid": false,
                "issues": [err.to_string()],
                "verified_at": Timestamp::new(verified_at_ms, verified_at_logical).to_string(),
            })
            .to_string(),
        );
    }

    let custody_digest = match custody_chain_digest(&evidence) {
        Ok(value) => value,
        Err(err) => return tool_error(err.to_string()),
    };

    let response = json!({
        "evidence_id": evidence_id_str,
        "chain_length": chain.len(),
        "valid": true,
        "issues": [],
        "final_custodian": final_custodian(&evidence).to_string(),
        "custody_digest": custody_digest.to_string(),
        "verified_at": Timestamp::new(verified_at_ms, verified_at_logical).to_string(),
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_generate_merkle_proof
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_generate_merkle_proof`.
#[must_use]
pub fn generate_merkle_proof_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_generate_merkle_proof".to_owned(),
        description: "Generate a Merkle inclusion proof for a target leaf given a set of leaves. Computes the actual Merkle root and proof path.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "leaves": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Array of hex-encoded leaf values."
                },
                "target_index": {
                    "type": "number",
                    "description": "Zero-based index of the target leaf."
                }
            },
            "required": ["leaves", "target_index"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_generate_merkle_proof` tool.
#[must_use]
pub fn execute_generate_merkle_proof(params: &Value, _context: &NodeContext) -> ToolResult {
    let leaves_val = match params.get("leaves").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: leaves (must be an array)"})
                    .to_string(),
            );
        }
    };
    let target_index = match params.get("target_index").and_then(Value::as_u64) {
        Some(n) => n as usize,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: target_index (must be a number)"})
                    .to_string(),
            );
        }
    };

    if leaves_val.is_empty() {
        return ToolResult::error(json!({"error": "leaves array must not be empty"}).to_string());
    }

    if target_index >= leaves_val.len() {
        return ToolResult::error(
            json!({"error": format!("target_index {} out of range (0..{})", target_index, leaves_val.len())})
                .to_string(),
        );
    }

    // Hash each leaf.
    let mut hashes: Vec<Hash256> = Vec::new();
    for (i, leaf) in leaves_val.iter().enumerate() {
        match leaf.as_str() {
            Some(s) => {
                let bytes = match hex::decode(s) {
                    Ok(b) => b,
                    Err(_) => {
                        return ToolResult::error(
                            json!({"error": format!("invalid hex at leaf index {i}")}).to_string(),
                        );
                    }
                };
                hashes.push(Hash256::digest(&bytes));
            }
            None => {
                return ToolResult::error(
                    json!({"error": format!("leaf at index {i} is not a string")}).to_string(),
                );
            }
        }
    }

    // Build the Merkle tree bottom-up and collect the proof path.
    let mut proof: Vec<String> = Vec::new();
    let mut current_level = hashes;
    let mut idx = target_index;

    while current_level.len() > 1 {
        let mut next_level: Vec<Hash256> = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                &current_level[i] // duplicate last if odd
            };

            // If this pair contains our target, record the sibling.
            if i == (idx & !1) {
                if idx % 2 == 0 {
                    if i + 1 < current_level.len() {
                        proof.push(right.to_string());
                    } else {
                        proof.push(left.to_string());
                    }
                } else {
                    proof.push(left.to_string());
                }
            }

            let mut combined = left.as_bytes().to_vec();
            combined.extend_from_slice(right.as_bytes());
            next_level.push(Hash256::digest(&combined));

            i += 2;
        }
        idx /= 2;
        current_level = next_level;
    }

    let root = current_level[0].to_string();
    let target_leaf = leaves_val[target_index].as_str().unwrap_or("");

    let response = json!({
        "root": root,
        "target_leaf": target_leaf,
        "target_index": target_index,
        "proof": proof,
        "leaf_count": leaves_val.len(),
    });
    ToolResult::success(response.to_string())
}

// ---------------------------------------------------------------------------
// exochain_verify_cgr_proof
// ---------------------------------------------------------------------------

/// Tool definition for `exochain_verify_cgr_proof`.
#[must_use]
pub fn verify_cgr_proof_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_verify_cgr_proof".to_owned(),
        description: "Fail-closed placeholder for CGR kernel proof verification until proof bytes, public inputs, checkpoint roots, and a production verifier are wired.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "proof_hash": {
                    "type": "string",
                    "description": "Hex-encoded hash claim for the CGR proof. Hash-only verification is refused."
                },
                "invariants_checked": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Caller-declared invariant names. These are not accepted as proof of verification."
                },
                "verified_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for the refusal record."
                }
            },
            "required": ["proof_hash", "invariants_checked", "verified_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_verify_cgr_proof` tool.
#[must_use]
pub fn execute_verify_cgr_proof(params: &Value, _context: &NodeContext) -> ToolResult {
    let proof_hash = match params.get("proof_hash").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: proof_hash"}).to_string(),
            );
        }
    };
    let invariants = match params.get("invariants_checked").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: invariants_checked (must be an array)"})
                    .to_string(),
            );
        }
    };
    let verified_at_ms = match required_nonzero_u64(params, "verified_at_ms") {
        Ok(value) => value,
        Err(result) => return result,
    };

    // Validate hex format.
    if hex::decode(proof_hash).is_err() {
        return ToolResult::error(
            json!({"error": "invalid proof_hash: not valid hexadecimal"}).to_string(),
        );
    }

    let invariant_names: Vec<String> = invariants
        .iter()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect();

    ToolResult::error(
        json!({
            "error": format!(
                "CGR proof verification is unavailable: exochain_verify_cgr_proof has no proof bytes, public inputs, checkpoint root, validator signature set, or production CGR proof verifier wired; refusing hash-only verification claims. See {MCP_CGR_PROOF_INITIATIVE}."
            ),
            "proof_hash": proof_hash,
            "invariants_requested": invariant_names,
            "refused_at": format!("{}:0", verified_at_ms),
            "initiative": MCP_CGR_PROOF_INITIATIVE,
        })
        .to_string(),
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -- create_evidence ------------------------------------------------------

    #[test]
    fn create_evidence_definition_valid() {
        let def = create_evidence_definition();
        assert_eq!(def.name, "exochain_create_evidence");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_create_evidence_success() {
        let params = json!({
            "description": "Contract PDF",
            "evidence_type": "document",
            "source_did": "did:exo:alice",
            "evidence_id": "00000000-0000-0000-0000-000000000001",
            "created_at_ms": 1700000000000_u64,
        });
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["evidence_id"], "00000000-0000-0000-0000-000000000001");
        assert_eq!(v["evidence_type"], "document");
        assert_eq!(v["source_did"], "did:exo:alice");
        assert_eq!(v["status"], "created");
        let chain = v["chain_of_custody"].as_array().expect("chain array");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0]["action"], "created");
    }

    #[test]
    fn execute_create_evidence_invalid_did() {
        let params = json!({
            "description": "test",
            "evidence_type": "document",
            "source_did": "bad",
            "evidence_id": "00000000-0000-0000-0000-000000000001",
            "created_at_ms": 1700000000000_u64,
        });
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_create_evidence_missing_description() {
        let result = execute_create_evidence(
            &json!({
                "evidence_type": "doc",
                "source_did": "did:exo:a",
                "evidence_id": "00000000-0000-0000-0000-000000000001",
                "created_at_ms": 1700000000000_u64
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn execute_create_evidence_rejects_missing_metadata() {
        let params = json!({
            "description": "Contract PDF",
            "evidence_type": "document",
            "source_did": "did:exo:alice",
        });
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- verify_chain_of_custody ----------------------------------------------

    #[test]
    fn verify_chain_of_custody_definition_valid() {
        let def = verify_chain_of_custody_definition();
        assert_eq!(def.name, "exochain_verify_chain_of_custody");
        assert!(!def.description.is_empty());
    }

    fn valid_custody_verification_params() -> Value {
        json!({
            "evidence_id": "00000000-0000-0000-0000-000000000111",
            "evidence_type": "document",
            "content_hash": "0101010101010101010101010101010101010101010101010101010101010101",
            "creator_did": "did:exo:alice",
            "created_at_ms": 1_700_000_000_000_u64,
            "created_at_logical": 0_u64,
            "chain": [
                {
                    "from_did": "did:exo:alice",
                    "to_did": "did:exo:bob",
                    "transferred_at_ms": 1_700_000_000_100_u64,
                    "transferred_at_logical": 0_u64,
                    "reason": "signed release to records custodian"
                },
                {
                    "from_did": "did:exo:bob",
                    "to_did": "did:exo:carol",
                    "transferred_at_ms": 1_700_000_000_200_u64,
                    "transferred_at_logical": 0_u64,
                    "reason": "litigation hold transfer"
                }
            ],
            "verified_at_ms": 1_700_000_000_300_u64,
            "verified_at_logical": 0_u64,
        })
    }

    #[test]
    fn execute_verify_chain_of_custody_rejects_shape_only_chain() {
        let legacy_shape_only_params = json!({
            "evidence_id": "00000000-0000-0000-0000-000000000222",
            "chain": [
                {"custodian": "did:exo:alice", "action": "created"},
                {"custodian": "did:exo:bob", "action": "transferred"},
            ],
            "verified_at_ms": 1700000000001_u64,
        });
        let result =
            execute_verify_chain_of_custody(&legacy_shape_only_params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("evidence_type"),
            "shape-only verification must be refused with required evidence metadata"
        );
    }

    #[test]
    fn execute_verify_chain_of_custody_accepts_legal_evidence_chain() {
        let params = valid_custody_verification_params();
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], true);
        assert_eq!(v["chain_length"], 2);
        assert_eq!(v["final_custodian"], "did:exo:carol");
        assert_eq!(
            v["custody_digest"].as_str().expect("custody digest").len(),
            64
        );
    }

    #[test]
    fn execute_verify_chain_of_custody_rejects_broken_transfer_continuity() {
        let mut params = valid_custody_verification_params();
        params["chain"][1]["from_did"] = json!("did:exo:alice");
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        assert!(
            v["issues"][0]
                .as_str()
                .expect("issue")
                .contains("current custodian")
        );
    }

    #[test]
    fn execute_verify_chain_of_custody_rejects_non_monotonic_transfer_timestamps() {
        let mut params = valid_custody_verification_params();
        params["chain"][1]["transferred_at_ms"] = json!(1_700_000_000_050_u64);
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
        assert!(
            v["issues"][0]
                .as_str()
                .expect("issue")
                .contains("must be after previous timestamp")
        );
    }

    #[test]
    fn execute_verify_chain_of_custody_allows_creator_only_chain() {
        let mut params = valid_custody_verification_params();
        params["chain"] = json!([]);
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], true);
        assert_eq!(v["chain_length"], 0);
        assert_eq!(v["final_custodian"], "did:exo:alice");
    }

    // -- generate_merkle_proof ------------------------------------------------

    #[test]
    fn generate_merkle_proof_definition_valid() {
        let def = generate_merkle_proof_definition();
        assert_eq!(def.name, "exochain_generate_merkle_proof");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_generate_merkle_proof_success() {
        let params = json!({
            "leaves": ["aabb", "ccdd", "eeff", "1122"],
            "target_index": 1,
        });
        let result = execute_generate_merkle_proof(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert!(v["root"].as_str().is_some());
        assert_eq!(v["target_index"], 1);
        assert_eq!(v["leaf_count"], 4);
        assert!(!v["proof"].as_array().expect("proof array").is_empty());
    }

    #[test]
    fn execute_generate_merkle_proof_out_of_range() {
        let params = json!({"leaves": ["aa"], "target_index": 5});
        let result = execute_generate_merkle_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_generate_merkle_proof_empty() {
        let params = json!({"leaves": [], "target_index": 0});
        let result = execute_generate_merkle_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    // -- verify_cgr_proof -----------------------------------------------------

    #[test]
    fn verify_cgr_proof_definition_valid() {
        let def = verify_cgr_proof_definition();
        assert_eq!(def.name, "exochain_verify_cgr_proof");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn execute_verify_cgr_proof_refuses_hash_only_claims() {
        let params = json!({
            "proof_hash": "abcdef01",
            "invariants_checked": ["consent_required", "no_self_dealing"],
            "verified_at_ms": 1700000000002_u64,
        });
        let result = execute_verify_cgr_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        let error = v["error"].as_str().expect("error string");
        assert!(error.contains("CGR proof verification is unavailable"));
        assert!(error.contains("fix-mcp-cgr-proof-verification-stub.md"));
        assert!(!result.content[0].text().contains("verification_status"));
    }

    #[test]
    fn execute_verify_cgr_proof_invalid_hex() {
        let params = json!({"proof_hash": "zzzz", "invariants_checked": [], "verified_at_ms": 1700000000002_u64});
        let result = execute_verify_cgr_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_verify_cgr_proof_missing_hash() {
        let result = execute_verify_cgr_proof(
            &json!({"invariants_checked": [], "verified_at_ms": 1700000000002_u64}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }
}
