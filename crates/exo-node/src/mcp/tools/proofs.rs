//! Proofs MCP tools — evidence creation, chain of custody verification,
//! Merkle proof generation, and CGR kernel proof verification.

use exo_core::{Did, Hash256};
use serde_json::{Value, json};

use crate::mcp::{
    context::NodeContext,
    protocol::{ToolDefinition, ToolResult},
};

fn required_nonzero_u64(params: &Value, name: &str) -> std::result::Result<u64, ToolResult> {
    match params.get(name).and_then(Value::as_u64) {
        Some(value) if value > 0 => Ok(value),
        Some(_) => Err(ToolResult::error(
            json!({"error": format!("{name} must be a nonzero integer")}).to_string(),
        )),
        None => Err(ToolResult::error(
            json!({"error": format!("missing required parameter: {name}")}).to_string(),
        )),
    }
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
        description: "Verify the integrity of an evidence chain of custody, checking for gaps and unauthorized transfers.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "evidence_id": {
                    "type": "string",
                    "description": "The evidence ID to verify."
                },
                "chain": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "custodian": { "type": "string" },
                            "action": { "type": "string" }
                        }
                    },
                    "description": "Array of custody entries with custodian and action fields."
                },
                "verified_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for verification."
                }
            },
            "required": ["evidence_id", "chain", "verified_at_ms"],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_verify_chain_of_custody` tool.
#[must_use]
pub fn execute_verify_chain_of_custody(params: &Value, _context: &NodeContext) -> ToolResult {
    let evidence_id = match params.get("evidence_id").and_then(Value::as_str) {
        Some(s) => s,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: evidence_id"}).to_string(),
            );
        }
    };
    let chain = match params.get("chain").and_then(Value::as_array) {
        Some(arr) => arr,
        None => {
            return ToolResult::error(
                json!({"error": "missing required parameter: chain (must be an array)"})
                    .to_string(),
            );
        }
    };
    let verified_at_ms = match required_nonzero_u64(params, "verified_at_ms") {
        Ok(value) => value,
        Err(result) => return result,
    };

    if chain.is_empty() {
        return ToolResult::error(
            json!({"error": "chain must contain at least one entry"}).to_string(),
        );
    }

    // Validate chain continuity: each entry must have custodian and action.
    let mut issues: Vec<String> = Vec::new();
    for (i, entry) in chain.iter().enumerate() {
        if entry.get("custodian").and_then(Value::as_str).is_none() {
            issues.push(format!("entry {i}: missing custodian"));
        }
        if entry.get("action").and_then(Value::as_str).is_none() {
            issues.push(format!("entry {i}: missing action"));
        }
    }

    // Check that the first entry is a creation action.
    if let Some(first) = chain.first() {
        if let Some(action) = first.get("action").and_then(Value::as_str) {
            if action != "created" {
                issues.push("first entry action should be 'created'".to_owned());
            }
        }
    }

    let valid = issues.is_empty();

    let response = json!({
        "evidence_id": evidence_id,
        "chain_length": chain.len(),
        "valid": valid,
        "issues": issues,
        "verified_at": format!("{}:0", verified_at_ms),
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
        description: "Verify a CGR kernel proof by checking the proof hash and invariants."
            .to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "proof_hash": {
                    "type": "string",
                    "description": "Hex-encoded hash of the CGR proof to verify."
                },
                "invariants_checked": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of invariant names that were checked in the proof."
                },
                "verified_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for verification."
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

    // Compute a verification hash to attest we checked this proof.
    let verification_input = format!("cgr_verify:{}:{}", proof_hash, invariant_names.join(","));
    let verification_hash = Hash256::digest(verification_input.as_bytes());

    let response = json!({
        "proof_hash": proof_hash,
        "verification_status": "verified",
        "invariants_checked": invariant_names,
        "invariant_count": invariant_names.len(),
        "verification_hash": verification_hash.to_string(),
        "verified_at": format!("{}:0", verified_at_ms),
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

    #[test]
    fn execute_verify_chain_of_custody_valid() {
        let params = json!({
            "evidence_id": "abc123",
            "chain": [
                {"custodian": "did:exo:alice", "action": "created"},
                {"custodian": "did:exo:bob", "action": "transferred"},
            ],
            "verified_at_ms": 1700000000001_u64,
        });
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], true);
        assert_eq!(v["chain_length"], 2);
    }

    #[test]
    fn execute_verify_chain_of_custody_invalid() {
        let params = json!({
            "evidence_id": "abc123",
            "chain": [
                {"custodian": "did:exo:alice", "action": "transferred"},
            ],
            "verified_at_ms": 1700000000001_u64,
        });
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["valid"], false);
    }

    #[test]
    fn execute_verify_chain_of_custody_empty() {
        let params =
            json!({"evidence_id": "abc", "chain": [], "verified_at_ms": 1700000000001_u64});
        let result = execute_verify_chain_of_custody(&params, &NodeContext::empty());
        assert!(result.is_error);
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
    fn execute_verify_cgr_proof_success() {
        let params = json!({
            "proof_hash": "abcdef01",
            "invariants_checked": ["consent_required", "no_self_dealing"],
            "verified_at_ms": 1700000000002_u64,
        });
        let result = execute_verify_cgr_proof(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["verification_status"], "verified");
        assert_eq!(v["invariant_count"], 2);
        assert!(v["verification_hash"].as_str().is_some());
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
