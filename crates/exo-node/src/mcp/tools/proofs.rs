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

//! Proofs MCP tools — evidence creation, chain of custody verification,
//! Merkle proof generation, and CGR kernel proof verification.

use exo_core::{
    Did, Hash256, Timestamp,
    hash::{merkle_proof, merkle_root, merkle_root_with_leaf_count},
};
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
const MAX_MERKLE_PROOF_LEAVES: usize = 1024;
const CGR_PROOF_HASH_HEX_CHARS: usize = 64;
const MAX_CGR_INVARIANTS_CHECKED: usize = 16;
const MAX_CGR_INVARIANT_NAME_BYTES: usize = 128;
const CALLER_SUPPLIED_TRUST_BOUNDARY: &str = "caller_supplied_untrusted_metadata";
const NOT_ATTESTED_STATUS: &str = "not_attested";

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
        Some(value) => {
            u32::try_from(value).map_err(|_| tool_error(format!("{name} must fit in u32")))
        }
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
        Some(value) => u32::try_from(value)
            .map_err(|_| tool_error(format!("chain entry {index}: {name} must fit in u32"))),
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

fn required_hash256_hex_claim(params: &Value, name: &str) -> std::result::Result<(), ToolResult> {
    let value = match params.get(name).and_then(Value::as_str) {
        Some(value) => value,
        None => return Err(tool_error(format!("missing required parameter: {name}"))),
    };

    if value.len() != CGR_PROOF_HASH_HEX_CHARS {
        return Err(tool_error(format!(
            "{name} must be exactly {CGR_PROOF_HASH_HEX_CHARS} hex characters"
        )));
    }

    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(tool_error(format!("{name} must be valid hexadecimal")));
    }

    Ok(())
}

fn required_bounded_string_array_len(
    params: &Value,
    name: &str,
    max_items: usize,
    max_item_bytes: usize,
) -> std::result::Result<usize, ToolResult> {
    let items = match params.get(name).and_then(Value::as_array) {
        Some(items) => items,
        None => {
            return Err(tool_error(format!(
                "missing required parameter: {name} (must be an array)"
            )));
        }
    };

    if items.len() > max_items {
        return Err(tool_error(format!(
            "{name} may contain at most {max_items} entries"
        )));
    }

    for (index, item) in items.iter().enumerate() {
        let Some(value) = item.as_str() else {
            return Err(tool_error(format!("{name}[{index}] must be a string")));
        };
        if value.trim().is_empty() {
            return Err(tool_error(format!("{name}[{index}] must not be empty")));
        }
        if value.len() > max_item_bytes {
            return Err(tool_error(format!(
                "{name}[{index}] may contain at most {max_item_bytes} bytes"
            )));
        }
    }

    Ok(items.len())
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
        description: "Construct an unpersisted draft legal evidence envelope from caller-supplied UUID, content hash, creator DID, and creation HLC. Returns a verifier-compatible creator-only custody payload marked not_attested; it does not persist evidence, bind trusted HLC time, authenticate the creator, or check uniqueness.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
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
                    "description": "DID of the evidence creator and initial custodian."
                },
                "evidence_id": {
                    "type": "string",
                    "description": "Caller-supplied non-nil evidence UUID. This value is not uniqueness-checked by the MCP tool."
                },
                "created_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds for the draft envelope; not a server-observed or trusted HLC time."
                },
                "created_at_logical": {
                    "type": "integer",
                    "description": "Caller-supplied HLC logical counter for the draft envelope; not a server-observed or trusted HLC time."
                }
            },
            "required": [
                "evidence_id",
                "evidence_type",
                "content_hash",
                "creator_did",
                "created_at_ms",
                "created_at_logical"
            ],
            "additionalProperties": false,
        }),
    }
}

/// Execute the `exochain_create_evidence` tool.
#[must_use]
pub fn execute_create_evidence(params: &Value, _context: &NodeContext) -> ToolResult {
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
    let created_at = Timestamp::new(created_at_ms, created_at_logical);
    let evidence = match create_evidence_from_hash(
        evidence_id,
        content_hash,
        &creator_did,
        evidence_type,
        created_at,
    ) {
        Ok(value) => value,
        Err(err) => return tool_error(err.to_string()),
    };
    let custody_digest = match custody_chain_digest(&evidence) {
        Ok(value) => value,
        Err(err) => return tool_error(err.to_string()),
    };

    let response = json!({
        "evidence_id": evidence_id_str,
        "evidence_type": evidence.type_tag.as_str(),
        "content_hash": evidence.hash.to_string(),
        "creator_did": evidence.creator.to_string(),
        "created_at": evidence.timestamp.to_string(),
        "created_at_ms": created_at_ms,
        "created_at_logical": created_at_logical,
        "chain": [],
        "final_custodian": final_custodian(&evidence).to_string(),
        "claimed_admissibility_status": &evidence.admissibility_status,
        "custody_digest": custody_digest.to_string(),
        "status": "draft_unattested",
        "attestation_status": NOT_ATTESTED_STATUS,
        "trust_boundary": CALLER_SUPPLIED_TRUST_BOUNDARY,
        "persistence": "not_persisted",
        "trusted_hlc_bound": false,
        "authenticated_actor_bound": false,
        "uniqueness_checked": false,
        "metadata_sources": {
            "evidence_id": "caller_supplied",
            "evidence_type": "caller_supplied",
            "content_hash": "caller_supplied",
            "creator_did": "caller_supplied",
            "created_at": "caller_supplied",
        },
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
        description: "Verify caller-supplied evidence chain-of-custody metadata using EXOCHAIN legal evidence rules, checking UUID/DID/hash metadata, transfer continuity, reasons, and monotonic HLC timestamps. The result is a deterministic validation of the supplied payload only; it is not persisted, not a legal-store attestation, and not bound to trusted server time.".to_owned(),
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
                    "description": "Caller-supplied nonzero HLC physical milliseconds for the local validation record; not a trusted server-observed verification time."
                },
                "verified_at_logical": {
                    "type": "integer",
                    "description": "Caller-supplied HLC logical counter for the local validation record; not a trusted server-observed verification time."
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
                    "verified_at_source": "caller_supplied",
                    "verification_scope": "caller_supplied_payload_only",
                    "attestation_status": NOT_ATTESTED_STATUS,
                    "trust_boundary": CALLER_SUPPLIED_TRUST_BOUNDARY,
                    "persistence": "not_persisted",
                    "trusted_hlc_bound": false,
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
                "verified_at_source": "caller_supplied",
                "verification_scope": "caller_supplied_payload_only",
                "attestation_status": NOT_ATTESTED_STATUS,
                "trust_boundary": CALLER_SUPPLIED_TRUST_BOUNDARY,
                "persistence": "not_persisted",
                "trusted_hlc_bound": false,
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
        "verified_at_source": "caller_supplied",
        "verification_scope": "caller_supplied_payload_only",
        "attestation_status": NOT_ATTESTED_STATUS,
        "trust_boundary": CALLER_SUPPLIED_TRUST_BOUNDARY,
        "persistence": "not_persisted",
        "trusted_hlc_bound": false,
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
        description: "Generate a verifier-compatible Merkle inclusion proof for a target event hash given a set of event hashes. Computes the actual Merkle root and proof path.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "leaves": {
                    "type": "array",
                    "items": { "type": "string" },
                    "maxItems": MAX_MERKLE_PROOF_LEAVES,
                    "description": "Array of 64-character hex-encoded Hash256 event hashes."
                },
                "target_index": {
                    "type": "integer",
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
        Some(n) => match usize::try_from(n) {
            Ok(index) => index,
            Err(_) => {
                return ToolResult::error(
                    json!({"error": "target_index must fit in usize"}).to_string(),
                );
            }
        },
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

    if leaves_val.len() > MAX_MERKLE_PROOF_LEAVES {
        return ToolResult::error(
            json!({
                "error": format!(
                    "leaves may contain at most {MAX_MERKLE_PROOF_LEAVES} hashes"
                )
            })
            .to_string(),
        );
    }

    if target_index >= leaves_val.len() {
        return ToolResult::error(
            json!({"error": format!("target_index {} out of range (0..{})", target_index, leaves_val.len())})
                .to_string(),
        );
    }

    // Parse each supplied leaf as the exact event hash consumed by
    // exochain_verify_inclusion. Do not hash arbitrary caller bytes here.
    let mut hashes: Vec<Hash256> = Vec::with_capacity(leaves_val.len());
    for (i, leaf) in leaves_val.iter().enumerate() {
        match leaf.as_str() {
            Some(s) => match parse_hash256_hex(s, &format!("leaf at index {i}")) {
                Ok(hash) if hash != Hash256::ZERO => hashes.push(hash),
                Ok(_) => {
                    return ToolResult::error(
                        json!({"error": format!("leaf at index {i} must not be Hash256::ZERO")})
                            .to_string(),
                    );
                }
                Err(result) => return result,
            },
            None => {
                return ToolResult::error(
                    json!({"error": format!("leaf at index {i} is not a string")}).to_string(),
                );
            }
        }
    }

    let tree_root = merkle_root(&hashes);
    let root_hash = merkle_root_with_leaf_count(&hashes);
    let proof_hashes = match merkle_proof(&hashes, target_index) {
        Ok(proof) => proof.iter().map(ToString::to_string).collect::<Vec<_>>(),
        Err(err) => return ToolResult::error(json!({"error": err.to_string()}).to_string()),
    };
    let target_hash = hashes[target_index].to_string();

    let response = json!({
        "root": root_hash.to_string(),
        "root_hash": root_hash.to_string(),
        "tree_root": tree_root.to_string(),
        "leaf_count_bound_root": root_hash.to_string(),
        "target_leaf": target_hash,
        "target_hash": target_hash,
        "event_hash": target_hash,
        "target_index": target_index,
        "proof": proof_hashes,
        "proof_hashes": proof_hashes,
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
                    "minLength": CGR_PROOF_HASH_HEX_CHARS,
                    "maxLength": CGR_PROOF_HASH_HEX_CHARS,
                    "description": "Hex-encoded hash claim for the CGR proof. Hash-only verification is refused."
                },
                "invariants_checked": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "maxLength": MAX_CGR_INVARIANT_NAME_BYTES
                    },
                    "maxItems": MAX_CGR_INVARIANTS_CHECKED,
                    "description": "Caller-declared invariant names. These are not accepted as proof of verification."
                },
                "verified_at_ms": {
                    "type": "integer",
                    "description": "Caller-supplied nonzero HLC physical milliseconds accepted only for backward-compatible request validation; it is not returned as a trusted refusal timestamp."
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
    if let Err(result) = required_hash256_hex_claim(params, "proof_hash") {
        return result;
    };
    let invariant_count = match required_bounded_string_array_len(
        params,
        "invariants_checked",
        MAX_CGR_INVARIANTS_CHECKED,
        MAX_CGR_INVARIANT_NAME_BYTES,
    ) {
        Ok(count) => count,
        Err(result) => return result,
    };
    if let Err(result) = required_nonzero_u64(params, "verified_at_ms") {
        return result;
    }

    ToolResult::error(
        json!({
            "error": format!(
                "CGR proof verification is unavailable: exochain_verify_cgr_proof has no proof bytes, public inputs, checkpoint root, validator signature set, or production CGR proof verifier wired; refusing hash-only verification claims. See {MCP_CGR_PROOF_INITIATIVE}."
            ),
            "invariant_count": invariant_count,
            "refusal_time_source": "not_recorded_without_trusted_hlc",
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
    use crate::mcp::tools::ledger::execute_verify_inclusion;

    // -- create_evidence ------------------------------------------------------

    #[test]
    fn create_evidence_definition_valid() {
        let def = create_evidence_definition();
        assert_eq!(def.name, "exochain_create_evidence");
        assert!(!def.description.is_empty());
    }

    fn valid_create_evidence_params() -> Value {
        json!({
            "evidence_type": "document",
            "content_hash": "0202020202020202020202020202020202020202020202020202020202020202",
            "creator_did": "did:exo:alice",
            "evidence_id": "00000000-0000-0000-0000-000000000001",
            "created_at_ms": 1700000000000_u64,
            "created_at_logical": 7_u64,
        })
    }

    #[test]
    fn execute_create_evidence_success_returns_verifier_compatible_envelope() {
        let params = valid_create_evidence_params();
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(!result.is_error, "{}", result.content[0].text());
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert_eq!(v["evidence_id"], "00000000-0000-0000-0000-000000000001");
        assert_eq!(v["evidence_type"], "document");
        assert_eq!(
            v["content_hash"],
            "0202020202020202020202020202020202020202020202020202020202020202"
        );
        assert_eq!(v["creator_did"], "did:exo:alice");
        assert_eq!(v["created_at_ms"], 1700000000000_u64);
        assert_eq!(v["created_at_logical"], 7_u64);
        assert_eq!(v["chain"], json!([]));
        assert_eq!(v["final_custodian"], "did:exo:alice");
        assert_eq!(v["claimed_admissibility_status"], "Pending");
        assert!(v.get("admissibility_status").is_none());
        assert_eq!(v["status"], "draft_unattested");
        assert_eq!(v["attestation_status"], "not_attested");
        assert_eq!(v["trust_boundary"], "caller_supplied_untrusted_metadata");
        assert_eq!(v["persistence"], "not_persisted");
        assert_eq!(v["trusted_hlc_bound"], false);
        assert_eq!(v["authenticated_actor_bound"], false);
        assert_eq!(v["uniqueness_checked"], false);
        assert_eq!(v["metadata_sources"]["evidence_id"], "caller_supplied");
        assert_eq!(v["metadata_sources"]["created_at"], "caller_supplied");
        assert_eq!(v["metadata_sources"]["creator_did"], "caller_supplied");
        assert_eq!(v["metadata_sources"]["content_hash"], "caller_supplied");
        assert_eq!(
            v["custody_digest"].as_str().expect("custody digest").len(),
            64
        );
    }

    #[test]
    fn execute_create_evidence_rejects_legacy_shape_without_content_hash() {
        let params = json!({
            "description": "Contract PDF",
            "evidence_type": "document",
            "source_did": "did:exo:alice",
            "evidence_id": "00000000-0000-0000-0000-000000000001",
            "created_at_ms": 1700000000000_u64,
        });
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("content_hash"),
            "legacy shape-only evidence creation must be refused with required content hash metadata"
        );
    }

    #[test]
    fn execute_create_evidence_invalid_did() {
        let mut params = valid_create_evidence_params();
        params["creator_did"] = json!("bad");
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(result.is_error);
    }

    #[test]
    fn execute_create_evidence_rejects_missing_hlc_logical_time() {
        let result = execute_create_evidence(
            &json!({
                "evidence_type": "doc",
                "content_hash": "0202020202020202020202020202020202020202020202020202020202020202",
                "creator_did": "did:exo:a",
                "evidence_id": "00000000-0000-0000-0000-000000000001",
                "created_at_ms": 1700000000000_u64
            }),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("created_at_logical"),
            "full HLC logical counter must be required"
        );
    }

    #[test]
    fn execute_create_evidence_rejects_zero_content_hash() {
        let mut params = valid_create_evidence_params();
        params["content_hash"] =
            json!("0000000000000000000000000000000000000000000000000000000000000000");
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0]
                .text()
                .contains("content hash must not be Hash256::ZERO"),
            "zero hashes are placeholders and must be refused"
        );
    }

    #[test]
    fn execute_create_evidence_rejects_nil_uuid() {
        let mut params = valid_create_evidence_params();
        params["evidence_id"] = json!("00000000-0000-0000-0000-000000000000");
        let result = execute_create_evidence(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("evidence ID must"),
            "nil UUID placeholders must be refused"
        );
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
        assert_eq!(v["verification_scope"], "caller_supplied_payload_only");
        assert_eq!(v["attestation_status"], "not_attested");
        assert_eq!(v["persistence"], "not_persisted");
        assert_eq!(v["verified_at_source"], "caller_supplied");
        assert_eq!(v["trusted_hlc_bound"], false);
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
    fn generate_merkle_proof_definition_bounds_leaves() {
        let def = generate_merkle_proof_definition();

        assert_eq!(
            def.input_schema["properties"]["leaves"]["maxItems"],
            MAX_MERKLE_PROOF_LEAVES
        );
    }

    #[test]
    fn execute_generate_merkle_proof_success() {
        let leaves = [
            Hash256::digest(b"event-0").to_string(),
            Hash256::digest(b"event-1").to_string(),
            Hash256::digest(b"event-2").to_string(),
            Hash256::digest(b"event-3").to_string(),
        ];
        let params = json!({
            "leaves": leaves,
            "target_index": 1,
        });
        let result = execute_generate_merkle_proof(&params, &NodeContext::empty());
        assert!(!result.is_error);
        let v: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");
        assert!(v["root_hash"].as_str().is_some());
        assert_eq!(v["root"], v["root_hash"]);
        assert_eq!(v["leaf_count_bound_root"], v["root_hash"]);
        assert_ne!(v["tree_root"], v["root_hash"]);
        assert_eq!(v["event_hash"], leaves[1]);
        assert_eq!(v["target_hash"], leaves[1]);
        assert_eq!(v["target_index"], 1);
        assert_eq!(v["leaf_count"], 4);
        assert_eq!(v["proof"], v["proof_hashes"]);
        assert!(
            !v["proof_hashes"]
                .as_array()
                .expect("proof array")
                .is_empty()
        );
    }

    #[test]
    fn execute_generate_merkle_proof_output_verifies_with_verify_inclusion() {
        let leaves = [
            Hash256::digest(b"event-0").to_string(),
            Hash256::digest(b"event-1").to_string(),
            Hash256::digest(b"event-2").to_string(),
        ];
        let result = execute_generate_merkle_proof(
            &json!({
                "leaves": leaves,
                "target_index": 2,
            }),
            &NodeContext::empty(),
        );
        assert!(!result.is_error, "{}", result.content[0].text());
        let generated: Value = serde_json::from_str(result.content[0].text()).expect("valid JSON");

        let verify_result = execute_verify_inclusion(
            &json!({
                "event_hash": generated["event_hash"].clone(),
                "proof_hashes": generated["proof_hashes"].clone(),
                "root_hash": generated["root_hash"].clone(),
                "target_index": generated["target_index"].clone(),
                "leaf_count": generated["leaf_count"].clone(),
            }),
            &NodeContext::empty(),
        );
        assert!(
            !verify_result.is_error,
            "{}",
            verify_result.content[0].text()
        );
        let verified: Value =
            serde_json::from_str(verify_result.content[0].text()).expect("valid JSON");
        assert_eq!(verified["verified"], true);
        assert_eq!(verified["computed_root"], generated["root_hash"]);
    }

    #[test]
    fn execute_generate_merkle_proof_rejects_short_raw_leaf_bytes() {
        let params = json!({"leaves": ["aabb", "ccdd"], "target_index": 0});
        let result = execute_generate_merkle_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("32 bytes"),
            "Merkle generation must accept event hashes, not hash arbitrary short raw leaf bytes"
        );
    }

    #[test]
    fn execute_generate_merkle_proof_rejects_zero_leaf_hashes() {
        let params = json!({
            "leaves": [
                "0000000000000000000000000000000000000000000000000000000000000000",
                Hash256::digest(b"event-1").to_string()
            ],
            "target_index": 0,
        });
        let result = execute_generate_merkle_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(
            result.content[0].text().contains("Hash256::ZERO"),
            "zero leaf hashes are placeholders and must be refused"
        );
    }

    #[test]
    fn execute_generate_merkle_proof_rejects_excessive_leaf_count() {
        let leaves: Vec<Value> = (0..=MAX_MERKLE_PROOF_LEAVES)
            .map(|idx| {
                Value::String(Hash256::digest(format!("event-{idx}").as_bytes()).to_string())
            })
            .collect();
        let result = execute_generate_merkle_proof(
            &json!({
                "leaves": leaves,
                "target_index": 0,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        assert!(
            result.content[0].text().contains(&format!(
                "leaves may contain at most {MAX_MERKLE_PROOF_LEAVES} hashes"
            )),
            "oversized leaf arrays must be rejected before proof construction"
        );
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
    fn verify_cgr_proof_definition_bounds_inputs() {
        let def = verify_cgr_proof_definition();

        assert_eq!(
            def.input_schema["properties"]["proof_hash"]["minLength"],
            64
        );
        assert_eq!(
            def.input_schema["properties"]["proof_hash"]["maxLength"],
            64
        );
        assert_eq!(
            def.input_schema["properties"]["invariants_checked"]["maxItems"],
            16
        );
        assert_eq!(
            def.input_schema["properties"]["invariants_checked"]["items"]["maxLength"],
            128
        );
    }

    #[test]
    fn execute_verify_cgr_proof_refuses_hash_only_claims() {
        let params = json!({
            "proof_hash": "ab".repeat(32),
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
        assert!(v.get("refused_at").is_none());
        assert_eq!(v["refusal_time_source"], "not_recorded_without_trusted_hlc");
    }

    #[test]
    fn execute_verify_cgr_proof_rejects_oversized_hash_without_echoing() {
        let oversized_hash = "ab".repeat(4096);
        let result = execute_verify_cgr_proof(
            &json!({
                "proof_hash": oversized_hash,
                "invariants_checked": [],
                "verified_at_ms": 1700000000002_u64,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("proof_hash must be exactly 64 hex characters"));
        assert!(
            !text.contains(&oversized_hash),
            "validation errors must not reflect unbounded proof_hash input"
        );
    }

    #[test]
    fn execute_verify_cgr_proof_rejects_excessive_invariants_without_echoing() {
        let invariants: Vec<String> = (0..=16)
            .map(|idx| format!("SensitiveInvariantName{idx}"))
            .collect();
        let result = execute_verify_cgr_proof(
            &json!({
                "proof_hash": "ab".repeat(32),
                "invariants_checked": invariants,
                "verified_at_ms": 1700000000002_u64,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(text.contains("invariants_checked may contain at most 16 entries"));
        assert!(
            !text.contains("SensitiveInvariantName16"),
            "validation errors must not reflect unbounded invariant names"
        );
    }

    #[test]
    fn execute_verify_cgr_proof_refusal_does_not_echo_caller_inputs() {
        let proof_hash = "cd".repeat(32);
        let invariant_name = "SensitiveTenantSpecificInvariant";
        let result = execute_verify_cgr_proof(
            &json!({
                "proof_hash": proof_hash,
                "invariants_checked": [invariant_name],
                "verified_at_ms": 1700000000002_u64,
            }),
            &NodeContext::empty(),
        );

        assert!(result.is_error);
        let text = result.content[0].text();
        assert!(!text.contains(&proof_hash));
        assert!(!text.contains(invariant_name));
        let v: Value = serde_json::from_str(text).expect("valid JSON");
        assert_eq!(v["invariant_count"], 1);
    }

    #[test]
    fn execute_verify_cgr_proof_invalid_hex() {
        let params = json!({"proof_hash": "zz".repeat(32), "invariants_checked": [], "verified_at_ms": 1700000000002_u64});
        let result = execute_verify_cgr_proof(&params, &NodeContext::empty());
        assert!(result.is_error);
        assert!(result.content[0].text().contains("valid hexadecimal"));
    }

    #[test]
    fn execute_verify_cgr_proof_missing_hash() {
        let result = execute_verify_cgr_proof(
            &json!({"invariants_checked": [], "verified_at_ms": 1700000000002_u64}),
            &NodeContext::empty(),
        );
        assert!(result.is_error);
    }

    #[test]
    fn proof_tools_do_not_emit_authoritative_statuses_from_caller_metadata() {
        let source = include_str!("proofs.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("tests marker present");
        for forbidden in [
            "\"status\": \"created\"",
            "\"verification_status\": \"verified\"",
            "\"refused_at\"",
            "\"admissibility_status\": &evidence.admissibility_status",
        ] {
            assert!(
                !production.contains(forbidden),
                "MCP proof tools must not emit authoritative status from caller-supplied metadata: {forbidden}"
            );
        }
    }
}
