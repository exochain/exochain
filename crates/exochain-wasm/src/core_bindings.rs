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

//! Core bindings: crypto, hashing, BCTS state machine, events, HLC

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

const HASH256_HEX_LEN: usize = 64;
const MAX_WASM_MERKLE_LEAVES: usize = 16_384;
const MAX_WASM_MERKLE_PROOF_HASHES: usize = 256;
const MAX_WASM_MERKLE_LEAVES_JSON_BYTES: usize = (HASH256_HEX_LEN + 4) * MAX_WASM_MERKLE_LEAVES + 2;
const MAX_WASM_MERKLE_PROOF_JSON_BYTES: usize =
    (HASH256_HEX_LEN + 4) * MAX_WASM_MERKLE_PROOF_HASHES + 2;

fn parse_hash256_array(
    json: &str,
    label: &str,
    max_items: usize,
    max_json_bytes: usize,
) -> Result<Vec<exo_core::Hash256>, JsValue> {
    if json.len() > max_json_bytes {
        return Err(JsValue::from_str(&format!(
            "{label} JSON exceeds maximum size of {max_json_bytes} bytes"
        )));
    }

    let hex_values: Vec<String> = from_json_str(json)?;
    if hex_values.len() > max_items {
        return Err(JsValue::from_str(&format!(
            "{label} contains {} hashes, maximum is {max_items}",
            hex_values.len()
        )));
    }

    hex_values
        .iter()
        .enumerate()
        .map(|(idx, h)| {
            if h.len() != HASH256_HEX_LEN {
                return Err(JsValue::from_str(&format!(
                    "{label}[{idx}] must be a 32-byte hash encoded as 64 hex characters"
                )));
            }
            let bytes = hex::decode(h).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                JsValue::from_str(&format!("{label}[{idx}] must decode to 32 bytes"))
            })?;
            Ok(exo_core::Hash256::from_bytes(arr))
        })
        .collect()
}

fn parse_public_key_hex(label: &str, public_hex: &str) -> Result<exo_core::PublicKey, JsValue> {
    let bytes =
        hex::decode(public_hex).map_err(|e| JsValue::from_str(&format!("{label} hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must be 32 bytes")))?;
    if arr.iter().all(|byte| *byte == 0) {
        return Err(JsValue::from_str(&format!("{label} must not be all-zero")));
    }
    Ok(exo_core::PublicKey::from_bytes(arr))
}

fn parse_signature_json(label: &str, signature_json: &str) -> Result<exo_core::Signature, JsValue> {
    let signature: exo_core::Signature = from_json_str(signature_json)?;
    if signature.is_empty() {
        return Err(JsValue::from_str(&format!("{label} must not be empty")));
    }
    Ok(signature)
}

// ── Hashing ──────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_hash_bytes(data: &[u8]) -> String {
    let hash = exo_core::hash::canonical_hash(data);
    hex::encode(hash.as_bytes())
}

#[wasm_bindgen]
pub fn wasm_hash_structured(json: &str) -> Result<String, JsValue> {
    let val: serde_json::Value = from_json_str(json)?;
    let hash = exo_core::hash::hash_structured(&val)
        .map_err(|e| JsValue::from_str(&format!("Hash error: {e}")))?;
    Ok(hex::encode(hash.as_bytes()))
}

// ── Merkle Trees ─────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_merkle_root(leaves_json: &str) -> Result<String, JsValue> {
    let leaves = parse_hash256_array(
        leaves_json,
        "merkle leaves",
        MAX_WASM_MERKLE_LEAVES,
        MAX_WASM_MERKLE_LEAVES_JSON_BYTES,
    )?;
    let root = exo_core::hash::merkle_root(&leaves);
    Ok(hex::encode(root.as_bytes()))
}

// ── Crypto ───────────────────────────────────────────────────────

/// Generate an Ed25519 keypair and return **only the public key**.
///
/// # Security
/// The secret key is **never returned** to JavaScript. This prevents it from
/// landing in the JS heap, appearing in devtools memory snapshots, or being
/// captured by an XSS payload.
///
/// - For one-shot signing use `wasm_sign_with_ephemeral_key`.
/// - For persistent keys use the WebCrypto SubtleCrypto API (BYOK pattern).
#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<JsValue, JsValue> {
    let kp = exo_core::crypto::KeyPair::generate();
    let result = serde_json::json!({
        "public_key": hex::encode(kp.public_key().as_bytes()),
    });
    to_js_value(&result)
}

/// Sign a message with an ephemeral Ed25519 keypair.
///
/// Generates a fresh keypair, signs the message, zeroizes the secret key
/// within the same Rust call, and returns `{signature, public_key}`.
/// The secret key never crosses the Rust/JS boundary.
///
/// Use this for one-shot attestations, event signing, and proof generation.
/// The caller receives the public key alongside the signature so the
/// recipient can verify without any out-of-band key exchange.
#[wasm_bindgen]
pub fn wasm_sign_with_ephemeral_key(message: &[u8]) -> Result<JsValue, JsValue> {
    let (pk, sk) = exo_core::crypto::generate_keypair();
    let sig = exo_core::crypto::sign(message, &sk);
    // sk is dropped here; zeroize feature on ed25519-dalek clears the bytes.
    let result = serde_json::json!({
        "signature": serde_json::to_value(&sig)
            .map_err(|e| JsValue::from_str(&format!("serialize: {e}")))?,
        "public_key": hex::encode(pk.as_bytes()),
    });
    to_js_value(&result)
}

#[wasm_bindgen]
pub fn wasm_sign(_message: &[u8], _secret_hex: &str) -> Result<String, JsValue> {
    Err(JsValue::from_str(
        "raw secret-key signing is disabled at the WASM boundary; use wasm_sign_with_ephemeral_key or sign wasm_event_signing_payload bytes with WebCrypto",
    ))
}

#[wasm_bindgen]
pub fn wasm_ed25519_public_from_secret(_secret_hex: &str) -> Result<String, JsValue> {
    Err(JsValue::from_str(
        "raw secret-key public derivation is disabled at the WASM boundary; derive public keys with WebCrypto or native key management before calling WASM",
    ))
}

#[wasm_bindgen]
pub fn wasm_verify(
    message: &[u8],
    signature_json: &str,
    public_hex: &str,
) -> Result<bool, JsValue> {
    let sig: exo_core::Signature = from_json_str(signature_json)?;
    let pubkey = parse_public_key_hex("public key", public_hex)?;
    Ok(exo_core::crypto::verify(message, &sig, &pubkey))
}

// ── Merkle Proofs ─────────────────────────────────────────────────

/// Compute a Merkle inclusion proof for the leaf at `index` in `leaves`.
///
/// `leaves_json` — JSON array of 32-byte leaf hashes as hex strings.
/// Returns a JSON array of hex-encoded sibling hashes (the proof path).
#[wasm_bindgen]
pub fn wasm_merkle_proof(leaves_json: &str, index: usize) -> Result<JsValue, JsValue> {
    let leaves = parse_hash256_array(
        leaves_json,
        "merkle leaves",
        MAX_WASM_MERKLE_LEAVES,
        MAX_WASM_MERKLE_LEAVES_JSON_BYTES,
    )?;

    let proof = exo_core::hash::merkle_proof(&leaves, index)
        .map_err(|e| JsValue::from_str(&format!("Proof error: {e}")))?;
    let hex_proof: Vec<String> = proof.iter().map(|h| hex::encode(h.as_bytes())).collect();
    to_js_value(&hex_proof)
}

/// Verify a Merkle inclusion proof.
///
/// `root_hex`   — Hex-encoded root hash.
/// `leaf_hex`   — Hex-encoded leaf hash.
/// `proof_json` — JSON array of hex-encoded sibling hashes (as returned by `wasm_merkle_proof`).
/// `index`      — Position of the leaf in the original leaves array.
#[wasm_bindgen]
pub fn wasm_verify_merkle_proof(
    root_hex: &str,
    leaf_hex: &str,
    proof_json: &str,
    index: usize,
) -> Result<bool, JsValue> {
    let root_bytes = hex::decode(root_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let root_arr: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("root must be 32 bytes"))?;
    let root = exo_core::Hash256::from_bytes(root_arr);

    let leaf_bytes = hex::decode(leaf_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let leaf_arr: [u8; 32] = leaf_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("leaf must be 32 bytes"))?;
    let leaf = exo_core::Hash256::from_bytes(leaf_arr);

    let proof = parse_hash256_array(
        proof_json,
        "merkle proof",
        MAX_WASM_MERKLE_PROOF_HASHES,
        MAX_WASM_MERKLE_PROOF_JSON_BYTES,
    )?;

    Ok(exo_core::hash::verify_merkle_proof(
        &root, &leaf, &proof, index,
    ))
}

// ── Events ─────────────────────────────────────────────────────────

fn deterministic_event_id(seed: &[u8]) -> String {
    let mut preimage = b"exo.wasm.event_id.v1".to_vec();
    preimage.extend_from_slice(seed);
    let digest = exo_core::Hash256::digest(&preimage);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    // RFC 9562 UUID version 8 with RFC 4122 variant bits, using caller seed
    // entropy hashed under the domain tag above.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn caller_event_id(event_id: &str) -> Result<exo_core::CorrelationId, JsValue> {
    let uuid = uuid::Uuid::parse_str(event_id)
        .map_err(|e| JsValue::from_str(&format!("event_id: {e}")))?;
    if uuid.is_nil() {
        return Err(JsValue::from_str("event_id must not be the nil UUID"));
    }
    Ok(exo_core::CorrelationId::from_uuid(uuid))
}

fn caller_timestamp(
    physical_ms: u64,
    logical: u32,
    label: &str,
) -> Result<exo_core::Timestamp, JsValue> {
    if physical_ms == 0 {
        return Err(JsValue::from_str(&format!(
            "{label} physical_ms must be caller-supplied and non-zero"
        )));
    }
    Ok(exo_core::Timestamp::new(physical_ms, logical))
}

fn unsigned_event(
    event_type_json: &str,
    payload: &[u8],
    source_did: &str,
    event_id: &str,
    timestamp_physical_ms: u64,
    timestamp_logical: u32,
) -> Result<exo_core::events::Event, JsValue> {
    let event_type: exo_core::events::EventType = from_json_str(event_type_json)?;
    let did = exo_core::Did::new(source_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    Ok(exo_core::events::Event {
        id: caller_event_id(event_id)?,
        timestamp: caller_timestamp(timestamp_physical_ms, timestamp_logical, "event timestamp")?,
        event_type,
        payload: payload.to_vec(),
        source_did: did,
        signature: exo_core::Signature::Empty,
    })
}

/// Derive an event correlation ID from caller-supplied seed bytes.
#[wasm_bindgen]
pub fn wasm_compute_event_id(seed: &[u8]) -> Result<String, JsValue> {
    if seed.is_empty() {
        return Err(JsValue::from_str("event_id seed must not be empty"));
    }
    Ok(deterministic_event_id(seed))
}

/// Verify the Ed25519 signature on a signed event.
///
/// `event_json`  — JSON `Event` (as returned by `wasm_create_signed_event`).
/// `public_hex`  — Hex-encoded 32-byte Ed25519 public key of the event source.
#[wasm_bindgen]
pub fn wasm_verify_event(event_json: &str, public_hex: &str) -> Result<bool, JsValue> {
    let event: exo_core::events::Event = from_json_str(event_json)?;
    let pubkey = parse_public_key_hex("public key", public_hex)?;
    Ok(exo_core::events::verify_event(&event, &pubkey))
}

// ── BCTS State Machine ──────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_bcts_valid_transitions(state_json: &str) -> Result<JsValue, JsValue> {
    let state: exo_core::bcts::BctsState = from_json_str(state_json)?;
    let transitions = state.valid_transitions();
    to_js_value(&transitions)
}

#[wasm_bindgen]
pub fn wasm_bcts_is_terminal(state_json: &str) -> Result<bool, JsValue> {
    let state: exo_core::bcts::BctsState = from_json_str(state_json)?;
    Ok(matches!(
        state,
        exo_core::bcts::BctsState::Closed | exo_core::bcts::BctsState::Denied
    ))
}

// ── Events ───────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn wasm_create_signed_event(
    event_type_json: &str,
    payload: &[u8],
    source_did: &str,
    secret_hex: &str,
    event_id: &str,
    timestamp_physical_ms: u64,
    timestamp_logical: u32,
) -> Result<JsValue, JsValue> {
    let _ = (
        event_type_json,
        payload,
        source_did,
        secret_hex,
        event_id,
        timestamp_physical_ms,
        timestamp_logical,
    );
    Err(JsValue::from_str(
        "raw secret-key event signing is disabled at the WASM boundary; call wasm_event_signing_payload, sign externally, then call wasm_create_event_with_signature",
    ))
}

/// Return canonical event signing bytes as a hex string.
///
/// JavaScript callers sign these bytes with WebCrypto or native key
/// management, then pass the resulting signature to
/// `wasm_create_event_with_signature`.
#[wasm_bindgen]
pub fn wasm_event_signing_payload(
    event_type_json: &str,
    payload: &[u8],
    source_did: &str,
    event_id: &str,
    timestamp_physical_ms: u64,
    timestamp_logical: u32,
) -> Result<String, JsValue> {
    let event = unsigned_event(
        event_type_json,
        payload,
        source_did,
        event_id,
        timestamp_physical_ms,
        timestamp_logical,
    )?;
    let bytes = event
        .signable_bytes()
        .map_err(|_| JsValue::from_str("event signing payload serialization failed"))?;
    Ok(hex::encode(bytes))
}

/// Create an event from a caller-produced Ed25519 signature.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn wasm_create_event_with_signature(
    event_type_json: &str,
    payload: &[u8],
    source_did: &str,
    signature_json: &str,
    public_hex: &str,
    event_id: &str,
    timestamp_physical_ms: u64,
    timestamp_logical: u32,
) -> Result<JsValue, JsValue> {
    let mut event = unsigned_event(
        event_type_json,
        payload,
        source_did,
        event_id,
        timestamp_physical_ms,
        timestamp_logical,
    )?;
    event.signature = parse_signature_json("event signature", signature_json)?;
    let public_key = parse_public_key_hex("event public key", public_hex)?;
    if !exo_core::events::verify_event(&event, &public_key) {
        return Err(JsValue::from_str("event signature verification failed"));
    }
    to_js_value(&event)
}
