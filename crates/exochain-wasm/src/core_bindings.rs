//! Core bindings: crypto, hashing, BCTS state machine, events, HLC

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

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
    let hex_leaves: Vec<String> = from_json_str(leaves_json)?;
    let leaves: Vec<exo_core::Hash256> = hex_leaves
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("hex: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "not 32 bytes")?;
            Ok(exo_core::Hash256::from_bytes(arr))
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsValue::from_str(&e))?;
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
pub fn wasm_sign(message: &[u8], secret_hex: &str) -> Result<String, JsValue> {
    let secret_bytes =
        hex::decode(secret_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("secret key must be 32 bytes"))?;
    let secret = exo_core::SecretKey::from_bytes(arr);
    let sig = exo_core::crypto::sign(message, &secret);
    let sig_json =
        serde_json::to_string(&sig).map_err(|e| JsValue::from_str(&format!("serialize: {e}")))?;
    Ok(sig_json)
}

#[wasm_bindgen]
pub fn wasm_ed25519_public_from_secret(secret_hex: &str) -> Result<String, JsValue> {
    let secret_bytes =
        hex::decode(secret_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("secret key must be 32 bytes"))?;
    let keypair = exo_core::crypto::KeyPair::from_secret_bytes(arr)
        .map_err(|e| JsValue::from_str(&format!("keypair: {e}")))?;
    Ok(hex::encode(keypair.public_key().as_bytes()))
}

#[wasm_bindgen]
pub fn wasm_verify(
    message: &[u8],
    signature_json: &str,
    public_hex: &str,
) -> Result<bool, JsValue> {
    let sig: exo_core::Signature = from_json_str(signature_json)?;
    let pub_bytes = hex::decode(public_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("public key must be 32 bytes"))?;
    let pubkey = exo_core::PublicKey::from_bytes(arr);
    Ok(exo_core::crypto::verify(message, &sig, &pubkey))
}

// ── Merkle Proofs ─────────────────────────────────────────────────

/// Compute a Merkle inclusion proof for the leaf at `index` in `leaves`.
///
/// `leaves_json` — JSON array of 32-byte leaf hashes as hex strings.
/// Returns a JSON array of hex-encoded sibling hashes (the proof path).
#[wasm_bindgen]
pub fn wasm_merkle_proof(leaves_json: &str, index: usize) -> Result<JsValue, JsValue> {
    let hex_leaves: Vec<String> = from_json_str(leaves_json)?;
    let leaves: Vec<exo_core::Hash256> = hex_leaves
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("hex: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "not 32 bytes")?;
            Ok(exo_core::Hash256::from_bytes(arr))
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsValue::from_str(&e))?;

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

    let hex_proof: Vec<String> = from_json_str(proof_json)?;
    let proof: Vec<exo_core::Hash256> = hex_proof
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).map_err(|e| format!("hex: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "not 32 bytes")?;
            Ok(exo_core::Hash256::from_bytes(arr))
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| JsValue::from_str(&e))?;

    Ok(exo_core::hash::verify_merkle_proof(
        &root, &leaf, &proof, index,
    ))
}

// ── Events ─────────────────────────────────────────────────────────

/// Generate a fresh event correlation ID.
#[wasm_bindgen]
pub fn wasm_compute_event_id() -> String {
    exo_core::CorrelationId::new().to_string()
}

/// Verify the Ed25519 signature on a signed event.
///
/// `event_json`  — JSON `Event` (as returned by `wasm_create_signed_event`).
/// `public_hex`  — Hex-encoded 32-byte Ed25519 public key of the event source.
#[wasm_bindgen]
pub fn wasm_verify_event(event_json: &str, public_hex: &str) -> Result<bool, JsValue> {
    let event: exo_core::events::Event = from_json_str(event_json)?;
    let pub_bytes = hex::decode(public_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("public key must be 32 bytes"))?;
    let pubkey = exo_core::PublicKey::from_bytes(arr);
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
) -> Result<JsValue, JsValue> {
    let event_type: exo_core::events::EventType = from_json_str(event_type_json)?;
    let did = exo_core::Did::new(source_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let secret_bytes =
        hex::decode(secret_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("secret key must be 32 bytes"))?;
    let secret = exo_core::SecretKey::from_bytes(arr);

    let mut clock = exo_core::hlc::HybridClock::new();
    let ts = clock.now();
    let corr = exo_core::CorrelationId::new();

    let event =
        exo_core::events::create_signed_event(corr, ts, event_type, payload.to_vec(), did, &secret);
    to_js_value(&event)
}
