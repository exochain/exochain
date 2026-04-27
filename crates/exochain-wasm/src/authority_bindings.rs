//! Authority bindings: delegation chain verification, permission checking

use std::collections::BTreeMap;

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Build and validate an authority chain from delegation links
#[wasm_bindgen]
pub fn wasm_build_authority_chain(links_json: &str) -> Result<JsValue, JsValue> {
    let links: Vec<exo_authority::AuthorityLink> = from_json_str(links_json)?;
    let chain = exo_authority::chain::build_chain(&links)
        .map_err(|e| JsValue::from_str(&format!("Chain error: {e}")))?;
    to_js_value(&chain)
}

/// Build authority chain with depth limit
#[wasm_bindgen]
pub fn wasm_build_authority_chain_with_depth(
    links_json: &str,
    max_depth: usize,
) -> Result<JsValue, JsValue> {
    let links: Vec<exo_authority::AuthorityLink> = from_json_str(links_json)?;
    let chain = exo_authority::chain::build_chain_with_depth(&links, max_depth)
        .map_err(|e| JsValue::from_str(&format!("Chain error: {e}")))?;
    to_js_value(&chain)
}

/// Check if an authority chain has a specific permission
#[wasm_bindgen]
pub fn wasm_has_permission(chain_json: &str, permission_json: &str) -> Result<bool, JsValue> {
    let chain: exo_authority::AuthorityChain = from_json_str(chain_json)?;
    let permission: exo_authority::Permission = from_json_str(permission_json)?;
    Ok(exo_authority::chain::has_permission(&chain, &permission))
}

/// Verify an authority chain against a public-key lookup table.
///
/// `chain_json`   — JSON `AuthorityChain`.
/// `now_ms`       — Current timestamp in milliseconds (hybrid logical clock).
/// `keys_json`    — JSON array of `[did_str, public_key_hex]` pairs used to
///                  resolve each delegator's Ed25519 public key.
///
/// Returns `{ok: true}` if the chain is cryptographically valid and all links
/// are unexpired, or `{ok: false, error: "..."}`.
#[wasm_bindgen]
pub fn wasm_verify_authority_chain(
    chain_json: &str,
    now_ms: u64,
    keys_json: &str,
) -> Result<JsValue, JsValue> {
    let chain: exo_authority::AuthorityChain = from_json_str(chain_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    let key_pairs: Vec<(String, String)> = from_json_str(keys_json)?;

    // Build deterministic lookup table from the caller-supplied key list.
    let mut lookup: BTreeMap<exo_core::Did, exo_core::PublicKey> = BTreeMap::new();
    for (did_str, key_hex) in &key_pairs {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        let key_bytes =
            hex::decode(key_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
        let arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("public key must be 32 bytes"))?;
        lookup.insert(did, exo_core::PublicKey::from_bytes(arr));
    }

    let resolve = |did: &exo_core::Did| lookup.get(did).copied();
    match exo_authority::chain::verify_chain(&chain, &now, resolve) {
        Ok(()) => to_js_value(&serde_json::json!({"ok": true})),
        Err(e) => to_js_value(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}
