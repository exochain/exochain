//! Consent bindings: bailment lifecycle, consent enforcement

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Propose a new bailment (consent-conditioned data sharing)
#[wasm_bindgen]
pub fn wasm_propose_bailment(
    bailor_did: &str,
    bailee_did: &str,
    terms: &[u8],
    bailment_type_json: &str,
) -> Result<JsValue, JsValue> {
    let bailor = exo_core::Did::new(bailor_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let bailee = exo_core::Did::new(bailee_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let bailment_type: exo_consent::BailmentType = from_json_str(bailment_type_json)?;
    let bailment = exo_consent::bailment::propose(&bailor, &bailee, terms, bailment_type);
    to_js_value(&bailment)
}

/// Check if a bailment is currently active
#[wasm_bindgen]
pub fn wasm_bailment_is_active(bailment_json: &str) -> Result<bool, JsValue> {
    let bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    let mut clock = exo_core::hlc::HybridClock::new();
    let now = clock.now();
    Ok(exo_consent::bailment::is_active(&bailment, &now))
}

/// Accept a proposed bailment (bailee countersigns, status → Active).
///
/// `signature_json` — JSON-serialized Ed25519 Signature from the bailee.
#[wasm_bindgen]
pub fn wasm_accept_bailment(
    bailment_json: &str,
    signature_json: &str,
) -> Result<JsValue, JsValue> {
    let mut bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    let sig: exo_core::Signature = from_json_str(signature_json)?;
    exo_consent::bailment::accept(&mut bailment, &sig)
        .map_err(|e| JsValue::from_str(&format!("Accept error: {e}")))?;
    to_js_value(&bailment)
}

/// Terminate an active bailment.
///
/// The `actor_did` must be either the bailor or bailee.
#[wasm_bindgen]
pub fn wasm_terminate_bailment(
    bailment_json: &str,
    actor_did: &str,
) -> Result<JsValue, JsValue> {
    let mut bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    let actor = exo_core::Did::new(actor_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    exo_consent::bailment::terminate(&mut bailment, &actor)
        .map_err(|e| JsValue::from_str(&format!("Terminate error: {e}")))?;
    to_js_value(&bailment)
}
