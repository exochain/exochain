//! Identity bindings: DID management, PACE continuity, risk assessment, Shamir

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Split a secret using Shamir's Secret Sharing
#[wasm_bindgen]
pub fn wasm_shamir_split(secret: &[u8], threshold: u8, shares: u8) -> Result<JsValue, JsValue> {
    let config = exo_identity::shamir::ShamirConfig { threshold, shares };
    let result = exo_identity::shamir::split(secret, &config)
        .map_err(|e| JsValue::from_str(&format!("Shamir split error: {e}")))?;
    to_js_value(&result)
}

/// Reconstruct a secret from Shamir shares
#[wasm_bindgen]
pub fn wasm_shamir_reconstruct(
    shares_json: &str,
    threshold: u8,
    total_shares: u8,
) -> Result<JsValue, JsValue> {
    let shares: Vec<exo_identity::shamir::Share> = from_json_str(shares_json)?;
    let config = exo_identity::shamir::ShamirConfig {
        threshold,
        shares: total_shares,
    };
    let secret = exo_identity::shamir::reconstruct(&shares, &config)
        .map_err(|e| JsValue::from_str(&format!("Shamir reconstruct error: {e}")))?;
    to_js_value(&serde_json::json!({
        "secret": hex::encode(&secret),
    }))
}

/// Resolve PACE operator for current state
#[wasm_bindgen]
pub fn wasm_pace_resolve(config_json: &str, state_json: &str) -> Result<JsValue, JsValue> {
    let config: exo_identity::pace::PaceConfig = from_json_str(config_json)?;
    let state: exo_identity::pace::PaceState = from_json_str(state_json)?;
    let operator = exo_identity::pace::resolve_operator(&config, &state);
    to_js_value(&serde_json::json!({
        "operator": operator.as_str(),
        "state": state,
    }))
}

/// Escalate PACE state (Primary -> Alternate -> Contingency -> Emergency)
#[wasm_bindgen]
pub fn wasm_pace_escalate(state_json: &str) -> Result<JsValue, JsValue> {
    let mut state: exo_identity::pace::PaceState = from_json_str(state_json)?;
    let new_state = exo_identity::pace::escalate(&mut state)
        .map_err(|e| JsValue::from_str(&format!("PACE escalation error: {e}")))?;
    to_js_value(&new_state)
}

/// De-escalate PACE state (Emergency -> Contingency -> Alternate -> Normal).
#[wasm_bindgen]
pub fn wasm_pace_deescalate(state_json: &str) -> Result<JsValue, JsValue> {
    let mut state: exo_identity::pace::PaceState = from_json_str(state_json)?;
    let new_state = exo_identity::pace::deescalate(&mut state)
        .map_err(|e| JsValue::from_str(&format!("PACE de-escalation error: {e}")))?;
    to_js_value(&new_state)
}

/// Check whether a risk attestation has expired relative to the current time.
#[wasm_bindgen]
pub fn wasm_is_expired(attestation_json: &str, now_ms: u64) -> Result<bool, JsValue> {
    let attestation: exo_identity::risk::RiskAttestation = from_json_str(attestation_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    Ok(exo_identity::risk::is_expired(&attestation, &now))
}

/// Assess risk for an identity (creates a signed risk attestation)
#[wasm_bindgen]
pub fn wasm_assess_risk(
    subject_did: &str,
    attester_did: &str,
    evidence: &[u8],
    level_json: &str,
    validity_ms: u64,
) -> Result<JsValue, JsValue> {
    let subject = exo_core::Did::new(subject_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let attester = exo_core::Did::new(attester_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let level: exo_identity::risk::RiskLevel = from_json_str(level_json)?;

    let mut clock = exo_core::hlc::HybridClock::new();
    let now = clock.now();

    let context = exo_identity::risk::RiskContext {
        attester_did: attester,
        evidence: evidence.to_vec(),
        now,
        validity_ms,
        level,
    };

    let (_, secret_key) = exo_core::crypto::generate_keypair();
    let attestation = exo_identity::risk::assess_risk(&subject, &context, &secret_key);
    to_js_value(&attestation)
}
