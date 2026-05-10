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

//! Identity bindings: DID management, PACE continuity, risk assessment, Shamir

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::serde_bridge::*;

const MAX_WASM_SHAMIR_SHARES: usize = u8::MAX as usize;

#[derive(serde::Deserialize)]
struct RiskAssessmentMetadata {
    validity_ms: u64,
    attester_secret_hex: String,
    now_physical_ms: u64,
    #[serde(default)]
    now_logical: u32,
}

fn parse_secret_key_hex(label: &str, value: &str) -> Result<exo_core::SecretKey, JsValue> {
    let bytes = Zeroizing::new(
        hex::decode(value).map_err(|e| JsValue::from_str(&format!("{label}: {e}")))?,
    );
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must be 32 bytes")))?;
    if arr.iter().all(|byte| *byte == 0) {
        return Err(JsValue::from_str(&format!("{label} must not be all-zero")));
    }
    let arr = Zeroizing::new(arr);
    Ok(exo_core::SecretKey::from_bytes(*arr))
}

fn parse_public_key_hex(label: &str, value: &str) -> Result<exo_core::PublicKey, JsValue> {
    let bytes = hex::decode(value).map_err(|e| JsValue::from_str(&format!("{label}: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must be 32 bytes")))?;
    if arr.iter().all(|byte| *byte == 0) {
        return Err(JsValue::from_str(&format!("{label} must not be all-zero")));
    }
    Ok(exo_core::PublicKey::from_bytes(arr))
}

fn parse_timestamp(
    physical_ms: u64,
    logical: u32,
    label: &str,
) -> Result<exo_core::Timestamp, JsValue> {
    if physical_ms == 0 {
        return Err(JsValue::from_str(&format!(
            "{label} timestamp must be caller-supplied HLC"
        )));
    }
    Ok(exo_core::Timestamp::new(physical_ms, logical))
}

/// Split a secret using Shamir's Secret Sharing
#[wasm_bindgen]
pub fn wasm_shamir_split(secret: &[u8], threshold: u8, shares: u8) -> Result<JsValue, JsValue> {
    let config = exo_identity::shamir::ShamirConfig { threshold, shares };
    let result = exo_identity::shamir::split(secret, &config)
        .map_err(|e| JsValue::from_str(&format!("Shamir split error: {e}")))?;
    to_js_value(&result)
}

/// Split a secret using Shamir's Secret Sharing with caller-supplied entropy.
#[wasm_bindgen]
pub fn wasm_shamir_split_with_entropy(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    entropy: &[u8],
) -> Result<JsValue, JsValue> {
    let config = exo_identity::shamir::ShamirConfig { threshold, shares };
    let result = exo_identity::shamir::split_with_entropy(secret, &config, entropy)
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
    let shares: Vec<exo_identity::shamir::Share> =
        from_json_bounded_vec(shares_json, "Shamir shares", MAX_WASM_SHAMIR_SHARES)?;
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
    let operator = exo_identity::pace::resolve_operator(&config, &state)
        .map_err(|e| JsValue::from_str(&format!("PACE resolve error: {e}")))?;
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

/// Assess risk for an identity using caller-supplied signer and HLC metadata.
#[wasm_bindgen]
pub fn wasm_assess_risk(
    subject_did: &str,
    attester_did: &str,
    evidence: &[u8],
    level_json: &str,
    metadata_json: &str,
) -> Result<JsValue, JsValue> {
    let subject = exo_core::Did::new(subject_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let attester = exo_core::Did::new(attester_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let level: exo_identity::risk::RiskLevel = from_json_str(level_json)?;
    let RiskAssessmentMetadata {
        validity_ms,
        attester_secret_hex,
        now_physical_ms,
        now_logical,
    } = from_json_str(metadata_json)?;
    let attester_secret_hex = Zeroizing::new(attester_secret_hex);
    if validity_ms == 0 {
        return Err(JsValue::from_str("validity_ms must be positive"));
    }
    let now = parse_timestamp(now_physical_ms, now_logical, "risk attestation")?;
    now.physical_ms
        .checked_add(validity_ms)
        .ok_or_else(|| JsValue::from_str("risk attestation expiry timestamp overflows u64"))?;
    let secret_key = parse_secret_key_hex("attester_secret_hex", &attester_secret_hex)?;

    let context = exo_identity::risk::RiskContext {
        attester_did: attester,
        evidence: evidence.to_vec(),
        now,
        validity_ms,
        level,
    };

    let attestation = exo_identity::risk::assess_risk(&subject, &context, &secret_key)
        .map_err(|e| JsValue::from_str(&format!("risk attestation error: {e}")))?;
    to_js_value(&attestation)
}

/// Verify a risk attestation against the caller-supplied attester public key.
#[wasm_bindgen]
pub fn wasm_verify_risk_attestation(
    attestation_json: &str,
    attester_public_key_hex: &str,
) -> Result<bool, JsValue> {
    let attestation: exo_identity::risk::RiskAttestation = from_json_str(attestation_json)?;
    let public_key = parse_public_key_hex("attester_public_key_hex", attester_public_key_hex)?;
    Ok(exo_identity::risk::verify_attestation(
        &attestation,
        &public_key,
    ))
}
