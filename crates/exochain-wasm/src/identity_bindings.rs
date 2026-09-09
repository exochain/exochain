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
use zeroize::{Zeroize, Zeroizing};

use crate::serde_bridge::*;

const MAX_WASM_SHAMIR_SHARES: usize = u8::MAX as usize;
const MAX_WASM_SHAMIR_SECRET_BYTES: usize = 4_096;
const MAX_WASM_SHAMIR_ENTROPY_BYTES: usize = 4_096;
const MAX_WASM_SHAMIR_SHARE_DATA_BYTES: usize = 262_144;
const MAX_WASM_SHAMIR_RESPONSE_BYTES: usize = 1_044_482;
const MAX_WASM_SHAMIR_GF_WORK_UNITS: usize = 1_048_576;
const MAX_WASM_SHAMIR_HASH_WORK_BYTES: usize = 16_777_216;
const SHAMIR_COEFFICIENT_FIXED_HASH_BYTES: usize = 128;
const SHAMIR_SPLIT_RESPONSE_ERROR: &str = "Shamir split error: response serialization failed";
const SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR: &str = "Shamir split error: WASM resource limit exceeded";
const SHAMIR_RECONSTRUCT_ERROR: &str = "Shamir reconstruct error: invalid shares";
const SHAMIR_RECONSTRUCT_RESPONSE_ERROR: &str =
    "Shamir reconstruct error: response serialization failed";
const SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR: &str =
    "Shamir reconstruct error: WASM resource limit exceeded";

#[derive(serde::Serialize)]
struct ShamirSecretResponse<'a> {
    secret: &'a str,
}

struct FixedLimitJsonWriter<'a> {
    bytes: &'a mut Zeroizing<Vec<u8>>,
    limit: usize,
}

impl std::io::Write for FixedLimitJsonWriter<'_> {
    fn write(&mut self, incoming: &[u8]) -> std::io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(incoming.len())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "JSON response length overflow",
                )
            })?;
        if next_len > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "JSON response exceeds reserved capacity",
            ));
        }
        self.bytes.extend_from_slice(incoming);
        Ok(incoming.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_shamir_shares_response<T, E>(
    shares: &[exo_identity::shamir::Share],
    parse_json: impl FnOnce(&str) -> Result<T, E>,
) -> Result<T, &'static str> {
    const JSON_FIXED_BYTES_PER_SHARE: usize = 256;

    let json_upper_bound = shares.iter().try_fold(2usize, |bound, share| {
        let data_bound = share.data.len().checked_mul(4)?;
        bound
            .checked_add(JSON_FIXED_BYTES_PER_SHARE)?
            .checked_add(data_bound)
    });
    let Some(json_upper_bound) = json_upper_bound else {
        return Err(SHAMIR_SPLIT_RESPONSE_ERROR);
    };
    if json_upper_bound > MAX_WASM_SHAMIR_RESPONSE_BYTES {
        return Err(SHAMIR_SPLIT_RESPONSE_ERROR);
    }
    let mut serialized = Zeroizing::new(Vec::new());
    if serialized.try_reserve_exact(json_upper_bound).is_err() {
        serialized.zeroize();
        return Err(SHAMIR_SPLIT_RESPONSE_ERROR);
    }
    let reserved_capacity = serialized.capacity();
    let serialization_result = {
        let mut writer = FixedLimitJsonWriter {
            bytes: &mut serialized,
            limit: json_upper_bound,
        };
        serde_json::to_writer(&mut writer, shares)
    };
    if serialization_result.is_err() {
        serialized.zeroize();
        return Err(SHAMIR_SPLIT_RESPONSE_ERROR);
    }
    if serialized.len() > json_upper_bound || serialized.capacity() != reserved_capacity {
        serialized.zeroize();
        return Err(SHAMIR_SPLIT_RESPONSE_ERROR);
    }
    let json = match std::str::from_utf8(serialized.as_slice()) {
        Ok(json) => json,
        Err(_) => {
            serialized.zeroize();
            return Err(SHAMIR_SPLIT_RESPONSE_ERROR);
        }
    };
    let result = parse_json(json);
    serialized.zeroize();
    result.map_err(|_| SHAMIR_SPLIT_RESPONSE_ERROR)
}

fn shamir_shares_to_js_value(shares: &[exo_identity::shamir::Share]) -> Result<JsValue, JsValue> {
    serialize_shamir_shares_response(shares, |json| js_sys::JSON::parse(json).map_err(|_| ()))
        .map_err(JsValue::from_str)
}

fn validate_shamir_split_budget(
    secret_len: usize,
    entropy_len: usize,
    threshold: u8,
    shares: u8,
) -> Result<(), &'static str> {
    if secret_len > MAX_WASM_SHAMIR_SECRET_BYTES || entropy_len > MAX_WASM_SHAMIR_ENTROPY_BYTES {
        return Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR);
    }

    let threshold = usize::from(threshold);
    let shares = usize::from(shares);
    let response_bytes = secret_len
        .checked_mul(4)
        .and_then(|data_bytes| data_bytes.checked_add(256))
        .and_then(|per_share| per_share.checked_mul(shares))
        .and_then(|all_shares| all_shares.checked_add(2))
        .ok_or(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)?;
    let gf_work = secret_len
        .checked_mul(threshold)
        .and_then(|work| work.checked_mul(shares))
        .ok_or(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)?;
    let coefficient_count = secret_len
        .checked_mul(threshold.saturating_sub(1))
        .ok_or(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)?;
    let hash_bytes_per_coefficient = secret_len
        .checked_add(entropy_len)
        .and_then(|bytes| bytes.checked_add(SHAMIR_COEFFICIENT_FIXED_HASH_BYTES))
        .ok_or(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)?;
    let hash_work = coefficient_count
        .checked_mul(hash_bytes_per_coefficient)
        .ok_or(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)?;

    if response_bytes > MAX_WASM_SHAMIR_RESPONSE_BYTES
        || gf_work > MAX_WASM_SHAMIR_GF_WORK_UNITS
        || hash_work > MAX_WASM_SHAMIR_HASH_WORK_BYTES
    {
        return Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR);
    }
    Ok(())
}

fn validate_shamir_reconstruct_budget(
    share_count: usize,
    max_share_len: usize,
    total_share_bytes: usize,
    threshold: u8,
) -> Result<(), &'static str> {
    if max_share_len > MAX_WASM_SHAMIR_SECRET_BYTES
        || total_share_bytes > MAX_WASM_SHAMIR_SHARE_DATA_BYTES
    {
        return Err(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR);
    }

    let interpolation_points = share_count
        .checked_add(1)
        .ok_or(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR)?;
    let threshold = usize::from(threshold);
    let gf_work = max_share_len
        .checked_mul(interpolation_points)
        .and_then(|work| work.checked_mul(threshold))
        .and_then(|work| work.checked_mul(threshold))
        .ok_or(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR)?;
    if gf_work > MAX_WASM_SHAMIR_GF_WORK_UNITS {
        return Err(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR);
    }
    Ok(())
}

fn reconstruct_shamir_secret_json(
    shares: &[exo_identity::shamir::Share],
    config: &exo_identity::shamir::ShamirConfig,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut secret = exo_identity::shamir::reconstruct_zeroizing(shares, config)
        .map_err(|_| SHAMIR_RECONSTRUCT_ERROR)?;
    let Some(secret_hex_len) = secret.len().checked_mul(2) else {
        secret.zeroize();
        return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
    };
    let mut secret_hex = Zeroizing::new(Vec::new());
    if secret_hex.try_reserve_exact(secret_hex_len).is_err() {
        secret.zeroize();
        secret_hex.zeroize();
        return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
    }
    let secret_hex_capacity = secret_hex.capacity();
    secret_hex.resize(secret_hex_len, 0);
    if secret_hex.capacity() != secret_hex_capacity
        || hex::encode_to_slice(secret.as_slice(), secret_hex.as_mut_slice()).is_err()
    {
        secret.zeroize();
        secret_hex.zeroize();
        return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
    }

    let Some(json_upper_bound) = secret_hex.len().checked_add(32) else {
        secret.zeroize();
        secret_hex.zeroize();
        return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
    };
    let mut output = Zeroizing::new(Vec::new());
    if output.try_reserve_exact(json_upper_bound).is_err() {
        secret.zeroize();
        secret_hex.zeroize();
        output.zeroize();
        return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
    }
    let output_capacity = output.capacity();
    let serialization_result = match std::str::from_utf8(secret_hex.as_slice()) {
        Ok(secret_hex) => {
            let response = ShamirSecretResponse { secret: secret_hex };
            let mut writer = FixedLimitJsonWriter {
                bytes: &mut output,
                limit: json_upper_bound,
            };
            serde_json::to_writer(&mut writer, &response)
        }
        Err(_) => {
            secret.zeroize();
            secret_hex.zeroize();
            output.zeroize();
            return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
        }
    };
    secret.zeroize();
    secret_hex.zeroize();
    if serialization_result.is_err()
        || output.len() > json_upper_bound
        || output.capacity() != output_capacity
    {
        output.zeroize();
        return Err(SHAMIR_RECONSTRUCT_RESPONSE_ERROR);
    }
    Ok(output)
}

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
    validate_shamir_split_budget(secret.len(), 0, threshold, shares).map_err(JsValue::from_str)?;
    let config = exo_identity::shamir::ShamirConfig { threshold, shares };
    let result = exo_identity::shamir::split(secret, &config)
        .map_err(|e| JsValue::from_str(&format!("Shamir split error: {e}")))?;
    shamir_shares_to_js_value(&result)
}

/// Split a secret using Shamir's Secret Sharing with caller-supplied entropy.
#[wasm_bindgen]
pub fn wasm_shamir_split_with_entropy(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    entropy: &[u8],
) -> Result<JsValue, JsValue> {
    validate_shamir_split_budget(secret.len(), entropy.len(), threshold, shares)
        .map_err(JsValue::from_str)?;
    let config = exo_identity::shamir::ShamirConfig { threshold, shares };
    let result = exo_identity::shamir::split_with_entropy(secret, &config, entropy)
        .map_err(|e| JsValue::from_str(&format!("Shamir split error: {e}")))?;
    shamir_shares_to_js_value(&result)
}

/// Reconstruct a secret from Shamir shares
///
/// Every Rust-owned secret intermediate is wiped after the final JavaScript
/// value is built. JavaScript heap lifecycle is controlled by the host runtime
/// and is outside this Rust zeroization boundary.
#[wasm_bindgen]
pub fn wasm_shamir_reconstruct(
    shares_json: &str,
    threshold: u8,
    total_shares: u8,
) -> Result<JsValue, JsValue> {
    let shares: Vec<exo_identity::shamir::Share> =
        from_json_bounded_vec(shares_json, "Shamir shares", MAX_WASM_SHAMIR_SHARES)?;
    let total_share_bytes = shares
        .iter()
        .try_fold(0usize, |total, share| total.checked_add(share.data.len()));
    let Some(total_share_bytes) = total_share_bytes else {
        return Err(JsValue::from_str(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR));
    };
    let max_share_len = shares
        .iter()
        .map(|share| share.data.len())
        .max()
        .unwrap_or(0);
    validate_shamir_reconstruct_budget(shares.len(), max_share_len, total_share_bytes, threshold)
        .map_err(JsValue::from_str)?;
    let config = exo_identity::shamir::ShamirConfig {
        threshold,
        shares: total_shares,
    };
    let mut secret_json =
        reconstruct_shamir_secret_json(&shares, &config).map_err(JsValue::from_str)?;
    let result = std::str::from_utf8(secret_json.as_slice())
        .map_err(|_| JsValue::from_str(SHAMIR_RECONSTRUCT_RESPONSE_ERROR))
        .and_then(|json| {
            js_sys::JSON::parse(json).map_err(|_| {
                JsValue::from_str("Shamir reconstruct error: JavaScript value creation failed")
            })
        });
    secret_json.zeroize();
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ENTROPY: &[u8] = b"exochain-wasm-shamir-test-entropy-v1";

    #[test]
    fn identity_shamir_reconstruct_preserves_exact_js_secret_contract() {
        let config = exo_identity::shamir::ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares =
            exo_identity::shamir::split_with_entropy(&[0x00, 0x01, 0xab], &config, TEST_ENTROPY)
                .expect("split with explicit entropy");

        let json = reconstruct_shamir_secret_json(&shares[..2], &config)
            .expect("reconstruct valid shares");

        assert_eq!(
            std::str::from_utf8(json.as_slice()).expect("JSON is UTF-8"),
            r#"{"secret":"0001ab"}"#
        );
    }

    #[test]
    fn identity_shamir_split_response_uses_fixed_capacity_and_preserves_exact_js_array_contract() {
        let config = exo_identity::shamir::ShamirConfig {
            threshold: 1,
            shares: 1,
        };
        let shares = exo_identity::shamir::split(&[0x00, 0x01, 0xab], &config)
            .expect("split one-of-one share");

        let parsed = serialize_shamir_shares_response(&shares, |json| {
            assert_eq!(
                json,
                r#"[{"index":1,"data":[0,1,171],"commitment":[78,33,233,176,117,100,24,2,148,241,188,72,241,146,195,243,9,126,38,209,213,108,39,199,196,13,235,198,37,6,138,100]}]"#
            );
            Ok::<_, ()>("parsed")
        })
        .expect("serialize exact share response");

        assert_eq!(parsed, "parsed");
    }

    #[test]
    fn identity_shamir_split_response_writer_rejects_growth_before_reallocation() {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(3)
            .expect("reserve fixed test buffer");
        let reserved_capacity = bytes.capacity();
        let mut writer = FixedLimitJsonWriter {
            bytes: &mut bytes,
            limit: 3,
        };

        std::io::Write::write_all(&mut writer, b"abc").expect("write within fixed limit");
        let error = std::io::Write::write_all(&mut writer, b"d")
            .expect_err("write beyond fixed limit must fail before growth");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(bytes.as_slice(), b"abc");
        assert_eq!(bytes.capacity(), reserved_capacity);
    }

    #[test]
    fn identity_shamir_split_exports_use_only_the_zeroizing_response_helper() {
        let source = include_str!("identity_bindings.rs");
        let split_exports = source
            .split("pub fn wasm_shamir_split(")
            .nth(1)
            .expect("basic Shamir split export exists")
            .split("/// Reconstruct a secret from Shamir shares")
            .next()
            .expect("split exports end before reconstruction");

        assert_eq!(
            split_exports
                .matches("shamir_shares_to_js_value(&result)")
                .count(),
            2,
            "both split exports must use the same specialized response helper"
        );
        assert!(
            !split_exports
                .lines()
                .any(|line| line.trim() == "to_js_value(&result)"),
            "neither split export may create a plaintext JSON String through the generic bridge"
        );

        let response_helper = source
            .split("fn serialize_shamir_shares_response")
            .nth(1)
            .expect("specialized share response serializer exists")
            .split("fn shamir_shares_to_js_value")
            .next()
            .expect("serializer ends before the JS adapter");
        assert!(response_helper.contains("FixedLimitJsonWriter"));
        assert!(
            response_helper.contains("Zeroizing::new(Vec::new())")
                && response_helper.contains("try_reserve_exact"),
            "the JSON writer must have zeroizing ownership before its first allocation"
        );
    }

    #[test]
    fn identity_shamir_split_budget_accepts_exact_limits_and_rejects_limit_plus_one() {
        assert_eq!(
            validate_shamir_split_budget(MAX_WASM_SHAMIR_SECRET_BYTES, 0, 1, 1),
            Ok(())
        );
        assert_eq!(
            validate_shamir_split_budget(MAX_WASM_SHAMIR_SECRET_BYTES + 1, 0, 1, 1),
            Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)
        );
        assert_eq!(validate_shamir_split_budget(128, 1_792, 65, 65), Ok(()));
        assert_eq!(
            validate_shamir_split_budget(128, 1_793, 65, 65),
            Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)
        );
        assert_eq!(validate_shamir_split_budget(64, 32, 128, 128), Ok(()));
        assert_eq!(
            validate_shamir_split_budget(65, 32, 128, 128),
            Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)
        );
        assert_eq!(validate_shamir_split_budget(960, 0, 1, 255), Ok(()));
        assert_eq!(
            validate_shamir_split_budget(961, 0, 1, 255),
            Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)
        );
        assert_eq!(
            validate_shamir_split_budget(1, MAX_WASM_SHAMIR_ENTROPY_BYTES, 2, 2),
            Ok(())
        );
        assert_eq!(
            validate_shamir_split_budget(1, MAX_WASM_SHAMIR_ENTROPY_BYTES + 1, 2, 2),
            Err(SHAMIR_SPLIT_RESOURCE_LIMIT_ERROR)
        );
    }

    #[test]
    fn identity_shamir_reconstruct_budget_accepts_exact_work_and_rejects_limit_plus_one() {
        assert_eq!(
            validate_shamir_reconstruct_budget(31, 128, 31 * 128, 16),
            Ok(())
        );
        assert_eq!(
            validate_shamir_reconstruct_budget(31, 129, 31 * 129, 16),
            Err(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR)
        );
        assert_eq!(
            validate_shamir_reconstruct_budget(
                1,
                MAX_WASM_SHAMIR_SECRET_BYTES,
                MAX_WASM_SHAMIR_SECRET_BYTES,
                1,
            ),
            Ok(())
        );
        assert_eq!(
            validate_shamir_reconstruct_budget(
                1,
                MAX_WASM_SHAMIR_SECRET_BYTES + 1,
                MAX_WASM_SHAMIR_SECRET_BYTES + 1,
                1,
            ),
            Err(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR)
        );
        assert_eq!(
            validate_shamir_reconstruct_budget(64, 4_096, MAX_WASM_SHAMIR_SHARE_DATA_BYTES, 1,),
            Ok(())
        );
        assert_eq!(
            validate_shamir_reconstruct_budget(64, 4_096, MAX_WASM_SHAMIR_SHARE_DATA_BYTES + 1, 1,),
            Err(SHAMIR_RECONSTRUCT_RESOURCE_LIMIT_ERROR)
        );
    }

    #[test]
    fn identity_shamir_exports_check_resource_budgets_before_core_work() {
        let source = include_str!("identity_bindings.rs");
        let basic_split = source
            .split("pub fn wasm_shamir_split(")
            .nth(1)
            .expect("basic Shamir split export exists")
            .split("pub fn wasm_shamir_split_with_entropy(")
            .next()
            .expect("basic split ends before entropy split");
        let entropy_split = source
            .split("pub fn wasm_shamir_split_with_entropy(")
            .nth(1)
            .expect("entropy Shamir split export exists")
            .split("pub fn wasm_shamir_reconstruct(")
            .next()
            .expect("entropy split ends before reconstruction");
        let reconstruct = source
            .split("pub fn wasm_shamir_reconstruct(")
            .nth(1)
            .expect("Shamir reconstruct export exists")
            .split("pub fn wasm_pace_resolve(")
            .next()
            .expect("reconstruction ends before PACE export");

        let basic_budget = basic_split
            .find("validate_shamir_split_budget")
            .expect("basic split budget check");
        let basic_core = basic_split
            .find("exo_identity::shamir::split(")
            .expect("basic split core call");
        assert!(basic_budget < basic_core);

        let entropy_budget = entropy_split
            .find("validate_shamir_split_budget")
            .expect("entropy split budget check");
        let entropy_core = entropy_split
            .find("exo_identity::shamir::split_with_entropy(")
            .expect("entropy split core call");
        assert!(entropy_budget < entropy_core);

        let reconstruct_budget = reconstruct
            .find("validate_shamir_reconstruct_budget")
            .expect("reconstruct budget check");
        let reconstruct_core = reconstruct
            .find("reconstruct_shamir_secret_json")
            .expect("reconstruct core wrapper call");
        assert!(reconstruct_budget < reconstruct_core);
    }

    #[test]
    fn identity_shamir_reconstruct_error_does_not_echo_malformed_share_bytes() {
        let config = exo_identity::shamir::ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let mut shares =
            exo_identity::shamir::split_with_entropy(b"secret-sentinel", &config, TEST_ENTROPY)
                .expect("split with explicit entropy");
        shares[0].data[0] = 0xde;

        let error = match reconstruct_shamir_secret_json(&shares[..2], &config) {
            Ok(_) => panic!("tampered share must fail closed"),
            Err(error) => error,
        };

        assert!(!error.contains("222"));
        assert!(!error.contains("de"));
        assert!(!error.contains("secret-sentinel"));
    }

    #[test]
    fn identity_shamir_wasm_path_uses_canonical_zeroizing_reconstruction() {
        let source = include_str!("identity_bindings.rs");
        let reconstruct_source = source
            .split("fn reconstruct_shamir_secret_json")
            .nth(1)
            .expect("reconstruction helper exists")
            .split("fn parse_secret_key_hex")
            .next()
            .expect("reconstruction helper ends before key parsing");

        assert!(reconstruct_source.contains("shamir::reconstruct_zeroizing"));
        assert!(!reconstruct_source.contains("shamir::reconstruct("));
        assert!(reconstruct_source.contains("FixedLimitJsonWriter"));
        assert!(reconstruct_source.contains("try_reserve_exact"));
        assert!(reconstruct_source.contains("hex::encode_to_slice"));
        assert!(reconstruct_source.contains("secret_hex.len().checked_add(32)"));
        assert!(
            !reconstruct_source.contains("serde_json::to_string"),
            "reconstruction must never allocate a plaintext JSON String"
        );
    }
}
