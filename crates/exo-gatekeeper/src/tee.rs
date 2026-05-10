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

//! Trusted Execution Environment (TEE) attestation.
//!
//! Provides attestation verification for hardware TEE platforms
//! and a simulated platform for testing.

use serde::{Deserialize, Serialize};

use crate::error::GatekeeperError;

// ---------------------------------------------------------------------------
// TEE platform
// ---------------------------------------------------------------------------

/// Supported TEE platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeePlatform {
    /// Intel SGX.
    Sgx,
    /// ARM TrustZone.
    TrustZone,
    /// AMD SEV.
    Sev,
    /// Simulated TEE for testing.
    Simulated,
}

// ---------------------------------------------------------------------------
// TEE environment
// ---------------------------------------------------------------------------

/// The deployment environment for TEE policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeEnvironment {
    /// Production — simulated TEE fixtures are rejected.
    Production,
    /// Testing — all platforms including Simulated are permitted.
    Testing,
}

// ---------------------------------------------------------------------------
// TEE attestation
// ---------------------------------------------------------------------------

/// An attestation from a TEE.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// The platform that produced this attestation.
    pub platform: TeePlatform,
    /// Blake3 hash of the enclave measurement.
    pub measurement_hash: [u8; 32],
    /// Timestamp (milliseconds since epoch).
    pub timestamp: u64,
    /// Signature over the measurement + timestamp.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for TeeAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeeAttestation")
            .field("platform", &self.platform)
            .field("measurement_hash", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// TEE policy
// ---------------------------------------------------------------------------

/// Policy defining acceptable TEE attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeePolicy {
    /// Accepted platforms.
    pub accepted_platforms: Vec<TeePlatform>,
    /// Required measurement hashes (if non-empty, attestation must match one).
    pub required_measurements: Vec<[u8; 32]>,
    /// Maximum attestation age in milliseconds (0 = no age limit).
    pub max_age_ms: u64,
    /// Current time in milliseconds (for age checking).
    pub current_time_ms: u64,
    /// Deployment environment (Production or Testing).
    pub environment: TeeEnvironment,
}

impl Default for TeePolicy {
    /// Secure by default: Production environment, hardware-only platforms.
    fn default() -> Self {
        Self::production()
    }
}

impl TeePolicy {
    /// Production policy — only hardware TEE platforms accepted.
    #[must_use]
    pub fn production() -> Self {
        Self {
            accepted_platforms: vec![TeePlatform::Sgx, TeePlatform::TrustZone, TeePlatform::Sev],
            required_measurements: vec![],
            max_age_ms: 0,
            current_time_ms: 0,
            environment: TeeEnvironment::Production,
        }
    }

    /// Testing policy — all platforms including Simulated are accepted.
    #[must_use]
    pub fn testing() -> Self {
        Self {
            accepted_platforms: vec![
                TeePlatform::Sgx,
                TeePlatform::TrustZone,
                TeePlatform::Sev,
                TeePlatform::Simulated,
            ],
            required_measurements: vec![],
            max_age_ms: 0,
            current_time_ms: 0,
            environment: TeeEnvironment::Testing,
        }
    }
}

// ---------------------------------------------------------------------------
// Platform gating
// ---------------------------------------------------------------------------

/// Check whether a platform is allowed by policy, enforcing the production
/// gate against simulated TEEs.
fn is_platform_allowed(platform: &TeePlatform, policy: &TeePolicy) -> bool {
    if *platform == TeePlatform::Simulated && policy.environment != TeeEnvironment::Testing {
        return false;
    }
    policy.accepted_platforms.contains(platform)
}

// ---------------------------------------------------------------------------
// Attestation generation
// ---------------------------------------------------------------------------

/// Generate an attestation for the given platform and measurement.
///
/// This creates deterministic simulated attestation fixtures. Hardware TEE
/// platforms require platform quote verification and are not accepted by
/// `verify_attestation` when carrying this synthetic signature.
#[must_use]
pub fn generate_attestation(
    platform: &TeePlatform,
    measurement: &[u8],
    timestamp: u64,
) -> TeeAttestation {
    let measurement_hash = *blake3::hash(measurement).as_bytes();

    TeeAttestation {
        platform: *platform,
        measurement_hash,
        timestamp,
        signature: synthetic_attestation_signature(platform, &measurement_hash, timestamp),
    }
}

/// Deterministic signature used only for simulated TEE test fixtures.
fn tee_platform_tag(platform: &TeePlatform) -> &'static [u8] {
    match platform {
        TeePlatform::Sgx => b"tee.platform.sgx.v1",
        TeePlatform::Sev => b"tee.platform.sev.v1",
        TeePlatform::TrustZone => b"tee.platform.trustzone.v1",
        TeePlatform::Simulated => b"tee.platform.simulated.v1",
    }
}

fn synthetic_attestation_signature(
    platform: &TeePlatform,
    measurement_hash: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(measurement_hash);
    sig_input.extend_from_slice(&timestamp.to_le_bytes());
    sig_input.extend_from_slice(tee_platform_tag(platform));
    blake3::hash(&sig_input).as_bytes().to_vec()
}

fn synthetic_signature_allowed(attestation: &TeeAttestation, policy: &TeePolicy) -> bool {
    if attestation.platform != TeePlatform::Simulated {
        return false;
    }

    policy.environment == TeeEnvironment::Testing
}

fn measurement_hash_eq_ct(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn required_measurement_matches(
    required_measurements: &[[u8; 32]],
    measurement: &[u8; 32],
) -> bool {
    let mut matched = 0u8;
    for required in required_measurements {
        matched |= u8::from(measurement_hash_eq_ct(required, measurement));
    }
    matched != 0
}

// ---------------------------------------------------------------------------
// Attestation verification
// ---------------------------------------------------------------------------

/// Platform-specific verifier for a hardware TEE quote.
///
/// The verifier is called only after deterministic policy checks pass and only
/// for non-synthetic hardware attestations. Simulated TEEs keep using the local
/// deterministic fixture signature path for tests.
pub trait TeeQuoteVerifier {
    /// Verify the platform quote carried in an attestation.
    ///
    /// Implementations should perform the platform-specific checks for SGX,
    /// SEV, or TrustZone quote material and return a detailed [`GatekeeperError`]
    /// on failure.
    fn verify_quote(
        &self,
        attestation: &TeeAttestation,
        policy: &TeePolicy,
    ) -> Result<(), GatekeeperError>;
}

impl<F> TeeQuoteVerifier for F
where
    F: Fn(&TeeAttestation, &TeePolicy) -> Result<(), GatekeeperError>,
{
    fn verify_quote(
        &self,
        attestation: &TeeAttestation,
        policy: &TeePolicy,
    ) -> Result<(), GatekeeperError> {
        self(attestation, policy)
    }
}

enum AttestationSignatureKind {
    SimulatedFixture,
    HardwareQuote,
}

fn check_attestation_policy(
    attestation: &TeeAttestation,
    policy: &TeePolicy,
) -> Result<AttestationSignatureKind, GatekeeperError> {
    // Check platform (includes production gate for Simulated).
    if !is_platform_allowed(&attestation.platform, policy) {
        return Err(GatekeeperError::TeeError(format!(
            "Platform {:?} is not accepted by policy",
            attestation.platform
        )));
    }

    // Check measurement (if policy specifies required measurements).
    if !policy.required_measurements.is_empty()
        && !required_measurement_matches(
            &policy.required_measurements,
            &attestation.measurement_hash,
        )
    {
        return Err(GatekeeperError::TeeError(
            "Measurement hash does not match any required measurement".into(),
        ));
    }

    // Check signature is non-empty.
    if attestation.signature.is_empty() {
        return Err(GatekeeperError::TeeError(
            "Attestation signature is empty".into(),
        ));
    }

    // Check age.
    if policy.max_age_ms > 0 {
        let age = policy
            .current_time_ms
            .checked_sub(attestation.timestamp)
            .ok_or_else(|| {
                GatekeeperError::TeeError(format!(
                    "Attestation timestamp {} is in the future relative to policy time {}",
                    attestation.timestamp, policy.current_time_ms
                ))
            })?;
        if age > policy.max_age_ms {
            return Err(GatekeeperError::TeeError(format!(
                "Attestation is too old: {} ms (max: {} ms)",
                age, policy.max_age_ms
            )));
        }
    }

    let synthetic_sig = synthetic_attestation_signature(
        &attestation.platform,
        &attestation.measurement_hash,
        attestation.timestamp,
    );

    if attestation.signature == synthetic_sig {
        if synthetic_signature_allowed(attestation, policy) {
            return Ok(AttestationSignatureKind::SimulatedFixture);
        }
        return Err(GatekeeperError::TeeError(
            "synthetic TEE attestation signatures are only accepted for simulated TEEs in explicitly allowed environments".into(),
        ));
    }

    if attestation.platform == TeePlatform::Simulated {
        return Err(GatekeeperError::TeeError(
            "simulated TEE attestation signature verification failed".into(),
        ));
    }

    Ok(AttestationSignatureKind::HardwareQuote)
}

/// Verify a TEE attestation against a policy.
pub fn verify_attestation(
    attestation: &TeeAttestation,
    policy: &TeePolicy,
) -> Result<(), GatekeeperError> {
    match check_attestation_policy(attestation, policy)? {
        AttestationSignatureKind::SimulatedFixture => Ok(()),
        AttestationSignatureKind::HardwareQuote => Err(GatekeeperError::TeeError(format!(
            "Hardware TEE attestation for platform {:?} requires a platform quote verifier",
            attestation.platform
        ))),
    }
}

/// Verify a TEE attestation with an explicit hardware quote verifier.
///
/// This preserves the fail-closed behavior of [`verify_attestation`] for
/// callers that do not provide platform quote verification, while allowing
/// production integrations to plug in audited SGX/SEV/TrustZone quote checks.
pub fn verify_attestation_with_quote_verifier<V>(
    attestation: &TeeAttestation,
    policy: &TeePolicy,
    verifier: &V,
) -> Result<(), GatekeeperError>
where
    V: TeeQuoteVerifier + ?Sized,
{
    match check_attestation_policy(attestation, policy)? {
        AttestationSignatureKind::SimulatedFixture => Ok(()),
        AttestationSignatureKind::HardwareQuote => verifier.verify_quote(attestation, policy),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const MEASUREMENT: &[u8] = b"enclave-binary-v1.0";
    const TIMESTAMP: u64 = 1_700_000_000_000;

    fn valid_attestation() -> TeeAttestation {
        generate_attestation(&TeePlatform::Simulated, MEASUREMENT, TIMESTAMP)
    }

    fn permissive_policy() -> TeePolicy {
        TeePolicy {
            accepted_platforms: vec![
                TeePlatform::Sgx,
                TeePlatform::TrustZone,
                TeePlatform::Sev,
                TeePlatform::Simulated,
            ],
            required_measurements: vec![],
            max_age_ms: 0,
            current_time_ms: TIMESTAMP,
            environment: TeeEnvironment::Testing,
        }
    }

    fn accepting_sgx_quote_verifier(
        verified_att: &TeeAttestation,
        _policy: &TeePolicy,
    ) -> Result<(), GatekeeperError> {
        if verified_att.platform == TeePlatform::Sgx && verified_att.signature == vec![0xA5; 64] {
            Ok(())
        } else {
            Err(GatekeeperError::TeeError(
                "unexpected quote material".into(),
            ))
        }
    }

    fn revoked_quote_verifier(
        _attestation: &TeeAttestation,
        _policy: &TeePolicy,
    ) -> Result<(), GatekeeperError> {
        Err(GatekeeperError::TeeError("quote revoked".into()))
    }

    fn panic_quote_verifier(
        _attestation: &TeeAttestation,
        _policy: &TeePolicy,
    ) -> Result<(), GatekeeperError> {
        panic!("synthetic hardware attestations must not reach quote verifier")
    }

    // --- Generation ---

    #[test]
    fn generate_produces_valid_attestation() {
        let att = valid_attestation();
        assert_eq!(att.platform, TeePlatform::Simulated);
        assert_eq!(att.timestamp, TIMESTAMP);
        assert!(!att.signature.is_empty());
        assert_eq!(att.measurement_hash, *blake3::hash(MEASUREMENT).as_bytes());
    }

    #[test]
    fn tee_attestation_debug_redacts_sensitive_material() {
        let att = valid_attestation();
        let rendered = format!("{att:?}");

        assert!(rendered.contains("TeeAttestation"));
        assert!(rendered.contains("measurement_hash: \"[REDACTED]\""));
        assert!(rendered.contains("signature: \"[REDACTED]\""));
        assert!(!rendered.contains(&format!("{:?}", att.measurement_hash)));
        assert!(!rendered.contains(&format!("{:?}", att.signature)));
    }

    #[test]
    fn generate_is_deterministic() {
        let att1 = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        let att2 = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        assert_eq!(att1, att2);
    }

    #[test]
    fn generate_different_platforms_produce_different_signatures() {
        let att_sgx = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        let att_sev = generate_attestation(&TeePlatform::Sev, MEASUREMENT, TIMESTAMP);
        assert_ne!(att_sgx.signature, att_sev.signature);
    }

    #[test]
    fn generate_different_measurements_produce_different_hashes() {
        let att1 = generate_attestation(&TeePlatform::Simulated, b"binary-v1", TIMESTAMP);
        let att2 = generate_attestation(&TeePlatform::Simulated, b"binary-v2", TIMESTAMP);
        assert_ne!(att1.measurement_hash, att2.measurement_hash);
    }

    // --- Verification: passing ---

    #[test]
    fn verify_passes_for_valid_attestation() {
        let att = valid_attestation();
        let policy = permissive_policy();
        assert!(verify_attestation(&att, &policy).is_ok());
    }

    #[test]
    fn verify_rejects_synthetic_sgx_attestation() {
        let att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn verify_rejects_synthetic_trustzone_attestation() {
        let att = generate_attestation(&TeePlatform::TrustZone, MEASUREMENT, TIMESTAMP);
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn verify_rejects_synthetic_sev_attestation() {
        let att = generate_attestation(&TeePlatform::Sev, MEASUREMENT, TIMESTAMP);
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    // --- Verification: platform rejection ---

    #[test]
    fn verify_rejects_unaccepted_platform() {
        let att = valid_attestation(); // Simulated
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Sgx], // only SGX
            required_measurements: vec![],
            max_age_ms: 0,
            current_time_ms: TIMESTAMP,
            environment: TeeEnvironment::Testing,
        };
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("not accepted"));
    }

    // --- Verification: measurement mismatch ---

    #[test]
    fn verify_rejects_measurement_mismatch() {
        let att = valid_attestation();
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![[0u8; 32]], // wrong hash
            max_age_ms: 0,
            current_time_ms: TIMESTAMP,
            environment: TeeEnvironment::Testing,
        };
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Measurement"));
    }

    #[test]
    fn verify_passes_when_measurement_matches() {
        let att = valid_attestation();
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![att.measurement_hash],
            max_age_ms: 0,
            current_time_ms: TIMESTAMP,
            environment: TeeEnvironment::Testing,
        };
        assert!(verify_attestation(&att, &policy).is_ok());
    }

    // --- Verification: empty signature ---

    #[test]
    fn verify_rejects_empty_signature() {
        let mut att = valid_attestation();
        att.signature = vec![]; // tamper
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("empty"));
    }

    // --- Verification: age ---

    #[test]
    fn verify_rejects_expired_attestation() {
        let att = valid_attestation(); // timestamp = TIMESTAMP
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![],
            max_age_ms: 1000,                  // 1 second max
            current_time_ms: TIMESTAMP + 5000, // 5 seconds later
            environment: TeeEnvironment::Testing,
        };
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("too old"));
    }

    #[test]
    fn verify_passes_within_age_limit() {
        let att = valid_attestation();
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![],
            max_age_ms: 10_000,
            current_time_ms: TIMESTAMP + 5_000,
            environment: TeeEnvironment::Testing,
        };
        assert!(verify_attestation(&att, &policy).is_ok());
    }

    #[test]
    fn verify_rejects_future_dated_attestation_when_age_limit_is_enforced() {
        let att = generate_attestation(&TeePlatform::Simulated, MEASUREMENT, TIMESTAMP + 5_000);
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![],
            max_age_ms: 1_000,
            current_time_ms: TIMESTAMP,
            environment: TeeEnvironment::Testing,
        };

        let result = verify_attestation(&att, &policy);

        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("future"));
    }

    #[test]
    fn verify_no_age_limit_passes_old_attestation() {
        let att = valid_attestation();
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![],
            max_age_ms: 0, // no limit
            current_time_ms: TIMESTAMP + 999_999_999,
            environment: TeeEnvironment::Testing,
        };
        assert!(verify_attestation(&att, &policy).is_ok());
    }

    // --- Verification: tampered signature ---

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut att = valid_attestation();
        att.signature = vec![0xDE, 0xAD, 0xBE, 0xEF]; // wrong
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("verification failed"));
    }

    #[test]
    fn verify_rejects_tampered_timestamp() {
        let mut att = valid_attestation();
        att.timestamp += 1; // tamper — signature won't match
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_tampered_measurement() {
        let mut att = valid_attestation();
        att.measurement_hash[0] ^= 0xFF; // tamper
        let policy = permissive_policy();
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
    }

    // --- Multiple required measurements: any match passes ---

    #[test]
    fn verify_passes_when_one_of_multiple_measurements_matches() {
        let att = valid_attestation();
        let policy = TeePolicy {
            accepted_platforms: vec![TeePlatform::Simulated],
            required_measurements: vec![[0u8; 32], att.measurement_hash, [1u8; 32]],
            max_age_ms: 0,
            current_time_ms: TIMESTAMP,
            environment: TeeEnvironment::Testing,
        };
        assert!(verify_attestation(&att, &policy).is_ok());
    }

    #[test]
    fn required_measurement_matcher_handles_empty_match_and_mismatch() {
        let att = valid_attestation();

        assert!(!required_measurement_matches(&[], &att.measurement_hash));
        assert!(required_measurement_matches(
            &[[0u8; 32], att.measurement_hash, [1u8; 32]],
            &att.measurement_hash
        ));
        assert!(!required_measurement_matches(
            &[[0u8; 32], [1u8; 32]],
            &att.measurement_hash
        ));
    }

    #[test]
    fn measurement_policy_does_not_use_short_circuit_contains() {
        let source = include_str!("tee.rs");
        let start = source
            .find("fn check_attestation_policy(")
            .expect("check_attestation_policy source exists");
        let end = source[start..]
            .find("// Check signature is non-empty.")
            .expect("signature check marker exists");
        let measurement_check = &source[start..start + end];

        assert!(
            !measurement_check.contains(".contains(&attestation.measurement_hash)"),
            "measurement hash matching must not use short-circuiting Vec::contains"
        );
    }

    // --- Production TEE gate tests ---

    #[test]
    fn simulated_rejected_in_production() {
        let att = generate_attestation(&TeePlatform::Simulated, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::production();
        // Even if someone manually adds Simulated to accepted_platforms,
        // the production gate must still reject it.
        policy.accepted_platforms.push(TeePlatform::Simulated);
        policy.current_time_ms = TIMESTAMP;
        assert!(verify_attestation(&att, &policy).is_err());
    }

    #[test]
    fn simulated_accepted_in_testing() {
        let att = generate_attestation(&TeePlatform::Simulated, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::testing();
        policy.current_time_ms = TIMESTAMP;
        assert!(verify_attestation(&att, &policy).is_ok());
    }

    #[test]
    fn synthetic_sgx_attestation_rejected_in_production() {
        let att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn synthetic_trustzone_attestation_rejected_in_production() {
        let att = generate_attestation(&TeePlatform::TrustZone, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn synthetic_sev_attestation_rejected_in_production() {
        let att = generate_attestation(&TeePlatform::Sev, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn synthetic_hardware_attestation_rejected_in_testing() {
        let att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::testing();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn sgx_non_synthetic_signature_rejected_without_quote_verifier_in_production() {
        let mut att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        att.signature = vec![0xA5; 64];
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("quote verifier"));
    }

    #[test]
    fn hardware_non_synthetic_signature_is_accepted_when_quote_verifier_accepts() {
        let mut att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        att.signature = vec![0xA5; 64];
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;

        let result =
            verify_attestation_with_quote_verifier(&att, &policy, &accepting_sgx_quote_verifier);

        assert!(result.is_ok());
    }

    #[test]
    fn hardware_quote_verifier_error_is_propagated() {
        let mut att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        att.signature = vec![0xA5; 64];
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;

        let result = verify_attestation_with_quote_verifier(&att, &policy, &revoked_quote_verifier);

        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("quote revoked"));
    }

    #[test]
    fn synthetic_hardware_attestation_is_rejected_before_quote_verifier() {
        let att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;

        let result = verify_attestation_with_quote_verifier(&att, &policy, &panic_quote_verifier);

        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("synthetic"));
    }

    #[test]
    fn sgx_non_synthetic_signature_rejected_without_quote_verifier_in_testing() {
        let mut att = generate_attestation(&TeePlatform::Sgx, MEASUREMENT, TIMESTAMP);
        att.signature = vec![0xA5; 64];
        let mut policy = TeePolicy::testing();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("quote verifier"));
    }

    #[test]
    fn trustzone_non_synthetic_signature_rejected_without_quote_verifier() {
        let mut att = generate_attestation(&TeePlatform::TrustZone, MEASUREMENT, TIMESTAMP);
        att.signature = vec![0xA5; 64];
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("quote verifier"));
    }

    #[test]
    fn sev_non_synthetic_signature_rejected_without_quote_verifier() {
        let mut att = generate_attestation(&TeePlatform::Sev, MEASUREMENT, TIMESTAMP);
        att.signature = vec![0xA5; 64];
        let mut policy = TeePolicy::production();
        policy.current_time_ms = TIMESTAMP;
        let result = verify_attestation(&att, &policy);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("quote verifier"));
    }

    #[test]
    fn default_policy_is_production() {
        let policy = TeePolicy::default();
        assert_eq!(policy.environment, TeeEnvironment::Production);
    }

    #[test]
    fn production_constructor_excludes_simulated() {
        let policy = TeePolicy::production();
        assert!(!policy.accepted_platforms.contains(&TeePlatform::Simulated));
    }

    #[test]
    fn testing_constructor_includes_simulated() {
        let policy = TeePolicy::testing();
        assert!(policy.accepted_platforms.contains(&TeePlatform::Simulated));
    }

    #[test]
    fn synthetic_attestation_signature_uses_stable_platform_tags() {
        let source = include_str!("tee.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            !production.contains("format!(\"{:?}\", platform)"),
            "synthetic attestation fixture signatures must not depend on Rust Debug output"
        );
    }
}
