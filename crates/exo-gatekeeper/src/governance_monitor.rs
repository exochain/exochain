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

//! Governance Monitor Poisoning defense (T-14).
//!
//! Validates governance health attestation payloads before they are persisted
//! or acted upon, preventing adversarial manipulation of continuous governance
//! monitoring output. Implements three sub-mitigations:
//!
//! 1. **Signed attestation verification** — rejects payloads without a valid
//!    Ed25519 signature over a domain-separated canonical message binding the
//!    signer DID to the findings payload digest (sub-threat T-14a).
//! 2. **Circuit breaker** — auto-pauses self-improvement when >3 Critical
//!    findings are recorded within a 24-hour window (sub-threat T-14c).
//! 3. **Human approval gate** — requires human-DID (`SignerType 0x01`)
//!    approval before self-improvement cycle may begin (sub-threat T-14b).
//!
//! This module is a pure validation library — no database or I/O dependency.
//! The persistence layer is the caller's concern.

use std::collections::BTreeMap;

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto, hash::hash_structured};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Signed attestation envelope (T-14a)
// ---------------------------------------------------------------------------

/// A signed governance health attestation.
///
/// The signature covers [`governance_attestation_signature_message_digest`],
/// which binds the signer DID, a governance-monitor domain separator, and the
/// `findings_digest`. The digest must match the canonical BLAKE3/CBOR digest of
/// the findings payload passed to [`verify_attestation`].
#[derive(Debug, Clone)]
pub struct GovernanceAttestation {
    /// DID of the entity that produced this attestation.
    pub signer_did: Did,
    /// BLAKE3 hash of the canonical findings payload.
    pub findings_digest: Hash256,
    /// Ed25519 signature over the governance attestation message digest bytes.
    pub signature: Signature,
}

/// Domain separator for governance-monitor attestation signatures.
pub const GOVERNANCE_ATTESTATION_SIGNATURE_DOMAIN: &str =
    "exo.gatekeeper.governance-monitor.attestation.v1";

#[derive(Serialize)]
struct GovernanceAttestationSignaturePayload<'a> {
    domain: &'static str,
    signer_did: &'a Did,
    findings_digest: &'a Hash256,
}

/// Errors from governance monitor validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GovernanceMonitorError {
    /// Attestation signature is missing.
    #[error("attestation signature is required")]
    MissingAttestation,

    /// Attestation signature is invalid.
    #[error("attestation signature verification failed for signer {signer_did}")]
    InvalidAttestation {
        /// DID of the claimed signer.
        signer_did: Did,
    },

    /// Findings payload could not be canonically encoded for digesting.
    #[error("findings payload digest encoding failed: {reason}")]
    FindingsDigestEncodingFailed {
        /// Encoding failure reason.
        reason: String,
    },

    /// Attestation signature message could not be canonically encoded.
    #[error("attestation signature message encoding failed: {reason}")]
    AttestationMessageEncodingFailed {
        /// Encoding failure reason.
        reason: String,
    },

    /// Attested digest does not match the actual findings payload.
    #[error(
        "attestation findings digest does not match canonical findings payload for signer {signer_did}"
    )]
    FindingsDigestMismatch {
        /// DID of the claimed signer.
        signer_did: Did,
    },

    /// Circuit breaker has been tripped — too many Critical findings.
    #[error(
        "circuit breaker triggered: {critical_count} Critical findings in 24h (threshold: {threshold})"
    )]
    CircuitBreakerTripped {
        /// Number of Critical findings in the window.
        critical_count: u64,
        /// The threshold that was exceeded.
        threshold: u64,
    },

    /// Self-improvement trigger requires human approval.
    #[error("human approval required: run_id={run_id}")]
    HumanApprovalRequired {
        /// The run ID that needs approval.
        run_id: String,
    },

    /// The approver is not a human DID (SignerType prefix != 0x01).
    #[error("approver must be a human DID (SignerType 0x01), got AI agent")]
    ApproverNotHuman,
}

/// Compute the canonical digest for a governance findings payload.
///
/// # Errors
///
/// Returns [`GovernanceMonitorError::FindingsDigestEncodingFailed`] if the
/// payload cannot be encoded with the canonical structured hash format.
pub fn governance_findings_digest<T: Serialize>(
    findings_payload: &T,
) -> Result<Hash256, GovernanceMonitorError> {
    hash_structured(findings_payload).map_err(|err| {
        GovernanceMonitorError::FindingsDigestEncodingFailed {
            reason: err.to_string(),
        }
    })
}

/// Compute the canonical domain-separated message digest that must be signed
/// for a governance monitor attestation.
///
/// # Errors
///
/// Returns [`GovernanceMonitorError::AttestationMessageEncodingFailed`] if the
/// message cannot be encoded with the canonical structured hash format.
pub fn governance_attestation_signature_message_digest(
    signer_did: &Did,
    findings_digest: &Hash256,
) -> Result<Hash256, GovernanceMonitorError> {
    let payload = GovernanceAttestationSignaturePayload {
        domain: GOVERNANCE_ATTESTATION_SIGNATURE_DOMAIN,
        signer_did,
        findings_digest,
    };
    hash_structured(&payload).map_err(|err| {
        GovernanceMonitorError::AttestationMessageEncodingFailed {
            reason: err.to_string(),
        }
    })
}

/// Verify the cryptographic attestation on a governance health payload.
///
/// **Security: This MUST be called BEFORE any data is stored or circuit
/// breaker state is updated.** An attacker injecting unsigned payloads
/// must never influence the circuit breaker's critical-finding counter.
///
/// # Errors
///
/// Returns [`GovernanceMonitorError::InvalidAttestation`] if the signature
/// does not verify against the signer's public key.
///
/// Returns [`GovernanceMonitorError::FindingsDigestMismatch`] if the digest
/// in the attestation is not the canonical digest of `findings_payload`.
pub fn verify_attestation<T: Serialize>(
    attestation: &GovernanceAttestation,
    signer_public_key: &PublicKey,
    findings_payload: &T,
) -> Result<(), GovernanceMonitorError> {
    let computed_digest = governance_findings_digest(findings_payload)?;
    if computed_digest != attestation.findings_digest {
        return Err(GovernanceMonitorError::FindingsDigestMismatch {
            signer_did: attestation.signer_did.clone(),
        });
    }

    let message = governance_attestation_signature_message_digest(
        &attestation.signer_did,
        &attestation.findings_digest,
    )?;
    if crypto::verify(
        message.as_bytes(),
        &attestation.signature,
        signer_public_key,
    ) {
        Ok(())
    } else {
        Err(GovernanceMonitorError::InvalidAttestation {
            signer_did: attestation.signer_did.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Circuit breaker (T-14c)
// ---------------------------------------------------------------------------

/// Circuit breaker threshold: maximum Critical findings in a 24-hour window
/// before auto-pause triggers.
pub const CIRCUIT_BREAKER_THRESHOLD: u64 = 3;

/// Duration of the circuit breaker window in milliseconds (24 hours).
pub const CIRCUIT_BREAKER_WINDOW_MS: u64 = 86_400_000;

/// In-memory circuit breaker tracking Critical finding timestamps.
///
/// Callers feed in timestamps of Critical findings; the breaker trips
/// when more than [`CIRCUIT_BREAKER_THRESHOLD`] Critical findings have
/// been recorded within [`CIRCUIT_BREAKER_WINDOW_MS`].
#[derive(Debug, Clone)]
pub struct GovernanceCircuitBreaker {
    /// Recent Critical findings grouped by timestamp (physical_ms).
    critical_timestamps: BTreeMap<u64, u64>,
    /// The threshold above which the breaker trips.
    threshold: u64,
    /// Window duration in milliseconds.
    window_ms: u64,
}

impl Default for GovernanceCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceCircuitBreaker {
    /// Create a new circuit breaker with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            critical_timestamps: BTreeMap::new(),
            threshold: CIRCUIT_BREAKER_THRESHOLD,
            window_ms: CIRCUIT_BREAKER_WINDOW_MS,
        }
    }

    /// Create a circuit breaker with custom thresholds (for testing).
    #[must_use]
    pub fn with_thresholds(threshold: u64, window_ms: u64) -> Self {
        Self {
            critical_timestamps: BTreeMap::new(),
            threshold,
            window_ms,
        }
    }

    /// Record Critical findings from a scan at the given timestamp.
    ///
    /// `critical_count` is the number of Critical-severity findings in
    /// a single scan run.
    pub fn record_critical_findings(&mut self, timestamp_ms: u64, critical_count: u64) {
        if critical_count == 0 {
            return;
        }

        let count = self.critical_timestamps.entry(timestamp_ms).or_insert(0);
        *count = (*count).saturating_add(critical_count);
    }

    /// Check whether the circuit breaker has tripped.
    ///
    /// Counts Critical findings within the window ending at `now_ms`.
    /// Returns `Ok(count_in_window)` if the breaker is healthy,
    /// or `Err(CircuitBreakerTripped)` if the threshold is exceeded.
    pub fn check(&self, now_ms: u64) -> Result<u64, GovernanceMonitorError> {
        let window_start = now_ms.saturating_sub(self.window_ms);
        let count = self
            .critical_timestamps
            .iter()
            .filter(|(ts, _)| **ts >= window_start)
            .fold(0u64, |total, (_, count)| total.saturating_add(*count));

        if count > self.threshold {
            Err(GovernanceMonitorError::CircuitBreakerTripped {
                critical_count: count,
                threshold: self.threshold,
            })
        } else {
            Ok(count)
        }
    }

    /// Evict timestamps older than the window (housekeeping).
    pub fn evict_expired(&mut self, now_ms: u64) {
        let window_start = now_ms.saturating_sub(self.window_ms);
        self.critical_timestamps.retain(|&ts, _| ts >= window_start);
    }
}

// ---------------------------------------------------------------------------
// Human approval gate (T-14b)
// ---------------------------------------------------------------------------

/// Approval status for a self-improvement trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Approval is pending human review.
    Pending,
    /// Approved by a human DID.
    Approved {
        /// DID of the human approver.
        approved_by: Did,
        /// Timestamp of approval.
        approved_at: Timestamp,
    },
    /// Rejected by a human DID.
    Rejected {
        /// DID of the human rejector.
        rejected_by: Did,
        /// Timestamp of rejection.
        rejected_at: Timestamp,
    },
}

/// A pending approval gate for a self-improvement cycle trigger.
#[derive(Debug, Clone)]
pub struct ApprovalGate {
    /// The run ID that triggered the approval requirement.
    pub run_id: String,
    /// Current approval status.
    pub status: ApprovalStatus,
}

impl ApprovalGate {
    /// Create a new pending approval gate.
    #[must_use]
    pub fn new(run_id: String) -> Self {
        Self {
            run_id,
            status: ApprovalStatus::Pending,
        }
    }

    /// Approve the gate with a human DID.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMonitorError::ApproverNotHuman`] if the
    /// approver's signer type is not human (prefix 0x01).
    pub fn approve(
        &mut self,
        approver_did: Did,
        signer_type: &exo_core::SignerType,
        timestamp: Timestamp,
    ) -> Result<(), GovernanceMonitorError> {
        // TNC-02: Only human signers may approve self-improvement triggers
        if *signer_type != exo_core::SignerType::Human {
            return Err(GovernanceMonitorError::ApproverNotHuman);
        }

        self.status = ApprovalStatus::Approved {
            approved_by: approver_did,
            approved_at: timestamp,
        };
        Ok(())
    }

    /// Reject the gate with a human DID.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMonitorError::ApproverNotHuman`] if the
    /// rejector's signer type is not human.
    pub fn reject(
        &mut self,
        rejector_did: Did,
        signer_type: &exo_core::SignerType,
        timestamp: Timestamp,
    ) -> Result<(), GovernanceMonitorError> {
        if *signer_type != exo_core::SignerType::Human {
            return Err(GovernanceMonitorError::ApproverNotHuman);
        }

        self.status = ApprovalStatus::Rejected {
            rejected_by: rejector_did,
            rejected_at: timestamp,
        };
        Ok(())
    }

    /// Whether the gate is approved and the cycle may proceed.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self.status, ApprovalStatus::Approved { .. })
    }

    /// Whether the gate is still pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self.status, ApprovalStatus::Pending)
    }
}

/// Determine whether a scan result requires a human approval gate.
///
/// Per T-14b: Critical or High findings require human approval before
/// any self-improvement cycle may begin implementation.
#[must_use]
pub fn requires_approval_gate(critical_count: u64, high_count: u64) -> bool {
    critical_count > 0 || high_count > 0
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::crypto::{generate_keypair, sign};

    use super::*;

    fn test_did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("valid")
    }

    fn make_attestation(
        findings_digest: Hash256,
        signer_did: Did,
        secret: &exo_core::SecretKey,
    ) -> GovernanceAttestation {
        let message =
            governance_attestation_signature_message_digest(&signer_did, &findings_digest)
                .expect("signature message digest");
        let signature = sign(message.as_bytes(), secret);
        GovernanceAttestation {
            signer_did,
            findings_digest,
            signature,
        }
    }

    fn findings_payload(label: &str, severity: &str) -> serde_json::Value {
        serde_json::json!([
            {
                "id": label,
                "severity": severity,
                "title": "governance monitor finding"
            }
        ])
    }

    // ── Attestation verification tests ──────────────────────────────────

    #[test]
    fn valid_attestation_passes() {
        let (pk, sk) = generate_keypair();
        let findings = findings_payload("F-001", "critical");
        let digest = exo_core::hash::hash_structured(&findings).expect("findings digest");
        let attestation = make_attestation(digest, test_did("scanner"), &sk);

        assert!(verify_attestation(&attestation, &pk, &findings).is_ok());
    }

    #[test]
    fn attestation_rejects_signature_replayed_for_different_findings_payload() {
        let (pk, sk) = generate_keypair();
        let signed_findings = findings_payload("F-001", "low");
        let substituted_findings = findings_payload("F-999", "critical");
        let signed_digest =
            exo_core::hash::hash_structured(&signed_findings).expect("findings digest");
        let attestation = make_attestation(signed_digest, test_did("scanner"), &sk);

        let err = verify_attestation(&attestation, &pk, &substituted_findings).unwrap_err();
        assert!(matches!(
            err,
            GovernanceMonitorError::FindingsDigestMismatch { .. }
        ));
    }

    #[test]
    fn attestation_rejects_signature_replayed_with_relabelled_signer_did() {
        let (pk, sk) = generate_keypair();
        let findings = findings_payload("F-001", "critical");
        let digest = exo_core::hash::hash_structured(&findings).expect("findings digest");
        let mut attestation = make_attestation(digest, test_did("scanner"), &sk);
        attestation.signer_did = test_did("impersonated-scanner");

        let err = verify_attestation(&attestation, &pk, &findings).unwrap_err();
        assert!(matches!(
            err,
            GovernanceMonitorError::InvalidAttestation { .. }
        ));
    }

    #[test]
    fn attestation_rejects_digest_only_signature_without_domain_context() {
        let (pk, sk) = generate_keypair();
        let findings = findings_payload("F-001", "critical");
        let digest = exo_core::hash::hash_structured(&findings).expect("findings digest");
        let signature = sign(digest.as_bytes(), &sk);
        let attestation = GovernanceAttestation {
            signer_did: test_did("scanner"),
            findings_digest: digest,
            signature,
        };

        let err = verify_attestation(&attestation, &pk, &findings).unwrap_err();
        assert!(matches!(
            err,
            GovernanceMonitorError::InvalidAttestation { .. }
        ));
    }

    #[test]
    fn attestation_signature_message_binds_domain_signer_and_findings_digest() {
        let signer = test_did("scanner");
        let findings = findings_payload("F-001", "critical");
        let digest = exo_core::hash::hash_structured(&findings).expect("findings digest");
        let signer_message =
            governance_attestation_signature_message_digest(&signer, &digest).expect("message");
        let relabelled_message =
            governance_attestation_signature_message_digest(&test_did("other-scanner"), &digest)
                .expect("message");
        let other_digest = Hash256::digest(b"other findings");
        let other_findings_message =
            governance_attestation_signature_message_digest(&signer, &other_digest)
                .expect("message");

        assert_ne!(
            signer_message, digest,
            "signature message must not be the raw findings digest"
        );
        assert_ne!(
            signer_message, relabelled_message,
            "signature message must bind the signer DID"
        );
        assert_ne!(
            signer_message, other_findings_message,
            "signature message must bind the findings digest"
        );
    }

    #[test]
    fn wrong_key_attestation_fails() {
        let (_pk, sk) = generate_keypair();
        let (wrong_pk, _) = generate_keypair();
        let findings = findings_payload("F-001", "critical");
        let digest = exo_core::hash::hash_structured(&findings).expect("findings digest");
        let attestation = make_attestation(digest, test_did("scanner"), &sk);

        let err = verify_attestation(&attestation, &wrong_pk, &findings).unwrap_err();
        assert!(matches!(
            err,
            GovernanceMonitorError::InvalidAttestation { .. }
        ));
    }

    #[test]
    fn tampered_digest_fails() {
        let (pk, sk) = generate_keypair();
        let findings = findings_payload("F-001", "critical");
        let digest = exo_core::hash::hash_structured(&findings).expect("findings digest");
        let mut attestation = make_attestation(digest, test_did("scanner"), &sk);

        // Tamper with the digest after signing
        attestation.findings_digest = Hash256::digest(b"tampered");

        let err = verify_attestation(&attestation, &pk, &findings).unwrap_err();
        assert!(matches!(
            err,
            GovernanceMonitorError::FindingsDigestMismatch { .. }
        ));
    }

    // ── Circuit breaker tests ───────────────────────────────────────────

    #[test]
    fn circuit_breaker_healthy_when_below_threshold() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 86_400_000);
        cb.record_critical_findings(1000, 2);

        let count = cb.check(2000).expect("should be healthy");
        assert_eq!(count, 2);
    }

    #[test]
    fn circuit_breaker_trips_above_threshold() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 86_400_000);
        cb.record_critical_findings(1000, 2);
        cb.record_critical_findings(2000, 2); // total = 4, threshold = 3

        let err = cb.check(3000).unwrap_err();
        assert!(matches!(
            err,
            GovernanceMonitorError::CircuitBreakerTripped {
                critical_count: 4,
                threshold: 3
            }
        ));
    }

    #[test]
    fn circuit_breaker_expired_findings_not_counted() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 1000); // 1s window
        cb.record_critical_findings(100, 4); // 4 findings at t=100

        // At t=1200, the window is [200, 1200] — t=100 is outside
        let count = cb.check(1200).expect("should be healthy after expiry");
        assert_eq!(count, 0);
    }

    #[test]
    fn circuit_breaker_eviction() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 1000);
        cb.record_critical_findings(100, 4);
        cb.evict_expired(1200);

        assert_eq!(cb.critical_timestamps.len(), 0);
    }

    #[test]
    fn circuit_breaker_exactly_at_threshold_is_ok() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 86_400_000);
        cb.record_critical_findings(1000, 3); // exactly 3 = threshold

        // threshold check is > not >=, so exactly at threshold is OK
        let count = cb.check(2000).expect("exactly at threshold should pass");
        assert_eq!(count, 3);
    }

    #[test]
    fn circuit_breaker_records_many_findings_as_one_timestamp_bucket() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 86_400_000);
        cb.record_critical_findings(1000, 1024);

        assert_eq!(cb.critical_timestamps.len(), 1);
        assert!(matches!(
            cb.check(2000),
            Err(GovernanceMonitorError::CircuitBreakerTripped {
                critical_count: 1024,
                threshold: 3
            })
        ));
    }

    #[test]
    fn circuit_breaker_coalesces_repeated_timestamp_counts() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 86_400_000);
        cb.record_critical_findings(1000, 2);
        cb.record_critical_findings(1000, 3);

        assert_eq!(cb.critical_timestamps.len(), 1);
        assert!(matches!(
            cb.check(2000),
            Err(GovernanceMonitorError::CircuitBreakerTripped {
                critical_count: 5,
                threshold: 3
            })
        ));
    }

    #[test]
    fn circuit_breaker_zero_count_does_not_create_bucket() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(3, 86_400_000);
        cb.record_critical_findings(1000, 0);

        assert_eq!(cb.critical_timestamps.len(), 0);
        assert!(matches!(cb.check(2000), Ok(0)));
    }

    #[test]
    fn circuit_breaker_saturates_count_overflow_without_per_finding_allocation() {
        let mut cb = GovernanceCircuitBreaker::with_thresholds(u64::MAX - 1, 86_400_000);
        cb.record_critical_findings(1000, u64::MAX);
        cb.record_critical_findings(2000, 1);

        assert_eq!(cb.critical_timestamps.len(), 2);
        assert!(matches!(
            cb.check(3000),
            Err(GovernanceMonitorError::CircuitBreakerTripped {
                critical_count: u64::MAX,
                threshold
            }) if threshold == u64::MAX - 1
        ));
    }

    #[test]
    fn circuit_breaker_default_thresholds() {
        let cb = GovernanceCircuitBreaker::new();
        assert_eq!(cb.threshold, CIRCUIT_BREAKER_THRESHOLD);
        assert_eq!(cb.window_ms, CIRCUIT_BREAKER_WINDOW_MS);
    }

    // ── Human approval gate tests ───────────────────────────────────────

    #[test]
    fn approval_gate_starts_pending() {
        let gate = ApprovalGate::new("run-001".to_string());
        assert!(gate.is_pending());
        assert!(!gate.is_approved());
    }

    #[test]
    fn human_can_approve() {
        let mut gate = ApprovalGate::new("run-001".to_string());
        let did = test_did("human-operator");
        let ts = Timestamp::new(5000, 0);

        gate.approve(did, &exo_core::SignerType::Human, ts)
            .expect("human approval should succeed");

        assert!(gate.is_approved());
        assert!(!gate.is_pending());
    }

    #[test]
    fn ai_cannot_approve() {
        let mut gate = ApprovalGate::new("run-001".to_string());
        let did = test_did("ai-agent");
        let ts = Timestamp::new(5000, 0);
        let ai_signer = exo_core::SignerType::Ai {
            delegation_id: Hash256::ZERO,
        };

        let err = gate.approve(did, &ai_signer, ts).unwrap_err();
        assert!(matches!(err, GovernanceMonitorError::ApproverNotHuman));
        assert!(gate.is_pending()); // status unchanged
    }

    #[test]
    fn human_can_reject() {
        let mut gate = ApprovalGate::new("run-001".to_string());
        let did = test_did("human-operator");
        let ts = Timestamp::new(5000, 0);

        gate.reject(did, &exo_core::SignerType::Human, ts)
            .expect("human rejection should succeed");

        assert!(!gate.is_approved());
        assert!(!gate.is_pending());
        assert!(matches!(gate.status, ApprovalStatus::Rejected { .. }));
    }

    #[test]
    fn ai_cannot_reject() {
        let mut gate = ApprovalGate::new("run-001".to_string());
        let did = test_did("ai-agent");
        let ts = Timestamp::new(5000, 0);
        let ai_signer = exo_core::SignerType::Ai {
            delegation_id: Hash256::ZERO,
        };

        let err = gate.reject(did, &ai_signer, ts).unwrap_err();
        assert!(matches!(err, GovernanceMonitorError::ApproverNotHuman));
    }

    // ── Approval gate trigger tests ─────────────────────────────────────

    #[test]
    fn critical_findings_require_approval() {
        assert!(requires_approval_gate(1, 0));
    }

    #[test]
    fn high_findings_require_approval() {
        assert!(requires_approval_gate(0, 1));
    }

    #[test]
    fn no_critical_or_high_no_approval_needed() {
        assert!(!requires_approval_gate(0, 0));
    }

    #[test]
    fn both_critical_and_high_require_approval() {
        assert!(requires_approval_gate(2, 3));
    }
}
