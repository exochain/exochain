//! Risk attestation for identity adjudication.

use exo_core::{Did, PublicKey, SecretKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;

/// Domain tag for signed risk-attestation payloads.
pub const RISK_ATTESTATION_SIGNING_DOMAIN: &str = "exo.identity.risk_attestation.v1";

const RISK_ATTESTATION_SIGNING_SCHEMA_VERSION: u16 = 1;

/// Discrete risk severity levels for identity adjudication, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
    Unassessed,
}

/// A signed risk assessment binding a subject DID to a risk level with expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAttestation {
    pub subject_did: Did,
    pub attester_did: Did,
    pub level: RiskLevel,
    pub evidence_hash: [u8; 32],
    pub timestamp: Timestamp,
    pub expiry: Timestamp,
    pub signature: Signature,
}

impl From<RiskLevel> for u8 {
    fn from(level: RiskLevel) -> Self {
        match level {
            RiskLevel::Minimal => 0,
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
            RiskLevel::Unassessed => 5,
        }
    }
}

/// Canonical CBOR payload signed by risk attesters.
///
/// The domain tag prevents cross-protocol signature reuse. The schema version
/// allows future payload changes without accepting legacy byte-concat
/// signatures.
pub fn risk_attestation_signing_payload(
    subject_did: &Did,
    attester_did: &Did,
    level: RiskLevel,
    evidence_hash: &[u8; 32],
    timestamp: Timestamp,
    expiry: Timestamp,
) -> Result<Vec<u8>, IdentityError> {
    let payload = (
        RISK_ATTESTATION_SIGNING_DOMAIN,
        RISK_ATTESTATION_SIGNING_SCHEMA_VERSION,
        subject_did,
        attester_did,
        level,
        evidence_hash,
        timestamp,
        expiry,
    );
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded).map_err(|e| {
        IdentityError::RiskAttestationSigningPayloadEncoding {
            reason: e.to_string(),
        }
    })?;
    Ok(encoded)
}

#[cfg(test)]
fn legacy_risk_attestation_signing_payload(
    subject_did: &Did,
    attester_did: &Did,
    level: RiskLevel,
    evidence_hash: &[u8; 32],
    timestamp: Timestamp,
    expiry: Timestamp,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(subject_did.as_str().as_bytes());
    payload.extend_from_slice(attester_did.as_str().as_bytes());
    payload.extend_from_slice(&[u8::from(level)]);
    payload.extend_from_slice(evidence_hash);
    payload.extend_from_slice(&timestamp.physical_ms.to_le_bytes());
    payload.extend_from_slice(&expiry.physical_ms.to_le_bytes());
    payload
}

/// Input parameters for producing a risk attestation.
#[derive(Debug, Clone)]
pub struct RiskContext {
    pub attester_did: Did,
    pub evidence: Vec<u8>,
    pub now: Timestamp,
    pub validity_ms: u64,
    pub level: RiskLevel,
}

/// Policy that maps operation names to maximum acceptable risk levels.
#[derive(Debug, Clone, Default)]
pub struct RiskPolicy {
    thresholds: std::collections::BTreeMap<String, RiskLevel>,
}

impl RiskPolicy {
    /// Create an empty risk policy with no thresholds defined.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum acceptable risk level for a named operation.
    pub fn set_threshold(&mut self, operation: &str, max_level: RiskLevel) {
        self.thresholds.insert(operation.to_owned(), max_level);
    }

    /// Return `true` if the given risk level is at or below the threshold for the operation.
    #[must_use]
    pub fn is_acceptable(&self, operation: &str, level: RiskLevel) -> bool {
        match self.thresholds.get(operation) {
            Some(max) => level <= *max,
            None => false,
        }
    }
}

/// Create a signed risk attestation for a subject DID using the given context and attester key.
pub fn assess_risk(
    subject: &Did,
    context: &RiskContext,
    attester_key: &SecretKey,
) -> Result<RiskAttestation, IdentityError> {
    let evidence_hash: [u8; 32] = *blake3::hash(&context.evidence).as_bytes();
    let expiry_physical_ms = context
        .now
        .physical_ms
        .checked_add(context.validity_ms)
        .ok_or(IdentityError::RiskAttestationExpiryOverflow {
            now_physical_ms: context.now.physical_ms,
            validity_ms: context.validity_ms,
        })?;
    let expiry = Timestamp::new(expiry_physical_ms, 0);

    let payload = risk_attestation_signing_payload(
        subject,
        &context.attester_did,
        context.level,
        &evidence_hash,
        context.now,
        expiry,
    )?;

    let signature = crypto::sign(&payload, attester_key);

    Ok(RiskAttestation {
        subject_did: subject.clone(),
        attester_did: context.attester_did.clone(),
        level: context.level,
        evidence_hash,
        timestamp: context.now,
        expiry,
        signature,
    })
}

/// Verify the cryptographic signature on a risk attestation against the attester's public key.
#[must_use]
pub fn verify_attestation(attestation: &RiskAttestation, attester_key: &PublicKey) -> bool {
    if attestation.signature.is_empty() || attestation.signature.ed25519_component_is_zero() {
        return false;
    }
    let Ok(payload) = risk_attestation_signing_payload(
        &attestation.subject_did,
        &attestation.attester_did,
        attestation.level,
        &attestation.evidence_hash,
        attestation.timestamp,
        attestation.expiry,
    ) else {
        return false;
    };
    crypto::verify(&payload, &attestation.signature, attester_key)
}

/// Check whether a risk attestation has expired relative to the given timestamp.
#[must_use]
pub fn is_expired(attestation: &RiskAttestation, now: &Timestamp) -> bool {
    now.physical_ms >= attestation.expiry.physical_ms
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::generate_keypair;

    use super::*;

    fn make_did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("valid did")
    }

    fn make_context(attester_did: Did, level: RiskLevel) -> RiskContext {
        RiskContext {
            attester_did,
            evidence: b"test evidence data".to_vec(),
            now: Timestamp::new(10_000, 0),
            validity_ms: 5_000,
            level,
        }
    }

    #[test]
    fn assess_and_verify() {
        let (pk, sk) = generate_keypair();
        let attester_did = make_did("attester");
        let subject_did = make_did("subject");
        let ctx = make_context(attester_did, RiskLevel::Low);

        let att = assess_risk(&subject_did, &ctx, &sk).expect("risk attestation");
        assert_eq!(att.level, RiskLevel::Low);
        assert_eq!(att.subject_did, subject_did);
        assert!(verify_attestation(&att, &pk));
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let (_pk, sk) = generate_keypair();
        let attester_did = make_did("attester2");
        let subject_did = make_did("subject2");
        let ctx = make_context(attester_did, RiskLevel::Medium);

        let att = assess_risk(&subject_did, &ctx, &sk).expect("risk attestation");
        let (wrong_pk, _) = generate_keypair();
        assert!(!verify_attestation(&att, &wrong_pk));
    }

    #[test]
    fn verify_rejects_empty_and_zero_signatures() {
        let (pk, sk) = generate_keypair();
        let attester_did = make_did("attester-empty");
        let subject_did = make_did("subject-empty");
        let ctx = make_context(attester_did, RiskLevel::Low);
        let mut att = assess_risk(&subject_did, &ctx, &sk).expect("risk attestation");

        att.signature = Signature::Empty;
        assert!(!verify_attestation(&att, &pk));

        att.signature = Signature::Ed25519([0u8; 64]);
        assert!(!verify_attestation(&att, &pk));
    }

    #[test]
    fn verify_rejects_tampered_attestation() {
        let (pk, sk) = generate_keypair();
        let attester_did = make_did("attester-tamper");
        let subject_did = make_did("subject-tamper");
        let ctx = make_context(attester_did, RiskLevel::Low);
        let mut att = assess_risk(&subject_did, &ctx, &sk).expect("risk attestation");

        att.level = RiskLevel::Critical;

        assert!(!verify_attestation(&att, &pk));
    }

    #[test]
    fn assess_risk_rejects_expiry_overflow() {
        let (_pk, sk) = generate_keypair();
        let attester_did = make_did("attester-overflow");
        let subject_did = make_did("subject-overflow");
        let ctx = RiskContext {
            attester_did,
            evidence: b"test evidence data".to_vec(),
            now: Timestamp::new(u64::MAX, 0),
            validity_ms: 1,
            level: RiskLevel::Low,
        };

        let err = assess_risk(&subject_did, &ctx, &sk).expect_err("expiry overflow");
        assert!(matches!(
            err,
            crate::error::IdentityError::RiskAttestationExpiryOverflow {
                now_physical_ms: u64::MAX,
                validity_ms: 1
            }
        ));
    }

    #[test]
    fn expiry_check() {
        let (_pk, sk) = generate_keypair();
        let attester_did = make_did("attester3");
        let subject_did = make_did("subject3");
        let ctx = make_context(attester_did, RiskLevel::Minimal);

        let att = assess_risk(&subject_did, &ctx, &sk).expect("risk attestation");
        assert!(!is_expired(&att, &Timestamp::new(14_999, 0)));
        assert!(is_expired(&att, &Timestamp::new(15_000, 0)));
        assert!(is_expired(&att, &Timestamp::new(20_000, 0)));
    }

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::Minimal < RiskLevel::Low);
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
        assert!(RiskLevel::Critical < RiskLevel::Unassessed);
    }

    #[test]
    fn risk_policy_threshold() {
        let mut policy = RiskPolicy::new();
        policy.set_threshold("transfer", RiskLevel::Medium);

        assert!(policy.is_acceptable("transfer", RiskLevel::Minimal));
        assert!(policy.is_acceptable("transfer", RiskLevel::Low));
        assert!(policy.is_acceptable("transfer", RiskLevel::Medium));
        assert!(!policy.is_acceptable("transfer", RiskLevel::High));
        assert!(!policy.is_acceptable("transfer", RiskLevel::Critical));
    }

    #[test]
    fn risk_policy_unknown_operation_denied() {
        let policy = RiskPolicy::new();
        assert!(!policy.is_acceptable("unknown_op", RiskLevel::Minimal));
    }

    #[test]
    fn all_risk_levels_assessed() {
        let (pk, sk) = generate_keypair();
        let attester_did = make_did("attester4");

        for level in [
            RiskLevel::Minimal,
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
            RiskLevel::Unassessed,
        ] {
            let subject = make_did("target");
            let ctx = make_context(attester_did.clone(), level);
            let att = assess_risk(&subject, &ctx, &sk).expect("risk attestation");
            assert_eq!(att.level, level);
            assert!(verify_attestation(&att, &pk));
        }
    }

    #[test]
    fn evidence_hash_deterministic() {
        let (_pk, sk) = generate_keypair();
        let attester_did = make_did("attester5");
        let subject = make_did("target2");
        let ctx = make_context(attester_did, RiskLevel::Low);

        let att1 = assess_risk(&subject, &ctx, &sk).expect("risk attestation");
        let att2 = assess_risk(&subject, &ctx, &sk).expect("risk attestation");
        assert_eq!(att1.evidence_hash, att2.evidence_hash);
    }

    #[test]
    fn risk_attestation_signing_payload_is_domain_separated_cbor() {
        let subject_did = make_did("payload-subject");
        let attester_did = make_did("payload-attester");
        let evidence_hash = [7u8; 32];

        let payload = risk_attestation_signing_payload(
            &subject_did,
            &attester_did,
            RiskLevel::High,
            &evidence_hash,
            Timestamp::new(12_000, 3),
            Timestamp::new(18_000, 4),
        )
        .expect("canonical risk payload");

        assert!(
            payload
                .windows(b"exo.identity.risk_attestation.v1".len())
                .any(|window| window == b"exo.identity.risk_attestation.v1"),
            "domain tag must be encoded inside the signed payload"
        );

        let payload_again = risk_attestation_signing_payload(
            &subject_did,
            &attester_did,
            RiskLevel::High,
            &evidence_hash,
            Timestamp::new(12_000, 3),
            Timestamp::new(18_000, 4),
        )
        .expect("canonical risk payload");
        assert_eq!(payload, payload_again);
    }

    #[test]
    fn verify_rejects_legacy_raw_concat_signature() {
        let (pk, sk) = generate_keypair();
        let subject_did = make_did("legacy-subject");
        let attester_did = make_did("legacy-attester");
        let evidence_hash = [9u8; 32];
        let timestamp = Timestamp::new(21_000, 1);
        let expiry = Timestamp::new(27_000, 2);
        let legacy_payload = legacy_risk_attestation_signing_payload(
            &subject_did,
            &attester_did,
            RiskLevel::Critical,
            &evidence_hash,
            timestamp,
            expiry,
        );
        let legacy_signature = crypto::sign(&legacy_payload, &sk);

        let attestation = RiskAttestation {
            subject_did,
            attester_did,
            level: RiskLevel::Critical,
            evidence_hash,
            timestamp,
            expiry,
            signature: legacy_signature,
        };

        assert!(
            !verify_attestation(&attestation, &pk),
            "legacy byte-concat signatures must not verify"
        );
    }
}
