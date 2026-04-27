//! Peer attestation creation and validation.
//!
//! Enforces:
//! - Self-attestation is rejected
//! - Duplicate attestation from same attester to same target is rejected
//! - Attestation from an unverified DID is rejected
//!
//! Spec reference: §7.2 (POST /api/v1/0dentity/:did/attest).

use exo_core::{
    crypto,
    types::{Did, Hash256, PublicKey, Signature},
};
use serde::Serialize;
use thiserror::Error;

use super::types::{AttestationType, ClaimStatus, ClaimType, IdentityClaim, PeerAttestation};

// ---------------------------------------------------------------------------
// AttestationError
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("Self-attestation is not permitted")]
    SelfAttestation,
    #[error("Duplicate attestation: already vouched for this identity")]
    DuplicateAttestation,
    #[error("Attester is not verified — at least one verified claim is required")]
    AttesterUnverified,
    #[error("Attestation signature verification failed")]
    InvalidSignature,
    #[error("Attestation signing payload encoding failed: {reason}")]
    SigningPayloadEncoding { reason: String },
    #[error("Attestation target claim encoding failed: {reason}")]
    TargetClaimEncoding { reason: String },
}

pub struct CreateAttestationInput<'a> {
    pub attester_did: &'a Did,
    pub target_did: &'a Did,
    pub attestation_type: AttestationType,
    pub message_hash: Option<Hash256>,
    pub dag_node_hash: Hash256,
    pub created_ms: u64,
    pub attester_public_key: PublicKey,
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate that an attestation is permitted.
///
/// Rules enforced (spec §7.2):
/// 1. `attester_did != target_did` (no self-attestation)
/// 2. `attester_did` has at least one verified claim
/// 3. No existing attestation from this attester to this target
pub fn validate_attestation(
    attester_did: &Did,
    target_did: &Did,
    attester_claims: &[IdentityClaim],
    already_exists: bool,
) -> Result<(), AttestationError> {
    // Rule 1: no self-attestation
    if attester_did.as_str() == target_did.as_str() {
        return Err(AttestationError::SelfAttestation);
    }

    // Rule 2: attester must have at least one verified claim
    let attester_is_verified = attester_claims
        .iter()
        .any(|c| c.status == ClaimStatus::Verified);
    if !attester_is_verified {
        return Err(AttestationError::AttesterUnverified);
    }

    // Rule 3: no duplicate
    if already_exists {
        return Err(AttestationError::DuplicateAttestation);
    }

    Ok(())
}

/// Canonical CBOR payload that an attester signs.
///
/// The domain tag prevents cross-protocol reuse. The tuple binds the signature
/// to one attester DID, target DID, attestation type, optional statement hash,
/// and signed creation timestamp.
pub fn attestation_signing_payload(
    attester_did: &Did,
    target_did: &Did,
    attestation_type: &AttestationType,
    message_hash: Option<&Hash256>,
    created_ms: u64,
) -> Result<Vec<u8>, AttestationError> {
    let tuple = (
        "exo.zerodentity.attestation.v1",
        attester_did,
        target_did,
        attestation_type,
        message_hash,
        created_ms,
    );
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
        AttestationError::SigningPayloadEncoding {
            reason: e.to_string(),
        }
    })?;
    Ok(buf)
}

fn canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, AttestationError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| {
        AttestationError::TargetClaimEncoding {
            reason: e.to_string(),
        }
    })?;
    Ok(buf)
}

/// Verify the attester's Ed25519 signature over the canonical payload.
///
/// Rejects `Signature::Empty`, all-zero Ed25519 sentinels, malformed payloads,
/// wrong keys, and signatures replayed over a different payload.
#[must_use]
pub fn verify_attestation_signature(
    attester_did: &Did,
    target_did: &Did,
    attestation_type: &AttestationType,
    message_hash: Option<&Hash256>,
    created_ms: u64,
    attester_public_key: &PublicKey,
    signature: &Signature,
) -> bool {
    if signature.is_empty() {
        return false;
    }
    let raw = signature.as_bytes();
    if !raw.is_empty() && raw.iter().all(|b| *b == 0) {
        return false;
    }
    let Ok(payload) = attestation_signing_payload(
        attester_did,
        target_did,
        attestation_type,
        message_hash,
        created_ms,
    ) else {
        return false;
    };
    crypto::verify(&payload, signature, attester_public_key)
}

/// Create a new peer attestation.
///
/// Callers must call `validate_attestation` first.
pub fn create_attestation(
    input: CreateAttestationInput<'_>,
) -> Result<PeerAttestation, AttestationError> {
    if !verify_attestation_signature(
        input.attester_did,
        input.target_did,
        &input.attestation_type,
        input.message_hash.as_ref(),
        input.created_ms,
        &input.attester_public_key,
        &input.signature,
    ) {
        return Err(AttestationError::InvalidSignature);
    }

    let signing_payload = attestation_signing_payload(
        input.attester_did,
        input.target_did,
        &input.attestation_type,
        input.message_hash.as_ref(),
        input.created_ms,
    )?;
    let mut id_input = signing_payload;
    id_input.extend_from_slice(input.attester_public_key.as_bytes());
    id_input.extend_from_slice(&input.signature.to_bytes());
    id_input.extend_from_slice(input.dag_node_hash.as_bytes());
    let attestation_id = hex::encode(Hash256::digest(&id_input).as_bytes());

    Ok(PeerAttestation {
        attestation_id,
        attester_did: input.attester_did.clone(),
        target_did: input.target_did.clone(),
        attestation_type: input.attestation_type,
        message_hash: input.message_hash,
        created_ms: input.created_ms,
        attester_public_key: input.attester_public_key,
        signature: input.signature,
        dag_node_hash: input.dag_node_hash,
    })
}

/// Score impact of an attestation on the target's network_reputation axis.
///
/// Returns the basis-point increase expected on the target's network_reputation.
pub fn target_score_impact() -> u32 {
    500 // +5 in basis points
}

/// Score impact on the attester's network_reputation axis.
///
/// Returns the basis-point increase expected on the attester's network_reputation.
pub fn attester_score_impact() -> u32 {
    300 // +3 in basis points
}

/// Convert attester's claims into `ClaimType::PeerAttestation` entries
/// that can be added to the target's claim set.
pub fn build_target_claim(
    attestation: &PeerAttestation,
    dag_node_hash: Hash256,
    now_ms: u64,
) -> Result<IdentityClaim, AttestationError> {
    Ok(IdentityClaim {
        claim_hash: target_claim_hash(&attestation.attester_did, &attestation.target_did)?,
        subject_did: attestation.target_did.clone(),
        claim_type: ClaimType::PeerAttestation {
            attester_did: attestation.attester_did.clone(),
        },
        status: ClaimStatus::Verified, // attestations are immediately verified
        created_ms: now_ms,
        verified_ms: Some(now_ms),
        expires_ms: None,
        signature: attestation.signature.clone(),
        dag_node_hash,
    })
}

/// Deterministic content hash for the target's derived peer-attestation claim.
pub fn target_claim_hash(
    attester_did: &Did,
    target_did: &Did,
) -> Result<Hash256, AttestationError> {
    let payload = (
        "exo.zerodentity.target_claim.v1",
        attester_did.as_str(),
        target_did.as_str(),
    );
    Ok(Hash256::digest(&canonical_cbor(&payload)?))
}

/// Deterministic store ID for the target's derived peer-attestation claim.
pub fn target_claim_id(attestation: &PeerAttestation) -> Result<String, AttestationError> {
    let payload = (
        "exo.zerodentity.target_claim_id.v1",
        attestation.attestation_id.as_str(),
        attestation.attester_did.as_str(),
        attestation.target_did.as_str(),
    );
    Ok(hex::encode(
        Hash256::digest(&canonical_cbor(&payload)?).as_bytes(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_core::{
        crypto,
        types::{PublicKey, SecretKey, Signature},
    };

    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s).expect("did")
    }
    fn hash(b: &[u8]) -> Hash256 {
        Hash256::digest(b)
    }

    fn keypair(seed: u8) -> (PublicKey, SecretKey) {
        let pair = crypto::KeyPair::from_secret_bytes([seed; 32]).expect("keypair");
        (*pair.public_key(), pair.secret_key().clone())
    }

    fn signed_attestation_signature(
        attester: &Did,
        target: &Did,
        attestation_type: &AttestationType,
        message_hash: Option<&Hash256>,
        created_ms: u64,
        secret_key: &SecretKey,
    ) -> Signature {
        let payload = attestation_signing_payload(
            attester,
            target,
            attestation_type,
            message_hash,
            created_ms,
        )
        .expect("signing payload");
        crypto::sign(&payload, secret_key)
    }

    fn verified_claim(d: &Did) -> IdentityClaim {
        IdentityClaim {
            claim_hash: hash(b"email"),
            subject_did: d.clone(),
            claim_type: ClaimType::Email,
            status: ClaimStatus::Verified,
            created_ms: 1000,
            verified_ms: Some(2000),
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: hash(b"dag"),
        }
    }

    // ---- Self-attestation rejected ----

    #[test]
    fn self_attestation_rejected() {
        let d = did("did:exo:self");
        let claims = vec![verified_claim(&d)];
        let err = validate_attestation(&d, &d, &claims, false).unwrap_err();
        assert_eq!(err, AttestationError::SelfAttestation);
    }

    // ---- Duplicate rejected ----

    #[test]
    fn duplicate_attestation_rejected() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let claims = vec![verified_claim(&attester)];
        let err = validate_attestation(&attester, &target, &claims, true).unwrap_err();
        assert_eq!(err, AttestationError::DuplicateAttestation);
    }

    // ---- Unverified attester rejected ----

    #[test]
    fn unverified_attester_rejected() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        // No verified claims
        let unverified_claim = IdentityClaim {
            claim_hash: hash(b"name"),
            subject_did: attester.clone(),
            claim_type: ClaimType::DisplayName,
            status: ClaimStatus::Pending,
            created_ms: 1000,
            verified_ms: None,
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: hash(b"dag"),
        };
        let err = validate_attestation(&attester, &target, &[unverified_claim], false).unwrap_err();
        assert_eq!(err, AttestationError::AttesterUnverified);
    }

    // ---- Valid attestation ----

    #[test]
    fn valid_attestation_ok() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let claims = vec![verified_claim(&attester)];
        assert!(validate_attestation(&attester, &target, &claims, false).is_ok());
    }

    // ---- create_attestation ----

    #[test]
    fn create_attestation_fields() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let (public_key, secret_key) = keypair(7);
        let created_ms = 1_000_000;
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            created_ms,
            &secret_key,
        );
        let att = create_attestation(CreateAttestationInput {
            attester_did: &attester,
            target_did: &target,
            attestation_type: AttestationType::Identity,
            message_hash: None,
            dag_node_hash: hash(b"dag"),
            created_ms,
            attester_public_key: public_key,
            signature: signature.clone(),
        })
        .expect("attestation");
        assert_eq!(att.attester_did.as_str(), attester.as_str());
        assert_eq!(att.target_did.as_str(), target.as_str());
        assert_eq!(att.attestation_type, AttestationType::Identity);
        assert_eq!(att.created_ms, 1_000_000);
        assert_eq!(att.attester_public_key, public_key);
        assert_eq!(att.signature, signature);
        assert_eq!(att.attestation_id.len(), 64);
    }

    // ---- build_target_claim ----

    #[test]
    fn build_target_claim_is_verified_peer_attestation() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let (public_key, secret_key) = keypair(9);
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Trustworthy,
            None,
            500,
            &secret_key,
        );
        let att = create_attestation(CreateAttestationInput {
            attester_did: &attester,
            target_did: &target,
            attestation_type: AttestationType::Trustworthy,
            message_hash: None,
            dag_node_hash: hash(b"dag"),
            created_ms: 500,
            attester_public_key: public_key,
            signature: signature.clone(),
        })
        .expect("attestation");
        let claim = build_target_claim(&att, hash(b"dag2"), 600).expect("target claim");
        assert_eq!(claim.subject_did.as_str(), target.as_str());
        assert_eq!(claim.status, ClaimStatus::Verified);
        assert_eq!(claim.signature, signature);
        assert!(matches!(
            claim.claim_type,
            ClaimType::PeerAttestation { .. }
        ));
    }

    #[test]
    fn target_claim_id_is_deterministic_and_attestation_bound() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let (public_key, secret_key) = keypair(17);
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            700,
            &secret_key,
        );
        let att = create_attestation(CreateAttestationInput {
            attester_did: &attester,
            target_did: &target,
            attestation_type: AttestationType::Identity,
            message_hash: None,
            dag_node_hash: hash(b"dag-a"),
            created_ms: 700,
            attester_public_key: public_key,
            signature,
        })
        .expect("attestation");
        let same = target_claim_id(&att).expect("claim id");

        let mut different = att.clone();
        different.attestation_id = "different-attestation-id".to_owned();

        assert_eq!(target_claim_id(&att).expect("claim id"), same);
        assert_ne!(target_claim_id(&different).expect("claim id"), same);
    }

    #[test]
    fn attestation_signing_payload_is_deterministic_and_domain_separated() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let payload_a =
            attestation_signing_payload(&attester, &target, &AttestationType::Identity, None, 42)
                .expect("payload");
        let payload_b =
            attestation_signing_payload(&attester, &target, &AttestationType::Identity, None, 42)
                .expect("payload");
        let replay_payload = attestation_signing_payload(
            &attester,
            &did("did:exo:other-target"),
            &AttestationType::Identity,
            None,
            42,
        )
        .expect("payload");

        assert_eq!(payload_a, payload_b);
        assert_ne!(payload_a, replay_payload);
        assert!(
            payload_a
                .windows(b"exo.zerodentity.attestation.v1".len())
                .any(|w| w == b"exo.zerodentity.attestation.v1")
        );
    }

    #[test]
    fn verify_attestation_signature_accepts_valid_signature() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let message_hash = hash(b"statement");
        let (public_key, secret_key) = keypair(11);
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Professional,
            Some(&message_hash),
            1234,
            &secret_key,
        );

        assert!(verify_attestation_signature(
            &attester,
            &target,
            &AttestationType::Professional,
            Some(&message_hash),
            1234,
            &public_key,
            &signature
        ));
    }

    #[test]
    fn verify_attestation_signature_rejects_empty_and_zero_signatures() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let (public_key, _) = keypair(13);

        assert!(!verify_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            1234,
            &public_key,
            &Signature::Empty
        ));
        assert!(!verify_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            1234,
            &public_key,
            &Signature::from_bytes([0u8; 64])
        ));
    }

    #[test]
    fn verify_attestation_signature_rejects_wrong_key() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let (_, secret_key) = keypair(15);
        let (wrong_public_key, _) = keypair(16);
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            1234,
            &secret_key,
        );

        assert!(!verify_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            1234,
            &wrong_public_key,
            &signature
        ));
    }

    #[test]
    fn verify_attestation_signature_rejects_tampered_payload() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let (public_key, secret_key) = keypair(17);
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            1234,
            &secret_key,
        );

        assert!(!verify_attestation_signature(
            &attester,
            &target,
            &AttestationType::Trustworthy,
            None,
            1234,
            &public_key,
            &signature
        ));
    }

    #[test]
    fn verify_attestation_signature_rejects_replay_to_other_target() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let replay_target = did("did:exo:replay-target");
        let (public_key, secret_key) = keypair(19);
        let signature = signed_attestation_signature(
            &attester,
            &target,
            &AttestationType::Identity,
            None,
            1234,
            &secret_key,
        );

        assert!(!verify_attestation_signature(
            &attester,
            &replay_target,
            &AttestationType::Identity,
            None,
            1234,
            &public_key,
            &signature
        ));
    }
}
