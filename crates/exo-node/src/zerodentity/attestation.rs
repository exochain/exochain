//! Peer attestation creation and validation.
//!
//! Enforces:
//! - Self-attestation is rejected
//! - Duplicate attestation from same attester to same target is rejected
//! - Attestation from an unverified DID is rejected
//!
//! Spec reference: §7.2 (POST /api/v1/0dentity/:did/attest).

use exo_core::types::{Did, Hash256};
use thiserror::Error;
use uuid::Uuid;

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

/// Create a new peer attestation.
///
/// Callers must call `validate_attestation` first.
pub fn create_attestation(
    attester_did: &Did,
    target_did: &Did,
    attestation_type: AttestationType,
    message_hash: Option<Hash256>,
    dag_node_hash: Hash256,
    now_ms: u64,
) -> PeerAttestation {
    PeerAttestation {
        attestation_id: Uuid::new_v4().to_string(),
        attester_did: attester_did.clone(),
        target_did: target_did.clone(),
        attestation_type,
        message_hash,
        created_ms: now_ms,
        dag_node_hash,
    }
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
) -> IdentityClaim {
    use exo_core::types::Signature;
    let payload = format!(
        "attestation:{}:{}",
        attestation.attester_did.as_str(),
        attestation.target_did.as_str()
    );
    IdentityClaim {
        claim_hash: Hash256::digest(payload.as_bytes()),
        subject_did: attestation.target_did.clone(),
        claim_type: ClaimType::PeerAttestation {
            attester_did: attestation.attester_did.clone(),
        },
        status: ClaimStatus::Verified, // attestations are immediately verified
        created_ms: now_ms,
        verified_ms: Some(now_ms),
        expires_ms: None,
        signature: Signature::Empty,
        dag_node_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use exo_core::types::Signature;

    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s).expect("did")
    }
    fn hash(b: &[u8]) -> Hash256 {
        Hash256::digest(b)
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
        let att = create_attestation(
            &attester,
            &target,
            AttestationType::Identity,
            None,
            hash(b"dag"),
            1_000_000,
        );
        assert_eq!(att.attester_did.as_str(), attester.as_str());
        assert_eq!(att.target_did.as_str(), target.as_str());
        assert_eq!(att.attestation_type, AttestationType::Identity);
        assert_eq!(att.created_ms, 1_000_000);
    }

    // ---- build_target_claim ----

    #[test]
    fn build_target_claim_is_verified_peer_attestation() {
        let attester = did("did:exo:attester");
        let target = did("did:exo:target");
        let att = create_attestation(
            &attester,
            &target,
            AttestationType::Trustworthy,
            None,
            hash(b"dag"),
            500,
        );
        let claim = build_target_claim(&att, hash(b"dag2"), 600);
        assert_eq!(claim.subject_did.as_str(), target.as_str());
        assert_eq!(claim.status, ClaimStatus::Verified);
        assert!(matches!(
            claim.claim_type,
            ClaimType::PeerAttestation { .. }
        ));
    }
}
