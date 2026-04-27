//! Challenge paths for Sybil adjudication — CR-001 section 8.5.
//!
//! Any credible allegation of one of the four formal Sybil challenge grounds
//! is admitted through `admit_challenge`, which immediately places the
//! contested action in `ContestStatus::PauseEligible` and opens an audit
//! trail.  The caller then signals the CGR Kernel that the action is under
//! active challenge by setting `active_challenge_reason` on the
//! `AdjudicationContext`, causing the kernel to return `Verdict::Escalated`
//! rather than `Verdict::Denied`.

use exo_core::{Did, PublicKey, SecretKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::EscalationError;

// ---------------------------------------------------------------------------
// Challenge grounds (CR-001 §8.5)
// ---------------------------------------------------------------------------

/// The four formal Sybil challenge grounds recognised by EXOCHAIN.
///
/// Any credible allegation on any of these grounds is admissible and places
/// the contested action in a pause-eligible hold pending review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SybilChallengeGround {
    /// One underlying actor or control plane appears as multiple independent
    /// approvers, reviewers, or DIDs.
    ConcealedCommonControl,
    /// Multiple actors behave in lockstep so as to inflate apparent consensus
    /// or quorum without genuine independent judgment.
    CoordinatedManipulation,
    /// The counted quorum is tainted by non-independent, coordinated, or
    /// synthetic participants.
    QuorumContamination,
    /// A synthetic (AI-generated) opinion or entity is presented as if it
    /// were an independent human participant.
    SyntheticHumanMisrepresentation,
}

impl std::fmt::Display for SybilChallengeGround {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConcealedCommonControl => write!(f, "ConcealedCommonControl"),
            Self::CoordinatedManipulation => write!(f, "CoordinatedManipulation"),
            Self::QuorumContamination => write!(f, "QuorumContamination"),
            Self::SyntheticHumanMisrepresentation => write!(f, "SyntheticHumanMisrepresentation"),
        }
    }
}

// ---------------------------------------------------------------------------
// Contest status
// ---------------------------------------------------------------------------

/// Lifecycle status of a contested action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContestStatus {
    /// Challenge admitted; action is paused pending review.  Callers MUST
    /// propagate this into `AdjudicationContext::active_challenge_reason` so
    /// the CGR Kernel returns `Verdict::Escalated`.
    PauseEligible,
    /// Evidentiary review is in progress.
    UnderReview,
    /// Challenge resolved: the contested action may proceed (or was reversed).
    Resolved,
    /// Challenge dismissed: insufficient grounds; action is unblocked.
    Dismissed,
}

// ---------------------------------------------------------------------------
// Challenge admission provenance
// ---------------------------------------------------------------------------

/// Canonical domain for Ed25519 signatures admitting Sybil challenges.
pub const CHALLENGE_ADMISSION_DOMAIN: &str = "exo.escalation.challenge.admission.v1";

/// The signable, deterministic challenge-admission payload.
///
/// A caller supplies every piece of identity, timing, and authority context.
/// This module only verifies the signed payload and materializes the hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeAdmission {
    pub hold_id: Uuid,
    pub action_id: [u8; 32],
    pub ground: SybilChallengeGround,
    pub admitted_at: Timestamp,
    pub admitted_by: Did,
    pub admitter_public_key: PublicKey,
    pub evidence_hash: [u8; 32],
    pub authority_chain_hash: [u8; 32],
}

/// A challenge admission plus the admitting actor's Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedChallengeAdmission {
    pub admission: ChallengeAdmission,
    pub admission_signature: Signature,
}

// ---------------------------------------------------------------------------
// ContestHold
// ---------------------------------------------------------------------------

/// A hold placed on a contested action upon challenge admission.
///
/// Every state transition appends an entry to `audit_log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestHold {
    pub id: Uuid,
    /// Identifies the action under challenge (matches kernel `action_id`).
    pub action_id: [u8; 32],
    pub ground: SybilChallengeGround,
    pub status: ContestStatus,
    pub admitted_at: Timestamp,
    pub admitted_by: Did,
    pub admitter_public_key: PublicKey,
    pub evidence_hash: [u8; 32],
    pub authority_chain_hash: [u8; 32],
    pub admission_signature: Signature,
    /// Append-only audit trail of status transitions.
    pub audit_log: Vec<String>,
}

impl ContestHold {
    /// Returns a human-readable reason string suitable for embedding in
    /// `AdjudicationContext::active_challenge_reason`.
    #[must_use]
    pub fn escalation_reason(&self) -> String {
        format!(
            "SybilChallenge/{}: action {:?} is pause-eligible under active review",
            self.ground, self.action_id
        )
    }
}

// ---------------------------------------------------------------------------
// Challenge admission
// ---------------------------------------------------------------------------

/// Build the canonical CBOR payload signed for challenge admission.
///
/// # Errors
/// Returns `EscalationError::SerializationFailed` if canonical CBOR encoding
/// fails.
pub fn challenge_admission_payload(
    admission: &ChallengeAdmission,
) -> Result<Vec<u8>, EscalationError> {
    let payload = (
        CHALLENGE_ADMISSION_DOMAIN,
        &admission.hold_id,
        &admission.action_id,
        &admission.ground,
        &admission.admitted_at,
        &admission.admitted_by,
        &admission.admitter_public_key,
        &admission.evidence_hash,
        &admission.authority_chain_hash,
    );
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        EscalationError::SerializationFailed {
            context: "challenge admission payload".into(),
            reason: e.to_string(),
        }
    })?;
    Ok(encoded)
}

/// Sign a challenge admission with the admitting actor's Ed25519 key.
///
/// # Errors
/// Returns an error if required provenance fields are placeholders or if the
/// canonical payload cannot be serialized.
pub fn sign_challenge_admission(
    admission: ChallengeAdmission,
    secret_key: &SecretKey,
) -> Result<SignedChallengeAdmission, EscalationError> {
    validate_challenge_admission_metadata(&admission)?;
    let payload = challenge_admission_payload(&admission)?;
    Ok(SignedChallengeAdmission {
        admission,
        admission_signature: crypto::sign(&payload, secret_key),
    })
}

/// Verify a signed Sybil challenge admission.
///
/// # Errors
/// Returns an error if provenance metadata is placeholder-like, if the
/// signature is empty/zero, or if Ed25519 verification fails.
pub fn verify_challenge_admission(
    signed: &SignedChallengeAdmission,
) -> Result<(), EscalationError> {
    validate_challenge_admission_metadata(&signed.admission)?;
    if signed.admission_signature.is_empty() {
        return Err(EscalationError::InvalidSignature {
            signer: signed.admission.admitted_by.to_string(),
            reason: "challenge admission signature is empty or all-zero".into(),
        });
    }
    let payload = challenge_admission_payload(&signed.admission)?;
    if !crypto::verify(
        &payload,
        &signed.admission_signature,
        &signed.admission.admitter_public_key,
    ) {
        return Err(EscalationError::InvalidSignature {
            signer: signed.admission.admitted_by.to_string(),
            reason: "challenge admission signature does not verify".into(),
        });
    }
    Ok(())
}

fn validate_challenge_admission_metadata(
    admission: &ChallengeAdmission,
) -> Result<(), EscalationError> {
    if admission.hold_id == Uuid::nil() {
        return Err(EscalationError::InvalidProvenance {
            reason: "challenge hold id must be caller-supplied and non-nil".into(),
        });
    }
    if admission.action_id == [0u8; 32] {
        return Err(EscalationError::InvalidProvenance {
            reason: "challenge action id must be non-zero".into(),
        });
    }
    if admission.evidence_hash == [0u8; 32] {
        return Err(EscalationError::InvalidProvenance {
            reason: "challenge admission requires non-zero evidence hash".into(),
        });
    }
    if admission.authority_chain_hash == [0u8; 32] {
        return Err(EscalationError::InvalidProvenance {
            reason: "challenge admission requires non-zero authority chain hash".into(),
        });
    }
    if admission.admitter_public_key == PublicKey::from_bytes([0u8; 32]) {
        return Err(EscalationError::InvalidProvenance {
            reason: "challenge admission requires a non-zero Ed25519 public key".into(),
        });
    }
    Ok(())
}

/// Admit a credible, signed Sybil challenge and return a `ContestHold` in
/// `PauseEligible` status.
///
/// The caller is responsible for:
/// 1. Storing the `ContestHold` in a durable audit store.
/// 2. Passing `hold.escalation_reason()` into the kernel's
///    `AdjudicationContext::active_challenge_reason` so the CGR Kernel
///    returns `Verdict::Escalated` (not `Verdict::Denied`) while review is
///    pending.
///
/// The hold id and `admitted_at` are supplied by the caller to avoid internal
/// randomness or clock calls.
///
/// # Errors
/// Returns an error if the admission signature or provenance metadata is
/// invalid.
pub fn admit_challenge(signed: SignedChallengeAdmission) -> Result<ContestHold, EscalationError> {
    verify_challenge_admission(&signed)?;
    let admission = signed.admission;
    let entry = format!(
        "admitted at {:?}: ground {} by {} evidence {:?}",
        admission.admitted_at, admission.ground, admission.admitted_by, admission.evidence_hash
    );
    Ok(ContestHold {
        id: admission.hold_id,
        action_id: admission.action_id,
        ground: admission.ground,
        status: ContestStatus::PauseEligible,
        admitted_at: admission.admitted_at,
        admitted_by: admission.admitted_by,
        admitter_public_key: admission.admitter_public_key,
        evidence_hash: admission.evidence_hash,
        authority_chain_hash: admission.authority_chain_hash,
        admission_signature: signed.admission_signature,
        audit_log: vec![entry],
    })
}

/// Advance a contest hold to `UnderReview`.
pub fn begin_review(hold: &mut ContestHold, at: Timestamp) -> Result<(), EscalationError> {
    if hold.status != ContestStatus::PauseEligible {
        return Err(EscalationError::InvalidStateTransition {
            from: format!("{:?}", hold.status),
            to: "UnderReview".into(),
        });
    }
    hold.audit_log.push(format!("review started at {at:?}"));
    hold.status = ContestStatus::UnderReview;
    Ok(())
}

/// Resolve a contest hold (challenge sustained or action reversed).
pub fn resolve_hold(
    hold: &mut ContestHold,
    at: Timestamp,
    outcome: &str,
) -> Result<(), EscalationError> {
    match hold.status {
        ContestStatus::PauseEligible | ContestStatus::UnderReview => {
            hold.audit_log
                .push(format!("resolved at {at:?}: {outcome}"));
            hold.status = ContestStatus::Resolved;
            Ok(())
        }
        _ => Err(EscalationError::InvalidStateTransition {
            from: format!("{:?}", hold.status),
            to: "Resolved".into(),
        }),
    }
}

/// Dismiss a contest hold (insufficient grounds; action unblocked).
pub fn dismiss_hold(
    hold: &mut ContestHold,
    at: Timestamp,
    reason: &str,
) -> Result<(), EscalationError> {
    match hold.status {
        ContestStatus::PauseEligible | ContestStatus::UnderReview => {
            hold.audit_log
                .push(format!("dismissed at {at:?}: {reason}"));
            hold.status = ContestStatus::Dismissed;
            Ok(())
        }
        _ => Err(EscalationError::InvalidStateTransition {
            from: format!("{:?}", hold.status),
            to: "Dismissed".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn action_id() -> [u8; 32] {
        [7u8; 32]
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }
    fn keypair(seed: u8) -> exo_core::crypto::KeyPair {
        exo_core::crypto::KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }
    fn admission_with(
        hold_id: Uuid,
        ground: SybilChallengeGround,
        keypair: &exo_core::crypto::KeyPair,
    ) -> ChallengeAdmission {
        ChallengeAdmission {
            hold_id,
            action_id: action_id(),
            ground,
            admitted_at: ts(1000),
            admitted_by: did("reviewer"),
            admitter_public_key: *keypair.public_key(),
            evidence_hash: [0xEEu8; 32],
            authority_chain_hash: [0xACu8; 32],
        }
    }
    fn signed_admission() -> SignedChallengeAdmission {
        let keypair = keypair(7);
        sign_challenge_admission(
            admission_with(
                uuid(1),
                SybilChallengeGround::ConcealedCommonControl,
                &keypair,
            ),
            keypair.secret_key(),
        )
        .unwrap()
    }

    #[test]
    fn admit_creates_pause_eligible_hold() {
        let hold = admit_challenge(signed_admission()).unwrap();
        assert_eq!(hold.status, ContestStatus::PauseEligible);
        assert_eq!(hold.ground, SybilChallengeGround::ConcealedCommonControl);
        assert_eq!(hold.action_id, action_id());
        assert_eq!(hold.id, uuid(1));
        assert_eq!(hold.admitted_by, did("reviewer"));
        assert_eq!(hold.evidence_hash, [0xEEu8; 32]);
        assert_eq!(hold.authority_chain_hash, [0xACu8; 32]);
        assert!(!hold.admission_signature.is_empty());
        assert!(!hold.audit_log.is_empty());
    }

    #[test]
    fn admit_challenge_is_deterministic_for_same_input() {
        let signed = signed_admission();
        let first = admit_challenge(signed.clone()).unwrap();
        let second = admit_challenge(signed).unwrap();

        assert_eq!(first.id, second.id);
        assert_eq!(first.admitted_at, second.admitted_at);
        assert_eq!(first.admission_signature, second.admission_signature);
    }

    #[test]
    fn verify_challenge_admission_accepts_valid_signature() {
        let signed = signed_admission();
        assert!(verify_challenge_admission(&signed).is_ok());
    }

    #[test]
    fn verify_challenge_admission_rejects_empty_and_zero_signatures() {
        let mut signed = signed_admission();
        signed.admission_signature = Signature::Empty;
        assert!(verify_challenge_admission(&signed).is_err());

        signed.admission_signature = Signature::Ed25519([0u8; 64]);
        assert!(verify_challenge_admission(&signed).is_err());
    }

    #[test]
    fn verify_challenge_admission_rejects_fake_non_empty_signature() {
        let mut signed = signed_admission();
        signed.admission_signature = Signature::Ed25519([0xABu8; 64]);
        assert!(verify_challenge_admission(&signed).is_err());
        assert!(admit_challenge(signed).is_err());
    }

    #[test]
    fn verify_challenge_admission_rejects_wrong_key() {
        let signer_keypair = keypair(7);
        let wrong_keypair = keypair(8);
        let mut signed = sign_challenge_admission(
            admission_with(
                uuid(2),
                SybilChallengeGround::CoordinatedManipulation,
                &signer_keypair,
            ),
            signer_keypair.secret_key(),
        )
        .unwrap();
        signed.admission.admitter_public_key = *wrong_keypair.public_key();
        assert!(verify_challenge_admission(&signed).is_err());
    }

    #[test]
    fn verify_challenge_admission_rejects_tampered_payload() {
        let mut signed = signed_admission();
        signed.admission.evidence_hash = [0xFEu8; 32];
        assert!(verify_challenge_admission(&signed).is_err());
    }

    #[test]
    fn verify_challenge_admission_rejects_replay_to_other_action() {
        let mut signed = signed_admission();
        signed.admission.action_id = [0x99u8; 32];
        assert!(verify_challenge_admission(&signed).is_err());
    }

    #[test]
    fn challenge_admission_payload_is_domain_separated_and_deterministic() {
        let keypair = keypair(7);
        let admission = admission_with(
            uuid(3),
            SybilChallengeGround::SyntheticHumanMisrepresentation,
            &keypair,
        );
        let first = challenge_admission_payload(&admission).unwrap();
        let second = challenge_admission_payload(&admission).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, action_id().to_vec());
        assert!(
            first
                .windows(CHALLENGE_ADMISSION_DOMAIN.len())
                .any(|window| window == CHALLENGE_ADMISSION_DOMAIN.as_bytes())
        );
    }

    #[test]
    fn admit_challenge_rejects_placeholder_provenance() {
        let keypair = keypair(7);
        let mut admission = admission_with(
            Uuid::nil(),
            SybilChallengeGround::ConcealedCommonControl,
            &keypair,
        );
        assert!(sign_challenge_admission(admission.clone(), keypair.secret_key()).is_err());

        admission.hold_id = uuid(4);
        admission.action_id = [0u8; 32];
        assert!(sign_challenge_admission(admission.clone(), keypair.secret_key()).is_err());

        admission.action_id = action_id();
        admission.evidence_hash = [0u8; 32];
        assert!(sign_challenge_admission(admission.clone(), keypair.secret_key()).is_err());

        admission.evidence_hash = [0xEEu8; 32];
        admission.authority_chain_hash = [0u8; 32];
        assert!(sign_challenge_admission(admission, keypair.secret_key()).is_err());
    }

    #[test]
    fn escalation_reason_contains_ground() {
        let keypair = keypair(7);
        let hold = admit_challenge(
            sign_challenge_admission(
                admission_with(
                    uuid(5),
                    SybilChallengeGround::CoordinatedManipulation,
                    &keypair,
                ),
                keypair.secret_key(),
            )
            .unwrap(),
        )
        .unwrap();
        let reason = hold.escalation_reason();
        assert!(reason.contains("CoordinatedManipulation"));
        assert!(reason.contains("SybilChallenge"));
    }

    #[test]
    fn begin_review_transitions_from_pause_eligible() {
        let keypair = keypair(7);
        let mut hold = admit_challenge(
            sign_challenge_admission(
                admission_with(uuid(6), SybilChallengeGround::QuorumContamination, &keypair),
                keypair.secret_key(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(begin_review(&mut hold, ts(2000)).is_ok());
        assert_eq!(hold.status, ContestStatus::UnderReview);
        assert_eq!(hold.audit_log.len(), 2);
    }

    #[test]
    fn begin_review_fails_if_not_pause_eligible() {
        let mut hold = admit_challenge(signed_admission()).unwrap();
        hold.status = ContestStatus::Resolved;
        assert!(begin_review(&mut hold, ts(2000)).is_err());
    }

    #[test]
    fn resolve_hold_from_pause_eligible() {
        let keypair = keypair(7);
        let mut hold = admit_challenge(
            sign_challenge_admission(
                admission_with(
                    uuid(7),
                    SybilChallengeGround::SyntheticHumanMisrepresentation,
                    &keypair,
                ),
                keypair.secret_key(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(resolve_hold(&mut hold, ts(3000), "challenge sustained").is_ok());
        assert_eq!(hold.status, ContestStatus::Resolved);
    }

    #[test]
    fn resolve_hold_from_under_review() {
        let mut hold = admit_challenge(signed_admission()).unwrap();
        begin_review(&mut hold, ts(2000)).unwrap();
        assert!(resolve_hold(&mut hold, ts(3000), "action reversed").is_ok());
        assert_eq!(hold.status, ContestStatus::Resolved);
    }

    #[test]
    fn dismiss_hold_unblocks_action() {
        let keypair = keypair(7);
        let mut hold = admit_challenge(
            sign_challenge_admission(
                admission_with(
                    uuid(8),
                    SybilChallengeGround::CoordinatedManipulation,
                    &keypair,
                ),
                keypair.secret_key(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(dismiss_hold(&mut hold, ts(2000), "insufficient evidence").is_ok());
        assert_eq!(hold.status, ContestStatus::Dismissed);
    }

    #[test]
    fn dismiss_after_resolved_fails() {
        let keypair = keypair(7);
        let mut hold = admit_challenge(
            sign_challenge_admission(
                admission_with(uuid(9), SybilChallengeGround::QuorumContamination, &keypair),
                keypair.secret_key(),
            )
            .unwrap(),
        )
        .unwrap();
        resolve_hold(&mut hold, ts(2000), "done").unwrap();
        assert!(dismiss_hold(&mut hold, ts(3000), "late").is_err());
    }

    #[test]
    fn all_four_grounds_admissible() {
        let keypair = keypair(7);
        let mut hold_id_marker = 10u8;
        for ground in [
            SybilChallengeGround::ConcealedCommonControl,
            SybilChallengeGround::CoordinatedManipulation,
            SybilChallengeGround::QuorumContamination,
            SybilChallengeGround::SyntheticHumanMisrepresentation,
        ] {
            let hold = admit_challenge(
                sign_challenge_admission(
                    admission_with(uuid(hold_id_marker), ground.clone(), &keypair),
                    keypair.secret_key(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(hold.status, ContestStatus::PauseEligible);
            hold_id_marker = hold_id_marker.saturating_add(1);
        }
    }

    #[test]
    fn audit_log_grows_with_transitions() {
        let mut hold = admit_challenge(signed_admission()).unwrap();
        assert_eq!(hold.audit_log.len(), 1);
        begin_review(&mut hold, ts(2000)).unwrap();
        assert_eq!(hold.audit_log.len(), 2);
        resolve_hold(&mut hold, ts(3000), "confirmed").unwrap();
        assert_eq!(hold.audit_log.len(), 3);
    }

    #[test]
    fn ground_display() {
        assert_eq!(
            SybilChallengeGround::ConcealedCommonControl.to_string(),
            "ConcealedCommonControl"
        );
        assert_eq!(
            SybilChallengeGround::SyntheticHumanMisrepresentation.to_string(),
            "SyntheticHumanMisrepresentation"
        );
    }
}
