//! Structured contestation and reversal (GOV-008).
//!
//! Links challenge objects to decision objects. CONTESTED status pauses
//! execution. Resolution creates new decision objects. Reversal creates
//! REVERSAL linkage. Uses exo_governance::challenge underneath.

use exo_core::types::{Did, Hash256, Timestamp};
use exo_governance::challenge::{ChallengeGround, ChallengeStatus, ChallengeVerdict};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ForumError, Result};

/// A challenge filed against a decision object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeObject {
    pub id: Uuid,
    pub decision_id: Uuid,
    pub challenger_did: Did,
    pub ground: ChallengeGround,
    pub evidence_hash: Hash256,
    pub status: ChallengeStatus,
    pub created_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
    pub resolution_decision_id: Option<Uuid>,
}

/// A reversal linkage between the original and the resolution decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReversalLink {
    pub original_decision_id: Uuid,
    pub reversal_decision_id: Uuid,
    pub challenge_id: Uuid,
    pub reversed_at: Timestamp,
}

/// Caller-supplied metadata for filing a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInput {
    pub id: Uuid,
    pub decision_id: Uuid,
    pub challenger: Did,
    pub ground: ChallengeGround,
    pub evidence_hash: Hash256,
    pub created_at: Timestamp,
}

/// File a challenge against a decision.
pub fn file_challenge(input: ChallengeInput) -> Result<ChallengeObject> {
    validate_uuid(input.id, "challenge id")?;
    validate_uuid(input.decision_id, "decision id")?;
    validate_timestamp(input.created_at, "challenge created_at")?;
    validate_hash(input.evidence_hash, "challenge evidence hash")?;

    Ok(ChallengeObject {
        id: input.id,
        decision_id: input.decision_id,
        challenger_did: input.challenger,
        ground: input.ground,
        evidence_hash: input.evidence_hash,
        status: ChallengeStatus::Filed,
        created_at: input.created_at,
        resolved_at: None,
        resolution_decision_id: None,
    })
}

/// Adjudicate a challenge with a verdict.
pub fn adjudicate(
    challenge: &mut ChallengeObject,
    verdict: ChallengeVerdict,
    timestamp: Timestamp,
) -> Result<()> {
    match challenge.status {
        ChallengeStatus::Filed | ChallengeStatus::UnderReview => {
            challenge.status = match verdict {
                ChallengeVerdict::Sustain => ChallengeStatus::Sustained,
                ChallengeVerdict::Overrule => ChallengeStatus::Overruled,
            };
            challenge.resolved_at = Some(timestamp);
            Ok(())
        }
        _ => Err(ForumError::ChallengeError {
            reason: format!("cannot adjudicate from status {:?}", challenge.status),
        }),
    }
}

/// Mark a challenge as under review.
pub fn begin_review(challenge: &mut ChallengeObject) -> Result<()> {
    if challenge.status != ChallengeStatus::Filed {
        return Err(ForumError::ChallengeError {
            reason: "can only begin review from Filed status".into(),
        });
    }
    challenge.status = ChallengeStatus::UnderReview;
    Ok(())
}

/// Withdraw a challenge.
pub fn withdraw(challenge: &mut ChallengeObject) -> Result<()> {
    match challenge.status {
        ChallengeStatus::Filed | ChallengeStatus::UnderReview => {
            challenge.status = ChallengeStatus::Withdrawn;
            Ok(())
        }
        _ => Err(ForumError::ChallengeError {
            reason: format!("cannot withdraw from {:?}", challenge.status),
        }),
    }
}

/// Create a reversal link after a challenge is sustained.
pub fn create_reversal(
    challenge: &ChallengeObject,
    reversal_decision_id: Uuid,
    timestamp: Timestamp,
) -> Result<ReversalLink> {
    if challenge.status != ChallengeStatus::Sustained {
        return Err(ForumError::ChallengeError {
            reason: "reversal requires sustained challenge".into(),
        });
    }
    Ok(ReversalLink {
        original_decision_id: challenge.decision_id,
        reversal_decision_id,
        challenge_id: challenge.id,
        reversed_at: timestamp,
    })
}

/// Check if a decision is currently contested (has an active, unresolved challenge).
#[must_use]
pub fn is_contested(challenges: &[ChallengeObject], decision_id: Uuid) -> bool {
    challenges.iter().any(|c| {
        c.decision_id == decision_id
            && matches!(
                c.status,
                ChallengeStatus::Filed | ChallengeStatus::UnderReview
            )
    })
}

fn validate_uuid(id: Uuid, label: &str) -> Result<()> {
    if id.is_nil() {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must not be nil"),
        });
    }
    Ok(())
}

fn validate_timestamp(timestamp: Timestamp, label: &str) -> Result<()> {
    if timestamp == Timestamp::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must be non-zero HLC"),
        });
    }
    Ok(())
}

fn validate_hash(hash: Hash256, label: &str) -> Result<()> {
    if hash == Hash256::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must be non-zero"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:exo:challenger").expect("ok")
    }
    fn ts() -> Timestamp {
        Timestamp::new(1000, 0)
    }
    fn decision_id() -> Uuid {
        Uuid::new_v4()
    }

    fn challenge_input(id: Uuid) -> ChallengeInput {
        ChallengeInput {
            id,
            decision_id: Uuid::from_u128(7),
            challenger: did(),
            ground: ChallengeGround::QuorumViolation,
            evidence_hash: Hash256::digest(b"evidence"),
            created_at: ts(),
        }
    }

    fn make_challenge(ground: ChallengeGround) -> ChallengeObject {
        file_challenge(ChallengeInput {
            ground,
            ..challenge_input(Uuid::from_u128(8))
        })
        .expect("valid challenge")
    }

    #[test]
    fn file_challenge_requires_caller_supplied_identity_and_hlc() {
        let challenge = file_challenge(challenge_input(Uuid::from_u128(9))).expect("valid");
        assert_eq!(challenge.id, Uuid::from_u128(9));
        assert_eq!(challenge.created_at, ts());

        let nil = file_challenge(challenge_input(Uuid::nil())).unwrap_err();
        assert!(matches!(nil, ForumError::InvalidProvenance { .. }));

        let zero_time = file_challenge(ChallengeInput {
            created_at: Timestamp::ZERO,
            ..challenge_input(Uuid::from_u128(10))
        })
        .unwrap_err();
        assert!(matches!(zero_time, ForumError::InvalidProvenance { .. }));

        let zero_evidence = file_challenge(ChallengeInput {
            evidence_hash: Hash256::ZERO,
            ..challenge_input(Uuid::from_u128(11))
        })
        .unwrap_err();
        assert!(matches!(
            zero_evidence,
            ForumError::InvalidProvenance { .. }
        ));
    }

    #[test]
    fn file_challenge_creates_filed() {
        let c = make_challenge(ChallengeGround::QuorumViolation);
        assert_eq!(c.status, ChallengeStatus::Filed);
        assert!(c.resolved_at.is_none());
    }

    #[test]
    fn adjudicate_sustain() {
        let mut c = make_challenge(ChallengeGround::ProceduralError);
        adjudicate(&mut c, ChallengeVerdict::Sustain, Timestamp::new(2000, 0)).expect("ok");
        assert_eq!(c.status, ChallengeStatus::Sustained);
        assert!(c.resolved_at.is_some());
    }

    #[test]
    fn adjudicate_overrule() {
        let mut c = make_challenge(ChallengeGround::ConsentViolation);
        adjudicate(&mut c, ChallengeVerdict::Overrule, Timestamp::new(2000, 0)).expect("ok");
        assert_eq!(c.status, ChallengeStatus::Overruled);
    }

    #[test]
    fn adjudicate_from_under_review() {
        let mut c = make_challenge(ChallengeGround::SybilAllegation);
        begin_review(&mut c).expect("ok");
        adjudicate(&mut c, ChallengeVerdict::Sustain, Timestamp::new(2000, 0)).expect("ok");
    }

    #[test]
    fn adjudicate_from_terminal_fails() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation);
        adjudicate(&mut c, ChallengeVerdict::Overrule, Timestamp::new(2000, 0)).expect("ok");
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain, Timestamp::new(3000, 0)).is_err());
    }

    #[test]
    fn withdraw_from_filed() {
        let mut c = make_challenge(ChallengeGround::UndisclosedConflict);
        withdraw(&mut c).expect("ok");
        assert_eq!(c.status, ChallengeStatus::Withdrawn);
    }

    #[test]
    fn withdraw_from_sustained_fails() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation);
        adjudicate(&mut c, ChallengeVerdict::Sustain, Timestamp::new(2000, 0)).expect("ok");
        assert!(withdraw(&mut c).is_err());
    }

    #[test]
    fn create_reversal_ok() {
        let mut c = make_challenge(ChallengeGround::AuthorityChainInvalid);
        adjudicate(&mut c, ChallengeVerdict::Sustain, Timestamp::new(2000, 0)).expect("ok");
        let reversal = create_reversal(&c, Uuid::new_v4(), Timestamp::new(3000, 0)).expect("ok");
        assert_eq!(reversal.challenge_id, c.id);
        assert_eq!(reversal.original_decision_id, c.decision_id);
    }

    #[test]
    fn create_reversal_requires_sustained() {
        let c = make_challenge(ChallengeGround::QuorumViolation);
        assert!(create_reversal(&c, Uuid::new_v4(), ts()).is_err());
    }

    #[test]
    fn is_contested_check() {
        let did = decision_id();
        let c = file_challenge(ChallengeInput {
            decision_id: did,
            ground: ChallengeGround::ProceduralError,
            ..challenge_input(Uuid::from_u128(12))
        })
        .expect("valid challenge");
        assert!(is_contested(std::slice::from_ref(&c), did));
        let mut c2 = c;
        adjudicate(&mut c2, ChallengeVerdict::Overrule, Timestamp::new(2000, 0)).expect("ok");
        assert!(!is_contested(&[c2], did));
    }

    #[test]
    fn begin_review_transitions() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation);
        begin_review(&mut c).expect("ok");
        assert_eq!(c.status, ChallengeStatus::UnderReview);
        // Can't begin review again
        assert!(begin_review(&mut c).is_err());
    }
}
