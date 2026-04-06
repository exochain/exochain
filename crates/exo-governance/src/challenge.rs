//! Challenge mechanism — constitutional brake per CR-001 section 8.5.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::GovernanceError;

/// Legal basis for filing a governance challenge (CR-001 section 8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeGround {
    AuthorityChainInvalid,
    QuorumViolation,
    UndisclosedConflict,
    ProceduralError,
    SybilAllegation,
    ConsentViolation,
}

/// Lifecycle state of a governance challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    Filed,
    UnderReview,
    Sustained,
    Overruled,
    Withdrawn,
}

/// Adjudication outcome for a challenge: sustain or overrule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeVerdict {
    Sustain,
    Overrule,
}

/// A formal governance challenge contesting a prior action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenger_did: Did,
    pub target_action_id: [u8; 32],
    pub ground: ChallengeGround,
    pub evidence: Vec<u8>,
    pub status: ChallengeStatus,
    pub created: Timestamp,
}

/// Order to pause a contested action while a challenge is adjudicated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseOrder {
    pub challenge_id: Uuid,
    pub target_action_id: [u8; 32],
    pub reason: String,
    pub issued: Timestamp,
}

/// File a new governance challenge against a target action with the given ground and evidence.
#[must_use]
pub fn file_challenge(
    challenger: &Did,
    target: &[u8; 32],
    ground: ChallengeGround,
    evidence: &[u8],
) -> Challenge {
    Challenge {
        id: Uuid::new_v4(),
        challenger_did: challenger.clone(),
        target_action_id: *target,
        ground,
        evidence: evidence.to_vec(),
        status: ChallengeStatus::Filed,
        created: Timestamp::now_utc(),
    }
}

/// Issue a pause order that halts the challenged action pending adjudication.
#[must_use]
pub fn pause_action(challenge: &Challenge) -> PauseOrder {
    PauseOrder {
        challenge_id: challenge.id,
        target_action_id: challenge.target_action_id,
        reason: format!("challenged on ground: {:?}", challenge.ground),
        issued: Timestamp::now_utc(),
    }
}

/// Resolve a challenge by applying the given verdict, transitioning it to a terminal state.
pub fn adjudicate(
    challenge: &mut Challenge,
    verdict: ChallengeVerdict,
) -> Result<(), GovernanceError> {
    match challenge.status {
        ChallengeStatus::Filed | ChallengeStatus::UnderReview => {
            challenge.status = match verdict {
                ChallengeVerdict::Sustain => ChallengeStatus::Sustained,
                ChallengeVerdict::Overrule => ChallengeStatus::Overruled,
            };
            Ok(())
        }
        _ => Err(GovernanceError::InvalidTransition {
            from: format!("{:?}", challenge.status),
            to: format!("{verdict:?}"),
        }),
    }
}

/// Withdraw a challenge, allowed only while it is still Filed or UnderReview.
pub fn withdraw(challenge: &mut Challenge) -> Result<(), GovernanceError> {
    match challenge.status {
        ChallengeStatus::Filed | ChallengeStatus::UnderReview => {
            challenge.status = ChallengeStatus::Withdrawn;
            Ok(())
        }
        _ => Err(GovernanceError::InvalidTransition {
            from: format!("{:?}", challenge.status),
            to: "Withdrawn".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> [u8; 32] {
        [42u8; 32]
    }
    fn challenger() -> Did {
        Did::new("did:exo:challenger").expect("ok")
    }

    #[test]
    fn file_creates_filed() {
        let c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"ev",
        );
        assert_eq!(c.status, ChallengeStatus::Filed);
        assert_eq!(c.ground, ChallengeGround::QuorumViolation);
    }
    #[test]
    fn pause_order() {
        let c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        let o = pause_action(&c);
        assert_eq!(o.challenge_id, c.id);
        assert!(o.reason.contains("SybilAllegation"));
    }
    #[test]
    fn adjudicate_sustain() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::ProceduralError,
            b"",
        );
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_ok());
        assert_eq!(c.status, ChallengeStatus::Sustained);
    }
    #[test]
    fn adjudicate_overrule() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::ConsentViolation,
            b"",
        );
        assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_ok());
        assert_eq!(c.status, ChallengeStatus::Overruled);
    }
    #[test]
    fn adjudicate_from_under_review() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::UndisclosedConflict,
            b"",
        );
        c.status = ChallengeStatus::UnderReview;
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_ok());
    }
    #[test]
    fn adjudicate_from_sustained_fails() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::AuthorityChainInvalid,
            b"",
        );
        c.status = ChallengeStatus::Sustained;
        assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_err());
    }
    #[test]
    fn adjudicate_from_overruled_fails() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::AuthorityChainInvalid,
            b"",
        );
        c.status = ChallengeStatus::Overruled;
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_err());
    }
    #[test]
    fn adjudicate_from_withdrawn_fails() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::AuthorityChainInvalid,
            b"",
        );
        c.status = ChallengeStatus::Withdrawn;
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_err());
    }
    #[test]
    fn withdraw_from_filed() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        assert!(withdraw(&mut c).is_ok());
        assert_eq!(c.status, ChallengeStatus::Withdrawn);
    }
    #[test]
    fn withdraw_from_under_review() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        c.status = ChallengeStatus::UnderReview;
        assert!(withdraw(&mut c).is_ok());
    }
    #[test]
    fn withdraw_from_sustained_fails() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        c.status = ChallengeStatus::Sustained;
        assert!(withdraw(&mut c).is_err());
    }
    #[test]
    fn all_grounds() {
        for g in [
            ChallengeGround::AuthorityChainInvalid,
            ChallengeGround::QuorumViolation,
            ChallengeGround::UndisclosedConflict,
            ChallengeGround::ProceduralError,
            ChallengeGround::SybilAllegation,
            ChallengeGround::ConsentViolation,
        ] {
            assert_eq!(
                file_challenge(&challenger(), &target(), g, b"").status,
                ChallengeStatus::Filed
            );
        }
    }

    // ── SPR2-04: challenge lifecycle completeness ─────────────────────────────

    /// The path Filed → UnderReview → Overruled was untested; verify it and
    /// confirm the challenge is terminal (no further transitions allowed).
    #[test]
    fn under_review_to_overruled() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        c.status = ChallengeStatus::UnderReview;
        assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_ok());
        assert_eq!(c.status, ChallengeStatus::Overruled);
        // terminal: cannot re-adjudicate or withdraw
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_err());
        assert!(withdraw(&mut c).is_err());
    }

    /// Full lifecycle walkthrough: File → UnderReview → Sustained, then
    /// verify all further transitions are correctly rejected.
    #[test]
    fn full_lifecycle_filed_under_review_sustained() {
        let mut c = file_challenge(
            &challenger(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"strong evidence",
        );
        // Stage 1: Filed
        assert_eq!(c.status, ChallengeStatus::Filed);
        let _ = pause_action(&c); // pause order issued on filing

        // Stage 2: Under review
        c.status = ChallengeStatus::UnderReview;
        assert_eq!(c.status, ChallengeStatus::UnderReview);

        // Stage 3: Sustained (challenge upheld)
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_ok());
        assert_eq!(c.status, ChallengeStatus::Sustained);

        // Terminal state: further adjudication and withdrawal must fail
        assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_err());
        assert!(withdraw(&mut c).is_err());
    }

    /// All 6 ChallengeGround values must transit through the complete lifecycle
    /// (Filed → UnderReview → Overruled) without error — verifying each ground
    /// is treated uniformly by the state machine.
    #[test]
    fn all_grounds_complete_lifecycle() {
        for g in [
            ChallengeGround::AuthorityChainInvalid,
            ChallengeGround::QuorumViolation,
            ChallengeGround::UndisclosedConflict,
            ChallengeGround::ProceduralError,
            ChallengeGround::SybilAllegation,
            ChallengeGround::ConsentViolation,
        ] {
            let mut c = file_challenge(&challenger(), &target(), g, b"evidence");
            assert_eq!(c.status, ChallengeStatus::Filed);

            c.status = ChallengeStatus::UnderReview;
            assert_eq!(c.status, ChallengeStatus::UnderReview);

            assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_ok());
            assert_eq!(c.status, ChallengeStatus::Overruled);
        }
    }
}
