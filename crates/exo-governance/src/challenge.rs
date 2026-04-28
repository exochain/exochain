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
pub fn file_challenge(
    id: Uuid,
    created: Timestamp,
    challenger: &Did,
    target: &[u8; 32],
    ground: ChallengeGround,
    evidence: &[u8],
) -> Result<Challenge, GovernanceError> {
    if id.is_nil() {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "challenge.id".into(),
            reason: "must be caller-supplied and non-nil".into(),
        });
    }
    if created == Timestamp::ZERO {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "challenge.created".into(),
            reason: "must be caller-supplied and non-zero".into(),
        });
    }

    Ok(Challenge {
        id,
        challenger_did: challenger.clone(),
        target_action_id: *target,
        ground,
        evidence: evidence.to_vec(),
        status: ChallengeStatus::Filed,
        created,
    })
}

/// Issue a pause order that halts the challenged action pending adjudication.
pub fn pause_action(
    challenge: &Challenge,
    issued: Timestamp,
) -> Result<PauseOrder, GovernanceError> {
    if issued == Timestamp::ZERO {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "pause_order.issued".into(),
            reason: "must be caller-supplied and non-zero".into(),
        });
    }

    Ok(PauseOrder {
        challenge_id: challenge.id,
        target_action_id: challenge.target_action_id,
        reason: format!("challenged on ground: {:?}", challenge.ground),
        issued,
    })
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

    fn challenge_id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn challenge_constructor_source() -> &'static str {
        let source = include_str!("challenge.rs");
        let start = source
            .find("pub fn file_challenge(")
            .expect("file_challenge source must exist");
        let end = source[start..]
            .find("#[cfg(test)]")
            .expect("tests marker must exist");
        &source[start..start + end]
    }

    #[test]
    fn challenge_constructors_have_no_internal_entropy_or_wall_clock() {
        let source = challenge_constructor_source();
        assert!(
            !source.contains("Uuid::new_v4"),
            "governance challenges must not fabricate UUIDs internally"
        );
        let forbidden_timestamp = ["Timestamp::", "now_utc"].concat();
        assert!(
            !source.contains(&forbidden_timestamp),
            "governance challenges and pause orders must not read wall-clock time internally"
        );
    }

    fn make_challenge(ground: ChallengeGround, evidence: &[u8]) -> Challenge {
        make_challenge_with_id(0xC001, ground, evidence)
    }

    fn make_challenge_with_id(id: u128, ground: ChallengeGround, evidence: &[u8]) -> Challenge {
        file_challenge(
            challenge_id(id),
            ts(10_000),
            &challenger(),
            &target(),
            ground,
            evidence,
        )
        .expect("deterministic challenge")
    }

    #[test]
    fn file_creates_filed() {
        let id = challenge_id(0xC010);
        let created = ts(10_010);
        let c = file_challenge(
            id,
            created,
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"ev",
        )
        .expect("deterministic challenge");
        assert_eq!(c.id, id);
        assert_eq!(c.created, created);
        assert_eq!(c.status, ChallengeStatus::Filed);
        assert_eq!(c.ground, ChallengeGround::QuorumViolation);
    }
    #[test]
    fn pause_order() {
        let c = make_challenge(ChallengeGround::SybilAllegation, b"");
        let issued = ts(10_011);
        let o = pause_action(&c, issued).expect("deterministic pause order");
        assert_eq!(o.challenge_id, c.id);
        assert_eq!(o.issued, issued);
        assert!(o.reason.contains("SybilAllegation"));
    }
    #[test]
    fn file_rejects_nil_id() {
        let err = file_challenge(
            Uuid::nil(),
            ts(10_012),
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"ev",
        )
        .expect_err("nil challenge id must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }
    #[test]
    fn file_rejects_zero_created_timestamp() {
        let err = file_challenge(
            challenge_id(0xC012),
            Timestamp::ZERO,
            &challenger(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"ev",
        )
        .expect_err("zero challenge created timestamp must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }
    #[test]
    fn pause_rejects_zero_issued_timestamp() {
        let c = make_challenge(ChallengeGround::SybilAllegation, b"");
        let err = pause_action(&c, Timestamp::ZERO)
            .expect_err("zero pause-order issued timestamp must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }
    #[test]
    fn adjudicate_sustain() {
        let mut c = make_challenge(ChallengeGround::ProceduralError, b"");
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_ok());
        assert_eq!(c.status, ChallengeStatus::Sustained);
    }
    #[test]
    fn adjudicate_overrule() {
        let mut c = make_challenge(ChallengeGround::ConsentViolation, b"");
        assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_ok());
        assert_eq!(c.status, ChallengeStatus::Overruled);
    }
    #[test]
    fn adjudicate_from_under_review() {
        let mut c = make_challenge(ChallengeGround::UndisclosedConflict, b"");
        c.status = ChallengeStatus::UnderReview;
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_ok());
    }
    #[test]
    fn adjudicate_from_sustained_fails() {
        let mut c = make_challenge(ChallengeGround::AuthorityChainInvalid, b"");
        c.status = ChallengeStatus::Sustained;
        assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_err());
    }
    #[test]
    fn adjudicate_from_overruled_fails() {
        let mut c = make_challenge(ChallengeGround::AuthorityChainInvalid, b"");
        c.status = ChallengeStatus::Overruled;
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_err());
    }
    #[test]
    fn adjudicate_from_withdrawn_fails() {
        let mut c = make_challenge(ChallengeGround::AuthorityChainInvalid, b"");
        c.status = ChallengeStatus::Withdrawn;
        assert!(adjudicate(&mut c, ChallengeVerdict::Sustain).is_err());
    }
    #[test]
    fn withdraw_from_filed() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation, b"");
        assert!(withdraw(&mut c).is_ok());
        assert_eq!(c.status, ChallengeStatus::Withdrawn);
    }
    #[test]
    fn withdraw_from_under_review() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation, b"");
        c.status = ChallengeStatus::UnderReview;
        assert!(withdraw(&mut c).is_ok());
    }
    #[test]
    fn withdraw_from_sustained_fails() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation, b"");
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
            assert_eq!(make_challenge(g, b"").status, ChallengeStatus::Filed);
        }
    }

    // ── SPR2-04: challenge lifecycle completeness ─────────────────────────────

    /// The path Filed → UnderReview → Overruled was untested; verify it and
    /// confirm the challenge is terminal (no further transitions allowed).
    #[test]
    fn under_review_to_overruled() {
        let mut c = make_challenge(ChallengeGround::QuorumViolation, b"");
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
        let mut c = make_challenge(ChallengeGround::SybilAllegation, b"strong evidence");
        // Stage 1: Filed
        assert_eq!(c.status, ChallengeStatus::Filed);
        let _ = pause_action(&c, ts(10_013)).expect("deterministic pause order");

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
            let mut c = make_challenge(g, b"evidence");
            assert_eq!(c.status, ChallengeStatus::Filed);

            c.status = ChallengeStatus::UnderReview;
            assert_eq!(c.status, ChallengeStatus::UnderReview);

            assert!(adjudicate(&mut c, ChallengeVerdict::Overrule).is_ok());
            assert_eq!(c.status, ChallengeStatus::Overruled);
        }
    }
}
