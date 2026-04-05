//! Quorum computation with independence-aware counting.
//!
//! Constitutional principle: "Numerical multiplicity without attributable
//! independence is theater, not legitimacy."

use exo_core::{Did, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    challenge::{Challenge, ChallengeStatus},
    errors::GovernanceError,
};

/// Roles that can participate in governance actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Steward,
    Governor,
    Reviewer,
    Contributor,
    Observer,
}

/// A signed declaration of independence — no common control, no coordination,
/// identity verified through independent channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceAttestation {
    pub attester_did: Did,
    pub no_common_control: bool,
    pub no_coordination: bool,
    pub identity_verified: bool,
    pub signature: Signature,
}

impl IndependenceAttestation {
    /// An attestation is valid only if all three declarations are true.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.no_common_control && self.no_coordination && self.identity_verified
    }
}

/// A single approval cast toward a quorum decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver_did: Did,
    pub role: Role,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub independence_attestation: Option<IndependenceAttestation>,
}

/// Policy defining what constitutes a valid quorum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumPolicy {
    pub min_approvals: usize,
    pub min_independent: usize,
    pub required_roles: Vec<Role>,
    pub timeout: Timestamp,
}

/// The result of a quorum computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumResult {
    Met {
        independent_count: usize,
        total_count: usize,
    },
    NotMet {
        reason: String,
    },
    Contested {
        challenge: String,
    },
}

/// Compute whether a quorum is met given a set of approvals and a policy.
#[must_use]
pub fn compute_quorum(approvals: &[Approval], policy: &QuorumPolicy) -> QuorumResult {
    let total_count = approvals.len();

    if total_count < policy.min_approvals {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient approvals: {total_count} < {}",
                policy.min_approvals
            ),
        };
    }

    for required_role in &policy.required_roles {
        if !approvals.iter().any(|a| &a.role == required_role) {
            return QuorumResult::NotMet {
                reason: format!("missing required role: {required_role:?}"),
            };
        }
    }

    let independent_count = approvals
        .iter()
        .filter(|a| {
            a.independence_attestation
                .as_ref()
                .is_some_and(|att| att.is_valid())
        })
        .count();

    if independent_count < policy.min_independent {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient independence: {independent_count} independent of {} required \
                 (numerical multiplicity without attributable independence is theater, not legitimacy)",
                policy.min_independent
            ),
        };
    }

    QuorumResult::Met {
        independent_count,
        total_count,
    }
}

/// Compute quorum with active-challenge guard.
///
/// If any challenge in `open_challenges` is still `Filed` or `UnderReview`,
/// the result is `Contested` — the unresolved independence challenge blocks
/// quorum achievement per CR-001 §8.4.  Only when all challenges are
/// resolved (Sustained, Overruled, or Withdrawn) does this delegate to the
/// standard `compute_quorum`.
#[must_use]
pub fn compute_quorum_with_challenges(
    approvals: &[Approval],
    policy: &QuorumPolicy,
    open_challenges: &[&Challenge],
) -> QuorumResult {
    if let Some(blocking) = open_challenges.iter().find(|c| {
        matches!(
            c.status,
            ChallengeStatus::Filed | ChallengeStatus::UnderReview
        )
    }) {
        return QuorumResult::Contested {
            challenge: format!(
                "unresolved independence challenge {} on ground {:?}",
                blocking.id, blocking.ground
            ),
        };
    }
    compute_quorum(approvals, policy)
}

/// Validate a single approval's basic structure.
pub fn validate_approval(approval: &Approval) -> Result<(), GovernanceError> {
    if approval.approver_did.as_str().is_empty() {
        return Err(GovernanceError::QuorumNotMet {
            required: 1,
            present: 0,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_core::crypto;

    use super::*;

    fn test_sig() -> Signature {
        let (_pk, sk) = crypto::generate_keypair();
        crypto::sign(b"test", &sk)
    }

    fn valid_attestation(did: &Did) -> IndependenceAttestation {
        IndependenceAttestation {
            attester_did: did.clone(),
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: test_sig(),
        }
    }

    fn invalid_attestation(did: &Did) -> IndependenceAttestation {
        IndependenceAttestation {
            attester_did: did.clone(),
            no_common_control: false,
            no_coordination: true,
            identity_verified: true,
            signature: test_sig(),
        }
    }

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("valid test DID")
    }

    fn make_approval(name: &str, role: Role, independent: bool) -> Approval {
        let d = did(name);
        Approval {
            approver_did: d.clone(),
            role,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: if independent {
                Some(valid_attestation(&d))
            } else {
                None
            },
        }
    }

    fn default_policy() -> QuorumPolicy {
        QuorumPolicy {
            min_approvals: 3,
            min_independent: 2,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        }
    }

    #[test]
    fn quorum_met_with_sufficient_independent_approvals() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        assert_eq!(
            compute_quorum(&approvals, &default_policy()),
            QuorumResult::Met {
                independent_count: 3,
                total_count: 3
            }
        );
    }

    #[test]
    fn quorum_fails_with_sufficient_approvals_but_insufficient_independence() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, false),
            make_approval("carol", Role::Contributor, false),
        ];
        match compute_quorum(&approvals, &default_policy()) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("insufficient independence"));
                assert!(reason.contains("theater, not legitimacy"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn quorum_fails_with_insufficient_total_approvals() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
        ];
        match compute_quorum(&approvals, &default_policy()) {
            QuorumResult::NotMet { reason } => assert!(reason.contains("insufficient approvals")),
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn quorum_fails_with_missing_required_role() {
        let approvals = vec![
            make_approval("alice", Role::Reviewer, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        match compute_quorum(&approvals, &default_policy()) {
            QuorumResult::NotMet { reason } => assert!(reason.contains("missing required role")),
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn quorum_fails_with_no_approvals() {
        assert!(matches!(
            compute_quorum(&[], &default_policy()),
            QuorumResult::NotMet { .. }
        ));
    }

    #[test]
    fn quorum_with_invalid_attestation_counts_as_non_independent() {
        let d = did("dave");
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            Approval {
                approver_did: d.clone(),
                role: Role::Contributor,
                timestamp: Timestamp::new(1000, 0),
                signature: test_sig(),
                independence_attestation: Some(invalid_attestation(&d)),
            },
        ];
        assert_eq!(
            compute_quorum(&approvals, &default_policy()),
            QuorumResult::Met {
                independent_count: 2,
                total_count: 3
            }
        );
    }

    #[test]
    fn independence_attestation_validity() {
        let d = did("test");
        assert!(valid_attestation(&d).is_valid());
        assert!(!invalid_attestation(&d).is_valid());
        let partial = IndependenceAttestation {
            attester_did: d.clone(),
            no_common_control: true,
            no_coordination: true,
            identity_verified: false,
            signature: test_sig(),
        };
        assert!(!partial.is_valid());
    }

    #[test]
    fn validate_approval_accepts_valid() {
        let approval = make_approval("alice", Role::Steward, true);
        assert!(validate_approval(&approval).is_ok());
    }

    #[test]
    fn quorum_policy_with_no_required_roles() {
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let approvals = vec![make_approval("alice", Role::Contributor, true)];
        assert!(matches!(
            compute_quorum(&approvals, &policy),
            QuorumResult::Met { .. }
        ));
    }

    #[test]
    fn contested_variant_exists() {
        let contested = QuorumResult::Contested {
            challenge: "test".to_string(),
        };
        assert!(matches!(contested, QuorumResult::Contested { .. }));
    }

    // ── WO-004: challenge-blocked quorum ──────────────────────────────────────

    use crate::challenge::{
        ChallengeGround, ChallengeStatus, ChallengeVerdict, adjudicate, file_challenge,
    };

    fn target() -> [u8; 32] {
        [1u8; 32]
    }
    fn challenger_did() -> Did {
        did("challenger")
    }

    #[test]
    fn open_challenge_blocks_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"coordinated approvers suspected",
        );
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));
    }

    #[test]
    fn under_review_challenge_blocks_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        ch.status = ChallengeStatus::UnderReview;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));
    }

    #[test]
    fn resolved_challenge_does_not_block_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        ch.status = ChallengeStatus::Overruled;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
        ));
    }

    #[test]
    fn no_challenges_delegates_to_compute_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        assert_eq!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[]),
            compute_quorum(&approvals, &default_policy())
        );
    }

    #[test]
    fn withdrawn_challenge_does_not_block_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        ch.status = ChallengeStatus::Withdrawn;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
        ));
    }

    // ── SPR2-04: quorum hardening edge cases ─────────────────────────────────

    /// Challenge filed mid-vote → Contested; moves to UnderReview → still
    /// Contested; then resolved (Overruled) → quorum proceeds to Met.
    #[test]
    fn challenge_filed_mid_vote_resolved_then_quorum_proceeds() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"coordinated approvers suspected",
        );

        // Phase 1: Filed → Contested
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));

        // Phase 2: UnderReview → still Contested
        ch.status = ChallengeStatus::UnderReview;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));

        // Phase 3: Overruled → quorum re-runs and succeeds
        adjudicate(&mut ch, ChallengeVerdict::Overrule).expect("adjudicate ok");
        assert_eq!(ch.status, ChallengeStatus::Overruled);
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
        ));
    }

    /// A Sustained challenge (upheld) is a terminal state; it is no longer
    /// Filed/UnderReview, so it must not block the quorum gate.
    #[test]
    fn sustained_challenge_does_not_block_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        adjudicate(&mut ch, ChallengeVerdict::Sustain).expect("adjudicate ok");
        assert_eq!(ch.status, ChallengeStatus::Sustained);
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
        ));
    }

    /// Two Filed challenges from different grounds must both produce Contested —
    /// numerical multiplicity of challenges mirrors multiplicity of approvals.
    #[test]
    fn simultaneous_challenges_different_grounds_both_contested() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let ch1 = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"sybil evidence",
        );
        let ch2 = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"quorum evidence",
        );
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch1, &ch2]),
            QuorumResult::Contested { .. }
        ));
    }

    /// One resolved challenge plus one still-Filed challenge must remain Contested.
    #[test]
    fn mixed_resolved_and_open_challenge_stays_contested() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut resolved = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        adjudicate(&mut resolved, ChallengeVerdict::Overrule).expect("adjudicate ok");

        let open = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::ProceduralError,
            b"",
        );

        // resolved first in slice — open challenge must still block
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&resolved, &open]),
            QuorumResult::Contested { .. }
        ));
    }
}
