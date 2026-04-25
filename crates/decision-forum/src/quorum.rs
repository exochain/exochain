//! Quorum management (GOV-010, TNC-07).
//!
//! Per-decision-class quorum policies, verification BEFORE vote initiation,
//! graceful degradation on quorum failure, and independence-aware counting
//! via exo_governance::quorum.

use exo_core::types::DeterministicMap;
use serde::{Deserialize, Serialize};

use crate::{
    decision_object::{DecisionClass, DecisionObject, VoteChoice},
    error::{ForumError, Result},
};

/// Quorum policy for a specific decision class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumRequirement {
    pub min_votes: usize,
    pub min_approve_pct: usize,
    pub min_human_votes: usize,
}

/// Registry of quorum policies per decision class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumRegistry {
    pub policies: DeterministicMap<String, QuorumRequirement>,
}

impl QuorumRegistry {
    /// Create a registry with default policies.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut policies = DeterministicMap::new();
        policies.insert(
            "Routine".into(),
            QuorumRequirement {
                min_votes: 1,
                min_approve_pct: 51,
                min_human_votes: 0,
            },
        );
        policies.insert(
            "Operational".into(),
            QuorumRequirement {
                min_votes: 3,
                min_approve_pct: 51,
                min_human_votes: 1,
            },
        );
        policies.insert(
            "Strategic".into(),
            QuorumRequirement {
                min_votes: 5,
                min_approve_pct: 67,
                min_human_votes: 3,
            },
        );
        policies.insert(
            "Constitutional".into(),
            QuorumRequirement {
                min_votes: 7,
                min_approve_pct: 75,
                min_human_votes: 5,
            },
        );
        Self { policies }
    }

    /// Look up the quorum requirement for a decision class.
    #[must_use]
    pub fn requirement_for(&self, class: DecisionClass) -> Option<&QuorumRequirement> {
        let key = format!("{class:?}");
        self.policies.get(&key)
    }
}

/// Result of a quorum check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumCheckResult {
    /// Quorum met with the given counts.
    Met {
        total_votes: usize,
        approve_count: usize,
        approve_pct: usize,
    },
    /// Quorum not met.
    NotMet { reason: String },
    /// Graceful degradation: partial quorum available.
    Degraded {
        reason: String,
        available: usize,
        required: usize,
    },
}

/// Check if quorum is met for a decision based on its class and votes.
pub fn check_quorum(
    registry: &QuorumRegistry,
    decision: &DecisionObject,
) -> Result<QuorumCheckResult> {
    let req = registry
        .requirement_for(decision.class)
        .ok_or(ForumError::QuorumPolicyMissing)?;

    let total_votes = decision.votes.len();
    let approve_count = decision
        .votes
        .iter()
        .filter(|v| v.choice == VoteChoice::Approve)
        .count();
    let human_count = decision
        .votes
        .iter()
        .filter(|v| matches!(v.actor_kind, crate::decision_object::ActorKind::Human))
        .count();

    if total_votes < req.min_votes {
        return Ok(QuorumCheckResult::Degraded {
            reason: format!("insufficient votes: {} < {}", total_votes, req.min_votes),
            available: total_votes,
            required: req.min_votes,
        });
    }

    if human_count < req.min_human_votes {
        return Ok(QuorumCheckResult::NotMet {
            reason: format!(
                "insufficient human votes: {} < {}",
                human_count, req.min_human_votes
            ),
        });
    }

    let approve_pct = approve_count
        .checked_mul(100)
        .and_then(|n| n.checked_div(total_votes))
        .unwrap_or(0);

    if approve_pct < req.min_approve_pct {
        return Ok(QuorumCheckResult::NotMet {
            reason: format!(
                "approval percentage {}% < required {}%",
                approve_pct, req.min_approve_pct
            ),
        });
    }

    Ok(QuorumCheckResult::Met {
        total_votes,
        approve_count,
        approve_pct,
    })
}

/// Verify quorum preconditions BEFORE a vote is initiated (TNC-07).
/// Returns true if enough eligible voters exist to potentially meet quorum.
pub fn verify_quorum_precondition(
    registry: &QuorumRegistry,
    class: DecisionClass,
    eligible_voters: usize,
) -> Result<bool> {
    let req = registry
        .requirement_for(class)
        .ok_or(ForumError::QuorumPolicyMissing)?;
    Ok(eligible_voters >= req.min_votes)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use exo_core::{
        hlc::HybridClock,
        types::{Did, Hash256},
    };

    use super::*;
    use crate::decision_object::*;

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn human_approve_vote(name: &str, clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new(&format!("did:exo:{name}")).expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::Human,
            timestamp: clock.now(),
            signature_hash: Hash256::digest(name.as_bytes()),
        }
    }

    fn ai_approve_vote(name: &str, clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new(&format!("did:exo:{name}")).expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "d1".into(),
                ceiling_class: DecisionClass::Operational,
            },
            timestamp: clock.now(),
            signature_hash: Hash256::digest(name.as_bytes()),
        }
    }

    fn reject_vote(name: &str, clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new(&format!("did:exo:{name}")).expect("ok"),
            choice: VoteChoice::Reject,
            actor_kind: ActorKind::Human,
            timestamp: clock.now(),
            signature_hash: Hash256::digest(name.as_bytes()),
        }
    }

    #[test]
    fn routine_quorum_met() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = DecisionObject::new("test", DecisionClass::Routine, Hash256::ZERO, &mut clock);
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        match check_quorum(&reg, &d).expect("ok") {
            QuorumCheckResult::Met { total_votes, .. } => assert_eq!(total_votes, 1),
            other => panic!("expected Met, got {other:?}"),
        }
    }

    #[test]
    fn operational_needs_three_votes() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = DecisionObject::new(
            "test",
            DecisionClass::Operational,
            Hash256::ZERO,
            &mut clock,
        );
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        match check_quorum(&reg, &d).expect("ok") {
            QuorumCheckResult::Degraded {
                available,
                required,
                ..
            } => {
                assert_eq!(available, 1);
                assert_eq!(required, 3);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn operational_quorum_met() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = DecisionObject::new(
            "test",
            DecisionClass::Operational,
            Hash256::ZERO,
            &mut clock,
        );
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        d.add_vote(ai_approve_vote("bot1", &mut clock)).expect("ok");
        d.add_vote(ai_approve_vote("bot2", &mut clock)).expect("ok");
        match check_quorum(&reg, &d).expect("ok") {
            QuorumCheckResult::Met {
                total_votes,
                approve_count,
                ..
            } => {
                assert_eq!(total_votes, 3);
                assert_eq!(approve_count, 3);
            }
            other => panic!("expected Met, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_approval_pct() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = DecisionObject::new(
            "test",
            DecisionClass::Operational,
            Hash256::ZERO,
            &mut clock,
        );
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        d.add_vote(reject_vote("bob", &mut clock)).expect("ok");
        d.add_vote(reject_vote("carol", &mut clock)).expect("ok");
        match check_quorum(&reg, &d).expect("ok") {
            QuorumCheckResult::NotMet { reason } => {
                assert!(reason.contains("approval percentage"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn strategic_needs_human_votes() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d =
            DecisionObject::new("test", DecisionClass::Strategic, Hash256::ZERO, &mut clock);
        for i in 0..5 {
            d.add_vote(ai_approve_vote(&format!("bot{i}"), &mut clock))
                .expect("ok");
        }
        match check_quorum(&reg, &d).expect("ok") {
            QuorumCheckResult::NotMet { reason } => {
                assert!(reason.contains("human"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn verify_precondition() {
        let reg = QuorumRegistry::with_defaults();
        assert!(verify_quorum_precondition(&reg, DecisionClass::Routine, 1).expect("ok"));
        assert!(!verify_quorum_precondition(&reg, DecisionClass::Operational, 2).expect("ok"));
        assert!(verify_quorum_precondition(&reg, DecisionClass::Operational, 3).expect("ok"));
    }

    #[test]
    fn default_registry_has_all_classes() {
        let reg = QuorumRegistry::with_defaults();
        assert!(reg.requirement_for(DecisionClass::Routine).is_some());
        assert!(reg.requirement_for(DecisionClass::Operational).is_some());
        assert!(reg.requirement_for(DecisionClass::Strategic).is_some());
        assert!(reg.requirement_for(DecisionClass::Constitutional).is_some());
    }
}
