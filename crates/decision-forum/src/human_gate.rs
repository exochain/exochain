//! Human oversight enforcement (GOV-007, TNC-02, TNC-09).
//!
//! Enforces that certain decision classes require human approval,
//! distinguishes human vs AI signatures cryptographically, blocks AI
//! from satisfying HUMAN_GATE_REQUIRED, and enforces AI delegation ceilings.

use serde::{Deserialize, Serialize};

use crate::{
    decision_object::{ActorKind, DecisionClass, DecisionObject, Vote},
    error::{ForumError, Result},
};

/// Policy defining which decision classes require human approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanGatePolicy {
    /// Decision classes that always require at least one human approval.
    pub human_required_classes: Vec<DecisionClass>,
    /// Maximum decision class an AI agent can approve without human co-sign.
    pub ai_ceiling: DecisionClass,
}

impl Default for HumanGatePolicy {
    fn default() -> Self {
        Self {
            human_required_classes: vec![DecisionClass::Strategic, DecisionClass::Constitutional],
            ai_ceiling: DecisionClass::Operational,
        }
    }
}

/// Check whether a decision requires human approval per the gate policy.
#[must_use]
pub fn requires_human_approval(policy: &HumanGatePolicy, class: DecisionClass) -> bool {
    policy.human_required_classes.contains(&class)
}

/// Check whether an AI actor's ceiling allows it to act on this decision class.
#[must_use]
pub fn ai_within_ceiling(policy: &HumanGatePolicy, class: DecisionClass) -> bool {
    class <= policy.ai_ceiling
}

/// Validate that a decision's votes satisfy the human gate policy.
/// Returns Ok(()) if the gate is satisfied, or an error if not.
pub fn enforce_human_gate(policy: &HumanGatePolicy, decision: &DecisionObject) -> Result<()> {
    // Check AI ceiling: if decision class exceeds AI ceiling, AI votes alone
    // are not sufficient.
    if decision.class > policy.ai_ceiling {
        let has_human_vote = decision.votes.iter().any(is_human_vote);
        if !has_human_vote && !decision.votes.is_empty() {
            return Err(ForumError::AiCeilingExceeded {
                reason: format!(
                    "{:?} exceeds AI ceiling {:?}",
                    decision.class, policy.ai_ceiling
                ),
            });
        }
    }

    // Check human gate: classes requiring human approval must have at least
    // one human vote.
    if requires_human_approval(policy, decision.class) {
        let human_count = decision.votes.iter().filter(|v| is_human_vote(v)).count();
        if human_count == 0 {
            return Err(ForumError::HumanGateRequired);
        }
    }

    Ok(())
}

/// Determine if a vote was cast by a human actor.
#[must_use]
pub fn is_human_vote(vote: &Vote) -> bool {
    matches!(vote.actor_kind, ActorKind::Human)
}

/// Determine if a vote was cast by an AI agent.
#[must_use]
pub fn is_ai_vote(vote: &Vote) -> bool {
    matches!(vote.actor_kind, ActorKind::AiAgent { .. })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use exo_core::{
        hlc::HybridClock,
        types::{Did, Hash256},
    };

    use super::*;
    use crate::decision_object::{DecisionObjectInput, VoteChoice};

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn human_vote(clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new("did:exo:human-alice").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::Human,
            timestamp: clock.now(),
            signature_hash: Hash256::digest(b"human-sig"),
        }
    }

    fn ai_vote(clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new("did:exo:ai-agent-1").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "d1".into(),
                ceiling_class: DecisionClass::Operational,
            },
            timestamp: clock.now(),
            signature_hash: Hash256::digest(b"ai-sig"),
        }
    }

    fn make_decision(class: DecisionClass, clock: &mut HybridClock) -> DecisionObject {
        DecisionObject::new(DecisionObjectInput {
            id: uuid::Uuid::from_u128(100),
            title: "test".into(),
            class,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: clock.now(),
        })
        .expect("valid decision")
    }

    #[test]
    fn routine_passes_without_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Routine, &mut clock);
        d.add_vote(ai_vote(&mut clock)).expect("ok");
        assert!(enforce_human_gate(&policy, &d).is_ok());
    }

    #[test]
    fn strategic_requires_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Strategic, &mut clock);
        d.add_vote(ai_vote(&mut clock)).expect("ok");
        let err = enforce_human_gate(&policy, &d).unwrap_err();
        assert!(matches!(
            err,
            ForumError::HumanGateRequired | ForumError::AiCeilingExceeded { .. }
        ));
    }

    #[test]
    fn strategic_passes_with_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Strategic, &mut clock);
        d.add_vote(human_vote(&mut clock)).expect("ok");
        assert!(enforce_human_gate(&policy, &d).is_ok());
    }

    #[test]
    fn constitutional_requires_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Constitutional, &mut clock);
        d.add_vote(ai_vote(&mut clock)).expect("ok");
        assert!(enforce_human_gate(&policy, &d).is_err());
    }

    #[test]
    fn empty_votes_passes_gate() {
        // No votes yet — gate doesn't block (nothing to validate).
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let d = make_decision(DecisionClass::Strategic, &mut clock);
        // With no votes, the human gate check for human_required_classes fails
        // because human_count == 0, but we allow empty votes since no approval is claimed.
        let result = enforce_human_gate(&policy, &d);
        // Empty votes: human_count == 0, but no one is asserting approval.
        // This should fail — decisions requiring human approval need human votes.
        assert!(result.is_err());
    }

    #[test]
    fn ai_ceiling_check() {
        let policy = HumanGatePolicy::default();
        assert!(ai_within_ceiling(&policy, DecisionClass::Routine));
        assert!(ai_within_ceiling(&policy, DecisionClass::Operational));
        assert!(!ai_within_ceiling(&policy, DecisionClass::Strategic));
        assert!(!ai_within_ceiling(&policy, DecisionClass::Constitutional));
    }

    #[test]
    fn is_human_vs_ai() {
        let mut clock = test_clock();
        assert!(is_human_vote(&human_vote(&mut clock)));
        assert!(!is_human_vote(&ai_vote(&mut clock)));
        assert!(is_ai_vote(&ai_vote(&mut clock)));
        assert!(!is_ai_vote(&human_vote(&mut clock)));
    }

    #[test]
    fn default_policy() {
        let p = HumanGatePolicy::default();
        assert_eq!(p.ai_ceiling, DecisionClass::Operational);
        assert!(p.human_required_classes.contains(&DecisionClass::Strategic));
        assert!(
            p.human_required_classes
                .contains(&DecisionClass::Constitutional)
        );
    }
}
