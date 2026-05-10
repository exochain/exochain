//! Human oversight enforcement (GOV-007, TNC-02, TNC-09).
//!
//! Enforces that certain decision classes require human approval,
//! distinguishes human vs AI signatures cryptographically, blocks AI
//! from satisfying HUMAN_GATE_REQUIRED, and enforces AI delegation ceilings.

use exo_core::{Did, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    constitution::PublicKeyResolver,
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
    enforce_human_gate_with_key_resolver(policy, decision, &no_voter_public_key)
}

/// Validate that a decision's votes satisfy the human gate policy using
/// trusted voter-key resolution.
pub fn enforce_human_gate_with_key_resolver<R: PublicKeyResolver>(
    policy: &HumanGatePolicy,
    decision: &DecisionObject,
    resolve_voter_public_key: &R,
) -> Result<()> {
    // Check AI ceiling: if decision class exceeds AI ceiling, AI votes alone
    // are not sufficient.
    if decision.class > policy.ai_ceiling {
        let has_human_vote = decision.votes.iter().any(|vote| {
            decision.is_verified_human_approval_with_key_resolver(vote, resolve_voter_public_key)
        });
        if !has_human_vote && !decision.votes.is_empty() {
            return Err(ForumError::AiCeilingExceeded {
                reason: format!(
                    "{} exceeds AI ceiling {}",
                    decision.class.quorum_policy_key(),
                    policy.ai_ceiling.quorum_policy_key()
                ),
            });
        }
    }

    // Check human gate: classes requiring human approval must have at least
    // one human vote.
    if requires_human_approval(policy, decision.class) {
        let human_count = decision
            .votes
            .iter()
            .filter(|vote| {
                decision
                    .is_verified_human_approval_with_key_resolver(vote, resolve_voter_public_key)
            })
            .count();
        if human_count == 0 {
            return Err(ForumError::HumanGateRequired);
        }
    }

    Ok(())
}

/// Determine if a vote was cast by a human actor.
#[must_use]
pub fn is_human_vote(vote: &Vote) -> bool {
    matches!(vote.actor_kind, ActorKind::Human) && vote.has_human_provenance_evidence()
}

/// Determine if a vote was cast by an AI agent.
#[must_use]
pub fn is_ai_vote(vote: &Vote) -> bool {
    matches!(vote.actor_kind, ActorKind::AiAgent { .. })
}

fn no_voter_public_key(_: &Did) -> Option<PublicKey> {
    None
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    use exo_core::{
        hlc::HybridClock,
        types::{Hash256, PublicKey},
    };
    use exo_gatekeeper::types::VoiceKind;

    use super::*;
    use crate::decision_object::{
        DecisionObjectInput, VoteChoice, VoteProvenance, vote_signature_message,
    };

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn signed_vote(
        decision: &DecisionObject,
        voter_did: Did,
        actor_kind: ActorKind,
        voice_kind: VoiceKind,
        clock: &mut HybridClock,
    ) -> Vote {
        let (public_key, secret_key) = exo_core::crypto::generate_keypair();
        let mut vote = Vote {
            voter_did,
            choice: VoteChoice::Approve,
            actor_kind,
            timestamp: clock.now().expect("HLC timestamp"),
            signature_hash: Hash256::ZERO,
            provenance: None,
        };
        let message = vote_signature_message(decision, &vote).expect("vote signing payload");
        let signature = exo_core::crypto::sign(&message, &secret_key);
        vote.signature_hash = Hash256::digest(&signature.to_bytes());
        vote.provenance = Some(VoteProvenance {
            public_key,
            signature,
            voice_kind,
        });
        vote
    }

    fn human_vote(decision: &DecisionObject, clock: &mut HybridClock) -> Vote {
        signed_vote(
            decision,
            Did::new("did:exo:human-alice").expect("ok"),
            ActorKind::Human,
            VoiceKind::Human,
            clock,
        )
    }

    fn ai_vote(decision: &DecisionObject, clock: &mut HybridClock) -> Vote {
        signed_vote(
            decision,
            Did::new("did:exo:ai-agent-1").expect("ok"),
            ActorKind::AiAgent {
                delegation_id: "d1".into(),
                ceiling_class: DecisionClass::Operational,
            },
            VoiceKind::Synthetic,
            clock,
        )
    }

    fn resolver_for_decision(decision: &DecisionObject) -> impl Fn(&Did) -> Option<PublicKey> {
        let keys: BTreeMap<Did, PublicKey> = decision
            .votes
            .iter()
            .filter_map(|vote| {
                vote.provenance
                    .as_ref()
                    .map(|provenance| (vote.voter_did.clone(), provenance.public_key))
            })
            .collect();
        move |did| keys.get(did).copied()
    }

    fn add_resolved_vote(decision: &mut DecisionObject, vote: Vote) -> Result<()> {
        let voter_did = vote.voter_did.clone();
        let public_key = vote
            .provenance
            .as_ref()
            .map(|provenance| provenance.public_key);
        decision.add_vote_with_key_resolver(vote, &move |did: &Did| {
            if did == &voter_did { public_key } else { None }
        })
    }

    fn make_decision(class: DecisionClass, clock: &mut HybridClock) -> DecisionObject {
        DecisionObject::new(DecisionObjectInput {
            id: uuid::Uuid::from_u128(100),
            title: "test".into(),
            class,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: clock.now().expect("HLC timestamp"),
        })
        .expect("valid decision")
    }

    #[test]
    fn routine_passes_without_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Routine, &mut clock);
        let vote = ai_vote(&d, &mut clock);
        add_resolved_vote(&mut d, vote).expect("ok");
        assert!(enforce_human_gate(&policy, &d).is_ok());
    }

    #[test]
    fn strategic_requires_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Strategic, &mut clock);
        let vote = ai_vote(&d, &mut clock);
        add_resolved_vote(&mut d, vote).expect("ok");
        let err = enforce_human_gate(&policy, &d).unwrap_err();
        assert_eq!(
            err.to_string(),
            "AI delegation ceiling exceeded: Strategic exceeds AI ceiling Operational"
        );
        assert!(matches!(
            err,
            ForumError::HumanGateRequired | ForumError::AiCeilingExceeded { .. }
        ));
    }

    #[test]
    fn human_gate_errors_do_not_depend_on_debug_formatting() {
        let production = include_str!("human_gate.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(
            !production.contains("{:?} exceeds AI ceiling {:?}"),
            "human-gate ceiling errors must use explicit stable class labels"
        );
    }

    #[test]
    fn strategic_passes_with_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Strategic, &mut clock);
        let vote = human_vote(&d, &mut clock);
        add_resolved_vote(&mut d, vote).expect("ok");
        let resolver = resolver_for_decision(&d);
        assert!(enforce_human_gate_with_key_resolver(&policy, &d, &resolver).is_ok());
    }

    #[test]
    fn constitutional_requires_human() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Constitutional, &mut clock);
        let vote = ai_vote(&d, &mut clock);
        add_resolved_vote(&mut d, vote).expect("ok");
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
        let d = make_decision(DecisionClass::Routine, &mut clock);
        assert!(is_human_vote(&human_vote(&d, &mut clock)));
        assert!(!is_human_vote(&ai_vote(&d, &mut clock)));
        assert!(is_ai_vote(&ai_vote(&d, &mut clock)));
        assert!(!is_ai_vote(&human_vote(&d, &mut clock)));
    }

    #[test]
    fn caller_asserted_human_without_signature_evidence_does_not_satisfy_gate() {
        let mut clock = test_clock();
        let policy = HumanGatePolicy::default();
        let mut d = make_decision(DecisionClass::Strategic, &mut clock);
        d.votes.push(Vote {
            voter_did: Did::new("did:exo:forged-human").expect("valid DID"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::Human,
            timestamp: clock.now().expect("HLC timestamp"),
            signature_hash: Hash256::ZERO,
            provenance: None,
        });

        let err = enforce_human_gate(&policy, &d)
            .expect_err("self-asserted human votes must not satisfy human gate");

        assert!(matches!(
            err,
            ForumError::HumanGateRequired | ForumError::AiCeilingExceeded { .. }
        ));
        assert!(
            !is_human_vote(&d.votes[0]),
            "human vote classification must require verified provenance evidence"
        );
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
