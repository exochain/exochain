//! The Decision Object — core domain type of the decision.forum.
//!
//! A Decision Object is:
//! - Storable, diffable, transferable, auditable, contestable (Axiom 2)
//! - Bound to constitutional version at creation (GOV-002)
//! - 14-state lifecycle matching BCTS (`exo_core::bcts`)
//! - Immutable after terminal status (TNC-08)

use exo_core::{
    bcts::BctsState,
    hash::hash_structured,
    types::{DeterministicMap, Did, Hash256, Timestamp},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ForumError, Result};

/// Classification of a decision, determining quorum, authority, and gate requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DecisionClass {
    /// Day-to-day operational decisions.
    Routine,
    /// Decisions affecting operations or resources.
    Operational,
    /// Long-term or high-impact decisions.
    Strategic,
    /// Decisions that modify the constitutional corpus itself.
    Constitutional,
}

/// Distinguishes human vs AI actors for human-gate enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorKind {
    Human,
    AiAgent {
        delegation_id: String,
        ceiling_class: DecisionClass,
    },
}

/// A single vote cast on a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub voter_did: Did,
    pub choice: VoteChoice,
    pub actor_kind: ActorKind,
    pub timestamp: Timestamp,
    pub signature_hash: Hash256,
}

/// Vote choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

/// A link in the authority chain attesting to delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLink {
    pub actor_did: Did,
    pub actor_kind: ActorKind,
    pub delegation_hash: Hash256,
    pub timestamp: Timestamp,
}

/// A piece of evidence attached to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub hash: Hash256,
    pub description: String,
    pub attached_at: Timestamp,
}

/// A receipt recording a lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleReceipt {
    pub from_state: BctsState,
    pub to_state: BctsState,
    pub actor_did: Did,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash256,
}

/// The core Decision Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionObject {
    pub id: Uuid,
    pub title: String,
    pub class: DecisionClass,
    pub constitutional_hash: Hash256,
    pub state: BctsState,
    pub authority_chain: Vec<AuthorityLink>,
    pub votes: Vec<Vote>,
    pub evidence_bundle: Vec<EvidenceItem>,
    pub receipt_chain: Vec<LifecycleReceipt>,
    pub created_at: Timestamp,
    pub metadata: DeterministicMap<String, String>,
}

/// Caller-supplied metadata for constructing a [`DecisionObject`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionObjectInput {
    pub id: Uuid,
    pub title: String,
    pub class: DecisionClass,
    pub constitutional_hash: Hash256,
    pub created_at: Timestamp,
}

impl DecisionObject {
    /// Create a new Decision Object in the Draft state, bound to the given
    /// constitutional hash.
    pub fn new(input: DecisionObjectInput) -> Result<Self> {
        validate_uuid(input.id, "decision id")?;
        validate_timestamp(input.created_at, "decision created_at")?;
        if input.title.trim().is_empty() {
            return Err(ForumError::InvalidProvenance {
                reason: "decision title must be non-empty".into(),
            });
        }
        if input.constitutional_hash == Hash256::ZERO {
            return Err(ForumError::InvalidProvenance {
                reason: "constitutional hash must be non-zero".into(),
            });
        }

        Ok(Self {
            id: input.id,
            title: input.title,
            class: input.class,
            constitutional_hash: input.constitutional_hash,
            state: BctsState::Draft,
            authority_chain: Vec::new(),
            votes: Vec::new(),
            evidence_bundle: Vec::new(),
            receipt_chain: Vec::new(),
            created_at: input.created_at,
            metadata: DeterministicMap::new(),
        })
    }

    /// Returns true if this decision is in a terminal state (Closed or
    /// Denied with no remediation pending).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state == BctsState::Closed
    }

    /// Transition the decision to a new BCTS state, recording a receipt.
    pub fn transition_at(
        &mut self,
        to: BctsState,
        actor: &Did,
        timestamp: Timestamp,
    ) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        if !self.state.can_transition_to(to) {
            return Err(ForumError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: format!("{to:?}"),
            });
        }
        self.validate_transition_timestamp(timestamp)?;

        let receipt_hash = self.compute_receipt_hash(self.state, to, &timestamp, actor)?;

        self.receipt_chain.push(LifecycleReceipt {
            from_state: self.state,
            to_state: to,
            actor_did: actor.clone(),
            timestamp,
            receipt_hash,
        });
        self.state = to;
        Ok(())
    }

    fn validate_transition_timestamp(&self, timestamp: Timestamp) -> Result<()> {
        validate_timestamp(timestamp, "transition timestamp")?;
        let floor = self
            .receipt_chain
            .last()
            .map(|r| r.timestamp)
            .unwrap_or(self.created_at);
        if timestamp <= floor {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "transition timestamp {:?} must be greater than prior timestamp {:?}",
                    timestamp, floor
                ),
            });
        }
        Ok(())
    }

    /// Add a vote to this decision.
    pub fn add_vote(&mut self, vote: Vote) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        // Prevent duplicate votes from the same DID.
        if self.votes.iter().any(|v| v.voter_did == vote.voter_did) {
            return Err(ForumError::EnactmentFailed {
                reason: format!("duplicate vote from {}", vote.voter_did),
            });
        }
        self.votes.push(vote);
        Ok(())
    }

    /// Add evidence to this decision.
    pub fn add_evidence(&mut self, item: EvidenceItem) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        self.evidence_bundle.push(item);
        Ok(())
    }

    /// Add an authority link to the chain.
    pub fn add_authority_link(&mut self, link: AuthorityLink) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        self.authority_chain.push(link);
        Ok(())
    }

    /// Compute a content hash over the full decision object for auditing.
    pub fn content_hash(&self) -> Result<Hash256> {
        #[derive(Serialize)]
        struct HashInput<'a> {
            id: &'a Uuid,
            title: &'a str,
            class: &'a DecisionClass,
            constitutional_hash: &'a Hash256,
            state: &'a BctsState,
            vote_count: usize,
            evidence_count: usize,
            receipt_count: usize,
        }
        let input = HashInput {
            id: &self.id,
            title: &self.title,
            class: &self.class,
            constitutional_hash: &self.constitutional_hash,
            state: &self.state,
            vote_count: self.votes.len(),
            evidence_count: self.evidence_bundle.len(),
            receipt_count: self.receipt_chain.len(),
        };
        hash_structured(&input).map_err(ForumError::from)
    }

    /// Compute a chained receipt hash.
    fn compute_receipt_hash(
        &self,
        from: BctsState,
        to: BctsState,
        timestamp: &Timestamp,
        actor: &Did,
    ) -> Result<Hash256> {
        #[derive(Serialize)]
        struct ReceiptInput<'a> {
            from: BctsState,
            to: BctsState,
            timestamp: &'a Timestamp,
            actor: &'a str,
            prev_hash: Hash256,
        }
        let prev = self
            .receipt_chain
            .last()
            .map(|r| r.receipt_hash)
            .unwrap_or(Hash256::ZERO);
        let input = ReceiptInput {
            from,
            to,
            timestamp,
            actor: actor.as_str(),
            prev_hash: prev,
        };
        hash_structured(&input).map_err(ForumError::from)
    }
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use exo_core::hlc::HybridClock;

    use super::*;

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn test_did() -> Did {
        Did::new("did:exo:test-actor").expect("valid")
    }

    fn make_decision(clock: &mut HybridClock) -> DecisionObject {
        DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(1),
            title: "Test Decision".into(),
            class: DecisionClass::Operational,
            constitutional_hash: Hash256::digest(b"const-v1"),
            created_at: clock.now(),
        })
        .expect("valid decision")
    }

    #[test]
    fn new_decision_requires_caller_supplied_identity_and_hlc() {
        let input = DecisionObjectInput {
            id: Uuid::from_u128(42),
            title: "Deterministic Decision".into(),
            class: DecisionClass::Strategic,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: Timestamp::new(10_000, 0),
        };
        let first = DecisionObject::new(input.clone()).expect("valid decision");
        let second = DecisionObject::new(input).expect("same metadata valid");

        assert_eq!(first.id, Uuid::from_u128(42));
        assert_eq!(first.created_at, Timestamp::new(10_000, 0));
        assert_eq!(
            first.content_hash().expect("hash"),
            second.content_hash().expect("hash")
        );

        let nil_id = DecisionObject::new(DecisionObjectInput {
            id: Uuid::nil(),
            title: "bad".into(),
            class: DecisionClass::Routine,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: Timestamp::new(10_000, 0),
        })
        .unwrap_err();
        assert!(matches!(nil_id, ForumError::InvalidProvenance { .. }));

        let zero_time = DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(43),
            title: "bad".into(),
            class: DecisionClass::Routine,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: Timestamp::ZERO,
        })
        .unwrap_err();
        assert!(matches!(zero_time, ForumError::InvalidProvenance { .. }));
    }

    #[test]
    fn transition_requires_caller_supplied_monotonic_hlc() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);

        d.transition_at(BctsState::Submitted, &actor, Timestamp::new(10_001, 0))
            .expect("submitted");

        let zero = d
            .transition_at(BctsState::IdentityResolved, &actor, Timestamp::ZERO)
            .unwrap_err();
        assert!(matches!(zero, ForumError::InvalidProvenance { .. }));

        let regressive = d
            .transition_at(
                BctsState::IdentityResolved,
                &actor,
                Timestamp::new(10_000, 0),
            )
            .unwrap_err();
        assert!(matches!(regressive, ForumError::InvalidProvenance { .. }));

        d.transition_at(
            BctsState::IdentityResolved,
            &actor,
            Timestamp::new(10_002, 0),
        )
        .expect("monotonic transition");
    }

    #[test]
    fn new_decision_is_draft() {
        let mut clock = test_clock();
        let d = make_decision(&mut clock);
        assert_eq!(d.state, BctsState::Draft);
        assert_eq!(d.class, DecisionClass::Operational);
        assert!(d.votes.is_empty());
        assert!(d.evidence_bundle.is_empty());
        assert!(d.receipt_chain.is_empty());
        assert!(d.authority_chain.is_empty());
    }

    #[test]
    fn transition_draft_to_submitted() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now();
        d.transition_at(BctsState::Submitted, &test_did(), ts)
            .expect("ok");
        assert_eq!(d.state, BctsState::Submitted);
        assert_eq!(d.receipt_chain.len(), 1);
    }

    #[test]
    fn transition_invalid_rejects() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now();
        let err = d
            .transition_at(BctsState::Closed, &test_did(), ts)
            .unwrap_err();
        assert!(matches!(err, ForumError::InvalidTransition { .. }));
    }

    #[test]
    fn full_lifecycle() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let steps = [
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Verified,
            BctsState::Governed,
            BctsState::Approved,
            BctsState::Executed,
            BctsState::Recorded,
            BctsState::Closed,
        ];
        for s in steps {
            let ts = clock.now();
            d.transition_at(s, &actor, ts).expect("ok");
        }
        assert!(d.is_terminal());
        assert_eq!(d.receipt_chain.len(), 10);
    }

    #[test]
    fn terminal_decision_is_immutable() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        for s in [
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Verified,
            BctsState::Governed,
            BctsState::Approved,
            BctsState::Executed,
            BctsState::Recorded,
            BctsState::Closed,
        ] {
            let ts = clock.now();
            d.transition_at(s, &actor, ts).expect("ok");
        }
        let ts = clock.now();
        assert!(d.transition_at(BctsState::Draft, &actor, ts).is_err());
        assert!(
            d.add_vote(Vote {
                voter_did: actor.clone(),
                choice: VoteChoice::Approve,
                actor_kind: ActorKind::Human,
                timestamp: clock.now(),
                signature_hash: Hash256::ZERO,
            })
            .is_err()
        );
        assert!(
            d.add_evidence(EvidenceItem {
                hash: Hash256::ZERO,
                description: "x".into(),
                attached_at: clock.now(),
            })
            .is_err()
        );
    }

    #[test]
    fn add_vote_prevents_duplicates() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let ts = clock.now();
        d.add_vote(Vote {
            voter_did: actor.clone(),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::Human,
            timestamp: ts,
            signature_hash: Hash256::ZERO,
        })
        .expect("ok");
        let err = d
            .add_vote(Vote {
                voter_did: actor.clone(),
                choice: VoteChoice::Reject,
                actor_kind: ActorKind::Human,
                timestamp: ts,
                signature_hash: Hash256::ZERO,
            })
            .unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn content_hash_deterministic() {
        let mut clock = test_clock();
        let d = make_decision(&mut clock);
        let h1 = d.content_hash().expect("ok");
        let h2 = d.content_hash().expect("ok");
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_changes_with_state() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let h1 = d.content_hash().expect("ok");
        let ts = clock.now();
        d.transition_at(BctsState::Submitted, &actor, ts)
            .expect("ok");
        let h2 = d.content_hash().expect("ok");
        assert_ne!(h1, h2);
    }

    #[test]
    fn receipt_chain_hashes_differ() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let ts = clock.now();
        d.transition_at(BctsState::Submitted, &actor, ts)
            .expect("ok");
        let ts = clock.now();
        d.transition_at(BctsState::IdentityResolved, &actor, ts)
            .expect("ok");
        assert_ne!(
            d.receipt_chain[0].receipt_hash,
            d.receipt_chain[1].receipt_hash
        );
    }

    #[test]
    fn decision_class_ordering() {
        assert!(DecisionClass::Routine < DecisionClass::Operational);
        assert!(DecisionClass::Operational < DecisionClass::Strategic);
        assert!(DecisionClass::Strategic < DecisionClass::Constitutional);
    }

    #[test]
    fn constitutional_hash_bound_at_creation() {
        let mut clock = test_clock();
        let hash = Hash256::digest(b"test-constitution");
        let d = DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(2),
            title: "test".into(),
            class: DecisionClass::Routine,
            constitutional_hash: hash,
            created_at: clock.now(),
        })
        .expect("valid");
        assert_eq!(d.constitutional_hash, hash);
    }

    #[test]
    fn add_authority_link() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now();
        d.add_authority_link(AuthorityLink {
            actor_did: test_did(),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: ts,
        })
        .expect("ok");
        assert_eq!(d.authority_chain.len(), 1);
    }

    #[test]
    fn serde_roundtrip() {
        let mut clock = test_clock();
        let d = make_decision(&mut clock);
        let json = serde_json::to_string(&d).expect("ser");
        let d2: DecisionObject = serde_json::from_str(&json).expect("de");
        assert_eq!(d.id, d2.id);
        assert_eq!(d.title, d2.title);
        assert_eq!(d.state, d2.state);
    }
}
