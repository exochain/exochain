//! Bailment-Conditioned Transaction Set (BCTS) state machine.
//!
//! The BCTS is the constitutional transaction lifecycle within EXOCHAIN.
//! Every transaction moves through a strict state machine with
//! cryptographic receipt chaining, actor attribution, and HLC-ordered
//! transitions.

use serde::{Deserialize, Serialize};

use crate::{
    error::{ExoError, Result},
    hash::hash_structured,
    hlc::HybridClock,
    types::{CorrelationId, Did, Hash256, Timestamp},
};

// ---------------------------------------------------------------------------
// BctsState
// ---------------------------------------------------------------------------

/// The lifecycle states of a BCTS transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BctsState {
    Draft,
    Submitted,
    IdentityResolved,
    ConsentValidated,
    Deliberated,
    Verified,
    Governed,
    Approved,
    Executed,
    Recorded,
    Closed,
    Denied,
    Escalated,
    Remediated,
}

impl BctsState {
    /// Return the set of states that are valid successors of `self`.
    #[must_use]
    pub fn valid_transitions(self) -> &'static [BctsState] {
        use BctsState::*;
        match self {
            Draft => &[Submitted],
            Submitted => &[IdentityResolved, Denied],
            IdentityResolved => &[ConsentValidated, Denied],
            ConsentValidated => &[Deliberated, Denied],
            Deliberated => &[Verified, Denied, Escalated],
            Verified => &[Governed, Denied, Escalated],
            Governed => &[Approved, Denied, Escalated],
            Approved => &[Executed, Denied],
            Executed => &[Recorded, Escalated],
            Recorded => &[Closed, Escalated],
            Closed => &[],
            Denied => &[Remediated],
            Escalated => &[Deliberated, Denied, Remediated],
            Remediated => &[Submitted],
        }
    }

    /// Check whether transitioning to `target` is allowed.
    #[must_use]
    pub fn can_transition_to(self, target: BctsState) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl core::fmt::Display for BctsState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ---------------------------------------------------------------------------
// BctsTransition
// ---------------------------------------------------------------------------

/// Record of a single state transition in a BCTS transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BctsTransition {
    pub from_state: BctsState,
    pub to_state: BctsState,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash256,
    pub actor_did: Did,
}

// ---------------------------------------------------------------------------
// BailmentTransaction trait
// ---------------------------------------------------------------------------

/// The contract every BCTS transaction implementation must satisfy.
pub trait BailmentTransaction {
    /// Current state of the transaction.
    fn state(&self) -> BctsState;

    /// Attempt a state transition.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::InvalidTransition` if the transition violates the
    /// state machine.
    fn transition(
        &mut self,
        to: BctsState,
        actor: &Did,
        clock: &mut HybridClock,
    ) -> Result<BctsTransition>;

    /// The chain of receipt hashes for every transition so far.
    fn receipt_chain(&self) -> &[Hash256];

    /// The correlation ID for end-to-end tracking.
    fn correlation_id(&self) -> &CorrelationId;
}

// ---------------------------------------------------------------------------
// Transaction (concrete implementation)
// ---------------------------------------------------------------------------

/// A concrete BCTS transaction with receipt-chain integrity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    correlation_id: CorrelationId,
    current_state: BctsState,
    receipt_chain: Vec<Hash256>,
    transitions: Vec<BctsTransition>,
}

impl Transaction {
    /// Create a new transaction in the `Draft` state.
    #[must_use]
    pub fn new(correlation_id: CorrelationId) -> Self {
        Self {
            correlation_id,
            current_state: BctsState::Draft,
            receipt_chain: Vec::new(),
            transitions: Vec::new(),
        }
    }

    /// Return all recorded transitions.
    #[must_use]
    pub fn transitions(&self) -> &[BctsTransition] {
        &self.transitions
    }

    /// Compute a receipt hash that chains to the previous receipt.
    fn compute_receipt(
        &self,
        from: BctsState,
        to: BctsState,
        timestamp: &Timestamp,
        actor: &Did,
    ) -> Result<Hash256> {
        // Build a canonical structure to hash
        #[derive(Serialize)]
        struct ReceiptInput<'a> {
            from: BctsState,
            to: BctsState,
            timestamp: &'a Timestamp,
            actor: &'a str,
            prev_hash: Hash256,
        }
        let prev = self.receipt_chain.last().copied().unwrap_or(Hash256::ZERO);
        let input = ReceiptInput {
            from,
            to,
            timestamp,
            actor: actor.as_str(),
            prev_hash: prev,
        };
        hash_structured(&input)
    }

    /// Verify the integrity of the receipt chain.
    ///
    /// Re-computes each receipt from the corresponding transition and checks
    /// it matches the stored receipt.
    pub fn verify_receipt_chain(&self) -> Result<()> {
        let mut prev = Hash256::ZERO;
        for (i, transition) in self.transitions.iter().enumerate() {
            #[derive(Serialize)]
            struct ReceiptInput<'a> {
                from: BctsState,
                to: BctsState,
                timestamp: &'a Timestamp,
                actor: &'a str,
                prev_hash: Hash256,
            }
            let input = ReceiptInput {
                from: transition.from_state,
                to: transition.to_state,
                timestamp: &transition.timestamp,
                actor: transition.actor_did.as_str(),
                prev_hash: prev,
            };
            let computed = hash_structured(&input)?;
            if computed != transition.receipt_hash {
                return Err(ExoError::ReceiptChainBroken { index: i });
            }
            if i < self.receipt_chain.len() && self.receipt_chain[i] != computed {
                return Err(ExoError::ReceiptChainBroken { index: i });
            }
            prev = computed;
        }
        Ok(())
    }
}

impl BailmentTransaction for Transaction {
    fn state(&self) -> BctsState {
        self.current_state
    }

    fn transition(
        &mut self,
        to: BctsState,
        actor: &Did,
        clock: &mut HybridClock,
    ) -> Result<BctsTransition> {
        let from = self.current_state;
        if !from.can_transition_to(to) {
            return Err(ExoError::InvalidTransition {
                from: from.to_string(),
                to: to.to_string(),
            });
        }

        let timestamp = clock.now();
        let receipt_hash = self.compute_receipt(from, to, &timestamp, actor)?;

        let transition = BctsTransition {
            from_state: from,
            to_state: to,
            timestamp,
            receipt_hash,
            actor_did: actor.clone(),
        };

        self.current_state = to;
        self.receipt_chain.push(receipt_hash);
        self.transitions.push(transition.clone());

        Ok(transition)
    }

    fn receipt_chain(&self) -> &[Hash256] {
        &self.receipt_chain
    }

    fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! correlation_id {
        () => {
            CorrelationId::from_uuid(uuid::Uuid::from_u128(u128::from(line!())))
        };
    }

    fn test_clock() -> HybridClock {
        let counter = std::sync::atomic::AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        })
    }

    fn test_did() -> Did {
        Did::new("did:exo:test-actor").expect("valid")
    }

    // -- BctsState ---------------------------------------------------------

    #[test]
    fn state_display() {
        assert_eq!(BctsState::Draft.to_string(), "Draft");
        assert_eq!(BctsState::Closed.to_string(), "Closed");
    }

    #[test]
    fn draft_can_only_go_to_submitted() {
        assert!(BctsState::Draft.can_transition_to(BctsState::Submitted));
        assert!(!BctsState::Draft.can_transition_to(BctsState::Closed));
        assert!(!BctsState::Draft.can_transition_to(BctsState::Draft));
    }

    #[test]
    fn submitted_transitions() {
        assert!(BctsState::Submitted.can_transition_to(BctsState::IdentityResolved));
        assert!(BctsState::Submitted.can_transition_to(BctsState::Denied));
        assert!(!BctsState::Submitted.can_transition_to(BctsState::Closed));
    }

    #[test]
    fn identity_resolved_transitions() {
        assert!(BctsState::IdentityResolved.can_transition_to(BctsState::ConsentValidated));
        assert!(BctsState::IdentityResolved.can_transition_to(BctsState::Denied));
        assert!(!BctsState::IdentityResolved.can_transition_to(BctsState::Submitted));
    }

    #[test]
    fn consent_validated_transitions() {
        assert!(BctsState::ConsentValidated.can_transition_to(BctsState::Deliberated));
        assert!(BctsState::ConsentValidated.can_transition_to(BctsState::Denied));
        assert!(!BctsState::ConsentValidated.can_transition_to(BctsState::Executed));
    }

    #[test]
    fn deliberated_transitions() {
        assert!(BctsState::Deliberated.can_transition_to(BctsState::Verified));
        assert!(BctsState::Deliberated.can_transition_to(BctsState::Denied));
        assert!(BctsState::Deliberated.can_transition_to(BctsState::Escalated));
        assert!(!BctsState::Deliberated.can_transition_to(BctsState::Closed));
    }

    #[test]
    fn verified_transitions() {
        assert!(BctsState::Verified.can_transition_to(BctsState::Governed));
        assert!(BctsState::Verified.can_transition_to(BctsState::Denied));
        assert!(BctsState::Verified.can_transition_to(BctsState::Escalated));
    }

    #[test]
    fn governed_transitions() {
        assert!(BctsState::Governed.can_transition_to(BctsState::Approved));
        assert!(BctsState::Governed.can_transition_to(BctsState::Denied));
        assert!(BctsState::Governed.can_transition_to(BctsState::Escalated));
    }

    #[test]
    fn approved_transitions() {
        assert!(BctsState::Approved.can_transition_to(BctsState::Executed));
        assert!(BctsState::Approved.can_transition_to(BctsState::Denied));
        assert!(!BctsState::Approved.can_transition_to(BctsState::Escalated));
    }

    #[test]
    fn executed_transitions() {
        assert!(BctsState::Executed.can_transition_to(BctsState::Recorded));
        assert!(BctsState::Executed.can_transition_to(BctsState::Escalated));
        assert!(!BctsState::Executed.can_transition_to(BctsState::Denied));
    }

    #[test]
    fn recorded_transitions() {
        assert!(BctsState::Recorded.can_transition_to(BctsState::Closed));
        assert!(BctsState::Recorded.can_transition_to(BctsState::Escalated));
        assert!(!BctsState::Recorded.can_transition_to(BctsState::Denied));
    }

    #[test]
    fn closed_is_terminal() {
        assert!(BctsState::Closed.valid_transitions().is_empty());
        assert!(!BctsState::Closed.can_transition_to(BctsState::Draft));
    }

    #[test]
    fn denied_transitions() {
        assert!(BctsState::Denied.can_transition_to(BctsState::Remediated));
        assert!(!BctsState::Denied.can_transition_to(BctsState::Closed));
    }

    #[test]
    fn escalated_transitions() {
        assert!(BctsState::Escalated.can_transition_to(BctsState::Deliberated));
        assert!(BctsState::Escalated.can_transition_to(BctsState::Denied));
        assert!(BctsState::Escalated.can_transition_to(BctsState::Remediated));
    }

    #[test]
    fn remediated_transitions() {
        assert!(BctsState::Remediated.can_transition_to(BctsState::Submitted));
        assert!(!BctsState::Remediated.can_transition_to(BctsState::Closed));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = BctsState::Governed;
        let json = serde_json::to_string(&s).expect("ser");
        let s2: BctsState = serde_json::from_str(&json).expect("de");
        assert_eq!(s, s2);
    }

    #[test]
    fn state_ord() {
        // Just ensure Ord is implemented and doesn't panic
        let mut states = vec![BctsState::Closed, BctsState::Draft, BctsState::Executed];
        states.sort();
        // We don't care about the specific order, just that it's deterministic
        let mut states2 = vec![BctsState::Closed, BctsState::Draft, BctsState::Executed];
        states2.sort();
        assert_eq!(states, states2);
    }

    // -- Transaction -------------------------------------------------------

    #[test]
    fn new_transaction_is_draft() {
        let cid = correlation_id!();
        let tx = Transaction::new(cid);
        assert_eq!(tx.state(), BctsState::Draft);
        assert!(tx.receipt_chain().is_empty());
        assert!(tx.transitions().is_empty());
        assert_eq!(*tx.correlation_id(), cid);
    }

    #[test]
    fn happy_path_full_lifecycle() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

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

        for (i, &target) in steps.iter().enumerate() {
            let t = tx
                .transition(target, &actor, &mut clock)
                .expect("transition ok");
            assert_eq!(t.to_state, target);
            assert_eq!(tx.state(), target);
            assert_eq!(tx.receipt_chain().len(), i + 1);
        }

        // Verify full chain integrity
        tx.verify_receipt_chain().expect("chain valid");
    }

    #[test]
    fn invalid_transition_from_draft_to_closed() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        let err = tx
            .transition(BctsState::Closed, &actor, &mut clock)
            .unwrap_err();
        assert!(matches!(err, ExoError::InvalidTransition { .. }));
        // State should not have changed
        assert_eq!(tx.state(), BctsState::Draft);
    }

    #[test]
    fn invalid_transition_from_closed() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        // Go to Closed via happy path
        for &s in &[
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
            tx.transition(s, &actor, &mut clock).expect("ok");
        }

        // Closed is terminal
        let err = tx
            .transition(BctsState::Draft, &actor, &mut clock)
            .unwrap_err();
        assert!(matches!(err, ExoError::InvalidTransition { .. }));
    }

    #[test]
    fn denial_path() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        tx.transition(BctsState::Denied, &actor, &mut clock)
            .expect("ok");
        assert_eq!(tx.state(), BctsState::Denied);
        tx.verify_receipt_chain().expect("chain valid");
    }

    #[test]
    fn escalation_path() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        for &s in &[
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Escalated,
            BctsState::Deliberated,
            BctsState::Verified,
        ] {
            tx.transition(s, &actor, &mut clock).expect("ok");
        }
        assert_eq!(tx.state(), BctsState::Verified);
        tx.verify_receipt_chain().expect("chain valid");
    }

    #[test]
    fn remediation_path() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        tx.transition(BctsState::Denied, &actor, &mut clock)
            .expect("ok");
        tx.transition(BctsState::Remediated, &actor, &mut clock)
            .expect("ok");
        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        assert_eq!(tx.state(), BctsState::Submitted);
        tx.verify_receipt_chain().expect("chain valid");
    }

    #[test]
    fn receipt_chain_grows_monotonically() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        assert_eq!(tx.receipt_chain().len(), 1);

        tx.transition(BctsState::IdentityResolved, &actor, &mut clock)
            .expect("ok");
        assert_eq!(tx.receipt_chain().len(), 2);

        // Each receipt should be unique
        assert_ne!(tx.receipt_chain()[0], tx.receipt_chain()[1]);
    }

    #[test]
    fn transition_records_correct_actor() {
        let mut clock = test_clock();
        let actor = Did::new("did:exo:alice").expect("valid");
        let mut tx = Transaction::new(correlation_id!());

        let t = tx
            .transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        assert_eq!(t.actor_did, actor);
    }

    #[test]
    fn transition_timestamps_are_monotonic() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        tx.transition(BctsState::IdentityResolved, &actor, &mut clock)
            .expect("ok");

        let ts = &tx.transitions();
        assert!(ts[0].timestamp < ts[1].timestamp);
    }

    #[test]
    fn verify_receipt_chain_detects_tampering() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");
        tx.transition(BctsState::IdentityResolved, &actor, &mut clock)
            .expect("ok");

        // Tamper with a receipt
        tx.receipt_chain[0] = Hash256::ZERO;
        let err = tx.verify_receipt_chain().unwrap_err();
        assert!(matches!(err, ExoError::ReceiptChainBroken { index: 0 }));
    }

    #[test]
    fn transaction_serde_roundtrip() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());
        tx.transition(BctsState::Submitted, &actor, &mut clock)
            .expect("ok");

        let json = serde_json::to_string(&tx).expect("ser");
        let tx2: Transaction = serde_json::from_str(&json).expect("de");
        assert_eq!(tx.state(), tx2.state());
        assert_eq!(tx.receipt_chain(), tx2.receipt_chain());
        assert_eq!(tx.correlation_id(), tx2.correlation_id());
    }

    #[test]
    fn every_invalid_transition_from_each_state() {
        // Exhaustively test that no invalid transition is accepted.
        let all_states = [
            BctsState::Draft,
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
            BctsState::Denied,
            BctsState::Escalated,
            BctsState::Remediated,
        ];

        for &from in &all_states {
            let valid = from.valid_transitions();
            for &to in &all_states {
                if valid.contains(&to) {
                    assert!(
                        from.can_transition_to(to),
                        "{from} should be able to transition to {to}"
                    );
                } else {
                    assert!(
                        !from.can_transition_to(to),
                        "{from} should NOT be able to transition to {to}"
                    );
                }
            }
        }
    }

    #[test]
    fn escalated_to_denied_to_remediated_to_submitted() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        for &s in &[
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Escalated,
            BctsState::Denied,
            BctsState::Remediated,
            BctsState::Submitted,
        ] {
            tx.transition(s, &actor, &mut clock).expect("ok");
        }
        assert_eq!(tx.state(), BctsState::Submitted);
        tx.verify_receipt_chain().expect("chain valid");
    }

    #[test]
    fn escalated_to_remediated() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut tx = Transaction::new(correlation_id!());

        for &s in &[
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Escalated,
            BctsState::Remediated,
            BctsState::Submitted,
        ] {
            tx.transition(s, &actor, &mut clock).expect("ok");
        }
        tx.verify_receipt_chain().expect("chain valid");
    }
}
