//! Integration tests for `exo-core`.
//!
//! These tests exercise cross-module interactions that unit tests in
//! individual modules don't cover.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::{
    bcts::{
        BailmentTransaction, BctsState, BctsTransitionAdjudicator, BctsTransitionRequest,
        Transaction,
    },
    crypto::KeyPair,
    events::{EventType, create_signed_event, verify_event},
    hash::{canonical_hash, hash_structured, merkle_proof, merkle_root, verify_merkle_proof},
    hlc::HybridClock,
    invariants::{
        Invariant, InvariantContext, InvariantSet, InvariantViolation, ViolationSeverity, check_all,
    },
    types::{CorrelationId, DeterministicMap, Did, Hash256, Timestamp, Version},
};

struct AllowAllAdjudicator;

impl BctsTransitionAdjudicator for AllowAllAdjudicator {
    fn adjudicate_transition(&self, _request: &BctsTransitionRequest) -> exo_core::Result<()> {
        Ok(())
    }
}

macro_rules! correlation_id {
    () => {
        CorrelationId::from_uuid(uuid::Uuid::from_u128(u128::from(line!())))
    };
}

fn indexed_correlation_id(base: u128, index: usize) -> CorrelationId {
    let offset = match u128::try_from(index) {
        Ok(value) => value,
        Err(_) => panic!("test correlation index must fit in u128"),
    };
    CorrelationId::from_uuid(uuid::Uuid::from_u128(base + offset))
}

// ---------------------------------------------------------------------------
// Full BCTS lifecycle with crypto + events
// ---------------------------------------------------------------------------

#[test]
fn full_bcts_lifecycle_with_signed_events() {
    let kp = KeyPair::generate();
    let actor = Did::new("did:exo:integration-actor").expect("valid");
    let mut clock = HybridClock::new();
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

    for (index, &target) in steps.iter().enumerate() {
        let transition = tx
            .transition(target, &actor, &mut clock, &AllowAllAdjudicator)
            .expect("ok");

        // Create a signed event for each transition
        let event = create_signed_event(
            indexed_correlation_id(1_000, index),
            transition.timestamp,
            EventType::TransactionStateChanged,
            transition.receipt_hash.as_bytes().to_vec(),
            actor.clone(),
            kp.secret_key(),
        )
        .expect("sign event");
        assert!(verify_event(&event, kp.public_key()));
    }

    assert_eq!(tx.state(), BctsState::Closed);
    tx.verify_receipt_chain().expect("chain valid");
}

// ---------------------------------------------------------------------------
// Receipt chain hashes form a valid merkle tree
// ---------------------------------------------------------------------------

#[test]
fn receipt_chain_merkle_tree() {
    let actor = Did::new("did:exo:merkle-actor").expect("valid");
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    for &s in &[
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
        BctsState::Deliberated,
    ] {
        tx.transition(s, &actor, &mut clock, &AllowAllAdjudicator)
            .expect("ok");
    }

    let receipts = tx.receipt_chain();
    assert_eq!(receipts.len(), 4);

    let root = merkle_root(receipts);
    assert_ne!(root, Hash256::ZERO);

    // Verify each leaf's proof
    for i in 0..receipts.len() {
        let proof = merkle_proof(receipts, i).expect("ok");
        assert!(
            verify_merkle_proof(&root, &receipts[i], &proof, i),
            "merkle proof failed for receipt {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-module: hashing + crypto
// ---------------------------------------------------------------------------

#[test]
fn signed_hash_verification() {
    let kp = KeyPair::generate();

    let data = b"constitutional trust fabric";
    let hash = canonical_hash(data);

    // Sign the hash
    let sig = kp.sign(hash.as_bytes());
    assert!(kp.verify(hash.as_bytes(), &sig));

    // Tampered hash should fail
    let mut tampered = *hash.as_bytes();
    tampered[0] ^= 0xff;
    assert!(!kp.verify(&tampered, &sig));
}

#[test]
fn hash_structured_with_deterministic_map() {
    let mut map = DeterministicMap::new();
    map.insert("z_key".to_string(), 1u32);
    map.insert("a_key".to_string(), 2u32);

    let h1 = hash_structured(&map).expect("ok");

    // Build the same map with different insertion order
    let mut map2 = DeterministicMap::new();
    map2.insert("a_key".to_string(), 2u32);
    map2.insert("z_key".to_string(), 1u32);

    let h2 = hash_structured(&map2).expect("ok");

    // Deterministic: same logical content = same hash
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// Cross-module: invariants + BCTS
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TransactionNotClosed {
    state: BctsState,
}

impl Invariant for TransactionNotClosed {
    fn name(&self) -> &str {
        "transaction_not_closed"
    }

    fn check(&self, _context: &InvariantContext) -> core::result::Result<(), InvariantViolation> {
        if self.state == BctsState::Closed {
            Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "transaction is already closed".to_string(),
                severity: ViolationSeverity::Error,
                context: DeterministicMap::new(),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn invariant_check_on_bcts_state() {
    let actor = Did::new("did:exo:inv-actor").expect("valid");
    let ctx = InvariantContext::new(actor, Timestamp::new(1000, 0), Hash256::ZERO);

    let mut set = InvariantSet::new();
    set.add(TransactionNotClosed {
        state: BctsState::Draft,
    });
    assert!(check_all(&set, &ctx).is_ok());

    let mut failing_set = InvariantSet::new();
    failing_set.add(TransactionNotClosed {
        state: BctsState::Closed,
    });
    assert!(check_all(&failing_set, &ctx).is_err());
}

// ---------------------------------------------------------------------------
// HLC + BCTS ordering guarantee
// ---------------------------------------------------------------------------

#[test]
fn hlc_ordering_across_transactions() {
    let mut clock = HybridClock::new();
    let actor = Did::new("did:exo:hlc-actor").expect("valid");

    let mut tx1 = Transaction::new(correlation_id!());
    let t1 = tx1
        .transition(
            BctsState::Submitted,
            &actor,
            &mut clock,
            &AllowAllAdjudicator,
        )
        .expect("ok");

    let mut tx2 = Transaction::new(correlation_id!());
    let t2 = tx2
        .transition(
            BctsState::Submitted,
            &actor,
            &mut clock,
            &AllowAllAdjudicator,
        )
        .expect("ok");

    // t2 must be after t1
    assert!(t2.timestamp > t1.timestamp);
    assert!(HybridClock::is_before(&t1.timestamp, &t2.timestamp));
}

// ---------------------------------------------------------------------------
// Re-export check
// ---------------------------------------------------------------------------

#[test]
fn re_exports_available() {
    // These types should be available from the crate root
    let _cid = correlation_id!();
    let _ts = Timestamp::new(0, 0);
    let _v = Version::ZERO;
    let _h = Hash256::ZERO;
    let _did = Did::new("did:exo:reexport").expect("valid");
    let _map: DeterministicMap<String, String> = DeterministicMap::new();
}

// ---------------------------------------------------------------------------
// Denial + remediation + re-submission cycle
// ---------------------------------------------------------------------------

#[test]
fn denial_remediation_resubmission() {
    let mut clock = HybridClock::new();
    let actor = Did::new("did:exo:cycle-actor").expect("valid");
    let mut tx = Transaction::new(correlation_id!());

    // Submit -> Deny -> Remediate -> Resubmit -> succeed
    tx.transition(
        BctsState::Submitted,
        &actor,
        &mut clock,
        &AllowAllAdjudicator,
    )
    .expect("ok");
    tx.transition(BctsState::Denied, &actor, &mut clock, &AllowAllAdjudicator)
        .expect("ok");
    tx.transition(
        BctsState::Remediated,
        &actor,
        &mut clock,
        &AllowAllAdjudicator,
    )
    .expect("ok");
    tx.transition(
        BctsState::Submitted,
        &actor,
        &mut clock,
        &AllowAllAdjudicator,
    )
    .expect("ok");
    tx.transition(
        BctsState::IdentityResolved,
        &actor,
        &mut clock,
        &AllowAllAdjudicator,
    )
    .expect("ok");

    assert_eq!(tx.state(), BctsState::IdentityResolved);
    assert_eq!(tx.receipt_chain().len(), 5);
    tx.verify_receipt_chain().expect("chain valid");
}

// ---------------------------------------------------------------------------
// Version monotonicity
// ---------------------------------------------------------------------------

#[test]
fn version_monotonicity() {
    let v0 = Version::ZERO;
    let v1 = v0.next();
    let v2 = v1.next();
    assert!(v0 < v1);
    assert!(v1 < v2);
    assert_eq!(v2.value(), 2);
}
