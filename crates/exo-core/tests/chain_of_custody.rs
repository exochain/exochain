//! End-to-end chain-of-custody proof tests.
//!
//! These tests exercise the full chain-of-custody lifecycle across the
//! exo-core crate: BCTS state machine → signed events → receipt chain →
//! Merkle proofs → hash verification → integrity checks.
//!
//! Satisfies: GOV-005 (authority chain), TNC-03 (audit continuity),
//! LEG-001 (business records), EXOCHAIN-REM-004 (coverage ≥ 90%)

#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::{
    bcts::{BailmentTransaction, BctsState, Transaction},
    crypto::{
        KeyPair, PqKeyPair, generate_keypair, generate_pq_keypair, sign, sign_hybrid, sign_pq,
        verify, verify_hybrid, verify_pq,
    },
    events::{EventType, create_signed_event, verify_event},
    hash::{
        canonical_hash, hash_structured, merkle_proof, merkle_root, merkle_root_from_proof,
        verify_merkle_proof,
    },
    hlc::HybridClock,
    types::{
        CorrelationId, DeterministicMap, Did, Hash256, Signature, SignerType, Timestamp, Version,
    },
};

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
// Helper: multi-actor governance scenario
// ---------------------------------------------------------------------------

struct GovernanceActors {
    proposer: (Did, KeyPair),
    reviewer1: (Did, KeyPair),
    reviewer2: (Did, KeyPair),
    steward: (Did, KeyPair),
}

impl GovernanceActors {
    fn new() -> Self {
        Self {
            proposer: (
                Did::new("did:exo:proposer-alice").expect("valid"),
                KeyPair::generate(),
            ),
            reviewer1: (
                Did::new("did:exo:reviewer-bob").expect("valid"),
                KeyPair::generate(),
            ),
            reviewer2: (
                Did::new("did:exo:reviewer-carol").expect("valid"),
                KeyPair::generate(),
            ),
            steward: (
                Did::new("did:exo:steward-dave").expect("valid"),
                KeyPair::generate(),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Multi-actor signed event chain with custody proof
// ---------------------------------------------------------------------------

#[test]
fn multi_actor_signed_event_chain_with_merkle_proof() {
    let actors = GovernanceActors::new();
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    // Phase 1: Proposer submits
    let t1 = tx
        .transition(BctsState::Submitted, &actors.proposer.0, &mut clock)
        .expect("submit ok");
    let event1 = create_signed_event(
        correlation_id!(),
        t1.timestamp,
        EventType::TransactionStateChanged,
        t1.receipt_hash.as_bytes().to_vec(),
        actors.proposer.0.clone(),
        actors.proposer.1.secret_key(),
    )
    .expect("sign event");
    assert!(verify_event(&event1, actors.proposer.1.public_key()));

    // Phase 2: Identity resolution by reviewer1
    let t2 = tx
        .transition(BctsState::IdentityResolved, &actors.reviewer1.0, &mut clock)
        .expect("identity ok");
    let event2 = create_signed_event(
        correlation_id!(),
        t2.timestamp,
        EventType::TransactionStateChanged,
        t2.receipt_hash.as_bytes().to_vec(),
        actors.reviewer1.0.clone(),
        actors.reviewer1.1.secret_key(),
    )
    .expect("sign event");
    assert!(verify_event(&event2, actors.reviewer1.1.public_key()));

    // Phase 3: Consent validation by reviewer2
    let t3 = tx
        .transition(BctsState::ConsentValidated, &actors.reviewer2.0, &mut clock)
        .expect("consent ok");
    let event3 = create_signed_event(
        correlation_id!(),
        t3.timestamp,
        EventType::TransactionStateChanged,
        t3.receipt_hash.as_bytes().to_vec(),
        actors.reviewer2.0.clone(),
        actors.reviewer2.1.secret_key(),
    )
    .expect("sign event");
    assert!(verify_event(&event3, actors.reviewer2.1.public_key()));

    // Phase 4: Deliberation by steward
    let t4 = tx
        .transition(BctsState::Deliberated, &actors.steward.0, &mut clock)
        .expect("deliberation ok");
    let event4 = create_signed_event(
        correlation_id!(),
        t4.timestamp,
        EventType::TransactionStateChanged,
        t4.receipt_hash.as_bytes().to_vec(),
        actors.steward.0.clone(),
        actors.steward.1.secret_key(),
    )
    .expect("sign event");
    assert!(verify_event(&event4, actors.steward.1.public_key()));

    // Verify receipt chain integrity
    tx.verify_receipt_chain().expect("receipt chain valid");

    // Build Merkle tree over receipts
    let receipts = tx.receipt_chain();
    assert_eq!(receipts.len(), 4);
    let root = merkle_root(receipts);
    assert_ne!(root, Hash256::ZERO);

    // Verify each receipt has a valid Merkle proof
    for i in 0..receipts.len() {
        let proof = merkle_proof(receipts, i).expect("proof ok");
        assert!(
            verify_merkle_proof(&root, &receipts[i], &proof, i),
            "merkle proof failed for receipt {i}"
        );
    }

    // Verify cross-actor event signatures don't mix
    assert!(
        !verify_event(&event1, actors.reviewer1.1.public_key()),
        "proposer's event should not verify with reviewer's key"
    );
    assert!(
        !verify_event(&event2, actors.proposer.1.public_key()),
        "reviewer's event should not verify with proposer's key"
    );
}

// ---------------------------------------------------------------------------
// 2. Full lifecycle with denial, remediation, and re-submission proof chain
// ---------------------------------------------------------------------------

#[test]
fn denial_remediation_resubmission_with_full_proof_chain() {
    let kp = KeyPair::generate();
    let actor = Did::new("did:exo:lifecycle-actor").expect("valid");
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    // Submit → Deny → Remediate → Re-submit → Continue to Approved
    let transitions = [
        BctsState::Submitted,
        BctsState::Denied,
        BctsState::Remediated,
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

    let mut events = Vec::new();
    for (index, &target) in transitions.iter().enumerate() {
        let t = tx
            .transition(target, &actor, &mut clock)
            .expect("transition ok");
        let event = create_signed_event(
            indexed_correlation_id(2_000, index),
            t.timestamp,
            EventType::TransactionStateChanged,
            t.receipt_hash.as_bytes().to_vec(),
            actor.clone(),
            kp.secret_key(),
        )
        .expect("sign event");
        assert!(verify_event(&event, kp.public_key()));
        events.push(event);
    }

    assert_eq!(tx.state(), BctsState::Closed);
    assert_eq!(tx.receipt_chain().len(), 13);
    tx.verify_receipt_chain().expect("chain valid");

    // Build Merkle tree over all 13 receipts
    let receipts = tx.receipt_chain();
    let root = merkle_root(receipts);
    assert_ne!(root, Hash256::ZERO);

    // Verify proof for the denial receipt (index 1)
    let denial_proof = merkle_proof(receipts, 1).expect("ok");
    assert!(verify_merkle_proof(&root, &receipts[1], &denial_proof, 1));

    // Verify proof for the remediation receipt (index 2)
    let remediation_proof = merkle_proof(receipts, 2).expect("ok");
    assert!(verify_merkle_proof(
        &root,
        &receipts[2],
        &remediation_proof,
        2
    ));

    // Verify proof for the final close receipt (last index)
    let close_idx = receipts.len() - 1;
    let close_proof = merkle_proof(receipts, close_idx).expect("ok");
    assert!(verify_merkle_proof(
        &root,
        &receipts[close_idx],
        &close_proof,
        close_idx
    ));
}

// ---------------------------------------------------------------------------
// 3. Hybrid (Ed25519 + ML-DSA-65) signed custody chain
// ---------------------------------------------------------------------------

#[test]
fn hybrid_crypto_custody_chain() {
    let (classical_pk, classical_sk) = generate_keypair();
    let (pq_pk, pq_sk) = generate_pq_keypair();

    // Sign each transition receipt with hybrid crypto
    let actor = Did::new("did:exo:hybrid-actor").expect("valid");
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    let states = [
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
    ];

    let mut hybrid_sigs = Vec::new();
    for &s in &states {
        let t = tx.transition(s, &actor, &mut clock).expect("ok");
        let sig =
            sign_hybrid(t.receipt_hash.as_bytes(), &classical_sk, &pq_sk).expect("hybrid sign");
        assert!(
            verify_hybrid(t.receipt_hash.as_bytes(), &sig, &classical_pk, &pq_pk),
            "hybrid verification must pass for each receipt"
        );
        hybrid_sigs.push(sig);
    }

    tx.verify_receipt_chain().expect("receipt chain valid");

    // Verify tamper detection: corrupt one hybrid signature's PQ component
    let tampered = match &hybrid_sigs[1] {
        Signature::Hybrid { classical, pq } => {
            let mut bad_pq = pq.clone();
            bad_pq[0] ^= 0xff;
            Signature::Hybrid {
                classical: *classical,
                pq: bad_pq,
            }
        }
        _ => panic!("expected Hybrid"),
    };
    assert!(
        !verify_hybrid(
            tx.receipt_chain()[1].as_bytes(),
            &tampered,
            &classical_pk,
            &pq_pk
        ),
        "tampered PQ component must be detected"
    );
}

// ---------------------------------------------------------------------------
// 4. PQ-only custody chain (post-quantum standalone)
// ---------------------------------------------------------------------------

#[test]
fn pq_only_custody_chain() {
    let pq_kp = PqKeyPair::generate();
    let actor = Did::new("did:exo:pq-actor").expect("valid");
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    for &s in &[
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
        BctsState::Deliberated,
    ] {
        let t = tx.transition(s, &actor, &mut clock).expect("ok");
        let sig = pq_kp.sign(t.receipt_hash.as_bytes()).expect("pq sign");
        assert!(
            pq_kp.verify(t.receipt_hash.as_bytes(), &sig),
            "PQ verification must pass"
        );
    }
    tx.verify_receipt_chain().expect("receipt chain valid");
}

// ---------------------------------------------------------------------------
// 5. Escalation path: Submitted → Escalated (valid transition)
// ---------------------------------------------------------------------------

#[test]
fn escalation_path_proof() {
    let actor = Did::new("did:exo:escalation-actor").expect("valid");
    let mut clock = HybridClock::new();
    let kp = KeyPair::generate();
    let mut tx = Transaction::new(correlation_id!());

    // Submit → IdentityResolved → ConsentValidated → Deliberated → Escalated
    tx.transition(BctsState::Submitted, &actor, &mut clock)
        .expect("ok");
    tx.transition(BctsState::IdentityResolved, &actor, &mut clock)
        .expect("ok");
    tx.transition(BctsState::ConsentValidated, &actor, &mut clock)
        .expect("ok");
    tx.transition(BctsState::Deliberated, &actor, &mut clock)
        .expect("ok");
    let t_esc = tx
        .transition(BctsState::Escalated, &actor, &mut clock)
        .expect("escalation ok");

    let event = create_signed_event(
        correlation_id!(),
        t_esc.timestamp,
        EventType::TransactionStateChanged,
        t_esc.receipt_hash.as_bytes().to_vec(),
        actor.clone(),
        kp.secret_key(),
    )
    .expect("sign event");
    assert!(verify_event(&event, kp.public_key()));
    tx.verify_receipt_chain().expect("chain valid");
    assert_eq!(tx.state(), BctsState::Escalated);
}

// ---------------------------------------------------------------------------
// 6. Receipt chain tamper detection
// ---------------------------------------------------------------------------

#[test]
fn receipt_chain_tamper_detection() {
    let actor = Did::new("did:exo:tamper-actor").expect("valid");
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    for &s in &[
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
    ] {
        tx.transition(s, &actor, &mut clock).expect("ok");
    }

    // Chain should be valid before tampering
    tx.verify_receipt_chain().expect("chain valid pre-tamper");

    // Build Merkle tree
    let receipts = tx.receipt_chain();
    let root = merkle_root(receipts);

    // A tampered hash should fail Merkle verification
    let mut tampered_hash = receipts[1];
    tampered_hash.0[0] ^= 0xff;
    let proof = merkle_proof(receipts, 1).expect("ok");
    assert!(
        !verify_merkle_proof(&root, &tampered_hash, &proof, 1),
        "tampered receipt must fail Merkle verification"
    );
}

// ---------------------------------------------------------------------------
// 7. Concurrent transactions share HLC ordering
// ---------------------------------------------------------------------------

#[test]
fn concurrent_transactions_hlc_ordering() {
    let mut clock = HybridClock::new();
    let actors = GovernanceActors::new();

    let mut tx_a = Transaction::new(correlation_id!());
    let mut tx_b = Transaction::new(correlation_id!());

    let t_a1 = tx_a
        .transition(BctsState::Submitted, &actors.proposer.0, &mut clock)
        .expect("ok");
    let t_b1 = tx_b
        .transition(BctsState::Submitted, &actors.reviewer1.0, &mut clock)
        .expect("ok");
    let t_a2 = tx_a
        .transition(BctsState::IdentityResolved, &actors.reviewer2.0, &mut clock)
        .expect("ok");

    // Strict HLC ordering: t_a1 < t_b1 < t_a2
    assert!(HybridClock::is_before(&t_a1.timestamp, &t_b1.timestamp));
    assert!(HybridClock::is_before(&t_b1.timestamp, &t_a2.timestamp));
}

// ---------------------------------------------------------------------------
// 8. Structured hash determinism with governance metadata
// ---------------------------------------------------------------------------

#[test]
fn governance_metadata_hash_determinism() {
    let mut map1 = DeterministicMap::new();
    map1.insert("decision_id".to_string(), "dec-001");
    map1.insert("actor".to_string(), "did:exo:alice");
    map1.insert("action".to_string(), "approve");
    map1.insert("timestamp_ms".to_string(), "1711929600000");

    let mut map2 = DeterministicMap::new();
    // Same keys/values but different insertion order
    map2.insert("timestamp_ms".to_string(), "1711929600000");
    map2.insert("action".to_string(), "approve");
    map2.insert("decision_id".to_string(), "dec-001");
    map2.insert("actor".to_string(), "did:exo:alice");

    let h1 = hash_structured(&map1).expect("ok");
    let h2 = hash_structured(&map2).expect("ok");
    assert_eq!(
        h1, h2,
        "deterministic map hash must be insertion-order independent"
    );
}

// ---------------------------------------------------------------------------
// 9. Signature variant exhaustiveness
// ---------------------------------------------------------------------------

#[test]
fn signature_variant_coverage() {
    let (pk, sk) = generate_keypair();
    let (pq_pk, pq_sk) = generate_pq_keypair();
    let msg = b"variant test";

    // Ed25519
    let ed_sig = sign(msg, &sk);
    assert!(verify(msg, &ed_sig, &pk));

    // PostQuantum
    let pq_sig = sign_pq(msg, &pq_sk).expect("pq sign");
    assert!(verify_pq(msg, &pq_sig, &pq_pk));

    // Hybrid
    let hybrid_sig = sign_hybrid(msg, &sk, &pq_sk).expect("hybrid sign");
    assert!(verify_hybrid(msg, &hybrid_sig, &pk, &pq_pk));

    // Empty — always rejected
    assert!(!verify(msg, &Signature::Empty, &pk));
    assert!(!verify_pq(msg, &Signature::Empty, &pq_pk));
    assert!(!verify_hybrid(msg, &Signature::Empty, &pk, &pq_pk));

    // Cross-variant rejection
    assert!(
        !verify(msg, &pq_sig, &pk),
        "PQ sig must be rejected by Ed25519 verify"
    );
    assert!(
        !verify_pq(msg, &ed_sig, &pq_pk),
        "Ed25519 sig must be rejected by PQ verify"
    );
}

// ---------------------------------------------------------------------------
// 10. PqKeyPair accessor coverage
// ---------------------------------------------------------------------------

#[test]
fn pq_keypair_accessors_and_debug() {
    let kp = PqKeyPair::generate();
    let pk = kp.public_key();
    assert_eq!(pk.as_bytes().len(), 1952);

    // Debug must redact secret
    let dbg = format!("{kp:?}");
    assert!(dbg.contains("PqKeyPair"));
    assert!(dbg.contains("***"));
}

// ---------------------------------------------------------------------------
// 11. Invalid transitions are rejected (negative proof)
// ---------------------------------------------------------------------------

#[test]
fn invalid_transition_rejected() {
    let actor = Did::new("did:exo:invalid-actor").expect("valid");
    let mut clock = HybridClock::new();
    let mut tx = Transaction::new(correlation_id!());

    // Draft → Approved (skipping required states) should fail
    let result = tx.transition(BctsState::Approved, &actor, &mut clock);
    assert!(
        result.is_err(),
        "skipping from Draft to Approved must be rejected"
    );

    // Draft → Submitted is valid
    tx.transition(BctsState::Submitted, &actor, &mut clock)
        .expect("ok");

    // Submitted → Closed (skipping) should fail
    let result2 = tx.transition(BctsState::Closed, &actor, &mut clock);
    assert!(
        result2.is_err(),
        "skipping from Submitted to Closed must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 12. Merkle proof boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn merkle_proof_single_leaf() {
    let hash = canonical_hash(b"single leaf");
    let leaves = vec![hash];
    let root = merkle_root(&leaves);
    assert_ne!(root, hash);
    let proof = merkle_proof(&leaves, 0).expect("ok");
    assert!(proof.is_empty());
    assert_eq!(merkle_root_from_proof(&hash, &proof, 0), root);
    assert!(verify_merkle_proof(&root, &hash, &proof, 0));
}

#[test]
fn merkle_proof_two_leaves() {
    let h0 = canonical_hash(b"leaf-0");
    let h1 = canonical_hash(b"leaf-1");
    let leaves = vec![h0, h1];
    let root = merkle_root(&leaves);
    assert_ne!(root, h0);
    assert_ne!(root, h1);

    for i in 0..2 {
        let proof = merkle_proof(&leaves, i).expect("ok");
        assert!(verify_merkle_proof(&root, &leaves[i], &proof, i));
    }
}

#[test]
fn merkle_proof_out_of_bounds() {
    let leaves = vec![canonical_hash(b"a")];
    let result = merkle_proof(&leaves, 5);
    assert!(result.is_err(), "out-of-bounds index must return error");
}

// ---------------------------------------------------------------------------
// 13. Version monotonicity and equality
// ---------------------------------------------------------------------------

#[test]
fn version_properties() {
    let v0 = Version::ZERO;
    let v1 = v0.next();
    let v2 = v1.next();
    let v3 = v2.next();

    assert_eq!(v0.value(), 0);
    assert_eq!(v3.value(), 3);
    assert!(v0 < v1);
    assert!(v1 < v2);
    assert!(v2 < v3);

    // Equality
    let v0b = Version::ZERO;
    assert_eq!(v0, v0b);
}

// ---------------------------------------------------------------------------
// 14. Timestamp ordering and construction
// ---------------------------------------------------------------------------

#[test]
fn timestamp_ordering_and_fields() {
    let t1 = Timestamp::new(1000, 0);
    let t2 = Timestamp::new(1000, 1);
    let t3 = Timestamp::new(1001, 0);

    assert!(t1 < t2, "same physical, higher logical should be greater");
    assert!(
        t2 < t3,
        "higher physical should be greater regardless of logical"
    );

    // Access fields
    assert_eq!(t1.physical_ms, 1000);
    assert_eq!(t1.logical, 0);
}

// ---------------------------------------------------------------------------
// 15. Hash256 properties
// ---------------------------------------------------------------------------

#[test]
fn hash256_zero_and_equality() {
    let zero = Hash256::ZERO;
    assert_eq!(zero.0, [0u8; 32]);

    let h1 = Hash256::from_bytes([1u8; 32]);
    let h2 = Hash256::from_bytes([1u8; 32]);
    assert_eq!(h1, h2);
    assert_ne!(h1, zero);
}

// ---------------------------------------------------------------------------
// 16. DID validation
// ---------------------------------------------------------------------------

#[test]
fn did_validation() {
    // Valid DID
    let d = Did::new("did:exo:test");
    assert!(d.is_ok());

    // Empty DID should fail
    let empty = Did::new("");
    assert!(empty.is_err());

    // DID as_str
    let d = Did::new("did:exo:hello").expect("valid");
    assert_eq!(d.as_str(), "did:exo:hello");
}

// ---------------------------------------------------------------------------
// 17. SignerType coverage
// ---------------------------------------------------------------------------

#[test]
fn signer_type_variants() {
    let human = SignerType::Human;
    let ai = SignerType::Ai {
        delegation_id: Hash256::from_bytes([42u8; 32]),
    };

    assert_ne!(human, ai);
    assert_eq!(human, SignerType::Human);
    assert!(matches!(ai, SignerType::Ai { .. }));
}

// ---------------------------------------------------------------------------
// 18. Canonical hash consistency
// ---------------------------------------------------------------------------

#[test]
fn canonical_hash_consistency() {
    let data = b"constitutional governance";
    let h1 = canonical_hash(data);
    let h2 = canonical_hash(data);
    assert_eq!(h1, h2, "same input must produce same hash");

    let h3 = canonical_hash(b"different data");
    assert_ne!(h1, h3, "different input must produce different hash");
}

// ---------------------------------------------------------------------------
// 19. Multiple Merkle trees are independent
// ---------------------------------------------------------------------------

#[test]
fn independent_merkle_trees() {
    let leaves_a: Vec<Hash256> = (0..4u8).map(|i| canonical_hash(&[i])).collect();
    let leaves_b: Vec<Hash256> = (10..14u8).map(|i| canonical_hash(&[i])).collect();

    let root_a = merkle_root(&leaves_a);
    let root_b = merkle_root(&leaves_b);
    assert_ne!(root_a, root_b);

    // Proof from tree A should not verify against tree B's root
    let proof_a0 = merkle_proof(&leaves_a, 0).expect("ok");
    assert!(!verify_merkle_proof(&root_b, &leaves_a[0], &proof_a0, 0));
}

// ---------------------------------------------------------------------------
// 20. BailmentTransaction trait coverage
// ---------------------------------------------------------------------------

#[test]
fn bailment_transaction_lifecycle() {
    let actor = Did::new("did:exo:bailment-actor").expect("valid");
    let mut clock = HybridClock::new();

    let mut tx = Transaction::new(correlation_id!());
    assert_eq!(tx.state(), BctsState::Draft);
    assert!(tx.receipt_chain().is_empty());

    tx.transition(BctsState::Submitted, &actor, &mut clock)
        .expect("ok");
    assert_eq!(tx.state(), BctsState::Submitted);
    assert_eq!(tx.receipt_chain().len(), 1);

    tx.verify_receipt_chain().expect("chain valid");
}
