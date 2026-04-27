//! Integration tests for APE-58 — decision-forum gateway wiring.
//!
//! These tests exercise the `DecisionObject` + quorum domain logic that backs
//! `POST /api/v1/decisions` without requiring a live database.  They verify the
//! three acceptance criteria that must hold regardless of network/DB state:
//!
//!   1. A valid vote is accepted and the quorum check result is included in the response.
//!   2. A duplicate voter is rejected (TNC-07 voter independence).
//!   3. A terminal-state decision refuses further votes (TNC-08 immutability).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};

use decision_forum::{
    decision_object::{
        ActorKind, DecisionClass, DecisionObject, DecisionObjectInput, Vote, VoteChoice,
    },
    quorum::{QuorumCheckResult, QuorumRegistry, check_quorum, verify_quorum_precondition},
};
use exo_core::{
    bcts::BctsState,
    hlc::HybridClock,
    types::{Did, Hash256},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_clock() -> HybridClock {
    let counter = AtomicU64::new(1_000_000);
    HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
}

fn did(s: &str) -> Did {
    Did::new(s).expect("valid DID")
}

fn routine_decision(clock: &mut HybridClock) -> DecisionObject {
    DecisionObject::new(DecisionObjectInput {
        id: uuid::Uuid::from_u128(400),
        title: "Routine test decision".into(),
        class: DecisionClass::Routine,
        constitutional_hash: Hash256::digest(b"test-constitution-v1"),
        created_at: clock.now(),
    })
    .expect("valid decision")
}

fn human_approve(name: &str, clock: &mut HybridClock) -> Vote {
    Vote {
        voter_did: did(&format!("did:exo:{name}")),
        choice: VoteChoice::Approve,
        actor_kind: ActorKind::Human,
        timestamp: clock.now(),
        signature_hash: Hash256::digest(name.as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Test 1 — Vote accepted → quorum status present in response
// ---------------------------------------------------------------------------

/// A single Approve vote on a Routine decision should be accepted and the
/// post-vote quorum check should report `Met` (Routine requires min 1 vote).
#[test]
fn vote_accepted_quorum_status_met() {
    let mut clock = test_clock();
    let registry = QuorumRegistry::with_defaults();
    let mut decision = routine_decision(&mut clock);

    // Verify precondition: 1 eligible voter satisfies Routine (min 1).
    let precondition_ok =
        verify_quorum_precondition(&registry, decision.class, 1, 1).expect("precondition ok");
    assert!(
        precondition_ok,
        "precondition should pass with 1 eligible voter"
    );

    // Add the vote — must succeed.
    decision
        .add_vote(human_approve("alice", &mut clock))
        .expect("vote should be accepted");

    // Post-vote quorum check.
    match check_quorum(&registry, &decision).expect("quorum check ok") {
        QuorumCheckResult::Met {
            total_votes,
            approve_count,
            approve_pct,
        } => {
            assert_eq!(total_votes, 1);
            assert_eq!(approve_count, 1);
            assert_eq!(approve_pct, 100);
        }
        other => panic!("expected QuorumCheckResult::Met, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 2 — Duplicate voter rejected (TNC-07 voter independence)
// ---------------------------------------------------------------------------

/// Casting a second vote from the same DID must be rejected to preserve
/// voter independence (TNC-07).
#[test]
fn duplicate_voter_rejected() {
    let mut clock = test_clock();
    let mut decision = routine_decision(&mut clock);

    // First vote from alice — must succeed.
    decision
        .add_vote(human_approve("alice", &mut clock))
        .expect("first vote should be accepted");

    // Second vote from the same DID — must fail.
    let err = decision
        .add_vote(Vote {
            voter_did: did("did:exo:alice"),
            choice: VoteChoice::Reject,
            actor_kind: ActorKind::Human,
            timestamp: clock.now(),
            signature_hash: Hash256::digest(b"alice-second"),
        })
        .unwrap_err();

    assert!(
        err.to_string().contains("duplicate"),
        "error should mention 'duplicate', got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — Terminal-state decision rejects further votes (TNC-08 immutability)
// ---------------------------------------------------------------------------

/// Once a decision reaches `BctsState::Closed` (terminal), any attempt to
/// add a vote must be refused (TNC-08 decision immutability).
#[test]
fn terminal_decision_rejects_votes() {
    let mut clock = test_clock();
    let actor = did("did:exo:admin");
    let mut decision = routine_decision(&mut clock);

    // Walk the full BCTS lifecycle to reach the terminal Closed state.
    let lifecycle = [
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
    for state in lifecycle {
        let ts = clock.now();
        decision
            .transition_at(state, &actor, ts)
            .expect("transition ok");
    }

    assert!(decision.is_terminal(), "decision must be in terminal state");

    // Attempting to vote on a closed decision must fail.
    let err = decision
        .add_vote(human_approve("bob", &mut clock))
        .unwrap_err();

    assert!(
        err.to_string().contains("immutable") || err.to_string().contains("terminal"),
        "error should indicate immutability, got: {err}"
    );
}
