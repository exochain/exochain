//! Integration tests: decision.forum governance layer → Kernel::adjudicate
#![allow(clippy::expect_used)]
//!
//! These tests verify that the judicial branch (`exo-gatekeeper`) correctly
//! adjudicates actions derived from governance decisions produced by the
//! `decision-forum` layer, exercising the full cross-crate integration path.
//!
//! ## Coverage
//!
//! | Test | Invariant(s) exercised | Expected verdict |
//! |------|------------------------|------------------|
//! | `strategic_decision_approved_permitted` | All 8 (passing) | Permitted |
//! | `missing_consent_denied` | CP-2 ConsentRequired | Denied |
//! | `quorum_not_met_escalates` | CP-7 QuorumLegitimate | Escalated |
//! | `full_lifecycle_adjudicated_at_each_transition` | All 8 (passing) | Permitted × 8 |
//! | `separation_of_powers_multi_branch_denied` | CP-1 SeparationOfPowers | Denied |
//! | `self_grant_denied` | CP-3 NoSelfGrant | Denied |
//! | `human_override_removed_denied` | CP-4 HumanOverride | Denied |
//! | `kernel_modification_denied` | CP-5 KernelImmutability | Denied |
//! | `authority_chain_empty_escalates` | CP-6 AuthorityChainValid | Escalated |
//! | `provenance_missing_denied` | CP-8 ProvenanceVerifiable | Denied |
//! | `governance_decision_denied_state_correlates_with_verdict` | CP-2 (no bailment) | Denied |
//! | `all_eight_invariants_exercised` | CP-1 through CP-8 | various |

use std::sync::atomic::{AtomicU64, Ordering};

use decision_forum::{
    decision_object::{
        ActorKind, AuthorityLink as ForumAuthorityLink, DecisionClass, DecisionObject,
        DecisionObjectInput, EvidenceItem,
    },
    tnc_enforcer::{TncContext, enforce_all as enforce_tnc_all},
};
use exo_core::{
    bcts::BctsState,
    hlc::HybridClock,
    types::{Did, Hash256},
};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{
        AuthorityChain, AuthorityLink as GkAuthorityLink, BailmentState, ConsentRecord,
        GovernmentBranch, Permission, PermissionSet, Provenance, QuorumEvidence, QuorumVote, Role,
    },
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared constants & helpers
// ---------------------------------------------------------------------------

/// The canonical constitution bytes used across all tests.
const CONSTITUTION: &[u8] = b"EXOCHAIN Constitutional Corpus v1.0 - in trust we govern";

fn test_clock() -> HybridClock {
    let counter = AtomicU64::new(1_000);
    HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
}

fn did(s: &str) -> Did {
    Did::new(s).expect("valid DID")
}

fn signed_authority_link(grantee: &Did) -> GkAuthorityLink {
    let (pk, sk) = exo_core::crypto::generate_keypair();
    let grantor = did("did:exo:governance-root");
    let permissions = PermissionSet::new(vec![Permission::new("enact:decision")]);

    let mut payload = Vec::new();
    payload.extend_from_slice(grantor.as_str().as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(grantee.as_str().as_bytes());
    payload.push(0x00);
    for permission in &permissions.permissions {
        payload.extend_from_slice(permission.0.as_bytes());
        payload.push(0x00);
    }
    let message = Hash256::digest(&payload);
    let signature = exo_core::crypto::sign(message.as_bytes(), &sk);

    GkAuthorityLink {
        grantor,
        grantee: grantee.clone(),
        permissions,
        signature: signature.to_bytes().to_vec(),
        grantor_public_key: Some(pk.as_bytes().to_vec()),
    }
}

fn signed_provenance(actor: &Did) -> Provenance {
    let (pk, sk) = exo_core::crypto::generate_keypair();
    let timestamp = "2026-03-30T00:00:00Z".to_owned();
    let action_hash = vec![0x01, 0x02, 0x03];

    let mut payload = Vec::new();
    payload.extend_from_slice(actor.as_str().as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&action_hash);
    payload.push(0x00);
    payload.extend_from_slice(timestamp.as_bytes());
    let message = Hash256::digest(&payload);
    let signature = exo_core::crypto::sign(message.as_bytes(), &sk);

    Provenance {
        actor: actor.clone(),
        timestamp,
        action_hash,
        signature: signature.to_bytes().to_vec(),
        public_key: Some(pk.as_bytes().to_vec()),
        voice_kind: None,
        independence: None,
        review_order: None,
    }
}

fn test_kernel() -> Kernel {
    Kernel::new(CONSTITUTION, InvariantSet::all())
}

/// Build a `DecisionObject` of the given class, advanced through the full
/// approved BCTS lifecycle. The decision has a human authority chain and
/// supporting evidence attached.
fn make_approved_decision(class: DecisionClass, clock: &mut HybridClock) -> DecisionObject {
    let actor = did("did:exo:governance-author");
    let const_hash = Hash256::digest(CONSTITUTION);

    let mut d = DecisionObject::new(DecisionObjectInput {
        id: Uuid::from_u128(500),
        title: "Integration Test Decision".into(),
        class,
        constitutional_hash: const_hash,
        created_at: clock.now(),
    })
    .expect("valid decision");

    // Attach a human authority link so TNC-01 is satisfied.
    d.add_authority_link(ForumAuthorityLink {
        actor_did: actor.clone(),
        actor_kind: ActorKind::Human,
        delegation_hash: Hash256::digest(b"root-delegation-v1"),
        timestamp: clock.now(),
    })
    .expect("add authority link");

    // Attach evidence so TNC-10 is satisfied.
    d.add_evidence(EvidenceItem {
        hash: Hash256::digest(b"impact-assessment-v1"),
        description: "Strategic impact assessment".to_string(),
        attached_at: clock.now(),
    })
    .expect("add evidence");

    // Advance through the full BCTS happy-path lifecycle.
    for state in [
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
        BctsState::Deliberated,
        BctsState::Verified,
        BctsState::Governed,
        BctsState::Approved,
    ] {
        let ts = clock.now();
        d.transition_at(state, &actor, ts)
            .expect("lifecycle transition");
    }

    d
}

/// Build a valid `AdjudicationContext` for the given actor.
///
/// All 8 constitutional invariants pass with this context:
/// - CP-1: single judicial role
/// - CP-2: active bailment + active consent record
/// - CP-3: `is_self_grant` = false (set on ActionRequest)
/// - CP-4: `human_override_preserved` = true
/// - CP-5: `modifies_kernel` = false (set on ActionRequest)
/// - CP-6: valid single-link authority chain ending at actor
/// - CP-7: `quorum_evidence` = None (invariant skips when None)
/// - CP-8: provenance present, actor matches, Ed25519 signature verifies
fn valid_adj_context(actor: &Did) -> AdjudicationContext {
    AdjudicationContext {
        actor_roles: vec![Role {
            name: "governance-judge".into(),
            branch: GovernmentBranch::Judicial,
        }],
        authority_chain: AuthorityChain {
            links: vec![signed_authority_link(actor)],
        },
        consent_records: vec![ConsentRecord {
            subject: did("did:exo:bailor"),
            granted_to: actor.clone(),
            scope: "governance:decision".into(),
            active: true,
        }],
        bailment_state: BailmentState::Active {
            bailor: did("did:exo:bailor"),
            bailee: actor.clone(),
            scope: "governance:decision".into(),
        },
        human_override_preserved: true,
        actor_permissions: PermissionSet::new(vec![Permission::new("enact:decision")]),
        provenance: Some(signed_provenance(actor)),
        quorum_evidence: None,
        active_challenge_reason: None,
    }
}

/// Build the `ActionRequest` for enacting a governance decision.
fn enact_action(actor: &Did) -> ActionRequest {
    ActionRequest {
        actor: actor.clone(),
        action: "enact_governance_decision".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("enact:decision")]),
        is_self_grant: false,
        modifies_kernel: false,
    }
}

// ---------------------------------------------------------------------------
// Happy-path test: strategic decision approved → Permitted
// ---------------------------------------------------------------------------

/// Full integration happy path.
///
/// A `DecisionObject` of class `Strategic` advances through the complete BCTS
/// lifecycle in the `decision-forum` layer, then the resulting governance state
/// is translated into a kernel `AdjudicationContext`. The kernel must return
/// `Verdict::Permitted`, confirming that all 8 constitutional invariants pass.
#[test]
fn strategic_decision_approved_permitted() {
    let mut clock = test_clock();
    let kernel = test_kernel();
    let actor = did("did:exo:governance-author");

    // Build a fully approved Strategic decision in the decision.forum layer.
    let decision = make_approved_decision(DecisionClass::Strategic, &mut clock);
    assert_eq!(
        decision.state,
        BctsState::Approved,
        "decision must be Approved"
    );

    // Verify the TNC controls on the forum side also pass.
    let tnc_ctx = TncContext {
        decision: &decision,
        constitutional_hash_valid: true,
        consent_verified: true,
        identity_verified: true,
        evidence_complete: true,
        quorum_met: true,
        human_gate_satisfied: true,
        authority_chain_verified: true,
        ai_ceilings_externally_verified: true,
    };
    enforce_tnc_all(&tnc_ctx).expect("TNC controls must all pass for approved decision");

    // Translate governance state → AdjudicationContext and invoke the CGR kernel.
    let context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_permitted(),
        "Approved strategic decision should yield Verdict::Permitted; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// Denial test: missing consent → Denied (CP-2 ConsentRequired)
// ---------------------------------------------------------------------------

/// Violate CP-2 (`ConsentRequired`) by removing the active bailment.
///
/// A valid decision exists in the forum layer, but the kernel context has no
/// active bailment for the enactment action. The kernel must return
/// `Verdict::Denied` with a `ConsentRequired` violation.
#[test]
fn missing_consent_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:governance-author");

    let mut context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    // Remove active bailment — violates CP-2.
    context.bailment_state = BailmentState::None;

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "No active bailment must yield Verdict::Denied; got {verdict:?}"
    );

    if let Verdict::Denied { violations } = &verdict {
        let has_consent = violations.iter().any(|v| {
            v.invariant == exo_gatekeeper::invariants::ConstitutionalInvariant::ConsentRequired
        });
        assert!(
            has_consent,
            "Expected ConsentRequired violation; got {violations:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Escalation test: quorum not met → Escalated (CP-7 QuorumLegitimate)
// ---------------------------------------------------------------------------

/// Violate CP-7 (`QuorumLegitimate`) by providing failing quorum evidence.
///
/// The quorum evidence has threshold=3 but only 1 approval, so the invariant
/// fires. Because it is the only violation and it is a `QuorumLegitimate`
/// violation, the kernel escalates rather than denying.
#[test]
fn quorum_not_met_escalates() {
    let kernel = test_kernel();
    let actor = did("did:exo:governance-author");

    let mut context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    // Provide quorum evidence that does not meet the threshold.
    context.quorum_evidence = Some(QuorumEvidence {
        threshold: 3,
        votes: vec![
            QuorumVote {
                voter: did("did:exo:voter-a"),
                approved: true,
                signature: vec![1],
                provenance: None,
            },
            QuorumVote {
                voter: did("did:exo:voter-b"),
                approved: false,
                signature: vec![2],
                provenance: None,
            },
            // Only 1 approval against threshold of 3.
        ],
    });

    match kernel.adjudicate(&action, &context) {
        Verdict::Escalated { reason } => {
            assert!(
                reason.contains("Quorum"),
                "Escalation reason must mention Quorum; got: {reason}"
            );
        }
        other => panic!("Expected Verdict::Escalated for failed quorum; got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Full lifecycle test: adjudicated at each BCTS transition
// ---------------------------------------------------------------------------

/// Advance a `DecisionObject` through every non-terminal BCTS state and
/// invoke `Kernel::adjudicate` at each checkpoint.
///
/// The governance action is independent of the decision state — the kernel
/// evaluates the `AdjudicationContext` constructed from the action's metadata,
/// not the decision's current BCTS state. All verdicts must be `Permitted`.
#[test]
fn full_lifecycle_adjudicated_at_each_transition() {
    let mut clock = test_clock();
    let kernel = test_kernel();
    let actor = did("did:exo:lifecycle-actor");
    let const_hash = Hash256::digest(CONSTITUTION);

    let mut d = DecisionObject::new(DecisionObjectInput {
        id: Uuid::from_u128(501),
        title: "Lifecycle Test".into(),
        class: DecisionClass::Operational,
        constitutional_hash: const_hash,
        created_at: clock.now(),
    })
    .expect("valid decision");
    d.add_authority_link(ForumAuthorityLink {
        actor_did: actor.clone(),
        actor_kind: ActorKind::Human,
        delegation_hash: Hash256::digest(b"lifecycle-delegation"),
        timestamp: clock.now(),
    })
    .expect("add authority link");

    let context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    // Check at initial Draft state.
    assert_eq!(d.state, BctsState::Draft);
    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_permitted(),
        "Expected Permitted at Draft; got {verdict:?}"
    );

    // Advance through each state and adjudicate at every checkpoint.
    let transitions = [
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
        BctsState::Deliberated,
        BctsState::Verified,
        BctsState::Governed,
        BctsState::Approved,
    ];

    for state in transitions {
        let ts = clock.now();
        d.transition_at(state, &actor, ts)
            .expect("lifecycle transition");
        let verdict = kernel.adjudicate(&action, &context);
        assert!(
            verdict.is_permitted(),
            "Expected Permitted at {state:?}; got {verdict:?}"
        );
    }

    assert_eq!(d.state, BctsState::Approved);
}

// ---------------------------------------------------------------------------
// CP-1: SeparationOfPowers
// ---------------------------------------------------------------------------

/// Violate CP-1 (`SeparationOfPowers`) by assigning the actor roles in two
/// branches of government. The kernel must deny the action.
#[test]
fn separation_of_powers_multi_branch_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:multi-branch-actor");

    let mut context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    // Assign both Legislative and Judicial roles — violates CP-1.
    context.actor_roles = vec![
        Role {
            name: "legislator".into(),
            branch: GovernmentBranch::Legislative,
        },
        Role {
            name: "judge".into(),
            branch: GovernmentBranch::Judicial,
        },
    ];

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Multi-branch actor must yield Verdict::Denied; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// CP-3: NoSelfGrant
// ---------------------------------------------------------------------------

/// Violate CP-3 (`NoSelfGrant`) by marking the action as a self-grant.
#[test]
fn self_grant_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:self-granting-actor");
    let context = valid_adj_context(&actor);

    let mut action = enact_action(&actor);
    action.is_self_grant = true; // CP-3 violation.

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Self-grant action must yield Verdict::Denied; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// CP-4: HumanOverride
// ---------------------------------------------------------------------------

/// Violate CP-4 (`HumanOverride`) by setting `human_override_preserved = false`.
#[test]
fn human_override_removed_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:autonomous-actor");

    let mut context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    context.human_override_preserved = false; // CP-4 violation.

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Removed human override must yield Verdict::Denied; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// CP-5: KernelImmutability
// ---------------------------------------------------------------------------

/// Violate CP-5 (`KernelImmutability`) by marking the action as a kernel modification.
#[test]
fn kernel_modification_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:kernel-modifier");
    let context = valid_adj_context(&actor);

    let mut action = enact_action(&actor);
    action.modifies_kernel = true; // CP-5 violation.

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Kernel modification must yield Verdict::Denied; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// CP-6: AuthorityChainValid (escalation path)
// ---------------------------------------------------------------------------

/// Violate CP-6 (`AuthorityChainValid`) by providing an empty authority chain.
///
/// An empty chain triggers a single `AuthorityChainValid` violation which, per
/// the kernel escalation logic, produces `Verdict::Escalated`.
#[test]
fn authority_chain_empty_escalates() {
    let kernel = test_kernel();
    let actor = did("did:exo:no-authority");
    let action = enact_action(&actor);

    let mut context = valid_adj_context(&actor);
    context.authority_chain = AuthorityChain { links: vec![] }; // CP-6 violation.

    match kernel.adjudicate(&action, &context) {
        Verdict::Escalated { .. } => { /* expected */ }
        other => panic!("Expected Verdict::Escalated for empty authority chain; got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// CP-8: ProvenanceVerifiable
// ---------------------------------------------------------------------------

/// Violate CP-8 (`ProvenanceVerifiable`) by omitting provenance entirely.
#[test]
fn provenance_missing_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:unprovenanced-actor");

    let mut context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    context.provenance = None; // CP-8 violation.

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Missing provenance must yield Verdict::Denied; got {verdict:?}"
    );
}

/// Violate CP-8 by providing provenance with an actor mismatch.
#[test]
fn provenance_actor_mismatch_denied() {
    let kernel = test_kernel();
    let actor = did("did:exo:real-actor");
    let impersonator = did("did:exo:impersonator");

    let mut context = valid_adj_context(&actor);
    let action = enact_action(&actor);

    // Provenance claims a different actor than the request actor.
    context.provenance = Some(Provenance {
        actor: impersonator.clone(),
        timestamp: "2026-03-30T00:00:00Z".into(),
        action_hash: vec![0x01],
        signature: vec![0x02],
        public_key: None,
        voice_kind: None,
        independence: None,
        review_order: None,
    });

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Provenance actor mismatch must yield Verdict::Denied; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// Cross-layer correlation test
// ---------------------------------------------------------------------------

/// Verify that a `Denied` BCTS state in the forum layer correlates with a
/// kernel denial when the corresponding governance context is invalid.
///
/// This exercises the conceptual bridge: when `decision.forum` denies a
/// decision (e.g., insufficient consent), the same governance failure should
/// cause `Kernel::adjudicate` to return `Denied` when the invalid context
/// is presented for enactment.
#[test]
fn denied_forum_decision_correlates_with_kernel_denial() {
    let mut clock = test_clock();
    let kernel = test_kernel();
    let actor = did("did:exo:governance-author");
    let const_hash = Hash256::digest(CONSTITUTION);

    // Build a decision that gets denied in the forum layer (transition to Denied).
    let mut d = DecisionObject::new(DecisionObjectInput {
        id: Uuid::from_u128(502),
        title: "Denied Decision".into(),
        class: DecisionClass::Operational,
        constitutional_hash: const_hash,
        created_at: clock.now(),
    })
    .expect("valid decision");
    d.add_authority_link(ForumAuthorityLink {
        actor_did: actor.clone(),
        actor_kind: ActorKind::Human,
        delegation_hash: Hash256::digest(b"delegation"),
        timestamp: clock.now(),
    })
    .expect("add link");
    let ts = clock.now();
    d.transition_at(BctsState::Submitted, &actor, ts)
        .expect("submit");
    let ts = clock.now();
    d.transition_at(BctsState::Denied, &actor, ts)
        .expect("deny");
    assert_eq!(d.state, BctsState::Denied);

    // The enactment context reflects the consent failure (no active bailment).
    let mut context = valid_adj_context(&actor);
    context.bailment_state = BailmentState::None; // mirrors the forum denial reason
    let action = enact_action(&actor);

    let verdict = kernel.adjudicate(&action, &context);
    assert!(
        verdict.is_denied(),
        "Denied forum decision with no consent must yield kernel Denied; got {verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// All 8 invariants — comprehensive sweep
// ---------------------------------------------------------------------------

/// Sweep all 8 invariants: each sub-test violates exactly one invariant with
/// the minimal change required, then verifies the expected verdict category.
#[test]
fn all_eight_invariants_exercised() {
    let kernel = test_kernel();

    struct Case {
        name: &'static str,
        mutate: fn(&mut ActionRequest, &mut AdjudicationContext),
        denied: bool,
        escalated: bool,
    }

    let actor = did("did:exo:sweep-actor");

    let cases: &[Case] = &[
        Case {
            name: "CP-1 SeparationOfPowers",
            mutate: |_, ctx| {
                ctx.actor_roles = vec![
                    Role {
                        name: "l".into(),
                        branch: GovernmentBranch::Legislative,
                    },
                    Role {
                        name: "e".into(),
                        branch: GovernmentBranch::Executive,
                    },
                    Role {
                        name: "j".into(),
                        branch: GovernmentBranch::Judicial,
                    },
                ];
            },
            denied: true,
            escalated: false,
        },
        Case {
            name: "CP-2 ConsentRequired",
            mutate: |_, ctx| {
                ctx.bailment_state = BailmentState::None;
            },
            denied: true,
            escalated: false,
        },
        Case {
            name: "CP-3 NoSelfGrant",
            mutate: |action, _| {
                action.is_self_grant = true;
            },
            denied: true,
            escalated: false,
        },
        Case {
            name: "CP-4 HumanOverride",
            mutate: |_, ctx| {
                ctx.human_override_preserved = false;
            },
            denied: true,
            escalated: false,
        },
        Case {
            name: "CP-5 KernelImmutability",
            mutate: |action, _| {
                action.modifies_kernel = true;
            },
            denied: true,
            escalated: false,
        },
        Case {
            name: "CP-6 AuthorityChainValid",
            mutate: |_, ctx| {
                ctx.authority_chain = AuthorityChain { links: vec![] };
            },
            denied: false,
            escalated: true,
        },
        Case {
            name: "CP-7 QuorumLegitimate",
            mutate: |_, ctx| {
                ctx.quorum_evidence = Some(QuorumEvidence {
                    threshold: 5,
                    votes: vec![QuorumVote {
                        voter: did("did:exo:single-voter"),
                        approved: true,
                        signature: vec![1],
                        provenance: None,
                    }],
                });
            },
            denied: false,
            escalated: true,
        },
        Case {
            name: "CP-8 ProvenanceVerifiable",
            mutate: |_, ctx| {
                ctx.provenance = None;
            },
            denied: true,
            escalated: false,
        },
    ];

    for case in cases {
        let mut action = enact_action(&actor);
        let mut context = valid_adj_context(&actor);
        (case.mutate)(&mut action, &mut context);

        let verdict = kernel.adjudicate(&action, &context);

        if case.denied {
            assert!(
                verdict.is_denied(),
                "{}: expected Denied, got {verdict:?}",
                case.name
            );
        } else if case.escalated {
            assert!(
                matches!(verdict, Verdict::Escalated { .. }),
                "{}: expected Escalated, got {verdict:?}",
                case.name
            );
        }
    }
}
