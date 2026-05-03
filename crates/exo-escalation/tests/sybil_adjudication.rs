//! Integration tests for the Sybil adjudication path — CR-001 §8.6.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! Exercises the full pipeline:
//!   Detection → Triage → Quarantine → Evidentiary Review →
//!   Clearance Downgrade → Reinstatement → Audit Log
//!
//! Also verifies:
//! - Quarantine pauses contested actions via the CGR Kernel (`Verdict::Escalated`)
//! - Reinstatement refuses zero-hash clearance evidence
//! - `check_completeness` returns `Complete` after all seven stages

use exo_core::{Did, Timestamp};
use exo_escalation::{
    challenge::{
        ChallengeAdmission, ContestStatus, SignedChallengeAdmission, SybilChallengeGround,
        admit_challenge, begin_review, resolve_hold, sign_challenge_admission,
    },
    completeness::{CompletenessResult, check_completeness},
    detector::{DetectionSignal, Severity, SignalType, evaluate_signals},
    escalation::{
        EscalationCaseInput, EscalationPath, SybilStage, advance_sybil_stage, escalate, reinstate,
    },
    triage::{TriageLevel, triage},
};
use exo_gatekeeper::{
    Kernel, Verdict, authority_link_signature_message,
    invariants::InvariantSet,
    kernel::{ActionRequest, AdjudicationContext},
    provenance_signature_message,
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role,
    },
};
use exo_governance::{
    audit::AuditLog,
    clearance::{ClearanceAssignment, ClearanceLevel, ClearanceRegistry},
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn did(s: &str) -> Did {
    Did::new(s).expect("valid DID")
}

fn ts(ms: u64) -> Timestamp {
    Timestamp::new(ms, 0)
}

fn uuid(byte: u8) -> uuid::Uuid {
    uuid::Uuid::from_bytes([byte; 16])
}

fn keypair(seed: u8) -> exo_core::crypto::KeyPair {
    exo_core::crypto::KeyPair::from_secret_bytes([seed; 32]).expect("valid keypair")
}

fn escalation_input(
    id_marker: u8,
    signal: DetectionSignal,
    path: EscalationPath,
    created_ms: u64,
) -> EscalationCaseInput {
    EscalationCaseInput {
        id: uuid(id_marker),
        created: ts(created_ms),
        signal,
        path,
    }
}

fn signed_challenge(
    hold_marker: u8,
    action_id: [u8; 32],
    ground: SybilChallengeGround,
    admitted_at: Timestamp,
) -> SignedChallengeAdmission {
    let keypair = keypair(7);
    sign_challenge_admission(
        ChallengeAdmission {
            hold_id: uuid(hold_marker),
            action_id,
            ground,
            admitted_at,
            admitted_by: did("did:exo:reviewer"),
            admitter_public_key: *keypair.public_key(),
            evidence_hash: [0xEEu8; 32],
            authority_chain_hash: [0xACu8; 32],
        },
        keypair.secret_key(),
    )
    .expect("valid challenge admission")
}

fn signed_authority_link(grantee: &Did) -> AuthorityLink {
    let keypair = keypair(11);
    let grantor = did("did:exo:root");
    let permissions = PermissionSet::new(vec![Permission::new("read")]);

    let mut link = AuthorityLink {
        grantor,
        grantee: grantee.clone(),
        permissions,
        signature: Vec::new(),
        grantor_public_key: Some(keypair.public_key().as_bytes().to_vec()),
    };
    let message = authority_link_signature_message(&link).expect("canonical link payload");
    let signature = exo_core::crypto::sign(message.as_bytes(), keypair.secret_key());
    link.signature = signature.to_bytes().to_vec();
    link
}

fn signed_provenance(actor: &Did) -> Provenance {
    let keypair = keypair(12);
    let timestamp = "2026-03-30T00:00:00Z".to_owned();
    let action_hash = vec![0xAA, 0xBB, 0xCC];

    let mut provenance = Provenance {
        actor: actor.clone(),
        timestamp,
        action_hash,
        signature: Vec::new(),
        public_key: Some(keypair.public_key().as_bytes().to_vec()),
        voice_kind: None,
        independence: None,
        review_order: None,
    };
    let message = provenance_signature_message(&provenance).expect("canonical provenance payload");
    let signature = exo_core::crypto::sign(message.as_bytes(), keypair.secret_key());
    provenance.signature = signature.to_bytes().to_vec();
    provenance
}

/// Build a fully valid `AdjudicationContext`.  Pass `Some(reason)` to inject
/// an active Sybil challenge hold so the kernel returns `Verdict::Escalated`.
fn valid_kernel_context(actor: &Did, challenge_reason: Option<String>) -> AdjudicationContext {
    AdjudicationContext {
        actor_roles: vec![Role {
            name: "reviewer".into(),
            branch: GovernmentBranch::Judicial,
        }],
        authority_chain: AuthorityChain {
            links: vec![signed_authority_link(actor)],
        },
        consent_records: vec![ConsentRecord {
            subject: did("did:exo:bailor"),
            granted_to: actor.clone(),
            scope: "data:governance".into(),
            active: true,
        }],
        bailment_state: BailmentState::Active {
            bailor: did("did:exo:bailor"),
            bailee: actor.clone(),
            scope: "data:governance".into(),
        },
        human_override_preserved: true,
        actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
        provenance: Some(signed_provenance(actor)),
        quorum_evidence: None,
        active_challenge_reason: challenge_reason,
    }
}

// ---------------------------------------------------------------------------
// WO-006 §1 — Full detection-to-reinstatement pipeline
// ---------------------------------------------------------------------------

/// End-to-end Sybil adjudication: all seven stages, clearance downgrade via
/// the governance registry, and completeness verified at the end.
#[test]
fn full_detection_to_reinstatement_flow() {
    let actor = did("did:exo:suspect-actor");

    // ── Stage 1: Detection ────────────────────────────────────────────────────
    let signal = DetectionSignal {
        source: "peer-reputation-system".into(),
        signal_type: SignalType::SybilSuspicion,
        confidence: 75,
        evidence_hash: [0xABu8; 32],
        timestamp: ts(1_000),
    };
    let assessment = evaluate_signals(std::slice::from_ref(&signal));
    assert_eq!(assessment.overall_severity, Severity::High);

    // ── Stage 2: Triage ───────────────────────────────────────────────────────
    let decision = triage(&assessment);
    assert_eq!(decision.level, TriageLevel::ManualRequired);
    assert_eq!(
        decision.escalation_path.as_ref().map(|p| p.name.as_str()),
        Some("sybil_adjudication"),
    );

    // ── Open escalation case (Detection stage logged) ─────────────────────────
    let mut case = escalate(escalation_input(
        1,
        signal.clone(),
        EscalationPath::SybilAdjudication,
        1_050,
    ))
    .unwrap();
    assert!(case.stages_completed.contains(&"Detection".to_string()));

    // ── Stage 2 (case): Triage ────────────────────────────────────────────────
    advance_sybil_stage(&mut case, SybilStage::Triage).unwrap();

    // ── Stage 3: Quarantine — admit challenge hold ────────────────────────────
    let action_id = [0x01u8; 32];
    let mut hold = admit_challenge(signed_challenge(
        2,
        action_id,
        SybilChallengeGround::ConcealedCommonControl,
        ts(1_100),
    ))
    .unwrap();
    assert_eq!(hold.status, ContestStatus::PauseEligible);
    advance_sybil_stage(&mut case, SybilStage::Quarantine).unwrap();

    // ── Stage 4: Evidentiary review ───────────────────────────────────────────
    begin_review(&mut hold, ts(1_200)).unwrap();
    assert_eq!(hold.status, ContestStatus::UnderReview);
    let evidence_hash = [0xEEu8; 32];
    case.evidence.push(evidence_hash);
    advance_sybil_stage(&mut case, SybilStage::EvidentaryReview).unwrap();

    // ── Stage 5: Clearance downgrade via exo-governance registry ─────────────
    let clearance_admin = did("did:exo:clearance-admin");
    let mut clearance_entries = std::collections::BTreeMap::new();
    clearance_entries.insert(clearance_admin.clone(), ClearanceLevel::Governor);
    clearance_entries.insert(actor.clone(), ClearanceLevel::Governor);
    let mut registry = ClearanceRegistry::from_verified_snapshot(clearance_entries);
    // Sybil evidence causes downgrade to ReadOnly
    let mut clearance_audit_log = AuditLog::new();
    registry
        .assign_level(
            &mut clearance_audit_log,
            ClearanceAssignment {
                entry_id: uuid(0xCE),
                timestamp: ts(1_300),
                assigner: clearance_admin,
                subject: actor.clone(),
                level: ClearanceLevel::ReadOnly,
            },
        )
        .unwrap();
    assert_eq!(registry.get_level(&actor), ClearanceLevel::ReadOnly);
    advance_sybil_stage(&mut case, SybilStage::ClearanceDowngrade).unwrap();

    // ── Stage 6: Reinstatement — explicit clearance evidence required ─────────
    let clearance_evidence = [0xCEu8; 32];
    reinstate(&mut case, clearance_evidence).unwrap();
    resolve_hold(
        &mut hold,
        ts(1_500),
        "challenge sustained; actor cleared after downgrade and review",
    )
    .unwrap();
    assert_eq!(hold.status, ContestStatus::Resolved);

    // ── Stage 7: Audit log ────────────────────────────────────────────────────
    case.assignee = Some(actor.clone());
    advance_sybil_stage(&mut case, SybilStage::AuditLog).unwrap();

    // ── Completeness ─────────────────────────────────────────────────────────
    assert_eq!(check_completeness(&case), CompletenessResult::Complete);
    assert_eq!(case.stages_completed.len(), 7); // Detection + 6 stages

    // Audit trail: hold has entries for admitted + review-started + resolved
    assert_eq!(hold.audit_log.len(), 3);

    // Clearance evidence appended when reinstate() was called
    assert!(case.evidence.contains(&clearance_evidence));
}

// ---------------------------------------------------------------------------
// WO-006 §2 — Quarantine pauses contested actions via CGR Kernel
// ---------------------------------------------------------------------------

/// While a ContestHold is PauseEligible, the kernel returns Verdict::Escalated
/// rather than Permitted or Denied, so the action is paused (not blocked).
/// Once the hold is cleared the action may proceed normally.
#[test]
fn quarantine_pauses_contested_actions_via_kernel() {
    let kernel = Kernel::new(b"We the people of EXOCHAIN...", InvariantSet::all());
    let actor = did("did:exo:contested-actor");
    let action = ActionRequest {
        actor: actor.clone(),
        action: "approve governance proposal".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("read")]),
        is_self_grant: false,
        modifies_kernel: false,
    };

    // Admit challenge → derive escalation reason
    let action_id = [0x02u8; 32];
    let hold = admit_challenge(signed_challenge(
        3,
        action_id,
        SybilChallengeGround::QuorumContamination,
        ts(2_000),
    ))
    .unwrap();
    let reason = hold.escalation_reason();
    assert!(reason.contains("SybilChallenge"));

    // With active challenge → Verdict::Escalated (action is paused)
    let ctx_challenged = valid_kernel_context(&actor, Some(reason));
    match kernel.adjudicate(&action, &ctx_challenged) {
        Verdict::Escalated { reason } => {
            assert!(
                reason.contains("SybilChallenge"),
                "escalation reason must cite challenge"
            );
        }
        other => panic!("expected Verdict::Escalated while challenge is active, got {other:?}"),
    }

    // Without active challenge → Verdict::Permitted
    let ctx_clear = valid_kernel_context(&actor, None);
    assert!(
        kernel.adjudicate(&action, &ctx_clear).is_permitted(),
        "action must be permitted once challenge is cleared",
    );
}

// ---------------------------------------------------------------------------
// WO-006 §3 — Reinstatement requires non-zero clearance evidence
// ---------------------------------------------------------------------------

/// Attempting to reinstate with a zero-hash evidence is rejected.
/// Only a non-zero evidence hash (representing a disclosed clearance decision)
/// is accepted, enforcing CR-001 §8.6.
#[test]
fn reinstatement_refuses_zero_hash_evidence() {
    let signal = DetectionSignal {
        source: "test".into(),
        signal_type: SignalType::SybilSuspicion,
        confidence: 80,
        evidence_hash: [0x01u8; 32],
        timestamp: ts(3_000),
    };
    let mut case = escalate(escalation_input(
        4,
        signal,
        EscalationPath::SybilAdjudication,
        3_100,
    ))
    .unwrap();
    for stage in [
        SybilStage::Triage,
        SybilStage::Quarantine,
        SybilStage::EvidentaryReview,
        SybilStage::ClearanceDowngrade,
    ] {
        advance_sybil_stage(&mut case, stage).unwrap();
    }

    // Zero-hash evidence must be rejected
    assert!(
        reinstate(&mut case, [0u8; 32]).is_err(),
        "zero-hash clearance evidence must be rejected by reinstate()"
    );

    // Non-zero evidence succeeds
    assert!(
        reinstate(&mut case, [0xAAu8; 32]).is_ok(),
        "non-zero clearance evidence must be accepted"
    );
}
