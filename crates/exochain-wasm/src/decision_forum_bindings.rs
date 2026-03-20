//! Decision Forum bindings: DecisionObject lifecycle, constitution, TNC enforcement,
//! contestation, accountability, workflow, emergency

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Create a new DecisionObject with full BCTS lifecycle
#[wasm_bindgen]
pub fn wasm_create_decision(
    title: &str,
    class_json: &str,
    constitution_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let class: decision_forum::decision_object::DecisionClass = from_json_str(class_json)?;
    let hash_bytes =
        hex::decode(constitution_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("hash must be 32 bytes"))?;
    let hash = exo_core::Hash256::from_bytes(arr);

    let mut clock = exo_core::hlc::HybridClock::new();
    let decision =
        decision_forum::decision_object::DecisionObject::new(title, class, hash, &mut clock);
    to_js_value(&decision)
}

/// Transition a DecisionObject to a new BCTS state
#[wasm_bindgen]
pub fn wasm_transition_decision(
    decision_json: &str,
    to_state_json: &str,
    actor_did: &str,
) -> Result<JsValue, JsValue> {
    let mut decision: decision_forum::decision_object::DecisionObject =
        from_json_str(decision_json)?;
    let to_state: exo_core::bcts::BctsState = from_json_str(to_state_json)?;
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let mut clock = exo_core::hlc::HybridClock::new();

    decision
        .transition(to_state, &actor, &mut clock)
        .map_err(|e| JsValue::from_str(&format!("Transition error: {e}")))?;
    to_js_value(&decision)
}

/// Add a vote to a DecisionObject
#[wasm_bindgen]
pub fn wasm_add_vote(decision_json: &str, vote_json: &str) -> Result<JsValue, JsValue> {
    let mut decision: decision_forum::decision_object::DecisionObject =
        from_json_str(decision_json)?;
    let vote: decision_forum::decision_object::Vote = from_json_str(vote_json)?;

    decision
        .add_vote(vote)
        .map_err(|e| JsValue::from_str(&format!("Vote error: {e}")))?;
    to_js_value(&decision)
}

/// Add evidence to a DecisionObject
#[wasm_bindgen]
pub fn wasm_add_evidence(decision_json: &str, evidence_json: &str) -> Result<JsValue, JsValue> {
    let mut decision: decision_forum::decision_object::DecisionObject =
        from_json_str(decision_json)?;
    let evidence: decision_forum::decision_object::EvidenceItem = from_json_str(evidence_json)?;

    decision
        .add_evidence(evidence)
        .map_err(|e| JsValue::from_str(&format!("Evidence error: {e}")))?;
    to_js_value(&decision)
}

/// Check if a DecisionObject is in a terminal state
#[wasm_bindgen]
pub fn wasm_decision_is_terminal(decision_json: &str) -> Result<bool, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    Ok(decision.is_terminal())
}

/// Compute the content hash of a DecisionObject (audit fingerprint)
#[wasm_bindgen]
pub fn wasm_decision_content_hash(decision_json: &str) -> Result<String, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let hash = decision
        .content_hash()
        .map_err(|e| JsValue::from_str(&format!("Hash error: {e}")))?;
    Ok(hex::encode(hash.as_bytes()))
}

/// File a challenge against a decision (contestation - GOV-008)
#[wasm_bindgen]
pub fn wasm_file_challenge(
    challenger_did: &str,
    decision_id: &str,
    ground_json: &str,
    evidence_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let challenger = exo_core::Did::new(challenger_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let id: uuid::Uuid = decision_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("Invalid UUID: {e}")))?;
    let ground: exo_governance::challenge::ChallengeGround = from_json_str(ground_json)?;
    let evidence_bytes =
        hex::decode(evidence_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = evidence_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("evidence hash must be 32 bytes"))?;
    let evidence_hash = exo_core::Hash256::from_bytes(arr);

    let mut clock = exo_core::hlc::HybridClock::new();
    let timestamp = clock.now();

    let challenge = decision_forum::contestation::file_challenge(
        id,
        &challenger,
        ground,
        evidence_hash,
        timestamp,
    );
    to_js_value(&challenge)
}

/// Propose an accountability action (GOV-012)
#[wasm_bindgen]
pub fn wasm_propose_accountability(
    target_did: &str,
    proposer_did: &str,
    action_type_json: &str,
    reason: &str,
    evidence_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let target = exo_core::Did::new(target_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let proposer = exo_core::Did::new(proposer_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let action_type: decision_forum::accountability::AccountabilityActionType =
        from_json_str(action_type_json)?;
    let evidence_bytes =
        hex::decode(evidence_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = evidence_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("evidence hash must be 32 bytes"))?;
    let evidence_hash = exo_core::Hash256::from_bytes(arr);

    let mut clock = exo_core::hlc::HybridClock::new();
    let timestamp = clock.now();

    let action = decision_forum::accountability::propose(
        action_type,
        &target,
        &proposer,
        reason,
        evidence_hash,
        timestamp,
    );
    to_js_value(&action)
}

/// Get all BCTS state names in lifecycle order.
#[wasm_bindgen]
pub fn wasm_workflow_stages() -> Result<JsValue, JsValue> {
    let stages = vec![
        "Draft",
        "Submitted",
        "IdentityResolved",
        "ConsentValidated",
        "Deliberated",
        "Verified",
        "Governed",
        "Approved",
        "Executed",
        "Recorded",
        "Closed",
        "Denied",
        "Escalated",
        "Remediated",
    ];
    to_js_value(&stages)
}

// ── Constitution ─────────────────────────────────────────────────

/// Ratify a constitutional corpus with a set of Ed25519 signatures.
///
/// `signatures_json` — JSON array of `[did_str, signature_hex]` pairs.
/// `quorum_json`     — JSON `{required_signatures, required_fraction_pct}`.
#[wasm_bindgen]
pub fn wasm_ratify_constitution(
    corpus_json: &str,
    signatures_json: &str,
    quorum_json: &str,
    timestamp_ms: u64,
) -> Result<JsValue, JsValue> {
    let mut corpus: decision_forum::constitution::ConstitutionCorpus =
        from_json_str(corpus_json)?;
    let quorum: decision_forum::constitution::ConstitutionQuorum = from_json_str(quorum_json)?;
    let sig_pairs: Vec<(String, String)> = from_json_str(signatures_json)?;

    let mut sigs: Vec<(exo_core::Did, exo_core::Signature)> = Vec::new();
    for (did_str, sig_hex) in &sig_pairs {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
        let arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("signature must be 64 bytes"))?;
        sigs.push((did, exo_core::Signature::from_bytes(arr)));
    }

    let ts = exo_core::types::Timestamp::new(timestamp_ms, 0);
    decision_forum::constitution::ratify(&mut corpus, &sigs, &quorum, ts)
        .map_err(|e| JsValue::from_str(&format!("Ratify error: {e}")))?;
    to_js_value(&corpus)
}

/// Amend a constitutional corpus by adding or updating an article.
///
/// `amendment_json`  — JSON `Article` object.
/// `signatures_json` — JSON array of `[did_str, signature_hex]` pairs.
#[wasm_bindgen]
pub fn wasm_amend_constitution(
    corpus_json: &str,
    amendment_json: &str,
    signatures_json: &str,
) -> Result<JsValue, JsValue> {
    let mut corpus: decision_forum::constitution::ConstitutionCorpus =
        from_json_str(corpus_json)?;
    let amendment: decision_forum::constitution::Article = from_json_str(amendment_json)?;
    let sig_pairs: Vec<(String, String)> = from_json_str(signatures_json)?;

    let mut sigs: Vec<(exo_core::Did, exo_core::Signature)> = Vec::new();
    for (did_str, sig_hex) in &sig_pairs {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
        let arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("signature must be 64 bytes"))?;
        sigs.push((did, exo_core::Signature::from_bytes(arr)));
    }

    decision_forum::constitution::amend(&mut corpus, amendment, &sigs)
        .map_err(|e| JsValue::from_str(&format!("Amend error: {e}")))?;
    to_js_value(&corpus)
}

/// Dry-run a constitutional amendment — returns conflict descriptions.
#[wasm_bindgen]
pub fn wasm_dry_run_amendment(
    corpus_json: &str,
    proposed_json: &str,
) -> Result<JsValue, JsValue> {
    let corpus: decision_forum::constitution::ConstitutionCorpus = from_json_str(corpus_json)?;
    let proposed: decision_forum::constitution::Article = from_json_str(proposed_json)?;
    let conflicts = decision_forum::constitution::dry_run_amendment(&corpus, &proposed)
        .map_err(|e| JsValue::from_str(&format!("Dry-run error: {e}")))?;
    to_js_value(&conflicts)
}

// ── TNC Enforcement ──────────────────────────────────────────────
//
// TncContext<'a> holds a borrowed &DecisionObject and cannot be deserialized
// directly.  Each binding takes:
//   - decision_json: &str — the DecisionObject (owned, deserialized locally)
//   - flags_json: &str    — JSON object with the seven boolean precondition
//                           fields: constitutional_hash_valid, consent_verified,
//                           identity_verified, evidence_complete, quorum_met,
//                           human_gate_satisfied, authority_chain_verified
//
// The TncContext is then constructed on the stack inside each function so the
// borrow checker is satisfied without requiring an unsafe transmute.

#[derive(serde::Deserialize)]
struct TncFlags {
    #[serde(default)]
    constitutional_hash_valid: bool,
    #[serde(default)]
    consent_verified: bool,
    #[serde(default)]
    identity_verified: bool,
    #[serde(default)]
    evidence_complete: bool,
    #[serde(default)]
    quorum_met: bool,
    #[serde(default)]
    human_gate_satisfied: bool,
    #[serde(default)]
    authority_chain_verified: bool,
}

fn build_tnc_ctx<'a>(
    decision: &'a decision_forum::decision_object::DecisionObject,
    flags: &TncFlags,
) -> decision_forum::tnc_enforcer::TncContext<'a> {
    decision_forum::tnc_enforcer::TncContext {
        decision,
        constitutional_hash_valid: flags.constitutional_hash_valid,
        consent_verified: flags.consent_verified,
        identity_verified: flags.identity_verified,
        evidence_complete: flags.evidence_complete,
        quorum_met: flags.quorum_met,
        human_gate_satisfied: flags.human_gate_satisfied,
        authority_chain_verified: flags.authority_chain_verified,
    }
}

fn tnc_result(r: decision_forum::error::Result<()>) -> Result<JsValue, JsValue> {
    match r {
        Ok(()) => to_js_value(&serde_json::json!({"ok": true})),
        Err(e) => to_js_value(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

/// Enforce TNC-01: authority chain cryptographically verified.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_01(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_01(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-02: human gate satisfied.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_02(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_02(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-03: consent verified.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_03(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_03(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-04: identity verified.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_04(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_04(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-05: delegation expiry enforced.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_05(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_05(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-06: constitutional binding valid.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_06(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_06(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-07: quorum verified.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_07(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_07(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-08: terminal decisions immutable.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_08(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_08(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-09: AI delegation ceiling enforced.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_09(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_09(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce TNC-10: evidence bundle complete.
#[wasm_bindgen]
pub fn wasm_enforce_tnc_10(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    tnc_result(decision_forum::tnc_enforcer::enforce_tnc_10(&build_tnc_ctx(&decision, &flags)))
}

/// Enforce all 10 TNCs — returns Ok or the first violation.
#[wasm_bindgen]
pub fn wasm_enforce_all_tnc(decision_json: &str, flags_json: &str) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    match decision_forum::tnc_enforcer::enforce_all(&build_tnc_ctx(&decision, &flags)) {
        Ok(()) => to_js_value(&serde_json::json!({"ok": true, "violations": []})),
        Err(e) => to_js_value(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

/// Collect all TNC violations without short-circuiting.
///
/// Returns `{violations: [...]}` — empty array means all TNCs pass.
#[wasm_bindgen]
pub fn wasm_collect_tnc_violations(
    decision_json: &str,
    flags_json: &str,
) -> Result<JsValue, JsValue> {
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let flags: TncFlags = from_json_str(flags_json)?;
    let violations =
        decision_forum::tnc_enforcer::collect_violations(&build_tnc_ctx(&decision, &flags));
    let descriptions: Vec<String> = violations.iter().map(|e| e.to_string()).collect();
    to_js_value(&serde_json::json!({"violations": descriptions}))
}

// ── Human Gate ───────────────────────────────────────────────────

/// Enforce the human gate for a decision — Err if human approval is required
/// but not present in the vote set.
#[wasm_bindgen]
pub fn wasm_enforce_human_gate(
    policy_json: &str,
    decision_json: &str,
) -> Result<JsValue, JsValue> {
    let policy: decision_forum::human_gate::HumanGatePolicy = from_json_str(policy_json)?;
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    match decision_forum::human_gate::enforce_human_gate(&policy, &decision) {
        Ok(()) => to_js_value(&serde_json::json!({"ok": true})),
        Err(e) => to_js_value(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

/// Return true if the given decision class requires human approval under the policy.
#[wasm_bindgen]
pub fn wasm_requires_human_approval(
    policy_json: &str,
    class_json: &str,
) -> Result<bool, JsValue> {
    let policy: decision_forum::human_gate::HumanGatePolicy = from_json_str(policy_json)?;
    let class: decision_forum::decision_object::DecisionClass = from_json_str(class_json)?;
    Ok(decision_forum::human_gate::requires_human_approval(&policy, class))
}

/// Return true if the given decision class is within the AI delegation ceiling.
#[wasm_bindgen]
pub fn wasm_ai_within_ceiling(policy_json: &str, class_json: &str) -> Result<bool, JsValue> {
    let policy: decision_forum::human_gate::HumanGatePolicy = from_json_str(policy_json)?;
    let class: decision_forum::decision_object::DecisionClass = from_json_str(class_json)?;
    Ok(decision_forum::human_gate::ai_within_ceiling(&policy, class))
}

/// Return true if the given vote was cast by a human actor.
#[wasm_bindgen]
pub fn wasm_is_human_vote(vote_json: &str) -> Result<bool, JsValue> {
    let vote: decision_forum::decision_object::Vote = from_json_str(vote_json)?;
    Ok(decision_forum::human_gate::is_human_vote(&vote))
}

/// Return true if the given vote was cast by an AI agent.
#[wasm_bindgen]
pub fn wasm_is_ai_vote(vote_json: &str) -> Result<bool, JsValue> {
    let vote: decision_forum::decision_object::Vote = from_json_str(vote_json)?;
    Ok(decision_forum::human_gate::is_ai_vote(&vote))
}

// ── Quorum ───────────────────────────────────────────────────────

/// Check whether the quorum requirement for a decision is satisfied.
///
/// Returns `{status, total_votes, approve_count, approve_pct}` on Met,
/// or `{status, reason}` on NotMet / Degraded.
#[wasm_bindgen]
pub fn wasm_check_quorum(registry_json: &str, decision_json: &str) -> Result<JsValue, JsValue> {
    use decision_forum::quorum::QuorumCheckResult;

    let registry: decision_forum::quorum::QuorumRegistry = from_json_str(registry_json)?;
    let decision: decision_forum::decision_object::DecisionObject = from_json_str(decision_json)?;
    let result = decision_forum::quorum::check_quorum(&registry, &decision)
        .map_err(|e| JsValue::from_str(&format!("Quorum error: {e}")))?;

    // QuorumCheckResult doesn't implement Serialize — flatten manually.
    let json = match result {
        QuorumCheckResult::Met {
            total_votes,
            approve_count,
            approve_pct,
        } => serde_json::json!({
            "status": "Met",
            "total_votes": total_votes,
            "approve_count": approve_count,
            "approve_pct": approve_pct,
        }),
        QuorumCheckResult::NotMet { reason } => serde_json::json!({
            "status": "NotMet",
            "reason": reason,
        }),
        QuorumCheckResult::Degraded {
            reason,
            available,
            required,
        } => serde_json::json!({
            "status": "Degraded",
            "reason": reason,
            "available": available,
            "required": required,
        }),
    };
    to_js_value(&json)
}

/// Verify that enough eligible voters exist to reach quorum before voting opens.
#[wasm_bindgen]
pub fn wasm_verify_quorum_precondition(
    registry_json: &str,
    class_json: &str,
    eligible_voters: usize,
) -> Result<bool, JsValue> {
    let registry: decision_forum::quorum::QuorumRegistry = from_json_str(registry_json)?;
    let class: decision_forum::decision_object::DecisionClass = from_json_str(class_json)?;
    decision_forum::quorum::verify_quorum_precondition(&registry, class, eligible_voters)
        .map_err(|e| JsValue::from_str(&format!("Precondition error: {e}")))
}

// ── Emergency Protocol ───────────────────────────────────────────

/// Create an emergency action under the given policy.
#[wasm_bindgen]
pub fn wasm_create_emergency_action(
    action_type_json: &str,
    actor_did: &str,
    justification: &str,
    monetary_cap_cents: u64,
    evidence_hash_hex: &str,
    policy_json: &str,
    timestamp_ms: u64,
) -> Result<JsValue, JsValue> {
    let action_type: decision_forum::emergency::EmergencyActionType =
        from_json_str(action_type_json)?;
    let actor = exo_core::Did::new(actor_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let evidence_bytes =
        hex::decode(evidence_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = evidence_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("evidence hash must be 32 bytes"))?;
    let evidence_hash = exo_core::Hash256::from_bytes(arr);
    let policy: decision_forum::emergency::EmergencyPolicy = from_json_str(policy_json)?;
    let ts = exo_core::types::Timestamp::new(timestamp_ms, 0);

    let action = decision_forum::emergency::create_emergency_action(
        action_type,
        &actor,
        justification,
        monetary_cap_cents,
        evidence_hash,
        &policy,
        ts,
    )
    .map_err(|e| JsValue::from_str(&format!("Emergency error: {e}")))?;
    to_js_value(&action)
}

/// Ratify an emergency action with a governance decision.
#[wasm_bindgen]
pub fn wasm_ratify_emergency(
    action_json: &str,
    decision_id: &str,
    timestamp_ms: u64,
) -> Result<JsValue, JsValue> {
    let mut action: decision_forum::emergency::EmergencyAction = from_json_str(action_json)?;
    let id: uuid::Uuid = decision_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("UUID error: {e}")))?;
    let ts = exo_core::types::Timestamp::new(timestamp_ms, 0);
    decision_forum::emergency::ratify_emergency(&mut action, id, ts)
        .map_err(|e| JsValue::from_str(&format!("Ratify error: {e}")))?;
    to_js_value(&action)
}

/// Check whether an emergency action's ratification window has expired.
/// Mutates `ratification_status` to `Expired` if so. Returns `true` if expired.
#[wasm_bindgen]
pub fn wasm_check_expiry(action_json: &str, now_ms: u64) -> Result<JsValue, JsValue> {
    let mut action: decision_forum::emergency::EmergencyAction = from_json_str(action_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    let expired = decision_forum::emergency::check_expiry(&mut action, &now);
    to_js_value(&serde_json::json!({"expired": expired, "action": action}))
}

/// Return true if the emergency action history requires a governance review
/// (e.g. frequency threshold exceeded under the policy).
#[wasm_bindgen]
pub fn wasm_needs_governance_review(
    actions_json: &str,
    policy_json: &str,
) -> Result<bool, JsValue> {
    let actions: Vec<decision_forum::emergency::EmergencyAction> = from_json_str(actions_json)?;
    let policy: decision_forum::emergency::EmergencyPolicy = from_json_str(policy_json)?;
    Ok(decision_forum::emergency::needs_governance_review(&actions, &policy))
}

// ── Contestation ─────────────────────────────────────────────────

/// Move a challenge from Filed → UnderReview.
#[wasm_bindgen]
pub fn wasm_begin_review(challenge_json: &str) -> Result<JsValue, JsValue> {
    let mut challenge: decision_forum::contestation::ChallengeObject =
        from_json_str(challenge_json)?;
    decision_forum::contestation::begin_review(&mut challenge)
        .map_err(|e| JsValue::from_str(&format!("Review error: {e}")))?;
    to_js_value(&challenge)
}

/// Withdraw a challenge (Filed or UnderReview → Withdrawn).
#[wasm_bindgen]
pub fn wasm_withdraw_challenge(challenge_json: &str) -> Result<JsValue, JsValue> {
    let mut challenge: decision_forum::contestation::ChallengeObject =
        from_json_str(challenge_json)?;
    decision_forum::contestation::withdraw(&mut challenge)
        .map_err(|e| JsValue::from_str(&format!("Withdraw error: {e}")))?;
    to_js_value(&challenge)
}

/// Return true if the given decision is currently contested (has an active challenge).
#[wasm_bindgen]
pub fn wasm_is_contested(
    challenges_json: &str,
    decision_id: &str,
) -> Result<bool, JsValue> {
    let challenges: Vec<decision_forum::contestation::ChallengeObject> =
        from_json_str(challenges_json)?;
    let id: uuid::Uuid = decision_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("UUID error: {e}")))?;
    Ok(decision_forum::contestation::is_contested(&challenges, id))
}

// ── Accountability ───────────────────────────────────────────────

/// Move an accountability action from Proposed → DueProcess.
#[wasm_bindgen]
pub fn wasm_begin_due_process(action_json: &str) -> Result<JsValue, JsValue> {
    let mut action: decision_forum::accountability::AccountabilityAction =
        from_json_str(action_json)?;
    decision_forum::accountability::begin_due_process(&mut action)
        .map_err(|e| JsValue::from_str(&format!("Due-process error: {e}")))?;
    to_js_value(&action)
}

/// Enact an accountability action after due process completes.
#[wasm_bindgen]
pub fn wasm_enact_accountability(
    action_json: &str,
    decision_id: &str,
    timestamp_ms: u64,
) -> Result<JsValue, JsValue> {
    let mut action: decision_forum::accountability::AccountabilityAction =
        from_json_str(action_json)?;
    let id: uuid::Uuid = decision_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("UUID error: {e}")))?;
    let ts = exo_core::types::Timestamp::new(timestamp_ms, 0);
    decision_forum::accountability::enact(&mut action, id, ts)
        .map_err(|e| JsValue::from_str(&format!("Enact error: {e}")))?;
    to_js_value(&action)
}

/// Reverse an enacted accountability action.
#[wasm_bindgen]
pub fn wasm_reverse_accountability(action_json: &str) -> Result<JsValue, JsValue> {
    let mut action: decision_forum::accountability::AccountabilityAction =
        from_json_str(action_json)?;
    decision_forum::accountability::reverse(&mut action)
        .map_err(|e| JsValue::from_str(&format!("Reverse error: {e}")))?;
    to_js_value(&action)
}

/// Return true if the due-process deadline has passed for an action.
#[wasm_bindgen]
pub fn wasm_is_due_process_expired(action_json: &str, now_ms: u64) -> Result<bool, JsValue> {
    let action: decision_forum::accountability::AccountabilityAction =
        from_json_str(action_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    Ok(decision_forum::accountability::is_due_process_expired(&action, &now))
}

// ── Forum Authority ──────────────────────────────────────────────

/// Verify the integrity and authenticity of a ForumAuthority object.
#[wasm_bindgen]
pub fn wasm_verify_forum_authority(authority_json: &str) -> Result<JsValue, JsValue> {
    let authority: decision_forum::authority::ForumAuthority = from_json_str(authority_json)?;
    match decision_forum::authority::verify_forum_authority(&authority) {
        Ok(()) => to_js_value(&serde_json::json!({"ok": true})),
        Err(e) => to_js_value(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}
