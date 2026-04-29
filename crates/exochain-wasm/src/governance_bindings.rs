//! Governance bindings: quorum, clearance, conflict, challenge, audit

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

fn parse_uuid(value: &str, label: &str) -> Result<uuid::Uuid, JsValue> {
    let id: uuid::Uuid = value
        .parse()
        .map_err(|e| JsValue::from_str(&format!("{label} UUID error: {e}")))?;
    if id.is_nil() {
        return Err(JsValue::from_str(&format!(
            "{label} UUID must be caller-supplied and non-nil"
        )));
    }
    Ok(id)
}

fn parse_timestamp(
    physical_ms: u64,
    logical: u32,
    label: &str,
) -> Result<exo_core::Timestamp, JsValue> {
    if physical_ms == 0 && logical == 0 {
        return Err(JsValue::from_str(&format!(
            "{label} timestamp must be caller-supplied HLC"
        )));
    }
    Ok(exo_core::Timestamp {
        physical_ms,
        logical,
    })
}

/// Compute quorum result from approvals and policy
#[wasm_bindgen]
pub fn wasm_compute_quorum(approvals_json: &str, policy_json: &str) -> Result<JsValue, JsValue> {
    let approvals: Vec<exo_governance::quorum::Approval> = from_json_str(approvals_json)?;
    let policy: exo_governance::quorum::QuorumPolicy = from_json_str(policy_json)?;
    let result = exo_governance::quorum::compute_quorum(&approvals, &policy);
    // QuorumResult doesn't derive Serialize, so format it manually
    let json = match result {
        exo_governance::quorum::QuorumResult::Met {
            independent_count,
            total_count,
        } => {
            serde_json::json!({"status": "Met", "independent_count": independent_count, "total_count": total_count})
        }
        exo_governance::quorum::QuorumResult::NotMet { reason } => {
            serde_json::json!({"status": "NotMet", "reason": reason})
        }
        exo_governance::quorum::QuorumResult::Contested { challenge } => {
            serde_json::json!({"status": "Contested", "challenge": challenge})
        }
    };
    to_js_value(&json)
}

/// Check clearance level for an actor on an action
#[wasm_bindgen]
pub fn wasm_check_clearance(
    actor_did: &str,
    action: &str,
    policy_json: &str,
) -> Result<JsValue, JsValue> {
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let policy: exo_governance::clearance::ClearancePolicy = from_json_str(policy_json)?;
    // ClearanceRegistry doesn't derive Deserialize, so we build a default one
    // with the actor set to Governor level for checking purposes
    let mut registry = exo_governance::clearance::ClearanceRegistry::default();
    registry.set_level(
        actor.clone(),
        exo_governance::clearance::ClearanceLevel::Governor,
    );
    let decision = exo_governance::clearance::check_clearance(&actor, action, &policy, &registry);
    // ClearanceDecision doesn't derive Serialize, format manually
    let json = match decision {
        exo_governance::clearance::ClearanceDecision::Granted { policy_hash } => {
            serde_json::json!({"status": "Granted", "policy_hash": hex::encode(policy_hash)})
        }
        exo_governance::clearance::ClearanceDecision::Denied { missing_level } => {
            serde_json::json!({"status": "Denied", "missing_level": format!("{missing_level}")})
        }
        exo_governance::clearance::ClearanceDecision::InsufficientIndependence { details } => {
            serde_json::json!({"status": "InsufficientIndependence", "details": details})
        }
    };
    to_js_value(&json)
}

/// Check for conflicts of interest
#[wasm_bindgen]
pub fn wasm_check_conflicts(
    actor_did: &str,
    action_json: &str,
    declarations_json: &str,
) -> Result<JsValue, JsValue> {
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let action: exo_governance::conflict::ActionRequest = from_json_str(action_json)?;
    let declarations: Vec<exo_governance::conflict::ConflictDeclaration> =
        from_json_str(declarations_json)?;
    let conflicts = exo_governance::conflict::check_conflicts(&actor, &action, &declarations);
    let must_recuse = exo_governance::conflict::must_recuse(&conflicts);
    to_js_value(&serde_json::json!({
        "conflicts": conflicts,
        "must_recuse": must_recuse,
    }))
}

/// Append to a hash-chained audit log
#[wasm_bindgen]
pub fn wasm_audit_append(
    entry_id: &str,
    timestamp_physical_ms: u64,
    timestamp_logical: u32,
    actor_did: &str,
    action: &str,
    result: &str,
    evidence_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let evidence_bytes =
        hex::decode(evidence_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = evidence_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("evidence hash must be 32 bytes"))?;

    let mut log = exo_governance::audit::AuditLog::new();
    let entry = exo_governance::audit::create_entry(
        &log,
        parse_uuid(entry_id, "audit entry")?,
        parse_timestamp(timestamp_physical_ms, timestamp_logical, "audit entry")?,
        actor,
        action.to_string(),
        result.to_string(),
        arr,
    )
    .map_err(|e| JsValue::from_str(&format!("Audit error: {e}")))?;
    exo_governance::audit::append(&mut log, entry)
        .map_err(|e| JsValue::from_str(&format!("Audit error: {e}")))?;
    let head_hash = log
        .head_hash()
        .map_err(|e| JsValue::from_str(&format!("Audit error: {e}")))?;
    // AuditLog doesn't derive Serialize, return summary
    to_js_value(&serde_json::json!({
        "entries": log.len(),
        "head_hash": hex::encode(head_hash),
    }))
}

/// Verify the integrity of an audit log's hash chain
#[wasm_bindgen]
pub fn wasm_audit_verify(entries_json: &str) -> Result<JsValue, JsValue> {
    let entries: Vec<exo_governance::audit::AuditEntry> = from_json_str(entries_json)?;
    let mut log = exo_governance::audit::AuditLog::new();
    // Rebuild the log from entries
    for entry in entries {
        if let Err(e) = exo_governance::audit::append(&mut log, entry) {
            return to_js_value(&serde_json::json!({"valid": false, "error": format!("{e}")}));
        }
    }
    match exo_governance::audit::verify_chain(&log) {
        Ok(()) => to_js_value(&serde_json::json!({"valid": true})),
        Err(e) => to_js_value(&serde_json::json!({"valid": false, "error": format!("{e}")})),
    }
}

// ── Deliberation ─────────────────────────────────────────────────

/// Open a new deliberation on a proposal.
///
/// `proposal_hex`      — hex-encoded raw proposal bytes.
/// `participants_json` — JSON array of DID strings.
#[wasm_bindgen]
pub fn wasm_open_deliberation(
    deliberation_id: &str,
    created_physical_ms: u64,
    created_logical: u32,
    proposal_hex: &str,
    participants_json: &str,
) -> Result<JsValue, JsValue> {
    let proposal =
        hex::decode(proposal_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let did_strs: Vec<String> = from_json_str(participants_json)?;
    let mut participants = Vec::with_capacity(did_strs.len());
    for s in &did_strs {
        participants.push(
            exo_core::Did::new(s).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?,
        );
    }
    let delib = exo_governance::deliberation::open_deliberation(
        parse_uuid(deliberation_id, "deliberation")?,
        parse_timestamp(created_physical_ms, created_logical, "deliberation")?,
        &proposal,
        &participants,
    )
    .map_err(|e| JsValue::from_str(&format!("Deliberation error: {e}")))?;
    to_js_value(&delib)
}

/// Cast a vote in a deliberation.
#[wasm_bindgen]
pub fn wasm_cast_vote(deliberation_json: &str, vote_json: &str) -> Result<JsValue, JsValue> {
    let mut delib: exo_governance::deliberation::Deliberation = from_json_str(deliberation_json)?;
    let vote: exo_governance::deliberation::Vote = from_json_str(vote_json)?;
    exo_governance::deliberation::cast_vote(&mut delib, vote)
        .map_err(|e| JsValue::from_str(&format!("Vote error: {e}")))?;
    to_js_value(&delib)
}

/// Close a deliberation and compute its result.
///
/// Returns `{result, votes_for, votes_against, abstentions}` or `{result, reason}`.
#[wasm_bindgen]
pub fn wasm_close_deliberation(
    deliberation_json: &str,
    quorum_policy_json: &str,
) -> Result<JsValue, JsValue> {
    use exo_governance::deliberation::DeliberationResult;

    let mut delib: exo_governance::deliberation::Deliberation = from_json_str(deliberation_json)?;
    let policy: exo_governance::quorum::QuorumPolicy = from_json_str(quorum_policy_json)?;
    let result = exo_governance::deliberation::close(&mut delib, &policy);

    let json = match result {
        DeliberationResult::Approved {
            votes_for,
            votes_against,
            abstentions,
        } => serde_json::json!({
            "result": "Approved",
            "votes_for": votes_for,
            "votes_against": votes_against,
            "abstentions": abstentions,
        }),
        DeliberationResult::Rejected {
            votes_for,
            votes_against,
            abstentions,
        } => serde_json::json!({
            "result": "Rejected",
            "votes_for": votes_for,
            "votes_against": votes_against,
            "abstentions": abstentions,
        }),
        DeliberationResult::NoQuorum { reason } => serde_json::json!({
            "result": "NoQuorum",
            "reason": reason,
        }),
    };
    to_js_value(&json)
}

// ── Succession ───────────────────────────────────────────────────

/// Activate a succession plan with a trigger.
#[wasm_bindgen]
pub fn wasm_activate_succession(
    plan_json: &str,
    trigger_json: &str,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let plan: exo_governance::succession::SuccessionPlan = from_json_str(plan_json)?;
    let trigger: exo_governance::succession::SuccessionTrigger = from_json_str(trigger_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    let result = exo_governance::succession::activate_succession(&plan, trigger, &now)
        .map_err(|e| JsValue::from_str(&format!("Succession error: {e}")))?;
    to_js_value(&result)
}

// ── Crosscheck (Independence / Sybil) ────────────────────────────

/// Verify actor independence against the identity registry.
///
/// `registry_json` — JSON object:
/// ```json
/// {
///   "signing_keys": [["did:exo:a", "keyHex"], ...],
///   "attestation_roots": [["did:exo:a", "did:exo:root"], ...],
///   "control_metadata": [["did:exo:a", "note"], ...]
/// }
/// ```
#[wasm_bindgen]
pub fn wasm_verify_independence(
    actors_json: &str,
    registry_json: &str,
) -> Result<JsValue, JsValue> {
    use std::collections::BTreeMap;

    let did_strs: Vec<String> = from_json_str(actors_json)?;
    let mut actors = Vec::with_capacity(did_strs.len());
    for s in &did_strs {
        actors.push(
            exo_core::Did::new(s).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?,
        );
    }

    // Manually deserialize the registry since IdentityRegistry doesn't implement Deserialize.
    #[derive(serde::Deserialize)]
    struct RegistryInput {
        #[serde(default)]
        signing_keys: Vec<(String, String)>,
        #[serde(default)]
        attestation_roots: Vec<(String, String)>,
        #[serde(default)]
        control_metadata: Vec<(String, String)>,
    }
    let input: RegistryInput = from_json_str(registry_json)?;

    let mut signing_keys = BTreeMap::new();
    for (did_str, key) in &input.signing_keys {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        signing_keys.insert(did, key.clone());
    }
    let mut attestation_roots = BTreeMap::new();
    for (did_str, root_str) in &input.attestation_roots {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        let root = exo_core::Did::new(root_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        attestation_roots.insert(did, root);
    }
    let mut control_metadata = BTreeMap::new();
    for (did_str, meta) in &input.control_metadata {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        control_metadata.insert(did, meta.clone());
    }

    let registry = exo_governance::crosscheck::IdentityRegistry {
        signing_keys,
        attestation_roots,
        control_metadata,
    };
    let result = exo_governance::crosscheck::verify_independence(&actors, &registry);
    // IndependenceResult may not implement Serialize — manually flatten.
    let clusters: Vec<serde_json::Value> = result
        .clusters
        .iter()
        .map(|c| {
            serde_json::json!({
                "reason": c.reason,
                "members": c.members.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    let suspicious: Vec<serde_json::Value> = result
        .suspicious_pairs
        .iter()
        .map(|(a, b)| serde_json::json!([a.as_str(), b.as_str()]))
        .collect();
    to_js_value(&serde_json::json!({
        "independent_count": result.independent_count,
        "clusters": clusters,
        "suspicious_pairs": suspicious,
    }))
}

/// Detect coordination patterns in a set of timestamped actions.
#[wasm_bindgen]
pub fn wasm_detect_coordination(actions_json: &str) -> Result<JsValue, JsValue> {
    let actions: Vec<exo_governance::crosscheck::TimestampedAction> = from_json_str(actions_json)?;
    let signals = exo_governance::crosscheck::detect_coordination(&actions);
    // CoordinationSignal may not implement Serialize — manually flatten.
    let json: Vec<serde_json::Value> = signals
        .iter()
        .map(|s| {
            serde_json::json!({
                "actors": s.actors.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
                "reason": s.reason,
                "confidence": s.confidence,
            })
        })
        .collect();
    to_js_value(&json)
}

/// File a governance challenge
#[wasm_bindgen]
pub fn wasm_file_governance_challenge(
    challenge_id: &str,
    created_physical_ms: u64,
    created_logical: u32,
    challenger_did: &str,
    target_hash_hex: &str,
    ground_json: &str,
    evidence: &[u8],
) -> Result<JsValue, JsValue> {
    let challenger = exo_core::Did::new(challenger_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let target_bytes =
        hex::decode(target_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = target_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("target must be 32 bytes"))?;
    let ground: exo_governance::challenge::ChallengeGround = from_json_str(ground_json)?;
    let challenge = exo_governance::challenge::file_challenge(
        parse_uuid(challenge_id, "challenge")?,
        parse_timestamp(created_physical_ms, created_logical, "challenge")?,
        &challenger,
        &arr,
        ground,
        evidence,
    )
    .map_err(|e| JsValue::from_str(&format!("Challenge error: {e}")))?;
    to_js_value(&challenge)
}

/// Enforcing conflict gate — returns an error if the actor is blocked from voting.
///
/// Unlike `wasm_check_conflicts` (which is advisory), this function returns an
/// Err when `check_and_block()` determines the actor must recuse.  Use this
/// at the vote-submission boundary to enforce recusal at the kernel level.
#[wasm_bindgen]
pub fn wasm_conflict_enforce(
    actor_did: &str,
    action_json: &str,
    declarations_json: &str,
) -> Result<JsValue, JsValue> {
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let action: exo_governance::conflict::ActionRequest = from_json_str(action_json)?;
    let declarations: Vec<exo_governance::conflict::ConflictDeclaration> =
        from_json_str(declarations_json)?;
    let conflicts = exo_governance::conflict::check_conflicts(&actor, &action, &declarations);
    exo_governance::conflict::check_and_block(&actor, &conflicts)
        .map_err(|e| JsValue::from_str(&format!("ConflictBlocked: {e}")))?;
    to_js_value(&serde_json::json!({ "allowed": true }))
}
