//! Governance bindings: quorum, clearance, conflict, challenge, audit

use serde::{Deserialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

const MAX_WASM_PUBLIC_KEYS: usize = 512;
const MAX_WASM_CLEARANCE_REGISTRY_ENTRIES: usize = 512;
const MAX_WASM_APPROVALS: usize = 1_024;
const MAX_WASM_CONFLICT_DECLARATIONS: usize = 1_024;
const MAX_WASM_AUDIT_ENTRIES: usize = 4_096;
const MAX_WASM_DELIBERATION_PARTICIPANTS: usize = 1_024;
const MAX_WASM_INDEPENDENCE_ACTORS: usize = 1_024;
const MAX_WASM_REGISTRY_RELATIONSHIPS: usize = 4_096;
const MAX_WASM_COORDINATION_ACTIONS: usize = 4_096;
const MAX_WASM_PROPOSAL_BYTES: usize = 64 * 1_024;
const MAX_WASM_CHALLENGE_EVIDENCE_BYTES: usize = 64 * 1_024;

#[derive(Deserialize)]
struct WasmClearanceRegistryEntry {
    did: String,
    level: exo_governance::clearance::ClearanceLevel,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
fn governance_boundary_error(_message: &str) -> JsValue {
    JsValue::NULL
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
fn governance_boundary_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}

fn ensure_len_at_most(label: &str, len: usize, max_items: usize) -> Result<(), JsValue> {
    if len > max_items {
        return Err(governance_boundary_error(&format!(
            "{label} contains {len} items, maximum is {max_items}"
        )));
    }
    Ok(())
}

fn parse_bounded_vec<T: DeserializeOwned>(
    json: &str,
    label: &str,
    max_items: usize,
) -> Result<Vec<T>, JsValue> {
    let values: Vec<T> = from_json_str(json)?;
    ensure_len_at_most(label, values.len(), max_items)?;
    Ok(values)
}

fn ensure_bytes_at_most(label: &str, len: usize, max_bytes: usize) -> Result<(), JsValue> {
    if len > max_bytes {
        return Err(governance_boundary_error(&format!(
            "{label} contains {len} bytes, maximum is {max_bytes}"
        )));
    }
    Ok(())
}

fn ensure_hex_bytes_at_most(label: &str, hex_value: &str, max_bytes: usize) -> Result<(), JsValue> {
    let max_hex_len = max_bytes * 2;
    if hex_value.len() > max_hex_len {
        return Err(governance_boundary_error(&format!(
            "{label} exceeds maximum encoded length for {max_bytes} bytes"
        )));
    }
    Ok(())
}

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

fn parse_public_key_map(
    public_keys_json: &str,
) -> Result<std::collections::BTreeMap<exo_core::Did, exo_core::PublicKey>, JsValue> {
    let key_pairs: Vec<(String, String)> =
        parse_bounded_vec(public_keys_json, "public keys", MAX_WASM_PUBLIC_KEYS)?;
    let mut keys = std::collections::BTreeMap::new();
    for (did_str, public_key_hex) in &key_pairs {
        let did = exo_core::Did::new(did_str)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        let bytes =
            hex::decode(public_key_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsValue::from_str("public key must be 32 bytes"))?;
        keys.insert(did, exo_core::PublicKey::from_bytes(arr));
    }
    Ok(keys)
}

fn parse_clearance_registry(
    registry_json: &str,
) -> Result<exo_governance::clearance::ClearanceRegistry, JsValue> {
    let entries: Vec<WasmClearanceRegistryEntry> = parse_bounded_vec(
        registry_json,
        "clearance registry",
        MAX_WASM_CLEARANCE_REGISTRY_ENTRIES,
    )?;
    let mut registry_entries = std::collections::BTreeMap::new();
    for entry in entries {
        let did = exo_core::Did::new(&entry.did)
            .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
        if registry_entries.insert(did.clone(), entry.level).is_some() {
            return Err(JsValue::from_str(&format!(
                "duplicate clearance registry entry for {did}"
            )));
        }
    }
    Ok(exo_governance::clearance::ClearanceRegistry::from_verified_snapshot(registry_entries))
}

/// Compute cryptographically verified quorum result from approvals, policy, and signer keys.
#[wasm_bindgen]
pub fn wasm_compute_quorum(
    approvals_json: &str,
    policy_json: &str,
    public_keys_json: &str,
) -> Result<JsValue, JsValue> {
    let approvals: Vec<exo_governance::quorum::Approval> =
        parse_bounded_vec(approvals_json, "approvals", MAX_WASM_APPROVALS)?;
    let policy: exo_governance::quorum::QuorumPolicy = from_json_str(policy_json)?;
    let public_keys = parse_public_key_map(public_keys_json)?;
    let resolver = |did: &exo_core::Did| public_keys.get(did).copied();
    let result = exo_governance::quorum::compute_quorum_verified(&approvals, &policy, &resolver);
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
    registry_json: &str,
) -> Result<JsValue, JsValue> {
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let policy: exo_governance::clearance::ClearancePolicy = from_json_str(policy_json)?;
    let registry = parse_clearance_registry(registry_json)?;
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
    let declarations: Vec<exo_governance::conflict::ConflictDeclaration> = parse_bounded_vec(
        declarations_json,
        "conflict declarations",
        MAX_WASM_CONFLICT_DECLARATIONS,
    )?;
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
    let entries: Vec<exo_governance::audit::AuditEntry> =
        parse_bounded_vec(entries_json, "audit entries", MAX_WASM_AUDIT_ENTRIES)?;
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
    ensure_hex_bytes_at_most("proposal", proposal_hex, MAX_WASM_PROPOSAL_BYTES)?;
    let proposal =
        hex::decode(proposal_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let did_strs: Vec<String> = parse_bounded_vec(
        participants_json,
        "deliberation participants",
        MAX_WASM_DELIBERATION_PARTICIPANTS,
    )?;
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
    public_keys_json: &str,
) -> Result<JsValue, JsValue> {
    use exo_governance::deliberation::DeliberationResult;

    let mut delib: exo_governance::deliberation::Deliberation = from_json_str(deliberation_json)?;
    let policy: exo_governance::quorum::QuorumPolicy = from_json_str(quorum_policy_json)?;
    let public_keys = parse_public_key_map(public_keys_json)?;
    let resolver = |did: &exo_core::Did| public_keys.get(did).copied();
    let result = exo_governance::deliberation::close_verified(&mut delib, &policy, &resolver);

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

    let did_strs: Vec<String> = parse_bounded_vec(
        actors_json,
        "independence actors",
        MAX_WASM_INDEPENDENCE_ACTORS,
    )?;
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
    let registry_relationships = input
        .signing_keys
        .len()
        .saturating_add(input.attestation_roots.len())
        .saturating_add(input.control_metadata.len());
    ensure_len_at_most(
        "identity registry relationships",
        registry_relationships,
        MAX_WASM_REGISTRY_RELATIONSHIPS,
    )?;

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
    let actions: Vec<exo_governance::crosscheck::TimestampedAction> = parse_bounded_vec(
        actions_json,
        "coordination actions",
        MAX_WASM_COORDINATION_ACTIONS,
    )?;
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
    ensure_bytes_at_most(
        "challenge evidence",
        evidence.len(),
        MAX_WASM_CHALLENGE_EVIDENCE_BYTES,
    )?;
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
    let declarations: Vec<exo_governance::conflict::ConflictDeclaration> = parse_bounded_vec(
        declarations_json,
        "conflict declarations",
        MAX_WASM_CONFLICT_DECLARATIONS,
    )?;
    let conflicts = exo_governance::conflict::check_conflicts(&actor, &action, &declarations);
    exo_governance::conflict::check_and_block(&actor, &conflicts)
        .map_err(|e| JsValue::from_str(&format!("ConflictBlocked: {e}")))?;
    to_js_value(&serde_json::json!({ "allowed": true }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::Did;
    use exo_governance::clearance::{
        ActionPolicy, ClearanceDecision, ClearanceLevel, ClearancePolicy, check_clearance,
    };

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value).expect("valid DID")
    }

    fn single_action_policy(action: &str, required_level: ClearanceLevel) -> ClearancePolicy {
        let mut actions = BTreeMap::new();
        actions.insert(
            action.to_owned(),
            ActionPolicy {
                required_level,
                quorum_policy: None,
                independence_required: false,
            },
        );
        ClearancePolicy {
            actions,
            policy_hash: [0xA5; 32],
        }
    }

    #[test]
    fn wasm_governance_bindings_registry_denies_low_clearance_actor() {
        let actor = did("did:exo:alice");
        let policy = single_action_policy("release-kernel", ClearanceLevel::Steward);
        let registry =
            parse_clearance_registry(r#"[{"did":"did:exo:alice","level":"Contributor"}]"#)
                .expect("valid registry");

        let decision = check_clearance(&actor, "release-kernel", &policy, &registry);

        assert_eq!(
            decision,
            ClearanceDecision::Denied {
                missing_level: ClearanceLevel::Steward
            }
        );
    }

    #[test]
    fn wasm_governance_bindings_registry_grants_only_policy_permitted_action() {
        let actor = did("did:exo:alice");
        let policy = single_action_policy("release-kernel", ClearanceLevel::Steward);
        let registry = parse_clearance_registry(r#"[{"did":"did:exo:alice","level":"Steward"}]"#)
            .expect("valid registry");

        let allowed = check_clearance(&actor, "release-kernel", &policy, &registry);
        let unknown_action = check_clearance(&actor, "mint-root", &policy, &registry);

        assert_eq!(
            allowed,
            ClearanceDecision::Granted {
                policy_hash: [0xA5; 32]
            }
        );
        let ClearanceDecision::Denied { missing_level } = unknown_action else {
            panic!("unknown action must be denied");
        };
        assert_eq!(missing_level.to_string(), "Governor");
    }

    #[test]
    fn parse_bounded_vec_accepts_items_at_the_configured_limit() {
        let input = vec!["did:exo:bounded"; MAX_WASM_PUBLIC_KEYS];
        let json = serde_json::to_string(&input).expect("serialize bounded input");

        let parsed: Vec<String> = parse_bounded_vec(&json, "public keys", MAX_WASM_PUBLIC_KEYS)
            .expect("input at the limit is accepted");

        assert_eq!(parsed.len(), MAX_WASM_PUBLIC_KEYS);
    }

    #[test]
    fn parse_bounded_vec_rejects_items_over_the_configured_limit() {
        let input = vec!["did:exo:bounded"; MAX_WASM_PUBLIC_KEYS + 1];
        let json = serde_json::to_string(&input).expect("serialize oversized input");

        let parsed: Result<Vec<String>, JsValue> =
            parse_bounded_vec(&json, "public keys", MAX_WASM_PUBLIC_KEYS);

        assert!(parsed.is_err(), "one item over the limit must fail closed");
    }

    #[test]
    fn byte_caps_reject_oversized_proposal_and_evidence_payloads() {
        let oversized_proposal = "ab".repeat(MAX_WASM_PROPOSAL_BYTES + 1);
        assert!(
            ensure_hex_bytes_at_most("proposal", &oversized_proposal, MAX_WASM_PROPOSAL_BYTES)
                .is_err(),
            "proposal hex larger than the byte cap must fail closed"
        );

        assert!(
            ensure_bytes_at_most(
                "challenge evidence",
                MAX_WASM_CHALLENGE_EVIDENCE_BYTES + 1,
                MAX_WASM_CHALLENGE_EVIDENCE_BYTES,
            )
            .is_err(),
            "challenge evidence larger than the byte cap must fail closed"
        );
    }

    #[test]
    fn registry_relationship_bound_counts_all_nested_registry_vectors() {
        let relationships =
            MAX_WASM_REGISTRY_RELATIONSHIPS - MAX_WASM_PUBLIC_KEYS - MAX_WASM_APPROVALS;
        let total = MAX_WASM_PUBLIC_KEYS
            .saturating_add(MAX_WASM_APPROVALS)
            .saturating_add(relationships)
            .saturating_add(1);

        assert!(
            ensure_len_at_most(
                "identity registry relationships",
                total,
                MAX_WASM_REGISTRY_RELATIONSHIPS,
            )
            .is_err(),
            "aggregate nested registry relationships must be bounded"
        );
    }
}
