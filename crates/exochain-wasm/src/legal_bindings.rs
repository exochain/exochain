//! Legal bindings: evidence chain of custody, fiduciary duty, eDiscovery

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Create a new piece of evidence with chain of custody
#[wasm_bindgen]
pub fn wasm_create_evidence(
    content: &[u8],
    type_tag: &str,
    creator_did: &str,
) -> Result<JsValue, JsValue> {
    let creator = exo_core::Did::new(creator_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let mut clock = exo_core::hlc::HybridClock::new();
    let timestamp = clock.now();
    let evidence = exo_legal::evidence::create_evidence(content, &creator, type_tag, timestamp)
        .map_err(|e| JsValue::from_str(&format!("Evidence error: {e}")))?;
    to_js_value(&evidence)
}

/// Verify the chain of custody for a piece of evidence
#[wasm_bindgen]
pub fn wasm_verify_chain_of_custody(evidence_json: &str) -> Result<JsValue, JsValue> {
    let evidence: exo_legal::evidence::Evidence = from_json_str(evidence_json)?;
    match exo_legal::evidence::verify_chain_of_custody(&evidence) {
        Ok(()) => to_js_value(&serde_json::json!({"valid": true})),
        Err(e) => to_js_value(&serde_json::json!({"valid": false, "error": format!("{e}")})),
    }
}

/// Check fiduciary duty compliance
#[wasm_bindgen]
pub fn wasm_check_fiduciary_duty(duty_json: &str, actions_json: &str) -> Result<JsValue, JsValue> {
    let duty: exo_legal::fiduciary::FiduciaryDuty = from_json_str(duty_json)?;
    let actions: Vec<exo_legal::fiduciary::AuditEntry> = from_json_str(actions_json)?;
    let result = exo_legal::fiduciary::check_duty_compliance(&duty, &actions);
    to_js_value(&result)
}

/// Search evidence corpus (eDiscovery)
#[wasm_bindgen]
pub fn wasm_ediscovery_search(request_json: &str, corpus_json: &str) -> Result<JsValue, JsValue> {
    let request: exo_legal::ediscovery::DiscoveryRequest = from_json_str(request_json)?;
    let corpus: Vec<exo_legal::evidence::Evidence> = from_json_str(corpus_json)?;
    let response = exo_legal::ediscovery::search(&request, &corpus);
    to_js_value(&response)
}

// ── Privilege ─────────────────────────────────────────────────────

/// Assert a legal privilege over an evidence item.
#[wasm_bindgen]
pub fn wasm_assert_privilege(
    evidence_id: &str,
    privilege_type_json: &str,
    asserter_did: &str,
    basis: &str,
) -> Result<JsValue, JsValue> {
    let id: uuid::Uuid = evidence_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("UUID error: {e}")))?;
    let privilege_type: exo_legal::privilege::PrivilegeType = from_json_str(privilege_type_json)?;
    let asserter = exo_core::Did::new(asserter_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let assertion = exo_legal::privilege::assert_privilege(&id, privilege_type, &asserter, basis);
    to_js_value(&assertion)
}

/// File a challenge to a privilege assertion.
#[wasm_bindgen]
pub fn wasm_challenge_privilege(
    assertion_json: &str,
    challenger_did: &str,
    grounds: &str,
) -> Result<JsValue, JsValue> {
    let assertion: exo_legal::privilege::PrivilegeAssertion = from_json_str(assertion_json)?;
    let challenger = exo_core::Did::new(challenger_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let challenge = exo_legal::privilege::challenge_privilege(&assertion, &challenger, grounds);
    to_js_value(&challenge)
}

// ── Records ───────────────────────────────────────────────────────

/// Create a new legal record from raw data.
#[wasm_bindgen]
pub fn wasm_create_record(
    data: &[u8],
    classification: &str,
    retention_days: u64,
) -> Result<JsValue, JsValue> {
    let record = exo_legal::records::create_record(data, classification, retention_days);
    to_js_value(&record)
}

/// Apply retention policy to a set of records, updating disposition fields.
///
/// `records_json` — JSON array of Record objects.
/// Returns the updated records array.
#[wasm_bindgen]
pub fn wasm_apply_retention(
    records_json: &str,
    policy_json: &str,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let mut records: Vec<exo_legal::records::Record> = from_json_str(records_json)?;
    let policy: exo_legal::records::RetentionPolicy = from_json_str(policy_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    exo_legal::records::apply_retention(&mut records, &policy, &now);
    to_js_value(&records)
}

// ── DGCL §144 Safe Harbor ────────────────────────────────────────

/// Initiate a DGCL §144 safe harbor process for an interested-party transaction.
#[wasm_bindgen]
pub fn wasm_initiate_safe_harbor(
    interested_party_did: &str,
    counterparty_did: &str,
    interest_description: &str,
    terms_hash_hex: &str,
    path_json: &str,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let interested_party = exo_core::Did::new(interested_party_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let counterparty = exo_core::Did::new(counterparty_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let hash_bytes =
        hex::decode(terms_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let arr: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("terms hash must be 32 bytes"))?;
    let terms_hash = exo_core::Hash256::from_bytes(arr);
    let path: exo_legal::dgcl144::SafeHarborPath = from_json_str(path_json)?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    let txn = exo_legal::dgcl144::initiate_safe_harbor(
        &interested_party,
        &counterparty,
        interest_description,
        terms_hash,
        path,
        now,
    )
    .map_err(|e| JsValue::from_str(&format!("Safe harbor error: {e}")))?;
    to_js_value(&txn)
}

/// Record the material-facts disclosure for a safe harbor transaction.
#[wasm_bindgen]
pub fn wasm_complete_disclosure(
    txn_json: &str,
    disclosed_by_did: &str,
    material_facts: &str,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let mut txn: exo_legal::dgcl144::InterestedTransaction = from_json_str(txn_json)?;
    let disclosed_by = exo_core::Did::new(disclosed_by_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    exo_legal::dgcl144::complete_disclosure(&mut txn, &disclosed_by, material_facts, now)
        .map_err(|e| JsValue::from_str(&format!("Disclosure error: {e}")))?;
    to_js_value(&txn)
}

/// Record a disinterested-party vote on a safe harbor transaction.
#[wasm_bindgen]
pub fn wasm_record_disinterested_vote(
    txn_json: &str,
    voter_did: &str,
    approved: bool,
    now_ms: u64,
) -> Result<JsValue, JsValue> {
    let mut txn: exo_legal::dgcl144::InterestedTransaction = from_json_str(txn_json)?;
    let voter = exo_core::Did::new(voter_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let now = exo_core::types::Timestamp::new(now_ms, 0);
    exo_legal::dgcl144::record_disinterested_vote(&mut txn, &voter, approved, now)
        .map_err(|e| JsValue::from_str(&format!("Vote error: {e}")))?;
    to_js_value(&txn)
}

/// Verify that a safe harbor transaction meets all §144 requirements.
#[wasm_bindgen]
pub fn wasm_verify_safe_harbor(txn_json: &str) -> Result<JsValue, JsValue> {
    let mut txn: exo_legal::dgcl144::InterestedTransaction = from_json_str(txn_json)?;
    match exo_legal::dgcl144::verify_safe_harbor(&mut txn) {
        Ok(()) => to_js_value(&serde_json::json!({"ok": true})),
        Err(e) => to_js_value(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}
