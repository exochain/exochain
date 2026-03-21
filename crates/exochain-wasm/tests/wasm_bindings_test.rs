//! WASM binding round-trip correctness tests.
//!
//! These tests use `#[wasm_bindgen_test]` and are only compiled and executed
//! when targeting `wasm32-unknown-unknown`. Run with:
//!
//!   wasm-pack test --node crates/exochain-wasm
//!
//! On native targets (`cargo test` / `cargo check --tests`) this file is a
//! no-op so that the native CI pipeline is not broken.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_node_experimental);

// ── Helpers ───────────────────────────────────────────────────────────────────

fn js_to_json(val: JsValue) -> serde_json::Value {
    let s = val.as_string().expect("JsValue should be a JSON string");
    serde_json::from_str(&s).expect("JsValue string should be valid JSON")
}

fn js_str(val: JsValue) -> String {
    val.as_string().expect("expected string JsValue")
}

// ── Core: Hashing ─────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_hash_bytes_is_deterministic() {
    let h1 = exochain_wasm::wasm_hash_bytes(b"hello");
    let h2 = exochain_wasm::wasm_hash_bytes(b"hello");
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64, "hex-encoded blake3 is 64 chars");
}

#[wasm_bindgen_test]
fn test_hash_bytes_differs_for_different_inputs() {
    let h1 = exochain_wasm::wasm_hash_bytes(b"hello");
    let h2 = exochain_wasm::wasm_hash_bytes(b"world");
    assert_ne!(h1, h2);
}

#[wasm_bindgen_test]
fn test_hash_structured_round_trip() {
    let hex = exochain_wasm::wasm_hash_structured(r#"{"key":"value"}"#)
        .expect("hash_structured should succeed");
    assert_eq!(hex.len(), 64);
}

// ── Core: Merkle ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_merkle_root_single_leaf() {
    let leaf = exochain_wasm::wasm_hash_bytes(b"leaf0");
    let leaves_json = format!(r#"["{}"]"#, leaf);
    let root = exochain_wasm::wasm_merkle_root(&leaves_json).expect("merkle_root should succeed");
    assert_eq!(root.len(), 64);
}

#[wasm_bindgen_test]
fn test_merkle_proof_and_verify() {
    let leaves: Vec<String> = (0..4)
        .map(|i| exochain_wasm::wasm_hash_bytes(format!("leaf{i}").as_bytes()))
        .collect();
    let leaves_json = serde_json::to_string(&leaves).unwrap();

    let root = exochain_wasm::wasm_merkle_root(&leaves_json).expect("root");

    for index in 0..4usize {
        let proof_json = exochain_wasm::wasm_merkle_proof(&leaves_json, index).expect("proof");

        let valid =
            exochain_wasm::wasm_verify_merkle_proof(&root, &leaves[index], &proof_json, index)
                .expect("verify");
        assert!(valid, "proof should be valid for leaf {index}");

        let wrong_index = (index + 1) % 4;
        let invalid = exochain_wasm::wasm_verify_merkle_proof(
            &root,
            &leaves[index],
            &proof_json,
            wrong_index,
        )
        .expect("verify wrong index");
        assert!(!invalid, "proof should fail with wrong index");
    }
}

// ── Core: Crypto ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_generate_keypair_no_secret_key() {
    let result = exochain_wasm::wasm_generate_keypair().expect("generate_keypair");
    let json = js_to_json(result);
    assert!(
        json.get("public_key").is_some(),
        "public_key must be present"
    );
    assert!(
        json.get("secret_key").is_none(),
        "secret_key must NOT be returned (KEY TRANSIT)"
    );
}

#[wasm_bindgen_test]
fn test_sign_with_ephemeral_key_and_verify() {
    let message = b"governance payload";
    let signed = exochain_wasm::wasm_sign_with_ephemeral_key(message).expect("sign");
    let json = js_to_json(signed);

    let sig_json = serde_json::to_string(json.get("signature").unwrap()).unwrap();
    let pub_hex = json["public_key"].as_str().unwrap().to_owned();

    let valid = exochain_wasm::wasm_verify(message, &sig_json, &pub_hex).expect("verify");
    assert!(valid, "ephemeral signature should verify");
}

#[wasm_bindgen_test]
fn test_verify_rejects_wrong_key() {
    let message = b"test";
    let signed = exochain_wasm::wasm_sign_with_ephemeral_key(message).expect("sign");
    let json = js_to_json(signed);
    let sig_json = serde_json::to_string(json.get("signature").unwrap()).unwrap();

    let other = js_to_json(exochain_wasm::wasm_generate_keypair().expect("kp"));
    let other_pub = other["public_key"].as_str().unwrap().to_owned();

    let valid = exochain_wasm::wasm_verify(message, &sig_json, &other_pub).expect("verify");
    assert!(!valid, "verification should fail with wrong public key");
}

// ── Core: Events ──────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_compute_event_id_is_unique() {
    let id1 = exochain_wasm::wasm_compute_event_id();
    let id2 = exochain_wasm::wasm_compute_event_id();
    assert_ne!(id1, id2, "correlation IDs must be unique");
    assert!(!id1.is_empty());
}

// ── BCTS State Machine ────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_bcts_valid_transitions_from_draft() {
    let result = exochain_wasm::wasm_bcts_valid_transitions(r#""Draft""#).expect("transitions");
    let json = js_to_json(result);
    let states: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        states.contains(&"Submitted"),
        "Draft → Submitted must be valid"
    );
}

#[wasm_bindgen_test]
fn test_bcts_terminal_states() {
    assert!(exochain_wasm::wasm_bcts_is_terminal(r#""Closed""#).expect("Closed"));
    assert!(exochain_wasm::wasm_bcts_is_terminal(r#""Denied""#).expect("Denied"));
    assert!(!exochain_wasm::wasm_bcts_is_terminal(r#""Draft""#).expect("Draft"));
}

// ── Decision Forum: Decision Object ──────────────────────────────────────────

#[wasm_bindgen_test]
fn test_create_decision_round_trip() {
    let hash_hex = "a".repeat(64);
    let result = exochain_wasm::wasm_create_decision("Test proposal", r#""Routine""#, &hash_hex)
        .expect("create_decision");
    let json = js_to_json(result);
    assert_eq!(json["title"].as_str().unwrap(), "Test proposal");
    assert!(!json["id"].as_str().unwrap().is_empty());
}

#[wasm_bindgen_test]
fn test_decision_is_not_terminal_after_creation() {
    let hash_hex = "b".repeat(64);
    let decision_json = js_str(
        exochain_wasm::wasm_create_decision("Draft dec", r#""Routine""#, &hash_hex)
            .expect("create"),
    );
    let terminal = exochain_wasm::wasm_decision_is_terminal(&decision_json).expect("is_terminal");
    assert!(!terminal);
}

#[wasm_bindgen_test]
fn test_decision_content_hash_is_deterministic() {
    let hash_hex = "c".repeat(64);
    let decision_json = js_str(
        exochain_wasm::wasm_create_decision("Stable", r#""Routine""#, &hash_hex).expect("create"),
    );
    let h1 = exochain_wasm::wasm_decision_content_hash(&decision_json).expect("h1");
    let h2 = exochain_wasm::wasm_decision_content_hash(&decision_json).expect("h2");
    assert_eq!(h1, h2);
}

// ── Decision Forum: Workflow Stages ──────────────────────────────────────────

#[wasm_bindgen_test]
fn test_workflow_stages_contains_all_14_bcts_states() {
    let result = exochain_wasm::wasm_workflow_stages().expect("workflow_stages");
    let json = js_to_json(result);
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 14, "BCTS has 14 states");
    let names: Vec<&str> = arr.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(names.contains(&"Draft"));
    assert!(names.contains(&"Closed"));
    assert!(names.contains(&"Denied"));
    assert!(names.contains(&"Escalated"));
    assert!(names.contains(&"Remediated"));
}

// ── Decision Forum: Contestation ─────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_file_challenge_creates_filed_status() {
    let evidence_hex = "d".repeat(64);
    let result = exochain_wasm::wasm_file_challenge(
        "did:exo:challenger",
        "00000000-0000-0000-0000-000000000001",
        r#""ProceduralError""#,
        &evidence_hex,
    )
    .expect("file_challenge");
    let json = js_to_json(result);
    assert_eq!(json["status"].as_str().unwrap(), "Filed");
}

#[wasm_bindgen_test]
fn test_begin_review_transitions_to_under_review() {
    let evidence_hex = "e".repeat(64);
    let challenge_json = js_str(
        exochain_wasm::wasm_file_challenge(
            "did:exo:c",
            "00000000-0000-0000-0000-000000000002",
            r#""ProceduralError""#,
            &evidence_hex,
        )
        .expect("file"),
    );
    let reviewed = exochain_wasm::wasm_begin_review(&challenge_json).expect("begin_review");
    let json = js_to_json(reviewed);
    assert_eq!(json["status"].as_str().unwrap(), "UnderReview");
}

#[wasm_bindgen_test]
fn test_is_contested_true_when_filed() {
    let id = "00000000-0000-0000-0000-000000000003";
    let evidence_hex = "f".repeat(64);
    let challenge_json = js_str(
        exochain_wasm::wasm_file_challenge("did:exo:c", id, r#""ProceduralError""#, &evidence_hex)
            .expect("file"),
    );
    let challenges_json = format!("[{}]", challenge_json);
    let contested = exochain_wasm::wasm_is_contested(&challenges_json, id).expect("is_contested");
    assert!(contested);
}

// ── Decision Forum: Accountability ───────────────────────────────────────────

#[wasm_bindgen_test]
fn test_begin_due_process_transitions_status() {
    let evidence_hex = "1".repeat(64);
    let action_json = js_str(
        exochain_wasm::wasm_propose_accountability(
            "did:exo:target",
            "did:exo:proposer",
            r#""Censure""#,
            "Violated transparency policy",
            &evidence_hex,
        )
        .expect("propose"),
    );
    let result = exochain_wasm::wasm_begin_due_process(&action_json).expect("begin_due_process");
    let json = js_to_json(result);
    assert_eq!(json["status"].as_str().unwrap(), "DueProcess");
}

// ── Decision Forum: TNC ───────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_enforce_all_tnc_passes_when_all_flags_set() {
    let hash_hex = "2".repeat(64);
    let decision_json = js_str(
        exochain_wasm::wasm_create_decision("TNC test", r#""Routine""#, &hash_hex).expect("create"),
    );
    let flags = r#"{
        "constitutional_hash_valid": true,
        "consent_verified": true,
        "identity_verified": true,
        "evidence_complete": true,
        "quorum_met": true,
        "human_gate_satisfied": true,
        "authority_chain_verified": true
    }"#;
    let result =
        exochain_wasm::wasm_enforce_all_tnc(&decision_json, flags).expect("enforce_all_tnc");
    let json = js_to_json(result);
    assert!(json["ok"].as_bool().unwrap());
}

#[wasm_bindgen_test]
fn test_collect_tnc_violations_when_flags_clear() {
    let hash_hex = "3".repeat(64);
    let decision_json = js_str(
        exochain_wasm::wasm_create_decision("Violation test", r#""Routine""#, &hash_hex)
            .expect("create"),
    );
    let result = exochain_wasm::wasm_collect_tnc_violations(&decision_json, r#"{}"#)
        .expect("collect_violations");
    let json = js_to_json(result);
    assert!(!json["violations"].as_array().unwrap().is_empty());
}

// ── Gatekeeper: Introspection ─────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_list_invariants_returns_8() {
    let result = exochain_wasm::wasm_list_invariants().expect("list_invariants");
    let json = js_to_json(result);
    assert_eq!(json.as_array().unwrap().len(), 8);
}

#[wasm_bindgen_test]
fn test_list_mcp_rules_nonempty() {
    let result = exochain_wasm::wasm_list_mcp_rules().expect("list_mcp_rules");
    let json = js_to_json(result);
    assert!(!json.as_array().unwrap().is_empty());
}

// ── Identity: PACE ───────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_pace_escalate_then_deescalate() {
    let escalated = exochain_wasm::wasm_pace_escalate(r#""Normal""#).expect("escalate");
    let escalated_str = js_str(escalated);
    assert_ne!(escalated_str.trim_matches('"'), "Normal");

    let deescalated = exochain_wasm::wasm_pace_deescalate(&escalated_str).expect("deescalate");
    let result = js_str(deescalated);
    assert_eq!(result.trim_matches('"'), "Normal");
}

// ── Consent: Bailment ────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_propose_bailment_creates_proposed_status() {
    let result = exochain_wasm::wasm_propose_bailment(
        "did:exo:bailor",
        "did:exo:bailee",
        b"data sharing terms v1",
        r#""Custody""#,
    )
    .expect("propose_bailment");
    let json = js_to_json(result);
    assert_eq!(json["status"].as_str().unwrap(), "Proposed");
}

#[wasm_bindgen_test]
fn test_bailment_not_active_when_proposed() {
    let bailment_json = js_str(
        exochain_wasm::wasm_propose_bailment(
            "did:exo:bailor",
            "did:exo:bailee",
            b"terms",
            r#""Processing""#,
        )
        .expect("propose"),
    );
    let active = exochain_wasm::wasm_bailment_is_active(&bailment_json).expect("is_active");
    assert!(!active);
}

// ── Emergency ────────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_create_emergency_action_round_trip() {
    let evidence_hex = "7".repeat(64);
    let policy = r#"{
        "max_monetary_cap_cents": 1000000,
        "allowed_actions": ["DataFreeze", "SystemHalt"],
        "ratification_window_ms": 3600000,
        "max_per_quarter": 5
    }"#;
    let result = exochain_wasm::wasm_create_emergency_action(
        r#""DataFreeze""#,
        "did:exo:operator",
        "Network anomaly detected",
        50000,
        &evidence_hex,
        policy,
        1_700_000_000_000,
    )
    .expect("create_emergency_action");
    let json = js_to_json(result);
    assert_eq!(
        json["justification"].as_str().unwrap(),
        "Network anomaly detected"
    );
    assert_eq!(json["ratification_status"].as_str().unwrap(), "Required");
}

// ── Legal: Records ────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_create_record_active_disposition() {
    let result = exochain_wasm::wasm_create_record(b"document contents", "Confidential", 365)
        .expect("create_record");
    let json = js_to_json(result);
    assert_eq!(json["retention_period_days"].as_u64().unwrap(), 365);
    assert_eq!(json["disposition"].as_str().unwrap(), "Active");
}
