// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! AVC bindings: subject-side action-signature production for
//! credential-bearing trust-receipt emission.
//!
//! An app holding a registered [`AutonomousVolitionCredential`] proves it
//! took an authorized action by signing the canonical action payload with
//! its subject key, then POSTing to the node's
//! `/api/v1/avc/receipts/emit`. The node re-verifies that signature, runs
//! [`exo_avc::validate_avc`], and — on `Allow` — signs and stores an
//! [`exo_avc::AvcTrustReceipt`].
//!
//! **Byte-parity is load-bearing.** The action signature the node accepts
//! is an Ed25519 signature over [`exo_avc::avc_action_signature_payload`]
//! (domain `exo.avc.action.v1`, canonical CBOR). This bridge **calls that
//! exact function** — it never reimplements the encoding — so the bytes a
//! JS caller signs are identical to the bytes the node verifies. The
//! `#[cfg(test)]` block below pins this against drift by returning bytes from
//! this bridge, signing them externally, and verifying through the node's own
//! verification path ([`exo_core::crypto::verify`] over the same payload).

use exo_avc::{
    AVC_MAX_SUPPORTED_PROTOCOL_VERSION, AVC_MIN_SUPPORTED_PROTOCOL_VERSION,
    AVC_PROTOCOL_DEPRECATION_WINDOW_DAYS, AVC_PROTOCOL_VERSION, AVC_SCHEMA_VERSION,
    AutonomousVolitionCredential, AvcActionRequest, AvcSubjectKind, AvcValidationRequest,
    DataClass, avc_action_signature_payload,
};
use exo_core::{PublicKey, Signature, Timestamp};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::serde_bridge::{MAX_JSON_INPUT_BYTES, from_json_str};

// ---------------------------------------------------------------------------
// Core logic — returns `Result<_, String>` so it is fully testable on the
// native target. `wasm_bindgen::JsValue` only functions on wasm32, so the
// two wasm exports below are thin wrappers that map `String -> JsValue` at
// the boundary; all real logic + every rejection path lives here and is
// exercised by the native test block.
// ---------------------------------------------------------------------------

const SUBJECT_PUBLIC_KEY_HEX_LEN: usize = 64;
const MAX_WASM_AVC_COLLECTION_ITEMS: usize = 256;
const MAX_WASM_AVC_STRING_BYTES: usize = 4_096;
const MAX_WASM_AVC_DID_BYTES: usize = 512;
const WASM_PACKAGE_NAME: &str = "@exochain/exochain-wasm";
const WASM_PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
struct WasmAvcProtocolInfo {
    protocol_version: u16,
    min_supported_protocol_version: u16,
    max_supported_protocol_version: u16,
    schema_version: u16,
    wasm_package_name: &'static str,
    wasm_package_version: &'static str,
    deprecation_window_days: u16,
}

fn ensure_json_input_at_most(value: &str, label: &str) -> Result<(), String> {
    if value.len() > MAX_JSON_INPUT_BYTES {
        return Err(format!("{label} json exceeds maximum size"));
    }
    Ok(())
}

fn parse_credential_json(value: &str) -> Result<AutonomousVolitionCredential, String> {
    ensure_json_input_at_most(value, "credential")?;
    from_json_str::<AutonomousVolitionCredential>(value)
        .map_err(|_| "credential json: JSON parse error".to_string())
}

fn avc_protocol_info_json_core() -> Result<String, String> {
    let info = WasmAvcProtocolInfo {
        protocol_version: AVC_PROTOCOL_VERSION,
        min_supported_protocol_version: AVC_MIN_SUPPORTED_PROTOCOL_VERSION,
        max_supported_protocol_version: AVC_MAX_SUPPORTED_PROTOCOL_VERSION,
        schema_version: AVC_SCHEMA_VERSION,
        wasm_package_name: WASM_PACKAGE_NAME,
        wasm_package_version: WASM_PACKAGE_VERSION,
        deprecation_window_days: AVC_PROTOCOL_DEPRECATION_WINDOW_DAYS,
    };
    serde_json::to_string(&info).map_err(|e| format!("avc protocol info json: {e}"))
}

fn parse_action_json(value: &str) -> Result<AvcActionRequest, String> {
    ensure_json_input_at_most(value, "action")?;
    from_json_str::<AvcActionRequest>(value)
        .map_err(|_| "action json: JSON parse error".to_string())
}

fn parse_signature_json(value: &str) -> Result<Signature, String> {
    ensure_json_input_at_most(value, "signature")?;
    from_json_str::<Signature>(value).map_err(|_| "signature json: JSON parse error".to_string())
}

fn ensure_len_at_most(label: &str, len: usize, max: usize) -> Result<(), String> {
    if len > max {
        return Err(format!("{label} contains {len} bytes, maximum is {max}"));
    }
    Ok(())
}

fn ensure_items_at_most(label: &str, len: usize) -> Result<(), String> {
    if len > MAX_WASM_AVC_COLLECTION_ITEMS {
        return Err(format!(
            "{label} contains {len} items, maximum is {MAX_WASM_AVC_COLLECTION_ITEMS}"
        ));
    }
    Ok(())
}

fn ensure_string_shape(label: &str, value: &str) -> Result<(), String> {
    ensure_len_at_most(label, value.len(), MAX_WASM_AVC_STRING_BYTES)
}

fn ensure_optional_string_shape(label: &str, value: Option<&String>) -> Result<(), String> {
    if let Some(value) = value {
        ensure_string_shape(label, value)?;
    }
    Ok(())
}

fn ensure_did_shape(label: &str, value: &exo_core::Did) -> Result<(), String> {
    ensure_len_at_most(label, value.as_str().len(), MAX_WASM_AVC_DID_BYTES)
}

fn ensure_optional_did_shape(label: &str, value: Option<&exo_core::Did>) -> Result<(), String> {
    if let Some(value) = value {
        ensure_did_shape(label, value)?;
    }
    Ok(())
}

fn ensure_string_items_shape(label: &str, values: &[String]) -> Result<(), String> {
    ensure_items_at_most(label, values.len())?;
    for value in values {
        ensure_string_shape(label, value)?;
    }
    Ok(())
}

fn ensure_did_items_shape(label: &str, values: &[exo_core::Did]) -> Result<(), String> {
    ensure_items_at_most(label, values.len())?;
    for value in values {
        ensure_did_shape(label, value)?;
    }
    Ok(())
}

fn ensure_data_class_shape(label: &str, value: &DataClass) -> Result<(), String> {
    if let DataClass::Custom(name) = value {
        ensure_string_shape(label, name)?;
    }
    Ok(())
}

fn ensure_optional_data_class_shape(label: &str, value: Option<&DataClass>) -> Result<(), String> {
    if let Some(value) = value {
        ensure_data_class_shape(label, value)?;
    }
    Ok(())
}

fn ensure_data_class_items_shape(label: &str, values: &[DataClass]) -> Result<(), String> {
    ensure_items_at_most(label, values.len())?;
    for value in values {
        ensure_data_class_shape(label, value)?;
    }
    Ok(())
}

fn ensure_subject_kind_shape(value: &AvcSubjectKind) -> Result<(), String> {
    match value {
        AvcSubjectKind::AiAgent {
            model_id,
            agent_version,
        } => {
            ensure_string_shape("subject_kind.model_id", model_id)?;
            ensure_optional_string_shape("subject_kind.agent_version", agent_version.as_ref())
        }
        AvcSubjectKind::AgentSwarm { swarm_id } => {
            ensure_string_shape("subject_kind.swarm_id", swarm_id)
        }
        AvcSubjectKind::Workflow { workflow_id } => {
            ensure_string_shape("subject_kind.workflow_id", workflow_id)
        }
        AvcSubjectKind::Service { service_id } => {
            ensure_string_shape("subject_kind.service_id", service_id)
        }
        AvcSubjectKind::Holon { holon_id } => {
            ensure_string_shape("subject_kind.holon_id", holon_id)
        }
        AvcSubjectKind::OrganizationUnit { unit_id } => {
            ensure_string_shape("subject_kind.unit_id", unit_id)
        }
        AvcSubjectKind::Unknown => Ok(()),
    }
}

fn ensure_credential_shape(value: &AutonomousVolitionCredential) -> Result<(), String> {
    ensure_did_shape("issuer_did", &value.issuer_did)?;
    ensure_did_shape("principal_did", &value.principal_did)?;
    ensure_did_shape("subject_did", &value.subject_did)?;
    ensure_optional_did_shape("holder_did", value.holder_did.as_ref())?;
    ensure_subject_kind_shape(&value.subject_kind)?;

    ensure_string_shape("delegated_intent.purpose", &value.delegated_intent.purpose)?;
    ensure_string_items_shape(
        "delegated_intent.allowed_objectives",
        &value.delegated_intent.allowed_objectives,
    )?;
    ensure_string_items_shape(
        "delegated_intent.prohibited_objectives",
        &value.delegated_intent.prohibited_objectives,
    )?;

    ensure_items_at_most(
        "authority_scope.permissions",
        value.authority_scope.permissions.len(),
    )?;
    ensure_string_items_shape("authority_scope.tools", &value.authority_scope.tools)?;
    ensure_data_class_items_shape(
        "authority_scope.data_classes",
        &value.authority_scope.data_classes,
    )?;
    ensure_did_items_shape(
        "authority_scope.counterparties",
        &value.authority_scope.counterparties,
    )?;
    ensure_string_items_shape(
        "authority_scope.jurisdictions",
        &value.authority_scope.jurisdictions,
    )?;

    ensure_optional_string_shape(
        "constraints.currency_code",
        value.constraints.currency_code.as_ref(),
    )?;
    ensure_string_items_shape(
        "constraints.forbidden_actions",
        &value.constraints.forbidden_actions,
    )?;
    ensure_string_items_shape(
        "constraints.emergency_stop_refs",
        &value.constraints.emergency_stop_refs,
    )?;
    ensure_items_at_most("consent_refs", value.consent_refs.len())?;
    ensure_items_at_most("policy_refs", value.policy_refs.len())?;
    Ok(())
}

fn ensure_action_shape(value: &AvcActionRequest) -> Result<(), String> {
    ensure_did_shape("action.actor_did", &value.actor_did)?;
    ensure_optional_string_shape("action.tool", value.tool.as_ref())?;
    ensure_optional_did_shape("action.target_did", value.target_did.as_ref())?;
    ensure_optional_data_class_shape("action.data_class", value.data_class.as_ref())?;
    ensure_optional_string_shape("action.action_name", value.action_name.as_ref())?;
    ensure_optional_string_shape(
        "action.requested_currency_code",
        value.requested_currency_code.as_ref(),
    )?;
    if let Some(approval) = &value.human_approval {
        ensure_did_shape("action.human_approval.approver_did", &approval.approver_did)?;
    }
    Ok(())
}

fn parse_subject_public_key_hex(value: &str) -> Result<Option<PublicKey>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() != SUBJECT_PUBLIC_KEY_HEX_LEN {
        return Err("subject_public_key_hex must be 64 hex characters".to_string());
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("subject_public_key_hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "subject_public_key_hex must be 32 bytes".to_string())?;
    if arr.iter().all(|byte| *byte == 0) {
        return Err("subject_public_key_hex must not be all-zero".to_string());
    }
    Ok(Some(PublicKey::from_bytes(arr)))
}

/// Build a caller-supplied HLC timestamp; reject the zero sentinel (the
/// bridge never reads wall-clock — `now` must come from the caller).
fn parse_now(physical_ms: u64, logical: u32) -> Result<Timestamp, String> {
    if physical_ms == 0 {
        return Err(
            "validation_now timestamp must be a caller-supplied HLC (physical_ms != 0)".to_string(),
        );
    }
    Ok(Timestamp::new(physical_ms, logical))
}

/// Core of [`wasm_avc_action_signing_payload`] — returns canonical CBOR bytes
/// for signing by external key management.
fn action_signing_payload_core(
    credential_json: &str,
    action_json: &str,
    now_physical_ms: u64,
    now_logical: u32,
) -> Result<Vec<u8>, String> {
    let credential = parse_credential_json(credential_json)?;
    let action = parse_action_json(action_json)?;
    ensure_credential_shape(&credential)?;
    ensure_action_shape(&action)?;
    let now = parse_now(now_physical_ms, now_logical)?;
    avc_action_signature_payload(&credential, &action, &now)
        .map_err(|e| format!("avc action signature payload: {e}"))
}

/// Core of [`wasm_avc_build_emit_request_from_signature`] — returns the full
/// POST body JSON after the caller signs the canonical payload outside WASM.
fn build_emit_request_from_signature_core(
    credential_json: &str,
    action_json: &str,
    now_physical_ms: u64,
    now_logical: u32,
    subject_signature_json: &str,
    subject_public_key_hex: &str,
) -> Result<String, String> {
    let credential = parse_credential_json(credential_json)?;
    let action = parse_action_json(action_json)?;
    ensure_credential_shape(&credential)?;
    ensure_action_shape(&action)?;
    let now = parse_now(now_physical_ms, now_logical)?;
    let signature = parse_signature_json(subject_signature_json)?;
    if signature.is_empty() {
        return Err("subject_signature_json must not be empty".to_string());
    }
    let subject_public_key = parse_subject_public_key_hex(subject_public_key_hex)?;

    // Reconstruct the canonical payload so request building fails before
    // transport if the credential/action/timestamp tuple cannot be signed.
    avc_action_signature_payload(&credential, &action, &now)
        .map_err(|e| format!("avc action signature payload: {e}"))?;

    // Inner validation request reuses the canonical exo-avc struct so its
    // shape never drifts from what the node deserializes.
    let validation = AvcValidationRequest {
        credential,
        action: Some(action),
        now,
    };

    // The outer 3-field wrapper mirrors the node's EmitReceiptRequest
    // (defined in exo-node, not importable here). Keys + optionality match.
    let mut body = serde_json::Map::new();
    body.insert(
        "validation".to_string(),
        serde_json::to_value(&validation).map_err(|e| format!("validation json: {e}"))?,
    );
    body.insert(
        "subject_signature".to_string(),
        serde_json::to_value(&signature).map_err(|e| format!("subject_signature json: {e}"))?,
    );
    if let Some(pk) = subject_public_key {
        body.insert(
            "subject_public_key".to_string(),
            serde_json::to_value(pk).map_err(|e| format!("subject_public_key json: {e}"))?,
        );
    }

    serde_json::to_string(&serde_json::Value::Object(body))
        .map_err(|e| format!("emit request json: {e}"))
}

// ---------------------------------------------------------------------------
// WASM boundary — thin wrappers. JsValue only constructed here.
// ---------------------------------------------------------------------------

/// Legacy raw subject-secret signing entry point.
///
/// This fails closed because public WASM cannot be the subject-key custody
/// boundary for AVC receipts. Use [`wasm_avc_action_signing_payload`], sign the
/// returned canonical CBOR bytes with external key management, then call
/// [`wasm_avc_build_emit_request_from_signature`].
#[wasm_bindgen]
pub fn wasm_avc_sign_action(
    _credential_json: &str,
    _action_json: &str,
    _now_physical_ms: u64,
    _now_logical: u32,
) -> Result<String, JsValue> {
    Err(JsValue::from_str(
        "raw AVC subject-key signing is disabled at the WASM boundary; use wasm_avc_action_signing_payload, sign externally, then call wasm_avc_build_emit_request_from_signature",
    ))
}

/// Return the canonical `exo.avc.action.v1` CBOR payload bytes for an AVC
/// subject action. The caller signs these bytes outside WASM.
#[wasm_bindgen]
pub fn wasm_avc_action_signing_payload(
    credential_json: &str,
    action_json: &str,
    now_physical_ms: u64,
    now_logical: u32,
) -> Result<Vec<u8>, JsValue> {
    action_signing_payload_core(credential_json, action_json, now_physical_ms, now_logical)
        .map_err(|e| JsValue::from_str(&e))
}

/// Return explicit AVC protocol/package compatibility metadata for clients.
#[wasm_bindgen]
pub fn wasm_avc_protocol_info() -> Result<String, JsValue> {
    avc_protocol_info_json_core().map_err(|e| JsValue::from_str(&e))
}

/// Legacy raw subject-secret request builder.
///
/// This fails closed for the same reason as [`wasm_avc_sign_action`].
#[wasm_bindgen]
pub fn wasm_avc_build_emit_request(
    _credential_json: &str,
    _action_json: &str,
    _now_physical_ms: u64,
    _now_logical: u32,
    _include_public_key: bool,
) -> Result<String, JsValue> {
    Err(JsValue::from_str(
        "raw AVC subject-key emit request building is disabled at the WASM boundary; use wasm_avc_action_signing_payload, sign externally, then call wasm_avc_build_emit_request_from_signature",
    ))
}

/// Build the full `POST /api/v1/avc/receipts/emit` request body from an
/// externally produced signature:
/// `{ validation: { credential, action, now }, subject_signature,
/// subject_public_key? }`. The app POSTs this JSON verbatim.
///
/// `subject_public_key_hex` is optional; pass an empty string to omit it. For
/// registered credentials this should be omitted so the node resolves the actor
/// key from its registry.
#[wasm_bindgen]
pub fn wasm_avc_build_emit_request_from_signature(
    credential_json: &str,
    action_json: &str,
    now_physical_ms: u64,
    now_logical: u32,
    subject_signature_json: &str,
    subject_public_key_hex: &str,
) -> Result<String, JsValue> {
    build_emit_request_from_signature_core(
        credential_json,
        action_json,
        now_physical_ms,
        now_logical,
        subject_signature_json,
        subject_public_key_hex,
    )
    .map_err(|e| JsValue::from_str(&e))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_authority::permission::Permission;
    use exo_avc::{
        AuthorityScope, AutonomyLevel, AvcConstraints, AvcSubjectKind, DataClass, DelegatedIntent,
        issue_avc,
    };
    use exo_core::{Did, Hash256, Timestamp, crypto};

    use super::*;

    fn did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("did")
    }

    /// A registered-shaped credential whose subject is `subject_did`,
    /// self-issued for the test (issuer == subject is fine — action signing
    /// is over credential_id + action + now, independent of the issuer sig).
    fn test_credential(
        subject_did: &Did,
        issuer_secret: &exo_core::SecretKey,
    ) -> AutonomousVolitionCredential {
        let draft = exo_avc::AvcDraft {
            schema_version: exo_avc::AVC_SCHEMA_VERSION,
            issuer_did: subject_did.clone(),
            principal_did: subject_did.clone(),
            subject_did: subject_did.clone(),
            holder_did: None,
            subject_kind: AvcSubjectKind::Service {
                service_id: "test-svc".into(),
            },
            created_at: Timestamp::new(1_000_000, 0),
            expires_at: Some(Timestamp::new(9_000_000, 0)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([7u8; 32]),
                purpose: "byte-parity test".into(),
                allowed_objectives: vec!["test".into()],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::ExecuteWithinBounds,
                delegation_allowed: true,
            },
            authority_scope: AuthorityScope {
                permissions: vec![Permission::Read, Permission::Write],
                tools: vec!["test-tool".into()],
                data_classes: vec![DataClass::Public, DataClass::Internal],
                counterparties: vec![],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints::permissive(),
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        };
        issue_avc(draft, |bytes| crypto::sign(bytes, issuer_secret)).expect("issue credential")
    }

    fn test_action(actor_did: &Did) -> AvcActionRequest {
        AvcActionRequest {
            action_id: Hash256::from_bytes([3u8; 32]),
            actor_did: actor_did.clone(),
            requested_permission: Permission::Write,
            tool: Some("test-tool".into()),
            target_did: None,
            data_class: Some(DataClass::Internal),
            estimated_budget_minor_units: None,
            estimated_risk_bp: None,
            human_approval: None,
            requires_human_approval: false,
            action_name: Some("test-action".into()),
            commercially_gated: false,
            payment_evidence_hash: None,
            requested_currency_code: None,
            session_spent_minor_units: None,
        }
    }

    fn signature_json_for_payload(payload: &[u8], subject_sk: &exo_core::SecretKey) -> String {
        serde_json::to_string(&crypto::sign(payload, subject_sk)).expect("signature json")
    }

    fn assert_error_contains<T>(result: Result<T, String>, needle: &str) {
        match result {
            Ok(_) => panic!("operation must fail closed"),
            Err(err) => assert!(
                err.contains(needle),
                "expected error to contain {needle:?}, got {err:?}"
            ),
        }
    }

    /// THE byte-parity proof. The bridge returns exactly the canonical payload
    /// reconstructed by the node's `avc_action_signature_payload`.
    #[test]
    fn bridge_action_payload_matches_node_verification_path() {
        let (_subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("byte-parity-subject");
        let credential = test_credential(&subject_did, &subject_sk);
        let action = test_action(&subject_did);
        let now = Timestamp::new(1_500_000, 0);

        let node_payload =
            avc_action_signature_payload(&credential, &action, &now).expect("node payload");
        let bridge_payload = action_signing_payload_core(
            &serde_json::to_string(&credential).unwrap(),
            &serde_json::to_string(&action).unwrap(),
            now.physical_ms,
            now.logical,
        )
        .expect("bridge payload");
        assert_eq!(
            bridge_payload, node_payload,
            "bridge payload bytes must match the node's canonical action payload"
        );
    }

    /// The payload entry point round-trips through JSON and can be signed by an
    /// external signer for node acceptance.
    #[test]
    fn avc_action_payload_entrypoint_supports_external_signature() {
        let (subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("entrypoint-subject");
        let credential = test_credential(&subject_did, &subject_sk);
        let action = test_action(&subject_did);

        let credential_json = serde_json::to_string(&credential).unwrap();
        let action_json = serde_json::to_string(&action).unwrap();
        let payload = action_signing_payload_core(&credential_json, &action_json, 2_000_000, 0)
            .expect("action payload");
        let signature: Signature =
            serde_json::from_str(&signature_json_for_payload(&payload, &subject_sk))
                .expect("sig parse");

        assert!(
            crypto::verify(&payload, &signature, &subject_pk),
            "externally signed wasm_avc_action_signing_payload output must verify"
        );
    }

    #[test]
    fn avc_protocol_info_exposes_supported_range_and_package_name() {
        let info: serde_json::Value =
            serde_json::from_str(&avc_protocol_info_json_core().expect("protocol info json"))
                .expect("protocol info parses");
        assert_eq!(info["protocol_version"], AVC_PROTOCOL_VERSION);
        assert_eq!(
            info["min_supported_protocol_version"],
            AVC_MIN_SUPPORTED_PROTOCOL_VERSION
        );
        assert_eq!(
            info["max_supported_protocol_version"],
            AVC_MAX_SUPPORTED_PROTOCOL_VERSION
        );
        assert_eq!(info["schema_version"], AVC_SCHEMA_VERSION);
        assert_eq!(info["wasm_package_name"], WASM_PACKAGE_NAME);
        assert_eq!(info["wasm_package_version"], WASM_PACKAGE_VERSION);
        assert_eq!(
            info["deprecation_window_days"],
            AVC_PROTOCOL_DEPRECATION_WINDOW_DAYS
        );
    }

    /// `wasm_avc_build_emit_request_from_signature` emits the wrapper the node expects.
    #[test]
    fn emit_request_has_expected_shape() {
        let (subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("emit-shape-subject");
        let credential = test_credential(&subject_did, &subject_sk);
        let action = test_action(&subject_did);

        let credential_json = serde_json::to_string(&credential).unwrap();
        let action_json = serde_json::to_string(&action).unwrap();
        let payload = action_signing_payload_core(&credential_json, &action_json, 3_000_000, 0)
            .expect("action payload");
        let signature_json = signature_json_for_payload(&payload, &subject_sk);

        let body = build_emit_request_from_signature_core(
            &credential_json,
            &action_json,
            3_000_000,
            0,
            &signature_json,
            "",
        )
        .expect("build emit request");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("validation").is_some(), "has validation");
        assert!(
            v.get("subject_signature").is_some(),
            "has subject_signature"
        );
        assert!(
            v.get("subject_public_key").is_none(),
            "omits subject_public_key when not requested"
        );
        assert!(
            v["validation"].get("credential").is_some(),
            "validation.credential"
        );
        assert!(v["validation"].get("action").is_some(), "validation.action");
        assert!(v["validation"].get("now").is_some(), "validation.now");
        assert_eq!(v["subject_signature"].to_string(), signature_json);

        let body_with_key = build_emit_request_from_signature_core(
            &credential_json,
            &action_json,
            3_000_000,
            0,
            &signature_json,
            &hex::encode(subject_pk.as_bytes()),
        )
        .expect("build emit request with key");
        let with_key: serde_json::Value = serde_json::from_str(&body_with_key).unwrap();
        assert!(
            with_key.get("subject_public_key").is_some(),
            "includes subject_public_key when explicitly supplied"
        );
    }

    /// Deterministic vector emitter. Ed25519 is deterministic (RFC 8032),
    /// and `issue_avc` + `avc_action_signature_payload` are canonical, so a
    /// fixed subject key + fixed credential + fixed action + fixed `now`
    /// yields a fixed signature. Run with `--ignored --nocapture` to print
    /// the checked-in vector at `test/avc_action_vector.json`.
    #[test]
    #[ignore]
    fn emit_deterministic_vector() {
        let subject_sk = exo_core::SecretKey::from_bytes([0x11u8; 32]);
        let issuer_sk = exo_core::SecretKey::from_bytes([0x22u8; 32]);
        let subject_kp = crypto::KeyPair::from_secret_bytes([0x11u8; 32]).unwrap();
        let subject_pk = *subject_kp.public_key();
        let subject_did = did("vector-subject");
        let credential = test_credential(&subject_did, &issuer_sk);
        let action = test_action(&subject_did);

        let credential_json = serde_json::to_string(&credential).unwrap();
        let action_json = serde_json::to_string(&action).unwrap();
        let payload =
            action_signing_payload_core(&credential_json, &action_json, 1_700_000, 5).unwrap();
        let sig_json = signature_json_for_payload(&payload, &subject_sk);

        let vector = serde_json::json!({
            "_comment": "Byte-parity vector for wasm_avc_action_signing_payload. Inputs are fixed; \
                         Ed25519 is deterministic so expected_signature is exact. \
                         Rust and bridge_verification.mjs assert the binding reproduces \
                         the node's avc_action_signature_payload bytes and an external \
                         signature verifies against those bytes.",
            "credential_json": credential_json,
            "action_json": action_json,
            "now_physical_ms": 1_700_000u64,
            "now_logical": 5u32,
            "expected_payload_hex": hex::encode(&payload),
            "subject_public_key_hex": hex::encode(subject_pk.as_bytes()),
            "expected_signature_json": sig_json,
        });
        println!(
            "AVC_VECTOR_JSON={}",
            serde_json::to_string_pretty(&vector).unwrap()
        );
    }

    /// Consume the checked-in vector: the binding must reproduce the node's
    /// canonical action payload, and an external signature over those bytes must
    /// match the checked-in signature and verify.
    #[test]
    fn checked_in_vector_reproduces_and_verifies() {
        let raw = include_str!("../test/avc_action_vector.json");
        let v: serde_json::Value = serde_json::from_str(raw).expect("vector json");

        let credential_json = v["credential_json"].as_str().unwrap();
        let action_json = v["action_json"].as_str().unwrap();
        let now_ms = v["now_physical_ms"].as_u64().unwrap();
        let now_logical = v["now_logical"].as_u64().unwrap() as u32;
        let expected_payload_hex = v["expected_payload_hex"].as_str().unwrap();
        let expected_sig_json = v["expected_signature_json"].as_str().unwrap();
        let subject_pk_hex = v["subject_public_key_hex"].as_str().unwrap();

        let credential: AutonomousVolitionCredential =
            serde_json::from_str(credential_json).unwrap();
        let action: AvcActionRequest = serde_json::from_str(action_json).unwrap();
        let now = Timestamp::new(now_ms, now_logical);
        let bridge_payload =
            action_signing_payload_core(credential_json, action_json, now_ms, now_logical)
                .expect("payload");
        let node_payload = avc_action_signature_payload(&credential, &action, &now).unwrap();
        assert_eq!(
            bridge_payload, node_payload,
            "binding must reproduce the node's checked-in action payload exactly"
        );
        assert_eq!(
            hex::encode(&bridge_payload),
            expected_payload_hex,
            "bridge payload must match the checked-in expected payload bytes"
        );

        let signature: Signature = serde_json::from_str(expected_sig_json).unwrap();
        let pk_bytes: [u8; 32] = hex::decode(subject_pk_hex).unwrap().try_into().unwrap();
        let subject_pk = exo_core::PublicKey::from_bytes(pk_bytes);
        assert!(
            crypto::verify(&node_payload, &signature, &subject_pk),
            "checked-in vector signature must verify against the node payload"
        );
    }

    /// Zero/empty inputs are rejected loudly, never silently request-built.
    #[test]
    fn rejects_zero_timestamp_and_bad_signature_or_public_key() {
        let (_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("reject-subject");
        let credential = test_credential(&subject_did, &subject_sk);
        let action = test_action(&subject_did);
        let credential_json = serde_json::to_string(&credential).unwrap();
        let action_json = serde_json::to_string(&action).unwrap();
        let payload =
            action_signing_payload_core(&credential_json, &action_json, 1_000, 0).expect("payload");
        let signature_json = signature_json_for_payload(&payload, &subject_sk);

        assert!(
            action_signing_payload_core(&credential_json, &action_json, 0, 0).is_err(),
            "zero timestamp must be rejected"
        );
        assert!(
            build_emit_request_from_signature_core(
                &credential_json,
                &action_json,
                1_000,
                0,
                r#""Empty""#,
                "",
            )
            .is_err(),
            "bad signature JSON must be rejected"
        );
        assert!(
            build_emit_request_from_signature_core(
                &credential_json,
                &action_json,
                1_000,
                0,
                &signature_json,
                "00",
            )
            .is_err(),
            "short subject public key must be rejected"
        );
    }

    #[test]
    fn avc_action_payload_rejects_oversized_credential_json_before_parse() {
        let oversized_credential_json = format!(
            "{{\"pad\":\"{}\"}}",
            "x".repeat(crate::serde_bridge::MAX_JSON_INPUT_BYTES)
        );
        assert_error_contains(
            action_signing_payload_core(&oversized_credential_json, "{}", 1_000, 0),
            "credential json exceeds maximum size",
        );
    }

    #[test]
    fn avc_emit_request_rejects_oversized_signature_json_before_parse() {
        let (_subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("oversized-signature-subject");
        let credential = test_credential(&subject_did, &subject_sk);
        let action = test_action(&subject_did);
        let credential_json = serde_json::to_string(&credential).unwrap();
        let action_json = serde_json::to_string(&action).unwrap();
        let oversized_signature_json = format!(
            "\"{}\"",
            "a".repeat(crate::serde_bridge::MAX_JSON_INPUT_BYTES)
        );

        assert_error_contains(
            build_emit_request_from_signature_core(
                &credential_json,
                &action_json,
                1_000,
                0,
                &oversized_signature_json,
                "",
            ),
            "signature json exceeds maximum size",
        );
    }

    #[test]
    fn avc_action_payload_rejects_unbounded_collection_counts() {
        let (_subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("collection-bound-subject");
        let mut credential = test_credential(&subject_did, &subject_sk);
        credential.authority_scope.tools = (0..257).map(|idx| format!("tool-{idx}")).collect();
        let action = test_action(&subject_did);

        assert_error_contains(
            action_signing_payload_core(
                &serde_json::to_string(&credential).unwrap(),
                &serde_json::to_string(&action).unwrap(),
                1_000,
                0,
            ),
            "authority_scope.tools",
        );
    }

    #[test]
    fn avc_action_payload_rejects_unbounded_free_form_strings() {
        let (_subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("string-bound-subject");
        let mut credential = test_credential(&subject_did, &subject_sk);
        credential.delegated_intent.purpose = "x".repeat(4_097);
        let action = test_action(&subject_did);

        assert_error_contains(
            action_signing_payload_core(
                &serde_json::to_string(&credential).unwrap(),
                &serde_json::to_string(&action).unwrap(),
                1_000,
                0,
            ),
            "delegated_intent.purpose",
        );
    }

    #[test]
    fn avc_emit_request_rejects_oversized_subject_public_key_hex_before_decode() {
        let (_subject_pk, subject_sk) = crypto::generate_keypair();
        let subject_did = did("public-key-bound-subject");
        let credential = test_credential(&subject_did, &subject_sk);
        let action = test_action(&subject_did);
        let credential_json = serde_json::to_string(&credential).unwrap();
        let action_json = serde_json::to_string(&action).unwrap();
        let payload =
            action_signing_payload_core(&credential_json, &action_json, 1_000, 0).expect("payload");
        let signature_json = signature_json_for_payload(&payload, &subject_sk);

        assert_error_contains(
            build_emit_request_from_signature_core(
                &credential_json,
                &action_json,
                1_000,
                0,
                &signature_json,
                &"ab".repeat(65),
            ),
            "subject_public_key_hex must be 64 hex characters",
        );
    }
}
