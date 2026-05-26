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

//! Gatekeeper bindings: CGR combinator algebra, kernel adjudication, invariants

use std::collections::BTreeMap;

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Deserializable mirror of `InvariantContext` for WASM callers.
///
/// All fields map 1-to-1 onto `exo_gatekeeper::invariants::InvariantContext`.
/// Booleans default to safe values (false / true for human_override_preserved).
///
/// The public WASM boundary cannot prove that caller-provided trusted key maps
/// came from DID resolution. Non-empty trusted key maps are deserialized only so
/// `wasm_enforce_invariants` can fail closed with an explicit violation.
#[derive(serde::Deserialize)]
struct WasmInvariantRequest {
    actor: exo_core::Did,
    actor_roles: Vec<exo_gatekeeper::types::Role>,
    bailment_state: exo_gatekeeper::types::BailmentState,
    consent_records: Vec<exo_gatekeeper::types::ConsentRecord>,
    authority_chain: exo_gatekeeper::types::AuthorityChain,
    #[serde(default)]
    is_self_grant: bool,
    #[serde(default = "default_true")]
    human_override_preserved: bool,
    #[serde(default)]
    kernel_modification_attempted: bool,
    quorum_evidence: Option<exo_gatekeeper::types::QuorumEvidence>,
    provenance: Option<exo_gatekeeper::types::Provenance>,
    #[serde(default)]
    actor_permissions: exo_gatekeeper::types::PermissionSet,
    #[serde(default)]
    requested_permissions: exo_gatekeeper::types::PermissionSet,
    #[serde(default)]
    trusted_authority_keys: exo_gatekeeper::types::TrustedAuthorityKeys,
    #[serde(default)]
    trusted_provenance_keys: exo_gatekeeper::types::TrustedProvenanceKeys,
}

fn default_true() -> bool {
    true
}

fn gatekeeper_boundary_error(operation: &'static str) -> JsValue {
    JsValue::from_str(operation)
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], JsValue> {
    let bytes = hex::decode(value).map_err(|e| JsValue::from_str(&format!("{label} hex: {e}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        JsValue::from_str(&format!("{label} must be {N} bytes, got {}", bytes.len()))
    })
}

fn holon_state_label(state: exo_gatekeeper::holon::HolonState) -> &'static str {
    match state {
        exo_gatekeeper::holon::HolonState::Idle => "idle",
        exo_gatekeeper::holon::HolonState::Executing => "executing",
        exo_gatekeeper::holon::HolonState::Suspended => "suspended",
        exo_gatekeeper::holon::HolonState::Terminated => "terminated",
    }
}

/// Reduce a combinator expression with the given input
#[wasm_bindgen]
pub fn wasm_reduce_combinator(combinator_json: &str, input_json: &str) -> Result<JsValue, JsValue> {
    let combinator: exo_gatekeeper::Combinator = from_json_str(combinator_json)?;
    let input: exo_gatekeeper::CombinatorInput = from_json_str(input_json)?;
    let output = exo_gatekeeper::combinator::reduce(&combinator, &input)
        .map_err(|_| gatekeeper_boundary_error("combinator reduction failed"))?;
    to_js_value(&output)
}

/// Enforce all constitutional invariants against the provided context.
///
/// Accepts a JSON object matching `WasmInvariantRequest` and delegates
/// to `exo_gatekeeper::invariants::enforce_all`. Returns a JSON object:
/// `{ "passed": bool, "violations": [...] }`.
#[wasm_bindgen]
pub fn wasm_enforce_invariants(request_json: &str) -> Result<JsValue, JsValue> {
    let req: WasmInvariantRequest = from_json_str(request_json)?;
    to_js_value(&enforce_invariants_response(req))
}

fn enforce_invariants_response(req: WasmInvariantRequest) -> serde_json::Value {
    let boundary_violations = caller_supplied_trusted_key_violations(&req);
    if !boundary_violations.is_empty() {
        return serde_json::json!({
            "passed": false,
            "violations": boundary_violations
        });
    }

    let context = exo_gatekeeper::invariants::InvariantContext {
        actor: req.actor,
        actor_roles: req.actor_roles,
        bailment_state: req.bailment_state,
        consent_records: req.consent_records,
        authority_chain: req.authority_chain,
        is_self_grant: req.is_self_grant,
        human_override_preserved: req.human_override_preserved,
        kernel_modification_attempted: req.kernel_modification_attempted,
        quorum_evidence: req.quorum_evidence,
        provenance: req.provenance,
        actor_permissions: req.actor_permissions,
        requested_permissions: req.requested_permissions,
        trusted_authority_keys: req.trusted_authority_keys,
        trusted_provenance_keys: req.trusted_provenance_keys,
    };

    let engine = exo_gatekeeper::InvariantEngine::all();

    match exo_gatekeeper::invariants::enforce_all(&engine, &context) {
        Ok(()) => serde_json::json!({
            "passed": true,
            "violations": []
        }),
        Err(violations) => serde_json::json!({
            "passed": false,
            "violations": violations
        }),
    }
}

fn caller_supplied_trusted_key_violations(
    req: &WasmInvariantRequest,
) -> Vec<exo_gatekeeper::invariants::InvariantViolation> {
    let mut violations = Vec::new();

    if !req.trusted_authority_keys.is_empty() {
        violations.push(exo_gatekeeper::invariants::InvariantViolation {
            invariant: exo_gatekeeper::invariants::ConstitutionalInvariant::AuthorityChainValid,
            description: "WASM invariant boundary cannot trust caller-supplied \
                trusted_authority_keys; submit authority-bearing requests to a core runtime \
                adapter with trusted DID resolution"
                .to_string(),
            evidence: vec!["field: trusted_authority_keys".to_string()],
        });
    }

    if !req.trusted_provenance_keys.is_empty() {
        violations.push(exo_gatekeeper::invariants::InvariantViolation {
            invariant: exo_gatekeeper::invariants::ConstitutionalInvariant::ProvenanceVerifiable,
            description: "WASM invariant boundary cannot trust caller-supplied \
                trusted_provenance_keys; submit provenance-bearing requests to a core runtime \
                adapter with trusted DID resolution"
                .to_string(),
            evidence: vec!["field: trusted_provenance_keys".to_string()],
        });
    }

    violations
}

/// Compute the canonical BLAKE3/CBOR digest for governance monitor findings.
#[wasm_bindgen]
pub fn wasm_governance_findings_digest(findings_json: &str) -> Result<String, JsValue> {
    let findings: serde_json::Value = from_json_str(findings_json)?;
    let digest = exo_gatekeeper::governance_monitor::governance_findings_digest(&findings)
        .map_err(|_| gatekeeper_boundary_error("governance findings digest failed"))?;
    Ok(hex::encode(digest.as_bytes()))
}

/// Compute the domain-separated governance attestation message digest.
#[wasm_bindgen]
pub fn wasm_governance_attestation_signature_message_digest(
    signer_did: &str,
    findings_json: &str,
) -> Result<String, JsValue> {
    let signer_did = exo_core::Did::new(signer_did)
        .map_err(|_| gatekeeper_boundary_error("invalid governance attestation signer DID"))?;
    let findings: serde_json::Value = from_json_str(findings_json)?;
    let findings_digest = exo_gatekeeper::governance_monitor::governance_findings_digest(&findings)
        .map_err(|_| gatekeeper_boundary_error("governance findings digest failed"))?;
    let message_digest =
        exo_gatekeeper::governance_monitor::governance_attestation_signature_message_digest(
            &signer_did,
            &findings_digest,
        )
        .map_err(|_| gatekeeper_boundary_error("governance attestation message digest failed"))?;
    Ok(hex::encode(message_digest.as_bytes()))
}

/// Verify a governance monitor attestation before persistence.
#[wasm_bindgen]
pub fn wasm_verify_governance_attestation_with_trusted_keys(
    signer_did: &str,
    findings_json: &str,
    signature_json: &str,
    trusted_signer_keys_json: &str,
) -> Result<bool, JsValue> {
    let signer_did = exo_core::Did::new(signer_did)
        .map_err(|_| gatekeeper_boundary_error("invalid governance attestation signer DID"))?;
    let trusted_signer_keys = parse_trusted_governance_attestation_keys(trusted_signer_keys_json)?;
    let signer_public_key = trusted_signer_keys
        .get(&signer_did)
        .ok_or_else(|| gatekeeper_boundary_error("governance attestation signer is not trusted"))?;
    verify_governance_attestation_with_key(
        &signer_did,
        findings_json,
        signature_json,
        signer_public_key,
    )
}

fn parse_trusted_governance_attestation_keys(
    trusted_signer_keys_json: &str,
) -> Result<BTreeMap<exo_core::Did, exo_core::PublicKey>, JsValue> {
    let raw_keys: BTreeMap<String, String> = from_json_str(trusted_signer_keys_json)?;
    if raw_keys.is_empty() {
        return Err(gatekeeper_boundary_error(
            "governance attestation trusted signer registry is empty",
        ));
    }

    let mut trusted_signer_keys = BTreeMap::new();
    for (signer_did, public_key_hex) in raw_keys {
        let signer_did = exo_core::Did::new(&signer_did).map_err(|_| {
            gatekeeper_boundary_error("invalid governance attestation trusted signer DID")
        })?;
        let public_key = exo_core::PublicKey::from_bytes(decode_fixed_hex(
            &public_key_hex,
            "governance attestation trusted signer public key",
        )?);
        trusted_signer_keys.insert(signer_did, public_key);
    }

    Ok(trusted_signer_keys)
}

fn verify_governance_attestation_with_key(
    signer_did: &exo_core::Did,
    findings_json: &str,
    signature_json: &str,
    signer_public_key: &exo_core::PublicKey,
) -> Result<bool, JsValue> {
    let findings: serde_json::Value = from_json_str(findings_json)?;
    let digest = exo_gatekeeper::governance_monitor::governance_findings_digest(&findings)
        .map_err(|_| gatekeeper_boundary_error("governance findings digest failed"))?;
    let signature: exo_core::Signature = from_json_str(signature_json)?;
    let attestation = exo_gatekeeper::governance_monitor::GovernanceAttestation {
        signer_did: signer_did.clone(),
        findings_digest: digest,
        signature,
    };

    exo_gatekeeper::governance_monitor::verify_attestation(
        &attestation,
        signer_public_key,
        &findings,
    )
    .map(|()| true)
    .map_err(|_| gatekeeper_boundary_error("governance attestation rejected"))
}

/// Build a deterministic valid invariant request fixture for external
/// health checks. The fixture signs only its own canonical validation
/// payloads and never accepts caller-supplied secret material.
#[wasm_bindgen]
pub fn wasm_validation_invariant_request() -> Result<JsValue, JsValue> {
    use exo_gatekeeper::{
        authority_link_signature_message, provenance_signature_message,
        types::{
            AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, PermissionSet, Provenance,
            TrustedAuthorityKeys, TrustedProvenanceKeys,
        },
    };

    let authority_keypair =
        exo_core::crypto::KeyPair::from_secret_bytes([0x31; 32]).map_err(|_| {
            gatekeeper_boundary_error("validation invariant authority key construction failed")
        })?;
    let provenance_keypair =
        exo_core::crypto::KeyPair::from_secret_bytes([0x32; 32]).map_err(|_| {
            gatekeeper_boundary_error("validation invariant provenance key construction failed")
        })?;

    let actor = exo_core::Did::new("did:exo:validation-actor")
        .map_err(|_| gatekeeper_boundary_error("validation invariant actor DID failed"))?;
    let grantor = exo_core::Did::new("did:exo:validation-root")
        .map_err(|_| gatekeeper_boundary_error("validation invariant grantor DID failed"))?;
    let permissions = PermissionSet::default();
    let mut authority_link = AuthorityLink {
        grantor: grantor.clone(),
        grantee: actor.clone(),
        permissions: permissions.clone(),
        signature: Vec::new(),
        grantor_public_key: Some(authority_keypair.public_key().as_bytes().to_vec()),
    };
    let authority_message = authority_link_signature_message(&authority_link)
        .map_err(|_| gatekeeper_boundary_error("validation authority signature payload failed"))?;
    authority_link.signature = authority_keypair
        .sign(authority_message.as_bytes())
        .to_bytes()
        .to_vec();

    let mut provenance = Provenance {
        actor: actor.clone(),
        timestamp: "2026-05-07T00:00:00.000Z".to_string(),
        action_hash: vec![0x41; 32],
        signature: Vec::new(),
        public_key: Some(provenance_keypair.public_key().as_bytes().to_vec()),
        voice_kind: None,
        independence: None,
        review_order: None,
    };
    let provenance_message = provenance_signature_message(&provenance)
        .map_err(|_| gatekeeper_boundary_error("validation provenance signature payload failed"))?;
    provenance.signature = provenance_keypair
        .sign(provenance_message.as_bytes())
        .to_bytes()
        .to_vec();
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(
        grantor,
        vec![authority_keypair.public_key().as_bytes().to_vec()],
    );
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(
        actor.clone(),
        vec![provenance_keypair.public_key().as_bytes().to_vec()],
    );

    to_js_value(&serde_json::json!({
        "actor": actor.clone(),
        "actor_roles": [],
        "bailment_state": BailmentState::Active {
            bailor: exo_core::Did::new("did:exo:validation-bailor")
                .map_err(|_| gatekeeper_boundary_error("validation bailor DID failed"))?,
            bailee: actor.clone(),
            scope: "validation-scope".to_string(),
        },
        "consent_records": [ConsentRecord {
            subject: exo_core::Did::new("did:exo:validation-bailor")
                .map_err(|_| gatekeeper_boundary_error("validation subject DID failed"))?,
            granted_to: actor.clone(),
            scope: "validation-scope".to_string(),
            active: true,
        }],
        "authority_chain": AuthorityChain {
            links: vec![authority_link],
        },
        "is_self_grant": false,
        "human_override_preserved": true,
        "kernel_modification_attempted": false,
        "quorum_evidence": null,
        "provenance": provenance,
        "actor_permissions": permissions,
        "requested_permissions": PermissionSet::default(),
        "trusted_authority_keys": trusted_authority_keys,
        "trusted_provenance_keys": trusted_provenance_keys,
    }))
}

/// Spawn a Holon (governed agent runtime)
#[wasm_bindgen]
pub fn wasm_spawn_holon(did: &str, program_json: &str) -> Result<JsValue, JsValue> {
    let program: exo_gatekeeper::Combinator = from_json_str(program_json)?;
    let holon_did =
        exo_core::Did::new(did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let permissions = exo_gatekeeper::types::PermissionSet::default();
    let holon = exo_gatekeeper::holon::spawn(holon_did, permissions, program);
    // Holon doesn't derive Serialize, return summary
    to_js_value(&serde_json::json!({
        "id": holon.id.as_str(),
        "state": holon_state_label(holon.state),
    }))
}

/// Step a Holon forward with input (simplified — no kernel context in WASM)
#[wasm_bindgen]
pub fn wasm_step_combinator(combinator_json: &str, input_json: &str) -> Result<JsValue, JsValue> {
    let combinator: exo_gatekeeper::Combinator = from_json_str(combinator_json)?;
    let input: exo_gatekeeper::CombinatorInput = from_json_str(input_json)?;
    let output = exo_gatekeeper::combinator::reduce(&combinator, &input)
        .map_err(|_| gatekeeper_boundary_error("combinator step failed"))?;
    to_js_value(&output)
}

/// Check MCP (Model Context Protocol) rule descriptions
#[wasm_bindgen]
pub fn wasm_mcp_rules() -> Result<JsValue, JsValue> {
    let rules = exo_gatekeeper::McpRule::all();
    let descriptions: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "rule": r.id(),
                "description": r.description(),
            })
        })
        .collect();
    to_js_value(&descriptions)
}

// ===========================================================================
// Tests — native Rust (no wasm32 target required)
//
// These tests exercise the enforcement logic directly through the inner
// exo_gatekeeper API used by the WASM bindings.  They run under `cargo test`
// on the rlib compilation and do not require wasm-pack or a browser.
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::Did;
    use exo_gatekeeper::{
        InvariantEngine,
        invariants::{ConstitutionalInvariant, InvariantContext, enforce_all},
        types::{
            AuthorityChain, BailmentState, ConsentRecord, PermissionSet, QuorumEvidence,
            QuorumVote, TrustedAuthorityKeys, TrustedProvenanceKeys,
        },
    };

    fn actor() -> Did {
        Did::new("did:exo:test-actor").expect("valid DID")
    }

    fn active_bailment() -> BailmentState {
        BailmentState::Active {
            bailor: Did::new("did:exo:bailor").expect("valid"),
            bailee: actor(),
            scope: "test-scope".to_string(),
        }
    }

    fn minimal_passing_context() -> InvariantContext {
        use exo_gatekeeper::{
            authority_link_signature_message, provenance_signature_message,
            types::{AuthorityLink, Provenance},
        };

        // Generate a real Ed25519 keypair and sign the canonical authority-link
        // payload so the invariant engine performs full cryptographic verification
        // (TNC-01) instead of the legacy non-emptiness fallback.
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = Did::new("did:exo:root").expect("valid");
        let grantee = actor();
        let permissions = PermissionSet::default();

        let mut authority_link = AuthorityLink {
            grantor,
            grantee,
            permissions,
            signature: Vec::new(),
            grantor_public_key: Some(pk.as_bytes().to_vec()),
        };
        let message =
            authority_link_signature_message(&authority_link).expect("canonical link payload");
        let sig = exo_core::crypto::sign(message.as_bytes(), &sk);
        authority_link.signature = sig.to_bytes().to_vec();

        let authority_chain = AuthorityChain {
            links: vec![authority_link],
        };
        let mut trusted_authority_keys = exo_gatekeeper::types::TrustedAuthorityKeys::default();
        for link in &authority_chain.links {
            if let Some(public_key) = &link.grantor_public_key {
                trusted_authority_keys.insert(link.grantor.clone(), vec![public_key.clone()]);
            }
        }

        let (provenance_pk, provenance_sk) = exo_core::crypto::generate_keypair();
        let provenance_actor = actor();
        let provenance_timestamp = "2026-03-20T00:00:00Z".to_string();
        let provenance_action_hash = vec![1u8; 32];
        let mut provenance = Provenance {
            actor: provenance_actor,
            timestamp: provenance_timestamp,
            action_hash: provenance_action_hash,
            signature: Vec::new(),
            public_key: Some(provenance_pk.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let provenance_message =
            provenance_signature_message(&provenance).expect("canonical provenance payload");
        let provenance_sig = exo_core::crypto::sign(provenance_message.as_bytes(), &provenance_sk);
        provenance.signature = provenance_sig.to_bytes().to_vec();
        let mut trusted_provenance_keys = exo_gatekeeper::types::TrustedProvenanceKeys::default();
        trusted_provenance_keys.insert(
            provenance.actor.clone(),
            vec![provenance_pk.as_bytes().to_vec()],
        );
        let provenance = Some(provenance);

        InvariantContext {
            actor: actor(),
            actor_roles: vec![],
            bailment_state: active_bailment(),
            consent_records: vec![ConsentRecord {
                subject: Did::new("did:exo:bailor").expect("valid"),
                granted_to: actor(),
                scope: "test-scope".to_string(),
                active: true,
            }],
            authority_chain,
            is_self_grant: false,
            human_override_preserved: true,
            kernel_modification_attempted: false,
            quorum_evidence: None,
            provenance,
            actor_permissions: PermissionSet::default(),
            requested_permissions: PermissionSet::default(),
            trusted_authority_keys,
            trusted_provenance_keys,
        }
    }

    #[test]
    fn enforce_all_passes_with_valid_context() {
        let engine = InvariantEngine::all();
        let ctx = minimal_passing_context();
        assert!(
            enforce_all(&engine, &ctx).is_ok(),
            "valid context must pass all invariants"
        );
    }

    #[test]
    fn enforce_all_fails_on_self_grant() {
        let engine = InvariantEngine::all();
        let mut ctx = minimal_passing_context();
        ctx.is_self_grant = true;
        let result = enforce_all(&engine, &ctx);
        assert!(result.is_err(), "self-grant must be denied");
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.invariant == ConstitutionalInvariant::NoSelfGrant),
            "NoSelfGrant violation must be present"
        );
    }

    #[test]
    fn enforce_all_fails_without_consent() {
        let engine = InvariantEngine::all();
        let mut ctx = minimal_passing_context();
        ctx.bailment_state = BailmentState::None;
        ctx.consent_records.clear();
        let result = enforce_all(&engine, &ctx);
        assert!(result.is_err(), "missing consent must be denied");
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.invariant == ConstitutionalInvariant::ConsentRequired),
            "ConsentRequired violation must be present"
        );
    }

    #[test]
    fn enforce_all_fails_when_human_override_blocked() {
        let engine = InvariantEngine::all();
        let mut ctx = minimal_passing_context();
        ctx.human_override_preserved = false;
        let result = enforce_all(&engine, &ctx);
        assert!(result.is_err(), "blocked human override must be denied");
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.invariant == ConstitutionalInvariant::HumanOverride),
            "HumanOverride violation must be present"
        );
    }

    #[test]
    fn enforce_all_fails_on_kernel_modification() {
        let engine = InvariantEngine::all();
        let mut ctx = minimal_passing_context();
        ctx.kernel_modification_attempted = true;
        let result = enforce_all(&engine, &ctx);
        assert!(result.is_err(), "kernel modification must be denied");
        let violations = result.unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.invariant == ConstitutionalInvariant::KernelImmutability),
            "KernelImmutability violation must be present"
        );
    }

    #[test]
    fn violation_description_is_non_empty() {
        let engine = InvariantEngine::all();
        let mut ctx = minimal_passing_context();
        ctx.is_self_grant = true;
        let violations = enforce_all(&engine, &ctx).unwrap_err();
        for v in &violations {
            assert!(
                !v.description.is_empty(),
                "violation description must be non-empty"
            );
        }
    }

    #[test]
    fn wasm_invariant_request_deserializes() {
        // Validates that the JSON schema accepted by wasm_enforce_invariants
        // deserialises correctly via serde_json (same path as from_json_str).
        let json = serde_json::json!({
            "actor": "did:exo:alice",
            "actor_roles": [],
            "bailment_state": {
                "Active": {
                    "bailor": "did:exo:bailor",
                    "bailee": "did:exo:alice",
                    "scope": "data"
                }
            },
            "consent_records": [{
                "subject": "did:exo:subject",
                "granted_to": "did:exo:alice",
                "scope": "data",
                "active": true
            }],
            "authority_chain": { "links": [] }
        });
        let result: Result<super::WasmInvariantRequest, _> = serde_json::from_value(json);
        assert!(
            result.is_ok(),
            "WasmInvariantRequest must deserialize from valid JSON"
        );
    }

    #[test]
    fn wasm_enforce_invariants_rejects_caller_supplied_trusted_key_maps() {
        let ctx = minimal_passing_context();
        let req = super::WasmInvariantRequest {
            actor: ctx.actor,
            actor_roles: ctx.actor_roles,
            bailment_state: ctx.bailment_state,
            consent_records: ctx.consent_records,
            authority_chain: ctx.authority_chain,
            is_self_grant: ctx.is_self_grant,
            human_override_preserved: ctx.human_override_preserved,
            kernel_modification_attempted: ctx.kernel_modification_attempted,
            quorum_evidence: ctx.quorum_evidence,
            provenance: ctx.provenance,
            actor_permissions: ctx.actor_permissions,
            requested_permissions: ctx.requested_permissions,
            trusted_authority_keys: ctx.trusted_authority_keys,
            trusted_provenance_keys: ctx.trusted_provenance_keys,
        };

        let response = super::enforce_invariants_response(req);
        assert_eq!(
            response["passed"], false,
            "WASM public enforcement must not treat caller-supplied trusted key maps as authoritative"
        );

        let descriptions = response["violations"]
            .as_array()
            .expect("violations must be an array")
            .iter()
            .filter_map(|violation| violation["description"].as_str())
            .collect::<Vec<_>>();
        assert!(
            descriptions
                .iter()
                .any(|description| description.contains("trusted_authority_keys")),
            "authority key map boundary violation must be explicit: {descriptions:?}"
        );
        assert!(
            descriptions
                .iter()
                .any(|description| description.contains("trusted_provenance_keys")),
            "provenance key map boundary violation must be explicit: {descriptions:?}"
        );
    }

    #[test]
    fn wasm_enforce_invariants_rejects_unproven_caller_quorum_evidence() {
        let mut ctx = minimal_passing_context();
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 2,
            votes: vec![
                QuorumVote {
                    voter: Did::new("did:exo:voter-one").expect("valid DID"),
                    approved: true,
                    signature: vec![1],
                    provenance: None,
                },
                QuorumVote {
                    voter: Did::new("did:exo:voter-two").expect("valid DID"),
                    approved: true,
                    signature: vec![2],
                    provenance: None,
                },
            ],
        });
        ctx.trusted_authority_keys = TrustedAuthorityKeys::default();
        ctx.trusted_provenance_keys = TrustedProvenanceKeys::default();
        let req = super::WasmInvariantRequest {
            actor: ctx.actor,
            actor_roles: ctx.actor_roles,
            bailment_state: ctx.bailment_state,
            consent_records: ctx.consent_records,
            authority_chain: ctx.authority_chain,
            is_self_grant: ctx.is_self_grant,
            human_override_preserved: ctx.human_override_preserved,
            kernel_modification_attempted: ctx.kernel_modification_attempted,
            quorum_evidence: ctx.quorum_evidence,
            provenance: ctx.provenance,
            actor_permissions: ctx.actor_permissions,
            requested_permissions: ctx.requested_permissions,
            trusted_authority_keys: ctx.trusted_authority_keys,
            trusted_provenance_keys: ctx.trusted_provenance_keys,
        };

        let response = super::enforce_invariants_response(req);
        assert_eq!(response["passed"], false);

        let descriptions = response["violations"]
            .as_array()
            .expect("violations must be an array")
            .iter()
            .filter_map(|violation| violation["description"].as_str())
            .collect::<Vec<_>>();
        assert!(
            descriptions
                .iter()
                .any(|description| description.contains("verified human")),
            "caller-supplied quorum evidence without verified human provenance must fail closed: {descriptions:?}"
        );
    }

    #[test]
    fn wasm_mcp_rules_use_stable_ids_not_debug_variants() {
        let source = include_str!("gatekeeper_bindings.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production section");

        assert!(!production.contains("format!(\"{r:?}\")"));
        assert!(production.contains("\"rule\": r.id()"));
    }

    #[test]
    fn governance_attestation_wasm_boundary_requires_trusted_signer_registry() {
        let source = include_str!("gatekeeper_bindings.rs");
        let production = source
            .split("// ===========================================================================\n// Tests")
            .next()
            .expect("production section");

        assert!(
            production.contains("wasm_verify_governance_attestation_with_trusted_keys"),
            "WASM governance attestation verification must expose a trusted-registry boundary"
        );
        assert!(
            production.contains("trusted_signer_keys_json"),
            "trusted signer keys must be passed as an explicit registry, not as a raw peer key"
        );
        assert!(
            production.contains("wasm_governance_attestation_signature_message_digest"),
            "WASM callers must have an exported domain-separated attestation signing message"
        );
        assert!(
            production.contains(
                "governance_attestation_signature_message_digest(\n            &signer_did,"
            ),
            "WASM attestation signing message must bind the signer DID before signing"
        );
        assert!(
            !production.contains("pub fn wasm_verify_governance_attestation("),
            "WASM governance attestations must not expose a raw caller-supplied public-key verifier"
        );
        assert!(
            !production.contains("signer_public_key_hex"),
            "WASM governance attestation verification must not accept a raw signer_public_key_hex parameter"
        );
    }

    #[test]
    fn governance_attestation_wasm_signing_message_is_domain_separated() {
        let findings_json = r#"[{"id":"F-001","severity":"critical"}]"#;
        let findings_digest =
            super::wasm_governance_findings_digest(findings_json).expect("findings digest");
        let message_digest = super::wasm_governance_attestation_signature_message_digest(
            "did:exo:governance-scanner",
            findings_json,
        )
        .expect("attestation signing digest");

        assert_ne!(
            message_digest, findings_digest,
            "WASM attestation signature message must not be raw findings digest"
        );
    }

    #[test]
    fn validation_invariant_request_includes_trusted_authority_keys() {
        let source = include_str!("gatekeeper_bindings.rs");
        let validation_fixture = source
            .split("pub fn wasm_validation_invariant_request")
            .nth(1)
            .expect("validation fixture is present")
            .split("pub fn wasm_spawn_holon")
            .next()
            .expect("validation fixture body is bounded");

        assert!(
            validation_fixture.contains("TrustedAuthorityKeys"),
            "validation invariant fixture must construct a trusted authority key map"
        );
        assert!(
            validation_fixture.contains("\"trusted_authority_keys\""),
            "validation invariant fixture must emit trusted authority keys for bridge verification"
        );
    }

    #[test]
    fn validation_invariant_request_includes_trusted_provenance_keys() {
        let source = include_str!("gatekeeper_bindings.rs");
        let validation_fixture = source
            .split("pub fn wasm_validation_invariant_request")
            .nth(1)
            .expect("validation fixture is present")
            .split("pub fn wasm_spawn_holon")
            .next()
            .expect("validation fixture body is bounded");

        assert!(
            validation_fixture.contains("TrustedProvenanceKeys"),
            "validation invariant fixture must construct a trusted provenance key map"
        );
        assert!(
            validation_fixture.contains("\"trusted_provenance_keys\""),
            "validation invariant fixture must emit trusted provenance keys for bridge verification"
        );
    }
}
