//! Gatekeeper bindings: CGR combinator algebra, kernel adjudication, invariants

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Deserializable mirror of `InvariantContext` for WASM callers.
///
/// All fields map 1-to-1 onto `exo_gatekeeper::invariants::InvariantContext`.
/// Booleans default to safe values (false / true for human_override_preserved).
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
}

fn default_true() -> bool {
    true
}

/// Reduce a combinator expression with the given input
#[wasm_bindgen]
pub fn wasm_reduce_combinator(combinator_json: &str, input_json: &str) -> Result<JsValue, JsValue> {
    let combinator: exo_gatekeeper::Combinator = from_json_str(combinator_json)?;
    let input: exo_gatekeeper::CombinatorInput = from_json_str(input_json)?;
    let output = exo_gatekeeper::combinator::reduce(&combinator, &input)
        .map_err(|e| JsValue::from_str(&format!("Reduction error: {e}")))?;
    to_js_value(&output)
}

/// Enforce all constitutional invariants against the provided context.
///
/// Accepts a JSON object matching [`WasmInvariantRequest`] and delegates
/// to `exo_gatekeeper::invariants::enforce_all`. Returns a JSON object:
/// `{ "passed": bool, "violations": [...] }`.
#[wasm_bindgen]
pub fn wasm_enforce_invariants(request_json: &str) -> Result<JsValue, JsValue> {
    let req: WasmInvariantRequest = from_json_str(request_json)?;

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
    };

    let engine = exo_gatekeeper::InvariantEngine::all();

    match exo_gatekeeper::invariants::enforce_all(&engine, &context) {
        Ok(()) => to_js_value(&serde_json::json!({
            "passed": true,
            "violations": []
        })),
        Err(violations) => to_js_value(&serde_json::json!({
            "passed": false,
            "violations": violations
        })),
    }
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
        "state": format!("{:?}", holon.state),
    }))
}

/// Step a Holon forward with input (simplified — no kernel context in WASM)
#[wasm_bindgen]
pub fn wasm_step_combinator(combinator_json: &str, input_json: &str) -> Result<JsValue, JsValue> {
    let combinator: exo_gatekeeper::Combinator = from_json_str(combinator_json)?;
    let input: exo_gatekeeper::CombinatorInput = from_json_str(input_json)?;
    let output = exo_gatekeeper::combinator::reduce(&combinator, &input)
        .map_err(|e| JsValue::from_str(&format!("Step error: {e}")))?;
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
                "rule": format!("{r:?}"),
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
        types::{AuthorityChain, BailmentState, ConsentRecord, PermissionSet},
    };

    fn actor() -> Did {
        Did::new("did:exo:test-actor").expect("valid DID")
    }

    fn active_bailment() -> BailmentState {
        BailmentState::Active {
            bailor: Did::new("did:exo:bailor").expect("valid"),
            bailee: Did::new("did:exo:bailee").expect("valid"),
            scope: "test-scope".to_string(),
        }
    }

    fn minimal_passing_context() -> InvariantContext {
        use exo_gatekeeper::types::{AuthorityLink, Provenance};

        // Authority chain must terminate at the actor.
        let authority_chain = AuthorityChain {
            links: vec![AuthorityLink {
                grantor: Did::new("did:exo:root").expect("valid"),
                grantee: actor(),
                permissions: PermissionSet::default(),
                signature: vec![0u8; 64], // placeholder — not cryptographically verified here
            }],
        };

        // Provenance must exist and be signed (non-empty signature).
        let provenance = Some(Provenance {
            actor: actor(),
            timestamp: "2026-03-20T00:00:00Z".to_string(),
            action_hash: vec![1u8; 32],
            signature: vec![2u8; 64],
        });

        InvariantContext {
            actor: actor(),
            actor_roles: vec![],
            bailment_state: active_bailment(),
            consent_records: vec![ConsentRecord {
                subject: Did::new("did:exo:subject").expect("valid"),
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
}
