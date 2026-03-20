//! Gatekeeper bindings: CGR combinator algebra, kernel adjudication, invariants

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Reduce a combinator expression with the given input
#[wasm_bindgen]
pub fn wasm_reduce_combinator(combinator_json: &str, input_json: &str) -> Result<JsValue, JsValue> {
    let combinator: exo_gatekeeper::Combinator = from_json_str(combinator_json)?;
    let input: exo_gatekeeper::CombinatorInput = from_json_str(input_json)?;
    let output = exo_gatekeeper::combinator::reduce(&combinator, &input)
        .map_err(|e| JsValue::from_str(&format!("Reduction error: {e}")))?;
    to_js_value(&output)
}

/// List all constitutional invariant names (introspection).
#[wasm_bindgen]
pub fn wasm_list_invariants() -> Result<JsValue, JsValue> {
    let invariants = vec![
        "DemocraticLegitimacy",
        "DelegationGovernance",
        "DualControl",
        "HumanOversight",
        "TransparencyAccountability",
        "ConflictAdjudication",
        "TechnologicalHumility",
        "ExistentialSafeguard",
    ];
    to_js_value(&invariants)
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

/// List the valid Holon state transitions (introspection).
///
/// `Holon` is a runtime-only type and cannot be serialized across the WASM
/// boundary.  This binding exposes the state machine topology so the frontend
/// can reason about legal transitions without holding a live Holon reference.
#[wasm_bindgen]
pub fn wasm_holon_state_transitions() -> Result<JsValue, JsValue> {
    to_js_value(&serde_json::json!({
        "Idle":       ["Executing", "Terminated"],
        "Executing":  ["Idle", "Suspended", "Terminated"],
        "Suspended":  ["Executing", "Terminated"],
        "Terminated": [],
    }))
}

/// List all MCP (Model Context Protocol) rule descriptions (introspection).
#[wasm_bindgen]
pub fn wasm_list_mcp_rules() -> Result<JsValue, JsValue> {
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
