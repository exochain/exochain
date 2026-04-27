//! `exochain://tools` — summary list of all 40 MCP tools grouped by domain.
//!
//! Walks the live [`ToolRegistry`] to compute the param count per tool so
//! the summary stays in sync with the actual definitions.

use serde_json::Value;

use crate::mcp::{
    context::NodeContext,
    protocol::{ResourceContent, ResourceDefinition},
    tools::ToolRegistry,
};

/// Build the resource definition.
#[must_use]
pub fn definition() -> ResourceDefinition {
    ResourceDefinition {
        uri: "exochain://tools".into(),
        name: "MCP Tools Summary".into(),
        description: Some(
            "Summary of all 40 MCP tools grouped by domain (node, identity, \
             consent, governance, authority, ledger, proofs, legal, escalation, \
             messaging). Each entry includes the tool name, human-readable \
             description, domain, and parameter count computed from the \
             registered input schema."
                .into(),
        ),
        mime_type: Some("application/json".into()),
    }
}

/// Classify a tool name into its canonical domain group.
fn domain_for(name: &str) -> &'static str {
    match name {
        "exochain_node_status" | "exochain_list_invariants" | "exochain_list_mcp_rules" => "node",
        "exochain_create_identity"
        | "exochain_resolve_identity"
        | "exochain_assess_risk"
        | "exochain_verify_signature"
        | "exochain_get_passport" => "identity",
        "exochain_propose_bailment"
        | "exochain_check_consent"
        | "exochain_list_bailments"
        | "exochain_terminate_bailment" => "consent",
        "exochain_create_decision"
        | "exochain_cast_vote"
        | "exochain_check_quorum"
        | "exochain_get_decision_status"
        | "exochain_propose_amendment" => "governance",
        "exochain_delegate_authority"
        | "exochain_verify_authority_chain"
        | "exochain_check_permission"
        | "exochain_adjudicate_action" => "authority",
        "exochain_submit_event"
        | "exochain_get_event"
        | "exochain_verify_inclusion"
        | "exochain_get_checkpoint" => "ledger",
        "exochain_create_evidence"
        | "exochain_verify_chain_of_custody"
        | "exochain_generate_merkle_proof"
        | "exochain_verify_cgr_proof" => "proofs",
        "exochain_ediscovery_search"
        | "exochain_assert_privilege"
        | "exochain_initiate_safe_harbor"
        | "exochain_check_fiduciary_duty" => "legal",
        "exochain_evaluate_threat"
        | "exochain_escalate_case"
        | "exochain_triage"
        | "exochain_record_feedback" => "escalation",
        "exochain_send_encrypted"
        | "exochain_receive_encrypted"
        | "exochain_configure_death_trigger" => "messaging",
        _ => "unknown",
    }
}

/// Count the declared parameters on an `inputSchema` object.
fn param_count(schema: &Value) -> usize {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(serde_json::Map::len)
        .unwrap_or(0)
}

/// Count the required parameters on an `inputSchema` object.
fn required_count(schema: &Value) -> usize {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

/// Build the pretty-printed JSON payload from a registry snapshot.
pub(crate) fn build_payload() -> Value {
    let registry = ToolRegistry::default();
    let mut tools: Vec<Value> = registry
        .list()
        .into_iter()
        .map(|def| {
            serde_json::json!({
                "name": def.name,
                "description": def.description,
                "domain": domain_for(&def.name),
                "param_count": param_count(&def.input_schema),
                "required_count": required_count(&def.input_schema),
            })
        })
        .collect();
    tools.sort_by(|a, b| {
        let da = a["domain"].as_str().unwrap_or("");
        let db = b["domain"].as_str().unwrap_or("");
        let na = a["name"].as_str().unwrap_or("");
        let nb = b["name"].as_str().unwrap_or("");
        da.cmp(db).then_with(|| na.cmp(nb))
    });

    // Build per-domain counts.
    let mut domains: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for t in &tools {
        let d = t["domain"].as_str().unwrap_or("unknown");
        let static_d: &'static str = match d {
            "node" => "node",
            "identity" => "identity",
            "consent" => "consent",
            "governance" => "governance",
            "authority" => "authority",
            "ledger" => "ledger",
            "proofs" => "proofs",
            "legal" => "legal",
            "escalation" => "escalation",
            "messaging" => "messaging",
            _ => "unknown",
        };
        *domains.entry(static_d).or_insert(0) += 1;
    }
    let domain_summary: Vec<Value> = domains
        .into_iter()
        .map(|(name, count)| serde_json::json!({ "domain": name, "count": count }))
        .collect();

    serde_json::json!({
        "total": tools.len(),
        "domains": domain_summary,
        "tools": tools,
    })
}

/// Read the resource contents.
#[must_use]
pub fn read(_context: &NodeContext) -> ResourceContent {
    let payload = build_payload();
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());

    ResourceContent {
        uri: "exochain://tools".into(),
        mime_type: Some("application/json".into()),
        text: Some(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_has_uri() {
        let def = definition();
        assert_eq!(def.uri, "exochain://tools");
    }

    #[test]
    fn read_returns_40_tools() {
        let content = read(&NodeContext::empty());
        let text = content.text.expect("text present");
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(parsed["total"], 40);
        let tools = parsed["tools"].as_array().expect("array");
        assert_eq!(tools.len(), 40);
    }

    #[test]
    fn every_tool_has_domain() {
        let content = read(&NodeContext::empty());
        let text = content.text.unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        for tool in parsed["tools"].as_array().unwrap() {
            let domain = tool["domain"].as_str().unwrap();
            assert_ne!(
                domain, "unknown",
                "tool {:?} has unknown domain",
                tool["name"]
            );
        }
    }

    #[test]
    fn domain_counts_sum_to_40() {
        let content = read(&NodeContext::empty());
        let text = content.text.unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        let total: u64 = parsed["domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["count"].as_u64().unwrap())
            .sum();
        assert_eq!(total, 40);
    }
}
