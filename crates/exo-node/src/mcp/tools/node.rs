//! Node information tools — the first tools to be operational.
//!
//! Provides tools for querying node status, listing constitutional invariants,
//! and listing MCP enforcement rules. These are foundational tools that any
//! AI agent needs to understand the governance environment.

use exo_gatekeeper::{invariants::ConstitutionalInvariant, mcp::McpRule};
use serde_json::Value;

use crate::mcp::context::NodeContext;
use crate::mcp::protocol::{ToolContent, ToolDefinition, ToolResult};

// ---------------------------------------------------------------------------
// exochain_node_status
// ---------------------------------------------------------------------------

/// Returns the tool definition for `exochain_node_status`.
#[must_use]
pub fn node_status_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_node_status".into(),
        description: "Returns the current node status including consensus round, \
                       committed height, validator count, and validator status."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": false
        }),
    }
}

/// Execute the `exochain_node_status` tool.
///
/// When a live reactor state is available in the context, returns the
/// current consensus round, committed height, validator set, and whether
/// this node is a validator. Otherwise returns a `standalone` template.
#[must_use]
pub fn execute_node_status(_params: &Value, context: &NodeContext) -> ToolResult {
    let status = if let Some(reactor) = context.reactor_state.as_ref() {
        match reactor.lock() {
            Ok(state) => {
                let consensus_round = state.consensus.current_round;
                let committed_height = state.consensus.committed.len() as u64;
                let validators: Vec<String> = state
                    .consensus
                    .config
                    .validators
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                let validator_count = validators.len();
                let is_validator = context
                    .node_did
                    .as_ref()
                    .and_then(|did| exo_core::Did::new(did).ok())
                    .is_some_and(|did| state.consensus.config.validators.contains(&did));

                serde_json::json!({
                    "node": "exochain",
                    "version": env!("CARGO_PKG_VERSION"),
                    "consensus_round": consensus_round,
                    "committed_height": committed_height,
                    "validator_count": validator_count,
                    "is_validator": is_validator,
                    "validators": validators,
                    "status": "live",
                })
            }
            Err(_) => {
                return ToolResult {
                    content: vec![ToolContent::Text {
                        text: serde_json::json!({
                            "error": "reactor state mutex poisoned",
                        })
                        .to_string(),
                    }],
                    is_error: true,
                };
            }
        }
    } else {
        serde_json::json!({
            "node": "exochain",
            "version": env!("CARGO_PKG_VERSION"),
            "consensus_round": 0,
            "committed_height": 0,
            "validator_count": 0,
            "is_validator": false,
            "status": "standalone",
        })
    };

    ToolResult {
        content: vec![ToolContent::Text {
            text: serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string()),
        }],
        is_error: false,
    }
}

// ---------------------------------------------------------------------------
// exochain_list_invariants
// ---------------------------------------------------------------------------

/// Returns the tool definition for `exochain_list_invariants`.
#[must_use]
pub fn list_invariants_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_list_invariants".into(),
        description: "Returns all 8 constitutional invariants enforced by the CGR Kernel, \
                       with their names and descriptions."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": false
        }),
    }
}

/// Returns a human-readable name for a constitutional invariant.
fn invariant_name(inv: &ConstitutionalInvariant) -> &'static str {
    match inv {
        ConstitutionalInvariant::SeparationOfPowers => "SeparationOfPowers",
        ConstitutionalInvariant::ConsentRequired => "ConsentRequired",
        ConstitutionalInvariant::NoSelfGrant => "NoSelfGrant",
        ConstitutionalInvariant::HumanOverride => "HumanOverride",
        ConstitutionalInvariant::KernelImmutability => "KernelImmutability",
        ConstitutionalInvariant::AuthorityChainValid => "AuthorityChainValid",
        ConstitutionalInvariant::QuorumLegitimate => "QuorumLegitimate",
        ConstitutionalInvariant::ProvenanceVerifiable => "ProvenanceVerifiable",
    }
}

/// Returns a human-readable description for a constitutional invariant.
fn invariant_description(inv: &ConstitutionalInvariant) -> &'static str {
    match inv {
        ConstitutionalInvariant::SeparationOfPowers => {
            "No single actor may hold legislative + executive + judicial power"
        }
        ConstitutionalInvariant::ConsentRequired => "Action denied without active bailment consent",
        ConstitutionalInvariant::NoSelfGrant => "An actor cannot expand its own permissions",
        ConstitutionalInvariant::HumanOverride => {
            "Emergency human intervention must always be possible"
        }
        ConstitutionalInvariant::KernelImmutability => {
            "Kernel configuration cannot be modified after creation"
        }
        ConstitutionalInvariant::AuthorityChainValid => {
            "Authority chain must be valid and unbroken"
        }
        ConstitutionalInvariant::QuorumLegitimate => {
            "Quorum decisions must meet threshold requirements"
        }
        ConstitutionalInvariant::ProvenanceVerifiable => {
            "All actions must have verifiable provenance"
        }
    }
}

/// Execute the `exochain_list_invariants` tool.
#[must_use]
pub fn execute_list_invariants(_params: &Value, _context: &NodeContext) -> ToolResult {
    let invariants: Vec<Value> = [
        ConstitutionalInvariant::SeparationOfPowers,
        ConstitutionalInvariant::ConsentRequired,
        ConstitutionalInvariant::NoSelfGrant,
        ConstitutionalInvariant::HumanOverride,
        ConstitutionalInvariant::KernelImmutability,
        ConstitutionalInvariant::AuthorityChainValid,
        ConstitutionalInvariant::QuorumLegitimate,
        ConstitutionalInvariant::ProvenanceVerifiable,
    ]
    .iter()
    .enumerate()
    .map(|(i, inv)| {
        serde_json::json!({
            "index": i + 1,
            "name": invariant_name(inv),
            "description": invariant_description(inv),
        })
    })
    .collect();

    let output = serde_json::json!({
        "count": invariants.len(),
        "invariants": invariants,
    });

    ToolResult {
        content: vec![ToolContent::Text {
            text: serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string()),
        }],
        is_error: false,
    }
}

// ---------------------------------------------------------------------------
// exochain_list_mcp_rules
// ---------------------------------------------------------------------------

/// Returns the tool definition for `exochain_list_mcp_rules`.
#[must_use]
pub fn list_mcp_rules_definition() -> ToolDefinition {
    ToolDefinition {
        name: "exochain_list_mcp_rules".into(),
        description: "Returns all 6 MCP enforcement rules governing AI behavior \
                       within the EXOCHAIN fabric, with their names and descriptions."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": false
        }),
    }
}

/// Returns a human-readable name for an MCP rule.
fn mcp_rule_name(rule: &McpRule) -> &'static str {
    match rule {
        McpRule::Mcp001BctsScope => "Mcp001BctsScope",
        McpRule::Mcp002NoSelfEscalation => "Mcp002NoSelfEscalation",
        McpRule::Mcp003ProvenanceRequired => "Mcp003ProvenanceRequired",
        McpRule::Mcp004NoIdentityForge => "Mcp004NoIdentityForge",
        McpRule::Mcp005Distinguishable => "Mcp005Distinguishable",
        McpRule::Mcp006ConsentBoundaries => "Mcp006ConsentBoundaries",
    }
}

/// Execute the `exochain_list_mcp_rules` tool.
#[must_use]
pub fn execute_list_mcp_rules(_params: &Value, _context: &NodeContext) -> ToolResult {
    let rules: Vec<Value> = McpRule::all()
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            serde_json::json!({
                "index": i + 1,
                "name": mcp_rule_name(rule),
                "description": rule.description(),
            })
        })
        .collect();

    let output = serde_json::json!({
        "count": rules.len(),
        "rules": rules,
    });

    ToolResult {
        content: vec![ToolContent::Text {
            text: serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string()),
        }],
        is_error: false,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_node_status_definition() {
        let def = node_status_definition();
        assert_eq!(def.name, "exochain_node_status");
        assert!(!def.description.is_empty());
        assert_eq!(def.input_schema["type"], "object");
    }

    #[test]
    fn tool_node_status_execute() {
        let result = execute_node_status(&serde_json::json!({}), &NodeContext::empty());
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["node"], "exochain");
                assert!(parsed.get("consensus_round").is_some());
                assert!(parsed.get("committed_height").is_some());
                assert!(parsed.get("validator_count").is_some());
            }
        }
    }

    #[test]
    fn tool_node_status_without_context_returns_standalone() {
        let result = execute_node_status(&serde_json::json!({}), &NodeContext::empty());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["status"], "standalone");
                assert_eq!(parsed["is_validator"], false);
            }
        }
    }

    #[test]
    fn tool_list_invariants_definition() {
        let def = list_invariants_definition();
        assert_eq!(def.name, "exochain_list_invariants");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn tool_list_invariants_returns_8() {
        let result = execute_list_invariants(&serde_json::json!({}), &NodeContext::empty());
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["count"], 8);
                let invariants = parsed["invariants"].as_array().unwrap();
                assert_eq!(invariants.len(), 8);
                // Verify first invariant
                assert_eq!(invariants[0]["name"], "SeparationOfPowers");
                assert!(!invariants[0]["description"].as_str().unwrap().is_empty());
                // Verify last invariant
                assert_eq!(invariants[7]["name"], "ProvenanceVerifiable");
            }
        }
    }

    #[test]
    fn tool_list_mcp_rules_definition() {
        let def = list_mcp_rules_definition();
        assert_eq!(def.name, "exochain_list_mcp_rules");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn tool_list_mcp_rules_returns_6() {
        let result = execute_list_mcp_rules(&serde_json::json!({}), &NodeContext::empty());
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["count"], 6);
                let rules = parsed["rules"].as_array().unwrap();
                assert_eq!(rules.len(), 6);
                // Verify first rule
                assert_eq!(rules[0]["name"], "Mcp001BctsScope");
                assert!(!rules[0]["description"].as_str().unwrap().is_empty());
                // Verify last rule
                assert_eq!(rules[5]["name"], "Mcp006ConsentBoundaries");
            }
        }
    }

    #[test]
    fn tool_invariants_all_have_descriptions() {
        let result = execute_list_invariants(&serde_json::json!({}), &NodeContext::empty());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                for inv in parsed["invariants"].as_array().unwrap() {
                    let desc = inv["description"].as_str().unwrap();
                    assert!(!desc.is_empty(), "invariant missing description");
                    let name = inv["name"].as_str().unwrap();
                    assert!(!name.is_empty(), "invariant missing name");
                }
            }
        }
    }

    #[test]
    fn tool_mcp_rules_all_have_descriptions() {
        let result = execute_list_mcp_rules(&serde_json::json!({}), &NodeContext::empty());
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                for rule in parsed["rules"].as_array().unwrap() {
                    let desc = rule["description"].as_str().unwrap();
                    assert!(!desc.is_empty(), "rule missing description");
                    let name = rule["name"].as_str().unwrap();
                    assert!(!name.is_empty(), "rule missing name");
                }
            }
        }
    }

    #[test]
    fn tool_node_status_with_context_uses_reactor() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        use exo_core::types::{Did, Signature};

        use crate::reactor::{ReactorConfig, create_reactor_state};

        // Build a live reactor state with a 4-validator set including this node.
        let this_did = Did::new("did:exo:v0").expect("valid DID");
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid"))
            .collect();
        let config = ReactorConfig {
            node_did: this_did.clone(),
            is_validator: true,
            validators,
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> =
            Arc::new(|_data: &[u8]| Signature::from_bytes([0u8; 64]));
        let reactor_state = create_reactor_state(&config, sign_fn, None);

        let context = NodeContext {
            reactor_state: Some(reactor_state),
            store: None,
            node_did: Some(this_did.to_string()),
        };

        let result = execute_node_status(&serde_json::json!({}), &context);
        assert!(!result.is_error);
        match &result.content[0] {
            ToolContent::Text { text } => {
                let parsed: Value = serde_json::from_str(text).unwrap();
                assert_eq!(parsed["status"], "live");
                assert_eq!(parsed["validator_count"], 4);
                assert_eq!(parsed["is_validator"], true);
                assert_eq!(parsed["consensus_round"], 0);
                let validators = parsed["validators"].as_array().unwrap();
                assert_eq!(validators.len(), 4);
            }
        }
    }
}
