//! `exochain://mcp-rules` — the 6 MCP enforcement rules as JSON.

use exo_gatekeeper::mcp::McpRule;
use serde_json::Value;

use crate::mcp::{
    context::NodeContext,
    protocol::{ResourceContent, ResourceDefinition},
};

/// Build the resource definition.
#[must_use]
pub fn definition() -> ResourceDefinition {
    ResourceDefinition {
        uri: "exochain://mcp-rules".into(),
        name: "MCP Enforcement Rules".into(),
        description: Some(
            "The 6 MCP rules governing AI behavior inside the EXOCHAIN fabric. \
             Returned as JSON with a `count` field and a `rules` array. Every \
             tool invocation by an AI actor is checked against all 6 rules \
             before the constitutional kernel adjudicates the action."
                .into(),
        ),
        mime_type: Some("application/json".into()),
    }
}

/// Canonical stable name for an `McpRule`.
pub(crate) fn name(rule: &McpRule) -> &'static str {
    match rule {
        McpRule::Mcp001BctsScope => "Mcp001BctsScope",
        McpRule::Mcp002NoSelfEscalation => "Mcp002NoSelfEscalation",
        McpRule::Mcp003ProvenanceRequired => "Mcp003ProvenanceRequired",
        McpRule::Mcp004NoIdentityForge => "Mcp004NoIdentityForge",
        McpRule::Mcp005Distinguishable => "Mcp005Distinguishable",
        McpRule::Mcp006ConsentBoundaries => "Mcp006ConsentBoundaries",
    }
}

/// Human-readable description for an `McpRule`.
pub(crate) fn description(rule: &McpRule) -> &'static str {
    match rule {
        McpRule::Mcp001BctsScope => {
            "AI actions must operate inside a declared BCTS (bailment consent \
             token scope). Requests without a scope label are rejected at the \
             middleware boundary."
        }
        McpRule::Mcp002NoSelfEscalation => {
            "An AI actor cannot grant itself new permissions, widen its own \
             scope, or escape its delegation bounds. Escalation must originate \
             from a separate, human-rooted authority."
        }
        McpRule::Mcp003ProvenanceRequired => {
            "Every AI action must carry provenance metadata — actor DID, \
             delegation hash, timestamp, and signature. Missing provenance \
             triggers an immediate rule violation."
        }
        McpRule::Mcp004NoIdentityForge => {
            "AI actors cannot forge or impersonate another identity. The \
             cryptographic `SignerType` is part of the signed payload itself, \
             making human-signature forgery impossible by construction."
        }
        McpRule::Mcp005Distinguishable => {
            "AI-generated outputs must be unambiguously marked as AI-produced. \
             Auditors and downstream systems rely on this marker to apply the \
             correct review and admissibility rules."
        }
        McpRule::Mcp006ConsentBoundaries => {
            "AI actions are bound by the consent records active at the moment \
             of the call. Revocation takes immediate effect — subsequent \
             actions against the revoked scope are denied."
        }
    }
}

/// Build the pretty-printed JSON payload for the 6 MCP rules.
pub(crate) fn build_payload() -> Value {
    let rules: Vec<Value> = McpRule::all()
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            serde_json::json!({
                "index": i + 1,
                "name": name(rule),
                "description": description(rule),
                "short": rule.description(),
            })
        })
        .collect();

    serde_json::json!({
        "count": rules.len(),
        "rules": rules,
    })
}

/// Read the resource contents.
#[must_use]
pub fn read(_context: &NodeContext) -> ResourceContent {
    let payload = build_payload();
    ResourceContent::json("exochain://mcp-rules", &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_has_uri() {
        let def = definition();
        assert_eq!(def.uri, "exochain://mcp-rules");
        assert_eq!(def.mime_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn read_returns_6_rules() {
        let content = read(&NodeContext::empty());
        let text = content.text.expect("text present");
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(parsed["count"], 6);
        let rules = parsed["rules"].as_array().expect("array");
        assert_eq!(rules.len(), 6);
        assert_eq!(rules[0]["name"], "Mcp001BctsScope");
        assert_eq!(rules[5]["name"], "Mcp006ConsentBoundaries");
    }

    #[test]
    fn every_rule_has_description() {
        let payload = build_payload();
        for rule in payload["rules"].as_array().unwrap() {
            let desc = rule["description"].as_str().unwrap();
            assert!(!desc.is_empty());
        }
    }
}
