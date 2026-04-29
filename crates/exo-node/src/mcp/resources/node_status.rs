//! `exochain://node/status` — live node status snapshot.
//!
//! Reads from the attached [`NodeContext`]. If a reactor state handle is
//! present, returns live values (round, committed height, validator set).
//! Otherwise returns a zeroed "standalone" template so clients can still
//! parse the same schema.

use serde_json::Value;

use crate::mcp::{
    context::NodeContext,
    protocol::{ResourceContent, ResourceDefinition},
};

/// Build the resource definition.
#[must_use]
pub fn definition() -> ResourceDefinition {
    ResourceDefinition {
        uri: "exochain://node/status".into(),
        name: "Node Status".into(),
        description: Some(
            "Live snapshot of this node's consensus state — round, committed \
             height, validator set, and whether this node is itself a validator. \
             Returns a `standalone` template when the MCP server is running \
             without a live reactor (e.g. pure stdio mode)."
                .into(),
        ),
        mime_type: Some("application/json".into()),
    }
}

/// Build the live or template status payload.
fn build_payload(context: &NodeContext) -> Value {
    if let Some(reactor) = context.reactor_state.as_ref() {
        if let Ok(state) = reactor.lock() {
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

            return serde_json::json!({
                "node": "exochain",
                "version": env!("CARGO_PKG_VERSION"),
                "node_did": context.node_did,
                "consensus_round": consensus_round,
                "committed_height": committed_height,
                "validator_count": validator_count,
                "is_validator": is_validator,
                "validators": validators,
                "has_store": context.has_store(),
                "status": "live",
            });
        }
    }

    serde_json::json!({
        "node": "exochain",
        "version": env!("CARGO_PKG_VERSION"),
        "node_did": context.node_did,
        "consensus_round": 0,
        "committed_height": 0,
        "validator_count": 0,
        "is_validator": false,
        "validators": [],
        "has_store": context.has_store(),
        "status": "standalone",
    })
}

/// Read the resource contents.
#[must_use]
pub fn read(context: &NodeContext) -> ResourceContent {
    let payload = build_payload(context);
    ResourceContent::json("exochain://node/status", &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_has_uri() {
        let def = definition();
        assert_eq!(def.uri, "exochain://node/status");
    }

    #[test]
    fn read_without_context_returns_standalone() {
        let content = read(&NodeContext::empty());
        let text = content.text.expect("text present");
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(parsed["status"], "standalone");
        assert_eq!(parsed["node"], "exochain");
        assert_eq!(parsed["is_validator"], false);
        assert_eq!(parsed["validator_count"], 0);
    }

    #[test]
    fn read_contains_version() {
        let content = read(&NodeContext::empty());
        let text = content.text.expect("text present");
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(parsed["version"].is_string());
    }
}
