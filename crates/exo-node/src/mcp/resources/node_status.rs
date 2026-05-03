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

fn count_as_u64(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

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
            let committed_height = count_as_u64(state.consensus.committed.len());
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    use exo_core::{Did, Hash256, Signature, types::PublicKey};

    use super::*;
    use crate::reactor::{ReactorConfig, create_reactor_state};

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

    #[test]
    fn read_with_live_reactor_reports_consensus_snapshot() {
        let node_did = Did::new("did:exo:validator-1").expect("valid DID");
        let other_validator = Did::new("did:exo:validator-2").expect("valid DID");
        let validators = BTreeSet::from([node_did.clone(), other_validator.clone()]);
        let validator_public_keys = BTreeMap::from([
            (node_did.clone(), PublicKey::from_bytes([1u8; 32])),
            (other_validator, PublicKey::from_bytes([2u8; 32])),
        ]);
        let reactor_state = create_reactor_state(
            &ReactorConfig {
                node_did: node_did.clone(),
                is_validator: true,
                validators,
                validator_public_keys,
                round_timeout_ms: 1_000,
            },
            Arc::new(|_| Signature::empty()),
            None,
        );
        {
            let mut state = reactor_state.lock().expect("reactor state lock");
            state.consensus.current_round = 7;
            state.consensus.committed.push(Hash256::digest(b"node-1"));
            state.consensus.committed.push(Hash256::digest(b"node-2"));
        }
        let context = NodeContext {
            reactor_state: Some(reactor_state),
            store: None,
            node_did: Some(node_did.to_string()),
        };

        let content = read(&context);
        let text = content.text.expect("text present");
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");

        assert_eq!(parsed["status"], "live");
        assert_eq!(parsed["node_did"], node_did.to_string());
        assert_eq!(parsed["consensus_round"], 7);
        assert_eq!(parsed["committed_height"], 2);
        assert_eq!(parsed["validator_count"], 2);
        assert_eq!(parsed["is_validator"], true);
        let validator_entries = parsed["validators"].as_array().expect("validators array");
        assert_eq!(validator_entries.len(), 2);
        assert_eq!(parsed["has_store"], false);
    }
}
