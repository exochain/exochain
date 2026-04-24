//! MCP Resources registry — declarative artifacts for AI clients.
//!
//! Exposes six constitutional artifacts over the MCP `resources/list` and
//! `resources/read` endpoints:
//!
//! - `exochain://constitution` — the BLAKE3-hashed root-of-trust text.
//! - `exochain://invariants` — 8 constitutional invariants (JSON).
//! - `exochain://mcp-rules` — 6 MCP enforcement rules (JSON).
//! - `exochain://node/status` — live node status snapshot (JSON).
//! - `exochain://tools` — all 40 MCP tools grouped by domain (JSON).
//! - `exochain://readme` — markdown agent quick-reference.

pub mod constitution;
pub mod invariants;
pub mod mcp_rules;
pub mod node_status;
pub mod readme;
pub mod tools_summary;

use std::collections::BTreeMap;

use super::context::NodeContext;
use super::protocol::{ResourceContent, ResourceDefinition};

/// Registry of available MCP resources.
///
/// Stores resource definitions keyed by URI and dispatches `read` calls
/// to the corresponding handler module.
pub struct ResourceRegistry {
    resources: BTreeMap<String, ResourceDefinition>,
}

impl ResourceRegistry {
    /// Create a new registry pre-populated with every built-in resource.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self {
            resources: BTreeMap::new(),
        };
        registry.register_all();
        registry
    }

    /// Register every built-in resource definition.
    pub fn register_all(&mut self) {
        self.register(constitution::definition());
        self.register(invariants::definition());
        self.register(mcp_rules::definition());
        self.register(node_status::definition());
        self.register(tools_summary::definition());
        self.register(readme::definition());
    }

    /// Insert a single resource definition.
    pub fn register(&mut self, def: ResourceDefinition) {
        self.resources.insert(def.uri.clone(), def);
    }

    /// List every registered resource definition (stable URI-sorted order).
    #[must_use]
    pub fn list(&self) -> Vec<&ResourceDefinition> {
        self.resources.values().collect()
    }

    /// Dispatch a `resources/read` call to the matching handler.
    ///
    /// Returns `None` if the URI is not registered.
    #[must_use]
    pub fn read(&self, uri: &str, context: &NodeContext) -> Option<ResourceContent> {
        if !self.resources.contains_key(uri) {
            return None;
        }
        match uri {
            "exochain://constitution" => Some(constitution::read(context)),
            "exochain://invariants" => Some(invariants::read(context)),
            "exochain://mcp-rules" => Some(mcp_rules::read(context)),
            "exochain://node/status" => Some(node_status::read(context)),
            "exochain://tools" => Some(tools_summary::read(context)),
            "exochain://readme" => Some(readme::read(context)),
            _ => None,
        }
    }
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn resource_registry_lists_6() {
        let registry = ResourceRegistry::default();
        assert_eq!(registry.list().len(), 6);
    }

    #[test]
    fn resource_registry_contains_expected_uris() {
        let registry = ResourceRegistry::default();
        let uris: Vec<&str> = registry.list().iter().map(|d| d.uri.as_str()).collect();
        assert!(uris.contains(&"exochain://constitution"));
        assert!(uris.contains(&"exochain://invariants"));
        assert!(uris.contains(&"exochain://mcp-rules"));
        assert!(uris.contains(&"exochain://node/status"));
        assert!(uris.contains(&"exochain://tools"));
        assert!(uris.contains(&"exochain://readme"));
    }

    #[test]
    fn resource_read_constitution() {
        let registry = ResourceRegistry::default();
        let content = registry
            .read("exochain://constitution", &NodeContext::empty())
            .expect("constitution present");
        assert_eq!(content.uri, "exochain://constitution");
        let text = content.text.expect("text present");
        assert!(!text.is_empty());
        // Hash must match what the kernel would compute.
        let hash = exo_core::Hash256::digest(text.as_bytes());
        let kernel_hash = exo_core::Hash256::digest(constitution::CONSTITUTION_TEXT);
        assert_eq!(hash, kernel_hash);
    }

    #[test]
    fn resource_read_invariants_returns_8() {
        let registry = ResourceRegistry::default();
        let content = registry
            .read("exochain://invariants", &NodeContext::empty())
            .expect("invariants present");
        let text = content.text.expect("text present");
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let invariants = parsed["invariants"].as_array().unwrap();
        assert_eq!(invariants.len(), 8);
    }

    #[test]
    fn resource_read_mcp_rules_returns_6() {
        let registry = ResourceRegistry::default();
        let content = registry
            .read("exochain://mcp-rules", &NodeContext::empty())
            .expect("mcp-rules present");
        let text = content.text.expect("text present");
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let rules = parsed["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 6);
    }

    #[test]
    fn resource_read_node_status() {
        let registry = ResourceRegistry::default();
        let content = registry
            .read("exochain://node/status", &NodeContext::empty())
            .expect("node status present");
        let text = content.text.expect("text present");
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["node"], "exochain");
    }

    #[test]
    fn resource_read_tools_summary_40() {
        let registry = ResourceRegistry::default();
        let content = registry
            .read("exochain://tools", &NodeContext::empty())
            .expect("tools present");
        let text = content.text.expect("text present");
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["total"], 40);
    }

    #[test]
    fn resource_read_readme_markdown() {
        let registry = ResourceRegistry::default();
        let content = registry
            .read("exochain://readme", &NodeContext::empty())
            .expect("readme present");
        assert_eq!(content.mime_type.as_deref(), Some("text/markdown"));
    }

    #[test]
    fn resource_read_unknown_uri() {
        let registry = ResourceRegistry::default();
        let out = registry.read("exochain://does-not-exist", &NodeContext::empty());
        assert!(out.is_none());
    }
}
