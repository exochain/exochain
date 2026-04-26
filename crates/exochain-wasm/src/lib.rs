//! ExoChain WASM Bindings
//!
//! Exposes the full ExoChain governance engine to JavaScript/Node.js via WebAssembly.
//! Covers 14 crates: core, identity, consent, authority, gatekeeper, governance,
//! escalation, legal, dag, proofs, api, tenant, decision-forum, and messaging.

pub mod authority_bindings;
pub mod catapult_bindings;
pub mod consent_bindings;
pub mod core_bindings;
pub mod decision_forum_bindings;
pub mod escalation_bindings;
pub mod gatekeeper_bindings;
pub mod governance_bindings;
pub mod identity_bindings;
pub mod legal_bindings;
pub mod messaging_bindings;
mod serde_bridge;

// Flat re-exports so integration tests and downstream rlib consumers can
// access all WASM bindings as `exochain_wasm::wasm_*` without module prefixes.
pub use authority_bindings::*;
pub use catapult_bindings::*;
pub use consent_bindings::*;
pub use core_bindings::*;
pub use decision_forum_bindings::*;
pub use escalation_bindings::*;
pub use gatekeeper_bindings::*;
pub use governance_bindings::*;
pub use identity_bindings::*;
pub use legal_bindings::*;
pub use messaging_bindings::*;

#[cfg(test)]
mod source_guard_tests {
    #[test]
    fn wasm_bridge_uses_deterministic_collections() {
        let binding_sources = [
            (
                "authority_bindings.rs",
                include_str!("authority_bindings.rs"),
            ),
            (
                "governance_bindings.rs",
                include_str!("governance_bindings.rs"),
            ),
        ];

        for (path, source) in binding_sources {
            assert!(
                !source.contains("HashMap"),
                "{path} must use deterministic BTreeMap-style collections at the WASM boundary"
            );
            assert!(
                !source.contains("HashSet"),
                "{path} must use deterministic BTreeSet-style collections at the WASM boundary"
            );
        }
    }

    #[test]
    fn wasm_consent_bridge_requires_caller_supplied_time() {
        let source = include_str!("consent_bindings.rs");
        let forbidden = [
            format!("{}{}", "Timestamp::", "now_utc()"),
            format!("{}{}", "Uuid::", "new_v4()"),
            "HybridClock::new()".to_string(),
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(&pattern),
                "consent WASM bindings must receive caller-supplied IDs and HLC timestamps"
            );
        }
    }
}
