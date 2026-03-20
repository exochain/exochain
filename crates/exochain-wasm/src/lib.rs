//! ExoChain WASM Bindings
//!
//! Exposes the full ExoChain governance engine to JavaScript/Node.js via WebAssembly.
//! Covers 13 crates: core, identity, consent, authority, gatekeeper, governance,
//! escalation, legal, dag, proofs, api, tenant, and decision-forum.

pub mod authority_bindings;
pub mod consent_bindings;
pub mod core_bindings;
pub mod decision_forum_bindings;
pub mod escalation_bindings;
pub mod gatekeeper_bindings;
pub mod governance_bindings;
pub mod identity_bindings;
pub mod legal_bindings;
mod serde_bridge;

// Flat re-exports so integration tests and downstream rlib consumers can
// access all WASM bindings as `exochain_wasm::wasm_*` without module prefixes.
pub use authority_bindings::*;
pub use consent_bindings::*;
pub use core_bindings::*;
pub use decision_forum_bindings::*;
pub use escalation_bindings::*;
pub use gatekeeper_bindings::*;
pub use governance_bindings::*;
pub use identity_bindings::*;
pub use legal_bindings::*;
