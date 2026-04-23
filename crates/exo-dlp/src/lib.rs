//! exoguard — DLP gateway for AI workflows.
//!
//! Sits between corporate users (or their stock LLM SDKs) and public upstream
//! providers. Every prompt is:
//!
//! 1. Wrapped in a short-lived `Delegation` bailment (scoped consent).
//! 2. Scanned locally for PHI / PII / corporate secrets.
//! 3. Adjudicated by the `ConstitutionalKernel` via MCP `enforce()`.
//! 4. Either blocked (returning a tamper-evident audit receipt) or routed
//!    blinded to an upstream provider (OpenRouter in MVP).
//! 5. Anchored in the DAG under `kind=llm_payload` when allowed.
//!
//! Every privileged control-plane action on exoguard itself is *also* routed
//! through the MCP enforce + audit pipeline — exoguard governs itself. See
//! [`self_supervision`].

pub mod buckets;
pub mod config;
pub mod custody;
pub mod error;
pub mod facade;
pub mod mcp_tools;
pub mod openrouter;
pub mod scanner;
pub mod self_supervision;

pub use error::DlpError;
