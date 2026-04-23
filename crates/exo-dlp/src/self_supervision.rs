//! Self-supervision — exoguard governs itself via the same MCP enforce +
//! audit pipeline it imposes on tenants.
//!
//! Control-plane actions (config updates, key rotations, deploys, tenant
//! registrations) are MCP tool calls in the `mcp_exoguard_ops` domain.
//! Each call is signed with `SignerType::Human` + an operator delegation;
//! Mcp004NoIdentityForge rejects any AI-originated attempt at these tools.
//!
//! Two-operator quorum on high-risk ops (`rotateOpenRouterKey`,
//! `deployExoguard`, `setCustodianSet`) is implemented via the
//! `Mcp009QuorumOps` rule (added in a follow-up commit to
//! `crates/exo-gatekeeper/src/mcp.rs`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpsAction {
    UpdateExoguardConfig,
    RotateOpenRouterKey,
    SwapScannerModel,
    DeployExoguard,
    RegisterTenant,
    SetCustodianSet,
}

impl OpsAction {
    /// Whether this action requires two-operator quorum (Mcp009QuorumOps).
    #[must_use]
    pub const fn requires_quorum(self) -> bool {
        matches!(
            self,
            Self::RotateOpenRouterKey | Self::DeployExoguard | Self::SetCustodianSet
        )
    }

    /// Stable string tag used in MCP tool call routing.
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::UpdateExoguardConfig => "mcp_exoguard_ops.updateExoguardConfig",
            Self::RotateOpenRouterKey => "mcp_exoguard_ops.rotateOpenRouterKey",
            Self::SwapScannerModel => "mcp_exoguard_ops.swapScannerModel",
            Self::DeployExoguard => "mcp_exoguard_ops.deployExoguard",
            Self::RegisterTenant => "mcp_exoguard_ops.registerTenant",
            Self::SetCustodianSet => "mcp_exoguard_ops.setCustodianSet",
        }
    }
}

/// Envelope for a signed ops call. The payload is the CBOR-encoded action
/// parameters; `build_signed_payload` in `exo-gatekeeper::mcp` prefixes the
/// SignerType byte so forging a Human signature from an AI context is
/// cryptographically impossible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOpsCall {
    pub action: OpsAction,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub operator_did: String,
    pub delegation_id: [u8; 32],
}
