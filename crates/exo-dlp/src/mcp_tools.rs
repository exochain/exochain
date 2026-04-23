//! MCP tool domain: `mcp_dlp` (tenant-facing) + `mcp_exoguard_ops`
//! (operator-facing, self-supervision).
//!
//! Tools are surfaced over the existing `/mcp/message` JSON-RPC endpoint on
//! `exo-gateway`; this module only defines the tool *identifiers* and the
//! request/response shapes. The actual dispatch + `enforce()` integration
//! lives in `crates/exo-gatekeeper/src/mcp.rs` once Mcp007 / Mcp008 / Mcp009
//! rules land.

use serde::{Deserialize, Serialize};

/// Tenant-facing DLP tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpTool {
    ScanForPhi,
    ScanForPii,
    ScanForSecrets,
    ApplyRedactionPolicy,
    RouteToUpstream,
}

impl DlpTool {
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::ScanForPhi => "mcp_dlp.scan_for_phi",
            Self::ScanForPii => "mcp_dlp.scan_for_pii",
            Self::ScanForSecrets => "mcp_dlp.scan_for_secrets",
            Self::ApplyRedactionPolicy => "mcp_dlp.apply_redaction_policy",
            Self::RouteToUpstream => "mcp_dlp.route_to_upstream",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub tenant_id: String,
    pub prompt: String,
    /// Bailment ID covering this scan (short-lived Delegation, opened by the
    /// facade before the tool call).
    pub bailment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRequest {
    pub tenant_id: String,
    pub prompt: String,
    pub bailment_id: String,
    /// Optional redaction plan returned from `apply_redaction_policy`.
    pub redacted_prompt: Option<String>,
}
