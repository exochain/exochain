//! exoguard configuration — both global (one deployment) and tenant overlays.
//!
//! Config changes happen *only* via signed `updateExoguardConfig` MCP calls
//! so that every reconfig is itself an auditable event in the chain. This
//! module defines the value shapes; ingestion + validation live in
//! `mcp_tools`.

use serde::{Deserialize, Serialize};

use crate::openrouter::BlindingMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerBackend {
    Ollama,
    RegexOnly,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProvider {
    OpenRouter,
    /// Dev/test only; production pilots must use OpenRouter.
    PassthroughOpenAi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalDlpConfig {
    pub listen_addr: String,
    pub facades: Vec<String>, // "openai" | "anthropic" | "gemini"
    pub scanner_backend: ScannerBackend,
    pub ollama_url: Option<String>,
    pub scanner_model: String,
    pub upstream: UpstreamProvider,
    pub tenant_config_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicy {
    pub ruleset: String, // "healthcare_hipaa" | "finance_pci" | "default"
    /// Severity threshold in basis points above which the prompt is blocked.
    pub block_threshold_bps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDlpConfig {
    pub tenant_id: String,
    pub policy: TenantPolicy,
    pub scanner_model: String,
    pub scanner_backend: ScannerBackend,
    pub blinding: BlindingMode,
    pub alert_webhook: Option<String>,
    pub custodian_members: Vec<String>,
    pub custodian_threshold: u32,
}
