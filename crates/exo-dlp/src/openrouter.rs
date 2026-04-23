//! Blinded egress client for OpenRouter (MVP upstream).
//!
//! Responsibilities:
//! - Rotate the per-call ephemeral API key (wrapper over a `KeyCustodian`).
//! - Strip tenant-identifying headers (Referer, x-tenant, x-user, …).
//! - Set `store=false` on providers that honour it.
//! - Emit inbound + outbound payload hashes so the DAG can anchor them
//!   without ever persisting plaintext at the provider boundary.

use serde::{Deserialize, Serialize};

use crate::error::DlpError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlindingMode {
    /// Strip identifying headers, force `store=false`, rotate keys.
    Full,
    /// Dev-only: pass through with logging, never ship.
    Passthrough,
}

pub struct OpenRouterClient {
    pub base_url: String,
    pub blinding: BlindingMode,
}

impl OpenRouterClient {
    #[must_use]
    pub fn new(base_url: impl Into<String>, blinding: BlindingMode) -> Self {
        Self {
            base_url: base_url.into(),
            blinding,
        }
    }

    /// Forward a prompt upstream. Scaffold — real HTTP + streaming lands
    /// alongside the facade routing layer.
    pub async fn forward(&self, _body: &[u8]) -> Result<Vec<u8>, DlpError> {
        Err(DlpError::Unimplemented("OpenRouterClient::forward"))
    }
}
