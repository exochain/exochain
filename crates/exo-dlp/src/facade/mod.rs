//! OpenAI / Anthropic / Gemini-shaped HTTP facades.
//!
//! Purpose: stock LLM SDKs (openai-python, @anthropic-ai/sdk, @google/genai)
//! can point at exoguard without code changes. Each facade module normalises
//! an inbound request into a canonical `FacadeRequest`, opens a bailment,
//! calls the `mcp_dlp.*` tools over the local MCP transport, and — if
//! allowed — forwards to OpenRouter via `openrouter.rs`.

use serde::{Deserialize, Serialize};

pub mod anthropic;
pub mod gemini;
pub mod openai;

/// Canonical, provider-agnostic request shape used inside exoguard after
/// facade normalisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacadeRequest {
    pub tenant_id: String,
    pub user_did: String,
    /// Human or AI signer; forwarded to `McpContext.signer_type`.
    pub signer_is_ai: bool,
    /// Canonicalised prompt text (system + user messages flattened).
    pub prompt: String,
    pub model_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FacadeResponse {
    Allowed { body: Vec<u8> },
    Blocked { audit_record_id: String },
}
