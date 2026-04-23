//! Local-model DLP scanner backed by an Ollama-compatible HTTP sidecar.
//!
//! The scaffold records the endpoint + model name. Real HTTP wiring lands
//! alongside a small blocking-vs-async integration so we don't pull a full
//! HTTP client into the workspace prematurely.

use async_trait::async_trait;

use super::{DlpScanner, ScanFindings};
use crate::error::DlpError;

pub struct OllamaScanner {
    pub endpoint: String,
    pub model: String,
}

impl OllamaScanner {
    #[must_use]
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            model: model.into(),
        }
    }
}

#[async_trait]
impl DlpScanner for OllamaScanner {
    async fn scan(&self, _prompt: &str) -> Result<ScanFindings, DlpError> {
        Err(DlpError::Unimplemented("OllamaScanner::scan"))
    }
}
