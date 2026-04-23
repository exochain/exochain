//! DLP scanner trait + supporting types.
//!
//! Severity is an integer score in basis points (0..=10_000). The workspace
//! lints deny float arithmetic, so scoring and thresholds are strictly
//! integer.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::DlpError;

pub mod ollama;
pub mod regex_preflight;

/// A single DLP finding (one regex hit, one model classification, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Coarse category — `pii`, `phi`, `secret`, `corporate_codename`, ...
    pub category: String,
    /// Free-form label scoped to `category` — e.g. `ssn`, `mrn`, `aws_key`.
    pub label: String,
    /// Byte span in the input; `None` for whole-document classifiers.
    pub span: Option<(usize, usize)>,
    /// Severity in basis points, 0..=10_000. Higher = more sensitive.
    pub severity_bps: u32,
    /// Scanner identifier — e.g. `regex_preflight`, `ollama:llama-guard3:8b`.
    pub source: String,
}

/// Result of a scan pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanFindings {
    pub findings: Vec<Finding>,
}

impl ScanFindings {
    /// Highest severity across all findings, or 0 if empty.
    #[must_use]
    pub fn max_severity_bps(&self) -> u32 {
        self.findings
            .iter()
            .map(|f| f.severity_bps)
            .max()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

/// A DLP scanner — a local classifier that receives prompt text and returns
/// structured findings. Implementations must be deterministic for a fixed
/// model + input (Ollama backends pin `seed`, `temperature=0`, etc.).
#[async_trait]
pub trait DlpScanner: Send + Sync {
    async fn scan(&self, prompt: &str) -> Result<ScanFindings, DlpError>;
}
