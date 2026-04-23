//! Fast, deterministic regex-based preflight scan. Runs before any
//! model-based scanner to catch unambiguous patterns (SSN, PAN, MRN, AWS
//! keys, tenant-specific codewords).
//!
//! Patterns are table-driven and loaded from tenant config; the scaffold
//! here wires the shape and leaves the actual pattern set to be populated
//! from `DlpConfig`.

use async_trait::async_trait;

use super::{DlpScanner, Finding, ScanFindings};
use crate::error::DlpError;

pub struct RegexPreflightScanner {
    // TODO: compile patterns ahead of time, store Vec<(category, label, Regex, severity_bps)>.
    // Populated from DlpConfig on construction.
}

impl RegexPreflightScanner {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for RegexPreflightScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DlpScanner for RegexPreflightScanner {
    async fn scan(&self, _prompt: &str) -> Result<ScanFindings, DlpError> {
        // Scaffold: empty findings. Real patterns land with the Mcp007 rule
        // + DlpConfig parsing in a follow-up commit.
        let _example: Finding = Finding {
            category: String::new(),
            label: String::new(),
            span: None,
            severity_bps: 0,
            source: "regex_preflight".into(),
        };
        drop(_example);
        Ok(ScanFindings::default())
    }
}
