//! Bucket registry for multi-panel "council" analysis of a prompt.
//!
//! Ports the exoforge 5-panel council prompts (Legal, Security, Architecture,
//! Compliance, BusinessSensitivity) as JSON-schema-constrained local-model
//! calls. Each bucket returns an independent verdict which the
//! `ConstitutionalKernel` merges into a single `McpEnforcementOutcome`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Bucket {
    Legal,
    Security,
    Architecture,
    Compliance,
    BusinessSensitivity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketVerdict {
    pub bucket: Bucket,
    /// Severity in basis points, 0..=10_000.
    pub severity_bps: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BucketRegistry {
    pub enabled: Vec<Bucket>,
}

impl BucketRegistry {
    #[must_use]
    pub fn all() -> Self {
        Self {
            enabled: vec![
                Bucket::Legal,
                Bucket::Security,
                Bucket::Architecture,
                Bucket::Compliance,
                Bucket::BusinessSensitivity,
            ],
        }
    }
}
