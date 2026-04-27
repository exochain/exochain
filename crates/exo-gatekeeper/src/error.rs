//! Gatekeeper-specific errors.

use thiserror::Error;

/// Top-level error type for the gatekeeper crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatekeeperError {
    #[error("kernel integrity check failed: expected {expected}, got {actual}")]
    KernelIntegrityFailure { expected: String, actual: String },

    #[error("invariant violation: {0}")]
    InvariantViolation(String),

    #[error("combinator reduction failed: {0}")]
    CombinatorError(String),

    #[error("holon error: {0}")]
    HolonError(String),

    #[error("MCP violation: {0}")]
    McpViolation(String),

    #[error("TEE attestation failed: {0}")]
    TeeError(String),

    #[error("capability denied: {0}")]
    CapabilityDenied(String),

    #[error("timeout after {0} ms")]
    Timeout(u64),

    #[error("checkpoint error: {0}")]
    CheckpointError(String),

    #[error("core error: {0}")]
    Core(String),

    #[error("MCP audit chain broken at index {index}")]
    McpAuditChainBroken { index: usize },

    #[error("MCP audit record invalid: {reason}")]
    McpAuditInvalidRecord { reason: String },
}

impl From<exo_core::ExoError> for GatekeeperError {
    fn from(e: exo_core::ExoError) -> Self {
        GatekeeperError::Core(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_all_variants() {
        let cases: Vec<(GatekeeperError, &str)> = vec![
            (
                GatekeeperError::KernelIntegrityFailure {
                    expected: "abc".into(),
                    actual: "def".into(),
                },
                "abc",
            ),
            (GatekeeperError::InvariantViolation("bad".into()), "bad"),
            (GatekeeperError::CombinatorError("fail".into()), "fail"),
            (GatekeeperError::HolonError("holon".into()), "holon"),
            (GatekeeperError::McpViolation("mcp".into()), "mcp"),
            (GatekeeperError::TeeError("tee".into()), "tee"),
            (GatekeeperError::CapabilityDenied("cap".into()), "cap"),
            (GatekeeperError::Timeout(500), "500"),
            (GatekeeperError::CheckpointError("ckpt".into()), "ckpt"),
            (GatekeeperError::Core("core".into()), "core"),
            (
                GatekeeperError::McpAuditInvalidRecord {
                    reason: "missing deterministic metadata".into(),
                },
                "missing deterministic metadata",
            ),
        ];
        for (err, fragment) in cases {
            assert!(err.to_string().contains(fragment), "{err}");
        }
    }

    #[test]
    fn from_exo_error() {
        let exo = exo_core::ExoError::InvalidDid { value: "x".into() };
        let gk = GatekeeperError::from(exo);
        assert!(matches!(gk, GatekeeperError::Core(_)));
    }
}
