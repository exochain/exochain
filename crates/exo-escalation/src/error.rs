//! Escalation error types.

use thiserror::Error;

/// Errors that can occur during escalation case management.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EscalationError {
    #[error("case not found: {0}")]
    CaseNotFound(String),

    #[error("invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("incomplete case: {reason}")]
    IncompleteCase { reason: String },

    #[error("invalid signal: {0}")]
    InvalidSignal(String),

    #[error("invalid provenance: {reason}")]
    InvalidProvenance { reason: String },

    #[error("invalid signature from {signer}: {reason}")]
    InvalidSignature { signer: String, reason: String },

    #[error("serialization failed for {context}: {reason}")]
    SerializationFailed { context: String, reason: String },

    #[error("column not found: {0}")]
    ColumnNotFound(String),
}
