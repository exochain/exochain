//! Error types for the proof system.

use thiserror::Error;

/// Errors arising from proof operations.
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("constraint system error: {0}")]
    ConstraintError(String),

    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("setup error: {0}")]
    SetupError(String),

    #[error("invalid witness: {0}")]
    InvalidWitness(String),

    #[error("deserialization error: {0}")]
    DeserializationError(String),
}

/// Convenience alias for results that may fail with a [`ProofError`].
pub type Result<T> = std::result::Result<T, ProofError>;
