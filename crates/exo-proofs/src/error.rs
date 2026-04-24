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

    /// The `exo-proofs` crate is a pedagogical/structural implementation —
    /// not cryptographically hardened. It refuses to execute unless the
    /// opt-in `unaudited-pedagogical-proofs` Cargo feature is enabled.
    ///
    /// Constitutional rule (per EXOCHAIN doctrine): never ship code that
    /// claims a capability it does not have. Callers who want to use this
    /// crate for classroom/structural work must explicitly opt in; callers
    /// who accidentally depend on it will fail loudly at call time instead
    /// of trusting a fake proof.
    ///
    /// When a real proof backend (production-hardened SNARK/STARK/ZKML)
    /// lands, the opt-in flag MUST be removed and this variant deleted.
    #[error(
        "exo-proofs is unaudited (pedagogical implementation). \
         Callers must opt in with the 'unaudited-pedagogical-proofs' \
         Cargo feature before {api} will execute. \
         Do NOT enable this flag in production."
    )]
    UnauditedImplementation {
        /// The verifier/prover API that refused.
        api: &'static str,
    },
}

/// Convenience alias for results that may fail with a [`ProofError`].
pub type Result<T> = std::result::Result<T, ProofError>;
