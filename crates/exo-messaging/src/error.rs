//! Messaging-specific error types.

/// Errors that can occur during messaging operations.
#[derive(Debug, thiserror::Error)]
pub enum MessagingError {
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: ciphertext invalid or wrong key")]
    DecryptionFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("death-trigger confirmation payload encoding failed: {0}")]
    DeathConfirmationPayloadEncoding(String),

    #[error("envelope signing payload encoding failed: {0}")]
    EnvelopeSigningPayloadEncoding(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("identity error: {0}")]
    Identity(#[from] exo_identity::error::IdentityError),

    #[error("death trigger already resolved")]
    DeathTriggerAlreadyResolved,

    #[error("invalid death verification: {0}")]
    InvalidDeathVerification(String),

    #[error("insufficient confirmations: need {need}, got {got}")]
    InsufficientConfirmations { need: u8, got: u8 },

    #[error("unauthorized death-trigger trustee: {0}")]
    UnauthorizedTrustee(String),

    #[error("duplicate confirmation from: {0}")]
    DuplicateConfirmation(String),
}
