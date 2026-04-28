//! Identity-specific error types for the EXOCHAIN identity subsystem.

use exo_core::{Did, Timestamp};

/// Errors that can occur during identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("DID already registered: {0}")]
    DuplicateDid(Did),

    #[error("DID not found: {0}")]
    DidNotFound(Did),

    #[error("DID has been revoked: {0}")]
    DidRevoked(Did),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("non-monotonic timestamp for DID {did}: current={current}, proposed={proposed}")]
    NonMonotonicTimestamp {
        did: Did,
        current: Timestamp,
        proposed: Timestamp,
    },

    #[error("invalid revocation proof for DID: {0}")]
    InvalidRevocationProof(Did),

    #[error("public key not found on DID: {0}")]
    KeyNotFound(Did),

    #[error("key already revoked")]
    KeyAlreadyRevoked,

    #[error("key already rotated")]
    KeyAlreadyRotated,

    #[error("invalid Shamir config: threshold={threshold}, shares={shares}")]
    InvalidShamirConfig { threshold: u8, shares: u8 },

    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: u8, got: u8 },

    #[error("invalid share index: {0}")]
    InvalidShareIndex(u8),

    #[error("duplicate share indices")]
    DuplicateShareIndices,

    #[error("invalid PACE config: {0}")]
    InvalidPaceConfig(String),

    #[error("cannot escalate: already at maximum level")]
    CannotEscalate,

    #[error("cannot de-escalate: already at Normal")]
    CannotDeescalate,

    #[error("risk attestation expired")]
    AttestationExpired,

    #[error("risk attestation signing payload encoding failed: {reason}")]
    RiskAttestationSigningPayloadEncoding { reason: String },

    #[error(
        "risk attestation expiry overflow: now_physical_ms={now_physical_ms}, validity_ms={validity_ms}"
    )]
    RiskAttestationExpiryOverflow {
        now_physical_ms: u64,
        validity_ms: u64,
    },

    #[error("duplicate DID across PACE levels: {0}")]
    DuplicatePaceDid(Did),

    #[error("vault key derivation failed: {0}")]
    VaultKeyDerivationFailed(String),

    #[error("vault encryption failed: {0}")]
    VaultEncryptionFailed(String),

    #[error("vault decryption failed: authentication or ciphertext invalid")]
    VaultDecryptionFailed,

    #[error("vault ciphertext too short")]
    VaultCiphertextTooShort,
}
