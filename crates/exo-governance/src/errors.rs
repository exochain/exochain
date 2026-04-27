//! Governance error types (canonical, TNC-aware).

use exo_core::{Did, Hash256};
use thiserror::Error;

use crate::types::{DecisionClass, SemVer};

/// Canonical error type for all governance operations, covering TNC compliance violations.
#[derive(Error, Debug)]
pub enum GovernanceError {
    // --- Decision lifecycle errors ---
    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition { from: String, to: String },

    #[error("Decision {0:?} is immutable (terminal status reached) — TNC-08")]
    DecisionImmutable(Hash256),

    #[error("Decision {0:?} not found")]
    DecisionNotFound(Hash256),

    // --- Authority chain errors ---
    #[error("Authority chain verification failed: {reason}")]
    AuthorityChainBroken { reason: String },

    #[error("Delegation {0:?} has expired — TNC-05")]
    DelegationExpired(Hash256),

    #[error("Delegation {0:?} has been revoked")]
    DelegationRevoked(Hash256),

    #[error("Delegation {0:?} not found")]
    DelegationNotFound(Hash256),

    #[error("Sub-delegation not permitted by parent delegation {0:?}")]
    SubDelegationNotPermitted(Hash256),

    #[error("Authority chain exceeds maximum depth of {0} levels")]
    ChainTooDeep(usize),

    // --- Human gate errors (TNC-02) ---
    #[error(
        "Human gate required for {class:?} decisions but signer {signer} is an AI agent — TNC-02"
    )]
    HumanGateViolation { class: DecisionClass, signer: Did },

    // --- AI ceiling errors (TNC-09) ---
    #[error(
        "AI agent delegation ceiling exceeded: action {action} not permitted for AI agents — TNC-09"
    )]
    AiCeilingExceeded { action: String },

    // --- Constitutional errors ---
    #[error("Constitutional constraint {constraint_id} violated: {reason} — TNC-04")]
    ConstitutionalViolation {
        constraint_id: String,
        reason: String,
    },

    #[error("Constitution version {required} required but {actual} is active")]
    ConstitutionVersionMismatch { required: SemVer, actual: SemVer },

    #[error("Constitution not found for tenant")]
    ConstitutionNotFound,

    // --- Quorum errors (TNC-07) ---
    #[error("Quorum not met: {present} of {required} required members present — TNC-07")]
    QuorumNotMet { required: u32, present: u32 },

    // --- Conflict disclosure errors (TNC-06) ---
    #[error("Conflict disclosure required before participation by {0} — TNC-06")]
    ConflictDisclosureRequired(Did),

    // --- Challenge errors ---
    #[error("Challenge {0:?} not found")]
    ChallengeNotFound(Hash256),

    #[error("Decision {0:?} is already contested")]
    AlreadyContested(Hash256),

    // --- Emergency errors (TNC-10) ---
    #[error("Emergency action requires ratification — TNC-10")]
    RatificationRequired,

    #[error("Emergency action frequency threshold exceeded: {count} in current quarter")]
    EmergencyFrequencyExceeded { count: u32 },

    // --- Audit errors (TNC-03) ---
    #[error(
        "Audit chain integrity violation at sequence {sequence}: expected {expected:?}, got {actual:?} — TNC-03"
    )]
    AuditChainBroken {
        sequence: u64,
        expected: Hash256,
        actual: Hash256,
    },

    // --- Deliberation errors ---
    #[error("Deliberation is not open for votes")]
    DeliberationNotOpen,

    #[error("Duplicate vote from {0}")]
    DuplicateVote(String),

    // --- Succession / action errors ---
    #[error("Action not found: {0}")]
    ActionNotFound(String),

    // --- Serialization errors ---
    #[error("Serialization error: {0}")]
    Serialization(String),

    // --- Crypto errors ---
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    // --- Deterministic metadata errors ---
    #[error("Invalid governance metadata for {field}: {reason}")]
    InvalidGovernanceMetadata { field: String, reason: String },
}
