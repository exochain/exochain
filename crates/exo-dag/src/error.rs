//! DAG error types.
//!
//! Defines the [`DagError`] enum and a convenience `Result` alias.

use exo_core::types::Hash256;
use thiserror::Error;

/// Errors for the DAG, consensus, and Merkle modules.
#[derive(Debug, Error)]
pub enum DagError {
    #[error("parent not found: {0}")]
    ParentNotFound(Hash256),

    #[error("node already exists: {0}")]
    NodeAlreadyExists(Hash256),

    #[error("cycle detected: node {0} would create a cycle")]
    CycleDetected(Hash256),

    #[error("invalid signature on node {0}")]
    InvalidSignature(Hash256),

    #[error("duplicate vote from {voter} in round {round}")]
    DuplicateVote { voter: String, round: u64 },

    #[error(
        "equivocation detected for {voter} in round {round}: first node {first_node}, conflicting node {conflicting_node}"
    )]
    EquivocationDetected {
        voter: String,
        round: u64,
        first_node: Hash256,
        conflicting_node: Hash256,
    },

    #[error("voter {0} is not a validator")]
    NotAValidator(String),

    #[error("invalid round: expected {expected}, got {got}")]
    InvalidRound { expected: u64, got: u64 },

    #[error("consensus round overflow: cannot advance beyond round {current_round}")]
    RoundOverflow { current_round: u64 },

    #[error("DAG clock overflow: cannot advance beyond timestamp {physical_ms}:{logical}")]
    ClockOverflow { physical_ms: u64, logical: u32 },

    #[error("insufficient quorum in round {round}: required {required}, got {actual}")]
    InsufficientQuorum {
        required: usize,
        actual: usize,
        round: u64,
    },

    #[error("node not found: {0}")]
    NodeNotFound(Hash256),

    #[error("empty parents list")]
    EmptyParents,

    #[error("sparse merkle tree error: {0}")]
    SmtError(String),

    #[error("MMR position out of bounds: requested position {position}, leaf count {leaf_count}")]
    MmrPositionOutOfBounds { position: usize, leaf_count: usize },

    #[error("mmr error: {0}")]
    MmrError(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("store error: {0}")]
    StoreError(String),
}

pub type Result<T> = std::result::Result<T, DagError>;
