use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Round limit exceeded")]
    RoundLimitExceeded,

    #[error("Commitment mismatch for model {model_id}")]
    CommitmentMismatch { model_id: String },

    #[error("Model {model_id} not found in panel")]
    ModelNotFound { model_id: String },

    #[error("LLM Provider error: {0}")]
    ProviderError(String),

    #[error("Invalid panel configuration: {0}")]
    InvalidPanel(String),

    #[error("State error: {0}")]
    StateError(String),
}

pub type Result<T> = std::result::Result<T, ConsensusError>;
