//! API-specific errors.
use thiserror::Error;

/// Errors returned by the exo-api layer.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("message verification failed: {reason}")]
    VerificationFailed { reason: String },
    #[error("rate limited: {peer_id}")]
    RateLimited { peer_id: String },
    #[error("invalid schema: {reason}")]
    InvalidSchema { reason: String },
    #[error("serialization error: {0}")]
    SerializationError(String),
}
/// Convenience alias for results with [`ApiError`].
pub type Result<T> = std::result::Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_variants_display() {
        let es: Vec<ApiError> = vec![
            ApiError::PeerNotFound("x".into()),
            ApiError::VerificationFailed { reason: "x".into() },
            ApiError::RateLimited {
                peer_id: "x".into(),
            },
            ApiError::InvalidSchema { reason: "x".into() },
            ApiError::SerializationError("x".into()),
        ];
        for e in &es {
            assert!(!e.to_string().is_empty());
        }
    }
    #[test]
    fn result_alias() {
        let ok: Result<u32> = Ok(1);
        assert!(ok.is_ok());
    }
}
