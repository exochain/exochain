//! Gateway-specific errors.
use thiserror::Error;

/// Errors returned by gateway operations.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("authentication failed: {reason}")]
    AuthenticationFailed { reason: String },
    #[error("consent denied: {reason}")]
    ConsentDenied { reason: String },
    #[error("governance denied: {reason}")]
    GovernanceDenied { reason: String },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("bad request: {0}")]
    BadRequest(String),
}
/// Convenience alias for `Result<T, GatewayError>`.
pub type Result<T> = std::result::Result<T, GatewayError>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_display() {
        let es: Vec<GatewayError> = vec![
            GatewayError::AuthenticationFailed { reason: "x".into() },
            GatewayError::ConsentDenied { reason: "x".into() },
            GatewayError::GovernanceDenied { reason: "x".into() },
            GatewayError::NotFound("x".into()),
            GatewayError::Internal("x".into()),
            GatewayError::BadRequest("x".into()),
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
