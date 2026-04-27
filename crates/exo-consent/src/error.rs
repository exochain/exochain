//! Consent-specific error types.

use thiserror::Error;

/// Errors arising from consent operations.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ConsentError {
    #[error("invalid bailment state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("expired: {0}")]
    Expired(String),

    #[error("no consent found for action: {0}")]
    NoConsent(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("consent denied: {0}")]
    Denied(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_state() {
        let e = ConsentError::InvalidState {
            expected: "Active".into(),
            actual: "Proposed".into(),
        };
        assert!(e.to_string().contains("Active"));
        assert!(e.to_string().contains("Proposed"));
    }

    #[test]
    fn error_display_unauthorized() {
        let e = ConsentError::Unauthorized("bad actor".into());
        assert!(e.to_string().contains("bad actor"));
    }

    #[test]
    fn error_display_expired() {
        let e = ConsentError::Expired("ts 1000".into());
        assert!(e.to_string().contains("ts 1000"));
    }

    #[test]
    fn error_display_no_consent() {
        let e = ConsentError::NoConsent("read".into());
        assert!(e.to_string().contains("read"));
    }

    #[test]
    fn error_display_invalid_signature() {
        let e = ConsentError::InvalidSignature;
        assert!(e.to_string().contains("invalid signature"));
    }

    #[test]
    fn error_display_denied() {
        let e = ConsentError::Denied("policy says no".into());
        assert!(e.to_string().contains("policy says no"));
    }

    #[test]
    fn error_clone_eq() {
        let e1 = ConsentError::InvalidSignature;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }
}
