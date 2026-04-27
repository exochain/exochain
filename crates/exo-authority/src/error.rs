//! Authority-specific error types.

use thiserror::Error;

/// Errors that can occur during authority chain validation and delegation operations.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AuthorityError {
    #[error("chain broken at index {index}: {reason}")]
    ChainBroken { index: usize, reason: String },

    #[error("delegation depth {depth} exceeds maximum {max_depth}")]
    DepthExceeded { depth: usize, max_depth: usize },

    #[error("scope widening detected at index {index}")]
    ScopeWidening { index: usize },

    #[error("expired link at index {index}")]
    ExpiredLink { index: usize },

    #[error("invalid signature at index {index}")]
    InvalidSignature { index: usize },

    #[error("delegation signing payload encoding failed: {reason}")]
    SigningPayloadEncoding { reason: String },

    #[error("invalid delegation: {reason}")]
    InvalidDelegation { reason: String },

    #[error("duplicate delegation: {id}")]
    DuplicateDelegation { id: String },

    #[error("circular delegation detected: {0}")]
    CircularDelegation(String),

    #[error("delegation not found: {0}")]
    NotFound(String),

    #[error("empty chain")]
    EmptyChain,

    #[error("permission not granted: {0}")]
    PermissionDenied(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_chain_broken() {
        let e = AuthorityError::ChainBroken {
            index: 2,
            reason: "gap".into(),
        };
        assert!(e.to_string().contains("2"));
        assert!(e.to_string().contains("gap"));
    }

    #[test]
    fn error_display_depth_exceeded() {
        let e = AuthorityError::DepthExceeded {
            depth: 6,
            max_depth: 5,
        };
        assert!(e.to_string().contains("6"));
    }

    #[test]
    fn error_display_scope_widening() {
        let e = AuthorityError::ScopeWidening { index: 1 };
        assert!(e.to_string().contains("1"));
    }

    #[test]
    fn error_display_expired_link() {
        let e = AuthorityError::ExpiredLink { index: 0 };
        assert!(e.to_string().contains("0"));
    }

    #[test]
    fn error_display_invalid_signature() {
        let e = AuthorityError::InvalidSignature { index: 3 };
        assert!(e.to_string().contains("3"));
    }

    #[test]
    fn error_display_signing_payload_encoding() {
        let e = AuthorityError::SigningPayloadEncoding {
            reason: "writer".into(),
        };
        assert!(e.to_string().contains("writer"));
    }

    #[test]
    fn error_display_invalid_delegation() {
        let e = AuthorityError::InvalidDelegation {
            reason: "empty scope".into(),
        };
        assert!(e.to_string().contains("empty scope"));
    }

    #[test]
    fn error_display_duplicate_delegation() {
        let e = AuthorityError::DuplicateDelegation { id: "abc".into() };
        assert!(e.to_string().contains("abc"));
    }

    #[test]
    fn error_display_circular() {
        let e = AuthorityError::CircularDelegation("A->B->A".into());
        assert!(e.to_string().contains("A->B->A"));
    }

    #[test]
    fn error_display_not_found() {
        let e = AuthorityError::NotFound("link-x".into());
        assert!(e.to_string().contains("link-x"));
    }

    #[test]
    fn error_display_empty_chain() {
        let e = AuthorityError::EmptyChain;
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn error_display_permission_denied() {
        let e = AuthorityError::PermissionDenied("write".into());
        assert!(e.to_string().contains("write"));
    }

    #[test]
    fn error_clone_eq() {
        let e1 = AuthorityError::EmptyChain;
        assert_eq!(e1.clone(), e1);
    }
}
