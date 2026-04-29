//! Legal-specific errors for the EXOCHAIN trust fabric.

use thiserror::Error;
use uuid::Uuid;

/// Errors originating from legal-domain operations (evidence, privilege, fiduciary, discovery).
#[derive(Debug, Error)]
pub enum LegalError {
    #[error("evidence not found: {0}")]
    EvidenceNotFound(Uuid),
    #[error("chain of custody broken at transfer index {index}")]
    CustodyChainBroken { index: usize },
    #[error("custody transfer failed: {reason}")]
    CustodyTransferFailed { reason: String },
    #[error("evidence is not admissible: {reason}")]
    NotAdmissible { reason: String },
    #[error("privilege assertion invalid: {reason}")]
    PrivilegeInvalid { reason: String },
    #[error("privilege already asserted for evidence {0}")]
    PrivilegeAlreadyAsserted(Uuid),
    #[error("fiduciary duty violation: {reason}")]
    FiduciaryViolation { reason: String },
    #[error("discovery scope too broad: {reason}")]
    DiscoveryScopeTooBoard { reason: String },
    #[error("retention policy violation: {reason}")]
    RetentionViolation { reason: String },
    #[error("disclosure required for action: {action}")]
    DisclosureRequired { action: String },
    #[error("disclosure verification invalid: {reason}")]
    DisclosureVerificationInvalid { reason: String },
    #[error("conflict of interest: {reason}")]
    ConflictOfInterest { reason: String },
    #[error("record not found: {0}")]
    RecordNotFound(Uuid),
    #[error("invalid state transition: {reason}")]
    InvalidStateTransition { reason: String },
    #[error("FRE 902(11) certificate hash encoding failed: {reason}")]
    CertificationHashEncodingFailed { reason: String },
}

/// Convenience alias for results that carry a [`LegalError`].
pub type Result<T> = std::result::Result<T, LegalError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_all_variants() {
        let id = Uuid::nil();
        let cases: Vec<Box<dyn std::fmt::Display>> = vec![
            Box::new(LegalError::EvidenceNotFound(id)),
            Box::new(LegalError::CustodyChainBroken { index: 3 }),
            Box::new(LegalError::CustodyTransferFailed { reason: "x".into() }),
            Box::new(LegalError::NotAdmissible { reason: "x".into() }),
            Box::new(LegalError::PrivilegeInvalid { reason: "x".into() }),
            Box::new(LegalError::PrivilegeAlreadyAsserted(id)),
            Box::new(LegalError::FiduciaryViolation { reason: "x".into() }),
            Box::new(LegalError::DiscoveryScopeTooBoard { reason: "x".into() }),
            Box::new(LegalError::RetentionViolation { reason: "x".into() }),
            Box::new(LegalError::DisclosureRequired {
                action: "vote".into(),
            }),
            Box::new(LegalError::DisclosureVerificationInvalid { reason: "x".into() }),
            Box::new(LegalError::ConflictOfInterest { reason: "x".into() }),
            Box::new(LegalError::RecordNotFound(id)),
            Box::new(LegalError::InvalidStateTransition { reason: "x".into() }),
            Box::new(LegalError::CertificationHashEncodingFailed { reason: "x".into() }),
        ];
        for c in &cases {
            assert!(!c.to_string().is_empty());
        }
    }

    #[test]
    fn result_alias() {
        let ok: Result<u32> = Ok(42);
        if let Ok(val) = ok {
            assert_eq!(val, 42);
        }
        let err: Result<u32> = Err(LegalError::EvidenceNotFound(Uuid::nil()));
        assert!(err.is_err());
    }
}
