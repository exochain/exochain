//! Decision forum error types.
//!
//! Every failure mode in the governance application has a dedicated variant
//! ensuring exhaustive error handling at compile time.

use thiserror::Error;

/// Unified error type for all decision-forum operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ForumError {
    // -- Authority errors --------------------------------------------------
    #[error("authority verification failed: {reason}")]
    AuthorityInvalid { reason: String },

    #[error("delegation expired")]
    DelegationExpired,

    #[error("delegation scope exceeded: {reason}")]
    DelegationScopeExceeded { reason: String },

    #[error("sub-delegation not permitted")]
    SubDelegationNotPermitted,

    // -- Constitution errors -----------------------------------------------
    #[error("constitution not ratified: {reason}")]
    NotRatified { reason: String },

    #[error("amendment failed: {reason}")]
    AmendmentFailed { reason: String },

    #[error("constitutional conflict: {reason}")]
    ConstitutionalConflict { reason: String },

    // -- Quorum errors -----------------------------------------------------
    #[error("quorum not met: required {required}, got {actual}")]
    QuorumNotMet { required: usize, actual: usize },

    #[error("quorum policy missing for decision class")]
    QuorumPolicyMissing,

    // -- Decision errors ---------------------------------------------------
    #[error("decision not found: {0}")]
    DecisionNotFound(String),

    #[error("enactment failed: {reason}")]
    EnactmentFailed { reason: String },

    #[error("decision immutable in terminal state")]
    DecisionImmutable,

    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("invalid provenance metadata: {reason}")]
    InvalidProvenance { reason: String },

    // -- Human gate errors -------------------------------------------------
    #[error("human gate required: AI cannot satisfy this approval")]
    HumanGateRequired,

    #[error("AI delegation ceiling exceeded: {reason}")]
    AiCeilingExceeded { reason: String },

    // -- TNC errors --------------------------------------------------------
    #[error("TNC violation: TNC-{tnc_id:02}: {reason}")]
    TncViolation { tnc_id: u32, reason: String },

    // -- Contestation errors -----------------------------------------------
    #[error("challenge error: {reason}")]
    ChallengeError { reason: String },

    #[error("decision contested — execution paused")]
    ExecutionPaused,

    // -- Emergency errors --------------------------------------------------
    #[error("emergency action invalid: {reason}")]
    EmergencyInvalid { reason: String },

    #[error("emergency cap exceeded: {reason}")]
    EmergencyCapExceeded { reason: String },

    // -- Accountability errors ---------------------------------------------
    #[error("accountability action failed: {reason}")]
    AccountabilityFailed { reason: String },

    // -- Terms errors ------------------------------------------------------
    #[error("terms not accepted by {0}")]
    TermsNotAccepted(String),

    // -- General -----------------------------------------------------------
    #[error("core error: {0}")]
    Core(String),

    #[error("governance error: {0}")]
    Governance(String),
}

/// Convenient Result alias.
pub type Result<T> = std::result::Result<T, ForumError>;

impl From<exo_core::ExoError> for ForumError {
    fn from(e: exo_core::ExoError) -> Self {
        ForumError::Core(e.to_string())
    }
}

impl From<exo_governance::GovernanceError> for ForumError {
    fn from(e: exo_governance::GovernanceError) -> Self {
        ForumError::Governance(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_display() {
        let errors: Vec<ForumError> = vec![
            ForumError::AuthorityInvalid {
                reason: "bad sig".into(),
            },
            ForumError::DelegationExpired,
            ForumError::DelegationScopeExceeded {
                reason: "too wide".into(),
            },
            ForumError::SubDelegationNotPermitted,
            ForumError::NotRatified {
                reason: "pending".into(),
            },
            ForumError::AmendmentFailed {
                reason: "no quorum".into(),
            },
            ForumError::ConstitutionalConflict {
                reason: "overlap".into(),
            },
            ForumError::QuorumNotMet {
                required: 3,
                actual: 1,
            },
            ForumError::QuorumPolicyMissing,
            ForumError::DecisionNotFound("abc".into()),
            ForumError::EnactmentFailed {
                reason: "rejected".into(),
            },
            ForumError::DecisionImmutable,
            ForumError::InvalidTransition {
                from: "Draft".into(),
                to: "Closed".into(),
            },
            ForumError::InvalidProvenance {
                reason: "nil id".into(),
            },
            ForumError::HumanGateRequired,
            ForumError::AiCeilingExceeded {
                reason: "Strategic".into(),
            },
            ForumError::TncViolation {
                tnc_id: 1,
                reason: "no auth".into(),
            },
            ForumError::ChallengeError {
                reason: "invalid".into(),
            },
            ForumError::ExecutionPaused,
            ForumError::EmergencyInvalid {
                reason: "no scope".into(),
            },
            ForumError::EmergencyCapExceeded {
                reason: "over limit".into(),
            },
            ForumError::AccountabilityFailed {
                reason: "no due process".into(),
            },
            ForumError::TermsNotAccepted("alice".into()),
            ForumError::Core("oops".into()),
            ForumError::Governance("quorum fail".into()),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty(), "empty display for {e:?}");
        }
    }

    #[test]
    fn tnc_violation_formats_id() {
        let e = ForumError::TncViolation {
            tnc_id: 7,
            reason: "test".into(),
        };
        assert!(e.to_string().contains("TNC-07"));
    }

    #[test]
    fn from_exo_error() {
        let core = exo_core::ExoError::InvalidMerkleProof;
        let forum: ForumError = core.into();
        assert!(matches!(forum, ForumError::Core(_)));
    }

    #[test]
    fn clone_eq() {
        let e1 = ForumError::DelegationExpired;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }
}
