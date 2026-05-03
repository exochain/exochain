//! Shared governance types used across the decision.forum domain.
//!
//! Provides the constitutional type vocabulary for governance policies:
//! - [`DecisionClass`] taxonomy with [`requires_human_gate`](DecisionClass::requires_human_gate) (TNC-02)
//! - [`SignerType`] distinguishing human vs AI signatures
//! - [`GovernanceSignature`] with signer identity and role metadata
//! - [`AuthorizedAction`] enumeration of governable operations
//! - [`SemVer`] for constitutional document versioning
//! - [`EvidenceRef`] for legal evidence attachment (LEG-004, LEG-006)
//! - [`FailureAction`] for constitutional constraint violation responses

use std::cmp::Ordering;

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

/// Tenant identifier — opaque string, unique per organization.
pub type TenantId = String;

/// Financial commitment threshold at or above which human approval is required.
///
/// Stored in cents to preserve deterministic integer arithmetic. This keeps
/// low-value operational spend below the human gate while preventing AI-only
/// authorization of material financial commitments.
pub const FINANCIAL_HUMAN_GATE_THRESHOLD_CENTS: u64 = 100_000;

/// Semantic version for constitutional documents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    #[must_use]
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns true if this version is compatible with (>=) `other`.
    #[must_use]
    pub fn is_compatible_with(&self, other: &SemVer) -> bool {
        self.major == other.major
            && (self.minor > other.minor
                || (self.minor == other.minor && self.patch >= other.patch))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Classification of decisions determining governance requirements.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DecisionClass {
    /// Operational decisions — routine, low-risk.
    Operational,
    /// Strategic decisions — significant impact, require broader approval.
    Strategic,
    /// Constitutional decisions — amendments to governance framework itself.
    Constitutional,
    /// Financial decisions — monetary commitments above threshold.
    Financial { threshold_cents: u64 },
    /// Emergency decisions — bypass normal process, require ratification.
    Emergency,
    /// Custom tenant-defined decision class.
    Custom(String),
}

impl DecisionClass {
    /// Returns true if this class requires a human gate (TNC-02).
    ///
    /// Constitutional, Strategic, Emergency, and material Financial decisions
    /// MUST have human approval — AI agents alone cannot authorize these
    /// decision classes.
    #[must_use]
    pub fn requires_human_gate(&self) -> bool {
        match self {
            DecisionClass::Constitutional | DecisionClass::Strategic | DecisionClass::Emergency => {
                true
            }
            DecisionClass::Financial { threshold_cents } => {
                *threshold_cents >= FINANCIAL_HUMAN_GATE_THRESHOLD_CENTS
            }
            DecisionClass::Operational | DecisionClass::Custom(_) => false,
        }
    }
}

impl std::fmt::Display for DecisionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecisionClass::Operational => f.write_str("Operational"),
            DecisionClass::Strategic => f.write_str("Strategic"),
            DecisionClass::Constitutional => f.write_str("Constitutional"),
            DecisionClass::Financial { threshold_cents } => {
                write!(f, "Financial(threshold_cents={threshold_cents})")
            }
            DecisionClass::Emergency => f.write_str("Emergency"),
            DecisionClass::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

/// Signer type — cryptographically distinguishes human vs AI signatures (TNC-02).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerType {
    /// Human signer — verified through authentication.
    Human,
    /// AI agent signer — acting under a specific delegation with expiry.
    AiAgent {
        /// Hash of the delegation authorization.
        delegation_id: Hash256,
        /// Expiry timestamp in milliseconds.
        expires_at: u64,
    },
}

/// Governance-aware signature that includes signer type metadata.
///
/// Extends a bare cryptographic signature with identity and role context,
/// enabling audit trails to distinguish human from AI attestations.
#[derive(Clone, Serialize, Deserialize)]
pub struct GovernanceSignature {
    /// DID of the signer.
    pub signer: Did,
    /// Whether this is a human or AI agent signature.
    pub signer_type: SignerType,
    /// Cryptographic signature bytes.
    pub signature: Signature,
    /// Key version used for signing.
    pub key_version: u64,
    /// Timestamp of signature.
    pub timestamp: Timestamp,
}

impl std::fmt::Debug for GovernanceSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernanceSignature")
            .field("signer", &self.signer)
            .field("signer_type", &self.signer_type)
            .field("signature", &"[REDACTED]")
            .field("key_version", &self.key_version)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Actions that can be authorized via delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuthorizedAction {
    CreateDecision,
    AdvanceDecision,
    CastVote,
    GrantDelegation,
    RevokeDelegation,
    RaiseChallenge,
    TakeEmergencyAction,
    AmendConstitution,
    DiscloseConflict,
    Custom(String),
}

impl std::fmt::Display for AuthorizedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizedAction::CreateDecision => f.write_str("CreateDecision"),
            AuthorizedAction::AdvanceDecision => f.write_str("AdvanceDecision"),
            AuthorizedAction::CastVote => f.write_str("CastVote"),
            AuthorizedAction::GrantDelegation => f.write_str("GrantDelegation"),
            AuthorizedAction::RevokeDelegation => f.write_str("RevokeDelegation"),
            AuthorizedAction::RaiseChallenge => f.write_str("RaiseChallenge"),
            AuthorizedAction::TakeEmergencyAction => f.write_str("TakeEmergencyAction"),
            AuthorizedAction::AmendConstitution => f.write_str("AmendConstitution"),
            AuthorizedAction::DiscloseConflict => f.write_str("DiscloseConflict"),
            AuthorizedAction::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

/// Reference to evidence attached to a decision (LEG-004, LEG-006).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub id: String,
    pub description: String,
    /// Hash of the evidence content for integrity verification.
    pub content_hash: Hash256,
    pub timestamp: Timestamp,
    pub author: Did,
}

/// Failure action when a constitutional constraint is violated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FailureAction {
    /// Block the action entirely.
    Block,
    /// Warn but allow the action to proceed.
    Warn,
    /// Escalate to a higher authority for review.
    Escalate { escalation_target: Did },
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_display() {
        let v = SemVer::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_semver_compatibility() {
        let v1 = SemVer::new(1, 2, 0);
        let v2 = SemVer::new(1, 1, 0);
        let v3 = SemVer::new(2, 0, 0);
        assert!(v1.is_compatible_with(&v2));
        assert!(!v2.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_semver_ordering_is_explicit_precedence_not_compatibility() {
        assert!(
            SemVer::new(1, 10, 0) > SemVer::new(1, 2, 99),
            "semantic precedence must compare numeric major, minor, then patch components"
        );
        assert!(
            SemVer::new(2, 0, 0) > SemVer::new(1, u32::MAX, u32::MAX),
            "major version precedence must dominate minor and patch components"
        );
        assert!(
            !SemVer::new(2, 0, 0).is_compatible_with(&SemVer::new(1, u32::MAX, u32::MAX)),
            "ordering precedence must not imply constitutional compatibility"
        );

        let source = include_str!("types.rs");
        assert!(
            !source.contains(concat!("Partial", "Ord, Ord")),
            "SemVer ordering must be implemented explicitly instead of derived"
        );
        assert!(
            source.contains(concat!("impl Ord", " for SemVer")),
            "SemVer must document precedence through an explicit Ord implementation"
        );
    }

    #[test]
    fn test_decision_class_human_gate() {
        assert!(DecisionClass::Constitutional.requires_human_gate());
        assert!(DecisionClass::Strategic.requires_human_gate());
        assert!(DecisionClass::Emergency.requires_human_gate());
        assert!(!DecisionClass::Operational.requires_human_gate());
        assert!(
            !DecisionClass::Financial {
                threshold_cents: 1000
            }
            .requires_human_gate()
        );
    }

    #[test]
    fn test_financial_decision_requires_human_gate_at_threshold() {
        assert!(
            !DecisionClass::Financial {
                threshold_cents: 99_999
            }
            .requires_human_gate()
        );
        assert!(
            DecisionClass::Financial {
                threshold_cents: 100_000
            }
            .requires_human_gate()
        );
        assert!(
            DecisionClass::Financial {
                threshold_cents: u64::MAX
            }
            .requires_human_gate()
        );
    }

    #[test]
    fn test_governance_signature_debug_redacts_signature_material() {
        let signature = GovernanceSignature {
            signer: Did::new("did:exo:secretary").expect("valid"),
            signer_type: SignerType::Human,
            signature: Signature::Ed25519([7_u8; 64]),
            key_version: 3,
            timestamp: Timestamp::new(1000, 0),
        };

        let debug = format!("{signature:?}");
        assert!(debug.contains("GovernanceSignature"));
        assert!(debug.contains("signature: \"[REDACTED]\""));
        assert!(!debug.contains("Ed25519"));
        assert!(!debug.contains("7, 7"));
    }

    #[test]
    fn test_custom_decision_class_no_human_gate() {
        assert!(!DecisionClass::Custom("routine".to_string()).requires_human_gate());
    }

    #[test]
    fn test_signer_type_variants() {
        let human = SignerType::Human;
        let ai = SignerType::AiAgent {
            delegation_id: Hash256::ZERO,
            expires_at: 9999,
        };
        assert_ne!(human, ai);
    }

    #[test]
    fn test_authorized_action_equality() {
        assert_eq!(AuthorizedAction::CastVote, AuthorizedAction::CastVote);
        assert_ne!(AuthorizedAction::CastVote, AuthorizedAction::CreateDecision);
    }

    #[test]
    fn stable_display_labels_for_class_and_action() {
        assert_eq!(DecisionClass::Strategic.to_string(), "Strategic");
        assert_eq!(
            DecisionClass::Financial {
                threshold_cents: 100_000
            }
            .to_string(),
            "Financial(threshold_cents=100000)"
        );
        assert_eq!(
            DecisionClass::Custom("tenant-local".to_string()).to_string(),
            "Custom(tenant-local)"
        );
        assert_eq!(AuthorizedAction::CastVote.to_string(), "CastVote");
        assert_eq!(
            AuthorizedAction::Custom("tenant-action".to_string()).to_string(),
            "Custom(tenant-action)"
        );
    }

    #[test]
    fn test_evidence_ref() {
        let evidence = EvidenceRef {
            id: "ev-001".to_string(),
            description: "Board minutes".to_string(),
            content_hash: Hash256::digest(b"board-minutes-2024"),
            timestamp: Timestamp::new(1000, 0),
            author: Did::new("did:exo:secretary").expect("valid"),
        };
        assert_eq!(evidence.id, "ev-001");
    }
}
