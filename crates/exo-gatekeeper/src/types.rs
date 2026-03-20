//! Gatekeeper governance types.
//!
//! Types specific to the judicial branch that are not part of exo-core.

use exo_core::Did;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Permission & capability types
// ---------------------------------------------------------------------------

/// A named permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission(pub String);

impl Permission {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// A set of permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PermissionSet {
    pub permissions: Vec<Permission>,
}

impl PermissionSet {
    #[must_use]
    pub fn new(permissions: Vec<Permission>) -> Self {
        Self { permissions }
    }

    pub fn contains(&self, p: &Permission) -> bool {
        self.permissions.contains(p)
    }

    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Government branches & roles
// ---------------------------------------------------------------------------

/// Branch of government.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovernmentBranch {
    Legislative,
    Executive,
    Judicial,
}

/// Role held by an actor in the constitutional fabric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub branch: GovernmentBranch,
}

// ---------------------------------------------------------------------------
// Bailment state (gatekeeper view — simpler than BCTS lifecycle)
// ---------------------------------------------------------------------------

/// Whether an active bailment + consent exists for a data scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BailmentState {
    /// No bailment established.
    None,
    /// Active bailment with consent.
    Active {
        bailor: Did,
        bailee: Did,
        scope: String,
    },
    /// Bailment suspended.
    Suspended { reason: String },
    /// Bailment terminated.
    Terminated,
}

impl BailmentState {
    pub fn is_active(&self) -> bool {
        matches!(self, BailmentState::Active { .. })
    }
}

// ---------------------------------------------------------------------------
// Consent record
// ---------------------------------------------------------------------------

/// A consent record for the gatekeeper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub subject: Did,
    pub granted_to: Did,
    pub scope: String,
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Authority chain
// ---------------------------------------------------------------------------

/// Authority chain — the delegation path from root to actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthorityChain {
    pub links: Vec<AuthorityLink>,
}

impl AuthorityChain {
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.links.len()
    }
}

/// A single link in an authority chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLink {
    pub grantor: Did,
    pub grantee: Did,
    pub permissions: PermissionSet,
    pub signature: Vec<u8>,
    /// Ed25519 public key (32 bytes) of the grantor.
    ///
    /// When present, `check_authority_chain_valid` performs full cryptographic
    /// Ed25519 signature verification over the canonical link payload
    /// (grantor || grantee || permissions). When absent, only non-emptiness of
    /// `signature` is checked (legacy path for links without embedded keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantor_public_key: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Quorum evidence
// ---------------------------------------------------------------------------

/// Quorum decision evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumEvidence {
    pub threshold: u32,
    pub votes: Vec<QuorumVote>,
}

impl QuorumEvidence {
    pub fn is_met(&self) -> bool {
        let approvals =
            u32::try_from(self.votes.iter().filter(|v| v.approved).count()).unwrap_or(u32::MAX);
        approvals >= self.threshold
    }
}

/// A single quorum vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumVote {
    pub voter: Did,
    pub approved: bool,
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Provenance metadata
// ---------------------------------------------------------------------------

/// Provenance metadata for an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub actor: Did,
    pub timestamp: String,
    pub action_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Provenance {
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    #[test]
    fn permission_set_contains() {
        let set = PermissionSet::new(vec![Permission::new("read"), Permission::new("write")]);
        assert!(set.contains(&Permission::new("read")));
        assert!(!set.contains(&Permission::new("admin")));
    }

    #[test]
    fn permission_set_empty() {
        let set = PermissionSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn bailment_state_is_active() {
        let active = BailmentState::Active {
            bailor: did("did:exo:bailor"),
            bailee: did("did:exo:bailee"),
            scope: "data".into(),
        };
        assert!(active.is_active());
        assert!(!BailmentState::None.is_active());
        assert!(!BailmentState::Terminated.is_active());
        let suspended = BailmentState::Suspended {
            reason: "audit".into(),
        };
        assert!(!suspended.is_active());
    }

    #[test]
    fn authority_chain_empty() {
        let chain = AuthorityChain::default();
        assert!(chain.is_empty());
        assert_eq!(chain.depth(), 0);
    }

    #[test]
    fn authority_chain_depth() {
        let chain = AuthorityChain {
            links: vec![
                AuthorityLink {
                    grantor: did("did:exo:root"),
                    grantee: did("did:exo:mid"),
                    permissions: PermissionSet::default(),
                    signature: vec![1],
                    grantor_public_key: None,
                },
                AuthorityLink {
                    grantor: did("did:exo:mid"),
                    grantee: did("did:exo:leaf"),
                    permissions: PermissionSet::default(),
                    signature: vec![2],
                    grantor_public_key: None,
                },
            ],
        };
        assert_eq!(chain.depth(), 2);
        assert!(!chain.is_empty());
    }

    #[test]
    fn quorum_evidence_met() {
        let ev = QuorumEvidence {
            threshold: 2,
            votes: vec![
                QuorumVote {
                    voter: did("did:exo:v1"),
                    approved: true,
                    signature: vec![1],
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: true,
                    signature: vec![2],
                },
                QuorumVote {
                    voter: did("did:exo:v3"),
                    approved: false,
                    signature: vec![3],
                },
            ],
        };
        assert!(ev.is_met());
    }

    #[test]
    fn quorum_evidence_not_met() {
        let ev = QuorumEvidence {
            threshold: 3,
            votes: vec![
                QuorumVote {
                    voter: did("did:exo:v1"),
                    approved: true,
                    signature: vec![1],
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: false,
                    signature: vec![2],
                },
            ],
        };
        assert!(!ev.is_met());
    }

    #[test]
    fn provenance_is_signed() {
        let signed = Provenance {
            actor: did("did:exo:actor"),
            timestamp: "2025-01-01".into(),
            action_hash: vec![1],
            signature: vec![4, 5, 6],
        };
        assert!(signed.is_signed());

        let unsigned = Provenance {
            actor: did("did:exo:actor"),
            timestamp: "2025-01-01".into(),
            action_hash: vec![1],
            signature: vec![],
        };
        assert!(!unsigned.is_signed());
    }
}
