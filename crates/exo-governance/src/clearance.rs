//! Clearance with independence enforcement.

use std::collections::BTreeMap;

use exo_core::{Did, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    audit::{self, AuditLog},
    errors::GovernanceError,
    quorum::QuorumPolicy,
};

const CLEARANCE_ASSIGNMENT_EVIDENCE_DOMAIN: &str = "exo.governance.clearance_assignment.v1";
const CLEARANCE_ASSIGNMENT_EVIDENCE_SCHEMA_VERSION: u16 = 1;

/// Hierarchical clearance level from None (lowest) to Governor (highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClearanceLevel {
    None,
    ReadOnly,
    Contributor,
    Reviewer,
    Steward,
    Governor,
}

impl std::fmt::Display for ClearanceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::ReadOnly => write!(f, "ReadOnly"),
            Self::Contributor => write!(f, "Contributor"),
            Self::Reviewer => write!(f, "Reviewer"),
            Self::Steward => write!(f, "Steward"),
            Self::Governor => write!(f, "Governor"),
        }
    }
}

/// Per-action policy: required clearance level, optional quorum, and
/// whether independent approvers are mandatory for multi-party actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPolicy {
    pub required_level: ClearanceLevel,
    pub quorum_policy: Option<QuorumPolicy>,
    /// When true, the action requires a quorum policy configured with
    /// `min_independent > 0`.  `check_clearance` returns
    /// `InsufficientIndependence` if this constraint is violated.
    #[serde(default)]
    pub independence_required: bool,
}

/// Governance clearance policy: maps action names to their requirements.
///
/// `policy_hash` is the canonical CBOR-SHA-256 digest of this policy at
/// the time it was disclosed; embed it in every `Granted` decision so
/// auditors can verify which policy governed the check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClearancePolicy {
    pub actions: BTreeMap<String, ActionPolicy>,
    /// 32-byte disclosed policy hash (all-zeros when not yet set).
    #[serde(default)]
    pub policy_hash: [u8; 32],
}

/// Caller-supplied metadata for a clearance assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceAssignment {
    pub entry_id: Uuid,
    pub timestamp: Timestamp,
    pub assigner: Did,
    pub subject: Did,
    pub level: ClearanceLevel,
}

/// Deterministic receipt proving the registry mutation and its audit evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearanceAssignmentReceipt {
    pub audit_entry_id: Uuid,
    pub timestamp: Timestamp,
    pub assigner: Did,
    pub subject: Did,
    pub previous_level: ClearanceLevel,
    pub assigned_level: ClearanceLevel,
    pub evidence_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
struct ClearanceAssignmentEvidencePayload {
    domain: &'static str,
    schema_version: u16,
    audit_entry_id: Uuid,
    timestamp: Timestamp,
    assigner: Did,
    assigner_level: ClearanceLevel,
    subject: Did,
    previous_level: ClearanceLevel,
    assigned_level: ClearanceLevel,
}

/// Maps DIDs to their assigned clearance levels.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClearanceRegistry {
    entries: BTreeMap<Did, ClearanceLevel>,
}

impl ClearanceRegistry {
    /// Build a registry from a previously verified state snapshot.
    #[must_use]
    pub fn from_verified_snapshot(entries: BTreeMap<Did, ClearanceLevel>) -> Self {
        Self { entries }
    }

    /// Return the immutable clearance state snapshot.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<Did, ClearanceLevel> {
        &self.entries
    }

    /// Return the clearance level for the given actor, defaulting to `None`.
    #[must_use]
    pub fn get_level(&self, actor: &Did) -> ClearanceLevel {
        self.entries
            .get(actor)
            .copied()
            .unwrap_or(ClearanceLevel::None)
    }

    /// Assign or update clearance through an audited authorization boundary.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::ConstitutionalViolation`] when the assignment
    /// is self-directed, the assigner is not a Governor, or the assignment would
    /// set a level equal to or above the assigner's own clearance. Returns audit
    /// and serialization errors from the underlying append-only audit log.
    pub fn assign_level(
        &mut self,
        audit_log: &mut AuditLog,
        assignment: ClearanceAssignment,
    ) -> Result<ClearanceAssignmentReceipt, GovernanceError> {
        if assignment.assigner == assignment.subject {
            return Err(GovernanceError::ConstitutionalViolation {
                constraint_id: "NoSelfGrant".into(),
                reason: format!(
                    "actor {} cannot assign its own clearance",
                    assignment.assigner
                ),
            });
        }

        let assigner_level = self.get_level(&assignment.assigner);
        if assigner_level != ClearanceLevel::Governor {
            return Err(GovernanceError::ConstitutionalViolation {
                constraint_id: "ClearanceAuthority".into(),
                reason: format!(
                    "assigner {} has clearance {assigner_level}; Governor required",
                    assignment.assigner
                ),
            });
        }
        if assignment.level >= assigner_level {
            return Err(GovernanceError::ConstitutionalViolation {
                constraint_id: "ClearanceCeiling".into(),
                reason: format!(
                    "assigner {} with clearance {assigner_level} cannot assign {}",
                    assignment.assigner, assignment.level
                ),
            });
        }

        let previous_level = self.get_level(&assignment.subject);
        let evidence_hash =
            clearance_assignment_evidence_hash(&assignment, assigner_level, previous_level)?;
        let audit_entry = audit::create_entry(
            audit_log,
            assignment.entry_id,
            assignment.timestamp,
            assignment.assigner.clone(),
            "clearance.assign".into(),
            format!(
                "subject={} previous={previous_level} assigned={}",
                assignment.subject, assignment.level
            ),
            evidence_hash,
        )?;
        audit::append(audit_log, audit_entry)?;

        self.entries
            .insert(assignment.subject.clone(), assignment.level);
        Ok(ClearanceAssignmentReceipt {
            audit_entry_id: assignment.entry_id,
            timestamp: assignment.timestamp,
            assigner: assignment.assigner,
            subject: assignment.subject,
            previous_level,
            assigned_level: assignment.level,
            evidence_hash,
        })
    }
}

fn clearance_assignment_evidence_hash(
    assignment: &ClearanceAssignment,
    assigner_level: ClearanceLevel,
    previous_level: ClearanceLevel,
) -> Result<[u8; 32], GovernanceError> {
    let payload = ClearanceAssignmentEvidencePayload {
        domain: CLEARANCE_ASSIGNMENT_EVIDENCE_DOMAIN,
        schema_version: CLEARANCE_ASSIGNMENT_EVIDENCE_SCHEMA_VERSION,
        audit_entry_id: assignment.entry_id,
        timestamp: assignment.timestamp,
        assigner: assignment.assigner.clone(),
        assigner_level,
        subject: assignment.subject.clone(),
        previous_level,
        assigned_level: assignment.level,
    };
    hash_structured(&payload)
        .map(|hash| *hash.as_bytes())
        .map_err(|e| {
            GovernanceError::Serialization(format!(
                "clearance assignment canonical CBOR hash failed: {e}"
            ))
        })
}

/// Result of a clearance check: granted (with policy hash), denied, or insufficient independence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearanceDecision {
    /// Actor is cleared; `policy_hash` binds this decision to the disclosed policy.
    Granted {
        policy_hash: [u8; 32],
    },
    Denied {
        missing_level: ClearanceLevel,
    },
    InsufficientIndependence {
        details: String,
    },
}

/// Check whether `actor` may perform `action` under `policy`.
///
/// When `independence_required` is set on the action, this function also
/// validates that the action's quorum policy is configured with
/// `min_independent > 0`.  If not, it returns `InsufficientIndependence`
/// rather than a spurious `Granted`, ensuring the policy can never silently
/// bypass independence enforcement.
#[must_use]
pub fn check_clearance(
    actor: &Did,
    action: &str,
    policy: &ClearancePolicy,
    registry: &ClearanceRegistry,
) -> ClearanceDecision {
    let ap = match policy.actions.get(action) {
        Some(ap) => ap,
        None => {
            return ClearanceDecision::Denied {
                missing_level: ClearanceLevel::Governor,
            };
        }
    };
    if registry.get_level(actor) < ap.required_level {
        return ClearanceDecision::Denied {
            missing_level: ap.required_level,
        };
    }
    if ap.independence_required {
        let min_independent = ap
            .quorum_policy
            .as_ref()
            .map(|qp| qp.min_independent)
            .unwrap_or(0);
        if min_independent == 0 {
            return ClearanceDecision::InsufficientIndependence {
                details: format!(
                    "action '{action}' requires independence but quorum policy has \
                     min_independent=0 (or no quorum policy configured)"
                ),
            };
        }
    }
    ClearanceDecision::Granted {
        policy_hash: policy.policy_hash,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("ok")
    }

    fn make_action_policy(level: ClearanceLevel) -> ActionPolicy {
        ActionPolicy {
            required_level: level,
            quorum_policy: None,
            independence_required: false,
        }
    }

    fn timestamp(ms: u64) -> exo_core::Timestamp {
        exo_core::Timestamp::new(ms, 0)
    }

    fn audit_id(value: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(value)
    }

    fn assignment(
        assigner: Did,
        subject: Did,
        level: ClearanceLevel,
        entry_id: uuid::Uuid,
    ) -> ClearanceAssignment {
        ClearanceAssignment {
            entry_id,
            timestamp: timestamp(10_000),
            assigner,
            subject,
            level,
        }
    }

    fn snapshot_registry(entries: Vec<(Did, ClearanceLevel)>) -> ClearanceRegistry {
        let mut levels = BTreeMap::new();
        for (did, level) in entries {
            assert!(
                levels.insert(did, level).is_none(),
                "test registry snapshots must not contain duplicates"
            );
        }
        ClearanceRegistry::from_verified_snapshot(levels)
    }

    fn production_source() -> &'static str {
        include_str!("clearance.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source")
    }

    fn setup() -> (ClearancePolicy, ClearanceRegistry) {
        let mut p = ClearancePolicy::default();
        p.actions
            .insert("read".into(), make_action_policy(ClearanceLevel::ReadOnly));
        p.actions.insert(
            "write".into(),
            make_action_policy(ClearanceLevel::Contributor),
        );
        p.actions.insert(
            "review".into(),
            make_action_policy(ClearanceLevel::Reviewer),
        );
        p.actions.insert(
            "govern".into(),
            make_action_policy(ClearanceLevel::Governor),
        );
        let r = snapshot_registry(vec![
            (did("alice"), ClearanceLevel::Governor),
            (did("bob"), ClearanceLevel::Contributor),
            (did("carol"), ClearanceLevel::ReadOnly),
        ]);
        (p, r)
    }

    fn granted() -> ClearanceDecision {
        ClearanceDecision::Granted {
            policy_hash: [0u8; 32],
        }
    }

    #[test]
    fn governor_can_do_everything() {
        let (p, r) = setup();
        let a = did("alice");
        assert_eq!(check_clearance(&a, "read", &p, &r), granted());
        assert_eq!(check_clearance(&a, "write", &p, &r), granted());
        assert_eq!(check_clearance(&a, "review", &p, &r), granted());
        assert_eq!(check_clearance(&a, "govern", &p, &r), granted());
    }
    #[test]
    fn contributor_cannot_review() {
        let (p, r) = setup();
        let b = did("bob");
        assert_eq!(check_clearance(&b, "read", &p, &r), granted());
        assert_eq!(check_clearance(&b, "write", &p, &r), granted());
        assert_eq!(
            check_clearance(&b, "review", &p, &r),
            ClearanceDecision::Denied {
                missing_level: ClearanceLevel::Reviewer
            }
        );
        assert_eq!(
            check_clearance(&b, "govern", &p, &r),
            ClearanceDecision::Denied {
                missing_level: ClearanceLevel::Governor
            }
        );
    }
    #[test]
    fn readonly_can_only_read() {
        let (p, r) = setup();
        let c = did("carol");
        assert_eq!(check_clearance(&c, "read", &p, &r), granted());
        assert_eq!(
            check_clearance(&c, "write", &p, &r),
            ClearanceDecision::Denied {
                missing_level: ClearanceLevel::Contributor
            }
        );
    }
    #[test]
    fn unknown_actor_denied() {
        let (p, r) = setup();
        assert_eq!(
            check_clearance(&did("unknown"), "read", &p, &r),
            ClearanceDecision::Denied {
                missing_level: ClearanceLevel::ReadOnly
            }
        );
    }
    #[test]
    fn unknown_action_denied() {
        let (p, r) = setup();
        assert_eq!(
            check_clearance(&did("alice"), "nonexistent", &p, &r),
            ClearanceDecision::Denied {
                missing_level: ClearanceLevel::Governor
            }
        );
    }
    #[test]
    fn level_ordering() {
        assert!(ClearanceLevel::None < ClearanceLevel::ReadOnly);
        assert!(ClearanceLevel::ReadOnly < ClearanceLevel::Contributor);
        assert!(ClearanceLevel::Contributor < ClearanceLevel::Reviewer);
        assert!(ClearanceLevel::Reviewer < ClearanceLevel::Steward);
        assert!(ClearanceLevel::Steward < ClearanceLevel::Governor);
    }
    #[test]
    fn level_display() {
        assert_eq!(ClearanceLevel::None.to_string(), "None");
        assert_eq!(ClearanceLevel::Governor.to_string(), "Governor");
    }
    #[test]
    fn registry_defaults_to_none() {
        assert_eq!(
            ClearanceRegistry::default().get_level(&did("nobody")),
            ClearanceLevel::None
        );
    }
    #[test]
    fn registry_set_get() {
        let d = did("test");
        let r = snapshot_registry(vec![(d.clone(), ClearanceLevel::Steward)]);
        assert_eq!(r.get_level(&d), ClearanceLevel::Steward);
    }

    #[test]
    fn registry_has_no_public_unchecked_mutation_surface() {
        let source = production_source();
        assert!(
            !source.contains("pub entries:"),
            "clearance entries must not be publicly mutable"
        );
        assert!(
            !source.contains("pub fn set_level("),
            "clearance assignment must pass through the audited authorization boundary"
        );
    }

    #[test]
    fn governor_assignment_updates_registry_and_appends_audit_entry() {
        let governor = did("governor");
        let subject = did("delegate");
        let mut registry = snapshot_registry(vec![(governor.clone(), ClearanceLevel::Governor)]);
        let mut audit_log = crate::audit::AuditLog::new();

        let receipt = registry
            .assign_level(
                &mut audit_log,
                assignment(
                    governor.clone(),
                    subject.clone(),
                    ClearanceLevel::Steward,
                    audit_id(0xC1EA),
                ),
            )
            .expect("governor may assign lower clearance");

        assert_eq!(registry.get_level(&subject), ClearanceLevel::Steward);
        assert_eq!(receipt.subject, subject);
        assert_eq!(receipt.previous_level, ClearanceLevel::None);
        assert_eq!(receipt.assigned_level, ClearanceLevel::Steward);
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log.entries[0].actor, governor);
        assert_eq!(audit_log.entries[0].action, "clearance.assign");
        assert_eq!(audit_log.entries[0].evidence_hash, receipt.evidence_hash);
        crate::audit::verify_chain(&audit_log).expect("assignment audit entry must chain");
    }

    #[test]
    fn clearance_assignment_rejects_self_grant_without_mutation_or_audit() {
        let actor = did("actor");
        let mut registry = snapshot_registry(vec![(actor.clone(), ClearanceLevel::Governor)]);
        let mut audit_log = crate::audit::AuditLog::new();

        let err = registry
            .assign_level(
                &mut audit_log,
                assignment(
                    actor.clone(),
                    actor.clone(),
                    ClearanceLevel::Steward,
                    audit_id(0xC1EB),
                ),
            )
            .expect_err("actors must not assign their own clearance");

        assert!(matches!(
            err,
            crate::GovernanceError::ConstitutionalViolation { .. }
        ));
        assert_eq!(registry.get_level(&actor), ClearanceLevel::Governor);
        assert!(audit_log.is_empty());
    }

    #[test]
    fn clearance_assignment_enforces_superior_clearance_ceiling() {
        let steward = did("steward");
        let subject = did("subject");
        let mut registry = snapshot_registry(vec![(steward.clone(), ClearanceLevel::Steward)]);
        let mut audit_log = crate::audit::AuditLog::new();

        let err = registry
            .assign_level(
                &mut audit_log,
                assignment(
                    steward,
                    subject.clone(),
                    ClearanceLevel::Steward,
                    audit_id(0xC1EC),
                ),
            )
            .expect_err("assigner must not assign its own level or higher");

        assert!(matches!(
            err,
            crate::GovernanceError::ConstitutionalViolation { .. }
        ));
        assert_eq!(registry.get_level(&subject), ClearanceLevel::None);
        assert!(audit_log.is_empty());
    }

    #[test]
    fn clearance_assignment_rejects_invalid_audit_metadata_before_mutation() {
        let governor = did("governor");
        let subject = did("subject");
        let mut registry = snapshot_registry(vec![(governor.clone(), ClearanceLevel::Governor)]);
        let mut audit_log = crate::audit::AuditLog::new();

        let err = registry
            .assign_level(
                &mut audit_log,
                assignment(
                    governor,
                    subject.clone(),
                    ClearanceLevel::Reviewer,
                    uuid::Uuid::nil(),
                ),
            )
            .expect_err("assignment requires caller-supplied audit metadata");

        assert!(matches!(
            err,
            crate::GovernanceError::InvalidGovernanceMetadata { .. }
        ));
        assert_eq!(registry.get_level(&subject), ClearanceLevel::None);
        assert!(audit_log.is_empty());
    }
    #[test]
    fn insufficient_independence_variant() {
        let d = ClearanceDecision::InsufficientIndependence {
            details: "test".into(),
        };
        assert!(matches!(
            d,
            ClearanceDecision::InsufficientIndependence { .. }
        ));
    }

    // ── WO-004: independence_required enforcement ─────────────────────────────

    #[test]
    fn independence_required_without_quorum_policy_returns_insufficient() {
        let mut p = ClearancePolicy::default();
        p.actions.insert(
            "critical".into(),
            ActionPolicy {
                required_level: ClearanceLevel::Reviewer,
                quorum_policy: None,
                independence_required: true,
            },
        );
        let r = snapshot_registry(vec![(did("alice"), ClearanceLevel::Governor)]);
        assert!(matches!(
            check_clearance(&did("alice"), "critical", &p, &r),
            ClearanceDecision::InsufficientIndependence { .. }
        ));
    }

    #[test]
    fn independence_required_with_zero_min_independent_returns_insufficient() {
        use exo_core::Timestamp;

        use crate::quorum::{QuorumPolicy, Role};
        let mut p = ClearancePolicy::default();
        p.actions.insert(
            "critical".into(),
            ActionPolicy {
                required_level: ClearanceLevel::Reviewer,
                quorum_policy: Some(QuorumPolicy {
                    min_approvals: 3,
                    min_independent: 0, // misconfigured
                    required_roles: vec![Role::Steward],
                    timeout: Timestamp::new(999_999, 0),
                }),
                independence_required: true,
            },
        );
        let r = snapshot_registry(vec![(did("alice"), ClearanceLevel::Governor)]);
        assert!(matches!(
            check_clearance(&did("alice"), "critical", &p, &r),
            ClearanceDecision::InsufficientIndependence { .. }
        ));
    }

    #[test]
    fn independence_required_with_valid_quorum_policy_grants() {
        use exo_core::Timestamp;

        use crate::quorum::{QuorumPolicy, Role};
        let hash = [1u8; 32];
        let mut p = ClearancePolicy {
            actions: BTreeMap::new(),
            policy_hash: hash,
        };
        p.actions.insert(
            "critical".into(),
            ActionPolicy {
                required_level: ClearanceLevel::Reviewer,
                quorum_policy: Some(QuorumPolicy {
                    min_approvals: 3,
                    min_independent: 2,
                    required_roles: vec![Role::Steward],
                    timeout: Timestamp::new(999_999, 0),
                }),
                independence_required: true,
            },
        );
        let r = snapshot_registry(vec![(did("alice"), ClearanceLevel::Governor)]);
        assert_eq!(
            check_clearance(&did("alice"), "critical", &p, &r),
            ClearanceDecision::Granted { policy_hash: hash }
        );
    }

    #[test]
    fn policy_hash_embedded_in_granted() {
        let hash = [42u8; 32];
        let mut p = ClearancePolicy {
            actions: BTreeMap::new(),
            policy_hash: hash,
        };
        p.actions
            .insert("read".into(), make_action_policy(ClearanceLevel::ReadOnly));
        let r = snapshot_registry(vec![(did("alice"), ClearanceLevel::Governor)]);
        assert_eq!(
            check_clearance(&did("alice"), "read", &p, &r),
            ClearanceDecision::Granted { policy_hash: hash }
        );
    }
}
