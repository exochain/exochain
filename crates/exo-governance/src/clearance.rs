//! Clearance with independence enforcement.

use std::collections::BTreeMap;

use exo_core::Did;
use serde::{Deserialize, Serialize};

use crate::quorum::QuorumPolicy;

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

#[derive(Debug, Clone, Default)]
pub struct ClearanceRegistry {
    pub entries: BTreeMap<Did, ClearanceLevel>,
}

impl ClearanceRegistry {
    #[must_use]
    pub fn get_level(&self, actor: &Did) -> ClearanceLevel {
        self.entries
            .get(actor)
            .copied()
            .unwrap_or(ClearanceLevel::None)
    }
    pub fn set_level(&mut self, actor: Did, level: ClearanceLevel) {
        self.entries.insert(actor, level);
    }
}

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
        let mut r = ClearanceRegistry::default();
        r.set_level(did("alice"), ClearanceLevel::Governor);
        r.set_level(did("bob"), ClearanceLevel::Contributor);
        r.set_level(did("carol"), ClearanceLevel::ReadOnly);
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
        let mut r = ClearanceRegistry::default();
        let d = did("test");
        r.set_level(d.clone(), ClearanceLevel::Steward);
        assert_eq!(r.get_level(&d), ClearanceLevel::Steward);
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
        let mut r = ClearanceRegistry::default();
        r.set_level(did("alice"), ClearanceLevel::Governor);
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
        let mut r = ClearanceRegistry::default();
        r.set_level(did("alice"), ClearanceLevel::Governor);
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
        let mut r = ClearanceRegistry::default();
        r.set_level(did("alice"), ClearanceLevel::Governor);
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
        let mut r = ClearanceRegistry::default();
        r.set_level(did("alice"), ClearanceLevel::Governor);
        assert_eq!(
            check_clearance(&did("alice"), "read", &p, &r),
            ClearanceDecision::Granted { policy_hash: hash }
        );
    }
}
