//! Authority Delegations — signed, scoped, time-bound, revocable.
//!
//! Satisfies: GOV-003, GOV-004, TNC-05, TNC-09

use exo_core::{
    Did,
    types::{Hash256, Timestamp},
};
use serde::{Deserialize, Serialize};

use crate::{errors::GovernanceError, types::*};

/// Scope of an authority delegation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationScope {
    /// Decision classes this delegation covers.
    pub decision_classes: Vec<DecisionClass>,
    /// Maximum monetary authority in cents (if applicable).
    pub monetary_cap: Option<u64>,
    /// Specific resource IDs this delegation applies to.
    pub resource_ids: Vec<String>,
    /// Actions authorized under this delegation.
    pub actions: Vec<AuthorizedAction>,
}

impl DelegationScope {
    /// Check whether this scope covers a given action on a given decision class.
    pub fn covers(&self, action: &AuthorizedAction, class: &DecisionClass) -> bool {
        self.actions.contains(action) && self.decision_classes.contains(class)
    }

    /// Check whether this scope is a subset of (contained within) another scope.
    /// Used to validate sub-delegation doesn't exceed parent scope.
    pub fn is_subset_of(&self, parent: &DelegationScope) -> bool {
        // All actions must be in parent
        let actions_ok = self.actions.iter().all(|a| parent.actions.contains(a));

        // All decision classes must be in parent
        let classes_ok = self
            .decision_classes
            .iter()
            .all(|c| parent.decision_classes.contains(c));

        // Monetary cap must be <= parent's cap
        let monetary_ok = match (self.monetary_cap, parent.monetary_cap) {
            (Some(child), Some(parent_cap)) => child <= parent_cap,
            (Some(_), None) => true, // Parent has no cap, child has cap — fine
            (None, Some(_)) => false, // Parent has cap, child has none — violation
            (None, None) => true,
        };

        actions_ok && classes_ok && monetary_ok
    }
}

/// An authority delegation from one DID to another.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    /// Content-addressed unique identifier.
    pub id: Hash256,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// DID granting the delegation.
    pub delegator: Did,
    /// DID receiving the delegation.
    pub delegatee: Did,
    /// Scope of authority being delegated.
    pub scope: DelegationScope,
    /// Whether the delegatee can sub-delegate.
    pub sub_delegation_allowed: bool,
    /// Maximum scope for any sub-delegation (must be subset of `scope`).
    pub sub_delegation_scope_cap: Option<DelegationScope>,
    /// Creation timestamp.
    pub created_at: Timestamp,
    /// Hard expiry timestamp — no grace period (TNC-05).
    pub expires_at: u64,
    /// Revocation timestamp (None if active).
    pub revoked_at: Option<u64>,
    /// Constitution version at time of delegation.
    pub constitution_version: SemVer,
    /// Cryptographic signature from delegator.
    pub signature: GovernanceSignature,
    /// Parent delegation ID (for sub-delegations).
    pub parent_delegation: Option<Hash256>,
}

impl Delegation {
    /// Check whether this delegation is currently active (not expired, not revoked).
    /// TNC-05: Immediate expiry, no grace period.
    pub fn is_active(&self, current_time_ms: u64) -> bool {
        // Not revoked
        if self.revoked_at.is_some() {
            return false;
        }
        // Not expired — TNC-05: strict enforcement
        current_time_ms < self.expires_at
    }

    /// Revoke this delegation.
    pub fn revoke(&mut self, timestamp: u64) {
        self.revoked_at = Some(timestamp);
    }

    /// Validate that a proposed sub-delegation is within this delegation's scope.
    pub fn validate_sub_delegation(
        &self,
        sub_scope: &DelegationScope,
        current_time_ms: u64,
    ) -> Result<(), GovernanceError> {
        // Must be active
        if !self.is_active(current_time_ms) {
            if self.revoked_at.is_some() {
                return Err(GovernanceError::DelegationRevoked(self.id));
            }
            return Err(GovernanceError::DelegationExpired(self.id));
        }

        // Sub-delegation must be permitted
        if !self.sub_delegation_allowed {
            return Err(GovernanceError::SubDelegationNotPermitted(self.id));
        }

        // Sub-delegation scope must be within cap (or parent scope if no cap)
        let cap = self
            .sub_delegation_scope_cap
            .as_ref()
            .unwrap_or(&self.scope);
        if !sub_scope.is_subset_of(cap) {
            return Err(GovernanceError::SubDelegationNotPermitted(self.id));
        }

        Ok(())
    }

    /// Check whether this delegation authorizes a specific action on a decision class.
    pub fn authorizes(
        &self,
        action: &AuthorizedAction,
        class: &DecisionClass,
        current_time_ms: u64,
    ) -> Result<(), GovernanceError> {
        if !self.is_active(current_time_ms) {
            if self.revoked_at.is_some() {
                return Err(GovernanceError::DelegationRevoked(self.id));
            }
            return Err(GovernanceError::DelegationExpired(self.id));
        }

        if !self.scope.covers(action, class) {
            return Err(GovernanceError::AuthorityChainBroken {
                reason: format!(
                    "Delegation {:?} does not cover action {:?} on class {:?}",
                    self.id, action, class
                ),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::types::{Signature, Timestamp};

    use super::*;

    fn test_scope(actions: Vec<AuthorizedAction>, classes: Vec<DecisionClass>) -> DelegationScope {
        DelegationScope {
            decision_classes: classes,
            monetary_cap: None,
            resource_ids: vec![],
            actions,
        }
    }

    fn test_signature() -> GovernanceSignature {
        GovernanceSignature {
            signer: Did::new("did:exo:signer").unwrap(),
            signer_type: SignerType::Human,
            signature: Signature::from_bytes([0u8; 64]),
            key_version: 1,
            timestamp: Timestamp::new(1_000, 0),
        }
    }

    fn test_delegation(
        scope: DelegationScope,
        expires_at: u64,
        sub_delegation_allowed: bool,
    ) -> Delegation {
        Delegation {
            id: Hash256::from_bytes([1u8; 32]),
            tenant_id: "tenant-1".to_string(),
            delegator: Did::new("did:exo:alice").unwrap(),
            delegatee: Did::new("did:exo:bob").unwrap(),
            scope,
            sub_delegation_allowed,
            sub_delegation_scope_cap: None,
            created_at: Timestamp::new(1_000, 0),
            expires_at,
            revoked_at: None,
            constitution_version: SemVer {
                major: 1,
                minor: 0,
                patch: 0,
            },
            signature: test_signature(),
            parent_delegation: None,
        }
    }

    // ---- DelegationScope::covers -------------------------------------

    #[test]
    fn covers_returns_true_when_both_action_and_class_present() {
        let scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        assert!(scope.covers(&AuthorizedAction::CastVote, &DecisionClass::Operational));
    }

    #[test]
    fn covers_returns_false_when_action_missing() {
        let scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        assert!(!scope.covers(
            &AuthorizedAction::CreateDecision,
            &DecisionClass::Operational
        ));
    }

    #[test]
    fn covers_returns_false_when_class_missing() {
        let scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        assert!(!scope.covers(&AuthorizedAction::CastVote, &DecisionClass::Strategic));
    }

    // ---- DelegationScope::is_subset_of -------------------------------

    #[test]
    fn is_subset_of_true_when_actions_and_classes_all_in_parent() {
        let parent = test_scope(
            vec![AuthorizedAction::CastVote, AuthorizedAction::CreateDecision],
            vec![DecisionClass::Operational, DecisionClass::Strategic],
        );
        let child = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn is_subset_of_false_when_child_has_extra_action() {
        let parent = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let child = test_scope(
            vec![
                AuthorizedAction::CastVote,
                AuthorizedAction::GrantDelegation,
            ],
            vec![DecisionClass::Operational],
        );
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn is_subset_of_false_when_child_has_extra_class() {
        let parent = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let child = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational, DecisionClass::Strategic],
        );
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn is_subset_of_monetary_child_leq_parent_cap() {
        let parent = DelegationScope {
            monetary_cap: Some(10_000),
            ..test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            )
        };
        let child = DelegationScope {
            monetary_cap: Some(5_000),
            ..test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            )
        };
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn is_subset_of_monetary_child_exceeds_parent_cap() {
        let parent = DelegationScope {
            monetary_cap: Some(1_000),
            ..test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            )
        };
        let child = DelegationScope {
            monetary_cap: Some(5_000),
            ..test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            )
        };
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn is_subset_of_monetary_parent_uncapped_child_capped_ok() {
        let parent = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let child = DelegationScope {
            monetary_cap: Some(5_000),
            ..test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            )
        };
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn is_subset_of_monetary_parent_capped_child_uncapped_rejected() {
        let parent = DelegationScope {
            monetary_cap: Some(1_000),
            ..test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            )
        };
        let child = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        assert!(!child.is_subset_of(&parent));
    }

    // ---- Delegation::is_active ---------------------------------------

    #[test]
    fn is_active_true_when_unrevoked_and_not_expired() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        assert!(d.is_active(5_000));
    }

    #[test]
    fn is_active_false_when_expired() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        assert!(!d.is_active(10_000)); // equal = expired (TNC-05 strict)
        assert!(!d.is_active(15_000));
    }

    #[test]
    fn is_active_false_when_revoked() {
        let mut d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        d.revoke(5_000);
        assert!(!d.is_active(6_000));
    }

    // ---- Delegation::revoke -------------------------------------------

    #[test]
    fn revoke_sets_timestamp() {
        let mut d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        assert!(d.revoked_at.is_none());
        d.revoke(3_000);
        assert_eq!(d.revoked_at, Some(3_000));
    }

    // ---- Delegation::authorizes --------------------------------------

    #[test]
    fn authorizes_ok_when_active_and_scope_covers() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        assert!(
            d.authorizes(
                &AuthorizedAction::CastVote,
                &DecisionClass::Operational,
                5_000
            )
            .is_ok()
        );
    }

    #[test]
    fn authorizes_revoked_error_when_revoked() {
        let mut d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        d.revoke(2_000);
        let err = d
            .authorizes(
                &AuthorizedAction::CastVote,
                &DecisionClass::Operational,
                3_000,
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::DelegationRevoked(_)));
    }

    #[test]
    fn authorizes_expired_error_when_expired() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        let err = d
            .authorizes(
                &AuthorizedAction::CastVote,
                &DecisionClass::Operational,
                20_000,
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::DelegationExpired(_)));
    }

    #[test]
    fn authorizes_chain_broken_when_scope_does_not_cover() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false,
        );
        let err = d
            .authorizes(
                &AuthorizedAction::GrantDelegation,
                &DecisionClass::Operational,
                5_000,
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::AuthorityChainBroken { .. }));
    }

    // ---- Delegation::validate_sub_delegation -------------------------

    #[test]
    fn validate_sub_delegation_ok_when_allowed_and_within_scope() {
        let parent_scope = test_scope(
            vec![AuthorizedAction::CastVote, AuthorizedAction::CreateDecision],
            vec![DecisionClass::Operational, DecisionClass::Strategic],
        );
        let d = test_delegation(parent_scope, 10_000, true);
        let sub_scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        assert!(d.validate_sub_delegation(&sub_scope, 5_000).is_ok());
    }

    #[test]
    fn validate_sub_delegation_error_when_not_permitted() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            false, // sub-delegation NOT allowed
        );
        let sub_scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let err = d.validate_sub_delegation(&sub_scope, 5_000).unwrap_err();
        assert!(matches!(err, GovernanceError::SubDelegationNotPermitted(_)));
    }

    #[test]
    fn validate_sub_delegation_error_when_exceeds_scope() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            true,
        );
        let sub_scope = test_scope(
            vec![
                AuthorizedAction::CastVote,
                AuthorizedAction::GrantDelegation,
            ],
            vec![DecisionClass::Operational],
        );
        let err = d.validate_sub_delegation(&sub_scope, 5_000).unwrap_err();
        assert!(matches!(err, GovernanceError::SubDelegationNotPermitted(_)));
    }

    #[test]
    fn validate_sub_delegation_error_when_revoked() {
        let mut d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            true,
        );
        d.revoke(2_000);
        let sub_scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let err = d.validate_sub_delegation(&sub_scope, 3_000).unwrap_err();
        assert!(matches!(err, GovernanceError::DelegationRevoked(_)));
    }

    #[test]
    fn validate_sub_delegation_error_when_expired() {
        let d = test_delegation(
            test_scope(
                vec![AuthorizedAction::CastVote],
                vec![DecisionClass::Operational],
            ),
            10_000,
            true,
        );
        let sub_scope = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let err = d.validate_sub_delegation(&sub_scope, 20_000).unwrap_err();
        assert!(matches!(err, GovernanceError::DelegationExpired(_)));
    }

    #[test]
    fn validate_sub_delegation_uses_explicit_cap_when_set() {
        // Parent scope is broad; explicit cap is narrower.
        let parent_scope = test_scope(
            vec![AuthorizedAction::CastVote, AuthorizedAction::CreateDecision],
            vec![DecisionClass::Operational, DecisionClass::Strategic],
        );
        let narrower_cap = test_scope(
            vec![AuthorizedAction::CastVote],
            vec![DecisionClass::Operational],
        );
        let d = Delegation {
            sub_delegation_scope_cap: Some(narrower_cap),
            ..test_delegation(parent_scope, 10_000, true)
        };
        // Sub-delegation matches parent but exceeds cap — must be rejected.
        let sub_scope = test_scope(
            vec![AuthorizedAction::CreateDecision],
            vec![DecisionClass::Operational],
        );
        let err = d.validate_sub_delegation(&sub_scope, 5_000).unwrap_err();
        assert!(matches!(err, GovernanceError::SubDelegationNotPermitted(_)));
    }
}
