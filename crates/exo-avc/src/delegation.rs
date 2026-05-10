// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! AVC delegation — issuance of a child credential whose scope is
//! strictly narrower than its parent.
//!
//! Every dimension that an AVC can carry must be **strictly narrowed or
//! preserved** when delegating. Any widening triggers
//! [`AvcError::DelegationWidens`], which is the dominant security
//! invariant for the delegation path: a holder must never be able to
//! produce a child AVC that outranks its parent.
//!
//! The delegation API mirrors `issue_avc` and yields a
//! [`AutonomousVolitionCredential`] whose `parent_avc_id` is set to the
//! parent's ID. The caller's `sign` closure is invoked exactly once
//! over the canonical signing payload of the child credential.

use std::collections::BTreeSet;

use exo_authority::permission::Permission;
use exo_core::{Hash256, Signature};

use crate::{
    credential::{AVC_SCHEMA_VERSION, AutonomousVolitionCredential, AvcDraft, issue_avc},
    error::AvcError,
};

/// Validate strict narrowing across every meaningful dimension and
/// issue the child credential.
///
/// The parent must have `delegated_intent.delegation_allowed == true`
/// and `constraints.max_delegation_depth >= 1`. The child draft's
/// `parent_avc_id` is rewritten to the parent's content-addressed ID
/// before signing so the parent linkage is part of the signed payload.
///
/// # Errors
/// Returns [`AvcError`] if the child draft is structurally invalid,
/// widens any scope dimension, or CBOR encoding fails.
pub fn delegate_avc<F>(
    parent: &AutonomousVolitionCredential,
    mut child: AvcDraft,
    sign: F,
) -> Result<AutonomousVolitionCredential, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    if !parent.delegated_intent.delegation_allowed {
        return Err(AvcError::DelegationRejected {
            reason: "parent credential does not permit delegation".into(),
        });
    }

    if parent.constraints.max_delegation_depth == 0 {
        return Err(AvcError::DelegationRejected {
            reason: "parent constraints.max_delegation_depth is zero".into(),
        });
    }

    if child.schema_version != AVC_SCHEMA_VERSION {
        return Err(AvcError::UnsupportedSchema {
            got: child.schema_version,
            supported: AVC_SCHEMA_VERSION,
        });
    }

    enforce_narrowing(parent, &child)?;

    // Stamp the parent ID into the child draft before signing so the
    // child's signed payload binds the linkage cryptographically.
    child.parent_avc_id = Some(parent.id()?);

    issue_avc(child, sign)
}

fn enforce_narrowing(
    parent: &AutonomousVolitionCredential,
    child: &AvcDraft,
) -> Result<(), AvcError> {
    if child.delegated_intent.autonomy_level > parent.delegated_intent.autonomy_level {
        return Err(AvcError::DelegationWidens {
            dimension: "autonomy_level",
        });
    }

    if !is_subset_copy(
        &child.authority_scope.permissions,
        &parent.authority_scope.permissions,
    ) {
        return Err(AvcError::DelegationWidens {
            dimension: "permissions",
        });
    }
    if !is_subset(&child.authority_scope.tools, &parent.authority_scope.tools) {
        return Err(AvcError::DelegationWidens { dimension: "tools" });
    }
    if !is_subset(
        &child.authority_scope.data_classes,
        &parent.authority_scope.data_classes,
    ) {
        return Err(AvcError::DelegationWidens {
            dimension: "data_classes",
        });
    }
    if !is_subset(
        &child.authority_scope.counterparties,
        &parent.authority_scope.counterparties,
    ) {
        return Err(AvcError::DelegationWidens {
            dimension: "counterparties",
        });
    }
    if !is_subset(
        &child.authority_scope.jurisdictions,
        &parent.authority_scope.jurisdictions,
    ) {
        return Err(AvcError::DelegationWidens {
            dimension: "jurisdictions",
        });
    }

    if !narrows_optional_u64(
        parent.constraints.max_budget_minor_units,
        child.constraints.max_budget_minor_units,
    ) {
        return Err(AvcError::DelegationWidens {
            dimension: "max_budget_minor_units",
        });
    }
    if !narrows_optional_u32(
        parent.constraints.max_action_risk_bp,
        child.constraints.max_action_risk_bp,
    ) {
        return Err(AvcError::DelegationWidens {
            dimension: "max_action_risk_bp",
        });
    }

    if child.constraints.max_delegation_depth >= parent.constraints.max_delegation_depth {
        return Err(AvcError::DelegationWidens {
            dimension: "max_delegation_depth",
        });
    }

    if !narrows_expiry(parent.expires_at, child.expires_at) {
        return Err(AvcError::DelegationWidens {
            dimension: "expiry",
        });
    }

    Ok(())
}

fn is_subset_copy(child: &[Permission], parent: &[Permission]) -> bool {
    let parent_set: BTreeSet<Permission> = parent.iter().copied().collect();
    child.iter().all(|p| parent_set.contains(p))
}

fn is_subset<T: Ord>(child: &[T], parent: &[T]) -> bool {
    let parent_set: BTreeSet<&T> = parent.iter().collect();
    child.iter().all(|t| parent_set.contains(t))
}

fn narrows_optional_u64(parent: Option<u64>, child: Option<u64>) -> bool {
    match (parent, child) {
        // Parent permits any budget — child may set any budget.
        (None, _) => true,
        // Parent restricts; child must restrict at least as tightly.
        (Some(_), None) => false,
        (Some(p), Some(c)) => c <= p,
    }
}

fn narrows_optional_u32(parent: Option<u32>, child: Option<u32>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => c <= p,
    }
}

fn narrows_expiry(parent: Option<exo_core::Timestamp>, child: Option<exo_core::Timestamp>) -> bool {
    match (parent, child) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => c <= p,
    }
}

/// Convenience: extract the parent ID from a delegated credential.
#[must_use]
pub fn parent_id_of(credential: &AutonomousVolitionCredential) -> Option<Hash256> {
    credential.parent_avc_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{
        AutonomyLevel, AvcConstraints, AvcSubjectKind, DataClass,
        test_support::{baseline_draft, did, ts},
    };

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    fn parent_credential() -> AutonomousVolitionCredential {
        let mut draft = baseline_draft();
        draft.delegated_intent.delegation_allowed = true;
        draft.constraints.max_delegation_depth = 3;
        draft.constraints.max_budget_minor_units = Some(10_000);
        draft.constraints.max_action_risk_bp = Some(5_000);
        draft.delegated_intent.autonomy_level = AutonomyLevel::ExecuteWithinBounds;
        draft.authority_scope.counterparties = vec![did("cp-a"), did("cp-b")];
        issue_avc(draft, |_| fixed_signature()).unwrap()
    }

    fn narrower_child(parent: &AutonomousVolitionCredential) -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: parent.subject_did.clone(),
            principal_did: parent.principal_did.clone(),
            subject_did: did("sub-agent"),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "child".into(),
                agent_version: None,
            },
            created_at: parent.created_at,
            expires_at: parent.expires_at, // equal — counts as narrowed
            delegated_intent: crate::credential::DelegatedIntent {
                intent_id: parent.delegated_intent.intent_id,
                purpose: "narrow scope".into(),
                allowed_objectives: vec!["narrow".into()],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::Draft, // strictly narrower
                delegation_allowed: false,
            },
            authority_scope: crate::credential::AuthorityScope {
                permissions: vec![Permission::Read], // subset of parent
                tools: vec!["alpha".into()],         // subset
                data_classes: vec![DataClass::Public],
                counterparties: vec![did("cp-a")],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints {
                max_budget_minor_units: Some(1_000),
                currency_code: None,
                max_action_risk_bp: Some(2_500),
                human_approval_required: false,
                approval_threshold_bp: None,
                max_delegation_depth: 1,
                allowed_time_window: None,
                forbidden_actions: vec![],
                emergency_stop_refs: vec![],
            },
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        }
    }

    #[test]
    fn delegate_succeeds_with_strictly_narrower_child() {
        let parent = parent_credential();
        let child_draft = narrower_child(&parent);
        let child = delegate_avc(&parent, child_draft, |_| fixed_signature()).unwrap();
        assert_eq!(child.parent_avc_id, Some(parent.id().unwrap()));
    }

    #[test]
    fn delegate_rejects_when_parent_disallows() {
        let mut parent = parent_credential();
        parent.delegated_intent.delegation_allowed = false;
        let child_draft = narrower_child(&parent);
        let err = delegate_avc(&parent, child_draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::DelegationRejected { .. }));
    }

    #[test]
    fn delegate_rejects_when_max_depth_zero() {
        let mut parent = parent_credential();
        parent.constraints.max_delegation_depth = 0;
        let child_draft = narrower_child(&parent);
        let err = delegate_avc(&parent, child_draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::DelegationRejected { .. }));
    }

    #[test]
    fn delegate_rejects_widening_autonomy() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.delegated_intent.autonomy_level = AutonomyLevel::DelegateWithinBounds;
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "autonomy_level")
        );
    }

    #[test]
    fn delegate_rejects_widening_permissions() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.authority_scope.permissions = vec![Permission::Govern];
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "permissions")
        );
    }

    #[test]
    fn delegate_rejects_widening_tools() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.authority_scope.tools = vec!["new-tool".into()];
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::DelegationWidens { dimension } if dimension == "tools"));
    }

    #[test]
    fn delegate_rejects_widening_data_classes() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.authority_scope.data_classes = vec![DataClass::Restricted];
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "data_classes")
        );
    }

    #[test]
    fn delegate_rejects_widening_counterparties() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.authority_scope.counterparties = vec![did("cp-c")];
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "counterparties")
        );
    }

    #[test]
    fn delegate_rejects_widening_jurisdictions() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.authority_scope.jurisdictions = vec!["EU".into()];
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "jurisdictions")
        );
    }

    #[test]
    fn delegate_rejects_widening_budget() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.constraints.max_budget_minor_units = Some(99_999);
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "max_budget_minor_units")
        );
    }

    #[test]
    fn delegate_rejects_unbounded_child_budget_when_parent_bounded() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.constraints.max_budget_minor_units = None;
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "max_budget_minor_units")
        );
    }

    #[test]
    fn delegate_rejects_widening_risk() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.constraints.max_action_risk_bp = Some(9_999);
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "max_action_risk_bp")
        );
    }

    #[test]
    fn delegate_rejects_unbounded_child_risk_when_parent_bounded() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.constraints.max_action_risk_bp = None;
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "max_action_risk_bp")
        );
    }

    #[test]
    fn delegate_rejects_equal_or_larger_max_depth() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.constraints.max_delegation_depth = parent.constraints.max_delegation_depth;
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::DelegationWidens { dimension } if dimension == "max_delegation_depth")
        );
    }

    #[test]
    fn delegate_rejects_extending_expiry() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.expires_at = Some(ts(99_999_999));
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::DelegationWidens { dimension } if dimension == "expiry"));
    }

    #[test]
    fn delegate_rejects_unbounded_child_expiry_when_parent_bounded() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.expires_at = None;
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::DelegationWidens { dimension } if dimension == "expiry"));
    }

    #[test]
    fn delegate_rejects_unsupported_schema() {
        let parent = parent_credential();
        let mut child = narrower_child(&parent);
        child.schema_version = 99;
        let err = delegate_avc(&parent, child, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::UnsupportedSchema { got: 99, .. }));
    }

    #[test]
    fn delegate_succeeds_when_parent_permits_unbounded_budget_and_risk() {
        // When the parent has no max_budget / max_action_risk, the child
        // may set any value (including None) without widening.
        let mut parent = parent_credential();
        parent.constraints.max_budget_minor_units = None;
        parent.constraints.max_action_risk_bp = None;
        // Re-issue parent with the relaxed constraints.
        let mut draft = baseline_draft();
        draft.delegated_intent.delegation_allowed = true;
        draft.constraints.max_delegation_depth = 3;
        draft.constraints.max_budget_minor_units = None;
        draft.constraints.max_action_risk_bp = None;
        draft.delegated_intent.autonomy_level = AutonomyLevel::ExecuteWithinBounds;
        draft.authority_scope.counterparties = vec![did("cp-a"), did("cp-b")];
        let parent = issue_avc(draft, |_| fixed_signature()).unwrap();

        // Child with bounded budget and bounded risk — narrower or equal
        // is fine when parent is None.
        let mut child = narrower_child(&parent);
        child.constraints.max_budget_minor_units = Some(1_000);
        child.constraints.max_action_risk_bp = Some(2_500);
        let result = delegate_avc(&parent, child, |_| fixed_signature()).unwrap();
        assert_eq!(result.parent_avc_id, Some(parent.id().unwrap()));

        // Child with unbounded budget and risk — also fine.
        let mut child = narrower_child(&parent);
        child.constraints.max_budget_minor_units = None;
        child.constraints.max_action_risk_bp = None;
        let result = delegate_avc(&parent, child, |_| fixed_signature()).unwrap();
        assert_eq!(result.parent_avc_id, Some(parent.id().unwrap()));
    }

    #[test]
    fn delegate_succeeds_when_parent_permits_unbounded_expiry() {
        // Re-issue parent with no expiry but matching baseline scope.
        let mut draft = baseline_draft();
        draft.delegated_intent.delegation_allowed = true;
        draft.constraints.max_delegation_depth = 3;
        draft.constraints.max_budget_minor_units = Some(10_000);
        draft.constraints.max_action_risk_bp = Some(5_000);
        draft.delegated_intent.autonomy_level = AutonomyLevel::ExecuteWithinBounds;
        draft.authority_scope.counterparties = vec![did("cp-a"), did("cp-b")];
        draft.expires_at = None;
        let parent = issue_avc(draft, |_| fixed_signature()).unwrap();

        // Child may have any expiry — ensure it is after `created_at`.
        let mut child = narrower_child(&parent);
        child.expires_at = Some(ts(5_000_000));
        let result = delegate_avc(&parent, child, |_| fixed_signature()).unwrap();
        assert_eq!(result.parent_avc_id, Some(parent.id().unwrap()));

        // Child may also be unbounded.
        let mut child = narrower_child(&parent);
        child.expires_at = None;
        let result = delegate_avc(&parent, child, |_| fixed_signature()).unwrap();
        assert_eq!(result.parent_avc_id, Some(parent.id().unwrap()));
    }

    #[test]
    fn parent_id_of_returns_recorded_link() {
        let parent = parent_credential();
        let child = delegate_avc(&parent, narrower_child(&parent), |_| fixed_signature()).unwrap();
        assert_eq!(parent_id_of(&child), Some(parent.id().unwrap()));
    }
}
