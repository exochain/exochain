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

//! AVC validation — fail-closed adjudication of a credential and an
//! optional action against a registry.
//!
//! Validation is **deterministic**: it consumes a `now` timestamp from
//! the caller (no wall-clock reads), iterates registry data through
//! `BTreeMap`/`BTreeSet`, and produces decisions whose reason codes are
//! sorted and deduplicated.
//!
//! Validation is **fail-closed**: any unresolved key, missing required
//! reference, malformed structural value, scope violation, expiration,
//! or revocation produces an explicit `Deny` with reason codes describing
//! the failure. Errors are reserved for transport-level failures (CBOR
//! encoding, registry I/O) and must never silently translate into
//! `Allow`.

use std::collections::BTreeSet;

use exo_authority::permission::Permission;
#[cfg(test)]
use exo_core::Signature;
use exo_core::{Did, Hash256, PublicKey, Timestamp, crypto};
use serde::{Deserialize, Serialize};

use crate::{
    credential::{AuthorityScope, AutonomousVolitionCredential, AvcConstraints, DataClass},
    error::AvcError,
    receipt::AvcTrustReceipt,
    registry::AvcRegistryRead,
};

// ---------------------------------------------------------------------------
// Decision / Reason
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcDecision {
    Allow,
    Deny,
    HumanApprovalRequired,
    ChallengeRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AvcReasonCode {
    Valid,
    InvalidSignature,
    InvalidIssuer,
    InvalidSubject,
    InvalidHolder,
    Expired,
    NotYetValid,
    Revoked,
    Suspended,
    Quarantined,
    AuthorityChainMissing,
    AuthorityChainInvalid,
    ScopeWidening,
    PermissionDenied,
    ToolDenied,
    CounterpartyDenied,
    DataClassDenied,
    BudgetExceeded,
    RiskExceeded,
    HumanApprovalMissing,
    DelegationNotAllowed,
    ConsentMissing,
    PolicyMissing,
    MalformedCredential,
    ForbiddenAction,
    OutsideTimeWindow,
}

// ---------------------------------------------------------------------------
// Validation request / result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcActionRequest {
    pub action_id: Hash256,
    pub actor_did: Did,
    pub requested_permission: Permission,
    pub tool: Option<String>,
    pub target_did: Option<Did>,
    pub data_class: Option<DataClass>,
    pub estimated_budget_minor_units: Option<u64>,
    pub estimated_risk_bp: Option<u32>,
    pub requires_human_approval: bool,
    /// Free-form action name used to enforce `forbidden_actions`.
    pub action_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcValidationRequest {
    pub credential: AutonomousVolitionCredential,
    pub action: Option<AvcActionRequest>,
    pub now: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcValidationResult {
    pub credential_id: Hash256,
    pub decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub normalized_holder_did: Did,
    pub valid_until: Option<Timestamp>,
    pub receipt: Option<AvcTrustReceipt>,
}

// ---------------------------------------------------------------------------
// Validation entry point
// ---------------------------------------------------------------------------

/// Validate a credential and optional action against a registry.
///
/// Decisions are deterministic: the same inputs always yield the same
/// reason codes in the same order.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if the credential cannot be CBOR
/// encoded for ID computation. All other failures flow as `Deny`
/// decisions with reason codes.
pub fn validate_avc<R: AvcRegistryRead>(
    request: &AvcValidationRequest,
    registry: &R,
) -> Result<AvcValidationResult, AvcError> {
    let credential = &request.credential;
    let credential_id = credential.id()?;
    let normalized_holder_did = credential.effective_holder().clone();
    let mut reasons: BTreeSet<AvcReasonCode> = BTreeSet::new();
    let mut human_approval_required = false;

    // Structural checks first — these would otherwise misroute later checks.
    if credential.created_at > request.now {
        reasons.insert(AvcReasonCode::NotYetValid);
    }
    if let Some(expires) = credential.expires_at {
        if expires <= request.now {
            reasons.insert(AvcReasonCode::Expired);
        }
    }
    if let Some(window) = &credential.constraints.allowed_time_window {
        if !window.contains(&request.now) {
            reasons.insert(AvcReasonCode::OutsideTimeWindow);
        }
    }

    // Signature: resolve issuer key and verify.
    if credential.signature.is_empty() {
        reasons.insert(AvcReasonCode::InvalidSignature);
    } else {
        match registry.resolve_public_key(&credential.issuer_did) {
            None => {
                reasons.insert(AvcReasonCode::InvalidIssuer);
            }
            Some(pubkey) => {
                if !verify_signature(credential, &pubkey)? {
                    reasons.insert(AvcReasonCode::InvalidSignature);
                }
            }
        }
    }

    // Authority chain when issuer != principal.
    if credential.issuer_did != credential.principal_did {
        match &credential.authority_chain {
            None => {
                reasons.insert(AvcReasonCode::AuthorityChainMissing);
            }
            Some(chain_ref) => {
                if !registry.authority_chain_valid(&chain_ref.chain_hash, &request.now) {
                    reasons.insert(AvcReasonCode::AuthorityChainInvalid);
                }
            }
        }
    }

    // Revocation.
    if registry.is_revoked(&credential_id) {
        reasons.insert(AvcReasonCode::Revoked);
    }

    // Required consent / policy refs.
    for consent_ref in &credential.consent_refs {
        if consent_ref.required && !registry.consent_ref_exists(&consent_ref.consent_id) {
            reasons.insert(AvcReasonCode::ConsentMissing);
        }
    }
    for policy_ref in &credential.policy_refs {
        if policy_ref.required
            && !registry.policy_ref_exists(&policy_ref.policy_id, policy_ref.policy_version)
        {
            reasons.insert(AvcReasonCode::PolicyMissing);
        }
    }

    // Action fit.
    if let Some(action) = &request.action {
        evaluate_action(
            credential,
            action,
            &normalized_holder_did,
            &mut reasons,
            &mut human_approval_required,
        );
    }

    let mut sorted: Vec<AvcReasonCode> = reasons.into_iter().collect();
    let decision = if sorted.is_empty() {
        sorted.push(AvcReasonCode::Valid);
        AvcDecision::Allow
    } else if human_approval_required
        && reasons_are_only(&sorted, AvcReasonCode::HumanApprovalMissing)
    {
        AvcDecision::HumanApprovalRequired
    } else {
        AvcDecision::Deny
    };

    Ok(AvcValidationResult {
        credential_id,
        decision,
        reason_codes: sorted,
        normalized_holder_did,
        valid_until: credential.expires_at,
        receipt: None,
    })
}

fn reasons_are_only(reasons: &[AvcReasonCode], expected: AvcReasonCode) -> bool {
    reasons.len() == 1 && reasons[0] == expected
}

fn verify_signature(
    credential: &AutonomousVolitionCredential,
    pubkey: &PublicKey,
) -> Result<bool, AvcError> {
    // Caller ensures `signature.is_empty()` is false before invoking this
    // helper (see validate_avc). `crypto::verify` itself returns `false`
    // for `Signature::Empty` defensively, so an empty value here is
    // simply rejected rather than producing a false positive.
    let payload = credential.signing_payload()?;
    Ok(crypto::verify(&payload, &credential.signature, pubkey))
}

fn evaluate_action(
    credential: &AutonomousVolitionCredential,
    action: &AvcActionRequest,
    normalized_holder: &Did,
    reasons: &mut BTreeSet<AvcReasonCode>,
    human_approval_required: &mut bool,
) {
    if action.actor_did != *normalized_holder && action.actor_did != credential.subject_did {
        reasons.insert(AvcReasonCode::InvalidHolder);
    }

    if !credential
        .authority_scope
        .permissions
        .contains(&action.requested_permission)
    {
        reasons.insert(AvcReasonCode::PermissionDenied);
    }

    enforce_tool(&credential.authority_scope, action, reasons);
    enforce_data_class(&credential.authority_scope, action, reasons);
    enforce_counterparty(&credential.authority_scope, action, reasons);
    enforce_budget(&credential.constraints, action, reasons);
    enforce_risk(
        &credential.constraints,
        action,
        reasons,
        human_approval_required,
    );
    enforce_forbidden_action(&credential.constraints, action, reasons);
}

fn enforce_tool(
    scope: &AuthorityScope,
    action: &AvcActionRequest,
    reasons: &mut BTreeSet<AvcReasonCode>,
) {
    let Some(tool) = &action.tool else {
        return;
    };
    if scope.tools.is_empty() || !scope.tools.iter().any(|t| t == tool) {
        reasons.insert(AvcReasonCode::ToolDenied);
    }
}

fn enforce_data_class(
    scope: &AuthorityScope,
    action: &AvcActionRequest,
    reasons: &mut BTreeSet<AvcReasonCode>,
) {
    let Some(class) = &action.data_class else {
        return;
    };
    if !scope.data_classes.iter().any(|c| c == class) {
        reasons.insert(AvcReasonCode::DataClassDenied);
    }
}

fn enforce_counterparty(
    scope: &AuthorityScope,
    action: &AvcActionRequest,
    reasons: &mut BTreeSet<AvcReasonCode>,
) {
    let Some(target) = &action.target_did else {
        return;
    };
    if !scope.counterparties.is_empty() && !scope.counterparties.iter().any(|d| d == target) {
        reasons.insert(AvcReasonCode::CounterpartyDenied);
    }
}

fn enforce_budget(
    constraints: &AvcConstraints,
    action: &AvcActionRequest,
    reasons: &mut BTreeSet<AvcReasonCode>,
) {
    if let (Some(cap), Some(estimate)) = (
        constraints.max_budget_minor_units,
        action.estimated_budget_minor_units,
    ) {
        if estimate > cap {
            reasons.insert(AvcReasonCode::BudgetExceeded);
        }
    }
}

fn enforce_risk(
    constraints: &AvcConstraints,
    action: &AvcActionRequest,
    reasons: &mut BTreeSet<AvcReasonCode>,
    human_approval_required: &mut bool,
) {
    let Some(estimate) = action.estimated_risk_bp else {
        return;
    };
    if let Some(cap) = constraints.max_action_risk_bp {
        if estimate > cap {
            reasons.insert(AvcReasonCode::RiskExceeded);
        }
    }
    if let Some(threshold) = constraints.approval_threshold_bp {
        if estimate >= threshold && !action.requires_human_approval {
            reasons.insert(AvcReasonCode::HumanApprovalMissing);
            *human_approval_required = true;
        }
    }
}

fn enforce_forbidden_action(
    constraints: &AvcConstraints,
    action: &AvcActionRequest,
    reasons: &mut BTreeSet<AvcReasonCode>,
) {
    let Some(name) = &action.action_name else {
        return;
    };
    if constraints.forbidden_actions.iter().any(|a| a == name) {
        reasons.insert(AvcReasonCode::ForbiddenAction);
    }
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::KeyPair;

    use super::*;
    use crate::{
        credential::{
            AVC_SCHEMA_VERSION, AuthorityChainRef, AvcConstraints, AvcDraft, AvcSubjectKind,
            ConsentRef, PolicyRef, TimeWindow, issue_avc, test_support::*,
        },
        registry::{AvcRegistryWrite, InMemoryAvcRegistry},
        revocation::{AvcRevocationReason, revoke_avc},
    };

    const ISSUER_SEED: [u8; 32] = [0x11; 32];

    fn issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ISSUER_SEED).expect("valid seed")
    }

    /// Build a registry seeded with the issuer's public key.
    struct Harness {
        registry: InMemoryAvcRegistry,
    }

    impl Harness {
        fn new() -> Self {
            let mut registry = InMemoryAvcRegistry::new();
            registry.put_public_key(did("issuer"), issuer_keypair().public);
            Self { registry }
        }

        fn issue(&self, draft: AvcDraft) -> AutonomousVolitionCredential {
            issue_avc(draft, |bytes| issuer_keypair().sign(bytes)).unwrap()
        }
    }

    fn baseline_request(
        cred: AutonomousVolitionCredential,
        now: Timestamp,
    ) -> AvcValidationRequest {
        AvcValidationRequest {
            credential: cred,
            action: None,
            now,
        }
    }

    fn baseline_action(actor: Did) -> AvcActionRequest {
        AvcActionRequest {
            action_id: h256(0x55),
            actor_did: actor,
            requested_permission: Permission::Read,
            tool: None,
            target_did: None,
            data_class: None,
            estimated_budget_minor_units: None,
            estimated_risk_bp: None,
            requires_human_approval: false,
            action_name: None,
        }
    }

    #[test]
    fn valid_credential_allows() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let request = baseline_request(cred, ts(1_500_000));
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn denies_unknown_issuer_key() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.issuer_did = did("ghost");
        draft.principal_did = did("ghost"); // ghost is also principal so authority chain not required
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(result.reason_codes.contains(&AvcReasonCode::InvalidIssuer));
    }

    #[test]
    fn denies_empty_signature() {
        let h = Harness::new();
        let mut cred = h.issue(baseline_draft());
        cred.signature = Signature::empty();
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::InvalidSignature)
        );
    }

    #[test]
    fn denies_invalid_signature_when_payload_tampered() {
        let h = Harness::new();
        let mut cred = h.issue(baseline_draft());
        // Mutate after signing — payload no longer matches signature.
        cred.delegated_intent.purpose = "tampered".into();
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::InvalidSignature)
        );
    }

    #[test]
    fn denies_wrong_key_signature() {
        let h = Harness::new();
        let other = KeyPair::from_secret_bytes([0x99; 32]).unwrap();
        let mut cred = h.issue(baseline_draft());
        // Re-sign with a different key.
        let payload = cred.signing_payload().unwrap();
        cred.signature = other.sign(&payload);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::InvalidSignature)
        );
    }

    #[test]
    fn denies_expired_credential() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let result = validate_avc(&baseline_request(cred, ts(3_000_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(result.reason_codes.contains(&AvcReasonCode::Expired));
    }

    #[test]
    fn denies_not_yet_valid_credential() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let result = validate_avc(&baseline_request(cred, ts(0)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(result.reason_codes.contains(&AvcReasonCode::NotYetValid));
    }

    #[test]
    fn denies_outside_time_window() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.allowed_time_window = Some(TimeWindow {
            not_before: ts(1_400_000),
            not_after: ts(1_450_000),
        });
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::OutsideTimeWindow)
        );
    }

    #[test]
    fn denies_revoked_credential() {
        let mut h = Harness::new();
        let cred = h.issue(baseline_draft());
        let id = cred.id().unwrap();
        h.registry.put_credential(cred.clone()).unwrap();
        let revocation = revoke_avc(
            id,
            did("issuer"),
            AvcRevocationReason::IssuerRevoked,
            ts(1_250_000),
            |bytes| issuer_keypair().sign(bytes),
        )
        .unwrap();
        h.registry.put_revocation(revocation).unwrap();
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(result.reason_codes.contains(&AvcReasonCode::Revoked));
    }

    #[test]
    fn denies_missing_authority_chain_when_issuer_differs_from_principal() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.principal_did = did("principal");
        // No authority_chain supplied.
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::AuthorityChainMissing)
        );
    }

    #[test]
    fn denies_invalid_authority_chain_hash() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.principal_did = did("principal");
        draft.authority_chain = Some(AuthorityChainRef {
            chain_hash: h256(0xDE),
        });
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::AuthorityChainInvalid)
        );
    }

    #[test]
    fn accepts_valid_authority_chain_hash() {
        let mut h = Harness::new();
        let mut draft = baseline_draft();
        draft.principal_did = did("principal");
        draft.authority_chain = Some(AuthorityChainRef {
            chain_hash: h256(0xDE),
        });
        h.registry.mark_authority_chain_valid(h256(0xDE));
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn denies_missing_required_consent_ref() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.consent_refs = vec![ConsentRef {
            consent_id: h256(0xC0),
            required: true,
        }];
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::ConsentMissing));
    }

    #[test]
    fn allows_when_optional_consent_ref_missing() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.consent_refs = vec![ConsentRef {
            consent_id: h256(0xC0),
            required: false,
        }];
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn denies_missing_required_policy_ref() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.policy_refs = vec![PolicyRef {
            policy_id: h256(0xB1),
            policy_version: 2,
            required: true,
        }];
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::PolicyMissing));
    }

    #[test]
    fn denies_actor_mismatch() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(baseline_action(did("imposter")));
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::InvalidHolder));
    }

    #[test]
    fn denies_permission_outside_scope() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.requested_permission = Permission::Govern;
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::PermissionDenied)
        );
    }

    #[test]
    fn denies_tool_outside_scope() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.tool = Some("ungoverned".into());
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::ToolDenied));
    }

    #[test]
    fn empty_tool_scope_denies_any_tool_action() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.authority_scope.tools = vec![];
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.tool = Some("anything".into());
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::ToolDenied));
    }

    #[test]
    fn empty_tool_scope_allows_action_without_tool() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.authority_scope.tools = vec![];
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let action = baseline_action(actor);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn denies_data_class_outside_scope() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.data_class = Some(DataClass::SensitivePersonalData);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::DataClassDenied)
        );
    }

    #[test]
    fn denies_counterparty_when_allowlist_present() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.authority_scope.counterparties = vec![did("approved-cp")];
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.target_did = Some(did("malicious-cp"));
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::CounterpartyDenied)
        );
    }

    #[test]
    fn empty_counterparty_list_allows_any_target() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.target_did = Some(did("any"));
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn denies_budget_exceeded() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_budget_minor_units = Some(1_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_budget_minor_units = Some(2_000);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::BudgetExceeded));
    }

    #[test]
    fn denies_risk_exceeded() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(1_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(5_000);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(result.reason_codes.contains(&AvcReasonCode::RiskExceeded));
    }

    #[test]
    fn risk_above_threshold_returns_human_approval_required() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(7_500);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::HumanApprovalRequired);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalMissing]
        );
    }

    #[test]
    fn risk_above_threshold_with_explicit_approval_does_not_flag() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(7_500);
        action.requires_human_approval = true;
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn denies_forbidden_action_name() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.forbidden_actions = vec!["payment.execute".into()];
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.action_name = Some("payment.execute".into());
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert!(
            result
                .reason_codes
                .contains(&AvcReasonCode::ForbiddenAction)
        );
    }

    #[test]
    fn reason_codes_are_sorted_and_deduped() {
        let h = Harness::new();
        // Construct a credential that fails several checks at once.
        let mut draft = baseline_draft();
        draft.principal_did = did("principal"); // forces authority chain
        // Keep tool empty; action will request a tool.
        draft.authority_scope.tools = vec![];
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.tool = Some("forbidden".into());
        action.requested_permission = Permission::Govern; // not in scope
        let mut request = baseline_request(cred, ts(3_000_000)); // also expired
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);

        let mut sorted = result.reason_codes.clone();
        sorted.sort();
        assert_eq!(sorted, result.reason_codes, "reason codes must be sorted");

        let mut deduped = result.reason_codes.clone();
        deduped.dedup();
        assert_eq!(deduped, result.reason_codes, "reason codes must be deduped");
    }

    #[test]
    fn validation_does_not_consult_payment_state() {
        // No quote/settlement registry exists; validation should still succeed.
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let r1 = validate_avc(&baseline_request(cred.clone(), ts(1_500_000)), &h.registry).unwrap();
        let r2 = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn validation_request_round_trip_serializes() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let request = baseline_request(cred, ts(1_500_000));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&request, &mut buf).unwrap();
        let decoded: AvcValidationRequest = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn unsupported_subject_with_unknown_kind_still_allows() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::Unknown;
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn validation_request_now_inside_window_is_inclusive() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.allowed_time_window = Some(TimeWindow {
            not_before: ts(1_500_000),
            not_after: ts(1_500_000_000),
        });
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[test]
    fn confirms_schema_constant_is_one() {
        assert_eq!(AVC_SCHEMA_VERSION, 1);
    }

    #[test]
    fn validation_with_only_constraints_passes_when_no_action() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints = AvcConstraints {
            max_budget_minor_units: Some(1_000),
            currency_code: Some("USD".into()),
            max_action_risk_bp: Some(2_000),
            human_approval_required: false,
            approval_threshold_bp: Some(5_000),
            max_delegation_depth: 1,
            allowed_time_window: None,
            forbidden_actions: vec!["bad".into()],
            emergency_stop_refs: vec!["stop".into()],
        };
        let cred = h.issue(draft);
        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
    }
}
