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
use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    credential::{
        AVC_SCHEMA_VERSION, AuthorityScope, AutonomousVolitionCredential, AvcConstraints, DataClass,
    },
    error::AvcError,
    llm_usage_receipt::{
        AVC_LLM_USAGE_EVIDENCE_DOMAIN, LlmUsageCustodyMode, LlmUsageEvidence,
        validate_llm_usage_evidence,
    },
    receipt::AvcTrustReceipt,
    registry::AvcRegistryRead,
};

/// Signing domain tag for AVC human approval evidence.
pub const AVC_HUMAN_APPROVAL_SIGNING_DOMAIN: &str = "exo.avc.human-approval.v1";
/// Signing domain tag for AVC subject action proofs.
pub const AVC_ACTION_SIGNING_DOMAIN: &str = "exo.avc.action.v1";
/// Signing domain tag for AVC receipt action commitments.
pub const AVC_ACTION_COMMITMENT_DOMAIN: &str = "exo.avc.action.commitment.v1";
/// Signing domain tag for canonical receipt action descriptors.
pub const AVC_ACTION_DESCRIPTOR_DOMAIN: &str = "exo.avc.action.descriptor.v1";
/// Canonical AVC action name for EXOCHAIN LYNK Protocol usage receipts.
pub const AVC_LLM_USAGE_ACTION_NAME: &str = "llm.usage.receipt.emit";

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
    HumanApprovalInvalid,
    HumanApprovalExpired,
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
    #[serde(default)]
    pub human_approval: Option<AvcHumanApproval>,
    pub requires_human_approval: bool,
    /// Free-form action name used to enforce `forbidden_actions`.
    pub action_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcActionDescriptor {
    pub schema_version: u16,
    pub action_id: Hash256,
    pub actor_did: Did,
    pub requested_permission: Permission,
    pub tool: Option<String>,
    pub target_did: Option<Did>,
    pub data_class: Option<DataClass>,
    pub estimated_budget_minor_units: Option<u64>,
    pub estimated_risk_bp: Option<u32>,
    pub requires_human_approval: bool,
    pub human_approval_present: bool,
    pub action_name: Option<String>,
}

impl AvcActionDescriptor {
    #[must_use]
    pub fn from_action(action: &AvcActionRequest) -> Self {
        Self {
            schema_version: AVC_SCHEMA_VERSION,
            action_id: action.action_id,
            actor_did: action.actor_did.clone(),
            requested_permission: action.requested_permission,
            tool: action.tool.clone(),
            target_did: action.target_did.clone(),
            data_class: action.data_class.clone(),
            estimated_budget_minor_units: action.estimated_budget_minor_units,
            estimated_risk_bp: action.estimated_risk_bp,
            requires_human_approval: action.requires_human_approval,
            human_approval_present: action.human_approval.is_some(),
            action_name: action.action_name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcHumanApproval {
    pub approver_did: Did,
    pub approved_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub signature: Signature,
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

#[derive(Serialize)]
struct HumanApprovalSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    action_id: &'a Hash256,
    actor_did: &'a Did,
    requested_permission: &'a Permission,
    tool: Option<&'a String>,
    target_did: Option<&'a Did>,
    data_class: Option<&'a DataClass>,
    estimated_budget_minor_units: Option<u64>,
    estimated_risk_bp: Option<u32>,
    action_name: Option<&'a String>,
    approver_did: &'a Did,
    approved_at: &'a Timestamp,
    expires_at: Option<&'a Timestamp>,
}

#[derive(Serialize)]
struct AvcActionSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    action: &'a AvcActionRequest,
    validation_now: &'a Timestamp,
}

#[derive(Serialize)]
struct AvcActionCommitmentPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    action: &'a AvcActionRequest,
    validation_now: &'a Timestamp,
}

#[derive(Serialize)]
struct AvcActionDescriptorPayload<'a> {
    domain: &'static str,
    descriptor: &'a AvcActionDescriptor,
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
    enforce_registered_issuer_grant(credential, registry, &mut reasons);

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
            registry,
            &request.now,
            &mut reasons,
            &mut human_approval_required,
        )?;
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

fn enforce_registered_issuer_grant<R: AvcRegistryRead>(
    credential: &AutonomousVolitionCredential,
    registry: &R,
    reasons: &mut BTreeSet<AvcReasonCode>,
) {
    let Some(granted_permissions) =
        registry.resolve_issuer_permission_grant(&credential.issuer_did)
    else {
        return;
    };
    if granted_permissions.is_empty()
        || credential
            .authority_scope
            .permissions
            .iter()
            .any(|permission| !granted_permissions.contains(permission))
    {
        reasons.insert(AvcReasonCode::ScopeWidening);
    }
}

/// Compute the canonical signing payload for a human approval over a
/// specific AVC credential/action pair.
///
/// The caller-provided `requires_human_approval` flag is deliberately
/// excluded because it is not proof of approval. Authorization depends
/// on this signed approval evidence and the trusted human-approver key
/// registry instead.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical CBOR encoding fails.
pub fn human_approval_signature_payload(
    credential: &AutonomousVolitionCredential,
    action: &AvcActionRequest,
    approval: &AvcHumanApproval,
) -> Result<Vec<u8>, AvcError> {
    let credential_id = credential.id()?;
    let payload = HumanApprovalSigningPayload {
        domain: AVC_HUMAN_APPROVAL_SIGNING_DOMAIN,
        schema_version: AVC_SCHEMA_VERSION,
        credential_id: &credential_id,
        action_id: &action.action_id,
        actor_did: &action.actor_did,
        requested_permission: &action.requested_permission,
        tool: action.tool.as_ref(),
        target_did: action.target_did.as_ref(),
        data_class: action.data_class.as_ref(),
        estimated_budget_minor_units: action.estimated_budget_minor_units,
        estimated_risk_bp: action.estimated_risk_bp,
        action_name: action.action_name.as_ref(),
        approver_did: &approval.approver_did,
        approved_at: &approval.approved_at,
        expires_at: approval.expires_at.as_ref(),
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf)?;
    Ok(buf)
}

/// Compute the canonical signing payload for a subject's action proof.
///
/// The payload binds the action to the AVC credential ID and the validation
/// timestamp supplied to the node. This prevents a detached action signature
/// from being replayed against a different credential or validation context.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical CBOR encoding fails.
pub fn avc_action_signature_payload(
    credential: &AutonomousVolitionCredential,
    action: &AvcActionRequest,
    validation_now: &Timestamp,
) -> Result<Vec<u8>, AvcError> {
    let credential_id = credential.id()?;
    let payload = AvcActionSigningPayload {
        domain: AVC_ACTION_SIGNING_DOMAIN,
        schema_version: AVC_SCHEMA_VERSION,
        credential_id: &credential_id,
        action,
        validation_now,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf)?;
    Ok(buf)
}

/// Compute a deterministic commitment over the subject-signed action content.
///
/// The commitment binds the full action request to the content-addressed AVC
/// credential ID and the validation timestamp used by the subject action
/// signature. It does not claim external anchoring.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical CBOR encoding fails.
pub fn avc_action_commitment_hash(
    credential: &AutonomousVolitionCredential,
    action: &AvcActionRequest,
    validation_now: &Timestamp,
) -> Result<Hash256, AvcError> {
    let credential_id = credential.id()?;
    let payload = AvcActionCommitmentPayload {
        domain: AVC_ACTION_COMMITMENT_DOMAIN,
        schema_version: AVC_SCHEMA_VERSION,
        credential_id: &credential_id,
        action,
        validation_now,
    };
    hash_structured(&payload).map_err(AvcError::from)
}

/// Compute a deterministic hash for the minimal action descriptor embedded in
/// trust receipts. The descriptor is intentionally narrower than the signed
/// action request: high-value proof material remains committed by
/// [`avc_action_commitment_hash`], while the receipt carries enough canonical
/// action meaning for court/audit reconstruction.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical CBOR encoding fails.
pub fn avc_action_descriptor_hash(descriptor: &AvcActionDescriptor) -> Result<Hash256, AvcError> {
    hash_structured(&AvcActionDescriptorPayload {
        domain: AVC_ACTION_DESCRIPTOR_DOMAIN,
        descriptor,
    })
    .map_err(AvcError::from)
}

/// Build the AVC action request represented by validated EXOCHAIN LYNK
/// Protocol evidence.
///
/// # Errors
/// Returns [`AvcError`] when LYNK evidence is structurally invalid.
pub fn avc_llm_usage_action_request(
    evidence: &LlmUsageEvidence,
) -> Result<AvcActionRequest, AvcError> {
    validate_llm_usage_evidence(evidence)?;
    Ok(AvcActionRequest {
        action_id: evidence.action_id,
        actor_did: evidence.actor_did.clone(),
        requested_permission: Permission::Execute,
        tool: Some(AVC_LLM_USAGE_EVIDENCE_DOMAIN.into()),
        target_did: None,
        data_class: Some(llm_usage_custody_data_class(evidence.custody_mode)),
        estimated_budget_minor_units: evidence.usage.cost_minor_units,
        estimated_risk_bp: None,
        human_approval: None,
        requires_human_approval: false,
        action_name: Some(AVC_LLM_USAGE_ACTION_NAME.into()),
    })
}

fn llm_usage_custody_data_class(custody_mode: LlmUsageCustodyMode) -> DataClass {
    match custody_mode {
        LlmUsageCustodyMode::ReceiptMinimized => DataClass::Internal,
        LlmUsageCustodyMode::ExternalPayloadRef => DataClass::Confidential,
        LlmUsageCustodyMode::DagDbCustody => DataClass::Restricted,
    }
}

fn evaluate_action<R: AvcRegistryRead>(
    credential: &AutonomousVolitionCredential,
    action: &AvcActionRequest,
    normalized_holder: &Did,
    registry: &R,
    now: &Timestamp,
    reasons: &mut BTreeSet<AvcReasonCode>,
    human_approval_required: &mut bool,
) -> Result<(), AvcError> {
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
        credential,
        &credential.constraints,
        action,
        registry,
        now,
        reasons,
        human_approval_required,
    )?;
    enforce_forbidden_action(&credential.constraints, action, reasons);
    Ok(())
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

fn enforce_risk<R: AvcRegistryRead>(
    credential: &AutonomousVolitionCredential,
    constraints: &AvcConstraints,
    action: &AvcActionRequest,
    registry: &R,
    now: &Timestamp,
    reasons: &mut BTreeSet<AvcReasonCode>,
    human_approval_required: &mut bool,
) -> Result<(), AvcError> {
    let risk_threshold_requires_approval = if let (Some(threshold), Some(estimate)) =
        (constraints.approval_threshold_bp, action.estimated_risk_bp)
    {
        estimate >= threshold
    } else {
        false
    };
    if let (Some(cap), Some(estimate)) = (constraints.max_action_risk_bp, action.estimated_risk_bp)
    {
        if estimate > cap {
            reasons.insert(AvcReasonCode::RiskExceeded);
        }
    }

    let approval_required = constraints.human_approval_required || risk_threshold_requires_approval;
    if approval_required {
        *human_approval_required = true;
    }
    if approval_required || action.human_approval.is_some() {
        match verify_human_approval(credential, action, registry, now)? {
            Ok(()) => {}
            Err(reason) => {
                reasons.insert(reason);
            }
        }
    }
    Ok(())
}

fn verify_human_approval<R: AvcRegistryRead>(
    credential: &AutonomousVolitionCredential,
    action: &AvcActionRequest,
    registry: &R,
    now: &Timestamp,
) -> Result<Result<(), AvcReasonCode>, AvcError> {
    let Some(approval) = &action.human_approval else {
        return Ok(Err(AvcReasonCode::HumanApprovalMissing));
    };
    if approval.signature.is_empty() || approval.approved_at > *now {
        return Ok(Err(AvcReasonCode::HumanApprovalInvalid));
    }
    if let Some(expires_at) = approval.expires_at {
        if expires_at <= approval.approved_at {
            return Ok(Err(AvcReasonCode::HumanApprovalInvalid));
        }
        if expires_at <= *now {
            return Ok(Err(AvcReasonCode::HumanApprovalExpired));
        }
    }

    let Some(public_key) = registry.resolve_human_approval_key(&approval.approver_did) else {
        return Ok(Err(AvcReasonCode::HumanApprovalInvalid));
    };
    let payload = human_approval_signature_payload(credential, action, approval)?;
    if crypto::verify(&payload, &approval.signature, &public_key) {
        Ok(Ok(()))
    } else {
        Ok(Err(AvcReasonCode::HumanApprovalInvalid))
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
        llm_usage_receipt::{EncryptedPayloadRef, ProviderUsageMetrics},
        registry::{AvcRegistryWrite, InMemoryAvcRegistry},
        revocation::{AvcRevocationReason, revoke_avc},
    };

    const ISSUER_SEED: [u8; 32] = [0x11; 32];
    const HUMAN_APPROVER_SEED: [u8; 32] = [0x44; 32];

    fn issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ISSUER_SEED).expect("valid seed")
    }

    fn human_approver_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(HUMAN_APPROVER_SEED).expect("valid seed")
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
            human_approval: None,
            requires_human_approval: false,
            action_name: None,
        }
    }

    fn baseline_llm_usage_evidence(custody_mode: LlmUsageCustodyMode) -> LlmUsageEvidence {
        let mut evidence = LlmUsageEvidence {
            schema_version: AVC_SCHEMA_VERSION,
            tenant_id: "tenant-alpha".into(),
            namespace: "default".into(),
            actor_did: did("agent"),
            provider: "openai".into(),
            provider_endpoint: "responses".into(),
            model_id: "gpt-test".into(),
            provider_request_id_hash: Some(h256(0xA1)),
            session_id_hash: Some(h256(0xA2)),
            idempotency_key_hash: h256(0xA3),
            action_id: h256(0xA4),
            prompt_hash: h256(0xA5),
            completion_hash: Some(h256(0xA6)),
            tool_call_hash: None,
            tool_result_hash: None,
            usage: ProviderUsageMetrics {
                input_tokens: 10,
                output_tokens: 20,
                total_tokens: 30,
                cached_input_tokens: None,
                reasoning_tokens: None,
                cost_minor_units: Some(125),
                cost_currency: Some("USD".into()),
                usage_complete: true,
            },
            custody_mode,
            encrypted_payload_refs: Vec::new(),
            custody_policy_hash: h256(0xA7),
            created_at: ts(1_600_000),
        };
        if custody_mode == LlmUsageCustodyMode::ExternalPayloadRef {
            evidence.encrypted_payload_refs = vec![EncryptedPayloadRef {
                ref_id_hash: h256(0xB1),
                ciphertext_hash: h256(0xB2),
                storage_policy_hash: h256(0xB3),
                key_policy_hash: h256(0xB4),
                payload_kind: "provider_exchange".into(),
                byte_length: 128,
            }];
        }
        evidence
    }

    fn attach_signed_human_approval(
        credential: &AutonomousVolitionCredential,
        action: &mut AvcActionRequest,
        approver_did: Did,
        approved_at: Timestamp,
        expires_at: Option<Timestamp>,
        approver_keypair: &KeyPair,
    ) {
        action.human_approval = Some(AvcHumanApproval {
            approver_did,
            approved_at,
            expires_at,
            signature: Signature::empty(),
        });
        let payload = human_approval_signature_payload(
            credential,
            action,
            action
                .human_approval
                .as_ref()
                .expect("approval placeholder"),
        )
        .expect("canonical approval payload");
        action
            .human_approval
            .as_mut()
            .expect("approval placeholder")
            .signature = approver_keypair.sign(&payload);
    }

    #[test]
    fn llm_usage_action_request_uses_execute_and_evidence_fields() {
        let evidence = baseline_llm_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized);
        let action = avc_llm_usage_action_request(&evidence).expect("LYNK action");

        assert_eq!(action.action_id, evidence.action_id);
        assert_eq!(action.actor_did, evidence.actor_did);
        assert_eq!(action.requested_permission, Permission::Execute);
        assert_eq!(action.tool, Some(AVC_LLM_USAGE_EVIDENCE_DOMAIN.into()));
        assert_eq!(action.data_class, Some(DataClass::Internal));
        assert_eq!(action.estimated_budget_minor_units, Some(125));
        assert_eq!(action.estimated_risk_bp, None);
        assert_eq!(action.action_name, Some(AVC_LLM_USAGE_ACTION_NAME.into()));
        assert!(!action.requires_human_approval);
        assert!(action.human_approval.is_none());
    }

    #[test]
    fn llm_usage_action_request_derives_data_class_from_custody_mode() {
        let minimized = avc_llm_usage_action_request(&baseline_llm_usage_evidence(
            LlmUsageCustodyMode::ReceiptMinimized,
        ))
        .expect("minimized action");
        let external = avc_llm_usage_action_request(&baseline_llm_usage_evidence(
            LlmUsageCustodyMode::ExternalPayloadRef,
        ))
        .expect("external action");
        let dagdb = avc_llm_usage_action_request(&baseline_llm_usage_evidence(
            LlmUsageCustodyMode::DagDbCustody,
        ))
        .expect("dagdb action");

        assert_eq!(minimized.data_class, Some(DataClass::Internal));
        assert_eq!(external.data_class, Some(DataClass::Confidential));
        assert_eq!(dagdb.data_class, Some(DataClass::Restricted));
    }

    #[test]
    fn llm_usage_action_request_fails_closed_on_invalid_evidence() {
        let mut evidence = baseline_llm_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized);
        evidence.provider_endpoint = " ".into();

        assert!(matches!(
            avc_llm_usage_action_request(&evidence),
            Err(AvcError::EmptyField {
                field: "llm_usage.provider_endpoint"
            })
        ));
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
    fn allows_credential_when_issuer_has_no_registered_grant() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![Permission::Read, Permission::Write];
        let cred = h.issue(draft);

        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();

        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn allows_credential_scope_within_registered_issuer_grant() {
        let mut h = Harness::new();
        h.registry
            .put_issuer_permission_grant(did("issuer"), vec![Permission::Read]);
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![Permission::Read];
        let cred = h.issue(draft);

        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();

        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn allows_credential_scope_with_duplicate_registered_grant_entries() {
        let mut h = Harness::new();
        h.registry.put_issuer_permission_grant(
            did("issuer"),
            vec![Permission::Write, Permission::Read, Permission::Write],
        );
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![Permission::Read, Permission::Write];
        let cred = h.issue(draft);

        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();

        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn action_signature_payload_is_domain_separated_and_context_bound() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let action = baseline_action(cred.subject_did.clone());
        let payload_one = avc_action_signature_payload(&cred, &action, &ts(1_500_000)).unwrap();
        let payload_two = avc_action_signature_payload(&cred, &action, &ts(1_500_001)).unwrap();
        let needle = AVC_ACTION_SIGNING_DOMAIN.as_bytes();

        assert!(payload_one.windows(needle.len()).any(|w| w == needle));
        assert_ne!(payload_one, payload_two);
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
    fn denies_credential_scope_wider_than_registered_issuer_grant() {
        let mut h = Harness::new();
        h.registry.put_issuer_permission_grant(
            did("issuer"),
            vec![
                Permission::Read,
                Permission::Write,
                Permission::Execute,
                Permission::Delegate,
            ],
        );
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![Permission::Govern];
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.requested_permission = Permission::Govern;
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);

        let result = validate_avc(&request, &h.registry).unwrap();

        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(
            result.reason_codes.contains(&AvcReasonCode::ScopeWidening),
            "root issuer grants must cap credential-declared permissions"
        );
    }

    #[test]
    fn denies_all_credentials_from_issuer_capped_to_empty_permission_set() {
        let mut h = Harness::new();
        h.registry
            .put_issuer_permission_grant(did("issuer"), vec![]);
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![];
        let cred = h.issue(draft);
        let request = baseline_request(cred, ts(1_500_000));

        let result = validate_avc(&request, &h.registry).unwrap();

        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(
            result.reason_codes.contains(&AvcReasonCode::ScopeWidening),
            "an issuer capped to no permissions must be able to sign nothing"
        );
    }

    #[test]
    fn denies_any_credential_permission_outside_registered_issuer_grant() {
        let mut h = Harness::new();
        h.registry
            .put_issuer_permission_grant(did("issuer"), vec![Permission::Read]);
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![Permission::Read, Permission::Write];
        let cred = h.issue(draft);

        let result = validate_avc(&baseline_request(cred, ts(1_500_000)), &h.registry).unwrap();

        assert_eq!(result.decision, AvcDecision::Deny);
        assert!(
            result.reason_codes.contains(&AvcReasonCode::ScopeWidening),
            "any credential permission outside the issuer grant must fail closed"
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
    fn in_scope_action_at_budget_and_risk_caps_allows() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.authority_scope.counterparties = vec![did("approved-cp")];
        draft.constraints.max_budget_minor_units = Some(1_000);
        draft.constraints.max_action_risk_bp = Some(1_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.tool = Some("alpha".into());
        action.data_class = Some(DataClass::Public);
        action.target_did = Some(did("approved-cp"));
        action.estimated_budget_minor_units = Some(1_000);
        action.estimated_risk_bp = Some(1_000);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn in_scope_action_with_allowed_tool_allows() {
        let h = Harness::new();
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.tool = Some("alpha".into());
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn non_expiring_credential_allows_explicit_holder_action() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.holder_did = Some(did("holder"));
        draft.expires_at = None;
        let cred = h.issue(draft);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(baseline_action(did("holder")));
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
        assert_eq!(result.normalized_holder_did, did("holder"));
        assert_eq!(result.valid_until, None);
    }

    #[test]
    fn subject_actor_remains_valid_when_holder_is_explicit() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.holder_did = Some(did("holder"));
        let cred = h.issue(draft);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(baseline_action(did("agent")));
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
        assert_eq!(result.normalized_holder_did, did("holder"));
    }

    #[test]
    fn risk_at_approval_threshold_requires_human_approval() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(5_000);
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
    fn risk_above_threshold_ignores_caller_approval_flag() {
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
        assert_eq!(result.decision, AvcDecision::HumanApprovalRequired);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalMissing]
        );
    }

    #[test]
    fn credential_human_approval_required_blocks_action_without_evidence() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let action = baseline_action(actor);
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
    fn signed_human_approval_satisfies_credential_requirement() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            Some(ts(1_900_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn signed_human_approval_satisfies_risk_threshold() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(7_500);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            None,
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn valid_optional_human_approval_evidence_allows_unrequired_action() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            Some(ts(1_900_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn human_approval_from_untrusted_approver_is_invalid() {
        let h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            Some(ts(1_900_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn issuer_public_key_alone_does_not_authorize_human_approval() {
        let h = Harness::new();
        let issuer_keypair = issuer_keypair();
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            did("issuer"),
            ts(1_400_000),
            Some(ts(1_900_000)),
            &issuer_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn optional_human_approval_evidence_must_still_verify() {
        let h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let cred = h.issue(baseline_draft());
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            did("human-approver"),
            ts(1_400_000),
            Some(ts(1_900_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn human_approval_signature_binds_action_fields() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(7_500);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            None,
            &approver_keypair,
        );
        action.estimated_risk_bp = Some(7_501);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn expired_human_approval_is_rejected() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_300_000),
            Some(ts(1_400_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalExpired]
        );
    }

    #[test]
    fn human_approval_with_empty_signature_is_invalid() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.human_approval = Some(AvcHumanApproval {
            approver_did,
            approved_at: ts(1_400_000),
            expires_at: Some(ts(1_900_000)),
            signature: Signature::empty(),
        });
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn human_approval_expiring_at_approval_time_is_invalid() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            Some(ts(1_400_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn human_approval_expiring_at_now_is_expired() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            Some(ts(1_500_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalExpired]
        );
    }

    #[test]
    fn human_approval_with_future_approval_time_is_invalid() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_600_000),
            Some(ts(1_900_000)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn human_approval_expiring_before_approval_time_is_invalid() {
        let mut h = Harness::new();
        let approver_keypair = human_approver_keypair();
        let approver_did = did("human-approver");
        h.registry
            .put_human_approval_key(approver_did.clone(), approver_keypair.public);
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        attach_signed_human_approval(
            &cred,
            &mut action,
            approver_did,
            ts(1_400_000),
            Some(ts(1_399_999)),
            &approver_keypair,
        );
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Deny);
        assert_eq!(
            result.reason_codes,
            vec![AvcReasonCode::HumanApprovalInvalid]
        );
    }

    #[test]
    fn risk_below_approval_threshold_allows_without_human_approval() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let mut action = baseline_action(actor);
        action.estimated_risk_bp = Some(4_999);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
    }

    #[test]
    fn risk_threshold_without_estimate_allows_without_human_approval() {
        let h = Harness::new();
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(10_000);
        draft.constraints.approval_threshold_bp = Some(5_000);
        let cred = h.issue(draft);
        let actor = cred.subject_did.clone();
        let action = baseline_action(actor);
        let mut request = baseline_request(cred, ts(1_500_000));
        request.action = Some(action);
        let result = validate_avc(&request, &h.registry).unwrap();
        assert_eq!(result.decision, AvcDecision::Allow);
        assert_eq!(result.reason_codes, vec![AvcReasonCode::Valid]);
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
