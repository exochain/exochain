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

//! Core AVC types: credential, draft, intent, scope, constraints, refs.
//!
//! All vectors are normalized (sorted and deduplicated) before any signing
//! or hashing operation so that two callers constructing the same logical
//! credential always produce the same bytes and the same ID.

use std::collections::BTreeSet;

use exo_authority::permission::Permission;
use exo_core::{Did, Hash256, Signature, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::error::AvcError;

/// Signing domain tag for AVC credentials.
pub const AVC_CREDENTIAL_SIGNING_DOMAIN: &str = "exo.avc.credential.v1";
/// Schema version supported by this binary.
pub const AVC_SCHEMA_VERSION: u16 = 1;
/// Maximum value (in basis points) that any AVC bp field may hold.
pub const MAX_BASIS_POINTS: u32 = 10_000;

// ---------------------------------------------------------------------------
// Subject kind
// ---------------------------------------------------------------------------

/// What kind of autonomous actor the AVC describes.
///
/// AVC subjects are not limited to AI agents — workflows, services,
/// holons, and organizational units can all hold credentials.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AvcSubjectKind {
    /// An AI agent identified by model ID (and optional version).
    AiAgent {
        model_id: String,
        agent_version: Option<String>,
    },
    /// A swarm or collective of AI agents.
    AgentSwarm { swarm_id: String },
    /// A deterministic workflow.
    Workflow { workflow_id: String },
    /// A long-running service.
    Service { service_id: String },
    /// A holon — a self-contained constitutional automation.
    Holon { holon_id: String },
    /// A unit of an organization (department, team, fund).
    OrganizationUnit { unit_id: String },
    /// Subject kind is not yet specified.
    Unknown,
}

impl AvcSubjectKind {
    fn validate(&self) -> Result<(), AvcError> {
        match self {
            Self::AiAgent { model_id, .. } => non_empty(model_id, "subject_kind.model_id"),
            Self::AgentSwarm { swarm_id } => non_empty(swarm_id, "subject_kind.swarm_id"),
            Self::Workflow { workflow_id } => non_empty(workflow_id, "subject_kind.workflow_id"),
            Self::Service { service_id } => non_empty(service_id, "subject_kind.service_id"),
            Self::Holon { holon_id } => non_empty(holon_id, "subject_kind.holon_id"),
            Self::OrganizationUnit { unit_id } => non_empty(unit_id, "subject_kind.unit_id"),
            Self::Unknown => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Autonomy level
// ---------------------------------------------------------------------------

/// Bounded integer ladder describing how autonomous the actor may be.
///
/// Repr is `u8` so it is canonical in CBOR and orderable as a small integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AutonomyLevel {
    ObserveOnly = 0,
    Recommend = 1,
    Draft = 2,
    ExecuteWithHumanApproval = 3,
    ExecuteWithinBounds = 4,
    DelegateWithinBounds = 5,
}

// ---------------------------------------------------------------------------
// Delegated intent
// ---------------------------------------------------------------------------

/// What the autonomous actor is being delegated to pursue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedIntent {
    /// Stable hash identifying the intent body.
    pub intent_id: Hash256,
    /// Plain-language purpose, included in the signed payload.
    pub purpose: String,
    /// Allowed objectives — sorted/deduped before signing.
    pub allowed_objectives: Vec<String>,
    /// Prohibited objectives — sorted/deduped before signing.
    pub prohibited_objectives: Vec<String>,
    /// Maximum autonomy permitted under this credential.
    pub autonomy_level: AutonomyLevel,
    /// Whether the holder may delegate a narrower AVC.
    pub delegation_allowed: bool,
}

impl DelegatedIntent {
    fn validate(&self) -> Result<(), AvcError> {
        non_empty(&self.purpose, "delegated_intent.purpose")?;
        for obj in &self.allowed_objectives {
            non_empty(obj, "delegated_intent.allowed_objectives")?;
        }
        for obj in &self.prohibited_objectives {
            non_empty(obj, "delegated_intent.prohibited_objectives")?;
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.allowed_objectives = sort_dedup(self.allowed_objectives.drain(..));
        self.prohibited_objectives = sort_dedup(self.prohibited_objectives.drain(..));
    }
}

// ---------------------------------------------------------------------------
// Data class
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Restricted,
    PersonalData,
    SensitivePersonalData,
    Financial,
    LegalPrivileged,
    Custom(String),
}

impl DataClass {
    fn validate(&self) -> Result<(), AvcError> {
        if let Self::Custom(name) = self {
            non_empty(name, "data_class.custom")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Authority scope
// ---------------------------------------------------------------------------

/// The set of permissions, tools, data classes, counterparties, and
/// jurisdictions that the credential authorizes the actor to use.
///
/// All vectors are normalized (sorted, deduplicated) before signing so
/// caller ordering does not affect the credential ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityScope {
    pub permissions: Vec<Permission>,
    pub tools: Vec<String>,
    pub data_classes: Vec<DataClass>,
    pub counterparties: Vec<Did>,
    pub jurisdictions: Vec<String>,
}

impl AuthorityScope {
    /// An empty scope — convenient for narrow delegation drafts.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            permissions: Vec::new(),
            tools: Vec::new(),
            data_classes: Vec::new(),
            counterparties: Vec::new(),
            jurisdictions: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), AvcError> {
        for tool in &self.tools {
            non_empty(tool, "authority_scope.tools")?;
        }
        for class in &self.data_classes {
            class.validate()?;
        }
        for jurisdiction in &self.jurisdictions {
            non_empty(jurisdiction, "authority_scope.jurisdictions")?;
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.permissions = sort_dedup_copy(self.permissions.iter().copied());
        self.tools = sort_dedup(self.tools.drain(..));
        self.data_classes = sort_dedup(self.data_classes.drain(..));
        let mut cp: Vec<Did> = self.counterparties.drain(..).collect();
        cp.sort();
        cp.dedup();
        self.counterparties = cp;
        self.jurisdictions = sort_dedup(self.jurisdictions.drain(..));
    }
}

// ---------------------------------------------------------------------------
// Time window
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl TimeWindow {
    fn validate(&self) -> Result<(), AvcError> {
        if self.not_after <= self.not_before {
            return Err(AvcError::InvalidTimestamp {
                reason: "time_window.not_after must be strictly after not_before".into(),
            });
        }
        Ok(())
    }

    /// Returns true when `now` is within `[not_before, not_after]`.
    #[must_use]
    pub fn contains(&self, now: &Timestamp) -> bool {
        now >= &self.not_before && now <= &self.not_after
    }
}

// ---------------------------------------------------------------------------
// Constraints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcConstraints {
    pub max_budget_minor_units: Option<u64>,
    pub currency_code: Option<String>,
    pub max_action_risk_bp: Option<u32>,
    pub human_approval_required: bool,
    pub approval_threshold_bp: Option<u32>,
    pub max_delegation_depth: u32,
    pub allowed_time_window: Option<TimeWindow>,
    pub forbidden_actions: Vec<String>,
    pub emergency_stop_refs: Vec<String>,
}

impl AvcConstraints {
    /// A permissive default — useful as a baseline for tests and demos.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_budget_minor_units: None,
            currency_code: None,
            max_action_risk_bp: None,
            human_approval_required: false,
            approval_threshold_bp: None,
            max_delegation_depth: 0,
            allowed_time_window: None,
            forbidden_actions: Vec::new(),
            emergency_stop_refs: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), AvcError> {
        if let Some(value) = self.max_action_risk_bp {
            require_bp("max_action_risk_bp", value)?;
        }
        if let Some(value) = self.approval_threshold_bp {
            require_bp("approval_threshold_bp", value)?;
        }
        if let Some(window) = &self.allowed_time_window {
            window.validate()?;
        }
        if let Some(currency) = &self.currency_code {
            non_empty(currency, "constraints.currency_code")?;
        }
        for action in &self.forbidden_actions {
            non_empty(action, "constraints.forbidden_actions")?;
        }
        for stop in &self.emergency_stop_refs {
            non_empty(stop, "constraints.emergency_stop_refs")?;
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.forbidden_actions = sort_dedup(self.forbidden_actions.drain(..));
        self.emergency_stop_refs = sort_dedup(self.emergency_stop_refs.drain(..));
    }
}

// ---------------------------------------------------------------------------
// Consent / Policy refs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConsentRef {
    pub consent_id: Hash256,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyRef {
    pub policy_id: Hash256,
    pub policy_version: u16,
    pub required: bool,
}

// ---------------------------------------------------------------------------
// Authority chain wrapper
// ---------------------------------------------------------------------------

/// Hash of an authority chain whose verification is delegated to
/// `exo-authority` at validation time. The chain itself is held by the
/// validator's registry; the credential carries only its hash so the
/// signed AVC payload remains compact and cannot replay private chain
/// content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityChainRef {
    pub chain_hash: Hash256,
}

// ---------------------------------------------------------------------------
// Credential — signed
// ---------------------------------------------------------------------------

/// A portable, signed, machine-verifiable Autonomous Volition Credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutonomousVolitionCredential {
    pub schema_version: u16,
    pub issuer_did: Did,
    pub principal_did: Did,
    pub subject_did: Did,
    pub holder_did: Option<Did>,
    pub subject_kind: AvcSubjectKind,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub delegated_intent: DelegatedIntent,
    pub authority_scope: AuthorityScope,
    pub constraints: AvcConstraints,
    pub authority_chain: Option<AuthorityChainRef>,
    pub consent_refs: Vec<ConsentRef>,
    pub policy_refs: Vec<PolicyRef>,
    pub parent_avc_id: Option<Hash256>,
    pub signature: Signature,
}

/// A credential draft — every field of the credential except `signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvcDraft {
    pub schema_version: u16,
    pub issuer_did: Did,
    pub principal_did: Did,
    pub subject_did: Did,
    pub holder_did: Option<Did>,
    pub subject_kind: AvcSubjectKind,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub delegated_intent: DelegatedIntent,
    pub authority_scope: AuthorityScope,
    pub constraints: AvcConstraints,
    pub authority_chain: Option<AuthorityChainRef>,
    pub consent_refs: Vec<ConsentRef>,
    pub policy_refs: Vec<PolicyRef>,
    pub parent_avc_id: Option<Hash256>,
}

impl AvcDraft {
    /// Normalize all collections deterministically and validate every
    /// structural rule. This is invoked from `issue_avc`/`delegate_avc`
    /// before signing so the signed payload is always canonical.
    ///
    /// # Errors
    /// Returns [`AvcError`] for any structural violation.
    pub fn normalize_and_validate(&mut self) -> Result<(), AvcError> {
        if self.schema_version != AVC_SCHEMA_VERSION {
            return Err(AvcError::UnsupportedSchema {
                got: self.schema_version,
                supported: AVC_SCHEMA_VERSION,
            });
        }
        self.subject_kind.validate()?;
        self.delegated_intent.validate()?;
        self.delegated_intent.normalize();
        self.authority_scope.validate()?;
        self.authority_scope.normalize();
        self.constraints.validate()?;
        self.constraints.normalize();

        if let Some(expires) = self.expires_at {
            if expires <= self.created_at {
                return Err(AvcError::InvalidTimestamp {
                    reason: "expires_at must be strictly after created_at".into(),
                });
            }
        }

        self.consent_refs.sort();
        self.consent_refs.dedup();
        self.policy_refs.sort();
        self.policy_refs.dedup();

        Ok(())
    }
}

#[derive(Serialize)]
struct AvcSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    issuer_did: &'a Did,
    principal_did: &'a Did,
    subject_did: &'a Did,
    holder_did: Option<&'a Did>,
    subject_kind: &'a AvcSubjectKind,
    created_at: &'a Timestamp,
    expires_at: Option<&'a Timestamp>,
    delegated_intent: &'a DelegatedIntent,
    authority_scope: &'a AuthorityScope,
    constraints: &'a AvcConstraints,
    authority_chain: Option<&'a AuthorityChainRef>,
    consent_refs: &'a [ConsentRef],
    policy_refs: &'a [PolicyRef],
    parent_avc_id: Option<&'a Hash256>,
}

impl AutonomousVolitionCredential {
    /// Compute the canonical signing payload bytes for this credential.
    ///
    /// The payload is domain-separated CBOR over every field _except_
    /// `signature`. Tampering with any signed field yields a different
    /// payload and therefore a different signature/ID.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let payload = AvcSigningPayload {
            domain: AVC_CREDENTIAL_SIGNING_DOMAIN,
            schema_version: self.schema_version,
            issuer_did: &self.issuer_did,
            principal_did: &self.principal_did,
            subject_did: &self.subject_did,
            holder_did: self.holder_did.as_ref(),
            subject_kind: &self.subject_kind,
            created_at: &self.created_at,
            expires_at: self.expires_at.as_ref(),
            delegated_intent: &self.delegated_intent,
            authority_scope: &self.authority_scope,
            constraints: &self.constraints,
            authority_chain: self.authority_chain.as_ref(),
            consent_refs: &self.consent_refs,
            policy_refs: &self.policy_refs,
            parent_avc_id: self.parent_avc_id.as_ref(),
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)?;
        Ok(buf)
    }

    /// Deterministic content-addressed identifier for the credential.
    ///
    /// `id = blake3(canonical_cbor(signing_payload))` — independent of
    /// caller insertion order or runtime memory layout.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn id(&self) -> Result<Hash256, AvcError> {
        Ok(Hash256::digest(&self.signing_payload()?))
    }

    /// Compute the same ID a credential _would have_ if its `signature`
    /// changed but every other field stayed the same. Equivalent to
    /// [`Self::id`] because `signature` is excluded from the payload.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn content_hash(&self) -> Result<Hash256, AvcError> {
        hash_structured(&AvcSigningPayload {
            domain: AVC_CREDENTIAL_SIGNING_DOMAIN,
            schema_version: self.schema_version,
            issuer_did: &self.issuer_did,
            principal_did: &self.principal_did,
            subject_did: &self.subject_did,
            holder_did: self.holder_did.as_ref(),
            subject_kind: &self.subject_kind,
            created_at: &self.created_at,
            expires_at: self.expires_at.as_ref(),
            delegated_intent: &self.delegated_intent,
            authority_scope: &self.authority_scope,
            constraints: &self.constraints,
            authority_chain: self.authority_chain.as_ref(),
            consent_refs: &self.consent_refs,
            policy_refs: &self.policy_refs,
            parent_avc_id: self.parent_avc_id.as_ref(),
        })
        .map_err(AvcError::from)
    }

    /// Returns the effective holder DID, defaulting to `subject_did`
    /// when `holder_did` is absent.
    #[must_use]
    pub fn effective_holder(&self) -> &Did {
        self.holder_did.as_ref().unwrap_or(&self.subject_did)
    }
}

/// Issue a signed AVC from a draft.
///
/// The draft is normalized and validated, the canonical signing payload
/// is computed, and the supplied `sign` closure is invoked exactly once
/// over those bytes. The resulting credential's ID is content-addressed
/// over the signing payload (excluding the signature).
///
/// # Errors
/// Returns [`AvcError`] if the draft is structurally invalid or CBOR
/// encoding fails.
pub fn issue_avc<F>(mut draft: AvcDraft, sign: F) -> Result<AutonomousVolitionCredential, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    draft.normalize_and_validate()?;

    let mut credential = AutonomousVolitionCredential {
        schema_version: draft.schema_version,
        issuer_did: draft.issuer_did,
        principal_did: draft.principal_did,
        subject_did: draft.subject_did,
        holder_did: draft.holder_did,
        subject_kind: draft.subject_kind,
        created_at: draft.created_at,
        expires_at: draft.expires_at,
        delegated_intent: draft.delegated_intent,
        authority_scope: draft.authority_scope,
        constraints: draft.constraints,
        authority_chain: draft.authority_chain,
        consent_refs: draft.consent_refs,
        policy_refs: draft.policy_refs,
        parent_avc_id: draft.parent_avc_id,
        signature: Signature::empty(),
    };

    let payload = credential.signing_payload()?;
    credential.signature = sign(&payload);
    Ok(credential)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn non_empty(value: &str, field: &'static str) -> Result<(), AvcError> {
    if value.trim().is_empty() {
        Err(AvcError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn require_bp(field: &'static str, value: u32) -> Result<(), AvcError> {
    if value > MAX_BASIS_POINTS {
        Err(AvcError::BasisPointOutOfRange { field, value })
    } else {
        Ok(())
    }
}

fn sort_dedup<T: Ord, I: IntoIterator<Item = T>>(items: I) -> Vec<T> {
    let set: BTreeSet<T> = items.into_iter().collect();
    set.into_iter().collect()
}

fn sort_dedup_copy<T: Ord + Copy, I: IntoIterator<Item = T>>(items: I) -> Vec<T> {
    let set: BTreeSet<T> = items.into_iter().collect();
    set.into_iter().collect()
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("test DID")
    }

    pub fn ts(physical: u64) -> Timestamp {
        Timestamp::new(physical, 0)
    }

    pub fn h256(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    pub fn permissive_intent(purpose: &str) -> DelegatedIntent {
        DelegatedIntent {
            intent_id: h256(0xAA),
            purpose: purpose.into(),
            allowed_objectives: vec!["primary".into()],
            prohibited_objectives: vec![],
            autonomy_level: AutonomyLevel::Draft,
            delegation_allowed: true,
        }
    }

    pub fn permissive_scope() -> AuthorityScope {
        AuthorityScope {
            permissions: vec![Permission::Read, Permission::Write],
            tools: vec!["alpha".into(), "beta".into()],
            data_classes: vec![DataClass::Public, DataClass::Internal],
            counterparties: vec![],
            jurisdictions: vec!["US".into()],
        }
    }

    pub fn baseline_draft() -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: did("issuer"),
            principal_did: did("issuer"),
            subject_did: did("agent"),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: Some("1.0.0".into()),
            },
            created_at: ts(1_000_000),
            expires_at: Some(ts(2_000_000)),
            delegated_intent: permissive_intent("research"),
            authority_scope: permissive_scope(),
            constraints: AvcConstraints::permissive(),
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    #[test]
    fn issue_avc_succeeds_for_valid_draft() {
        let draft = baseline_draft();
        let cred = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert_eq!(cred.signature, fixed_signature());
    }

    #[test]
    fn issue_avc_normalizes_collections_and_dedupes() {
        let mut draft = baseline_draft();
        draft.authority_scope.tools = vec!["beta".into(), "alpha".into(), "alpha".into()];
        draft.authority_scope.permissions =
            vec![Permission::Write, Permission::Read, Permission::Read];
        let cred = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert_eq!(cred.authority_scope.tools, vec!["alpha", "beta"]);
        assert_eq!(
            cred.authority_scope.permissions,
            vec![Permission::Read, Permission::Write]
        );
    }

    #[test]
    fn issue_avc_rejects_unsupported_schema() {
        let mut draft = baseline_draft();
        draft.schema_version = 99;
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::UnsupportedSchema { got: 99, .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_purpose() {
        let mut draft = baseline_draft();
        draft.delegated_intent.purpose = "   ".into();
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(
            matches!(err, AvcError::EmptyField { field } if field == "delegated_intent.purpose")
        );
    }

    #[test]
    fn issue_avc_rejects_empty_allowed_objective() {
        let mut draft = baseline_draft();
        draft.delegated_intent.allowed_objectives = vec!["valid".into(), "  ".into()];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_prohibited_objective() {
        let mut draft = baseline_draft();
        draft.delegated_intent.prohibited_objectives = vec!["".into()];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_tool_in_scope() {
        let mut draft = baseline_draft();
        draft.authority_scope.tools = vec!["".into()];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_jurisdiction() {
        let mut draft = baseline_draft();
        draft.authority_scope.jurisdictions = vec!["".into()];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_data_class_custom() {
        let mut draft = baseline_draft();
        draft.authority_scope.data_classes = vec![DataClass::Custom("   ".into())];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_currency_code() {
        let mut draft = baseline_draft();
        draft.constraints.currency_code = Some("   ".into());
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_forbidden_action() {
        let mut draft = baseline_draft();
        draft.constraints.forbidden_actions = vec!["".into()];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_emergency_stop_ref() {
        let mut draft = baseline_draft();
        draft.constraints.emergency_stop_refs = vec!["".into()];
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn issue_avc_rejects_basis_points_out_of_range() {
        let mut draft = baseline_draft();
        draft.constraints.max_action_risk_bp = Some(11_000);
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::BasisPointOutOfRange { .. }));
    }

    #[test]
    fn issue_avc_rejects_approval_threshold_out_of_range() {
        let mut draft = baseline_draft();
        draft.constraints.approval_threshold_bp = Some(99_999);
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::BasisPointOutOfRange { .. }));
    }

    #[test]
    fn issue_avc_rejects_expiry_at_or_before_created_at() {
        let mut draft = baseline_draft();
        draft.expires_at = Some(draft.created_at);
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::InvalidTimestamp { .. }));
    }

    #[test]
    fn issue_avc_rejects_inverted_time_window() {
        let mut draft = baseline_draft();
        draft.constraints.allowed_time_window = Some(TimeWindow {
            not_before: ts(2_000),
            not_after: ts(1_000),
        });
        let err = issue_avc(draft, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, AvcError::InvalidTimestamp { .. }));
    }

    #[test]
    fn issue_avc_rejects_empty_subject_kind_field() {
        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::AgentSwarm {
            swarm_id: "".into(),
        };
        assert!(issue_avc(draft, |_| fixed_signature()).is_err());

        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::Workflow {
            workflow_id: "".into(),
        };
        assert!(issue_avc(draft, |_| fixed_signature()).is_err());

        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::Service {
            service_id: "".into(),
        };
        assert!(issue_avc(draft, |_| fixed_signature()).is_err());

        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::Holon {
            holon_id: "".into(),
        };
        assert!(issue_avc(draft, |_| fixed_signature()).is_err());

        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::OrganizationUnit { unit_id: "".into() };
        assert!(issue_avc(draft, |_| fixed_signature()).is_err());
    }

    #[test]
    fn subject_kind_unknown_validates() {
        let mut draft = baseline_draft();
        draft.subject_kind = AvcSubjectKind::Unknown;
        let cred = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert!(matches!(cred.subject_kind, AvcSubjectKind::Unknown));
    }

    #[test]
    fn id_is_deterministic() {
        let draft = baseline_draft();
        let cred1 = issue_avc(draft.clone(), |_| fixed_signature()).unwrap();
        let cred2 = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert_eq!(cred1.id().unwrap(), cred2.id().unwrap());
    }

    #[test]
    fn id_changes_when_signed_field_changes() {
        let draft1 = baseline_draft();
        let mut draft2 = draft1.clone();
        draft2.delegated_intent.purpose = "different".into();
        let cred1 = issue_avc(draft1, |_| fixed_signature()).unwrap();
        let cred2 = issue_avc(draft2, |_| fixed_signature()).unwrap();
        assert_ne!(cred1.id().unwrap(), cred2.id().unwrap());
    }

    #[test]
    fn signing_payload_contains_domain_tag() {
        let cred = issue_avc(baseline_draft(), |_| fixed_signature()).unwrap();
        let bytes = cred.signing_payload().unwrap();
        let needle = AVC_CREDENTIAL_SIGNING_DOMAIN.as_bytes();
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn signing_payload_excludes_signature_so_id_is_signature_independent() {
        let mut cred = issue_avc(baseline_draft(), |_| fixed_signature()).unwrap();
        let id1 = cred.id().unwrap();
        cred.signature = Signature::from_bytes([0x42u8; 64]);
        let id2 = cred.id().unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn id_changes_when_holder_changes() {
        let mut draft1 = baseline_draft();
        draft1.holder_did = Some(did("holder-a"));
        let mut draft2 = draft1.clone();
        draft2.holder_did = Some(did("holder-b"));
        let id1 = issue_avc(draft1, |_| fixed_signature())
            .unwrap()
            .id()
            .unwrap();
        let id2 = issue_avc(draft2, |_| fixed_signature())
            .unwrap()
            .id()
            .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn id_changes_when_authority_chain_changes() {
        let mut draft1 = baseline_draft();
        draft1.authority_chain = Some(AuthorityChainRef {
            chain_hash: h256(0x11),
        });
        let mut draft2 = draft1.clone();
        draft2.authority_chain = Some(AuthorityChainRef {
            chain_hash: h256(0x22),
        });
        let id1 = issue_avc(draft1, |_| fixed_signature())
            .unwrap()
            .id()
            .unwrap();
        let id2 = issue_avc(draft2, |_| fixed_signature())
            .unwrap()
            .id()
            .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn content_hash_matches_id() {
        let cred = issue_avc(baseline_draft(), |_| fixed_signature()).unwrap();
        assert_eq!(cred.content_hash().unwrap(), cred.id().unwrap());
    }

    #[test]
    fn effective_holder_defaults_to_subject() {
        let cred = issue_avc(baseline_draft(), |_| fixed_signature()).unwrap();
        assert_eq!(cred.effective_holder(), &cred.subject_did);
    }

    #[test]
    fn effective_holder_uses_explicit_holder_when_present() {
        let mut draft = baseline_draft();
        draft.holder_did = Some(did("holder-x"));
        let cred = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert_eq!(cred.effective_holder(), &did("holder-x"));
    }

    #[test]
    fn time_window_contains_inclusive_bounds() {
        let window = TimeWindow {
            not_before: ts(100),
            not_after: ts(200),
        };
        assert!(window.contains(&ts(100)));
        assert!(window.contains(&ts(150)));
        assert!(window.contains(&ts(200)));
        assert!(!window.contains(&ts(99)));
        assert!(!window.contains(&ts(201)));
    }

    #[test]
    fn autonomy_level_orderable() {
        assert!(AutonomyLevel::ObserveOnly < AutonomyLevel::Recommend);
        assert!(AutonomyLevel::Recommend < AutonomyLevel::Draft);
        assert!(AutonomyLevel::Draft < AutonomyLevel::ExecuteWithHumanApproval);
        assert!(AutonomyLevel::ExecuteWithHumanApproval < AutonomyLevel::ExecuteWithinBounds);
        assert!(AutonomyLevel::ExecuteWithinBounds < AutonomyLevel::DelegateWithinBounds);
    }

    #[test]
    fn permissions_normalize_deterministically() {
        let mut draft = baseline_draft();
        draft.authority_scope.permissions = vec![
            Permission::Govern,
            Permission::Read,
            Permission::Write,
            Permission::Read,
        ];
        let cred = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert_eq!(
            cred.authority_scope.permissions,
            vec![Permission::Read, Permission::Write, Permission::Govern]
        );
    }

    #[test]
    fn consent_and_policy_refs_normalize() {
        let mut draft = baseline_draft();
        draft.consent_refs = vec![
            ConsentRef {
                consent_id: h256(2),
                required: true,
            },
            ConsentRef {
                consent_id: h256(1),
                required: true,
            },
            ConsentRef {
                consent_id: h256(2),
                required: true,
            },
        ];
        draft.policy_refs = vec![
            PolicyRef {
                policy_id: h256(5),
                policy_version: 1,
                required: true,
            },
            PolicyRef {
                policy_id: h256(5),
                policy_version: 1,
                required: true,
            },
        ];
        let cred = issue_avc(draft, |_| fixed_signature()).unwrap();
        assert_eq!(cred.consent_refs.len(), 2);
        assert!(cred.consent_refs[0].consent_id <= cred.consent_refs[1].consent_id);
        assert_eq!(cred.policy_refs.len(), 1);
    }

    #[test]
    fn permissive_constraints_validate() {
        let constraints = AvcConstraints::permissive();
        assert!(constraints.validate().is_ok());
    }

    #[test]
    fn empty_authority_scope_validates() {
        let mut scope = AuthorityScope::empty();
        scope.normalize();
        assert!(scope.validate().is_ok());
    }
}
