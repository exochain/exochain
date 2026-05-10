<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# PRD: Autonomous Volition Credential (A.V.C.) for EXOCHAIN

**Product:** EXOCHAIN / CommandBase.ai  
**Feature:** Autonomous Volition Credential (A.V.C.)  
**Implementation language:** Rust  
**Target repository:** `exochain/exochain`  
**Primary deliverable:** First-class Rust credential primitive, validation engine, revocation model, trust receipt, and node/API integration for autonomous agent authority.

---

## 1. Executive Summary

Implement **A.V.C. — Autonomous Volition Credential** as a first-class Rust primitive inside EXOCHAIN.

An **Autonomous Volition Credential** is a portable, signed, machine-verifiable credential that defines what an autonomous actor is authorized to **pursue, initiate, delegate, access, execute, and prove** under a human or organizational principal.

The core purpose is to move EXOCHAIN from having adjacent primitives — identity, authority, consent, agent passports, governance, receipts — into a unified agent-native trust object that agents, humans, systems, auditors, and counterparties can all inspect and validate before autonomous action occurs.

Core thesis:

> Identity proves who an agent is. Authority proves who delegated power. Consent proves what data/action posture applies. An AVC proves what the autonomous actor is allowed to pursue.

---

## 2. Product Name and Language

### Formal name

**Autonomous Volition Credential**

### Acronym

**A.V.C.** or **AVC**

### One-line definition

A portable credential for autonomous intent, authority, constraints, and accountability.

### Plain-English definition

An AVC tells the network what an autonomous actor is authorized to pursue before it acts.

### Important semantic constraint

In this product, **volition** means **delegated operational intent**, not consciousness, sentience, emotion, or human-like free will.

---

## 3. Why This Exists

EXOCHAIN already contains strong adjacent trust primitives:

- decentralized identity and key management
- authority delegation and attestation chains
- consent and bailment enforcement
- legal provenance and audit admissibility
- governance enforcement
- agent passport surfaces
- trust receipts and autonomous corporation scaffolding

However, these pieces need one portable, inspectable object that agents can present to one another before cooperation or execution.

The missing object is the **AVC**.

Without AVCs, an agent can be known, authorized, and logged, but the system still lacks a unified credential that answers:

1. Who or what is this autonomous actor?
2. Who is the principal behind it?
3. What delegated intent is it authorized to pursue?
4. Which actions, tools, data, counterparties, and jurisdictions are in scope?
5. What constraints, expiry, revocation, consent rules, and human gates apply?
6. Can another agent verify this before interacting?
7. Can the action later be attached to a trust receipt?

---

## 4. Goals

### P0 Goals

1. Add a new Rust crate: `crates/exo-avc`.
2. Define an `AutonomousVolitionCredential` data model.
3. Support deterministic credential IDs using canonical CBOR + BLAKE3/`Hash256`.
4. Support signed credential issuance using existing EXOCHAIN cryptographic primitives.
5. Support validation of:
   - credential structure
   - subject identity
   - issuer signature
   - authority chain
   - permission scope
   - delegated intent scope
   - expiry
   - revocation
   - consent references, where available
   - risk/human-gate constraints
6. Support credential delegation with strict scope narrowing.
7. Support credential revocation.
8. Support trust receipt creation for validation decisions and executed actions.
9. Add tests proving deterministic, tamper-evident, fail-closed behavior.
10. Add `exo-node` API routes for issuing, validating, delegating, revoking, and retrieving AVCs.
11. Export the new types through `exochain-sdk`.
12. Add documentation and traceability entries.

### P1 Goals

1. Persist AVCs and revocations through the existing DAG/SQLite store where feasible.
2. Attach AVC summaries to the existing agent passport endpoint.
3. Add CommandBase-facing endpoints or adapters.
4. Add WASM exports if current bridge structure supports it cleanly.

### P2 Goals

1. Map AVCs to W3C Verifiable Credential JSON-LD shape.
2. Add selective disclosure or ZK-friendly proofs.
3. Add multi-agent credential exchange flow.
4. Add distributed revocation registry replication.
5. Add policy simulation: “Would this credential allow this action?” without recording a live receipt.

---

## 5. Non-Goals

Do **not** implement the following in the first pass:

1. Full W3C VC JSON-LD conformance.
2. Full UI implementation in CommandBase or Decision Forum.
3. New cryptographic algorithms beyond existing EXOCHAIN primitives.
4. Floating-point risk scores. Use integer basis points only.
5. Ad hoc admin overrides.
6. Ledger storage of PII.
7. A production-grade global revocation network.
8. Natural-language policy parsing.
9. Autonomous agent runtime execution.
10. Claims that an agent has consciousness or real free will.

---

## 6. Primary Users / Actors

### 6.1 Autonomous Actor

An AI agent, workflow, bot, synthetic worker, service, autonomous company function, or other software actor that needs to prove what it may pursue.

### 6.2 Principal

The human, organization, department, fund, DAO, tenant, or other entity on whose behalf the autonomous actor operates.

### 6.3 Issuer

The DID that signs and issues the credential. Usually the principal, controller, CommandBase authority, or delegated issuer.

### 6.4 Holder

The autonomous actor or system that presents the credential.

### 6.5 Verifier

Another agent, API, EXOCHAIN node, organization, counterparty, auditor, gateway, or CommandBase control plane verifying the AVC.

### 6.6 Auditor

A human or system reconstructing the credential, validation decision, and action receipt after the fact.

---

## 7. User Stories

### US-001: Issue an AVC

As a principal or authorized issuer, I need to issue an AVC to an autonomous actor so it can prove what it is allowed to pursue.

### US-002: Validate an AVC

As a verifier, I need to validate a presented AVC so I can decide whether to accept, reject, challenge, or escalate an agent action.

### US-003: Delegate an AVC

As an authorized autonomous actor, I need to delegate a narrowed AVC to another actor so multi-agent workflows can occur without scope widening.

### US-004: Revoke an AVC

As an issuer or authorized revoker, I need to revoke an AVC so the actor can no longer rely on stale or unsafe authority.

### US-005: Attach an AVC to an action receipt

As EXOCHAIN, I need to create a trust receipt when an AVC is validated for an action so later auditors can reconstruct who authorized what.

### US-006: Query AVC standing

As a verifier, I need to query the current standing of an AVC so I can determine if it is active, expired, revoked, suspended, quarantined, or invalid.

---

## 8. Core Product Model

### 8.1 AVC Conceptual Shape

An AVC binds these layers together:

```text
Issuer DID
  -> Principal DID
    -> Autonomous Subject DID
      -> Delegated Intent
        -> Authority Scope
          -> Constraints
            -> Consent / Policy References
              -> Expiry / Revocation / Receipts
```

### 8.2 Required Credential Fields

The credential MUST include:

- `schema_version`
- `id`
- `issuer_did`
- `principal_did`
- `subject_did`
- `subject_kind`
- `holder_did`, optional; defaults to `subject_did` if absent
- `created_at`
- `expires_at`, optional but recommended
- `delegated_intent`
- `authority_scope`
- `constraints`
- `authority_chain`, optional but required when issuer is not the principal
- `consent_refs`
- `policy_refs`
- `parent_avc_id`, optional for delegation
- `signature`

### 8.3 AVC ID

The AVC ID MUST be deterministic:

```text
avc_id = Hash256::digest(canonical_cbor(signing_payload_without_signature))
```

The ID MUST NOT depend on map insertion order, JSON formatting, timestamps outside the credential body, or runtime memory layout.

### 8.4 Signing Payload

Credential signing MUST be domain-separated:

```text
exo.avc.credential.v1
```

The signed payload MUST include a fixed-width schema version:

```rust
schema_version: u16
```

The signed payload MUST NOT serialize `usize` or platform-dependent integer widths.

---

## 9. Proposed Rust Crate

### 9.1 New crate

Create:

```text
crates/exo-avc/
```

### 9.2 Suggested crate structure

```text
crates/exo-avc/
  Cargo.toml
  src/
    lib.rs
    credential.rs
    intent.rs
    constraints.rs
    validation.rs
    delegation.rs
    revocation.rs
    receipt.rs
    registry.rs
    error.rs
    serde_cbor.rs
```

### 9.3 Cargo dependencies

Use existing workspace dependencies where possible.

Expected dependencies:

```toml
[dependencies]
exo-core = { path = "../exo-core" }
exo-authority = { path = "../exo-authority" }
exo-consent = { path = "../exo-consent", optional = true }
serde = { workspace = true, features = ["derive"] }
ciborium = { workspace = true }
thiserror = { workspace = true }
zeroize = { workspace = true, optional = true }
```

If the workspace does not define a dependency in `[workspace.dependencies]`, use the version already used by nearby crates.

Do not add unnecessary new dependencies.

---

## 10. Core Rust Types

Use deterministic containers: `BTreeMap`, `BTreeSet`, and `Vec` with explicit deterministic ordering. Do not use `HashMap` or `HashSet` in production logic.

### 10.1 Credential type

```rust
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
    pub authority_chain: Option<AuthorityChain>,
    pub consent_refs: Vec<ConsentRef>,
    pub policy_refs: Vec<PolicyRef>,
    pub parent_avc_id: Option<Hash256>,
    pub signature: Signature,
}
```

### 10.2 Subject kind

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcSubjectKind {
    AiAgent { model_id: String, agent_version: Option<String> },
    AgentSwarm { swarm_id: String },
    Workflow { workflow_id: String },
    Service { service_id: String },
    OrganizationUnit { unit_id: String },
    Unknown,
}
```

### 10.3 Delegated intent

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedIntent {
    pub intent_id: Hash256,
    pub purpose: String,
    pub allowed_objectives: Vec<String>,
    pub prohibited_objectives: Vec<String>,
    pub autonomy_level: AutonomyLevel,
    pub delegation_allowed: bool,
}
```

### 10.4 Autonomy level

No floats. Use a bounded integer enum.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AutonomyLevel {
    ObserveOnly = 0,
    Recommend = 1,
    Draft = 2,
    ExecuteWithHumanApproval = 3,
    ExecuteWithinBounds = 4,
    DelegateWithinBounds = 5,
}
```

### 10.5 Authority scope

Use existing `exo_authority::permission::Permission` if accessible.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityScope {
    pub permissions: Vec<Permission>,
    pub tools: Vec<String>,
    pub data_classes: Vec<DataClass>,
    pub counterparties: Vec<Did>,
    pub jurisdictions: Vec<String>,
}
```

All vectors MUST be normalized before signing: sorted, deduplicated, deterministic.

### 10.6 Data class

```rust
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
```

### 10.7 Constraints

```rust
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
```

Use basis points for risk thresholds:

```text
0..=10_000
```

Reject values above `10_000`.

### 10.8 Consent and policy refs

```rust
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
```

### 10.9 Validation request

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcValidationRequest {
    pub credential: AutonomousVolitionCredential,
    pub action: Option<AvcActionRequest>,
    pub now: Timestamp,
}
```

### 10.10 Action request

```rust
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
}
```

### 10.11 Validation result

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcValidationResult {
    pub credential_id: Hash256,
    pub decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub normalized_holder_did: Did,
    pub valid_until: Option<Timestamp>,
    pub receipt: Option<AvcTrustReceipt>,
}
```

### 10.12 Decision enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcDecision {
    Allow,
    Deny,
    HumanApprovalRequired,
    ChallengeRequired,
}
```

### 10.13 Reason codes

```rust
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
}
```

### 10.14 Trust receipt

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcTrustReceipt {
    pub schema_version: u16,
    pub receipt_id: Hash256,
    pub credential_id: Hash256,
    pub action_id: Option<Hash256>,
    pub validator_did: Did,
    pub decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub created_at: Timestamp,
    pub validation_hash: Hash256,
    pub signature: Signature,
}
```

Trust receipt signing domain:

```text
exo.avc.receipt.v1
```

### 10.15 Revocation

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcRevocation {
    pub schema_version: u16,
    pub credential_id: Hash256,
    pub revoker_did: Did,
    pub reason: AvcRevocationReason,
    pub created_at: Timestamp,
    pub signature: Signature,
}
```

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcRevocationReason {
    IssuerRevoked,
    PrincipalRevoked,
    ExpiredAuthority,
    CompromisedKey,
    PolicyViolation,
    SybilChallenge,
    EmergencyStop,
    Superseded,
    Other(String),
}
```

Revocation signing domain:

```text
exo.avc.revocation.v1
```

---

## 11. Public Rust API

Implement these public functions or equivalent methods.

### 11.1 Credential ID

```rust
impl AutonomousVolitionCredential {
    pub fn id(&self) -> Result<Hash256, AvcError>;
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError>;
    pub fn normalize(&mut self);
}
```

### 11.2 Issue credential

```rust
pub fn issue_avc<F>(
    draft: AvcDraft,
    sign: F,
) -> Result<AutonomousVolitionCredential, AvcError>
where
    F: Fn(&[u8]) -> Signature;
```

`AvcDraft` should contain all credential fields except `signature`.

### 11.3 Validate credential

```rust
pub fn validate_avc<R>(
    request: &AvcValidationRequest,
    registry: &R,
) -> Result<AvcValidationResult, AvcError>
where
    R: AvcRegistryRead;
```

### 11.4 Delegate credential

```rust
pub fn delegate_avc<F>(
    parent: &AutonomousVolitionCredential,
    draft: AvcDelegationDraft,
    sign: F,
) -> Result<AutonomousVolitionCredential, AvcError>
where
    F: Fn(&[u8]) -> Signature;
```

Delegation MUST fail if the child widens:

- autonomy level
- permission scope
- tool scope
- data class scope
- counterparty scope
- jurisdiction scope
- budget
- risk threshold
- delegation depth
- expiry

### 11.5 Revoke credential

```rust
pub fn revoke_avc<F>(
    credential_id: Hash256,
    revoker_did: Did,
    reason: AvcRevocationReason,
    now: Timestamp,
    sign: F,
) -> Result<AvcRevocation, AvcError>
where
    F: Fn(&[u8]) -> Signature;
```

### 11.6 Create trust receipt

```rust
pub fn create_trust_receipt<F>(
    validation: &AvcValidationResult,
    validator_did: Did,
    now: Timestamp,
    sign: F,
) -> Result<AvcTrustReceipt, AvcError>
where
    F: Fn(&[u8]) -> Signature;
```

### 11.7 Registry traits

```rust
pub trait AvcRegistryRead {
    fn resolve_public_key(&self, did: &Did) -> Option<PublicKey>;
    fn is_revoked(&self, credential_id: &Hash256) -> bool;
    fn get_revocation(&self, credential_id: &Hash256) -> Option<AvcRevocation>;
    fn consent_ref_exists(&self, consent_ref: &ConsentRef) -> bool;
    fn policy_ref_exists(&self, policy_ref: &PolicyRef) -> bool;
}

pub trait AvcRegistryWrite: AvcRegistryRead {
    fn put_credential(&mut self, credential: AutonomousVolitionCredential) -> Result<(), AvcError>;
    fn put_revocation(&mut self, revocation: AvcRevocation) -> Result<(), AvcError>;
    fn put_receipt(&mut self, receipt: AvcTrustReceipt) -> Result<(), AvcError>;
}
```

### 11.8 In-memory registry

Implement deterministic in-memory registry for tests and MVP endpoints:

```rust
pub struct InMemoryAvcRegistry {
    credentials: BTreeMap<Hash256, AutonomousVolitionCredential>,
    revocations: BTreeMap<Hash256, AvcRevocation>,
    receipts: BTreeMap<Hash256, AvcTrustReceipt>,
    public_keys: BTreeMap<Did, PublicKey>,
    consent_refs: BTreeSet<Hash256>,
    policy_refs: BTreeSet<Hash256>,
}
```

---

## 12. Validation Rules

Validation MUST be fail-closed.

### 12.1 Structural validation

Deny if:

- schema version unsupported
- subject DID malformed
- issuer DID malformed
- missing signature
- `created_at` after `now`
- `expires_at` before or equal to `now`
- basis point fields greater than `10_000`
- required string fields are empty after trimming
- normalized vectors contain duplicates after normalization

### 12.2 Signature validation

Deny if:

- issuer public key cannot be resolved
- signature is empty
- signature does not verify against canonical signing payload
- payload uses non-domain-separated format

### 12.3 Authority chain validation

If `issuer_did != principal_did`, `authority_chain` MUST be present and valid.

Use existing `exo-authority` chain verification where possible.

Deny if:

- authority chain missing
- authority chain invalid
- scope widens
- chain expired
- chain does not connect principal to issuer or issuer to subject, depending on existing authority semantics
- chain does not include needed permission

### 12.4 Subject/holder validation

Deny if action actor DID does not match:

- `subject_did`, or
- `holder_did` when holder is present and allowed.

### 12.5 Permission validation

Deny if requested permission is not in `authority_scope.permissions`.

### 12.6 Tool validation

If action includes `tool`, deny if tool is not in credential tool scope.

Empty tool scope means no tools are authorized unless the requested action has no tool.

### 12.7 Data class validation

If action includes `data_class`, deny if not authorized.

`Custom(String)` values must match exactly.

### 12.8 Counterparty validation

If action includes `target_did`, deny if credential contains a non-empty counterparty list and target is not included.

### 12.9 Budget validation

If both credential budget and action budget exist, deny when action budget exceeds credential budget.

### 12.10 Risk validation

If both max action risk and action estimated risk exist, deny when action risk exceeds max.

If `estimated_risk_bp` exceeds `approval_threshold_bp`, return `HumanApprovalRequired` unless `requires_human_approval` is true and approval has been modeled by a future approval ref.

For P0, treat `requires_human_approval == true` as an action flag only. Do not implement approval documents unless an existing approval primitive is easy to reuse.

### 12.11 Revocation validation

Deny if registry reports the credential ID revoked.

### 12.12 Consent and policy refs

For each required consent ref or policy ref:

- if registry cannot prove it exists, return `Deny` with `ConsentMissing` or `PolicyMissing`.

Optional refs must not fail validation if missing.

---

## 13. Node API Integration

### 13.1 New module

Add:

```text
crates/exo-node/src/avc.rs
```

Register routes alongside passport/governance routes.

Use existing bearer auth middleware pattern from `passport.rs` if available.

### 13.2 API routes

#### POST `/api/v1/avc/issue`

Issues or registers an AVC.

For P0, support either:

1. signed credential registration; or
2. draft issuance signed by node identity if existing node signer is accessible.

Prefer implementation option 2 only if the node signer is already available without new key-management architecture. Otherwise use option 1.

Request shape option 1:

```json
{
  "credential": { "...": "signed AVC" }
}
```

Response:

```json
{
  "credential_id": "...",
  "status": "registered"
}
```

#### POST `/api/v1/avc/validate`

Validates a credential and optional action.

Request:

```json
{
  "credential": { "...": "AVC" },
  "action": {
    "action_id": "...",
    "actor_did": "did:exo:agent1",
    "requested_permission": "Read",
    "tool": "crm.lookup",
    "target_did": null,
    "data_class": "Internal",
    "estimated_budget_minor_units": null,
    "estimated_risk_bp": 1000,
    "requires_human_approval": false
  }
}
```

Response:

```json
{
  "credential_id": "...",
  "decision": "Allow",
  "reason_codes": ["Valid"],
  "valid_until": 1770000000000,
  "receipt": { "...": "optional trust receipt" }
}
```

#### POST `/api/v1/avc/delegate`

Creates or registers a child AVC with narrowed scope.

Request shape:

```json
{
  "parent_credential": { "...": "AVC" },
  "child_credential": { "...": "signed child AVC" }
}
```

Response:

```json
{
  "credential_id": "...",
  "parent_avc_id": "...",
  "status": "registered"
}
```

#### POST `/api/v1/avc/revoke`

Registers a signed revocation.

Request:

```json
{
  "revocation": { "...": "signed revocation" }
}
```

Response:

```json
{
  "credential_id": "...",
  "status": "revoked"
}
```

#### GET `/api/v1/avc/:id`

Returns credential if known.

#### GET `/api/v1/agents/:did/avcs`

Returns known AVC summaries for a subject DID.

### 13.3 API error behavior

- Invalid DID: `400`
- Unsupported schema version: `400`
- Missing bearer token: `401`
- Invalid bearer token: `401`
- Credential not found: `404`
- Validation denied: `200` with `decision: Deny`; do not use `403` for ordinary AVC denials
- Internal store error: `500`

### 13.4 Concurrency

Follow the existing `passport.rs` pattern:

- do not lock `std::sync::Mutex` directly inside async handlers
- use `tokio::task::spawn_blocking` for blocking registry/store access
- add a concurrency limit layer

---

## 14. Agent Passport Integration

Update `passport.rs` after the core AVC module is stable.

Add `avc` summary to `AgentPassport`:

```rust
pub avc: AvcPassportProfile,
```

Suggested profile:

```rust
#[derive(Debug, Serialize)]
pub struct AvcPassportProfile {
    pub active_credentials: u64,
    pub revoked_credentials: u64,
    pub highest_autonomy_level: Option<AutonomyLevel>,
    pub credential_ids: Vec<Hash256>,
}
```

For P0, this may return zeros unless registry state is wired into passport state. Do not break existing passport behavior.

---

## 15. SDK Integration

Update `crates/exochain-sdk` to export AVC types and high-level helpers:

```rust
pub use exo_avc::{
    AutonomousVolitionCredential,
    DelegatedIntent,
    AvcConstraints,
    AvcValidationRequest,
    AvcValidationResult,
    AvcTrustReceipt,
    AvcRevocation,
    issue_avc,
    validate_avc,
    delegate_avc,
    revoke_avc,
};
```

If SDK structure prefers modules:

```rust
pub mod avc;
```

---

## 16. Documentation Deliverables

Add:

```text
docs/avc/README.md
```

Include:

1. Definition of Autonomous Volition Credential.
2. Explanation of delegated operational intent.
3. Examples of issue / validate / delegate / revoke.
4. Example JSON credential.
5. Security model.
6. Non-claim of AI consciousness or sentience.
7. Relationship to agent passport.
8. Relationship to authority chains and consent refs.
9. Example agent-to-agent validation handshake.

Update if applicable:

```text
README.md
governance/traceability_matrix.md
governance/threat_matrix.md
governance/quality_gates.md
```

Do not overstate production readiness.

Suggested README phrase:

```text
AVC — Autonomous Volition Credential — is a first-class EXOCHAIN primitive for credentialing autonomous intent, authority, constraints, and accountability before agent action.
```

---

## 17. Security Requirements

### 17.1 Fail closed

Unknown keys, missing refs, invalid signatures, unsupported schemas, malformed DIDs, and invalid basis point values MUST deny validation.

### 17.2 No PII on ledger

Do not place PII in credential fields. Use hashes, DIDs, refs, and opaque IDs.

### 17.3 Determinism

- No floats.
- No nondeterministic maps/sets in production logic.
- No wall-clock calls inside pure validation; `now` must be passed in.
- No randomized IDs.

### 17.4 Domain-separated signing

Credentials, revocations, and receipts must use distinct signing domains.

### 17.5 Anti-replay

Credential validation must check expiry and revocation.

Receipt IDs must be deterministic over receipt payload and not reusable for different actions.

### 17.6 Tamper detection

Changing any signed field must invalidate the signature.

### 17.7 Scope narrowing

Delegation must reject child AVCs that widen any meaningful field.

### 17.8 Auditability

Every allow/deny decision should be representable as an AVC trust receipt.

---

## 18. Test Plan

### 18.1 Crate unit tests

Add tests under `crates/exo-avc/src/*`.

Required tests:

1. `avc_id_is_deterministic`
2. `avc_signing_payload_is_domain_tagged_cbor`
3. `avc_signing_payload_excludes_signature`
4. `avc_rejects_empty_signature`
5. `avc_rejects_invalid_signature`
6. `avc_rejects_tampered_subject`
7. `avc_rejects_tampered_intent`
8. `avc_rejects_created_at_in_future`
9. `avc_rejects_expired_credential`
10. `avc_rejects_revoked_credential`
11. `avc_rejects_permission_not_in_scope`
12. `avc_rejects_tool_not_in_scope`
13. `avc_rejects_data_class_not_in_scope`
14. `avc_rejects_budget_exceeded`
15. `avc_rejects_risk_exceeded`
16. `avc_requires_human_approval_when_threshold_crossed`
17. `delegate_rejects_scope_widening`
18. `delegate_rejects_autonomy_widening`
19. `delegate_rejects_expiry_extension_beyond_parent`
20. `delegate_accepts_strictly_narrower_scope`
21. `revocation_signature_is_domain_tagged`
22. `receipt_signature_is_domain_tagged`
23. `receipt_id_is_deterministic`
24. `validation_reason_codes_are_sorted_and_deduped`
25. `production_code_does_not_use_hashmap_or_hashset`

### 18.2 Node route tests

Add tests in `crates/exo-node/src/avc.rs`.

Required route tests:

1. `avc_validate_requires_bearer_token`
2. `avc_validate_with_bearer_token_passes`
3. `avc_validate_invalid_did_returns_bad_request`
4. `avc_validate_allows_valid_credential`
5. `avc_validate_denies_revoked_credential`
6. `avc_revoke_marks_credential_revoked`
7. `avc_get_unknown_returns_404`
8. `avc_agent_list_returns_subject_credentials`
9. `avc_handlers_use_spawn_blocking_for_registry_access`
10. `avc_handlers_do_not_lock_mutex_directly_in_async_context`

### 18.3 Workspace checks

The implementation must pass:

```bash
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fmt --all -- --check
cargo deny check
```

If `cargo deny check` depends on tool availability in the environment, document the result but do not bypass project policy.

---

## 19. Acceptance Criteria

This PR is acceptable when all of the following are true:

1. `crates/exo-avc` exists and is included in the workspace.
2. `AutonomousVolitionCredential` is implemented with deterministic ID generation.
3. Credential signing and verification work using EXOCHAIN `Signature`, `PublicKey`, `Did`, `Timestamp`, and `Hash256` types.
4. Validation is fail-closed.
5. Delegation rejects scope widening.
6. Revocation prevents future validation.
7. Trust receipts are generated deterministically and signed.
8. `exo-node` exposes AVC API routes protected by bearer auth.
9. API tests cover issue/register, validate, delegate/register, revoke, get, and list flows.
10. `exochain-sdk` exports AVC primitives.
11. Documentation exists under `docs/avc/README.md`.
12. No floating-point arithmetic is introduced.
13. No `HashMap` or `HashSet` is used in production AVC code.
14. Workspace formatting, linting, and tests pass.
15. README or traceability docs do not claim production-grade decentralized adoption.

---

## 20. Implementation Plan for Codex

Execute in this order.

### Step 1: Inspect existing types

Inspect these crates before coding:

```text
crates/exo-core
crates/exo-authority
crates/exo-consent
crates/exo-node/src/passport.rs
crates/exochain-sdk
```

Reuse existing types and naming conventions wherever possible.

### Step 2: Create `exo-avc`

Add crate files, module skeleton, errors, and core structs.

### Step 3: Implement canonical signing payloads

Implement deterministic CBOR encoding for:

- credential
- revocation
- receipt

Add domain tags and schema versions.

### Step 4: Implement issue / validate / delegate / revoke / receipt

Implement public API functions and in-memory registry.

### Step 5: Add unit tests

Start with deterministic ID and signature tests. Then validation and delegation tests.

### Step 6: Add `exo-node` API module

Add `crates/exo-node/src/avc.rs`, state, routes, handlers, and tests.

### Step 7: Wire routes

Register AVC router wherever passport routes are currently merged.

### Step 8: Export SDK symbols

Update `crates/exochain-sdk`.

### Step 9: Add docs

Add `docs/avc/README.md` and update README lightly.

### Step 10: Run gates and fix warnings

Run workspace checks and fix all clippy/fmt/test failures.

---

## 21. Suggested PR Title

```text
feat(avc): add Autonomous Volition Credential primitive for agent intent authority
```

---

## 22. Suggested PR Description

```markdown
## Summary

Adds AVC — Autonomous Volition Credential — as a first-class Rust primitive for credentialing autonomous intent, authority, constraints, delegation, revocation, and validation receipts.

## What changed

- Added `crates/exo-avc`
- Implemented deterministic AVC IDs via canonical CBOR + `Hash256`
- Implemented signed credential issuance and validation
- Implemented delegation with strict scope narrowing
- Implemented revocation and trust receipts
- Added node API routes for AVC registration, validation, delegation, revocation, lookup, and agent listing
- Exported AVC types through `exochain-sdk`
- Added AVC docs and tests

## Why

EXOCHAIN already has identity, authority, consent, passport, governance, and receipt primitives. AVC unifies those into a portable trust object that autonomous actors can present and verifiers can evaluate before agent action.

## Safety

- Fail-closed validation
- Domain-separated signatures
- No floats
- No PII on ledger
- Scope narrowing enforced for delegation
- Revocation checked during validation

## Test plan

- `cargo build --workspace --all-targets`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo +nightly fmt --all -- --check`
- `cargo deny check`
```

---

## 23. Example AVC JSON Shape

This is illustrative. Exact serialization should follow the Rust model.

```json
{
  "schema_version": 1,
  "issuer_did": "did:exo:issuer",
  "principal_did": "did:exo:principal",
  "subject_did": "did:exo:agent-alpha",
  "holder_did": "did:exo:agent-alpha",
  "subject_kind": {
    "AiAgent": {
      "model_id": "agent-alpha-v1",
      "agent_version": "1.0.0"
    }
  },
  "created_at": { "millis": 1770000000000, "counter": 0 },
  "expires_at": { "millis": 1770086400000, "counter": 0 },
  "delegated_intent": {
    "intent_id": "blake3-hash",
    "purpose": "Research approved counterparties and prepare recommendations",
    "allowed_objectives": ["vendor_research", "risk_summary", "draft_recommendation"],
    "prohibited_objectives": ["execute_payment", "sign_contract", "share_personal_data"],
    "autonomy_level": "Draft",
    "delegation_allowed": false
  },
  "authority_scope": {
    "permissions": ["Read"],
    "tools": ["vendor.search", "crm.read"],
    "data_classes": ["Public", "Internal"],
    "counterparties": [],
    "jurisdictions": ["US"]
  },
  "constraints": {
    "max_budget_minor_units": null,
    "currency_code": null,
    "max_action_risk_bp": 2000,
    "human_approval_required": false,
    "approval_threshold_bp": 5000,
    "max_delegation_depth": 0,
    "allowed_time_window": null,
    "forbidden_actions": ["payment.execute", "contract.sign"],
    "emergency_stop_refs": []
  },
  "authority_chain": null,
  "consent_refs": [],
  "policy_refs": [],
  "parent_avc_id": null,
  "signature": "..."
}
```

---

## 24. Conceptual Handshake

```text
Agent A wants to call Agent B.
Agent B requests AVC.
Agent A presents AVC.
Agent B validates:
  - issuer signature
  - principal / subject binding
  - delegated intent
  - authority scope
  - revocation state
  - expiry
  - consent refs
  - action fit
EXOCHAIN returns decision + trust receipt.
Agent B proceeds only if decision is Allow.
```

---

## 25. Final Product Promise

After this PR, EXOCHAIN should be able to say:

> EXOCHAIN now supports Autonomous Volition Credentials: portable, verifiable credentials that define what autonomous actors are authorized to pursue before they act.

Do not claim broad network adoption yet. This PR creates the primitive and control-plane/API surface needed for adoption to begin.
