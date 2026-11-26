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

//! GraphQL schema, resolvers, and axum HTTP handler for the ExoChain governance API.
//!
//! The schema is backed by an `AppState` held behind a Tokio reader/writer lock.
//! Production deployments replace the in-memory collections with a database pool
//! injected via `GatewayConfig::database_pool_url`.
//!
//! ## Schema surface
//!
//! | Operation        | Count |
//! |-----------------|-------|
//! | Queries          | 9     |
//! | Mutations        | 9     |
//! | Subscriptions    | 3     |
//!
//! Queries include two end-to-end constitutional resolvers:
//! - `resolveIdentity(did)` — looks up a DID document from the shared `LocalDidRegistry`
//! - `evaluateConsent(subject, actor, scope, actionType)` — runs the `PolicyEngine`
//!
//! Subscriptions use `tokio::sync::broadcast` for real-time event delivery.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex as StdMutex, RwLock},
};

use async_graphql::{
    Context, ID, InputObject, Object, Result as GqlResult, Schema, SimpleObject, Subscription,
    futures_util::Stream,
};
#[cfg(feature = "unaudited-gateway-graphql-api")]
use async_graphql_axum::GraphQLSubscription;
use async_stream::stream;
use axum::Router;
#[cfg(feature = "unaudited-gateway-graphql-api")]
use axum::response::IntoResponse;
#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
use axum::routing::get;
#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
use axum::{Json, http::StatusCode};
use exo_consent::policy::{
    ActionRequest as ConsentActionRequest, ConsentDecision, ConsentPolicy, ConsentRequirement,
    PolicyEngine,
};
use exo_core::{Did, Hash256, Timestamp, hash::hash_structured, hlc::HybridClock};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest as GkActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{
        AuthorityChain, BailmentState, ConsentRecord, Permission, PermissionSet, Provenance, Role,
        TrustedAuthorityKeys, TrustedProvenanceKeys,
    },
};
// Only the `unaudited-gateway-graphql-api` mutation-adjudication tests use these
// (they build genuinely-signed authority/provenance fixtures); gating to that
// feature keeps the default-feature test build free of unused imports.
#[cfg(all(test, feature = "unaudited-gateway-graphql-api"))]
use exo_gatekeeper::{
    invariants::{authority_link_signature_message, provenance_signature_message},
    types::{AuthorityLink, GovernmentBranch},
};
use exo_identity::registry::{DidRegistry, LocalDidRegistry};
use serde::Serialize;
use tokio::sync::{RwLock as AsyncRwLock, broadcast};

use crate::auth::AuthenticatedActor;

// ---------------------------------------------------------------------------
// GraphQL output types
// ---------------------------------------------------------------------------

/// A single vote cast on a decision.
#[derive(Debug, Clone, Serialize, SimpleObject)]
pub struct GqlVote {
    pub voter: String,
    pub choice: String,
    pub rationale: Option<String>,
    pub timestamp: String,
}

/// A challenge raised against a decision.
#[derive(Debug, Clone, Serialize, SimpleObject)]
pub struct GqlChallenge {
    pub id: ID,
    pub grounds: String,
    pub status: String,
}

/// A governance decision.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlDecision {
    pub id: ID,
    pub tenant_id: String,
    pub status: String,
    pub title: String,
    pub decision_class: String,
    pub author: String,
    pub created_at: String,
    pub votes: Vec<GqlVote>,
    pub challenges: Vec<GqlChallenge>,
    /// Blake3 content hash over the decision state (for audit provenance).
    pub content_hash: String,
}

/// An authority delegation record.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlDelegation {
    pub id: ID,
    pub delegator: String,
    pub delegatee: String,
    pub scope: String,
    pub expires_at: String,
    pub active: bool,
}

/// A tenant constitutional corpus snapshot.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlConstitution {
    pub tenant_id: String,
    pub version: String,
    pub hash: String,
}

/// An emergency action record.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlEmergencyAction {
    pub id: ID,
    pub decision_id: String,
    pub ratification_deadline: String,
    pub justification: String,
    pub tenant_id: String,
}

/// A conflict-of-interest disclosure.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlConflictDisclosure {
    pub discloser: String,
    pub description: String,
    pub nature: String,
    pub timestamp: String,
}

/// The delegated authority chain for an actor.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlAuthorityChain {
    pub actor_did: String,
    pub chain_length: i32,
    pub valid: bool,
}

/// A single entry in the append-only audit log.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlAuditEntry {
    pub sequence: i32,
    pub event_type: String,
    pub actor: String,
    pub timestamp: String,
    /// Blake3 hash of the entry content (chained with previous entry hash).
    pub receipt_hash: String,
}

/// Result of verifying a proof.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlVerificationResult {
    pub proof_type: String,
    pub valid: bool,
    pub message: String,
}

/// A resolved DID identity document.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlIdentity {
    /// The DID string (e.g. `did:exo:alice`).
    pub did: String,
    /// Whether the DID is registered and not revoked.
    pub registered: bool,
    /// Number of active verification methods.
    pub active_key_count: i32,
    /// Number of active service endpoints.
    pub service_endpoint_count: i32,
}

/// Result of a consent policy evaluation.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlConsentResult {
    /// The subject DID whose data is being accessed.
    pub subject: String,
    /// The actor DID requesting access.
    pub actor: String,
    /// The scope being requested (e.g. `"data:medical"`).
    pub scope: String,
    /// Whether consent was granted.
    pub granted: bool,
    /// Human-readable outcome message.
    pub message: String,
}

// ---------------------------------------------------------------------------
// GraphQL input types
// ---------------------------------------------------------------------------

/// Input for creating a new governance decision.
#[derive(Debug, InputObject)]
pub struct CreateDecisionInput {
    pub tenant_id: String,
    pub title: String,
    pub body: String,
    pub decision_class: String,
}

/// Input for granting a delegation.
#[derive(Debug, InputObject)]
pub struct GrantDelegationInput {
    pub delegatee_did: String,
    pub scope: String,
    pub expires_in_hours: i32,
}

// ---------------------------------------------------------------------------
// Broadcast events for subscriptions
// ---------------------------------------------------------------------------

/// Real-time governance events broadcast to subscribers.
#[derive(Clone, Debug)]
pub enum GovEvent {
    DecisionUpdated(GqlDecision),
    DelegationExpiring(GqlDelegation),
    EmergencyActionCreated(GqlEmergencyAction),
}

// ---------------------------------------------------------------------------
// In-memory application state
// ---------------------------------------------------------------------------

struct DecisionRecord {
    decision: GqlDecision,
    audit_trail: Vec<GqlAuditEntry>,
}

#[derive(Serialize)]
struct GraphqlAuditReceiptPayload<'a> {
    domain: &'static str,
    decision_id: &'a str,
    previous_receipt_hash: &'a str,
    event_type: &'a str,
    actor: &'a str,
    sequence: i32,
    timestamp: &'a str,
}

#[derive(Serialize)]
struct GraphqlDecisionHashPayload<'a> {
    domain: &'static str,
    decision_id: &'a str,
    tenant_id: &'a str,
    status: &'a str,
    title: &'a str,
    decision_class: &'a str,
    author: &'a str,
    created_at: &'a str,
    votes: &'a [GqlVote],
    challenges: &'a [GqlChallenge],
}

#[derive(Serialize)]
struct GraphqlDecisionIdPayload<'a> {
    domain: &'static str,
    tenant_id: &'a str,
    title: &'a str,
    body: &'a str,
    decision_class: &'a str,
    created_at: &'a Timestamp,
}

#[derive(Serialize)]
struct GraphqlContentHashPayload<'a> {
    domain: &'static str,
    body: &'a str,
}

#[derive(Serialize)]
struct GraphqlDelegationIdPayload<'a> {
    domain: &'static str,
    delegator: &'a str,
    delegatee: &'a str,
    scope: &'a str,
    created_at: &'a Timestamp,
    expires_in_hours: i32,
}

#[derive(Serialize)]
struct GraphqlChallengeIdPayload<'a> {
    domain: &'static str,
    decision_id: &'a str,
    grounds: &'a str,
    created_at: &'a Timestamp,
}

#[derive(Serialize)]
struct GraphqlEmergencyActionIdPayload<'a> {
    domain: &'static str,
    decision_id: &'a str,
    tenant_id: &'a str,
    justification: &'a str,
    created_at: &'a Timestamp,
}

#[derive(Serialize)]
struct GraphqlConstitutionHashPayload<'a> {
    domain: &'static str,
    previous_hash: &'a str,
    tenant_id: &'a str,
    previous_version: &'a str,
    amendment: &'a str,
}

fn graphql_hash_hex<T: Serialize>(payload: &T) -> GqlResult<String> {
    hash_structured(payload)
        .map(|hash| hash.to_string())
        .map_err(|e| async_graphql::Error::new(format!("GraphQL canonical hash failed: {e}")))
}

/// Shared application state.  Replace in-memory `BTreeMap`s with a sqlx
/// `PgPool` when `GatewayConfig::database_pool_url` is set.
pub struct AppState {
    decisions: BTreeMap<String, DecisionRecord>,
    decision_ids_by_tenant: BTreeMap<String, BTreeSet<String>>,
    decision_ids_by_tenant_status: BTreeMap<(String, String), BTreeSet<String>>,
    delegations: BTreeMap<String, GqlDelegation>,
    emergency_actions: BTreeMap<String, GqlEmergencyAction>,
    constitution: GqlConstitution,
    next_audit_seq: i32,
    clock: StdMutex<HybridClock>,
    event_tx: broadcast::Sender<GovEvent>,
    /// Shared DID registry — wired from `server::AppState` for identity resolution.
    registry: Arc<RwLock<LocalDidRegistry>>,
    /// Consent policy engine — evaluates `PolicyEngine` rules for consent checks.
    consent_engine: PolicyEngine,
    /// Real, cryptographically-verifiable per-actor constitutional grants
    /// (authority chain, bailment/consent, provenance, roles) consulted by
    /// [`AppState::actor_adjudication_context`] when adjudicating GraphQL
    /// mutations. Populated only via [`AppState::seed_actor_grant`] — never
    /// self-issued by a resolver or derived from an unauthenticated claim.
    /// An actor with no entry here is denied by default (see
    /// `graphql_deny_all_adjudication_context`).
    actor_grants: BTreeMap<Did, ActorGrant>,
}

/// Real constitutional grant state held for a single actor DID.
///
/// This is the GraphQL gateway's own record of authority genuinely delegated
/// to an actor — every field carries the same cryptographic material the
/// constitutional kernel independently verifies (`AuthorityChainValid`,
/// `ConsentRequired`, `ProvenanceVerifiable`). Nothing here is fabricated
/// from the request; it must be established ahead of time via
/// [`AppState::seed_actor_grant`] by a party that genuinely holds the
/// grantor's signing key.
#[derive(Clone)]
pub struct ActorGrant {
    pub roles: Vec<Role>,
    pub authority_chain: AuthorityChain,
    pub trusted_authority_keys: TrustedAuthorityKeys,
    pub bailment_state: BailmentState,
    pub consent_records: Vec<ConsentRecord>,
    pub provenance: Provenance,
    pub trusted_provenance_keys: TrustedProvenanceKeys,
    pub permissions: PermissionSet,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Create a new `AppState` with a default empty DID registry.
    pub fn new() -> Self {
        Self::with_registry(Arc::new(RwLock::new(LocalDidRegistry::new())))
    }

    /// Create a new `AppState` with the given shared DID registry.
    pub fn with_registry(registry: Arc<RwLock<LocalDidRegistry>>) -> Self {
        Self::with_registry_and_clock(registry, HybridClock::new())
    }

    /// Create a new `AppState` with the given shared DID registry and HLC.
    pub fn with_registry_and_clock(
        registry: Arc<RwLock<LocalDidRegistry>>,
        clock: HybridClock,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            decisions: BTreeMap::new(),
            decision_ids_by_tenant: BTreeMap::new(),
            decision_ids_by_tenant_status: BTreeMap::new(),
            delegations: BTreeMap::new(),
            emergency_actions: BTreeMap::new(),
            constitution: GqlConstitution {
                tenant_id: "default".into(),
                version: "1.0.0".into(),
                hash: Hash256::digest(b"constitution-v1").to_string(),
            },
            next_audit_seq: 1,
            clock: StdMutex::new(clock),
            event_tx,
            registry,
            consent_engine: PolicyEngine::new(),
            actor_grants: BTreeMap::new(),
        }
    }

    /// Create a new `AppState` wrapped in a reader/writer lock for concurrent access.
    pub fn new_arc() -> SharedGraphqlState {
        Arc::new(AsyncRwLock::new(Self::new()))
    }

    /// Create a new `AppState` with a shared registry, wrapped in a reader/writer lock.
    pub fn new_arc_with_registry(registry: Arc<RwLock<LocalDidRegistry>>) -> SharedGraphqlState {
        Arc::new(AsyncRwLock::new(Self::with_registry(registry)))
    }

    fn remove_decision_index(
        index: &mut BTreeMap<String, BTreeSet<String>>,
        key: &str,
        decision_id: &str,
    ) {
        let remove_key = index.get_mut(key).is_some_and(|ids| {
            ids.remove(decision_id);
            ids.is_empty()
        });
        if remove_key {
            index.remove(key);
        }
    }

    fn remove_decision_status_index(
        index: &mut BTreeMap<(String, String), BTreeSet<String>>,
        key: &(String, String),
        decision_id: &str,
    ) {
        let remove_key = index.get_mut(key).is_some_and(|ids| {
            ids.remove(decision_id);
            ids.is_empty()
        });
        if remove_key {
            index.remove(key);
        }
    }

    fn index_decision_id(&mut self, decision_id: &str) {
        if let Some(record) = self.decisions.get(decision_id) {
            self.decision_ids_by_tenant
                .entry(record.decision.tenant_id.clone())
                .or_default()
                .insert(decision_id.to_owned());
            self.decision_ids_by_tenant_status
                .entry((
                    record.decision.tenant_id.clone(),
                    record.decision.status.clone(),
                ))
                .or_default()
                .insert(decision_id.to_owned());
        }
    }

    fn remove_decision_from_indexes(&mut self, decision_id: &str, tenant_id: &str, status: &str) {
        Self::remove_decision_index(&mut self.decision_ids_by_tenant, tenant_id, decision_id);
        Self::remove_decision_status_index(
            &mut self.decision_ids_by_tenant_status,
            &(tenant_id.to_owned(), status.to_owned()),
            decision_id,
        );
    }

    fn insert_decision_record(&mut self, decision_id: String, record: DecisionRecord) {
        if let Some(existing) = self.decisions.get(&decision_id) {
            let previous_tenant_id = existing.decision.tenant_id.clone();
            let previous_status = existing.decision.status.clone();
            self.remove_decision_from_indexes(&decision_id, &previous_tenant_id, &previous_status);
        }
        self.decisions.insert(decision_id.clone(), record);
        self.index_decision_id(&decision_id);
    }

    fn reindex_decision_after_state_change(
        &mut self,
        decision_id: &str,
        previous_tenant_id: String,
        previous_status: String,
    ) {
        self.remove_decision_from_indexes(decision_id, &previous_tenant_id, &previous_status);
        self.index_decision_id(decision_id);
    }

    fn decision_ids_for_query(
        &self,
        tenant_id: &str,
        status: Option<&str>,
    ) -> Option<&BTreeSet<String>> {
        status.map_or_else(
            || self.decision_ids_by_tenant.get(tenant_id),
            |status| {
                self.decision_ids_by_tenant_status
                    .get(&(tenant_id.to_owned(), status.to_owned()))
            },
        )
    }

    /// Record a genuine constitutional grant for `actor`: a real Ed25519
    /// authority-chain link, an active bailment + matching consent record,
    /// and verifiable provenance — the same shape the constitutional kernel
    /// independently verifies via [`InvariantSet::all`].
    ///
    /// This is **not** a GraphQL mutation and is never reachable from an
    /// unauthenticated or self-serving request path: it exists for callers
    /// that already hold (or, in tests, construct) a real grantor signing
    /// key, exactly mirroring
    /// `exo_gatekeeper::kernel::tests::valid_context`. Registering a grant
    /// here is how an actor comes to be genuinely authorized — resolvers
    /// never fabricate this state, they only ever read it back through this
    /// `AppState`'s internal adjudication-context resolution.
    pub fn seed_actor_grant(&mut self, actor: Did, grant: ActorGrant) {
        self.actor_grants.insert(actor, grant);
    }

    /// Resolve the real per-actor [`AdjudicationContext`] for `actor` from
    /// genuinely recorded grant state.
    ///
    /// An actor with no recorded grant falls back to
    /// [`graphql_deny_all_adjudication_context`] — deny-by-default is the
    /// property of the actor's real (absent) state, not an artifact of a
    /// kernel that refuses everyone unconditionally (see
    /// `graphql_mutation_denied_for_unauthorized_actor`).
    fn actor_adjudication_context(&self, actor: &Did) -> AdjudicationContext {
        match self.actor_grants.get(actor) {
            Some(grant) => AdjudicationContext {
                actor_roles: grant.roles.clone(),
                authority_chain: grant.authority_chain.clone(),
                consent_records: grant.consent_records.clone(),
                bailment_state: grant.bailment_state.clone(),
                human_override_preserved: true,
                actor_permissions: grant.permissions.clone(),
                trusted_authority_keys: grant.trusted_authority_keys.clone(),
                trusted_provenance_keys: grant.trusted_provenance_keys.clone(),
                provenance: Some(grant.provenance.clone()),
                quorum_evidence: None,
                active_challenge_reason: None,
            },
            None => graphql_deny_all_adjudication_context(),
        }
    }

    /// Adjudicate `action` for `actor` through the shared constitutional
    /// kernel, using this `AppState`'s real per-actor grant state. Returns
    /// the kernel [`Verdict`] — callers must gate mutation on
    /// `Verdict::Permitted` and must never treat `require_authenticated_actor`
    /// succeeding as authorization by itself.
    fn adjudicate_mutation(&self, actor: &Did, action_name: &str, scope: &str) -> Verdict {
        let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
        let action = GkActionRequest {
            actor: actor.clone(),
            action: format!("graphql.{action_name}"),
            required_permissions: PermissionSet::new(vec![Permission::new(scope)]),
            is_self_grant: false,
            modifies_kernel: false,
        };
        let context = self.actor_adjudication_context(actor);
        kernel.adjudicate(&action, &context)
    }

    fn next_timestamp(&self) -> GqlResult<Timestamp> {
        let mut clock = self
            .clock
            .lock()
            .map_err(|_| async_graphql::Error::new("GraphQL HLC mutex poisoned"))?;
        clock
            .now()
            .map_err(|err| async_graphql::Error::new(format!("HLC clock exhausted: {err}")))
    }

    fn now_str(&self) -> GqlResult<String> {
        Ok(self.next_timestamp()?.to_string())
    }

    fn append_audit(&mut self, decision_id: &str, event_type: &str, actor: &str) -> GqlResult<()> {
        if !self.decisions.contains_key(decision_id) {
            return Err(async_graphql::Error::new(format!(
                "decision {decision_id} not found"
            )));
        }

        let seq = self.next_audit_seq;
        let next_seq = seq
            .checked_add(1)
            .ok_or_else(|| async_graphql::Error::new("audit sequence exhausted"))?;
        let ts = self.now_str()?;

        if let Some(rec) = self.decisions.get_mut(decision_id) {
            self.next_audit_seq = next_seq;
            let prev_hash = rec
                .audit_trail
                .last()
                .map(|e| e.receipt_hash.clone())
                .unwrap_or_else(|| Hash256::ZERO.to_string());
            let receipt_hash = graphql_hash_hex(&GraphqlAuditReceiptPayload {
                domain: "exo.gateway.graphql.audit_receipt.v1",
                decision_id,
                previous_receipt_hash: &prev_hash,
                event_type,
                actor,
                sequence: seq,
                timestamp: &ts,
            })?;
            rec.audit_trail.push(GqlAuditEntry {
                sequence: seq,
                event_type: event_type.into(),
                actor: actor.into(),
                timestamp: ts,
                receipt_hash,
            });
        }
        Ok(())
    }

    fn compute_decision_hash(d: &GqlDecision) -> GqlResult<String> {
        let id = d.id.to_string();
        graphql_hash_hex(&GraphqlDecisionHashPayload {
            domain: "exo.gateway.graphql.decision_state.v1",
            decision_id: &id,
            tenant_id: &d.tenant_id,
            status: &d.status,
            title: &d.title,
            decision_class: &d.decision_class,
            author: &d.author,
            created_at: &d.created_at,
            votes: &d.votes,
            challenges: &d.challenges,
        })
    }
}

#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
fn graphql_execution_disabled_error() -> async_graphql::Error {
    async_graphql::Error::new(format!(
        "unaudited_graphql_api_disabled: GraphQL resolver execution is disabled by default; enable `{UNAUDITED_GRAPHQL_API_FEATURE}` only for audited development use. See {UNAUDITED_GRAPHQL_API_INITIATIVE} and {UNAUDITED_GRAPHQL_API_MEMO}."
    ))
}

fn guard_graphql_execution() -> GqlResult<()> {
    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    {
        Err(graphql_execution_disabled_error())
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    {
        Ok(())
    }
}

fn graphql_mutation_execution_disabled_error() -> async_graphql::Error {
    async_graphql::Error::new(format!(
        "unaudited_graphql_mutations_disabled: GraphQL mutations require a verified authenticated actor and constitutional adjudication context before writes are enabled. See {UNAUDITED_GRAPHQL_API_INITIATIVE} and {UNAUDITED_GRAPHQL_API_MEMO}."
    ))
}

/// Feature-gate check shared by every GraphQL mutation resolver. Mutations
/// remain refused by default via [`guard_graphql_execution`]; when the
/// `unaudited-gateway-graphql-api` feature is enabled, resolvers additionally
/// require a per-request [`AuthenticatedActor`] genuinely authorized by the
/// constitutional kernel via [`require_permitted_actor`] — authentication
/// alone is never sufficient (VCG-003).
fn guard_graphql_mutation_execution() -> GqlResult<()> {
    guard_graphql_execution()
}

/// Typed refusal for a mutation that reached the actor-context check with no
/// [`AuthenticatedActor`] present in the per-request GraphQL context. Distinct
/// from — but still contains — the blanket
/// `unaudited_graphql_mutations_disabled` refusal so both the legacy
/// blanket-disable contract and the new per-request actor-context contract
/// hold simultaneously: mutations remain refused with no verified authz
/// context, and the refusal now names the specific missing precondition.
fn graphql_missing_authenticated_actor_error() -> async_graphql::Error {
    async_graphql::Error::new(format!(
        "missing_authenticated_actor: {} ",
        graphql_mutation_execution_disabled_error().message
    ))
}

/// Read the per-request [`AuthenticatedActor`] injected into the GraphQL
/// context by the gateway's actor-context middleware (see `server.rs`).
///
/// # Errors
///
/// Returns a typed `missing_authenticated_actor` error when no authenticated
/// actor is present — this is the *only* source of caller identity for
/// mutation resolvers; there is no hardcoded fallback.
fn require_authenticated_actor<'ctx>(
    ctx: &'ctx Context<'_>,
) -> GqlResult<&'ctx AuthenticatedActor> {
    ctx.data::<AuthenticatedActor>()
        .map_err(|_| graphql_missing_authenticated_actor_error())
}

/// Typed refusal for a mutation whose actor was authenticated but denied (or
/// escalated) by the constitutional kernel. Distinct from
/// [`graphql_missing_authenticated_actor_error`]: this fires only once an
/// [`AuthenticatedActor`] is present but does not hold the authority,
/// consent, or provenance state required for the requested action —
/// authentication is never conflated with authorization.
fn graphql_verdict_denied_error(action_name: &str, verdict: &Verdict) -> async_graphql::Error {
    match verdict {
        Verdict::Permitted => unreachable!("graphql_verdict_denied_error called with Permitted"),
        Verdict::Denied { violations } => async_graphql::Error::new(format!(
            "adjudication_denied: constitutional kernel denied '{action_name}': {violations:?}"
        )),
        Verdict::Escalated { reason } => async_graphql::Error::new(format!(
            "adjudication_escalated: constitutional kernel escalated '{action_name}' for review: {reason}"
        )),
    }
}

/// Require that `ctx` carries an [`AuthenticatedActor`] genuinely authorized
/// by the constitutional kernel to perform `action_name` under `scope`.
///
/// This is the single mutation gate: [`guard_graphql_mutation_execution`]
/// (feature-off refusal) must already have been checked by the caller.
/// Returns the actor's DID (as an owned `String`, since callers hold the
/// `AppState` lock across `.await` points that outlive `ctx`'s borrow) only
/// when the kernel's `Verdict` is `Permitted` — an authenticated-but-
/// unauthorized actor is refused with [`graphql_verdict_denied_error`] and no
/// mutation proceeds.
async fn require_permitted_actor(
    ctx: &Context<'_>,
    action_name: &str,
    scope: &str,
) -> GqlResult<String> {
    let actor = require_authenticated_actor(ctx)?;
    let did = actor.did.clone();
    let state = app_state_from_context(ctx)?;
    let verdict = {
        let guard = state.read().await;
        guard.adjudicate_mutation(&did, action_name, scope)
    };
    match verdict {
        Verdict::Permitted => Ok(did.as_str().to_owned()),
        denied => Err(graphql_verdict_denied_error(action_name, &denied)),
    }
}

fn app_state_from_context<'ctx>(ctx: &'ctx Context<'_>) -> GqlResult<&'ctx SharedGraphqlState> {
    ctx.data::<SharedGraphqlState>()
}

fn graphql_nonnegative_i32_to_usize(value: i32, field: &'static str) -> GqlResult<usize> {
    usize::try_from(value)
        .map_err(|_| async_graphql::Error::new(format!("{field} cannot be represented as usize")))
}

fn graphql_count_to_i32(count: usize, field: &'static str) -> GqlResult<i32> {
    i32::try_from(count)
        .map_err(|_| async_graphql::Error::new(format!("{field} exceeds GraphQL i32 range")))
}

/// Deny-by-default adjudication context for GraphQL-originated kernel checks.
///
/// Mirrors `server::deny_all_adjudication_context` (see `server.rs:812-852`,
/// WO-009 SAFETY NOTE — CR-001 §8.9 No-Admin Preservation): `BailmentState::None`
/// fails the `ConsentRequired` invariant and `AuthorityChain::default()` fails
/// `AuthorityChainValid`, both intentionally. The GraphQL gateway module has no
/// DB-backed adjudication state of its own, so this scaffold is always the
/// active path here — it must never be short-circuited to an allow.
fn graphql_deny_all_adjudication_context() -> AdjudicationContext {
    AdjudicationContext {
        actor_roles: vec![],
        authority_chain: AuthorityChain::default(),
        consent_records: vec![],
        bailment_state: BailmentState::None,
        human_override_preserved: true,
        actor_permissions: PermissionSet::default(),
        trusted_authority_keys: TrustedAuthorityKeys::default(),
        trusted_provenance_keys: TrustedProvenanceKeys::default(),
        provenance: None,
        quorum_evidence: None,
        active_challenge_reason: None,
    }
}

/// Adjudicate a GraphQL `evaluateConsent` query through the same constitutional
/// kernel used by REST governance routes, following the
/// `AppState::build_adjudication_context` pattern (`server.rs:812-852`). The
/// GraphQL gateway module holds no DB pool, so there is no DB-backed
/// adjudication state to resolve from; the deny-by-default scaffold is the
/// only path and every request is denied unless a future DB-backed resolver
/// is wired in, exactly as the REST path falls back when its DB query fails
/// or is unavailable.
fn graphql_evaluate_consent_verdict(subject_actor: &Did, action_type: &str) -> Verdict {
    let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
    let action = GkActionRequest {
        actor: subject_actor.clone(),
        action: format!("graphql.evaluate_consent:{action_type}"),
        required_permissions: PermissionSet::new(vec![Permission::new("consent:evaluate")]),
        is_self_grant: false,
        modifies_kernel: false,
    };
    let context = graphql_deny_all_adjudication_context();
    kernel.adjudicate(&action, &context)
}

// ---------------------------------------------------------------------------
// Schema type alias
// ---------------------------------------------------------------------------

/// Fully-built GraphQL schema type with query, mutation, and subscription roots.
pub type GovSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

pub const UNAUDITED_GRAPHQL_API_FEATURE: &str = "unaudited-gateway-graphql-api";
pub const UNAUDITED_GRAPHQL_API_INITIATIVE: &str = "Initiatives/fix-spline-r1-graphql-auth-gate.md";
pub const UNAUDITED_GRAPHQL_API_MEMO: &str =
    "exochain/council-intake/exo-spline-gateway-api-messaging.md";
pub const GRAPHQL_MAX_QUERY_DEPTH: usize = 12;
pub const GRAPHQL_MAX_QUERY_COMPLEXITY: usize = 256;
pub const GRAPHQL_MAX_DECISIONS_LIMIT: i32 = 200;
pub const GRAPHQL_MAX_DECISIONS_OFFSET: i32 = 10_000;
pub type SharedGraphqlState = Arc<AsyncRwLock<AppState>>;
pub const GRAPHQL_CONSENT_FABRICATION_INITIATIVE: &str =
    "Initiatives/fix-spline-r2-graphql-consent-fabrication.md";
pub const GRAPHQL_PROOF_STUB_INITIATIVE: &str = "Initiatives/fix-spline-r3-graphql-proof-stub.md";

// ---------------------------------------------------------------------------
// Query resolvers
// ---------------------------------------------------------------------------

/// GraphQL query root — governance decisions, delegations, identity, and consent.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Fetch a single decision by ID.
    async fn decision(&self, ctx: &Context<'_>, id: ID) -> GqlResult<Option<GqlDecision>> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        Ok(guard.decisions.get(id.as_str()).map(|r| r.decision.clone()))
    }

    /// List decisions for a tenant with optional status filter and pagination.
    async fn decisions(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        status: Option<String>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> GqlResult<Vec<GqlDecision>> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        let offset = graphql_nonnegative_i32_to_usize(
            offset.unwrap_or(0).clamp(0, GRAPHQL_MAX_DECISIONS_OFFSET),
            "decisions.offset",
        )?;
        let limit = graphql_nonnegative_i32_to_usize(
            limit.unwrap_or(50).clamp(1, GRAPHQL_MAX_DECISIONS_LIMIT),
            "decisions.limit",
        )?;
        let results: Vec<GqlDecision> = guard
            .decision_ids_for_query(tenant_id.as_str(), status.as_deref())
            .into_iter()
            .flat_map(|ids| ids.iter())
            .skip(offset)
            .take(limit)
            .filter_map(|id| guard.decisions.get(id))
            .map(|record| record.decision.clone())
            .collect();
        Ok(results)
    }

    /// Get the delegated authority chain for an actor DID.
    async fn authority_chain(
        &self,
        ctx: &Context<'_>,
        actor_did: String,
    ) -> GqlResult<GqlAuthorityChain> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        let chain_length = graphql_count_to_i32(
            guard
                .delegations
                .values()
                .filter(|d| d.delegatee == actor_did && d.active)
                .count(),
            "authority_chain.chain_length",
        )?;
        Ok(GqlAuthorityChain {
            actor_did,
            chain_length,
            valid: chain_length > 0,
        })
    }

    /// Get the constitutional corpus for a tenant at an optional version.
    async fn constitution(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        #[graphql(default)] version: Option<String>,
    ) -> GqlResult<GqlConstitution> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        let _ = version; // version pinning reserved for DB layer
        if guard.constitution.tenant_id == tenant_id.as_str() {
            Ok(guard.constitution.clone())
        } else {
            Err(async_graphql::Error::new(format!(
                "constitution for tenant {} not found",
                tenant_id.as_str()
            )))
        }
    }

    /// List all active delegations for an actor DID.
    async fn delegations(
        &self,
        ctx: &Context<'_>,
        actor_did: String,
    ) -> GqlResult<Vec<GqlDelegation>> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        let results = guard
            .delegations
            .values()
            .filter(|d| d.delegatee == actor_did || d.delegator == actor_did)
            .cloned()
            .collect();
        Ok(results)
    }

    /// Retrieve the append-only audit trail for a decision.
    async fn audit_trail(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
    ) -> GqlResult<Vec<GqlAuditEntry>> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        let decision_id = decision_id.to_string();
        let record = guard.decisions.get(&decision_id).ok_or_else(|| {
            async_graphql::Error::new(format!("decision {decision_id} not found"))
        })?;
        Ok(record.audit_trail.clone())
    }

    /// Verify a cryptographic proof by ID.
    async fn verify_proof(
        &self,
        _ctx: &Context<'_>,
        proof_id: ID,
    ) -> GqlResult<GqlVerificationResult> {
        guard_graphql_execution()?;
        Ok(GqlVerificationResult {
            proof_type: "Unavailable".into(),
            valid: false,
            message: format!(
                "Proof verification refused: gateway GraphQL proof storage and verification are not wired for proof ID '{}'; see {}",
                proof_id.as_str(),
                GRAPHQL_PROOF_STUB_INITIATIVE
            ),
        })
    }

    /// Resolve a DID identity from the shared `LocalDidRegistry`.
    ///
    /// Returns the registration status and key counts for the given DID.
    /// Wired end-to-end to `exo-identity::LocalDidRegistry` (APE-35 acceptance criterion).
    async fn resolve_identity(&self, ctx: &Context<'_>, did: ID) -> GqlResult<GqlIdentity> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let registry = {
            let guard = state.read().await;
            Arc::clone(&guard.registry)
        };
        let did_str = did.to_string();
        let did_key = Did::new(&did_str)
            .map_err(|e| async_graphql::Error::new(format!("invalid DID: {e}")))?;

        tokio::task::spawn_blocking(move || -> GqlResult<GqlIdentity> {
            let registry = registry.read().unwrap_or_else(|e| e.into_inner());
            match registry.resolve(&did_key) {
                Some(doc) => {
                    let active_key_count = graphql_count_to_i32(
                        doc.verification_methods
                            .iter()
                            .filter(|vm| vm.active)
                            .count(),
                        "resolve_identity.active_key_count",
                    )?;
                    let service_endpoint_count = graphql_count_to_i32(
                        doc.service_endpoints.len(),
                        "resolve_identity.service_endpoint_count",
                    )?;
                    Ok(GqlIdentity {
                        did: did_str,
                        registered: true,
                        active_key_count,
                        service_endpoint_count,
                    })
                }
                None => Ok(GqlIdentity {
                    did: did_str,
                    registered: false,
                    active_key_count: 0,
                    service_endpoint_count: 0,
                }),
            }
        })
        .await
        .map_err(|e| async_graphql::Error::new(format!("registry lookup task failed: {e}")))?
    }

    /// Evaluate whether an actor has active consent from a subject for a given
    /// scope and action type.
    ///
    /// Uses `exo-consent::PolicyEngine` with a minimal deny-by-default policy.
    /// Wired end-to-end to constitutional consent enforcement (APE-35 acceptance
    /// criterion).
    async fn evaluate_consent(
        &self,
        ctx: &Context<'_>,
        subject: ID,
        actor: ID,
        scope: String,
        action_type: String,
    ) -> GqlResult<GqlConsentResult> {
        guard_graphql_execution()?;
        let state = app_state_from_context(ctx)?;
        let guard = state.read().await;
        let subject_str = subject.to_string();
        let actor_str = actor.to_string();
        Did::new(&subject_str)
            .map_err(|e| async_graphql::Error::new(format!("invalid subject DID: {e}")))?;
        let actor_did = Did::new(&actor_str)
            .map_err(|e| async_graphql::Error::new(format!("invalid actor DID: {e}")))?;

        // Build a policy requiring `action_type` for this scope.
        let policy = ConsentPolicy {
            id: format!("gql-eval-{scope}"),
            name: format!("GraphQL consent check for {scope}"),
            required_consents: vec![ConsentRequirement {
                action_type: action_type.clone(),
                required_role: "any".into(),
                min_clearance_level: 0,
            }],
            deny_by_default: true,
        };

        let action = ConsentActionRequest {
            actor: actor_did.clone(),
            action_type: action_type.clone(),
        };
        let decision = guard
            .consent_engine
            .evaluate(&policy, &[], &action, &Timestamp::ZERO);
        // Route through the same constitutional kernel adjudication path used by
        // REST governance routes (`AppState::build_adjudication_context`,
        // `server.rs:812-852`). The GraphQL module has no DB-backed adjudication
        // state, so this always resolves through the deny-by-default scaffold —
        // `evaluateConsent` can never report `granted: true` without it.
        let kernel_verdict = graphql_evaluate_consent_verdict(&actor_did, &action_type);
        let (granted, message) = match (decision, kernel_verdict) {
            (ConsentDecision::Granted { .. }, Verdict::Permitted) => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
                ),
            ),
            (ConsentDecision::Denied { reason }, _) => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; policy reason: {reason}; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
                ),
            ),
            (ConsentDecision::Escalated { to }, _) => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; policy escalated to {to}; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
                ),
            ),
            (
                ConsentDecision::Granted { .. },
                Verdict::Denied { .. } | Verdict::Escalated { .. },
            ) => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; kernel adjudication denied the request under the deny-by-default adjudication scaffold; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
                ),
            ),
        };
        Ok(GqlConsentResult {
            subject: subject_str,
            actor: actor_str,
            scope,
            granted,
            message,
        })
    }
}

// ---------------------------------------------------------------------------
// Mutation resolvers
// ---------------------------------------------------------------------------

/// GraphQL mutation root — decision lifecycle, voting, delegations, and emergency actions.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Create a new governance decision in CREATED status.
    async fn create_decision(
        &self,
        ctx: &Context<'_>,
        input: CreateDecisionInput,
    ) -> GqlResult<GqlDecision> {
        guard_graphql_mutation_execution()?;
        let author = require_permitted_actor(ctx, "create_decision", "governance:mutate").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let created = guard.next_timestamp()?;
        let created_at = created.to_string();
        let id = graphql_hash_hex(&GraphqlDecisionIdPayload {
            domain: "exo.gateway.graphql.decision_id.v1",
            tenant_id: &input.tenant_id,
            title: &input.title,
            body: &input.body,
            decision_class: &input.decision_class,
            created_at: &created,
        })?;
        let body_hash = graphql_hash_hex(&GraphqlContentHashPayload {
            domain: "exo.gateway.graphql.decision_body.v1",
            body: &input.body,
        })?;
        let decision = GqlDecision {
            id: ID::from(id.clone()),
            tenant_id: input.tenant_id,
            status: "CREATED".into(),
            title: input.title,
            decision_class: input.decision_class,
            author: author.clone(),
            created_at,
            votes: Vec::new(),
            challenges: Vec::new(),
            content_hash: body_hash,
        };
        if guard
            .event_tx
            .send(GovEvent::DecisionUpdated(decision.clone()))
            .is_err()
        {
            tracing::warn!("Governance event channel closed — DecisionUpdated dropped");
        }
        guard.insert_decision_record(
            id.clone(),
            DecisionRecord {
                decision: decision.clone(),
                audit_trail: Vec::new(),
            },
        );
        guard.append_audit(&id, "DecisionCreated", &author)?;
        Ok(decision)
    }

    /// Advance a decision to a new status.
    async fn advance_decision(
        &self,
        ctx: &Context<'_>,
        id: ID,
        new_status: String,
        reason: Option<String>,
    ) -> GqlResult<GqlDecision> {
        guard_graphql_mutation_execution()?;
        let actor_did =
            require_permitted_actor(ctx, "advance_decision", "governance:mutate").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let id_str = id.to_string();
        let (previous_tenant_id, previous_status, decision) = {
            let rec = guard
                .decisions
                .get_mut(&id_str)
                .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
            let previous_tenant_id = rec.decision.tenant_id.clone();
            let previous_status = rec.decision.status.clone();
            rec.decision.status = new_status.clone();
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision)?;
            (previous_tenant_id, previous_status, rec.decision.clone())
        };
        guard.reindex_decision_after_state_change(&id_str, previous_tenant_id, previous_status);
        // `reason` is a human-supplied, caller-controlled annotation only; it
        // must never be bound as the acting identity. The audit actor is
        // always the checked `AuthenticatedActor`'s DID (VCG-003 corrective —
        // adversarial review found `reason.as_deref().unwrap_or("system")`
        // spoofing the audit actor with caller-controlled input). `reason` is
        // accepted as an input parameter but, matching this resolver's
        // pre-existing audit-event text at base, does not itself appear in
        // the audit trail.
        let _ = reason;
        guard.append_audit(&id_str, &format!("StatusAdvanced:{new_status}"), &actor_did)?;
        if guard
            .event_tx
            .send(GovEvent::DecisionUpdated(decision.clone()))
            .is_err()
        {
            tracing::warn!("Governance event channel closed — DecisionUpdated dropped");
        }
        Ok(decision)
    }

    /// Cast a vote on a decision. Enforces duplicate-vote prevention.
    async fn cast_vote(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
        choice: String,
        rationale: Option<String>,
    ) -> GqlResult<GqlVote> {
        guard_graphql_mutation_execution()?;
        let voter = require_permitted_actor(ctx, "cast_vote", "governance:mutate").await?;
        let valid_choices = ["APPROVE", "REJECT", "ABSTAIN"];
        if !valid_choices.contains(&choice.as_str()) {
            return Err(async_graphql::Error::new(format!(
                "invalid choice '{choice}'; must be one of APPROVE, REJECT, ABSTAIN"
            )));
        }
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let id_str = decision_id.to_string();
        let duplicate_vote = guard
            .decisions
            .get(&id_str)
            .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?
            .decision
            .votes
            .iter()
            .any(|v| v.voter == voter);
        if duplicate_vote {
            return Err(async_graphql::Error::new("duplicate vote from this DID"));
        }
        let timestamp = guard.now_str()?;
        let vote = GqlVote {
            voter: voter.clone(),
            choice,
            rationale,
            timestamp,
        };
        let decision = if let Some(rec) = guard.decisions.get_mut(&id_str) {
            rec.decision.votes.push(vote.clone());
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision)?;
            rec.decision.clone()
        } else {
            return Err(async_graphql::Error::new(format!(
                "decision {id_str} not found"
            )));
        };
        guard.append_audit(&id_str, "VoteCast", &voter)?;
        if guard
            .event_tx
            .send(GovEvent::DecisionUpdated(decision))
            .is_err()
        {
            tracing::warn!("Governance event channel closed — DecisionUpdated dropped");
        }
        Ok(vote)
    }

    /// Grant a delegation from the caller to a delegatee DID.
    async fn grant_delegation(
        &self,
        ctx: &Context<'_>,
        input: GrantDelegationInput,
    ) -> GqlResult<GqlDelegation> {
        guard_graphql_mutation_execution()?;
        let delegator =
            require_permitted_actor(ctx, "grant_delegation", "governance:delegate").await?;
        if input.expires_in_hours <= 0 {
            return Err(async_graphql::Error::new("expires_in_hours must be > 0"));
        }
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let now = guard.next_timestamp()?;
        let id = graphql_hash_hex(&GraphqlDelegationIdPayload {
            domain: "exo.gateway.graphql.delegation_id.v1",
            delegator: &delegator,
            delegatee: &input.delegatee_did,
            scope: &input.scope,
            created_at: &now,
            expires_in_hours: input.expires_in_hours,
        })?;
        let expires_hours = u64::try_from(input.expires_in_hours)
            .map_err(|_| async_graphql::Error::new("expires_in_hours must fit u64"))?;
        let expires_delta = expires_hours
            .checked_mul(3_600_000)
            .ok_or_else(|| async_graphql::Error::new("expires_in_hours overflows milliseconds"))?;
        let expires_ms = now
            .physical_ms
            .checked_add(expires_delta)
            .ok_or_else(|| async_graphql::Error::new("delegation expiration overflows u64"))?;
        let delegation = GqlDelegation {
            id: ID::from(id.clone()),
            delegator,
            delegatee: input.delegatee_did,
            scope: input.scope,
            expires_at: Timestamp::new(expires_ms, 0).to_string(),
            active: true,
        };
        guard.delegations.insert(id, delegation.clone());
        Ok(delegation)
    }

    /// Revoke an existing delegation by ID.
    async fn revoke_delegation(&self, ctx: &Context<'_>, id: ID) -> GqlResult<GqlDelegation> {
        guard_graphql_mutation_execution()?;
        require_permitted_actor(ctx, "revoke_delegation", "governance:delegate").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let id_str = id.to_string();
        let delegation = guard
            .delegations
            .get_mut(&id_str)
            .ok_or_else(|| async_graphql::Error::new(format!("delegation {id_str} not found")))?;
        delegation.active = false;
        Ok(delegation.clone())
    }

    /// Raise a structured challenge against a decision.
    async fn raise_challenge(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
        grounds: String,
    ) -> GqlResult<GqlChallenge> {
        guard_graphql_mutation_execution()?;
        let actor_did =
            require_permitted_actor(ctx, "raise_challenge", "governance:challenge").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let id_str = decision_id.to_string();
        let challenge_created = guard.next_timestamp()?;
        let challenge_id = graphql_hash_hex(&GraphqlChallengeIdPayload {
            domain: "exo.gateway.graphql.challenge_id.v1",
            decision_id: &id_str,
            grounds: &grounds,
            created_at: &challenge_created,
        })?;
        let (challenge, previous_tenant_id, previous_status, decision) = {
            let rec = guard
                .decisions
                .get_mut(&id_str)
                .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
            let previous_tenant_id = rec.decision.tenant_id.clone();
            let previous_status = rec.decision.status.clone();
            let challenge = GqlChallenge {
                id: ID::from(challenge_id),
                grounds: grounds.clone(),
                status: "OPEN".into(),
            };
            rec.decision.challenges.push(challenge.clone());
            rec.decision.status = "CONTESTED".into();
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision)?;
            (
                challenge,
                previous_tenant_id,
                previous_status,
                rec.decision.clone(),
            )
        };
        guard.reindex_decision_after_state_change(&id_str, previous_tenant_id, previous_status);
        guard.append_audit(&id_str, &format!("ChallengeRaised:{grounds}"), &actor_did)?;
        if guard
            .event_tx
            .send(GovEvent::DecisionUpdated(decision))
            .is_err()
        {
            tracing::warn!("Governance event channel closed — DecisionUpdated dropped");
        }
        Ok(challenge)
    }

    /// Take an emergency action on a decision.
    ///
    /// **DualControl**: production implementation must verify two independent
    /// actor DIDs have both approved before this mutation proceeds.
    async fn take_emergency_action(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
        justification: String,
    ) -> GqlResult<GqlEmergencyAction> {
        guard_graphql_mutation_execution()?;
        let actor_did =
            require_permitted_actor(ctx, "take_emergency_action", "governance:emergency").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let id_str = decision_id.to_string();
        // Verify decision exists before creating emergency action.
        if !guard.decisions.contains_key(&id_str) {
            return Err(async_graphql::Error::new(format!(
                "decision {id_str} not found"
            )));
        }
        let tenant_id = guard
            .decisions
            .get(&id_str)
            .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?
            .decision
            .tenant_id
            .clone();
        let now = guard.next_timestamp()?;
        let action_id = graphql_hash_hex(&GraphqlEmergencyActionIdPayload {
            domain: "exo.gateway.graphql.emergency_action_id.v1",
            decision_id: &id_str,
            tenant_id: &tenant_id,
            justification: &justification,
            created_at: &now,
        })?;
        // Ratification deadline: 24 hours from now.
        let deadline_ms = now
            .physical_ms
            .checked_add(86_400_000)
            .ok_or_else(|| async_graphql::Error::new("emergency deadline overflows u64"))?;
        let action = GqlEmergencyAction {
            id: ID::from(action_id.clone()),
            decision_id: id_str.clone(),
            ratification_deadline: Timestamp::new(deadline_ms, 0).to_string(),
            justification: justification.clone(),
            tenant_id,
        };
        guard
            .emergency_actions
            .insert(action_id.clone(), action.clone());
        guard.append_audit(
            &id_str,
            &format!("EmergencyAction:{justification}"),
            &actor_did,
        )?;
        if guard
            .event_tx
            .send(GovEvent::EmergencyActionCreated(action.clone()))
            .is_err()
        {
            tracing::warn!("Governance event channel closed — EmergencyActionCreated dropped");
        }
        Ok(action)
    }

    /// Record a conflict-of-interest disclosure for a decision.
    async fn disclose_conflict(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
        description: String,
        nature: String,
    ) -> GqlResult<GqlConflictDisclosure> {
        guard_graphql_mutation_execution()?;
        let actor_did =
            require_permitted_actor(ctx, "disclose_conflict", "governance:disclose").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let id_str = decision_id.to_string();
        // Conflict records are append-only — no update path exists.
        let disclosure = GqlConflictDisclosure {
            discloser: actor_did.clone(),
            description: description.clone(),
            nature: nature.clone(),
            timestamp: guard.now_str()?,
        };
        guard.append_audit(&id_str, &format!("ConflictDisclosed:{nature}"), &actor_did)?;
        Ok(disclosure)
    }

    /// Amend the tenant constitutional corpus.
    ///
    /// **ExistentialSafeguard**: production implementation must enforce
    /// Constitutional-class quorum (supermajority + all human votes) before
    /// this mutation proceeds.
    async fn amend_constitution(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
        amendment: String,
    ) -> GqlResult<GqlConstitution> {
        guard_graphql_mutation_execution()?;
        require_permitted_actor(ctx, "amend_constitution", "governance:amend").await?;
        let state = app_state_from_context(ctx)?;
        let mut guard = state.write().await;
        let new_hash = graphql_hash_hex(&GraphqlConstitutionHashPayload {
            domain: "exo.gateway.graphql.constitution_amendment_hash.v1",
            previous_hash: &guard.constitution.hash,
            tenant_id: tenant_id.as_str(),
            previous_version: &guard.constitution.version,
            amendment: &amendment,
        })?;
        guard.constitution = GqlConstitution {
            tenant_id: tenant_id.to_string(),
            version: bump_version(&guard.constitution.version),
            hash: new_hash,
        };
        Ok(guard.constitution.clone())
    }
}

fn bump_version(v: &str) -> String {
    let parts: Vec<&str> = v.splitn(3, '.').collect();
    if parts.len() == 3
        && let Ok(patch) = parts[2].parse::<u32>()
    {
        return format!("{}.{}.{}", parts[0], parts[1], patch + 1);
    }
    format!("{v}.1")
}

// ---------------------------------------------------------------------------
// Subscription resolvers
// ---------------------------------------------------------------------------

/// GraphQL subscription root — real-time decision, delegation, and emergency events.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Subscribe to status updates for a specific decision.
    async fn decision_updated(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
    ) -> impl Stream<Item = GqlResult<GqlDecision>> {
        #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
        {
            let _ = (ctx, decision_id);
            let error = graphql_execution_disabled_error();
            return stream! {
                yield Err(error);
            };
        }

        #[cfg(feature = "unaudited-gateway-graphql-api")]
        {
            let state = app_state_from_context(ctx).cloned();
            let id_str = decision_id.to_string();
            stream! {
                match state {
                    Ok(state) => {
                        let mut rx = state.read().await.event_tx.subscribe();
                        loop {
                            match rx.recv().await {
                                Ok(GovEvent::DecisionUpdated(d)) if d.id.to_string() == id_str => yield Ok(d),
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error) => yield Err(error),
                }
            }
        }
    }

    /// Subscribe to delegation-expiry warnings for an actor DID.
    async fn delegation_expiring(
        &self,
        ctx: &Context<'_>,
        actor_did: String,
    ) -> impl Stream<Item = GqlResult<GqlDelegation>> {
        #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
        {
            let _ = (ctx, actor_did);
            let error = graphql_execution_disabled_error();
            return stream! {
                yield Err(error);
            };
        }

        #[cfg(feature = "unaudited-gateway-graphql-api")]
        {
            let state = app_state_from_context(ctx).cloned();
            let did = actor_did;
            stream! {
                match state {
                    Ok(state) => {
                        let mut rx = state.read().await.event_tx.subscribe();
                        loop {
                            match rx.recv().await {
                                Ok(GovEvent::DelegationExpiring(d)) if d.delegatee == did || d.delegator == did => {
                                    yield Ok(d)
                                }
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error) => yield Err(error),
                }
            }
        }
    }

    /// Subscribe to emergency action notifications for a tenant.
    async fn emergency_action(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
    ) -> impl Stream<Item = GqlResult<GqlEmergencyAction>> {
        #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
        {
            let _ = (ctx, tenant_id);
            let error = graphql_execution_disabled_error();
            return stream! {
                yield Err(error);
            };
        }

        #[cfg(feature = "unaudited-gateway-graphql-api")]
        {
            let state = app_state_from_context(ctx).cloned();
            let tid = tenant_id.to_string();
            stream! {
                match state {
                    Ok(state) => {
                        let mut rx = state.read().await.event_tx.subscribe();
                        loop {
                            match rx.recv().await {
                                Ok(GovEvent::EmergencyActionCreated(a)) if a.tenant_id == tid => yield Ok(a),
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    }
                    Err(error) => yield Err(error),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Schema builder and axum router
// ---------------------------------------------------------------------------

/// Build the executable `GovSchema` with shared `AppState` data.
pub fn build_schema(state: SharedGraphqlState) -> GovSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .disable_introspection()
        .limit_depth(GRAPHQL_MAX_QUERY_DEPTH)
        .limit_complexity(GRAPHQL_MAX_QUERY_COMPLEXITY)
        .data(state)
        .finish()
}

/// `POST /graphql` handler that reads a per-request [`AuthenticatedActor`]
/// injected into the request extensions by the gateway's actor-context
/// middleware (see `server::graphql_actor_context_middleware`) and merges it
/// into the executed [`async_graphql::Request`] data, mirroring the
/// `.data(actor)` fixture pattern in `auth.rs`'s own tests. Requests with no
/// authenticated actor execute with no actor in context — resolvers that
/// require one refuse with a typed `missing_authenticated_actor` error; this
/// handler never fabricates a fallback identity.
///
/// Parses the GraphQL request body directly via
/// `async_graphql::http::receive_body` rather than the `async-graphql-axum`
/// extractors: this crate's axum dependency (0.7) and `async-graphql-axum`'s
/// (0.8) are different major versions, so axum `Handler`/`FromRequest` impls
/// from the two do not compose.
#[cfg(feature = "unaudited-gateway-graphql-api")]
async fn graphql_post_handler(
    axum::extract::State(schema): axum::extract::State<GovSchema>,
    axum::extract::Extension(actor): axum::extract::Extension<Option<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let reader = async_graphql::futures_util::io::Cursor::new(body.to_vec());
    let request = match async_graphql::http::receive_body(
        content_type,
        reader,
        async_graphql::http::MultipartOptions::default(),
    )
    .await
    {
        Ok(request) => request,
        Err(err) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };
    let request = match actor {
        Some(actor) => request.data(actor),
        None => request,
    };
    let response = schema.execute(request).await;
    let mut http_response = axum::Json(&response).into_response();
    http_response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/graphql-response+json"),
    );
    http_response
}

/// Construct the axum `Router` with:
/// - `POST /graphql` — query and mutation handler
/// - `GET  /graphql/ws` — WebSocket subscription endpoint
#[cfg(feature = "unaudited-gateway-graphql-api")]
pub fn graphql_router(schema: GovSchema) -> Router {
    tracing::warn!(
        feature_flag = UNAUDITED_GRAPHQL_API_FEATURE,
        initiative = UNAUDITED_GRAPHQL_API_INITIATIVE,
        memo = UNAUDITED_GRAPHQL_API_MEMO,
        "unaudited gateway GraphQL API enabled"
    );
    Router::new()
        .route(
            "/graphql",
            axum::routing::post(graphql_post_handler).with_state(schema.clone()),
        )
        .route_service("/graphql/ws", GraphQLSubscription::new(schema))
}

/// Construct the default-safe GraphQL router.
///
/// GraphQL operations are refused unless `unaudited-gateway-graphql-api` is
/// explicitly enabled. This avoids exposing resolver-local placeholder caller
/// identity, fabricated consent, proof-verification scaffolding, and unauthenticated
/// playground HTML.
#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
pub fn graphql_router(_schema: GovSchema) -> Router {
    Router::new()
        .route(
            "/graphql",
            get(graphql_refusal_handler).post(graphql_refusal_handler),
        )
        .route("/graphql/ws", get(graphql_refusal_handler))
}

#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
async fn graphql_refusal_handler() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "unaudited_graphql_api_disabled",
            "message": "The gateway GraphQL execution surface is disabled by default pending Spline R1 remediation.",
            "feature_flag": UNAUDITED_GRAPHQL_API_FEATURE,
            "initiative": UNAUDITED_GRAPHQL_API_INITIATIVE,
            "memo": UNAUDITED_GRAPHQL_API_MEMO,
        })),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn build_test_schema() -> GovSchema {
        build_schema(AppState::new_arc())
    }

    #[test]
    fn app_state_timestamps_advance_through_hybrid_clock() {
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        let state =
            AppState::with_registry_and_clock(registry, HybridClock::with_wall_clock(|| 42_000));

        assert_eq!(
            state.next_timestamp().expect("HLC timestamp"),
            Timestamp::new(42_000, 0)
        );
        assert_eq!(
            state.next_timestamp().expect("HLC timestamp"),
            Timestamp::new(42_000, 1)
        );
    }

    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    #[tokio::test]
    async fn direct_schema_execution_default_off_refuses_mutations() {
        let schema = build_test_schema();
        let res = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1",
                        title: "Must Refuse",
                        body: "body text",
                        decisionClass: "Operational"
                    }) { id status title tenantId }
                }"#,
            )
            .await;

        assert!(
            !res.errors.is_empty(),
            "direct schema execution must be refused when unaudited GraphQL is disabled"
        );
        let message = res.errors[0].message.as_str();
        assert!(message.contains("unaudited_graphql_api_disabled"));
        assert!(message.contains(UNAUDITED_GRAPHQL_API_FEATURE));
        assert!(message.contains(UNAUDITED_GRAPHQL_API_INITIATIVE));
    }

    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    #[tokio::test]
    async fn direct_schema_execution_default_off_refuses_queries() {
        let schema = build_test_schema();
        let res = schema
            .execute(r#"{ decisions(tenantId: "t1") { id status } }"#)
            .await;

        assert!(
            !res.errors.is_empty(),
            "direct schema execution must not bypass the default-off GraphQL gate"
        );
        let message = res.errors[0].message.as_str();
        assert!(message.contains("unaudited_graphql_api_disabled"));
        assert!(message.contains(UNAUDITED_GRAPHQL_API_FEATURE));
        assert!(message.contains(UNAUDITED_GRAPHQL_API_INITIATIVE));
    }

    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    #[tokio::test]
    async fn direct_schema_execution_default_off_refuses_subscriptions() {
        use async_graphql::futures_util::StreamExt;

        let schema = build_test_schema();
        let mut stream = schema.execute_stream(
            r#"subscription { decisionUpdated(decisionId: "decision-1") { id status } }"#,
        );
        let res = stream.next().await.expect("subscription response");

        assert!(
            !res.errors.is_empty(),
            "direct subscription execution must not bypass the default-off GraphQL gate"
        );
        let message = res.errors[0].message.as_str();
        assert!(message.contains("unaudited_graphql_api_disabled"));
        assert!(message.contains(UNAUDITED_GRAPHQL_API_FEATURE));
        assert!(message.contains(UNAUDITED_GRAPHQL_API_INITIATIVE));
    }

    #[test]
    fn production_graphql_resolvers_have_default_off_guards() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let query_section = production
            .split("#[Object]\nimpl QueryRoot")
            .nth(1)
            .expect("query section")
            .split("// ---------------------------------------------------------------------------\n// Mutation resolvers")
            .next()
            .expect("query section end");
        let mutation_section = production
            .split("#[Object]\nimpl MutationRoot")
            .nth(1)
            .expect("mutation section")
            .split("// ---------------------------------------------------------------------------\n// Subscription resolvers")
            .next()
            .expect("mutation section end");
        let subscription_section = production
            .split("#[Subscription]\nimpl SubscriptionRoot")
            .nth(1)
            .expect("subscription section")
            .split("// ---------------------------------------------------------------------------\n// Schema builder and axum router")
            .next()
            .expect("subscription section end");

        assert_eq!(
            query_section.matches("    async fn ").count(),
            query_section.matches("guard_graphql_execution()?;").count(),
            "every GraphQL query resolver must call the default-off execution guard"
        );
        assert_eq!(
            mutation_section.matches("    async fn ").count(),
            mutation_section
                .matches("guard_graphql_mutation_execution()?;")
                .count(),
            "every GraphQL mutation resolver must call the mutation guard, which preserves the default-off execution guard and fail-closes unaudited writes"
        );
        assert_eq!(
            subscription_section.matches("    async fn ").count(),
            subscription_section.matches("yield Err(error);").count(),
            "every GraphQL subscription resolver must yield the default-off refusal error"
        );
    }

    #[test]
    fn graphql_resolvers_use_checked_context_data_lookup() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            production.contains("fn app_state_from_context"),
            "GraphQL state lookup must be centralized"
        );
        assert!(
            production.contains("ctx.data::<SharedGraphqlState>()"),
            "GraphQL state lookup must return an error on missing AppState"
        );
        assert!(
            !production.contains("data_unchecked::<SharedGraphqlState>"),
            "GraphQL resolvers must not panic if schema data is misconfigured"
        );
    }

    #[test]
    fn graphql_app_state_uses_reader_writer_lock_not_single_mutex() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            production.contains("type SharedGraphqlState = Arc<AsyncRwLock<AppState>>"),
            "GraphQL AppState must use a reader/writer lock so independent queries do not serialize behind one mutex"
        );
        assert!(
            !production.contains("Arc<Mutex<AppState>>"),
            "GraphQL AppState must not expose a single shared Tokio mutex"
        );
        assert!(
            !production.contains(".lock().await"),
            "GraphQL resolvers must acquire read/write guards explicitly instead of serializing every operation through lock().await"
        );
    }

    #[test]
    fn graphql_decisions_query_uses_tenant_indexes_before_pagination() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let app_state = production
            .split("pub struct AppState")
            .nth(1)
            .expect("AppState section")
            .split("impl Default for AppState")
            .next()
            .expect("AppState section end");
        let decisions_resolver = production
            .split("async fn decisions")
            .nth(1)
            .expect("decisions resolver")
            .split("    /// Get the delegated authority chain")
            .next()
            .expect("decisions resolver end");

        assert!(
            app_state.contains("decision_ids_by_tenant: BTreeMap<String, BTreeSet<String>>"),
            "GraphQL AppState must keep a tenant decision index"
        );
        assert!(
            app_state.contains(
                "decision_ids_by_tenant_status: BTreeMap<(String, String), BTreeSet<String>>"
            ),
            "GraphQL AppState must keep a tenant+status decision index"
        );
        assert!(
            decisions_resolver.contains("decision_ids_for_query"),
            "decisions resolver must fetch candidate IDs from indexes before pagination"
        );
        assert!(
            !decisions_resolver.contains(".decisions\n            .values()"),
            "decisions resolver must not scan all in-memory decision records per request"
        );
    }

    #[test]
    fn graphql_feature_on_resolvers_use_deterministic_ids_and_structured_hashes() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        for forbidden in [
            "Uuid::new_v4",
            "Hash256::digest(format!",
            "receipt_hash =\n                Hash256::digest",
        ] {
            assert!(
                !production.contains(forbidden),
                "GraphQL feature-on resolver code must not use nondeterministic IDs or raw string-concat hashes via {forbidden}"
            );
        }
        assert!(
            production.contains("hash_structured"),
            "GraphQL hashes must use canonical structured hashing"
        );
    }

    #[test]
    fn graphql_schema_builder_disables_introspection_and_limits_query_cost() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let builder = production
            .split("pub fn build_schema")
            .nth(1)
            .expect("schema builder")
            .split("/// Construct the axum `Router`")
            .next()
            .expect("schema builder end");

        assert!(
            builder.contains(".disable_introspection()"),
            "GraphQL schema must disable introspection in executable gateway schemas"
        );
        assert!(
            builder.contains(".limit_depth(GRAPHQL_MAX_QUERY_DEPTH)"),
            "GraphQL schema must set an explicit query depth limit"
        );
        assert!(
            builder.contains(".limit_complexity(GRAPHQL_MAX_QUERY_COMPLEXITY)"),
            "GraphQL schema must set an explicit query complexity limit"
        );
    }

    #[test]
    fn graphql_router_does_not_expose_playground_html() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            !production.contains("playground_source"),
            "gateway GraphQL router must not serve unauthenticated playground HTML"
        );
        assert!(
            !production.contains("GraphQLPlaygroundConfig"),
            "gateway GraphQL router must not configure unauthenticated playground HTML"
        );
        assert!(
            !production.contains("graphql_playground_handler"),
            "gateway GraphQL router must not route GET /graphql to playground HTML"
        );
    }

    #[test]
    fn graphql_mutation_resolvers_fail_closed_before_state_mutation() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let mutation_section = production
            .split("#[Object]\nimpl MutationRoot")
            .nth(1)
            .expect("mutation section")
            .split("// ---------------------------------------------------------------------------\n// Subscription resolvers")
            .next()
            .expect("mutation section end");

        assert_eq!(
            mutation_section.matches("    async fn ").count(),
            mutation_section
                .matches("guard_graphql_mutation_execution()?;")
                .count(),
            "every GraphQL mutation resolver must fail closed before reading or mutating state"
        );
        assert_eq!(
            mutation_section.matches("    async fn ").count(),
            mutation_section
                .matches("require_permitted_actor(ctx,")
                .count(),
            "every GraphQL mutation resolver must route through real constitutional kernel \
             adjudication (require_permitted_actor) — no mutation may execute or persist state \
             for an actor the kernel has not adjudicated Permitted (VCG-003 GREEN)"
        );
        assert!(
            !mutation_section.contains("refuse_graphql_mutation_execution()?;"),
            "the unconditional VCG-003 kill switch must be fully removed from every wired \
             mutation resolver now that real kernel adjudication gates execution"
        );
    }

    #[test]
    fn graphql_integer_conversions_do_not_silently_default_on_overflow() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let lines: Vec<&str> = production.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            if line.contains("::try_from(") {
                let end = (idx + 6).min(lines.len());
                let conversion_window = lines[idx..end].join("\n");
                assert!(
                    !conversion_window.contains(".unwrap_or("),
                    "GraphQL integer conversions must return typed errors instead of defaulting on overflow:\n{conversion_window}"
                );
            }
        }
    }

    #[test]
    fn resolve_identity_moves_sync_registry_lock_off_async_worker() {
        let production = include_str!("graphql.rs")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let resolver = production
            .split("async fn resolve_identity")
            .nth(1)
            .expect("resolve_identity resolver")
            .split("    /// Evaluate whether an actor has active consent")
            .next()
            .expect("resolve_identity resolver end");

        assert!(
            resolver.contains("tokio::task::spawn_blocking"),
            "synchronous LocalDidRegistry lock acquisition must run off the async worker"
        );
        assert!(
            !resolver.contains("guard.registry.read()"),
            "resolve_identity must not block the async worker on std::sync::RwLock"
        );
    }

    #[test]
    fn append_audit_rejects_sequence_overflow_without_wrapping() {
        let mut state = AppState::new();
        let decision_id = "decision-overflow".to_owned();
        state.insert_decision_record(
            decision_id.clone(),
            DecisionRecord {
                decision: GqlDecision {
                    id: ID::from(decision_id.clone()),
                    tenant_id: "tenant".to_owned(),
                    status: "CREATED".to_owned(),
                    title: "Overflow".to_owned(),
                    decision_class: "Routine".to_owned(),
                    author: "did:exo:author".to_owned(),
                    created_at: "1:0".to_owned(),
                    votes: Vec::new(),
                    challenges: Vec::new(),
                    content_hash: Hash256::digest(b"overflow").to_string(),
                },
                audit_trail: Vec::new(),
            },
        );
        state.next_audit_seq = i32::MAX;

        let append_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.append_audit(&decision_id, "OverflowAttempt", "did:exo:actor")
        }));

        let err = append_result
            .expect("overflowing audit sequence must be rejected without panic")
            .expect_err("overflowing audit sequence must return an error");

        assert!(err.message.contains("audit sequence exhausted"));
        assert_eq!(state.next_audit_seq, i32::MAX);
        assert!(
            state
                .decisions
                .get(&decision_id)
                .expect("decision")
                .audit_trail
                .is_empty(),
            "overflowing audit append must not write a wrapped sequence entry"
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_decisions_empty() {
        let schema = build_test_schema();
        let res = schema
            .execute(r#"{ decisions(tenantId: "t1") { id status } }"#)
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(data["decisions"], serde_json::json!([]));
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_decisions_clamps_oversized_offset() {
        let mut state = AppState::new();
        for index in 0..10_002 {
            let id = format!("decision-{index:05}");
            state.insert_decision_record(
                id.clone(),
                DecisionRecord {
                    decision: GqlDecision {
                        id: ID::from(id),
                        tenant_id: "tenant-a".to_owned(),
                        status: "CREATED".to_owned(),
                        title: format!("Decision {index:05}"),
                        decision_class: "Routine".to_owned(),
                        author: "did:exo:author".to_owned(),
                        created_at: "1:0".to_owned(),
                        votes: Vec::new(),
                        challenges: Vec::new(),
                        content_hash: Hash256::digest(format!("decision-{index:05}").as_bytes())
                            .to_string(),
                    },
                    audit_trail: Vec::new(),
                },
            );
        }
        let schema = build_schema(Arc::new(AsyncRwLock::new(state)));

        let res = schema
            .execute(r#"{ decisions(tenantId: "tenant-a", limit: 1, offset: 10001) { id title } }"#)
            .await;

        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(
            data["decisions"],
            serde_json::json!([
                {"id": "decision-10000", "title": "Decision 10000"}
            ]),
            "oversized offsets must clamp to the gateway GraphQL offset ceiling"
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn assert_graphql_mutation_refused(response: &async_graphql::Response) {
        assert!(
            response.errors.iter().any(|error| error
                .message
                .contains("unaudited_graphql_mutations_disabled")),
            "unauthenticated GraphQL mutations must fail closed, got {:?}",
            response.errors
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn all_graphql_mutations_refuse_without_verified_authz_context() {
        let schema = build_test_schema();

        for mutation in [
            r#"mutation {
                createDecision(input: {
                    tenantId: "t1",
                    title: "Must Refuse",
                    body: "body text",
                    decisionClass: "Operational"
                }) { id status title tenantId }
            }"#,
            r#"mutation {
                advanceDecision(
                    id: "decision-1",
                    newStatus: "DELIBERATION"
                ) { id status }
            }"#,
            r#"mutation {
                castVote(decisionId: "decision-1", choice: "APPROVE") { voter choice }
            }"#,
            r#"mutation {
                grantDelegation(input: {
                    delegateeDid: "did:exo:bob",
                    scope: "vote",
                    expiresInHours: 48
                }) { id delegatee active }
            }"#,
            r#"mutation {
                revokeDelegation(id: "delegation-1") { id active }
            }"#,
            r#"mutation {
                raiseChallenge(decisionId: "decision-1", grounds: "procedural error") {
                    id grounds status
                }
            }"#,
            r#"mutation {
                takeEmergencyAction(decisionId: "decision-1", justification: "system failure") {
                    id decisionId
                }
            }"#,
            r#"mutation {
                discloseConflict(
                    decisionId: "decision-1",
                    description: "outside interest",
                    nature: "financial"
                ) { discloser nature }
            }"#,
            r#"mutation {
                amendConstitution(tenantId: "t1", amendment: "add-article-7") {
                    tenantId version hash
                }
            }"#,
        ] {
            let response = schema.execute(mutation).await;
            assert_graphql_mutation_refused(&response);
        }
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn refused_create_decision_does_not_persist_state() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1",
                        title: "Must Refuse",
                        body: "body text",
                        decisionClass: "Operational"
                    }) { id status title tenantId }
                }"#,
            )
            .await;
        assert_graphql_mutation_refused(&create);

        let query = schema
            .execute(r#"{ decisions(tenantId: "t1") { id status title } }"#)
            .await;
        assert!(query.errors.is_empty(), "query errors: {:?}", query.errors);
        let qdata = query.data.into_json().expect("data");
        assert_eq!(
            qdata["decisions"],
            serde_json::json!([]),
            "refused mutation must not persist a decision"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-003: GraphQL authenticated-actor wiring (CORRECTIVE STAGE)
    //
    // The nine hardcoded actor literals (`did:exo:caller` x7, `system` x2) at
    // graphql.rs have been replaced by an `AuthenticatedActor` read from
    // per-request GraphQL context. Mutations bind the checked actor's DID for
    // identity fields (author/voter/delegator/discloser/audit actor), but the
    // unconditional mutation-execution kill switch still fires after the
    // actor-context check: no mutation may execute or persist state in this
    // lane until core-backed mutation adjudication wiring lands. The final
    // test in this section is a standing-red test documenting that future
    // behavior; it is `#[ignore]`d and not part of the default gate.
    // -----------------------------------------------------------------------

    /// Build a `LocalDidRegistry` with a single registered DID and return the
    /// registry plus the secret key needed to sign requests as that DID.
    /// Mirrors `auth.rs`'s own `registry_with_alice` test fixture.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn vcg003_registry_with_actor(
        did_str: &str,
    ) -> (
        std::sync::Arc<RwLock<LocalDidRegistry>>,
        exo_core::SecretKey,
    ) {
        use exo_identity::did::{DidDocument, VerificationMethod};

        let did = Did::new(did_str).unwrap();
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let multibase = format!("z{}", bs58::encode(pk.as_bytes()).into_string());
        let doc = DidDocument {
            id: did.clone(),
            public_keys: vec![pk],
            authentication: vec![],
            verification_methods: vec![VerificationMethod {
                id: format!("{did_str}#key-1"),
                key_type: "Ed25519VerificationKey2020".into(),
                controller: did,
                public_key_multibase: multibase,
                version: 1,
                active: true,
                valid_from: 0,
                revoked_at: None,
            }],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::ZERO,
            updated: Timestamp::ZERO,
            revoked: false,
        };
        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();
        (Arc::new(RwLock::new(reg)), sk)
    }

    /// Construct a real `AuthenticatedActor` for `did_str` by driving
    /// `crate::auth::authenticate` against a `LocalDidRegistry` fixture,
    /// exactly as `auth.rs`'s own tests do (`registry_with_alice` +
    /// `signed_request` + `authenticate`).
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn vcg003_authenticated_actor(
        did_str: &str,
        registry: &LocalDidRegistry,
        sk: &exo_core::SecretKey,
    ) -> crate::auth::AuthenticatedActor {
        use exo_core::{Hash256, Signature, crypto::sign};

        use crate::auth::{AuthenticationMetadata, Request as AuthRequest, authenticate};

        let observed_at = Timestamp::new(10_000, 0);
        let metadata = AuthenticationMetadata::new(observed_at).unwrap();
        let mut request = AuthRequest {
            actor_did: did_str.to_string(),
            action: "graphql".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::Empty,
            timestamp: observed_at,
        };
        let payload = crate::auth::request_signing_payload(&request).unwrap();
        request.signature = sign(&payload, sk);
        authenticate(&request, registry, metadata).expect("authenticate must succeed")
    }

    /// VCG-003 corrective test 1: identity-bearing mutations must refuse with
    /// a dedicated `missing_authenticated_actor` typed error when no
    /// authenticated actor is present in the per-request GraphQL context —
    /// distinct from the `adjudication_denied` refusal that fires once an
    /// actor *is* present but is not genuinely authorized (see
    /// `require_permitted_actor`). No result/audit field may fall back to
    /// the hardcoded `did:exo:caller` or `system` literals as actor
    /// identity.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn mutations_refuse_without_authenticated_actor_context() {
        let schema = build_test_schema();

        let identity_bearing_mutations = [
            r#"mutation {
                castVote(decisionId: "decision-1", choice: "APPROVE") { voter choice }
            }"#,
            r#"mutation {
                createDecision(input: {
                    tenantId: "t1",
                    title: "Must Refuse",
                    body: "body text",
                    decisionClass: "Operational"
                }) { id status title tenantId author }
            }"#,
            r#"mutation {
                grantDelegation(input: {
                    delegateeDid: "did:exo:bob",
                    scope: "vote",
                    expiresInHours: 48
                }) { id delegator delegatee active }
            }"#,
        ];

        for mutation in identity_bearing_mutations {
            let response = schema.execute(mutation).await;

            assert!(
                !response.errors.is_empty(),
                "mutation must refuse without an authenticated actor in context: {mutation}"
            );
            assert!(
                response
                    .errors
                    .iter()
                    .any(|error| error.message.contains("missing_authenticated_actor")),
                "refusal must use a dedicated missing_authenticated_actor error code naming the \
                 missing authenticated actor (not the blanket unaudited_graphql_mutations_disabled \
                 refusal), got {:?} for mutation {mutation}",
                response.errors
            );

            let data_json = response.data.into_json().unwrap_or(serde_json::Value::Null);
            let rendered = data_json.to_string();
            assert!(
                !rendered.contains("did:exo:caller"),
                "response must never surface the hardcoded 'did:exo:caller' literal as actor identity: {rendered}"
            );
            assert!(
                !rendered.contains("\"system\""),
                "response must never surface the hardcoded 'system' literal as actor identity: {rendered}"
            );
        }
    }

    /// VCG-003 GREEN: when a real `AuthenticatedActor` is injected into the
    /// per-request GraphQL context (constructed via `crate::auth` against a
    /// `LocalDidRegistry` fixture, mirroring `auth.rs`'s own tests) but that
    /// actor holds no recorded constitutional grant (no authority chain, no
    /// consent/bailment, no provenance — i.e. exactly today's real, unseeded
    /// state), `castVote` and `createDecision` must reach — and be refused
    /// by — the real constitutional kernel's `adjudication_denied` verdict,
    /// *not* the `missing_authenticated_actor` refusal: the actor-context
    /// gate engaged (proving the per-request actor plumbing works) and
    /// authentication succeeded, but the kernel denies the action because
    /// authentication alone is never authorization. No output may ever carry
    /// the hardcoded `did:exo:caller` or `system` literals as identity,
    /// injected actor or not.
    ///
    /// This directly complements `graphql_mutation_denied_for_unauthorized_actor`
    /// (kernel-level) by proving the same property holds end-to-end through
    /// the GraphQL resolver layer: an authenticated-but-unauthorized actor
    /// never mutates state.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn mutations_bind_injected_authenticated_actor() {
        let (registry, sk) = vcg003_registry_with_actor("did:exo:alice");
        let actor = {
            let reg = registry.read().unwrap();
            vcg003_authenticated_actor("did:exo:alice", &reg, &sk)
        };
        let state = AppState::new_arc_with_registry(registry);
        let schema = build_schema(state);

        let cast_vote_request = async_graphql::Request::new(
            r#"mutation {
                castVote(decisionId: "decision-1", choice: "APPROVE") { voter choice }
            }"#,
        )
        .data(actor.clone());
        let vote_response = schema.execute(cast_vote_request).await;
        assert!(
            !vote_response.errors.is_empty(),
            "castVote must still refuse for an unauthorized actor — the kernel denies actors \
             with no recorded constitutional grant"
        );
        assert!(
            vote_response
                .errors
                .iter()
                .any(|error| error.message.contains("adjudication_denied")),
            "castVote with an authenticated-but-unauthorized injected actor must fail via the \
             real kernel's adjudication_denied verdict, not missing_authenticated_actor (the \
             actor gate must have engaged first): {:?}",
            vote_response.errors
        );
        assert!(
            !vote_response
                .errors
                .iter()
                .any(|error| error.message.contains("missing_authenticated_actor")),
            "castVote with an injected actor must NOT report missing_authenticated_actor: {:?}",
            vote_response.errors
        );
        let vote_rendered = vote_response
            .data
            .into_json()
            .unwrap_or(serde_json::Value::Null)
            .to_string();
        assert!(
            !vote_rendered.contains("did:exo:caller"),
            "response must never surface the hardcoded 'did:exo:caller' literal as actor identity: {vote_rendered}"
        );
        assert!(
            !vote_rendered.contains("\"system\""),
            "response must never surface the hardcoded 'system' literal as actor identity: {vote_rendered}"
        );

        let create_decision_request = async_graphql::Request::new(
            r#"mutation {
                createDecision(input: {
                    tenantId: "t1",
                    title: "Bound To Actor",
                    body: "body text",
                    decisionClass: "Operational"
                }) { id status title tenantId author }
            }"#,
        )
        .data(actor.clone());
        let create_response = schema.execute(create_decision_request).await;
        assert!(
            !create_response.errors.is_empty(),
            "createDecision must still refuse for an unauthorized actor — the kernel denies \
             actors with no recorded constitutional grant"
        );
        assert!(
            create_response
                .errors
                .iter()
                .any(|error| error.message.contains("adjudication_denied")),
            "createDecision with an authenticated-but-unauthorized injected actor must fail via \
             the real kernel's adjudication_denied verdict, not missing_authenticated_actor (the \
             actor gate must have engaged first): {:?}",
            create_response.errors
        );
        assert!(
            !create_response
                .errors
                .iter()
                .any(|error| error.message.contains("missing_authenticated_actor")),
            "createDecision with an injected actor must NOT report missing_authenticated_actor: {:?}",
            create_response.errors
        );
        let create_rendered = create_response
            .data
            .into_json()
            .unwrap_or(serde_json::Value::Null)
            .to_string();
        assert!(
            !create_rendered.contains("did:exo:caller"),
            "response must never surface the hardcoded 'did:exo:caller' literal as actor identity: {create_rendered}"
        );
        assert!(
            !create_rendered.contains("\"system\""),
            "response must never surface the hardcoded 'system' literal as actor identity: {create_rendered}"
        );
    }

    /// VCG-003 GREEN: with a real, AUTHORIZED actor injected — a signed
    /// authority chain link terminating at the actor, an active bailment +
    /// matching consent record, and verifiable provenance, i.e. the same
    /// recipe as `exo_gatekeeper::kernel::tests::valid_context`, genuinely
    /// recorded via [`AppState::seed_actor_grant`] (mirroring
    /// `vcg003_authorized_adjudication_context`) — `createDecision` followed
    /// by `castVote` succeeds and the recorded voter is the injected actor's
    /// DID.
    ///
    /// Critically, the actor is granted real state through
    /// `seed_actor_grant` here, exactly the way a legitimate out-of-band
    /// grantor would establish it; the resolver itself never fabricates
    /// authority for an authenticated actor (see
    /// `graphql_mutation_denied_for_unauthorized_actor` and
    /// `mutations_bind_injected_authenticated_actor` for the same actor
    /// DID *without* a recorded grant, which must still be denied).
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn mutations_execute_with_actor_after_adjudication_wiring() {
        let (registry, sk) = vcg003_registry_with_actor("did:exo:alice");
        let actor = {
            let reg = registry.read().unwrap();
            vcg003_authenticated_actor("did:exo:alice", &reg, &sk)
        };
        let state = AppState::new_arc_with_registry(registry);
        {
            let mut guard = state.write().await;
            let grant = vcg003_actor_grant_for(&actor.did);
            guard.seed_actor_grant(actor.did.clone(), grant);
        }
        let schema = build_schema(state);

        let create_decision_request = async_graphql::Request::new(
            r#"mutation {
                createDecision(input: {
                    tenantId: "t1",
                    title: "Adjudicated Decision",
                    body: "body text",
                    decisionClass: "Operational"
                }) { id status title tenantId author }
            }"#,
        )
        .data(actor.clone());
        let create_response = schema.execute(create_decision_request).await;
        assert!(
            create_response.errors.is_empty(),
            "createDecision with an injected authenticated actor must succeed once core-backed \
             mutation adjudication wiring lands: {:?}",
            create_response.errors
        );
        let create_data = create_response.data.into_json().expect("data");
        let decision_id = create_data["createDecision"]["id"]
            .as_str()
            .expect("decision id")
            .to_owned();

        let cast_vote_request = async_graphql::Request::new(format!(
            r#"mutation {{
                castVote(decisionId: "{decision_id}", choice: "APPROVE") {{ voter choice }}
            }}"#
        ))
        .data(actor.clone());
        let vote_response = schema.execute(cast_vote_request).await;
        assert!(
            vote_response.errors.is_empty(),
            "castVote with an injected authenticated actor must succeed once core-backed \
             mutation adjudication wiring lands: {:?}",
            vote_response.errors
        );
        let vote_data = vote_response.data.into_json().expect("data");
        assert_eq!(
            vote_data["castVote"]["voter"],
            serde_json::json!(actor.did.as_str()),
            "castVote must bind voter to the injected authenticated actor's DID"
        );
    }

    /// Construct a signed `AuthorityLink` terminating at `grantee`, exactly
    /// mirroring `exo_gatekeeper::kernel::tests::signed_link` — a real
    /// Ed25519-signed grant from `grantor_str` to `grantee`, carrying the
    /// grantor's public key so `AuthorityChainValid`'s trusted-key resolution
    /// can verify the signature.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn vcg003_signed_authority_link(grantor_str: &str, grantee: &Did) -> AuthorityLink {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = Did::new(grantor_str).unwrap();
        let permissions = PermissionSet::new(vec![Permission::new("governance:mutate")]);
        let mut link = AuthorityLink {
            grantor,
            grantee: grantee.clone(),
            permissions,
            signature: Vec::new(),
            grantor_public_key: Some(pk.as_bytes().to_vec()),
        };
        let message = authority_link_signature_message(&link).expect("canonical link payload");
        let signature = exo_core::crypto::sign(message.as_bytes(), &sk);
        link.signature = signature.to_bytes().to_vec();
        link
    }

    /// Construct verifiable `Provenance` for `actor`, mirroring
    /// `exo_gatekeeper::kernel::tests::signed_provenance` — a real
    /// Ed25519-signed provenance record binding the action to the actor.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn vcg003_signed_provenance(actor: &Did) -> Provenance {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let mut provenance = Provenance {
            actor: actor.clone(),
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            action_hash: vec![1, 2, 3],
            signature: Vec::new(),
            public_key: Some(pk.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message =
            provenance_signature_message(&provenance).expect("canonical provenance payload");
        let signature = exo_core::crypto::sign(message.as_bytes(), &sk);
        provenance.signature = signature.to_bytes().to_vec();
        provenance
    }

    /// Build a fully-authorized `AdjudicationContext` for `actor`: a signed
    /// authority chain link terminating at the actor with its grantor key
    /// marked trusted, an active bailment with a matching active consent
    /// record, and verifiable provenance — the same recipe as
    /// `exo_gatekeeper::kernel::tests::valid_context`, which the kernel
    /// adjudicates as `Verdict::Permitted` for a `governance:mutate` action.
    /// GREEN's real per-actor `AdjudicationContext` builder must resolve to
    /// an equivalent context for an actor who genuinely holds this state
    /// (authority chain + bailment + consent + provenance), not fabricate it
    /// from the request — this fixture exists only to prove the kernel path
    /// itself is reachable and permits a genuinely-authorized actor once
    /// GREEN wires a real (non-scaffold) context builder.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn vcg003_authorized_adjudication_context(actor: &Did) -> AdjudicationContext {
        let bailor = Did::new("did:exo:bailor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![vcg003_signed_authority_link("did:exo:root", actor)],
        };
        let mut trusted_authority_keys = TrustedAuthorityKeys::default();
        for link in &authority_chain.links {
            if let Some(public_key) = &link.grantor_public_key {
                trusted_authority_keys.insert(link.grantor.clone(), vec![public_key.clone()]);
            }
        }
        let provenance = vcg003_signed_provenance(actor);
        let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
        if let Some(public_key) = &provenance.public_key {
            trusted_provenance_keys.insert(actor.clone(), vec![public_key.clone()]);
        }
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "judge".into(),
                branch: GovernmentBranch::Judicial,
            }],
            authority_chain,
            consent_records: vec![exo_gatekeeper::types::ConsentRecord {
                subject: bailor.clone(),
                granted_to: actor.clone(),
                scope: "governance:mutate".into(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor,
                bailee: actor.clone(),
                scope: "governance:mutate".into(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("governance:mutate")]),
            trusted_authority_keys,
            trusted_provenance_keys,
            provenance: Some(provenance),
            quorum_evidence: None,
            active_challenge_reason: None,
        }
    }

    /// Build a real [`ActorGrant`] for `actor` with the exact same
    /// cryptographic recipe as [`vcg003_authorized_adjudication_context`] —
    /// a signed authority chain link, an active bailment + matching consent
    /// record, and verifiable provenance — so callers can register it via
    /// [`AppState::seed_actor_grant`] and have the `AppState`'s internal
    /// adjudication-context resolution resolve to an equivalent,
    /// genuinely-authorized `AdjudicationContext`.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    fn vcg003_actor_grant_for(actor: &Did) -> ActorGrant {
        let ctx = vcg003_authorized_adjudication_context(actor);
        ActorGrant {
            roles: ctx.actor_roles,
            authority_chain: ctx.authority_chain,
            trusted_authority_keys: ctx.trusted_authority_keys,
            bailment_state: ctx.bailment_state,
            consent_records: ctx.consent_records,
            provenance: ctx.provenance.expect("fixture always sets provenance"),
            trusted_provenance_keys: ctx.trusted_provenance_keys,
            permissions: ctx.actor_permissions,
        }
    }

    /// VCG-003 deny-by-default guard: an actor who is authenticated (real
    /// Ed25519-verified `AuthenticatedActor`) but who holds NONE of the
    /// authority/consent/provenance state `vcg003_authorized_adjudication_context`
    /// grants — i.e. exactly today's `graphql_deny_all_adjudication_context`
    /// scaffold — must be denied by the kernel and the mutation must refuse.
    /// This proves the kernel's own deny-by-default verdict is authoritative:
    /// authentication alone (`require_authenticated_actor` succeeding) must
    /// never be conflated with authorization. Nothing may be recorded for a
    /// denied actor.
    ///
    /// This is a RED-stage assertion on the *kernel adjudication itself* — it
    /// does not require GREEN's resolver wiring to exist yet, and passes
    /// today (deny-all is exactly this actor's real state). Once GREEN wires
    /// resolvers through real per-actor context resolution, this same
    /// property — an unauthorized actor denied, no mutation performed — must
    /// continue to hold at the GraphQL layer, not just at the kernel layer.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[test]
    fn graphql_mutation_denied_for_unauthorized_actor() {
        let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
        let actor = Did::new("did:exo:unauthorized-actor").unwrap();
        let action = GkActionRequest {
            actor: actor.clone(),
            action: "graphql.create_decision".into(),
            required_permissions: PermissionSet::new(vec![Permission::new("governance:mutate")]),
            is_self_grant: false,
            modifies_kernel: false,
        };

        // The actor has no authority chain, no consent, no provenance — this
        // is exactly `graphql_deny_all_adjudication_context()`, the scaffold
        // every GraphQL mutation resolver currently routes through in spirit
        // (via the unconditional kill switch). An authenticated-but-
        // unauthorized actor must be denied here.
        let denied_context = graphql_deny_all_adjudication_context();
        let verdict = kernel.adjudicate(&action, &denied_context);
        assert!(
            verdict.is_denied(),
            "an actor with no authority chain, consent, or provenance must be Denied, not {verdict:?}"
        );

        // Sanity: the SAME actor, with genuinely-held authorized state
        // (`vcg003_authorized_adjudication_context`), reaches `Permitted`.
        // This proves the denial above is about the actor's actual state —
        // not an artifact of a kernel that denies everyone unconditionally.
        let authorized_context = vcg003_authorized_adjudication_context(&actor);
        let authorized_verdict = kernel.adjudicate(&action, &authorized_context);
        assert!(
            authorized_verdict.is_permitted(),
            "the same actor with genuine authority/consent/provenance must be Permitted, got {authorized_verdict:?}; \
             deny-by-default must be a property of the actor's real state, not an unconditional kernel refusal"
        );
    }

    /// VCG-003 actor-binding guard: the audit/identity actor recorded for a
    /// mutation must always be the checked `AuthenticatedActor`'s DID — never
    /// a caller-supplied field such as `advanceDecision`'s `reason`. This
    /// documents the corrective already applied to `advance_decision`
    /// (`let _ = reason;`) as a permanent contract: even if `reason` is
    /// crafted to look like a DID (e.g. `"did:exo:mallory"`), it must never
    /// appear as the audit actor once adjudicated mutations persist audit
    /// entries. GREEN's adjudicated `advance_decision` must keep binding
    /// `actor.did`, not `reason`, as the audit actor.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn graphql_mutation_actor_is_bound_not_caller_reason() {
        let (registry, sk) = vcg003_registry_with_actor("did:exo:alice");
        let actor = {
            let reg = registry.read().unwrap();
            vcg003_authenticated_actor("did:exo:alice", &reg, &sk)
        };
        let state = AppState::new_arc_with_registry(registry);
        let schema = build_schema(state);

        // A `reason` crafted to look like a different actor's DID must never
        // become the recorded/audit actor — the bound actor must always be
        // `actor.did` ("did:exo:alice"), regardless of this field's content.
        let spoofed_reason = "did:exo:mallory";
        let advance_request = async_graphql::Request::new(format!(
            r#"mutation {{
                advanceDecision(id: "decision-1", newStatus: "APPROVED", reason: "{spoofed_reason}") {{
                    id status author
                }}
            }}"#
        ))
        .data(actor.clone());
        let response = schema.execute(advance_request).await;
        let errors_empty = response.errors.is_empty();

        // Mutations remain refused in this lane today (RED baseline), but
        // regardless of refusal, the spoofed reason must never leak into the
        // response as if it were bound actor identity.
        let data_json = response.data.into_json().unwrap_or(serde_json::Value::Null);
        let rendered = data_json.to_string();
        assert!(
            !rendered.contains(spoofed_reason),
            "caller-supplied 'reason' must never be surfaced as bound actor identity: {rendered}"
        );

        // Once GREEN wires adjudicated execution, the same request must
        // succeed only with the caller genuinely authorized, and the
        // recorded actor must equal `actor.did`, never the `reason` text.
        // Assert that property directly against the audit-actor contract
        // documented on `advance_decision`: the reason value it accepts must
        // never be usable as an actor identity, which today's refusal-before-
        // persistence path already guarantees by construction (no audit
        // entry is written at all).
        if errors_empty {
            assert_ne!(
                data_json["advanceDecision"]["author"],
                serde_json::json!(spoofed_reason),
                "advanceDecision must never bind the caller-supplied reason as the actor/author"
            );
        }
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_audit_trail_unknown_decision_errors() {
        let schema = build_test_schema();

        let trail = schema
            .execute(r#"{ auditTrail(decisionId: "missing-decision") { sequence eventType } }"#)
            .await;

        assert!(
            !trail.errors.is_empty(),
            "unknown decision audit trail must fail closed instead of returning an empty trail"
        );
        assert!(
            trail.errors[0].message.contains("missing-decision"),
            "error must name the missing decision, got {:?}",
            trail.errors
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_constitution_default() {
        let schema = build_test_schema();
        let res = schema
            .execute(r#"{ constitution(tenantId: "default") { tenantId version } }"#)
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(data["constitution"]["tenantId"], "default");
        assert_eq!(data["constitution"]["version"], "1.0.0");
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_constitution_unknown_tenant_errors() {
        let schema = build_test_schema();

        let res = schema
            .execute(r#"{ constitution(tenantId: "unknown") { tenantId version hash } }"#)
            .await;

        assert!(
            !res.errors.is_empty(),
            "unknown tenant constitution query must fail closed instead of synthesizing a corpus"
        );
        assert!(
            res.errors[0].message.contains("unknown"),
            "error must name the missing tenant, got {:?}",
            res.errors
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn schema_introspection_queries_are_disabled() {
        let schema = build_test_schema();
        let res = schema.execute(r#"{ __schema { types { name } } }"#).await;
        let data = res.data.into_json().expect("data");
        assert!(
            data["__schema"].is_null(),
            "gateway executable schema must not return introspection data: {data}"
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn schema_sdl_has_required_types_without_enabling_introspection() {
        let schema = build_test_schema();
        let sdl = schema.sdl();
        for required in [
            "type GqlDecision",
            "type GqlVote",
            "type GqlDelegation",
            "type GqlAuditEntry",
            "type GqlEmergencyAction",
            "type QueryRoot",
            "type MutationRoot",
            "type SubscriptionRoot",
        ] {
            assert!(sdl.contains(required), "missing SDL type: {required}");
        }
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn schema_rejects_queries_over_complexity_limit() {
        let schema = build_test_schema();
        let expected_complexity_limit = 256usize;
        let repeated_fields = (0..expected_complexity_limit + 1)
            .map(|idx| format!("a{idx}: decisions(tenantId: \"t1\") {{ id }}"))
            .collect::<Vec<_>>()
            .join("\n");
        let res = schema.execute(format!("{{ {repeated_fields} }}")).await;
        assert!(
            !res.errors.is_empty(),
            "queries beyond the configured complexity limit must be rejected"
        );
        assert!(
            res.errors
                .iter()
                .any(|error| error.message.contains("too complex")),
            "unexpected complexity-limit errors: {:?}",
            res.errors
        );
    }

    #[test]
    fn bump_version_patch() {
        assert_eq!(bump_version("1.0.0"), "1.0.1");
        assert_eq!(bump_version("2.3.9"), "2.3.10");
    }

    // -----------------------------------------------------------------------
    // APE-35: Identity + Consent end-to-end tests
    // -----------------------------------------------------------------------

    /// APE-35: resolveIdentity returns `registered: false` for an unknown DID.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_resolve_identity_unknown_did() {
        let schema = build_test_schema();
        let res = schema
            .execute(
                r#"{ resolveIdentity(did: "did:exo:unknown") { did registered activeKeyCount } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(data["resolveIdentity"]["registered"], false);
        assert_eq!(data["resolveIdentity"]["activeKeyCount"], 0);
    }

    /// APE-35: resolveIdentity returns `registered: true` after a DID is added
    /// to the shared registry (end-to-end through LocalDidRegistry).
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_resolve_identity_registered_did() {
        use exo_core::Timestamp as Ts;
        use exo_identity::did::{DidDocument, VerificationMethod};

        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        // Register a DID with one active verification method.
        {
            let did = Did::new("did:exo:alice").unwrap();
            let (pk, _) = exo_core::crypto::generate_keypair();
            let multibase = format!("z{}", bs58::encode(pk.as_bytes()).into_string());
            let mut reg = registry.write().unwrap();
            reg.register(DidDocument {
                id: did.clone(),
                public_keys: vec![pk],
                authentication: vec![],
                verification_methods: vec![VerificationMethod {
                    id: "did:exo:alice#key-1".into(),
                    controller: did,
                    key_type: "Ed25519VerificationKey2020".into(),
                    public_key_multibase: multibase,
                    version: 1,
                    active: true,
                    valid_from: 0,
                    revoked_at: None,
                }],
                hybrid_verification_methods: vec![],
                service_endpoints: vec![],
                created: Ts::ZERO,
                updated: Ts::ZERO,
                revoked: false,
            })
            .expect("register ok");
        }
        let state = AppState::new_arc_with_registry(registry);
        let schema = build_schema(state);
        let res = schema
            .execute(
                r#"{ resolveIdentity(did: "did:exo:alice") { did registered activeKeyCount } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(data["resolveIdentity"]["registered"], true);
        assert_eq!(data["resolveIdentity"]["activeKeyCount"], 1);
    }

    /// SPLINE-R2: evaluateConsent must fail closed when GraphQL has no verified
    /// consent evidence source. The resolver must not fabricate an active
    /// bailment for the requested subject/actor pair.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_evaluate_consent_denies_without_verified_consent_evidence() {
        let schema = build_test_schema();
        let res = schema
            .execute(
                r#"{ evaluateConsent(
                    subject: "did:exo:alice",
                    actor: "did:exo:bob",
                    scope: "data:medical",
                    actionType: "read"
                ) { subject actor scope granted message } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(data["evaluateConsent"]["granted"], false);
        assert_eq!(data["evaluateConsent"]["scope"], "data:medical");
        assert_eq!(data["evaluateConsent"]["subject"], "did:exo:alice");
        let message = data["evaluateConsent"]["message"]
            .as_str()
            .expect("message is a string");
        assert!(message.contains("no verified consent evidence"));
        assert!(message.contains("fix-spline-r2-graphql-consent-fabrication.md"));
    }

    /// SPLINE-R3: verifyProof must not treat arbitrary proof IDs as valid.
    /// The GraphQL schema has no proof bytes, public inputs, or verified proof
    /// store wired, so it must fail closed instead of using hash parity.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_verify_proof_refuses_arbitrary_proof_id() {
        let schema = build_test_schema();
        let res = schema
            .execute(
                r#"{ verifyProof(proofId: "proof-acceptance-must-not-depend-on-id-hash") {
                    proofType
                    valid
                    message
                } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().expect("data");
        assert_eq!(data["verifyProof"]["valid"], false);
        assert_eq!(data["verifyProof"]["proofType"], "Unavailable");
        let message = data["verifyProof"]["message"]
            .as_str()
            .expect("message is a string");
        assert!(message.contains("proof storage and verification are not wired"));
        assert!(message.contains("fix-spline-r3-graphql-proof-stub.md"));
    }

    /// APE-35: resolveIdentity rejects malformed DIDs with a GraphQL error.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn query_resolve_identity_invalid_did_returns_error() {
        let schema = build_test_schema();
        let res = schema
            .execute(r#"{ resolveIdentity(did: "not-a-valid-did") { registered } }"#)
            .await;
        assert!(!res.errors.is_empty(), "expected error for invalid DID");
    }

    /// APE-35: schema SDL includes the new identity + consent types without
    /// enabling runtime introspection.
    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn schema_sdl_includes_identity_and_consent_types() {
        let schema = build_test_schema();
        let sdl = schema.sdl();
        for required in ["type GqlIdentity", "type GqlConsentResult"] {
            assert!(sdl.contains(required), "missing SDL type: {required}");
        }
    }
}
