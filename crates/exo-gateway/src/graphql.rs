//! GraphQL schema, resolvers, and axum HTTP handler for the ExoChain governance API.
//!
//! The schema is backed by an `AppState` held behind `Arc<tokio::sync::Mutex<>>` which is
//! shared across all requests.  Production deployments replace the in-memory collections
//! with a database pool injected via `GatewayConfig::database_pool_url`.
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
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use async_graphql::{
    Context, ID, InputObject, Object, Result as GqlResult, Schema, SimpleObject, Subscription,
    futures_util::Stream,
};
#[cfg(feature = "unaudited-gateway-graphql-api")]
use async_graphql_axum::{GraphQL, GraphQLSubscription};
use async_stream::stream;
use axum::Router;
#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
use axum::routing::get;
#[cfg(feature = "unaudited-gateway-graphql-api")]
use axum::routing::post_service;
#[cfg(not(feature = "unaudited-gateway-graphql-api"))]
use axum::{Json, http::StatusCode};
use exo_consent::policy::{
    ActionRequest as ConsentActionRequest, ConsentDecision, ConsentPolicy, ConsentRequirement,
    PolicyEngine,
};
use exo_core::{Did, Hash256, Timestamp, hash::hash_structured, hlc::HybridClock};
use exo_identity::registry::{DidRegistry, LocalDidRegistry};
use serde::Serialize;
use tokio::sync::{Mutex, broadcast};

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
    delegations: BTreeMap<String, GqlDelegation>,
    emergency_actions: BTreeMap<String, GqlEmergencyAction>,
    constitution: GqlConstitution,
    next_audit_seq: i32,
    clock: HybridClock,
    event_tx: broadcast::Sender<GovEvent>,
    /// Shared DID registry — wired from `server::AppState` for identity resolution.
    registry: Arc<RwLock<LocalDidRegistry>>,
    /// Consent policy engine — evaluates `PolicyEngine` rules for consent checks.
    consent_engine: PolicyEngine,
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
            delegations: BTreeMap::new(),
            emergency_actions: BTreeMap::new(),
            constitution: GqlConstitution {
                tenant_id: "default".into(),
                version: "1.0.0".into(),
                hash: Hash256::digest(b"constitution-v1").to_string(),
            },
            next_audit_seq: 1,
            clock,
            event_tx,
            registry,
            consent_engine: PolicyEngine::new(),
        }
    }

    /// Create a new `AppState` wrapped in `Arc<Mutex<>>` for concurrent access.
    pub fn new_arc() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Create a new `AppState` with a shared registry, wrapped in `Arc<Mutex<>>`.
    pub fn new_arc_with_registry(registry: Arc<RwLock<LocalDidRegistry>>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::with_registry(registry)))
    }

    fn next_timestamp(&mut self) -> GqlResult<Timestamp> {
        self.clock
            .now()
            .map_err(|err| async_graphql::Error::new(format!("HLC clock exhausted: {err}")))
    }

    fn now_str(&mut self) -> GqlResult<String> {
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

fn guard_graphql_mutation_execution() -> GqlResult<()> {
    guard_graphql_execution()?;
    Err(graphql_mutation_execution_disabled_error())
}

fn app_state_from_context<'ctx>(ctx: &'ctx Context<'_>) -> GqlResult<&'ctx Arc<Mutex<AppState>>> {
    ctx.data::<Arc<Mutex<AppState>>>()
}

fn graphql_nonnegative_i32_to_usize(value: i32, field: &'static str) -> GqlResult<usize> {
    usize::try_from(value)
        .map_err(|_| async_graphql::Error::new(format!("{field} cannot be represented as usize")))
}

fn graphql_count_to_i32(count: usize, field: &'static str) -> GqlResult<i32> {
    i32::try_from(count)
        .map_err(|_| async_graphql::Error::new(format!("{field} exceeds GraphQL i32 range")))
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
        let guard = state.lock().await;
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
        let guard = state.lock().await;
        let offset =
            graphql_nonnegative_i32_to_usize(offset.unwrap_or(0).max(0), "decisions.offset")?;
        let limit =
            graphql_nonnegative_i32_to_usize(limit.unwrap_or(50).clamp(1, 200), "decisions.limit")?;
        let results: Vec<GqlDecision> = guard
            .decisions
            .values()
            .filter(|r| r.decision.tenant_id == tenant_id.as_str())
            .filter(|r| status.as_ref().is_none_or(|s| *s == r.decision.status))
            .map(|r| r.decision.clone())
            .skip(offset)
            .take(limit)
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
        let guard = state.lock().await;
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
        let guard = state.lock().await;
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
        let guard = state.lock().await;
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
        let guard = state.lock().await;
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
            let guard = state.lock().await;
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
        let guard = state.lock().await;
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
            actor: actor_did,
            action_type: action_type.clone(),
        };
        let decision = guard
            .consent_engine
            .evaluate(&policy, &[], &action, &Timestamp::ZERO);
        let (granted, message) = match decision {
            ConsentDecision::Granted { .. } => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
                ),
            ),
            ConsentDecision::Denied { reason } => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; policy reason: {reason}; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
                ),
            ),
            ConsentDecision::Escalated { to } => (
                false,
                format!(
                    "Consent denied: gateway GraphQL has no verified consent evidence for {subject_str} -> {actor_str} scope '{scope}' action '{action_type}'; policy escalated to {to}; see {GRAPHQL_CONSENT_FABRICATION_INITIATIVE}"
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
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
            author: "system".into(), // caller DID injected by auth layer in production
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
        guard.decisions.insert(
            id.clone(),
            DecisionRecord {
                decision: decision.clone(),
                audit_trail: Vec::new(),
            },
        );
        guard.append_audit(&id, "DecisionCreated", "system")?;
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
        let id_str = id.to_string();
        let decision = {
            let rec = guard
                .decisions
                .get_mut(&id_str)
                .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
            rec.decision.status = new_status.clone();
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision)?;
            rec.decision.clone()
        };
        let actor = reason.as_deref().unwrap_or("system");
        guard.append_audit(&id_str, &format!("StatusAdvanced:{new_status}"), actor)?;
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
        let valid_choices = ["APPROVE", "REJECT", "ABSTAIN"];
        if !valid_choices.contains(&choice.as_str()) {
            return Err(async_graphql::Error::new(format!(
                "invalid choice '{choice}'; must be one of APPROVE, REJECT, ABSTAIN"
            )));
        }
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        let duplicate_vote = guard
            .decisions
            .get(&id_str)
            .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?
            .decision
            .votes
            .iter()
            .any(|v| v.voter == "did:exo:caller");
        if duplicate_vote {
            return Err(async_graphql::Error::new("duplicate vote from this DID"));
        }
        // Caller DID comes from auth context in production; use placeholder here.
        let voter = "did:exo:caller".to_string();
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
        if input.expires_in_hours <= 0 {
            return Err(async_graphql::Error::new("expires_in_hours must be > 0"));
        }
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
        let now = guard.next_timestamp()?;
        let id = graphql_hash_hex(&GraphqlDelegationIdPayload {
            domain: "exo.gateway.graphql.delegation_id.v1",
            delegator: "did:exo:caller",
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
            delegator: "did:exo:caller".into(),
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        let challenge_created = guard.next_timestamp()?;
        let challenge_id = graphql_hash_hex(&GraphqlChallengeIdPayload {
            domain: "exo.gateway.graphql.challenge_id.v1",
            decision_id: &id_str,
            grounds: &grounds,
            created_at: &challenge_created,
        })?;
        let (challenge, decision) = {
            let rec = guard
                .decisions
                .get_mut(&id_str)
                .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
            let challenge = GqlChallenge {
                id: ID::from(challenge_id),
                grounds: grounds.clone(),
                status: "OPEN".into(),
            };
            rec.decision.challenges.push(challenge.clone());
            rec.decision.status = "CONTESTED".into();
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision)?;
            (challenge, rec.decision.clone())
        };
        guard.append_audit(
            &id_str,
            &format!("ChallengeRaised:{grounds}"),
            "did:exo:caller",
        )?;
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
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
            "did:exo:caller",
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        // Conflict records are append-only — no update path exists.
        let disclosure = GqlConflictDisclosure {
            discloser: "did:exo:caller".into(),
            description: description.clone(),
            nature: nature.clone(),
            timestamp: guard.now_str()?,
        };
        guard.append_audit(
            &id_str,
            &format!("ConflictDisclosed:{nature}"),
            "did:exo:caller",
        )?;
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
        let state = app_state_from_context(ctx)?;
        let mut guard = state.lock().await;
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
    if parts.len() == 3 {
        if let Ok(patch) = parts[2].parse::<u32>() {
            return format!("{}.{}.{}", parts[0], parts[1], patch + 1);
        }
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
                        let mut rx = state.lock().await.event_tx.subscribe();
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
                        let mut rx = state.lock().await.event_tx.subscribe();
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
                        let mut rx = state.lock().await.event_tx.subscribe();
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
pub fn build_schema(state: Arc<Mutex<AppState>>) -> GovSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .disable_introspection()
        .limit_depth(GRAPHQL_MAX_QUERY_DEPTH)
        .limit_complexity(GRAPHQL_MAX_QUERY_COMPLEXITY)
        .data(state)
        .finish()
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
        .route("/graphql", post_service(GraphQL::new(schema.clone())))
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
        let mut state =
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
            production.contains("ctx.data::<Arc<Mutex<AppState>>>()"),
            "GraphQL state lookup must return an error on missing AppState"
        );
        assert!(
            !production.contains("data_unchecked::<Arc<Mutex<AppState>>>"),
            "GraphQL resolvers must not panic if schema data is misconfigured"
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
        state.decisions.insert(
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
            let mut reg = registry.write().unwrap();
            reg.register(DidDocument {
                id: Did::new("did:exo:alice").unwrap(),
                public_keys: vec![],
                authentication: vec![],
                verification_methods: vec![VerificationMethod {
                    id: "did:exo:alice#key-1".into(),
                    controller: Did::new("did:exo:alice").unwrap(),
                    key_type: "Ed25519VerificationKey2020".into(),
                    public_key_multibase: "zABC".into(),
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
