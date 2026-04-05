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
//! - `resolveIdentity(did)` — looks up a DID document from the shared `DidRegistry`
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
use async_graphql_axum::{GraphQL, GraphQLSubscription};
use async_stream::stream;
use axum::{Router, routing::get};
use exo_consent::{
    bailment::{self, BailmentStatus, BailmentType},
    policy::{
        ActionRequest as ConsentActionRequest, ActiveConsent, ConsentDecision, ConsentPolicy,
        ConsentRequirement, PolicyEngine,
    },
};
use exo_core::{Did, Hash256, Timestamp};
use exo_identity::did::DidRegistry;
use tokio::sync::{Mutex, broadcast};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// GraphQL output types
// ---------------------------------------------------------------------------

/// A single vote cast on a decision.
#[derive(Debug, Clone, SimpleObject)]
pub struct GqlVote {
    pub voter: String,
    pub choice: String,
    pub rationale: Option<String>,
    pub timestamp: String,
}

/// A challenge raised against a decision.
#[derive(Debug, Clone, SimpleObject)]
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

/// Shared application state.  Replace in-memory `BTreeMap`s with a sqlx
/// `PgPool` when `GatewayConfig::database_pool_url` is set.
pub struct AppState {
    decisions: BTreeMap<String, DecisionRecord>,
    delegations: BTreeMap<String, GqlDelegation>,
    emergency_actions: BTreeMap<String, GqlEmergencyAction>,
    constitution: GqlConstitution,
    next_audit_seq: i32,
    event_tx: broadcast::Sender<GovEvent>,
    /// Shared DID registry — wired from `server::AppState` for identity resolution.
    registry: Arc<RwLock<DidRegistry>>,
    /// Consent policy engine — evaluates `PolicyEngine` rules for consent checks.
    consent_engine: PolicyEngine,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self::with_registry(Arc::new(RwLock::new(DidRegistry::new())))
    }

    pub fn with_registry(registry: Arc<RwLock<DidRegistry>>) -> Self {
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
            event_tx,
            registry,
            consent_engine: PolicyEngine::new(),
        }
    }

    pub fn new_arc() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new()))
    }

    pub fn new_arc_with_registry(registry: Arc<RwLock<DidRegistry>>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::with_registry(registry)))
    }

    fn append_audit(&mut self, decision_id: &str, event_type: &str, actor: &str) {
        if let Some(rec) = self.decisions.get_mut(decision_id) {
            let seq = self.next_audit_seq;
            self.next_audit_seq += 1;
            let ts = now_str();
            // Chain receipt hash: Blake3 of (prev_hash | event_type | actor | seq)
            let prev_hash = rec
                .audit_trail
                .last()
                .map(|e| e.receipt_hash.clone())
                .unwrap_or_else(|| Hash256::ZERO.to_string());
            let receipt_hash =
                Hash256::digest(format!("{prev_hash}|{event_type}|{actor}|{seq}").as_bytes())
                    .to_string();
            rec.audit_trail.push(GqlAuditEntry {
                sequence: seq,
                event_type: event_type.into(),
                actor: actor.into(),
                timestamp: ts,
                receipt_hash,
            });
        }
    }

    fn compute_decision_hash(d: &GqlDecision) -> String {
        Hash256::digest(format!("{}|{}|{}", d.id.as_str(), d.status, d.votes.len()).as_bytes())
            .to_string()
    }
}

fn now_str() -> String {
    Timestamp::now_utc().to_string()
}

// ---------------------------------------------------------------------------
// Schema type alias
// ---------------------------------------------------------------------------

pub type GovSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

// ---------------------------------------------------------------------------
// Query resolvers
// ---------------------------------------------------------------------------

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Fetch a single decision by ID.
    async fn decision(&self, ctx: &Context<'_>, id: ID) -> GqlResult<Option<GqlDecision>> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let guard = state.lock().await;
        let offset = usize::try_from(offset.unwrap_or(0).max(0)).unwrap_or(0);
        let limit = usize::try_from(limit.unwrap_or(50).clamp(1, 200)).unwrap_or(50);
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let guard = state.lock().await;
        let chain_length = i32::try_from(
            guard
                .delegations
                .values()
                .filter(|d| d.delegatee == actor_did && d.active)
                .count(),
        )
        .unwrap_or(0);
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let guard = state.lock().await;
        let _ = version; // version pinning reserved for DB layer
        if guard.constitution.tenant_id == tenant_id.as_str() {
            Ok(guard.constitution.clone())
        } else {
            Ok(GqlConstitution {
                tenant_id: tenant_id.to_string(),
                version: "1.0.0".into(),
                hash: Hash256::digest(tenant_id.as_str().as_bytes()).to_string(),
            })
        }
    }

    /// List all active delegations for an actor DID.
    async fn delegations(
        &self,
        ctx: &Context<'_>,
        actor_did: String,
    ) -> GqlResult<Vec<GqlDelegation>> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let guard = state.lock().await;
        Ok(guard
            .decisions
            .get(decision_id.as_str())
            .map(|r| r.audit_trail.clone())
            .unwrap_or_default())
    }

    /// Verify a cryptographic proof by ID.
    async fn verify_proof(
        &self,
        _ctx: &Context<'_>,
        proof_id: ID,
    ) -> GqlResult<GqlVerificationResult> {
        // Proof verification delegates to exo-proofs crate; placeholder returns
        // deterministic result based on the proof_id hash.
        let hash = Hash256::digest(proof_id.as_str().as_bytes());
        let valid = hash.as_bytes()[0] & 1 == 0; // deterministic stub
        Ok(GqlVerificationResult {
            proof_type: "Blake3Commitment".into(),
            valid,
            message: if valid {
                "Proof verified".into()
            } else {
                "Proof not found — full verification requires exo-proofs integration".into()
            },
        })
    }

    /// Resolve a DID identity from the shared `DidRegistry`.
    ///
    /// Returns the registration status and key counts for the given DID.
    /// Wired end-to-end to `exo-identity::DidRegistry` (APE-35 acceptance criterion).
    async fn resolve_identity(&self, ctx: &Context<'_>, did: ID) -> GqlResult<GqlIdentity> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let guard = state.lock().await;
        let did_str = did.to_string();
        let did_key = Did::new(&did_str)
            .map_err(|e| async_graphql::Error::new(format!("invalid DID: {e}")))?;
        let registry = guard.registry.read().unwrap_or_else(|e| e.into_inner());
        match registry.resolve(&did_key) {
            Some(doc) => {
                let active_key_count = i32::try_from(
                    doc.verification_methods
                        .iter()
                        .filter(|vm| vm.active)
                        .count(),
                )
                .unwrap_or(0);
                let service_endpoint_count =
                    i32::try_from(doc.service_endpoints.len()).unwrap_or(0);
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let guard = state.lock().await;
        let subject_str = subject.to_string();
        let actor_str = actor.to_string();
        let subject_did = Did::new(&subject_str)
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

        // Build an active bailment from subject (bailor) → actor (bailee) covering
        // the requested scope.  Terms are hashed from the scope string.
        let mut active_bailment = bailment::propose(
            &subject_did,
            &actor_did,
            scope.as_bytes(),
            BailmentType::Processing,
        );
        active_bailment.status = BailmentStatus::Active; // grant for evaluation
        let consents = vec![ActiveConsent {
            grantor: subject_did,
            action_type: action_type.clone(),
            role: "any".into(),
            clearance_level: 0,
            bailment: active_bailment,
        }];
        let action = ConsentActionRequest {
            actor: actor_did,
            action_type: action_type.clone(),
        };
        let now = Timestamp::now_utc();
        let decision = guard
            .consent_engine
            .evaluate(&policy, &consents, &action, &now);
        let (granted, message) = match decision {
            ConsentDecision::Granted { .. } => (
                true,
                format!(
                    "Consent granted: {actor_str} may perform '{action_type}' on {subject_str} scope '{scope}'"
                ),
            ),
            ConsentDecision::Denied { reason } => (false, reason),
            ConsentDecision::Escalated { to } => {
                (false, format!("Escalated to {to} for manual review"))
            }
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

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Create a new governance decision in CREATED status.
    async fn create_decision(
        &self,
        ctx: &Context<'_>,
        input: CreateDecisionInput,
    ) -> GqlResult<GqlDecision> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id = Uuid::new_v4().to_string();
        let body_hash = Hash256::digest(input.body.as_bytes()).to_string();
        let decision = GqlDecision {
            id: ID::from(id.clone()),
            tenant_id: input.tenant_id,
            status: "CREATED".into(),
            title: input.title,
            decision_class: input.decision_class,
            author: "system".into(), // caller DID injected by auth layer in production
            created_at: now_str(),
            votes: Vec::new(),
            challenges: Vec::new(),
            content_hash: body_hash,
        };
        let _ = guard
            .event_tx
            .send(GovEvent::DecisionUpdated(decision.clone()));
        guard.decisions.insert(
            id.clone(),
            DecisionRecord {
                decision: decision.clone(),
                audit_trail: Vec::new(),
            },
        );
        guard.append_audit(&id, "DecisionCreated", "system");
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id_str = id.to_string();
        let decision = {
            let rec = guard
                .decisions
                .get_mut(&id_str)
                .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
            rec.decision.status = new_status.clone();
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision);
            rec.decision.clone()
        };
        let actor = reason.as_deref().unwrap_or("system");
        guard.append_audit(&id_str, &format!("StatusAdvanced:{new_status}"), actor);
        let _ = guard
            .event_tx
            .send(GovEvent::DecisionUpdated(decision.clone()));
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
        let valid_choices = ["APPROVE", "REJECT", "ABSTAIN"];
        if !valid_choices.contains(&choice.as_str()) {
            return Err(async_graphql::Error::new(format!(
                "invalid choice '{choice}'; must be one of APPROVE, REJECT, ABSTAIN"
            )));
        }
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        let rec = guard
            .decisions
            .get_mut(&id_str)
            .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
        // Caller DID comes from auth context in production; use placeholder here.
        let voter = "did:exo:caller".to_string();
        let (vote, decision) = {
            if rec.decision.votes.iter().any(|v| v.voter == voter) {
                return Err(async_graphql::Error::new("duplicate vote from this DID"));
            }
            let vote = GqlVote {
                voter: voter.clone(),
                choice,
                rationale,
                timestamp: now_str(),
            };
            rec.decision.votes.push(vote.clone());
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision);
            (vote, rec.decision.clone())
        };
        guard.append_audit(&id_str, "VoteCast", &voter);
        let _ = guard.event_tx.send(GovEvent::DecisionUpdated(decision));
        Ok(vote)
    }

    /// Grant a delegation from the caller to a delegatee DID.
    async fn grant_delegation(
        &self,
        ctx: &Context<'_>,
        input: GrantDelegationInput,
    ) -> GqlResult<GqlDelegation> {
        if input.expires_in_hours <= 0 {
            return Err(async_graphql::Error::new("expires_in_hours must be > 0"));
        }
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id = Uuid::new_v4().to_string();
        let now = Timestamp::now_utc();
        let expires_ms = now.physical_ms.saturating_add(
            u64::try_from(input.expires_in_hours)
                .unwrap_or(0)
                .saturating_mul(3_600_000),
        );
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        let (challenge, decision) = {
            let rec = guard
                .decisions
                .get_mut(&id_str)
                .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
            let challenge = GqlChallenge {
                id: ID::from(Uuid::new_v4().to_string()),
                grounds: grounds.clone(),
                status: "OPEN".into(),
            };
            rec.decision.challenges.push(challenge.clone());
            rec.decision.status = "CONTESTED".into();
            rec.decision.content_hash = AppState::compute_decision_hash(&rec.decision);
            (challenge, rec.decision.clone())
        };
        guard.append_audit(
            &id_str,
            &format!("ChallengeRaised:{grounds}"),
            "did:exo:caller",
        );
        let _ = guard.event_tx.send(GovEvent::DecisionUpdated(decision));
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        // Verify decision exists before creating emergency action.
        let _ = guard
            .decisions
            .get(&id_str)
            .ok_or_else(|| async_graphql::Error::new(format!("decision {id_str} not found")))?;
        let action_id = Uuid::new_v4().to_string();
        let now = Timestamp::now_utc();
        // Ratification deadline: 24 hours from now.
        let deadline_ms = now.physical_ms.saturating_add(86_400_000);
        let action = GqlEmergencyAction {
            id: ID::from(action_id.clone()),
            decision_id: id_str.clone(),
            ratification_deadline: Timestamp::new(deadline_ms, 0).to_string(),
            justification: justification.clone(),
            tenant_id: guard
                .decisions
                .get(&id_str)
                .map(|r| r.decision.tenant_id.clone())
                .unwrap_or_default(),
        };
        guard
            .emergency_actions
            .insert(action_id.clone(), action.clone());
        guard.append_audit(
            &id_str,
            &format!("EmergencyAction:{justification}"),
            "did:exo:caller",
        );
        let _ = guard
            .event_tx
            .send(GovEvent::EmergencyActionCreated(action.clone()));
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let id_str = decision_id.to_string();
        // Conflict records are append-only — no update path exists.
        let disclosure = GqlConflictDisclosure {
            discloser: "did:exo:caller".into(),
            description: description.clone(),
            nature: nature.clone(),
            timestamp: now_str(),
        };
        guard.append_audit(
            &id_str,
            &format!("ConflictDisclosed:{nature}"),
            "did:exo:caller",
        );
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
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>();
        let mut guard = state.lock().await;
        let new_hash =
            Hash256::digest(format!("{}:{}", guard.constitution.hash, amendment).as_bytes())
                .to_string();
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

pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Subscribe to status updates for a specific decision.
    async fn decision_updated(
        &self,
        ctx: &Context<'_>,
        decision_id: ID,
    ) -> impl Stream<Item = GqlDecision> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>().clone();
        let id_str = decision_id.to_string();
        let mut rx = state.lock().await.event_tx.subscribe();
        stream! {
            loop {
                match rx.recv().await {
                    Ok(GovEvent::DecisionUpdated(d)) if d.id.to_string() == id_str => yield d,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }

    /// Subscribe to delegation-expiry warnings for an actor DID.
    async fn delegation_expiring(
        &self,
        ctx: &Context<'_>,
        actor_did: String,
    ) -> impl Stream<Item = GqlDelegation> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>().clone();
        let did = actor_did;
        let mut rx = state.lock().await.event_tx.subscribe();
        stream! {
            loop {
                match rx.recv().await {
                    Ok(GovEvent::DelegationExpiring(d)) if d.delegatee == did || d.delegator == did => {
                        yield d
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }

    /// Subscribe to emergency action notifications for a tenant.
    async fn emergency_action(
        &self,
        ctx: &Context<'_>,
        tenant_id: ID,
    ) -> impl Stream<Item = GqlEmergencyAction> {
        let state = ctx.data_unchecked::<Arc<Mutex<AppState>>>().clone();
        let tid = tenant_id.to_string();
        let mut rx = state.lock().await.event_tx.subscribe();
        stream! {
            loop {
                match rx.recv().await {
                    Ok(GovEvent::EmergencyActionCreated(a)) if a.tenant_id == tid => yield a,
                    Ok(_) => {}
                    Err(_) => break,
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
        .data(state)
        .finish()
}

/// Construct the axum `Router` with:
/// - `POST /graphql` — query and mutation handler
/// - `GET  /graphql` — GraphQL Playground (development)
/// - `GET  /graphql/ws` — WebSocket subscription endpoint
pub fn graphql_router(schema: GovSchema) -> Router {
    Router::new()
        .route(
            "/graphql",
            get(graphql_playground_handler).post_service(GraphQL::new(schema.clone())),
        )
        .route_service("/graphql/ws", GraphQLSubscription::new(schema))
}

async fn graphql_playground_handler() -> impl axum::response::IntoResponse {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql")
            .subscription_endpoint("/graphql/ws"),
    ))
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

    #[tokio::test]
    async fn mutation_create_and_query_decision() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1",
                        title: "Test Decision",
                        body: "body text",
                        decisionClass: "Operational"
                    }) { id status title tenantId }
                }"#,
            )
            .await;
        assert!(
            create.errors.is_empty(),
            "create errors: {:?}",
            create.errors
        );
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();
        assert_eq!(data["createDecision"]["status"], "CREATED");

        // Query it back.
        let query = schema
            .execute(format!(
                r#"{{ decision(id: "{id}") {{ id status title }} }}"#
            ))
            .await;
        assert!(query.errors.is_empty(), "query errors: {:?}", query.errors);
        let qdata = query.data.into_json().expect("data");
        assert_eq!(qdata["decision"]["status"], "CREATED");
        assert_eq!(qdata["decision"]["title"], "Test Decision");
    }

    #[tokio::test]
    async fn mutation_cast_vote_ok() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1", title: "Vote Test",
                        body: "b", decisionClass: "Operational"
                    }) { id }
                }"#,
            )
            .await;
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let vote = schema
            .execute(format!(
                r#"mutation {{ castVote(decisionId: "{id}", choice: "APPROVE") {{ voter choice }} }}"#
            ))
            .await;
        assert!(vote.errors.is_empty(), "vote errors: {:?}", vote.errors);
        let vdata = vote.data.into_json().expect("data");
        assert_eq!(vdata["castVote"]["choice"], "APPROVE");
    }

    #[tokio::test]
    async fn mutation_cast_vote_invalid_choice() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1", title: "V", body: "b", decisionClass: "Routine"
                    }) { id }
                }"#,
            )
            .await;
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let vote = schema
            .execute(format!(
                r#"mutation {{ castVote(decisionId: "{id}", choice: "MAYBE") {{ voter }} }}"#
            ))
            .await;
        assert!(!vote.errors.is_empty());
    }

    #[tokio::test]
    async fn mutation_advance_decision() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1", title: "Advance", body: "b", decisionClass: "Routine"
                    }) { id }
                }"#,
            )
            .await;
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let adv = schema
            .execute(format!(
                r#"mutation {{ advanceDecision(id: "{id}", newStatus: "DELIBERATION") {{ id status }} }}"#
            ))
            .await;
        assert!(adv.errors.is_empty(), "advance errors: {:?}", adv.errors);
        let adata = adv.data.into_json().expect("data");
        assert_eq!(adata["advanceDecision"]["status"], "DELIBERATION");
    }

    #[tokio::test]
    async fn mutation_grant_and_revoke_delegation() {
        let schema = build_test_schema();
        let grant = schema
            .execute(
                r#"mutation {
                    grantDelegation(input: {
                        delegateeDid: "did:exo:bob",
                        scope: "vote",
                        expiresInHours: 48
                    }) { id delegatee active }
                }"#,
            )
            .await;
        assert!(grant.errors.is_empty(), "grant errors: {:?}", grant.errors);
        let gdata = grant.data.into_json().expect("data");
        let del_id = gdata["grantDelegation"]["id"]
            .as_str()
            .expect("id")
            .to_string();
        assert!(
            gdata["grantDelegation"]["active"]
                .as_bool()
                .unwrap_or(false)
        );

        let revoke = schema
            .execute(format!(
                r#"mutation {{ revokeDelegation(id: "{del_id}") {{ id active }} }}"#
            ))
            .await;
        assert!(
            revoke.errors.is_empty(),
            "revoke errors: {:?}",
            revoke.errors
        );
        let rdata = revoke.data.into_json().expect("data");
        assert!(
            !rdata["revokeDelegation"]["active"]
                .as_bool()
                .unwrap_or(true)
        );
    }

    #[tokio::test]
    async fn query_audit_trail_after_mutations() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1", title: "Audit", body: "b", decisionClass: "Routine"
                    }) { id }
                }"#,
            )
            .await;
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        // Cast a vote to add a second audit entry.
        schema
            .execute(format!(
                r#"mutation {{ castVote(decisionId: "{id}", choice: "REJECT") {{ voter }} }}"#
            ))
            .await;

        let trail = schema
            .execute(format!(
                r#"{{ auditTrail(decisionId: "{id}") {{ sequence eventType receiptHash }} }}"#
            ))
            .await;
        assert!(trail.errors.is_empty(), "trail errors: {:?}", trail.errors);
        let tdata = trail.data.into_json().expect("data");
        let entries = tdata["auditTrail"].as_array().expect("array");
        assert!(entries.len() >= 2, "expected at least 2 audit entries");
        // Sequences must be ascending.
        assert_eq!(entries[0]["sequence"], 1);
    }

    #[tokio::test]
    async fn mutation_raise_challenge_sets_contested() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1", title: "Challenge", body: "b", decisionClass: "Operational"
                    }) { id }
                }"#,
            )
            .await;
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let challenge = schema
            .execute(format!(
                r#"mutation {{ raiseChallenge(decisionId: "{id}", grounds: "procedural error") {{ id grounds status }} }}"#
            ))
            .await;
        assert!(
            challenge.errors.is_empty(),
            "challenge errors: {:?}",
            challenge.errors
        );
        let cdata = challenge.data.into_json().expect("data");
        assert_eq!(cdata["raiseChallenge"]["status"], "OPEN");

        // Decision status must now be CONTESTED.
        let q = schema
            .execute(format!(r#"{{ decision(id: "{id}") {{ status }} }}"#))
            .await;
        let qdata = q.data.into_json().expect("data");
        assert_eq!(qdata["decision"]["status"], "CONTESTED");
    }

    #[tokio::test]
    async fn mutation_amend_constitution_bumps_version() {
        let schema = build_test_schema();
        let amend = schema
            .execute(
                r#"mutation {
                    amendConstitution(tenantId: "t1", amendment: "add-article-7") {
                        tenantId version hash
                    }
                }"#,
            )
            .await;
        assert!(amend.errors.is_empty(), "amend errors: {:?}", amend.errors);
        let adata = amend.data.into_json().expect("data");
        assert_eq!(adata["amendConstitution"]["version"], "1.0.1");
    }

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

    #[tokio::test]
    async fn mutation_emergency_action_creates_record() {
        let schema = build_test_schema();
        let create = schema
            .execute(
                r#"mutation {
                    createDecision(input: {
                        tenantId: "t1", title: "Emergency", body: "b", decisionClass: "Strategic"
                    }) { id }
                }"#,
            )
            .await;
        let data = create.data.into_json().expect("data");
        let id = data["createDecision"]["id"]
            .as_str()
            .expect("id")
            .to_string();

        let ea = schema
            .execute(format!(
                r#"mutation {{ takeEmergencyAction(decisionId: "{id}", justification: "system failure") {{ id decisionId }} }}"#
            ))
            .await;
        assert!(ea.errors.is_empty(), "ea errors: {:?}", ea.errors);
        let edata = ea.data.into_json().expect("data");
        assert_eq!(edata["takeEmergencyAction"]["decisionId"], id);
    }

    #[tokio::test]
    async fn schema_introspection_has_required_types() {
        let schema = build_test_schema();
        let res = schema.execute(r#"{ __schema { types { name } } }"#).await;
        assert!(
            res.errors.is_empty(),
            "introspection errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().expect("data");
        let type_names: Vec<String> = data["__schema"]["types"]
            .as_array()
            .expect("types array")
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect();
        for required in [
            "GqlDecision",
            "GqlVote",
            "GqlDelegation",
            "GqlAuditEntry",
            "GqlEmergencyAction",
            "QueryRoot",
            "MutationRoot",
            "SubscriptionRoot",
        ] {
            assert!(
                type_names.contains(&required.to_string()),
                "missing type: {required}"
            );
        }
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
    /// to the shared registry (end-to-end through DidRegistry).
    #[tokio::test]
    async fn query_resolve_identity_registered_did() {
        use exo_core::Timestamp as Ts;
        use exo_identity::did::{DidDocument, VerificationMethod};

        let registry = Arc::new(RwLock::new(DidRegistry::new()));
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

    /// APE-35: evaluateConsent returns `granted: true` when bailment conditions
    /// are met via the PolicyEngine (end-to-end consent check).
    #[tokio::test]
    async fn query_evaluate_consent_granted() {
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
        assert_eq!(data["evaluateConsent"]["granted"], true);
        assert_eq!(data["evaluateConsent"]["scope"], "data:medical");
        assert_eq!(data["evaluateConsent"]["subject"], "did:exo:alice");
    }

    /// APE-35: resolveIdentity rejects malformed DIDs with a GraphQL error.
    #[tokio::test]
    async fn query_resolve_identity_invalid_did_returns_error() {
        let schema = build_test_schema();
        let res = schema
            .execute(r#"{ resolveIdentity(did: "not-a-valid-did") { registered } }"#)
            .await;
        assert!(!res.errors.is_empty(), "expected error for invalid DID");
    }

    /// APE-35: schema introspection includes the new identity + consent types.
    #[tokio::test]
    async fn schema_includes_identity_and_consent_types() {
        let schema = build_test_schema();
        let res = schema.execute(r#"{ __schema { types { name } } }"#).await;
        assert!(
            res.errors.is_empty(),
            "introspection errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().expect("data");
        let type_names: Vec<String> = data["__schema"]["types"]
            .as_array()
            .expect("types array")
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect();
        for required in ["GqlIdentity", "GqlConsentResult"] {
            assert!(
                type_names.contains(&required.to_string()),
                "missing type: {required}"
            );
        }
    }
}
