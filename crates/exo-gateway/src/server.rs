//! HTTP server skeleton — gateway configuration, lifecycle, and axum routing.
use std::sync::{Arc, RwLock};

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
};
use exo_core::{Did, Hash256, Signature, Timestamp};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest as GkActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{AuthorityChain, BailmentState, Permission, PermissionSet},
};
use exo_governance::conflict::ConflictDeclaration;
use exo_identity::{
    did::DidDocument,
    registry::{DidRegistry, LocalDidRegistry},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::{
    auth::{AuthenticatedActor, AuthenticationMetadata, Request as AuthRequest, authenticate},
    db,
    error::{GatewayError, Result},
    graphql,
    handlers::{health_handler as db_health_handler, vote_handler},
    rest::HealthResponse,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// TLS certificate and key paths for HTTPS termination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Gateway server configuration: bind address, TLS, and connection limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub bind_address: String,
    pub tls_config: Option<TlsConfig>,
    pub max_connections: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8443".into(),
            tls_config: None,
            max_connections: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Synchronous handle (kept for backward compatibility)
// ---------------------------------------------------------------------------

/// Handle returned by `start()` representing a validated gateway configuration.
#[derive(Debug)]
pub struct GatewayHandle {
    pub config: GatewayConfig,
    pub running: bool,
}

/// Validate config and return a handle.  Does not bind a port or start an
/// async runtime — use `serve()` for a running server.
pub fn start(config: GatewayConfig) -> Result<GatewayHandle> {
    if config.bind_address.is_empty() {
        return Err(GatewayError::BadRequest(
            "bind_address cannot be empty".into(),
        ));
    }
    if config.max_connections == 0 {
        return Err(GatewayError::BadRequest(
            "max_connections must be > 0".into(),
        ));
    }
    Ok(GatewayHandle {
        config,
        running: true,
    })
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Shared state injected into every axum handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// Live PostgreSQL pool.  `None` when the gateway starts without a DB
    /// URL (e.g. local dev without Docker Compose).
    pub pool: Option<sqlx::PgPool>,
    /// In-memory DID registry shared across all request handlers.
    pub registry: Arc<RwLock<LocalDidRegistry>>,
    /// Constitutional kernel — enforces the 8 invariants on every action.
    pub kernel: Arc<Kernel>,
    /// Wall-clock milliseconds at server start, used to compute uptime.
    start_ms: u64,
}

impl AppState {
    /// Create a new `AppState` with an optional database pool and a shared DID registry.
    pub fn new(pool: Option<sqlx::PgPool>, registry: Arc<RwLock<LocalDidRegistry>>) -> Self {
        // Bootstrap kernel with the all-invariants set.
        // constitution bytes are hashed for immutability verification.
        let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
        Self {
            pool,
            registry,
            kernel: Arc::new(kernel),
            start_ms: now_ms(),
        }
    }

    fn uptime_seconds(&self) -> u64 {
        now_ms().saturating_sub(self.start_ms) / 1000
    }

    /// Return the DB pool or a 503 if none is configured.
    pub fn require_db(&self) -> Result<&sqlx::PgPool> {
        self.pool.as_ref().ok_or_else(|| {
            GatewayError::Internal("no database configured — start with DATABASE_URL".into())
        })
    }

    /// Load conflict declarations for an actor.
    ///
    /// Currently returns an empty list until the DB schema includes a
    /// `conflict_declarations` table.  Handlers should call
    /// `.await.unwrap_or_default()` for graceful degradation.
    pub async fn load_conflict_declarations(
        &self,
        _actor: &Did,
    ) -> std::result::Result<Vec<ConflictDeclaration>, GatewayError> {
        // TODO: query `conflict_declarations` table when DB is available
        Ok(vec![])
    }

    /// Build an adjudication context for the given actor.
    ///
    /// **WO-009 SAFETY NOTE (CR-001 §8.9 — No-Admin Preservation):**
    /// The *deny-all dev scaffold* below is the **default path** and MUST
    /// remain unchanged.  `BailmentState::None` fails the `ConsentRequired`
    /// invariant and `AuthorityChain::default()` fails `AuthorityChainValid` —
    /// both are intentional.  Do NOT short-circuit this method or change
    /// `bailment_state` to `Active` without routing through the DB resolver
    /// activated by the `production-db` Cargo feature.
    ///
    /// When `production-db` is enabled **and** a DB pool is configured, the
    /// call is forwarded to `build_adjudication_context_from_db`.  If that
    /// query fails the method falls back to the scaffold so the gateway stays
    /// safe even under transient DB outages.
    // `actor` is only consumed inside the #[cfg(feature = "production-db")] block.
    // Suppress the "unused variable" lint when the feature is disabled.
    #[cfg_attr(not(feature = "production-db"), allow(unused_variables))]
    pub async fn build_adjudication_context(&self, actor: &Did) -> AdjudicationContext {
        // Production path — compiled only when the feature flag is set.
        #[cfg(feature = "production-db")]
        if let Some(pool) = &self.pool {
            match build_adjudication_context_from_db(pool, actor).await {
                Ok(ctx) => return ctx,
                Err(e) => {
                    tracing::warn!(
                        actor = %actor,
                        error = %e,
                        "DB adjudication context query failed; falling back to WO-009 scaffold"
                    );
                }
            }
        }

        // WO-009 deny-all scaffold (dev/test default and production fallback).
        AdjudicationContext {
            actor_roles: vec![],
            authority_chain: AuthorityChain::default(),
            consent_records: vec![],
            bailment_state: BailmentState::None,
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("vote")]),
            provenance: None,
            quorum_evidence: None,
            active_challenge_reason: None,
        }
    }
}

fn now_ms() -> u64 {
    exo_core::Timestamp::now_utc().physical_ms
}

const GATEWAY_SERVER_METADATA_INITIATIVE: &str =
    "Initiatives/fix-gateway-server-deterministic-metadata.md";
const GATEWAY_SESSION_LOGIN_DOMAIN: &str = "exo.gateway.session_login.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionIssueMetadata {
    created_at: i64,
    expires_at: i64,
}

impl SessionIssueMetadata {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let created_at = required_nonzero_i64(body, "createdAt")?;
        let expires_at = required_nonzero_i64(body, "expiresAt")?;
        if expires_at <= created_at {
            return Err(metadata_error(
                "session expiresAt must be greater than caller-supplied createdAt",
            ));
        }
        Ok(Self {
            created_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionLoginProof {
    timestamp: Timestamp,
    observed_at: Timestamp,
    signature: Signature,
}

impl SessionLoginProof {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let timestamp = Timestamp::new(
            required_nonzero_u64(body, "authTimestampPhysicalMs")?,
            required_u32(body, "authTimestampLogical")?,
        );
        let observed_at = Timestamp::new(
            required_nonzero_u64(body, "observedAt")?,
            required_u32(body, "observedAtLogical")?,
        );
        Ok(Self {
            timestamp,
            observed_at,
            signature: required_ed25519_signature_hex(body, "signature")?,
        })
    }
}

#[derive(Serialize)]
struct SessionLoginPayload<'a> {
    domain: &'static str,
    did: &'a str,
    created_at: i64,
    expires_at: i64,
    auth_timestamp_physical_ms: u64,
    auth_timestamp_logical: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionRefreshMetadata {
    observed_at: i64,
    expires_at: i64,
}

impl SessionRefreshMetadata {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let observed_at = required_nonzero_i64(body, "observedAt")?;
        let expires_at = required_nonzero_i64(body, "expiresAt")?;
        if expires_at <= observed_at {
            return Err(metadata_error(
                "session refresh expiresAt must be greater than caller-supplied observedAt",
            ));
        }
        Ok(Self {
            observed_at,
            expires_at,
        })
    }

    fn from_optional_body(body: Option<&serde_json::Value>) -> Result<Self> {
        let body = body.ok_or_else(|| {
            metadata_error(
                "session refresh requires caller-supplied observedAt and expiresAt metadata",
            )
        })?;
        Self::from_body(body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LayoutTemplateMetadata {
    created_at: i64,
    updated_at: i64,
}

impl LayoutTemplateMetadata {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let created_at = required_nonzero_i64(body, "createdAt")?;
        let updated_at = required_nonzero_i64(body, "updatedAt")?;
        if updated_at < created_at {
            return Err(metadata_error(
                "layout updatedAt must not be earlier than caller-supplied createdAt",
            ));
        }
        Ok(Self {
            created_at,
            updated_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FeedbackIssueCreateMetadata {
    id: String,
    created_at: i64,
}

impl FeedbackIssueCreateMetadata {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        Ok(Self {
            id: required_nonempty_string(body, "id")?,
            created_at: required_nonzero_i64(body, "createdAt")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeedbackIssueUpdateMetadata {
    updated_at: i64,
}

impl FeedbackIssueUpdateMetadata {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        Ok(Self {
            updated_at: required_nonzero_i64(body, "updatedAt")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdvancePaceMetadata {
    queued_at: i64,
}

impl AdvancePaceMetadata {
    fn from_optional_body(body: Option<&serde_json::Value>) -> Result<Self> {
        let body = body.ok_or_else(|| {
            metadata_error("advance pace requires caller-supplied queuedAt metadata")
        })?;
        Ok(Self {
            queued_at: required_nonzero_i64(body, "queuedAt")?,
        })
    }
}

fn required_nonempty_string(body: &serde_json::Value, field: &str) -> Result<String> {
    let value = body
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| metadata_error(format!("{field} must be caller-supplied")))?;
    if value.trim().is_empty() {
        return Err(metadata_error(format!("{field} must not be empty")));
    }
    Ok(value.to_owned())
}

fn required_nonzero_i64(body: &serde_json::Value, field: &str) -> Result<i64> {
    let value = body
        .get(field)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| metadata_error(format!("{field} must be caller-supplied")))?;
    if value <= 0 {
        return Err(metadata_error(format!(
            "{field} must be a positive non-zero epoch millisecond"
        )));
    }
    Ok(value)
}

fn required_nonzero_u64(body: &serde_json::Value, field: &str) -> Result<u64> {
    let value = body
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| metadata_error(format!("{field} must be caller-supplied")))?;
    if value == 0 {
        return Err(metadata_error(format!(
            "{field} must be a positive non-zero HLC physical millisecond"
        )));
    }
    Ok(value)
}

fn required_u32(body: &serde_json::Value, field: &str) -> Result<u32> {
    let value = body
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| metadata_error(format!("{field} must be caller-supplied")))?;
    u32::try_from(value).map_err(|_| metadata_error(format!("{field} must fit in u32")))
}

fn required_ed25519_signature_hex(body: &serde_json::Value, field: &str) -> Result<Signature> {
    let encoded = required_nonempty_string(body, field)?;
    let bytes = hex::decode(&encoded)
        .map_err(|e| metadata_error(format!("{field} must be hex-encoded Ed25519: {e}")))?;
    let signature_bytes: [u8; 64] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        metadata_error(format!("{field} must be 64 bytes, got {}", bytes.len()))
    })?;
    let signature = Signature::Ed25519(signature_bytes);
    if signature.is_empty() {
        return Err(metadata_error(format!(
            "{field} must not be empty or all-zero"
        )));
    }
    Ok(signature)
}

fn session_login_payload_hash(
    did: &str,
    metadata: &SessionIssueMetadata,
    timestamp: &Timestamp,
) -> Result<Hash256> {
    let payload = SessionLoginPayload {
        domain: GATEWAY_SESSION_LOGIN_DOMAIN,
        did,
        created_at: metadata.created_at,
        expires_at: metadata.expires_at,
        auth_timestamp_physical_ms: timestamp.physical_ms,
        auth_timestamp_logical: timestamp.logical,
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded)
        .map_err(|e| GatewayError::Internal(format!("session login payload CBOR: {e:?}")))?;
    Ok(Hash256::digest(&encoded))
}

fn authenticate_session_login(
    did: &str,
    metadata: &SessionIssueMetadata,
    proof: &SessionLoginProof,
    registry: &dyn DidRegistry,
) -> Result<AuthenticatedActor> {
    let body_hash = session_login_payload_hash(did, metadata, &proof.timestamp)?;
    let request = AuthRequest {
        actor_did: did.to_owned(),
        action: "gateway_session_login".to_owned(),
        body_hash,
        signature: proof.signature.clone(),
        timestamp: proof.timestamp,
    };
    let auth_metadata = AuthenticationMetadata::new(proof.observed_at)?;
    authenticate(&request, registry, auth_metadata)
}

fn metadata_error(reason: impl Into<String>) -> GatewayError {
    GatewayError::BadRequest(format!(
        "{}; see {}",
        reason.into(),
        GATEWAY_SERVER_METADATA_INITIATIVE
    ))
}

fn metadata_error_response(error: GatewayError) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "missing_or_invalid_caller_supplied_metadata",
            "message": error.to_string(),
            "initiative": GATEWAY_SERVER_METADATA_INITIATIVE
        })),
    )
        .into_response()
}

fn generate_session_token() -> Result<String> {
    let mut token_bytes = [0u8; 32];
    getrandom::getrandom(&mut token_bytes)
        .map_err(|e| GatewayError::Internal(format!("session token entropy unavailable: {e}")))?;
    Ok(hex::encode(token_bytes))
}

// ---------------------------------------------------------------------------
// Production DB adjudication context resolver (APE-53)
// ---------------------------------------------------------------------------

/// Build an `AdjudicationContext` by loading the actor's roles, consent
/// records, and authority chain from the live database.
///
/// Only compiled when the `production-db` Cargo feature is enabled.  Callers
/// should not invoke this directly — use `AppState::build_adjudication_context`
/// which dispatches here when both the feature flag and a DB pool are present.
///
/// **WO-009**: never call this outside the feature-gated dispatch to avoid
/// inadvertently bypassing the deny-all scaffold in dev/test environments.
#[cfg(feature = "production-db")]
async fn build_adjudication_context_from_db(
    pool: &sqlx::PgPool,
    actor: &Did,
) -> Result<AdjudicationContext> {
    use exo_gatekeeper::types::{
        AuthorityChain as GkChain, BailmentState as GkBailment, ConsentRecord, GovernmentBranch,
        Role,
    };

    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let actor_str = actor.as_str();

    let role_rows = crate::db::load_agent_roles(pool, actor_str, now)
        .await
        .map_err(|e| GatewayError::Internal(format!("adjudication roles query: {e}")))?;

    let consent_rows = crate::db::load_consent_records(pool, actor_str, now)
        .await
        .map_err(|e| GatewayError::Internal(format!("adjudication consents query: {e}")))?;

    let chain_row = crate::db::load_authority_chain(pool, actor_str, now)
        .await
        .map_err(|e| GatewayError::Internal(format!("adjudication chain query: {e}")))?;

    // Convert role rows → `Role` values.
    let actor_roles: Vec<Role> = role_rows
        .iter()
        .map(|r| {
            let branch = match r.branch.as_str() {
                "legislative" => GovernmentBranch::Legislative,
                "judicial" => GovernmentBranch::Judicial,
                _ => GovernmentBranch::Executive,
            };
            Role {
                name: r.role.clone(),
                branch,
            }
        })
        .collect();

    // Convert consent rows → `ConsentRecord` values.
    let consent_records: Vec<ConsentRecord> = consent_rows
        .iter()
        .filter_map(|r| {
            let subject = Did::new(&r.subject_did).ok()?;
            Some(ConsentRecord {
                subject,
                granted_to: actor.clone(),
                scope: r.scope.clone(),
                active: r.status == "active",
            })
        })
        .collect();

    // Derive `BailmentState` from the first active consent record.
    // `BailmentState::None` is the safe default when no active consent exists.
    let bailment_state = consent_rows
        .iter()
        .find(|r| r.status == "active")
        .and_then(|r| {
            let bailor = Did::new(&r.subject_did).ok()?;
            Some(GkBailment::Active {
                bailor,
                bailee: actor.clone(),
                scope: r.scope.clone(),
            })
        })
        .unwrap_or(GkBailment::None);

    // Deserialise the stored `AuthorityChain` blob; fall back to empty chain.
    let authority_chain = chain_row
        .as_ref()
        .and_then(|row| serde_json::from_value::<GkChain>(row.chain_json.clone()).ok())
        .unwrap_or_default();

    Ok(AdjudicationContext {
        actor_roles,
        authority_chain,
        consent_records,
        bailment_state,
        human_override_preserved: true,
        actor_permissions: PermissionSet::new(vec![Permission::new("vote")]),
        // Provenance is per-action, not per-actor; callers that need full
        // ProvenanceVerifiable enforcement must attach it before adjudication.
        provenance: None,
        quorum_evidence: None,
        active_challenge_reason: None,
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /health — always returns 200 OK.
async fn handle_health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_seconds: state.uptime_seconds(),
    })
}

/// GET /ready — returns 200 when the DB pool is reachable, 503 otherwise.
async fn handle_ready(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let (status_str, http_status) = match &state.pool {
        Some(pool) => match sqlx::query("SELECT 1").fetch_one(pool).await {
            Ok(_) => ("ok", StatusCode::OK),
            Err(_) => ("db_unavailable", StatusCode::SERVICE_UNAVAILABLE),
        },
        None => ("no_db_configured", StatusCode::SERVICE_UNAVAILABLE),
    };
    let body = HealthResponse {
        status: status_str.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_seconds: state.uptime_seconds(),
    };
    (http_status, Json(body))
}

// ---------------------------------------------------------------------------
// DID / Auth / Agent handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/auth/register — register a new DID document.
///
/// Body: a `DidDocument` JSON object.  Returns 201 on success, 409 if the
/// DID is already registered.
async fn handle_auth_register(
    State(state): State<AppState>,
    Json(doc): Json<DidDocument>,
) -> impl IntoResponse {
    let did_str = doc.id.as_str().to_owned();
    let mut reg = state.registry.write().unwrap_or_else(|e| e.into_inner());
    match reg.register(doc) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "did": did_str, "status": "registered" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/v1/auth/me — resolve the caller's DID document.
///
/// Requires `X-Actor-Did: did:exo:<id>` request header.
async fn handle_auth_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let did_str = match headers.get("x-actor-did").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing X-Actor-Did header" })),
            )
                .into_response();
        }
    };
    let did = match Did::new(&did_str) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid DID format" })),
            )
                .into_response();
        }
    };
    let reg = state.registry.read().unwrap_or_else(|e| e.into_inner());
    match reg.resolve(&did) {
        Some(doc) => Json(doc.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "DID not found" })),
        )
            .into_response(),
    }
}

/// GET /api/v1/agents — list all registered DID identifiers.
async fn handle_agents_list(State(state): State<AppState>) -> impl IntoResponse {
    let reg = state.registry.read().unwrap_or_else(|e| e.into_inner());
    let dids: Vec<String> = reg.list_dids().into_iter().map(|s| s.to_owned()).collect();
    Json(serde_json::json!({ "agents": dids }))
}

/// GET /api/v1/agents/:did — resolve a single DID document by its identifier.
async fn handle_agent_get(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
) -> impl IntoResponse {
    let did = match Did::new(&did_str) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid DID format" })),
            )
                .into_response();
        }
    };
    let reg = state.registry.read().unwrap_or_else(|e| e.into_inner());
    match reg.resolve(&did) {
        Some(doc) => Json(doc.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "DID not found" })),
        )
            .into_response(),
    }
}

/// GET /api/v1/identity/:did/score — return a trust-score for a registered DID.
///
/// Scores are expressed as basis points (integer, 0–10000 = 0%–100%):
/// - 0     DID not registered
/// - 5000  Registered but revoked or has no active verification methods
/// - 7500  Registered with active verification methods
/// - 10000 (reserved for governance-attested DIDs — future work)
async fn handle_identity_score(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
) -> impl IntoResponse {
    let did = match Did::new(&did_str) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid DID format" })),
            )
                .into_response();
        }
    };
    let reg = state.registry.read().unwrap_or_else(|e| e.into_inner());
    match reg.resolve(&did) {
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "did": did_str,
                "registered": false,
                "score_bps": 0u32,
                "factors": { "registered": false }
            })),
        )
            .into_response(),
        Some(doc) => {
            let has_active_keys = !doc.verification_methods.is_empty();
            let score_bps: u32 = if doc.revoked || !has_active_keys {
                5000
            } else {
                7500
            };
            Json(serde_json::json!({
                "did": did_str,
                "registered": true,
                "score_bps": score_bps,
                "factors": {
                    "registered": true,
                    "has_active_verification_methods": has_active_keys,
                    "revoked": doc.revoked,
                }
            }))
            .into_response()
        }
    }
}

/// GET /api/v1/tenants/:id/constitution — return the ExoChain constitutional invariants.
///
/// The constitution is embedded at compile time from the `exo-gatekeeper` invariant
/// definitions.  Every tenant in an ExoChain deployment shares the same constitutional
/// fabric; the `:id` path is accepted for API compatibility but currently ignored.
async fn handle_get_constitution(Path(_id): Path<String>) -> impl IntoResponse {
    Json(serde_json::json!({
        "version": "exochain-constitution-v1",
        "invariants": [
            {
                "name": "SeparationOfPowers",
                "description": "No single actor may hold legislative + executive + judicial power."
            },
            {
                "name": "ConsentRequired",
                "description": "Action denied without active bailment consent."
            },
            {
                "name": "NoSelfGrant",
                "description": "An actor cannot expand its own permissions."
            },
            {
                "name": "HumanOverride",
                "description": "Emergency human intervention must always be possible."
            },
            {
                "name": "KernelImmutability",
                "description": "Kernel configuration cannot be modified after creation."
            },
            {
                "name": "AuthorityChainValid",
                "description": "Authority chain must be valid and unbroken."
            },
            {
                "name": "QuorumLegitimate",
                "description": "Quorum decisions must meet threshold requirements."
            },
            {
                "name": "ProvenanceVerifiable",
                "description": "All actions must have verifiable provenance."
            }
        ]
    }))
}

/// GET /api/v1/users — list all registered user DIDs.
///
/// Currently backed by the same DID registry as the agents list.  In a multi-tenant
/// deployment the user and agent registries would be separated; for now they share
/// the in-memory store.
async fn handle_users_list(State(state): State<AppState>) -> impl IntoResponse {
    let reg = state.registry.read().unwrap_or_else(|e| e.into_inner());
    let dids: Vec<String> = reg.list_dids().into_iter().map(|s| s.to_owned()).collect();
    Json(serde_json::json!({ "users": dids }))
}

/// GET /api/v1/decisions/:id — retrieve a specific decision record.
///
/// Returns the full serialized `DecisionObject` stored in the `decisions` table.
/// Requires a DB pool; returns 503 when the gateway starts without `DATABASE_URL`.
async fn handle_decision_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "database not configured",
                    "message": "Start the gateway with DATABASE_URL to enable decision queries."
                })),
            )
                .into_response();
        }
    };
    match sqlx::query("SELECT payload FROM decisions WHERE id_hash = $1")
        .bind(&id)
        .fetch_optional(db)
        .await
    {
        Ok(Some(row)) => match row.try_get::<serde_json::Value, _>("payload") {
            Ok(payload) => Json::<serde_json::Value>(payload).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "decision not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/v1/audit/:decision_id — retrieve the audit trail for a decision.
///
/// Queries the `audit_entries` table populated by the vote handler.  Requires a DB pool.
async fn handle_audit_trail(
    State(state): State<AppState>,
    Path(decision_id): Path<String>,
) -> impl IntoResponse {
    let pool = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "database not configured",
                    "message": "Start the gateway with DATABASE_URL to enable audit queries."
                })),
            )
                .into_response();
        }
    };
    match db::list_audit_entries_for_decision(pool, &decision_id).await {
        Ok(rows) => {
            let entries: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|entry| {
                    serde_json::json!({
                        "sequence": entry.sequence,
                        "prev_hash": entry.prev_hash,
                        "event_hash": entry.event_hash,
                        "event_type": entry.event_type,
                        "actor": entry.actor,
                        "tenant_id": entry.tenant_id,
                        "decision_id": entry.decision_id,
                        "timestamp_physical_ms": entry.timestamp_physical_ms,
                        "timestamp_logical": entry.timestamp_logical,
                        "entry_hash": entry.entry_hash,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "decision_id": decision_id,
                "audit_entries": entries,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/v1/agents/enroll — enroll an agent by registering its DID document.
///
/// Identical to `POST /api/v1/auth/register`; the distinct path expresses the
/// agent-specific enrollment workflow while sharing the underlying DID registry.
async fn handle_agents_enroll(
    State(state): State<AppState>,
    Json(doc): Json<DidDocument>,
) -> impl IntoResponse {
    let did_str = doc.id.as_str().to_owned();
    let mut reg = state.registry.write().unwrap_or_else(|e| e.into_inner());
    match reg.register(doc) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "did": did_str, "status": "enrolled" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Session auth handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/auth/login — authenticate a DID and issue a session token.
///
/// Body includes the actor DID, session metadata, HLC authentication metadata,
/// and an Ed25519 `signature` hex string over the canonical domain-tagged
/// session-login payload.
///
/// Returns a 256-bit bearer session token stored in the `sessions` table:
/// ```sql
/// CREATE TABLE IF NOT EXISTS sessions (
///     token       TEXT    PRIMARY KEY,
///     actor_did   TEXT    NOT NULL,
///     created_at  BIGINT  NOT NULL,
///     expires_at  BIGINT  NOT NULL,
///     revoked     BOOLEAN NOT NULL DEFAULT FALSE
/// );
/// ```
/// Returns 503 when no DB pool is configured, 401 when the DID is not
/// registered, and 200 with the token on success.
async fn handle_auth_login(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "database not configured",
                    "message": "Start the gateway with DATABASE_URL to enable session auth."
                })),
            )
                .into_response();
        }
    };
    let did_str = match body.get("did").and_then(|v| v.as_str()) {
        Some(s) => s.to_owned(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing 'did' field" })),
            )
                .into_response();
        }
    };
    if Did::new(&did_str).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid DID format" })),
        )
            .into_response();
    }
    let metadata = match SessionIssueMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    let proof = match SessionLoginProof::from_body(&body) {
        Ok(proof) => proof,
        Err(e) => return metadata_error_response(e),
    };
    {
        let reg = state.registry.read().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = authenticate_session_login(&did_str, &metadata, &proof, &*reg) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "authentication failed",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    }
    let token = match generate_session_token() {
        Ok(token) => token,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    match sqlx::query(
        "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
         VALUES ($1, $2, $3, $4, false)",
    )
    .bind(&token)
    .bind(&did_str)
    .bind(metadata.created_at)
    .bind(metadata.expires_at)
    .execute(db)
    .await
    {
        Ok(_) => Json(serde_json::json!({
            "token": token,
            "actor_did": did_str,
            "expires_at": metadata.expires_at,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/v1/auth/token — bearer-token grant (same semantics as login).
///
/// Accepts the same body as `/auth/login` and produces an identical response.
/// The distinct path mirrors OAuth2 token-endpoint convention.
async fn handle_auth_token(
    State(state): State<AppState>,
    body: Json<serde_json::Value>,
) -> impl IntoResponse {
    handle_auth_login(State(state), body).await
}

/// POST /api/v1/auth/refresh — extend an existing session.
///
/// Requires `Authorization: Bearer <token>` plus a JSON body with caller-supplied
/// `observedAt` and replacement `expiresAt` metadata.
/// Returns 401 when the token is missing, expired, or revoked; 503 without DB.
async fn handle_auth_refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "database not configured",
                    "message": "Start the gateway with DATABASE_URL to enable session refresh."
                })),
            )
                .into_response();
        }
    };
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing or malformed Authorization header" })),
            )
                .into_response();
        }
    };
    let body_ref = body.as_ref().map(|Json(value)| value);
    let metadata = match SessionRefreshMetadata::from_optional_body(body_ref) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    match sqlx::query(
        "UPDATE sessions SET expires_at = $1 \
         WHERE token = $2 AND expires_at > $3 AND revoked = false",
    )
    .bind(metadata.expires_at)
    .bind(&token)
    .bind(metadata.observed_at)
    .execute(db)
    .await
    {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "token expired, revoked, or not found" })),
        )
            .into_response(),
        Ok(_) => Json(serde_json::json!({
            "token": token,
            "expires_at": metadata.expires_at,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/v1/auth/logout — revoke the caller's session token.
///
/// Requires `Authorization: Bearer <token>`.  Marks the session row as
/// `revoked = true`.  Returns 401 for unknown tokens; 503 without DB.
async fn handle_auth_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "database not configured",
                    "message": "Start the gateway with DATABASE_URL to enable session logout."
                })),
            )
                .into_response();
        }
    };
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing or malformed Authorization header" })),
            )
                .into_response();
        }
    };
    match sqlx::query("UPDATE sessions SET revoked = true WHERE token = $1")
        .bind(&token)
        .execute(db)
        .await
    {
        Ok(r) if r.rows_affected() == 0 => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "token not found" })),
        )
            .into_response(),
        Ok(_) => Json(serde_json::json!({ "status": "logged_out" })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/v1/auth/saml/callback — SAML 2.0 SP callback (not configured).
///
/// ExoChain uses DID-based authentication.  SAML integration is reserved for
/// enterprise tenants and is not yet configured in this deployment.
async fn handle_auth_saml_callback() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "saml_not_configured",
            "message": "SAML 2.0 SP is not configured for this ExoChain deployment. \
                        Use DID-based authentication via /api/v1/auth/login."
        })),
    )
}

// ---------------------------------------------------------------------------
// Constitutional action handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/agents/:did/advance-pace — advance a constitutional pacing token.
/// POST /api/v1/users/:did/advance-pace  — same for user DIDs.
///
/// Adjudicated by the Kernel before any DB write.  Without a valid authority
/// chain the Kernel returns 403.  Without a DB pool the handler returns 503.
/// On success returns 202 Accepted.
async fn handle_advance_pace(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let did = match Did::new(&did_str) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid DID format" })),
            )
                .into_response();
        }
    };
    // Build an adjudication context for this actor.
    let ctx = state.build_adjudication_context(&did).await;
    let action = GkActionRequest {
        actor: did.clone(),
        action: "advance_pace".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("advance_pace")]),
        is_self_grant: false,
        modifies_kernel: false,
    };
    match state.kernel.adjudicate(&action, &ctx) {
        Verdict::Permitted => {}
        Verdict::Denied { .. } | Verdict::Escalated { .. } => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "forbidden",
                    "message": "Kernel rejected advance-pace: authority chain invalid or \
                                consent not established."
                })),
            )
                .into_response();
        }
    }
    // Require DB for the pace record.
    let _db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "database not configured",
                    "message": "Start the gateway with DATABASE_URL to enable pace advancement."
                })),
            )
                .into_response();
        }
    };
    let body_ref = body.as_ref().map(|Json(value)| value);
    let metadata = match AdvancePaceMetadata::from_optional_body(body_ref) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "pace_advanced",
            "actor_did": did_str,
            "queued_at": metadata.queued_at,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Legal / eDiscovery handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/ediscovery/export — legal hold / eDiscovery export request.
///
/// Stub endpoint reserved for legal compliance tooling.  Returns 501 until a
/// legal-hold workflow is configured for this deployment.
async fn handle_ediscovery_export() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "ediscovery_not_configured",
            "message": "eDiscovery export is not configured for this ExoChain deployment. \
                        Contact the system administrator to enable legal hold features."
        })),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the bearer token from an `Authorization: Bearer <token>` header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_owned())
}

// ---------------------------------------------------------------------------
// Dashboard handlers (layout templates + feedback issues)
// ---------------------------------------------------------------------------

/// PUT /api/v1/layout-templates — upsert a layout template.
async fn handle_layout_template_put(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(s) => s.to_owned(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing 'id' field" })),
            )
                .into_response();
        }
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled");
    let layout_json = body.get("layout").cloned().unwrap_or(serde_json::json!([]));
    let hidden_panels = body
        .get("hiddenPanels")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let is_built_in = body
        .get("isBuiltIn")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let metadata = match LayoutTemplateMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };

    // Extract user DID from bearer token session if available.
    // For now, accept an optional `userDid` field in the body.
    let user_did_owned = body
        .get("userDid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let user_did = user_did_owned.as_deref();

    match crate::db::upsert_layout_template(
        db,
        &id,
        user_did,
        name,
        &layout_json,
        &hidden_panels,
        is_built_in,
        metadata.created_at,
        metadata.updated_at,
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": id, "status": "saved" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// DELETE /api/v1/layout-templates/:id — delete a user layout template.
async fn handle_layout_template_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };
    match crate::db::delete_layout_template(db, &id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": id, "status": "deleted" })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "template not found or is built-in" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/v1/layout-templates — list all layout templates.
async fn handle_layout_templates_list(State(state): State<AppState>) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };
    match crate::db::list_layout_templates(db, None).await {
        Ok(rows) => {
            let templates: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "layout": r.layout_json,
                        "hiddenPanels": r.hidden_panels,
                        "isBuiltIn": r.is_built_in,
                        "createdAt": r.created_at,
                        "updatedAt": r.updated_at,
                    })
                })
                .collect();
            Json(serde_json::json!({ "templates": templates })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/v1/feedback-issues — file a new feedback issue.
async fn handle_feedback_issue_create(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };
    let title = match body.get("title").and_then(|v| v.as_str()) {
        Some(s) => s.to_owned(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing 'title' field" })),
            )
                .into_response();
        }
    };
    let source_widget_id = match body.get("sourceWidgetId").and_then(|v| v.as_str()) {
        Some(s) => s.to_owned(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing 'sourceWidgetId' field" })),
            )
                .into_response();
        }
    };
    let metadata = match FeedbackIssueCreateMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let severity = body
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let category = body
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("bug");
    let source_module_type = body
        .get("sourceModuleType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let reporter_did_owned = body
        .get("reporterDid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let reporter_did = reporter_did_owned.as_deref();
    let widget_state = body.get("widgetState");
    let browser_info = body.get("browserInfo");

    match crate::db::insert_feedback_issue(
        db,
        &metadata.id,
        &title,
        description,
        severity,
        category,
        &source_widget_id,
        source_module_type,
        reporter_did,
        widget_state,
        browser_info,
        metadata.created_at,
    )
    .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "id": metadata.id, "status": "filed" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/v1/feedback-issues — list feedback issues.
async fn handle_feedback_issues_list(State(state): State<AppState>) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };
    match crate::db::list_feedback_issues(db, None).await {
        Ok(rows) => {
            let issues: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "title": r.title,
                        "description": r.description,
                        "severity": r.severity,
                        "category": r.category,
                        "status": r.status,
                        "sourceWidgetId": r.source_widget_id,
                        "sourceModuleType": r.source_module_type,
                        "reporterDid": r.reporter_did,
                        "assignedAgentTeam": r.assigned_agent_team,
                        "createdAt": r.created_at,
                        "updatedAt": r.updated_at,
                    })
                })
                .collect();
            Json(serde_json::json!({ "issues": issues })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// PATCH /api/v1/feedback-issues/:id — update issue status/assignment.
async fn handle_feedback_issue_update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };
    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("open");
    let agent_team_owned = body
        .get("assignedAgentTeam")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let agent_team = agent_team_owned.as_deref();
    let notes_owned = body
        .get("resolutionNotes")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let notes = notes_owned.as_deref();
    let metadata = match FeedbackIssueUpdateMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };

    match crate::db::update_feedback_issue_status(
        db,
        &id,
        status,
        agent_team,
        notes,
        metadata.updated_at,
    )
    .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": id, "status": status })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "issue not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the axum `Router` with all constitutional middleware wired.
///
/// All 20 `RestRoute` paths are registered.  Unimplemented handlers return
/// 501 until the full handler stack lands in a follow-up PR.
pub fn build_router(state: AppState) -> Router {
    // GraphQL sub-router shares the gateway's DID registry so that
    // `resolveIdentity` queries see any DIDs registered via REST.
    let gql_state = graphql::AppState::new_arc_with_registry(state.registry.clone());
    let schema = graphql::build_schema(gql_state);
    let gql_router = graphql::graphql_router(schema);

    Router::new()
        // Probes
        .route("/health", get(handle_health))
        .route("/ready", get(handle_ready))
        // DB health deep probe (requires pool to be configured)
        .route("/health/db", get(db_health_handler))
        // Decisions — vote handler enforces ConflictAdjudication + TNC-01
        .route("/api/v1/decisions/:id", get(handle_decision_get))
        .route("/api/v1/decisions", post(vote_handler))
        // Auth
        .route("/api/v1/auth/token", post(handle_auth_token))
        .route(
            "/api/v1/auth/saml/callback",
            post(handle_auth_saml_callback),
        )
        .route("/api/v1/auth/register", post(handle_auth_register))
        .route("/api/v1/auth/login", post(handle_auth_login))
        .route("/api/v1/auth/refresh", post(handle_auth_refresh))
        .route("/api/v1/auth/me", get(handle_auth_me))
        .route("/api/v1/auth/logout", post(handle_auth_logout))
        // Agents (static route before parameterised to avoid ambiguity)
        .route("/api/v1/agents/enroll", post(handle_agents_enroll))
        .route("/api/v1/agents", get(handle_agents_list))
        .route("/api/v1/agents/:did", get(handle_agent_get))
        .route(
            "/api/v1/agents/:did/advance-pace",
            post(handle_advance_pace),
        )
        // Identity
        .route("/api/v1/identity/:did/score", get(handle_identity_score))
        // Tenant
        .route(
            "/api/v1/tenants/:id/constitution",
            get(handle_get_constitution),
        )
        // Legal
        .route("/api/v1/ediscovery/export", post(handle_ediscovery_export))
        // Audit
        .route("/api/v1/audit/:decision_id", get(handle_audit_trail))
        // Users
        .route("/api/v1/users", get(handle_users_list))
        .route("/api/v1/users/:did/advance-pace", post(handle_advance_pace))
        // Dashboard layout templates
        .route(
            "/api/v1/layout-templates",
            get(handle_layout_templates_list).put(handle_layout_template_put),
        )
        .route(
            "/api/v1/layout-templates/:id",
            axum::routing::delete(handle_layout_template_delete),
        )
        // Feedback issues (mandated reporter)
        .route(
            "/api/v1/feedback-issues",
            get(handle_feedback_issues_list).post(handle_feedback_issue_create),
        )
        .route(
            "/api/v1/feedback-issues/:id",
            axum::routing::patch(handle_feedback_issue_update),
        )
        .with_state(state)
        // GraphQL sub-router has its own state — merge after with_state()
        .merge(gql_router)
        // Emit structured tracing spans for every request/response.
        .layer(TraceLayer::new_for_http())
}

// ---------------------------------------------------------------------------
// Graceful shutdown signal
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let sigterm = async {
        let mut stream = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|_| panic!("failed to install SIGTERM handler"));
        stream.recv().await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C — shutting down");
        }
        _ = sigterm => {
            tracing::info!("Received SIGTERM — shutting down");
        }
    }
}

// ---------------------------------------------------------------------------
// Async server entry point
// ---------------------------------------------------------------------------

/// Bind to `config.bind_address`, serve all routes, and drain on SIGTERM /
/// Ctrl+C.  Returns once shutdown is complete.
pub async fn serve(config: GatewayConfig, pool: Option<sqlx::PgPool>) -> Result<()> {
    serve_with_extra_routes(config, pool, None).await
}

/// Like [`serve`] but merges an additional [`Router`] into the app.
///
/// The `extra` router is merged *after* the gateway's own routes, giving
/// callers a way to inject endpoints (e.g. `/metrics`) without modifying
/// this crate.
pub async fn serve_with_extra_routes(
    config: GatewayConfig,
    pool: Option<sqlx::PgPool>,
    extra: Option<Router>,
) -> Result<()> {
    let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
    let state = AppState::new(pool, registry);
    let mut app = build_router(state);

    if let Some(extra_router) = extra {
        app = app.merge(extra_router);
    }

    let listener = TcpListener::bind(&config.bind_address)
        .await
        .map_err(|e| GatewayError::Internal(format!("bind failed: {e}")))?;

    tracing::info!("exo-gateway listening on {}", config.bind_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| GatewayError::Internal(format!("server error: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::{body::Body, http::Request};
    use exo_core::{
        Timestamp,
        crypto::{generate_keypair, sign},
    };
    use exo_identity::did::{DidDocument, VerificationMethod};
    use tower::ServiceExt;

    use super::*; // for .oneshot()

    fn state() -> AppState {
        AppState::new(None, Arc::new(RwLock::new(LocalDidRegistry::new())))
    }

    /// Build a minimal DidDocument for use in registration tests.
    fn minimal_doc(did_str: &str) -> DidDocument {
        let did = Did::new(did_str).expect("valid DID");
        DidDocument {
            id: did,
            public_keys: vec![],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::ZERO,
            updated: Timestamp::ZERO,
            revoked: false,
        }
    }

    fn signing_registry() -> (Arc<RwLock<LocalDidRegistry>>, exo_core::SecretKey) {
        let did = Did::new("did:exo:login-alice").unwrap();
        let (pk, sk) = generate_keypair();
        let multibase = format!("z{}", bs58::encode(pk.as_bytes()).into_string());
        let doc = DidDocument {
            id: did.clone(),
            public_keys: vec![pk],
            authentication: vec![],
            verification_methods: vec![VerificationMethod {
                id: "did:exo:login-alice#key-1".into(),
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
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        (registry, sk)
    }

    async fn gateway_test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("./migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    // --- GatewayConfig / start() (existing tests preserved) ---

    #[test]
    fn start_default() {
        let h = start(GatewayConfig::default()).unwrap();
        assert!(h.running);
        assert_eq!(h.config.bind_address, "127.0.0.1:8443");
    }
    #[test]
    fn start_empty_addr() {
        let c = GatewayConfig {
            bind_address: String::new(),
            ..Default::default()
        };
        assert!(start(c).is_err());
    }
    #[test]
    fn start_zero_connections() {
        let c = GatewayConfig {
            max_connections: 0,
            ..Default::default()
        };
        assert!(start(c).is_err());
    }
    #[test]
    fn config_serde() {
        let c = GatewayConfig::default();
        let j = serde_json::to_string(&c).unwrap();
        let r: GatewayConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(r.bind_address, c.bind_address);
    }
    #[test]
    fn tls_config_serde() {
        let t = TlsConfig {
            cert_path: "c".into(),
            key_path: "k".into(),
        };
        let j = serde_json::to_string(&t).unwrap();
        let r: TlsConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(r.cert_path, "c");
    }
    #[test]
    fn config_with_tls() {
        let c = GatewayConfig {
            tls_config: Some(TlsConfig {
                cert_path: "c".into(),
                key_path: "k".into(),
            }),
            ..Default::default()
        };
        let h = start(c).unwrap();
        assert!(h.config.tls_config.is_some());
    }

    // --- Router integration tests (no network listener needed) ---

    #[tokio::test]
    async fn health_returns_200() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ready_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/does-not-exist")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn defined_api_routes_return_non_404() {
        // Routes that return non-404 regardless of body/headers.
        // NOTE: /api/v1/agents/:did is excluded here because it returns 404
        // when the DID is not registered — that behaviour is tested separately.
        let paths = [
            // decisions GET returns 503 (no DB) not 404 — route exists
            "/api/v1/decisions/some-id",
            "/api/v1/auth/me",
            "/api/v1/agents",
            // identity score for unregistered DID returns 404 by design;
            // excluded here — tested separately in identity_score_* tests
            "/api/v1/users",
            // audit returns 503 (no DB) not 404 — route exists
            "/api/v1/audit/decision-123",
            "/api/v1/tenants/tenant-1/constitution",
        ];
        for path in paths {
            let app = build_router(state());
            let resp = app
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "expected non-404 for GET {path}"
            );
        }
    }

    // --- New DID / auth / agent endpoint tests ---

    #[tokio::test]
    async fn auth_register_returns_201() {
        let body = serde_json::to_string(&minimal_doc("did:exo:tester")).unwrap();
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn auth_register_duplicate_returns_409() {
        let doc = minimal_doc("did:exo:dup");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc.clone()).unwrap();
        let st = AppState::new(None, registry);
        let body = serde_json::to_string(&doc).unwrap();
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn auth_me_missing_header_returns_400() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_me_known_did_returns_200() {
        let doc = minimal_doc("did:exo:me-test");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(None, registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .header("x-actor-did", "did:exo:me-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_me_unknown_did_returns_404() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .header("x-actor-did", "did:exo:ghost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agents_list_returns_registered_dids() {
        let doc = minimal_doc("did:exo:listed");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(None, registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            val["agents"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("did:exo:listed"))
        );
    }

    #[tokio::test]
    async fn agent_get_known_did_returns_200() {
        let doc = minimal_doc("did:exo:agent-get");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(None, registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:agent-get")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn agent_get_unknown_returns_404() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:nobody")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn agents_enroll_returns_201() {
        let body = serde_json::to_string(&minimal_doc("did:exo:enrollee")).unwrap();
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn health_db_without_pool_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health/db")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn graphql_playground_returns_200() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/graphql")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    #[tokio::test]
    async fn graphql_post_default_off_returns_403_with_initiative() {
        let app = build_router(state());
        let body = serde_json::json!({
            "query": "mutation { createDecision(input: { tenantId: \"t1\", title: \"x\", body: \"y\", decisionClass: \"Routine\" }) { id } }"
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/graphql")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["error"], "unaudited_graphql_api_disabled");
        assert_eq!(val["feature_flag"], "unaudited-gateway-graphql-api");
        assert_eq!(
            val["initiative"],
            "Initiatives/fix-spline-r1-graphql-auth-gate.md"
        );
    }

    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    #[tokio::test]
    async fn graphql_ws_default_off_returns_403_with_initiative() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/graphql/ws")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["feature_flag"], "unaudited-gateway-graphql-api");
        assert_eq!(
            val["initiative"],
            "Initiatives/fix-spline-r1-graphql-auth-gate.md"
        );
    }

    #[cfg(feature = "unaudited-gateway-graphql-api")]
    #[tokio::test]
    async fn graphql_post_feature_on_preserves_existing_mutation_behavior() {
        let app = build_router(state());
        let body = serde_json::json!({
            "query": "mutation { createDecision(input: { tenantId: \"t1\", title: \"x\", body: \"y\", decisionClass: \"Routine\" }) { id status author } }"
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/graphql")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(val["errors"].is_null(), "unexpected errors: {val}");
        assert_eq!(val["data"]["createDecision"]["status"], "CREATED");
        assert_eq!(val["data"]["createDecision"]["author"], "system");
    }

    #[tokio::test]
    async fn vote_route_without_authority_returns_403() {
        let body = serde_json::to_string(&serde_json::json!({
            "decision_id": "d1",
            "voter_did": "did:exo:alice",
            "choice": "Approve",
            "actor_kind": "Human",
            "rationale": null,
            "timestamp_physical_ms": 7000,
            "timestamp_logical": 0,
        }))
        .unwrap();
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/decisions")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        // The Kernel adjudicates before the DB check.  The dev-scaffold context
        // has BailmentState::None (fails ConsentRequired) and an empty authority
        // chain (fails AuthorityChainValid), so the Kernel correctly returns 403
        // before we ever reach the DB-pool check.
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // --- Identity score endpoint tests ---

    #[tokio::test]
    async fn identity_score_unregistered_did_returns_404() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/identity/did:exo:ghost/score")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn identity_score_registered_did_returns_200() {
        let doc = minimal_doc("did:exo:scored");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(None, registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/identity/did:exo:scored/score")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["registered"], true);
        assert!(val["score_bps"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn constitution_returns_eight_invariants() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tenants/tenant-xyz/constitution")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["invariants"].as_array().unwrap().len(), 8);
    }

    #[tokio::test]
    async fn users_list_returns_200() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn decision_get_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/decisions/some-decision-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn audit_trail_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit/decision-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // --- Session auth handler tests (no DB — expect 503 or 400/401) ---

    #[tokio::test]
    async fn auth_login_without_db_returns_503() {
        let body = serde_json::to_string(&serde_json::json!({ "did": "did:exo:alice" })).unwrap();
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn auth_login_valid_signature_creates_session_row_with_caller_metadata() {
        use sqlx::Row;

        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:login-alice";
        sqlx::query("DELETE FROM sessions WHERE actor_did = $1")
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();

        let (registry, sk) = signing_registry();
        let metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 20_000,
        };
        let timestamp = Timestamp::new(10_000, 0);
        let observed_at = Timestamp::new(10_000, 0);
        let body_hash = session_login_payload_hash(did, &metadata, &timestamp).unwrap();
        let signature = sign(body_hash.as_bytes(), &sk);
        let body = serde_json::json!({
            "did": did,
            "createdAt": metadata.created_at,
            "expiresAt": metadata.expires_at,
            "authTimestampPhysicalMs": timestamp.physical_ms,
            "authTimestampLogical": timestamp.logical,
            "observedAt": observed_at.physical_ms,
            "observedAtLogical": observed_at.logical,
            "signature": hex::encode(signature.as_bytes())
        });

        let response = handle_auth_login(
            State(AppState::new(Some(pool.clone()), registry)),
            Json(body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let rows = sqlx::query(
            "SELECT actor_did, created_at, expires_at, revoked \
             FROM sessions WHERE actor_did = $1",
        )
        .bind(did)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<String, _>("actor_did"), did);
        assert_eq!(rows[0].get::<i64, _>("created_at"), metadata.created_at);
        assert_eq!(rows[0].get::<i64, _>("expires_at"), metadata.expires_at);
        assert!(!rows[0].get::<bool, _>("revoked"));

        sqlx::query("DELETE FROM sessions WHERE actor_did = $1")
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn session_login_proof_rejects_missing_signature() {
        let body = serde_json::json!({
            "authTimestampPhysicalMs": 10_000,
            "authTimestampLogical": 0,
            "observedAt": 10_000,
            "observedAtLogical": 0
        });
        let err = SessionLoginProof::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("signature")),
            "expected signature refusal, got {err}"
        );
    }

    #[test]
    fn session_login_proof_rejects_empty_signature() {
        let body = serde_json::json!({
            "authTimestampPhysicalMs": 10_000,
            "authTimestampLogical": 0,
            "observedAt": 10_000,
            "observedAtLogical": 0,
            "signature": ""
        });
        let err = SessionLoginProof::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("signature")),
            "expected empty signature refusal, got {err}"
        );
    }

    #[test]
    fn session_login_authentication_accepts_valid_signature() {
        let (registry, sk) = signing_registry();
        let metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 20_000,
        };
        let timestamp = Timestamp::new(10_000, 0);
        let body_hash =
            session_login_payload_hash("did:exo:login-alice", &metadata, &timestamp).unwrap();
        let signature = sign(body_hash.as_bytes(), &sk);
        let proof = SessionLoginProof {
            timestamp,
            observed_at: timestamp,
            signature,
        };
        let guard = registry.read().unwrap();
        let actor =
            authenticate_session_login("did:exo:login-alice", &metadata, &proof, &*guard).unwrap();

        assert_eq!(actor.did.as_str(), "did:exo:login-alice");
    }

    #[test]
    fn session_login_authentication_rejects_wrong_key_signature() {
        let (registry, _sk) = signing_registry();
        let (_wrong_pk, wrong_sk) = generate_keypair();
        let metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 20_000,
        };
        let timestamp = Timestamp::new(10_000, 0);
        let body_hash =
            session_login_payload_hash("did:exo:login-alice", &metadata, &timestamp).unwrap();
        let proof = SessionLoginProof {
            timestamp,
            observed_at: timestamp,
            signature: sign(body_hash.as_bytes(), &wrong_sk),
        };
        let guard = registry.read().unwrap();

        assert!(
            authenticate_session_login("did:exo:login-alice", &metadata, &proof, &*guard).is_err()
        );
    }

    #[test]
    fn session_login_authentication_rejects_tampered_payload() {
        let (registry, sk) = signing_registry();
        let signed_metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 20_000,
        };
        let tampered_metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 30_000,
        };
        let timestamp = Timestamp::new(10_000, 0);
        let body_hash =
            session_login_payload_hash("did:exo:login-alice", &signed_metadata, &timestamp)
                .unwrap();
        let proof = SessionLoginProof {
            timestamp,
            observed_at: timestamp,
            signature: sign(body_hash.as_bytes(), &sk),
        };
        let guard = registry.read().unwrap();

        assert!(
            authenticate_session_login("did:exo:login-alice", &tampered_metadata, &proof, &*guard)
                .is_err()
        );
    }

    #[test]
    fn session_login_authentication_rejects_stale_timestamp() {
        let (registry, sk) = signing_registry();
        let metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 20_000,
        };
        let timestamp = Timestamp::new(1, 0);
        let observed_at = Timestamp::new(400_000, 0);
        let body_hash =
            session_login_payload_hash("did:exo:login-alice", &metadata, &timestamp).unwrap();
        let proof = SessionLoginProof {
            timestamp,
            observed_at,
            signature: sign(body_hash.as_bytes(), &sk),
        };
        let guard = registry.read().unwrap();
        let err = authenticate_session_login("did:exo:login-alice", &metadata, &proof, &*guard)
            .unwrap_err();

        assert!(
            err.to_string().contains("freshness window"),
            "expected stale timestamp refusal, got {err}"
        );
    }

    #[test]
    fn auth_login_handler_requires_proof_of_possession() {
        let source = include_str!("server.rs");
        let login_handler = source_between(
            source,
            "async fn handle_auth_login",
            "/// POST /api/v1/auth/token",
        );

        assert!(
            login_handler.contains("authenticate_session_login"),
            "login must use DID proof-of-possession before issuing a session"
        );
        assert!(
            !login_handler.contains("reg.resolve(&did).is_none()"),
            "login must not downgrade to a registry-membership-only check"
        );
    }

    #[tokio::test]
    async fn auth_token_without_db_returns_503() {
        let body = serde_json::to_string(&serde_json::json!({ "did": "did:exo:alice" })).unwrap();
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/token")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn auth_refresh_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/refresh")
                    .header("authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn auth_refresh_missing_token_returns_503_or_401() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Without DB, 503 is returned before the header check.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn auth_logout_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .header("authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn auth_saml_callback_returns_501() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/saml/callback")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn session_issue_metadata_rejects_missing_created_at() {
        let body = serde_json::json!({
            "did": "did:exo:alice",
            "expiresAt": 4_600_000
        });
        let err = SessionIssueMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("createdAt")),
            "expected createdAt refusal, got {err}"
        );
    }

    #[test]
    fn session_issue_metadata_rejects_zero_created_at() {
        let body = serde_json::json!({
            "did": "did:exo:alice",
            "createdAt": 0,
            "expiresAt": 4_600_000
        });
        let err = SessionIssueMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("createdAt")),
            "expected zero createdAt refusal, got {err}"
        );
    }

    #[test]
    fn session_issue_metadata_requires_expiry_after_creation() {
        let body = serde_json::json!({
            "did": "did:exo:alice",
            "createdAt": 4_600_000,
            "expiresAt": 4_600_000
        });
        let err = SessionIssueMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("expiresAt")),
            "expected expiresAt ordering refusal, got {err}"
        );
    }

    #[test]
    fn session_refresh_metadata_requires_observed_at() {
        let body = serde_json::json!({
            "expiresAt": 4_600_000
        });
        let err = SessionRefreshMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("observedAt")),
            "expected observedAt refusal, got {err}"
        );
    }

    #[test]
    fn feedback_issue_create_metadata_requires_id_and_created_at() {
        let missing_id = serde_json::json!({
            "createdAt": 4_000
        });
        let missing_created_at = serde_json::json!({
            "id": "fb-1"
        });
        assert!(matches!(
            FeedbackIssueCreateMetadata::from_body(&missing_id),
            Err(GatewayError::BadRequest(reason)) if reason.contains("id")
        ));
        assert!(matches!(
            FeedbackIssueCreateMetadata::from_body(&missing_created_at),
            Err(GatewayError::BadRequest(reason)) if reason.contains("createdAt")
        ));
    }

    #[test]
    fn layout_template_metadata_requires_created_and_updated_at() {
        let missing_created_at = serde_json::json!({
            "updatedAt": 5_000
        });
        let missing_updated_at = serde_json::json!({
            "createdAt": 4_000
        });
        assert!(matches!(
            LayoutTemplateMetadata::from_body(&missing_created_at),
            Err(GatewayError::BadRequest(reason)) if reason.contains("createdAt")
        ));
        assert!(matches!(
            LayoutTemplateMetadata::from_body(&missing_updated_at),
            Err(GatewayError::BadRequest(reason)) if reason.contains("updatedAt")
        ));
    }

    #[test]
    fn feedback_issue_update_metadata_requires_updated_at() {
        let body = serde_json::json!({
            "status": "closed"
        });
        let err = FeedbackIssueUpdateMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("updatedAt")),
            "expected updatedAt refusal, got {err}"
        );
    }

    #[test]
    fn advance_pace_metadata_requires_queued_at() {
        let body = serde_json::json!({});
        let err = AdvancePaceMetadata::from_optional_body(Some(&body)).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("queuedAt")),
            "expected queuedAt refusal, got {err}"
        );
    }

    #[test]
    fn gateway_server_durable_handlers_do_not_fabricate_metadata() {
        let source = include_str!("server.rs");
        let durable_handlers = [
            source_between(
                source,
                "async fn handle_auth_login",
                "/// POST /api/v1/auth/token",
            ),
            source_between(
                source,
                "async fn handle_auth_refresh",
                "/// POST /api/v1/auth/logout",
            ),
            source_between(
                source,
                "async fn handle_advance_pace",
                "// ---------------------------------------------------------------------------\n// Legal / eDiscovery handlers",
            ),
            source_between(
                source,
                "async fn handle_layout_template_put",
                "/// DELETE /api/v1/layout-templates/:id",
            ),
            source_between(
                source,
                "async fn handle_feedback_issue_create",
                "/// GET /api/v1/feedback-issues",
            ),
            source_between(
                source,
                "async fn handle_feedback_issue_update",
                "pub fn build_router",
            ),
        ];

        for handler in durable_handlers {
            assert!(
                !handler.contains("now_ms()"),
                "durable gateway handlers must not fabricate timestamps"
            );
            assert!(
                !handler.contains("Uuid::new_v4"),
                "durable gateway handlers must not fabricate persistent IDs"
            );
        }
    }

    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_index = source.find(start).expect("source start marker");
        let after_start = &source[start_index..];
        let end_index = after_start.find(end).expect("source end marker");
        &after_start[..end_index]
    }

    #[tokio::test]
    async fn advance_pace_without_authority_returns_403() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/did:exo:alice/advance-pace")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Kernel rejects before DB check: no consent + no authority chain.
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn user_advance_pace_without_authority_returns_403() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/users/did:exo:bob/advance-pace")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ediscovery_export_returns_501() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/ediscovery/export")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn extract_bearer_token_parses_header() {
        use axum::http::HeaderValue;
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer my-test-token"),
        );
        assert_eq!(
            extract_bearer_token(&headers).as_deref(),
            Some("my-test-token")
        );
    }

    #[tokio::test]
    async fn extract_bearer_token_missing_returns_none() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());
    }

    // -----------------------------------------------------------------------
    // Adjudication context integration tests (APE-53)
    //
    // These tests verify that the `Kernel` produces the correct `Verdict` for
    // different adjudication contexts that mirror what the DB resolver would
    // build.  No live database is required — contexts are constructed directly
    // from types.
    //
    // Note on InvariantSet: `ProvenanceVerifiable` is intentionally excluded
    // from these tests because provenance is per-action (not per-actor) and is
    // not stored in the adjudication tables.  Callers that require full
    // ProvenanceVerifiable enforcement must attach provenance to the context
    // before calling `Kernel::adjudicate`.
    // -----------------------------------------------------------------------

    use exo_gatekeeper::{
        invariants::ConstitutionalInvariant,
        types::{
            AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Role,
        },
    };

    /// Returns a `Kernel` that checks all invariants **except** ProvenanceVerifiable.
    fn adjudication_kernel() -> Kernel {
        Kernel::new(
            b"exochain-constitution-v1",
            InvariantSet::with(vec![
                ConstitutionalInvariant::SeparationOfPowers,
                ConstitutionalInvariant::ConsentRequired,
                ConstitutionalInvariant::NoSelfGrant,
                ConstitutionalInvariant::HumanOverride,
                ConstitutionalInvariant::KernelImmutability,
                ConstitutionalInvariant::AuthorityChainValid,
                ConstitutionalInvariant::QuorumLegitimate,
            ]),
        )
    }

    /// Build a minimal valid `AdjudicationContext` for `actor` that satisfies
    /// all non-provenance invariants.  Mirrors the context that
    /// `build_adjudication_context_from_db` would produce for an actor with
    /// a single role, one active consent record, and a one-link authority chain.
    fn valid_db_context(actor: &Did) -> AdjudicationContext {
        let root = Did::new("did:exo:root-grantor").unwrap();
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "voter".to_string(),
                branch: GovernmentBranch::Executive,
            }],
            authority_chain: AuthorityChain {
                links: vec![AuthorityLink {
                    grantor: root.clone(),
                    grantee: actor.clone(),
                    permissions: PermissionSet::new(vec![Permission::new("vote")]),
                    // Non-empty signature satisfies the legacy (no-public-key) path.
                    signature: vec![0xAB; 8],
                    grantor_public_key: None,
                }],
            },
            consent_records: vec![ConsentRecord {
                subject: root.clone(),
                granted_to: actor.clone(),
                scope: "data:vote".to_string(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor: root,
                bailee: actor.clone(),
                scope: "data:vote".to_string(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("vote")]),
            provenance: None,
            quorum_evidence: None,
            active_challenge_reason: None,
        }
    }

    fn vote_action(actor: &Did) -> GkActionRequest {
        GkActionRequest {
            actor: actor.clone(),
            action: "vote".into(),
            required_permissions: PermissionSet::new(vec![Permission::new("vote")]),
            is_self_grant: false,
            modifies_kernel: false,
        }
    }

    /// [APE-53 test 1] Scaffold remains deny-all regardless of feature flag.
    #[tokio::test]
    async fn scaffold_context_is_still_deny_all() {
        // The default `AppState` (no pool, no production-db feature) must always
        // produce a deny-all context — this is the WO-009 preservation check.
        let st = state();
        let actor = Did::new("did:exo:alice").unwrap();
        let ctx = st.build_adjudication_context(&actor).await;
        let verdict = st.kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(verdict.is_denied(), "scaffold must always deny");
    }

    /// [APE-53 test 2] Role present + consent + valid chain → Permitted.
    #[test]
    fn kernel_permits_with_role_consent_and_valid_chain() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let ctx = valid_db_context(&actor);
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(verdict.is_permitted(), "full DB context must be permitted");
    }

    /// [APE-53 test 3] Role absent (empty roles) + consent + valid chain → Permitted.
    ///
    /// The Kernel does not require roles to be present; `SeparationOfPowers`
    /// only fires when an actor holds roles across *multiple* branches.
    /// When no roles are present, all non-provenance invariants still pass.
    #[test]
    fn kernel_permits_consent_and_chain_even_without_roles() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let mut ctx = valid_db_context(&actor);
        ctx.actor_roles = vec![]; // simulate no DB role records
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(
            verdict.is_permitted(),
            "absent roles alone must not deny — consent+chain suffice"
        );
    }

    /// [APE-53 test 4] No active bailment → ConsentRequired denied.
    ///
    /// Mirrors a DB state where the actor has no active consent records
    /// (all expired or revoked), so `bailment_state` stays `BailmentState::None`.
    #[test]
    fn kernel_denies_without_active_bailment() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let mut ctx = valid_db_context(&actor);
        ctx.bailment_state = BailmentState::None;
        ctx.consent_records = vec![];
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(verdict.is_denied(), "no bailment must be denied");
    }

    /// [APE-53 test 5] Active bailment but no matching consent record → ConsentRequired denied.
    ///
    /// Mirrors a DB state where the bailment record exists but no `consent_records`
    /// row is present for this actor, violating the second half of ConsentRequired.
    #[test]
    fn kernel_denies_bailment_active_but_no_consent_record() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let root = Did::new("did:exo:root-grantor").unwrap();
        let mut ctx = valid_db_context(&actor);
        ctx.consent_records = vec![]; // remove consent records
        // Keep bailment Active — the invariant checks both bailment AND records.
        ctx.bailment_state = BailmentState::Active {
            bailor: root,
            bailee: actor.clone(),
            scope: "data:vote".to_string(),
        };
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(
            verdict.is_denied(),
            "active bailment without consent record must be denied"
        );
    }

    /// [APE-53 test 6] Consent present but empty authority chain → not permitted.
    ///
    /// Mirrors a DB state where no `authority_chains` row exists for the actor.
    /// A single `AuthorityChainValid` violation escalates (not denies) per
    /// the Kernel escalation policy; the important assertion is that the action
    /// is never `Permitted`.
    #[test]
    fn kernel_blocks_with_empty_authority_chain() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let mut ctx = valid_db_context(&actor);
        ctx.authority_chain = AuthorityChain::default(); // empty
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(
            !verdict.is_permitted(),
            "empty chain must never be permitted (got Denied or Escalated)"
        );
    }

    /// [APE-53 test 7] Roles spanning multiple branches → SeparationOfPowers denied.
    ///
    /// Mirrors a DB state where `agent_roles` has rows for both Executive and
    /// Legislative branches, violating the single-branch rule.
    #[test]
    fn kernel_denies_roles_spanning_two_branches() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let mut ctx = valid_db_context(&actor);
        ctx.actor_roles = vec![
            Role {
                name: "voter".to_string(),
                branch: GovernmentBranch::Executive,
            },
            Role {
                name: "legislator".to_string(),
                branch: GovernmentBranch::Legislative,
            },
        ];
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);
        assert!(
            verdict.is_denied(),
            "cross-branch roles must be denied by SeparationOfPowers"
        );
    }
}
