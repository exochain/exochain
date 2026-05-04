//! HTTP server skeleton — gateway configuration, lifecycle, and axum routing.
use std::{
    collections::BTreeMap,
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use exo_core::{Did, Hash256, Signature, Timestamp, hlc::HybridClock};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest as GkActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{AuthorityChain, BailmentState, Permission, PermissionSet},
};
use exo_governance::conflict::ConflictDeclaration;
use exo_identity::{
    did::DidDocument,
    error::IdentityError,
    registry::{DidRegistry, LocalDidRegistry},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::trace::TraceLayer;

/// Maximum accepted request body size, in bytes (1 MiB).
///
/// Caps inbound JSON payloads to prevent memory exhaustion from hostile
/// clients. Larger uploads (e.g. e-discovery export streams) should use
/// dedicated streaming endpoints that override this cap with
/// `DefaultBodyLimit::disable()` at the route level. (A-022)
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_DID_DOCUMENT_BODY_BYTES: usize = 64 * 1024;

use crate::{
    auth::{AuthenticatedActor, AuthenticationMetadata, Request as AuthRequest, authenticate},
    db,
    error::{GatewayError, Result},
    graphql,
    handlers::{health_handler as db_health_handler, vote_handler},
    rest::HealthResponse,
};

const XSRF_COOKIE_PREFIX: &str = "XSRF-TOKEN=";
const CSRF_HEADER_NAME: &str = "x-csrf-token";
const AUTH_OBSERVED_AT_MS_HEADER: &str = "x-exo-auth-observed-at-ms";
const GLOBAL_CONCURRENCY_LIMIT: usize = 1024;
const GATEWAY_RATE_LIMIT_REQUESTS_PER_WINDOW: u32 = 120;
const GATEWAY_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const GATEWAY_RATE_LIMIT_MAX_CLIENTS: usize = 16_384;
const STRICT_TRANSPORT_SECURITY_VALUE: &str = "max-age=63072000; includeSubDomains";
const CONTENT_SECURITY_POLICY_VALUE: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const PERMISSIONS_POLICY_VALUE: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayRateLimitOutcome {
    Allowed,
    Limited { retry_after_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GatewayRateLimitBucket {
    window_start_ms: u64,
    request_count: u32,
    last_seen_ms: u64,
}

#[derive(Debug)]
struct GatewayRateLimiter {
    clients: BTreeMap<String, GatewayRateLimitBucket>,
    max_requests_per_window: u32,
    window_ms: u64,
    max_tracked_clients: usize,
}

impl Default for GatewayRateLimiter {
    fn default() -> Self {
        Self::with_limits(
            GATEWAY_RATE_LIMIT_REQUESTS_PER_WINDOW,
            GATEWAY_RATE_LIMIT_WINDOW_MS,
            GATEWAY_RATE_LIMIT_MAX_CLIENTS,
        )
    }
}

impl GatewayRateLimiter {
    fn with_limits(
        max_requests_per_window: u32,
        window_ms: u64,
        max_tracked_clients: usize,
    ) -> Self {
        Self {
            clients: BTreeMap::new(),
            max_requests_per_window,
            window_ms,
            max_tracked_clients,
        }
    }

    fn check(&mut self, client_key: &str, now_ms: u64) -> GatewayRateLimitOutcome {
        if self.max_requests_per_window == 0 || self.window_ms == 0 {
            return GatewayRateLimitOutcome::Limited {
                retry_after_ms: self.window_ms.max(1),
            };
        }

        self.prune_stale(now_ms);

        if let Some(bucket) = self.clients.get_mut(client_key) {
            let elapsed_ms = now_ms.saturating_sub(bucket.window_start_ms);
            if elapsed_ms >= self.window_ms {
                *bucket = GatewayRateLimitBucket {
                    window_start_ms: now_ms,
                    request_count: 1,
                    last_seen_ms: now_ms,
                };
                return GatewayRateLimitOutcome::Allowed;
            }

            bucket.last_seen_ms = now_ms;
            if bucket.request_count >= self.max_requests_per_window {
                return GatewayRateLimitOutcome::Limited {
                    retry_after_ms: self.window_ms.saturating_sub(elapsed_ms).max(1),
                };
            }
            bucket.request_count = bucket.request_count.saturating_add(1);
            return GatewayRateLimitOutcome::Allowed;
        }

        if self.clients.len() >= self.max_tracked_clients {
            return GatewayRateLimitOutcome::Limited {
                retry_after_ms: self.window_ms,
            };
        }

        self.clients.insert(
            client_key.to_owned(),
            GatewayRateLimitBucket {
                window_start_ms: now_ms,
                request_count: 1,
                last_seen_ms: now_ms,
            },
        );
        GatewayRateLimitOutcome::Allowed
    }

    fn prune_stale(&mut self, now_ms: u64) {
        let retention_ms = self.window_ms.saturating_mul(2).max(self.window_ms);
        self.clients
            .retain(|_, bucket| now_ms.saturating_sub(bucket.last_seen_ms) <= retention_ms);
    }
}

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
    validate_tls_config(config.tls_config.as_ref())?;
    Ok(GatewayHandle {
        config,
        running: true,
    })
}

fn validate_tls_config(tls_config: Option<&TlsConfig>) -> Result<()> {
    if let Some(tls) = tls_config {
        if tls.cert_path.trim().is_empty() {
            return Err(GatewayError::BadRequest(
                "tls_config.cert_path cannot be empty".into(),
            ));
        }
        if tls.key_path.trim().is_empty() {
            return Err(GatewayError::BadRequest(
                "tls_config.key_path cannot be empty".into(),
            ));
        }
    }
    Ok(())
}

fn parse_tls_bind_address(bind_address: &str) -> Result<SocketAddr> {
    bind_address.parse::<SocketAddr>().map_err(|e| {
        GatewayError::BadRequest(format!(
            "tls_config requires bind_address to be an explicit socket address: {e}"
        ))
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
    /// HLC timestamp captured at server start, used to compute uptime.
    start_time: Timestamp,
    /// HLC source used for default-on gateway runtime timestamps.
    clock: Arc<Mutex<HybridClock>>,
    /// Default-on per-client request-rate admission state.
    rate_limiter: Arc<Mutex<GatewayRateLimiter>>,
}

/// Non-secret authenticated session profile used to carry tenant scope across
/// gateway runtime adapter boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionUser {
    pub did: Did,
    pub tenant_id: String,
}

impl AppState {
    /// Create a new `AppState` with an optional database pool and a shared DID registry.
    pub fn new(pool: Option<sqlx::PgPool>, registry: Arc<RwLock<LocalDidRegistry>>) -> Self {
        Self::new_with_clock(pool, registry, HybridClock::new())
    }

    /// Create a new `AppState` with an explicit HLC source.
    pub fn new_with_clock(
        pool: Option<sqlx::PgPool>,
        registry: Arc<RwLock<LocalDidRegistry>>,
        mut clock: HybridClock,
    ) -> Self {
        // Bootstrap kernel with the all-invariants set.
        // constitution bytes are hashed for immutability verification.
        let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
        let start_time = match clock.now() {
            Ok(timestamp) => timestamp,
            Err(err) => {
                tracing::error!(error = %err, "Gateway AppState HLC exhausted at startup");
                Timestamp::ZERO
            }
        };
        Self {
            pool,
            registry,
            kernel: Arc::new(kernel),
            start_time,
            clock: Arc::new(Mutex::new(clock)),
            rate_limiter: Arc::new(Mutex::new(GatewayRateLimiter::default())),
        }
    }

    fn try_now_ms(&self) -> std::result::Result<u64, &'static str> {
        let mut clock = self
            .clock
            .lock()
            .map_err(|_| "Gateway AppState HLC mutex poisoned while reading timestamp")?;
        clock
            .now()
            .map(|timestamp| timestamp.physical_ms)
            .map_err(|_| "Gateway AppState HLC exhausted while reading timestamp")
    }

    fn now_ms(&self) -> u64 {
        match self.try_now_ms() {
            Ok(now_ms) => now_ms,
            Err(message) => {
                tracing::error!(message, "Gateway AppState timestamp unavailable");
                0
            }
        }
    }

    fn uptime_seconds(&self) -> u64 {
        self.now_ms().saturating_sub(self.start_time.physical_ms) / 1000
    }

    /// Return the DB pool or a 503 if none is configured.
    pub fn require_db(&self) -> Result<&sqlx::PgPool> {
        self.pool
            .as_ref()
            .ok_or_else(|| GatewayError::Internal("database unavailable".into()))
    }

    /// Resolve the authenticated actor from the DB-backed bearer session.
    pub async fn require_authenticated_session_actor_from_header(
        &self,
        headers: &HeaderMap,
    ) -> Result<Did> {
        let token = require_bearer_token(headers)?;
        let observed_at = required_observed_at_ms_header(headers)?;
        require_authenticated_session_actor_for_token(self, &token, observed_at).await
    }

    /// Resolve the authenticated actor and its tenant scope from DB-backed
    /// bearer session state.
    pub async fn require_authenticated_session_user_from_header(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedSessionUser> {
        let did = self
            .require_authenticated_session_actor_from_header(headers)
            .await?;
        let db = self.require_db()?;
        let user = db::find_user_by_did(db, did.as_str())
            .await
            .map_err(|e| GatewayError::Internal(format!("session user lookup failed: {e}")))?
            .ok_or_else(|| GatewayError::AuthenticationFailed {
                reason: "authenticated session actor has no tenant profile".to_owned(),
            })?;
        Ok(AuthenticatedSessionUser {
            did,
            tenant_id: user.tenant_id,
        })
    }

    /// Return the number of registered DIDs without blocking a Tokio worker
    /// on the synchronous registry lock.
    pub async fn registry_len(&self) -> Result<usize> {
        registry_len(Arc::clone(&self.registry))
            .await
            .map_err(|e| GatewayError::Internal(e.to_string()))
    }

    /// Load conflict declarations for an actor from the DB-backed standing
    /// conflict register.
    pub async fn load_conflict_declarations(
        &self,
        actor: &Did,
    ) -> std::result::Result<Vec<ConflictDeclaration>, GatewayError> {
        let pool = self.require_db()?;
        let payloads = db::list_conflict_declaration_payloads_db(pool, actor.as_str())
            .await
            .map_err(|e| {
                GatewayError::Internal(format!("failed to load conflict declarations: {e}"))
            })?;

        payloads
            .into_iter()
            .map(|payload| decode_conflict_declaration_payload(actor, payload))
            .collect()
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
            let now = i64::try_from(self.now_ms()).unwrap_or(i64::MAX);
            match build_adjudication_context_from_db(pool, actor, now).await {
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

#[derive(Debug)]
enum RegistryBlockingError {
    Registration(IdentityError),
    Operation(String),
    Join(String),
}

impl fmt::Display for RegistryBlockingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(error) => write!(f, "registry registration failed: {error}"),
            Self::Operation(error) => write!(f, "registry operation failed: {error}"),
            Self::Join(error) => write!(f, "registry blocking task failed: {error}"),
        }
    }
}

fn did_registration_rejection_response(
    error: IdentityError,
    duplicate_message: &'static str,
) -> Response {
    match error {
        IdentityError::DuplicateDid(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": duplicate_message })),
        )
            .into_response(),
        IdentityError::RegistryCapacityExceeded { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "DID registry capacity exhausted" })),
        )
            .into_response(),
        IdentityError::InvalidDidDocumentField { .. }
        | IdentityError::DidDocumentFieldTooLarge { .. } => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid DID document" })),
        )
            .into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "DID registration rejected" })),
        )
            .into_response(),
    }
}

async fn registry_register_document(
    registry: Arc<RwLock<LocalDidRegistry>>,
    doc: DidDocument,
) -> std::result::Result<(), RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
        reg.register(doc)
            .map_err(RegistryBlockingError::Registration)
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

async fn registry_resolve_document(
    registry: Arc<RwLock<LocalDidRegistry>>,
    did: Did,
) -> std::result::Result<Option<DidDocument>, RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let reg = registry.read().unwrap_or_else(|e| e.into_inner());
        Ok(reg.resolve(&did).cloned())
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

async fn registry_list_dids(
    registry: Arc<RwLock<LocalDidRegistry>>,
) -> std::result::Result<Vec<String>, RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let reg = registry.read().unwrap_or_else(|e| e.into_inner());
        Ok(reg.list_dids().into_iter().map(|s| s.to_owned()).collect())
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

async fn registry_len(
    registry: Arc<RwLock<LocalDidRegistry>>,
) -> std::result::Result<usize, RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let reg = registry.read().unwrap_or_else(|e| e.into_inner());
        Ok(reg.len())
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

async fn registry_authenticate_session_login(
    registry: Arc<RwLock<LocalDidRegistry>>,
    did: String,
    metadata: SessionIssueMetadata,
    proof: SessionLoginProof,
) -> std::result::Result<(), RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let reg = registry.read().unwrap_or_else(|e| e.into_inner());
        authenticate_session_login(&did, &metadata, &proof, &*reg)
            .map(|_| ())
            .map_err(|e| RegistryBlockingError::Operation(e.to_string()))
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

fn decode_conflict_declaration_payload(
    actor: &Did,
    payload: serde_json::Value,
) -> std::result::Result<ConflictDeclaration, GatewayError> {
    let declaration: ConflictDeclaration = serde_json::from_value(payload).map_err(|e| {
        GatewayError::Internal(format!("invalid stored conflict declaration payload: {e}"))
    })?;
    validate_conflict_declaration(actor, declaration)
}

fn validate_conflict_declaration(
    actor: &Did,
    declaration: ConflictDeclaration,
) -> std::result::Result<ConflictDeclaration, GatewayError> {
    if &declaration.declarant_did != actor {
        return Err(GatewayError::Internal(format!(
            "stored conflict declaration for {} was returned while loading {}",
            declaration.declarant_did, actor
        )));
    }
    if declaration.nature.trim().is_empty() {
        return Err(GatewayError::Internal(
            "stored conflict declaration has empty nature".into(),
        ));
    }
    if declaration.related_dids.is_empty() {
        return Err(GatewayError::Internal(
            "stored conflict declaration has no related DIDs".into(),
        ));
    }
    if declaration.timestamp == Timestamp::ZERO {
        return Err(GatewayError::Internal(
            "stored conflict declaration has zero timestamp".into(),
        ));
    }
    Ok(declaration)
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

fn internal_error_response(
    error: impl fmt::Display,
    context: &'static str,
    client_error: &'static str,
) -> Response {
    tracing::error!(error = %error, context, "gateway internal operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": client_error })),
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

#[cfg(any(test, feature = "production-db"))]
fn build_adjudication_context_from_rows(
    actor: &Did,
    role_rows: &[crate::db::AgentRoleRow],
    consent_rows: &[crate::db::ConsentRecordRow],
    chain_row: Option<&crate::db::AuthorityChainRow>,
) -> Result<AdjudicationContext> {
    use exo_gatekeeper::types::{
        AuthorityChain as GkChain, BailmentState as GkBailment, ConsentRecord, GovernmentBranch,
        Role,
    };

    let actor_roles: Vec<Role> = role_rows
        .iter()
        .map(|r| {
            let branch = match r.branch.as_str() {
                "executive" => GovernmentBranch::Executive,
                "legislative" => GovernmentBranch::Legislative,
                "judicial" => GovernmentBranch::Judicial,
                other => {
                    return Err(GatewayError::Internal(format!(
                        "adjudication role row unknown role branch for actor '{}' role '{}': '{}'",
                        r.agent_did, r.role, other
                    )));
                }
            };
            Ok(Role {
                name: r.role.clone(),
                branch,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let consent_records: Vec<ConsentRecord> = consent_rows
        .iter()
        .map(|r| {
            let subject = Did::new(&r.subject_did).map_err(|e| {
                GatewayError::Internal(format!(
                    "adjudication consent subject DID invalid for actor '{}' scope '{}': '{}' ({e})",
                    r.actor_did, r.scope, r.subject_did
                ))
            })?;
            Ok(ConsentRecord {
                subject,
                granted_to: actor.clone(),
                scope: r.scope.clone(),
                active: r.status == "active",
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let bailment_state = match consent_rows.iter().find(|r| r.status == "active") {
        Some(r) => {
            let bailor = Did::new(&r.subject_did).map_err(|e| {
                GatewayError::Internal(format!(
                    "adjudication consent subject DID invalid for active bailment actor '{}' scope '{}': '{}' ({e})",
                    r.actor_did, r.scope, r.subject_did
                ))
            })?;
            GkBailment::Active {
                bailor,
                bailee: actor.clone(),
                scope: r.scope.clone(),
            }
        }
        None => GkBailment::None,
    };

    let authority_chain = match chain_row {
        Some(row) => serde_json::from_value::<GkChain>(row.chain_json.clone()).map_err(|e| {
            GatewayError::Internal(format!(
                "adjudication authority chain JSON invalid for actor '{}': {e}",
                row.actor_did
            ))
        })?,
        None => GkChain::default(),
    };

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
    now: i64,
) -> Result<AdjudicationContext> {
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

    build_adjudication_context_from_rows(actor, &role_rows, &consent_rows, chain_row.as_ref())
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
    match registry_register_document(Arc::clone(&state.registry), doc).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "did": did_str, "status": "registered" })),
        )
            .into_response(),
        Err(RegistryBlockingError::Registration(e)) => {
            tracing::warn!(error = %e, did = %did_str, "DID registration rejected");
            did_registration_rejection_response(e, "DID already registered")
        }
        Err(e) => {
            tracing::error!(error = %e, "DID registry registration task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/auth/me — resolve the caller's DID document.
///
/// Requires `Authorization: Bearer <token>` and
/// `x-exo-auth-observed-at-ms`. The actor DID is resolved from the session
/// token; caller-supplied DID headers are ignored.
async fn handle_auth_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let did = match require_authenticated_session_actor_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    match registry_resolve_document(Arc::clone(&state.registry), did).await {
        Ok(Some(doc)) => Json(doc).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "DID not found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "DID registry lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/agents — list all registered DID identifiers.
///
/// Requires a DB-backed bearer session before reading registry state.
async fn handle_agents_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_authenticated_session_actor_from_header(&state, &headers).await {
        return auth_boundary_error_response(e);
    }
    match registry_list_dids(Arc::clone(&state.registry)).await {
        Ok(dids) => Json(serde_json::json!({ "agents": dids })).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "DID registry listing failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/agents/:did — resolve a single DID document by its identifier.
///
/// Requires a DB-backed bearer session before reading registry state.
async fn handle_agent_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(did_str): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_authenticated_session_actor_from_header(&state, &headers).await {
        return auth_boundary_error_response(e);
    }
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
    match registry_resolve_document(Arc::clone(&state.registry), did).await {
        Ok(Some(doc)) => Json(doc).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "DID not found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "DID registry lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response()
        }
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
    match registry_resolve_document(Arc::clone(&state.registry), did).await {
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "did": did_str,
                "registered": false,
                "score_bps": 0u32,
                "factors": { "registered": false }
            })),
        )
            .into_response(),
        Ok(Some(doc)) => {
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
        Err(e) => {
            tracing::error!(error = %e, "DID registry lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
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
/// the in-memory store. Requires a DB-backed bearer session before reading registry
/// state.
async fn handle_users_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = require_authenticated_session_actor_from_header(&state, &headers).await {
        return auth_boundary_error_response(e);
    }
    match registry_list_dids(Arc::clone(&state.registry)).await {
        Ok(dids) => Json(serde_json::json!({ "users": dids })).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "DID registry listing failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/decisions/:id — retrieve a specific decision record.
///
/// Returns the full serialized `DecisionObject` stored in the `decisions` table.
/// Requires a DB-backed bearer session and a DB pool; returns 503 when the gateway
/// starts without `DATABASE_URL`.
async fn handle_decision_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let actor = match require_authenticated_session_user_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response();
        }
    };
    match db::find_decision(db, &id, &actor.tenant_id).await {
        Ok(Some(row)) => Json::<serde_json::Value>(row.payload).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "decision not found" })),
        )
            .into_response(),
        Err(e) => internal_error_response(e, "decision lookup query", "decision lookup failed"),
    }
}

/// GET /api/v1/audit/:decision_id — retrieve the audit trail for a decision.
///
/// Queries the `audit_entries` table populated by the vote handler. Requires a
/// DB-backed bearer session and a DB pool.
async fn handle_audit_trail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(decision_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_authenticated_session_actor_from_header(&state, &headers).await {
        return auth_boundary_error_response(e);
    }
    let pool = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
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
        Err(e) => internal_error_response(e, "audit trail query", "audit trail unavailable"),
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
    match registry_register_document(Arc::clone(&state.registry), doc).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "did": did_str, "status": "enrolled" })),
        )
            .into_response(),
        Err(RegistryBlockingError::Registration(e)) => {
            tracing::warn!(error = %e, did = %did_str, "agent enrollment rejected");
            did_registration_rejection_response(e, "DID already enrolled")
        }
        Err(e) => {
            tracing::error!(error = %e, "DID registry enrollment task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response()
        }
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
                Json(serde_json::json!({"error": "database unavailable"})),
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
    match registry_authenticate_session_login(
        Arc::clone(&state.registry),
        did_str.clone(),
        metadata,
        proof,
    )
    .await
    {
        Ok(()) => {}
        Err(RegistryBlockingError::Operation(e)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "authentication failed",
                    "message": e
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "DID registry authentication task failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "DID registry unavailable" })),
            )
                .into_response();
        }
    }
    let token = match generate_session_token() {
        Ok(token) => token,
        Err(e) => return internal_error_response(e, "session token generation", "login failed"),
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
        Err(e) => internal_error_response(e, "session insert", "login failed"),
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
                Json(serde_json::json!({"error": "database unavailable"})),
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
        Err(e) => internal_error_response(e, "session refresh update", "session refresh failed"),
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
                Json(serde_json::json!({"error": "database unavailable"})),
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
        Err(e) => internal_error_response(e, "session logout update", "logout failed"),
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
    headers: HeaderMap,
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
    let actor = match state
        .require_authenticated_session_actor_from_header(&headers)
        .await
    {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    if actor != did {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "forbidden",
                "message": "authenticated session actor does not match advance-pace target"
            })),
        )
            .into_response();
    }
    // Build an adjudication context for this actor.
    let ctx = state.build_adjudication_context(&actor).await;
    let action = GkActionRequest {
        actor: actor.clone(),
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
                Json(serde_json::json!({"error": "database unavailable"})),
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

fn require_bearer_token(headers: &HeaderMap) -> Result<String> {
    extract_bearer_token(headers).ok_or_else(|| GatewayError::AuthenticationFailed {
        reason: "missing or malformed Authorization header".to_owned(),
    })
}

fn required_observed_at_ms_header(headers: &HeaderMap) -> Result<i64> {
    let raw = headers
        .get(AUTH_OBSERVED_AT_MS_HEADER)
        .ok_or_else(|| {
            GatewayError::BadRequest(format!(
                "missing required '{AUTH_OBSERVED_AT_MS_HEADER}' header"
            ))
        })?
        .to_str()
        .map_err(|_| {
            GatewayError::BadRequest(format!(
                "'{AUTH_OBSERVED_AT_MS_HEADER}' header must be valid UTF-8"
            ))
        })?;
    let observed_at = raw.parse::<i64>().map_err(|e| {
        GatewayError::BadRequest(format!(
            "'{AUTH_OBSERVED_AT_MS_HEADER}' header must be an integer millisecond timestamp: {e}"
        ))
    })?;
    if observed_at <= 0 {
        return Err(GatewayError::BadRequest(format!(
            "'{AUTH_OBSERVED_AT_MS_HEADER}' header must be non-zero"
        )));
    }
    Ok(observed_at)
}

async fn require_authenticated_session_actor_from_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Did> {
    let token = require_bearer_token(headers)?;
    let observed_at = required_observed_at_ms_header(headers)?;
    require_authenticated_session_actor_for_token(state, &token, observed_at).await
}

async fn require_authenticated_session_user_from_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSessionUser> {
    state
        .require_authenticated_session_user_from_header(headers)
        .await
}

async fn require_authenticated_session_actor(
    state: &AppState,
    headers: &HeaderMap,
    observed_at_ms: i64,
) -> Result<Did> {
    let token = require_bearer_token(headers)?;
    require_authenticated_session_actor_for_token(state, &token, observed_at_ms).await
}

async fn require_authenticated_session_actor_for_token(
    state: &AppState,
    token: &str,
    observed_at_ms: i64,
) -> Result<Did> {
    if observed_at_ms <= 0 {
        return Err(GatewayError::BadRequest(
            "session authentication observed_at must be caller-supplied and non-zero".into(),
        ));
    }
    let db = state.require_db()?;
    let actor_did: Option<String> = sqlx::query_scalar(
        "SELECT actor_did FROM sessions \
         WHERE token = $1 AND revoked = false AND expires_at > $2",
    )
    .bind(token)
    .bind(observed_at_ms)
    .fetch_optional(db)
    .await
    .map_err(|e| GatewayError::Internal(format!("session actor lookup failed: {e}")))?;

    let actor_did = actor_did.ok_or_else(|| GatewayError::AuthenticationFailed {
        reason: "session token expired, revoked, or not found".to_owned(),
    })?;
    Did::new(&actor_did).map_err(|e| {
        GatewayError::Internal(format!(
            "session actor DID stored in database is invalid: {actor_did}: {e}"
        ))
    })
}

fn reject_caller_supplied_identity_field(body: &serde_json::Value, field: &str) -> Result<()> {
    if body
        .as_object()
        .is_some_and(|object| object.contains_key(field))
    {
        return Err(GatewayError::BadRequest(format!(
            "{field} is derived from the authenticated session actor and must not be supplied"
        )));
    }
    Ok(())
}

fn reject_caller_supplied_builtin_layout(body: &serde_json::Value) -> Result<()> {
    let Some(value) = body.as_object().and_then(|object| object.get("isBuiltIn")) else {
        return Ok(());
    };
    match value.as_bool() {
        Some(false) | None => Ok(()),
        Some(true) => Err(GatewayError::BadRequest(
            "built-in layout templates are code-owned and cannot be persisted by callers".into(),
        )),
    }
}

pub(crate) fn auth_boundary_error_response(err: GatewayError) -> Response {
    match err {
        GatewayError::AuthenticationFailed { reason } => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "authentication failed",
                "message": reason,
            })),
        )
            .into_response(),
        GatewayError::BadRequest(reason) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": reason })),
        )
            .into_response(),
        GatewayError::Internal(reason) if reason.contains("database unavailable") => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "database unavailable"})),
        )
            .into_response(),
        other => internal_error_response(other, "authentication boundary", "authentication failed"),
    }
}

fn is_csrf_protected_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn xsrf_cookie_token(headers: &HeaderMap) -> std::result::Result<Option<String>, ()> {
    let cookie_headers = headers.get_all(header::COOKIE);
    for value in cookie_headers {
        let Ok(raw) = value.to_str() else {
            return Err(());
        };
        for cookie in raw.split(';').map(str::trim) {
            let Some(token) = cookie.strip_prefix(XSRF_COOKIE_PREFIX) else {
                continue;
            };
            return percent_decode_str(token)
                .decode_utf8()
                .map(|decoded| Some(decoded.into_owned()))
                .map_err(|_| ());
        }
    }
    Ok(None)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

async fn require_csrf_double_submit(
    request: Request<Body>,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    if !is_csrf_protected_method(request.method()) {
        return Ok(next.run(request).await);
    }

    let Some(cookie_token) =
        xsrf_cookie_token(request.headers()).map_err(|_| StatusCode::FORBIDDEN)?
    else {
        return Ok(next.run(request).await);
    };
    let Some(header_token) = request
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(StatusCode::FORBIDDEN);
    };

    if constant_time_eq(header_token.as_bytes(), cookie_token.as_bytes()) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn insert_static_response_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

async fn attach_gateway_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    insert_static_response_header(headers, "x-content-type-options", "nosniff");
    insert_static_response_header(headers, "x-frame-options", "DENY");
    insert_static_response_header(headers, "referrer-policy", "no-referrer");
    insert_static_response_header(
        headers,
        "strict-transport-security",
        STRICT_TRANSPORT_SECURITY_VALUE,
    );
    insert_static_response_header(
        headers,
        "content-security-policy",
        CONTENT_SECURITY_POLICY_VALUE,
    );
    insert_static_response_header(headers, "permissions-policy", PERMISSIONS_POLICY_VALUE);

    response
}

// ---------------------------------------------------------------------------
// Dashboard handlers (layout templates + feedback issues)
// ---------------------------------------------------------------------------

/// PUT /api/v1/layout-templates — upsert a layout template.
async fn handle_layout_template_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let metadata = match LayoutTemplateMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    let actor =
        match require_authenticated_session_actor(&state, &headers, metadata.updated_at).await {
            Ok(actor) => actor,
            Err(e) => return auth_boundary_error_response(e),
        };
    if let Err(e) = reject_caller_supplied_identity_field(&body, "userDid") {
        return metadata_error_response(e);
    }
    if let Err(e) = reject_caller_supplied_builtin_layout(&body) {
        return metadata_error_response(e);
    }
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database unavailable" })),
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

    match crate::db::upsert_layout_template(
        db,
        &id,
        Some(actor.as_str()),
        name,
        &layout_json,
        &hidden_panels,
        false,
        metadata.created_at,
        metadata.updated_at,
    )
    .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": id, "status": "saved" })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "layout template belongs to another actor or is code-owned"
            })),
        )
            .into_response(),
        Err(e) => internal_error_response(e, "layout template upsert", "template save failed"),
    }
}

/// DELETE /api/v1/layout-templates/:id — delete a user layout template.
async fn handle_layout_template_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let actor = match require_authenticated_session_actor_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database unavailable" })),
            )
                .into_response();
        }
    };
    match crate::db::delete_layout_template(db, &id, actor.as_str()).await {
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
        Err(e) => internal_error_response(e, "layout template delete", "template delete failed"),
    }
}

/// GET /api/v1/layout-templates — list all layout templates.
async fn handle_layout_templates_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let actor = match require_authenticated_session_actor_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database unavailable" })),
            )
                .into_response();
        }
    };
    match crate::db::list_layout_templates(db, Some(actor.as_str())).await {
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
        Err(e) => internal_error_response(e, "layout template list", "templates unavailable"),
    }
}

/// POST /api/v1/feedback-issues — file a new feedback issue.
async fn handle_feedback_issue_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let metadata = match FeedbackIssueCreateMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    let actor =
        match require_authenticated_session_actor(&state, &headers, metadata.created_at).await {
            Ok(actor) => actor,
            Err(e) => return auth_boundary_error_response(e),
        };
    if let Err(e) = reject_caller_supplied_identity_field(&body, "reporterDid") {
        return metadata_error_response(e);
    }
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database unavailable" })),
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
        Some(actor.as_str()),
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
        Err(e) => {
            internal_error_response(e, "feedback issue insert", "feedback issue filing failed")
        }
    }
}

/// GET /api/v1/feedback-issues — list feedback issues.
async fn handle_feedback_issues_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let actor = match require_authenticated_session_actor_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database unavailable" })),
            )
                .into_response();
        }
    };
    match crate::db::list_feedback_issues(db, Some(actor.as_str()), None).await {
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
        Err(e) => internal_error_response(e, "feedback issue list", "feedback issues unavailable"),
    }
}

/// PATCH /api/v1/feedback-issues/:id — update issue status/assignment.
async fn handle_feedback_issue_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let metadata = match FeedbackIssueUpdateMetadata::from_body(&body) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    let actor =
        match require_authenticated_session_actor(&state, &headers, metadata.updated_at).await {
            Ok(actor) => actor,
            Err(e) => return auth_boundary_error_response(e),
        };
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "database unavailable" })),
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

    match crate::db::update_feedback_issue_status(
        db,
        &id,
        actor.as_str(),
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
        Err(e) => {
            internal_error_response(e, "feedback issue update", "feedback issue update failed")
        }
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
    build_router_with_extra_routes(state, None)
}

fn build_router_with_extra_routes(state: AppState, extra: Option<Router>) -> Router {
    let mut router = build_unlayered_router(state.clone());
    if let Some(extra_router) = extra {
        router = router.merge(extra_router);
    }
    apply_gateway_layers(router, state, GLOBAL_CONCURRENCY_LIMIT)
}

fn build_unlayered_router(state: AppState) -> Router {
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
        .route(
            "/api/v1/auth/register",
            post(handle_auth_register).layer(DefaultBodyLimit::max(MAX_DID_DOCUMENT_BODY_BYTES)),
        )
        .route("/api/v1/auth/login", post(handle_auth_login))
        .route("/api/v1/auth/refresh", post(handle_auth_refresh))
        .route("/api/v1/auth/me", get(handle_auth_me))
        .route("/api/v1/auth/logout", post(handle_auth_logout))
        // Agents (static route before parameterised to avoid ambiguity)
        .route(
            "/api/v1/agents/enroll",
            post(handle_agents_enroll).layer(DefaultBodyLimit::max(MAX_DID_DOCUMENT_BODY_BYTES)),
        )
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
}

fn gateway_rate_limit_key(request: &Request<Body>) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string())
        .unwrap_or_else(|| "unknown-client".to_owned())
}

fn gateway_rate_limit_response(retry_after_ms: u64) -> Response {
    let retry_after_seconds = retry_after_ms.saturating_add(999) / 1000;
    let mut response =
        (StatusCode::TOO_MANY_REQUESTS, "gateway rate limit exceeded").into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

async fn enforce_gateway_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_key = gateway_rate_limit_key(&request);
    let now_ms = match state.try_now_ms() {
        Ok(now_ms) => now_ms,
        Err(message) => {
            tracing::error!(message, "Gateway rate limiter timestamp unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway rate limiter unavailable",
            )
                .into_response();
        }
    };

    let outcome = match state.rate_limiter.lock() {
        Ok(mut limiter) => limiter.check(&client_key, now_ms),
        Err(_) => {
            tracing::error!("Gateway rate limiter mutex poisoned");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway rate limiter unavailable",
            )
                .into_response();
        }
    };

    match outcome {
        GatewayRateLimitOutcome::Allowed => next.run(request).await,
        GatewayRateLimitOutcome::Limited { retry_after_ms } => {
            gateway_rate_limit_response(retry_after_ms)
        }
    }
}

fn apply_gateway_layers(router: Router, state: AppState, concurrency_limit: usize) -> Router {
    router
        .layer(middleware::from_fn(require_csrf_double_submit))
        .layer(middleware::from_fn_with_state(
            state,
            enforce_gateway_rate_limit,
        ))
        // Attach browser-facing hardening headers to every gateway response. (F-116)
        .layer(middleware::from_fn(attach_gateway_security_headers))
        // Cap inbound body size before the handler reads a single byte. (A-022)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        // Emit structured tracing spans for every request/response.
        .layer(TraceLayer::new_for_http())
        // Global concurrency ceiling as DoS admission control.
        .layer(GlobalConcurrencyLimitLayer::new(concurrency_limit))
}

// ---------------------------------------------------------------------------
// Graceful shutdown signal
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(err = %e, "Failed to install Ctrl+C shutdown handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let sigterm = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                tracing::warn!(err = %e, "Failed to install SIGTERM shutdown handler");
                std::future::pending::<()>().await;
            }
        }
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
/// The `extra` router is merged before gateway-wide layers are applied so
/// injected endpoints (e.g. `/metrics`) share the same admission controls.
pub async fn serve_with_extra_routes(
    config: GatewayConfig,
    pool: Option<sqlx::PgPool>,
    extra: Option<Router>,
) -> Result<()> {
    validate_tls_config(config.tls_config.as_ref())?;
    let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
    let state = AppState::new(pool, registry);
    let app = build_router_with_extra_routes(state, extra);

    if let Some(tls_config) = config.tls_config.as_ref() {
        let bind_address = parse_tls_bind_address(&config.bind_address)?;
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            tracing::debug!("Rustls crypto provider was already installed");
        }
        let rustls_config =
            RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
                .await
                .map_err(|e| GatewayError::Internal(format!("TLS configuration failed: {e}")))?;
        let handle = axum_server::Handle::new();
        let server = axum_server::bind_rustls(bind_address, rustls_config)
            .handle(handle.clone())
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());

        tracing::info!("exo-gateway listening with TLS on {}", config.bind_address);

        tokio::pin!(server);
        let result = tokio::select! {
            result = &mut server => result,
            () = shutdown_signal() => {
                handle.graceful_shutdown(None);
                (&mut server).await
            }
        };

        return result.map_err(|e| GatewayError::Internal(format!("server error: {e}")));
    }

    let listener = TcpListener::bind(&config.bind_address)
        .await
        .map_err(|e| GatewayError::Internal(format!("bind failed: {e}")))?;

    tracing::info!("exo-gateway listening on {}", config.bind_address);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, header},
    };
    use exo_core::{
        Timestamp,
        crypto::{generate_keypair, sign},
        hlc::HybridClock,
    };
    use exo_identity::did::{DidDocument, VerificationMethod};
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use super::*; // for .oneshot()

    fn state() -> AppState {
        AppState::new(None, Arc::new(RwLock::new(LocalDidRegistry::new())))
    }

    async fn probe() -> StatusCode {
        StatusCode::OK
    }

    fn rate_limited_state(
        max_requests_per_window: u32,
        window_ms: u64,
        wall: Arc<AtomicU64>,
    ) -> AppState {
        let wall_for_clock = Arc::clone(&wall);
        let mut state = AppState::new_with_clock(
            None,
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            HybridClock::with_wall_clock(move || wall_for_clock.load(Ordering::Relaxed)),
        );
        state.rate_limiter = Arc::new(Mutex::new(GatewayRateLimiter::with_limits(
            max_requests_per_window,
            window_ms,
            8,
        )));
        state
    }

    fn request_from(path: &str, address: SocketAddr, forwarded_for: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header("x-forwarded-for", forwarded_for)
            .extension(ConnectInfo(address))
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn gateway_uptime_uses_injected_hlc_source() {
        let wall = Arc::new(AtomicU64::new(80_000));
        let wall_for_clock = Arc::clone(&wall);
        let state = AppState::new_with_clock(
            None,
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            HybridClock::with_wall_clock(move || wall_for_clock.load(Ordering::Relaxed)),
        );

        wall.store(86_000, Ordering::Relaxed);

        assert_eq!(state.uptime_seconds(), 6);
    }

    #[test]
    fn gateway_server_runtime_sources_do_not_read_wall_clock_directly() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        let timestamp_now = format!("{}{}", "Timestamp::", "now_utc()");
        let system_time_now = format!("{}{}", "SystemTime::", "now()");
        let instant_now = format!("{}{}", "Instant::", "now()");

        assert!(!production.contains(&timestamp_now));
        assert!(!production.contains(&system_time_now));
        assert!(!production.contains(&instant_now));
    }

    #[test]
    fn shutdown_signal_setup_failures_are_not_silent_or_panicking() {
        let source = include_str!("server.rs");
        let shutdown_signal = source_between(
            source,
            "async fn shutdown_signal",
            "// ---------------------------------------------------------------------------\n// Async server entry point",
        );

        assert!(
            !shutdown_signal.contains("let _ = tokio::signal::ctrl_c().await"),
            "Ctrl+C listener errors must be observed"
        );
        assert!(
            !shutdown_signal.contains("panic!(\"failed to install SIGTERM handler\")"),
            "SIGTERM listener setup errors must not panic the gateway"
        );
    }

    #[tokio::test]
    async fn conflict_declaration_loader_fails_closed_without_db_pool() {
        let state = state();
        let actor = Did::new("did:exo:alice").expect("valid DID");
        let err = state
            .load_conflict_declarations(&actor)
            .await
            .expect_err("missing conflict register must fail closed");
        assert!(
            err.to_string().contains("database"),
            "error should identify missing DB-backed conflict register, got: {err}"
        );
    }

    #[test]
    fn conflict_declaration_payload_validation_rejects_wrong_actor_and_placeholders() {
        let actor = Did::new("did:exo:alice").expect("valid DID");
        let related = Did::new("did:exo:tenant-a").expect("valid DID");

        let valid = serde_json::json!({
            "declarant_did": actor,
            "nature": "financial ownership",
            "related_dids": [related],
            "timestamp": { "physical_ms": 7000, "logical": 0 }
        });
        let decoded =
            decode_conflict_declaration_payload(&actor, valid).expect("valid declaration payload");
        assert_eq!(decoded.declarant_did, actor);

        let wrong_actor = serde_json::json!({
            "declarant_did": "did:exo:bob",
            "nature": "financial ownership",
            "related_dids": ["did:exo:tenant-a"],
            "timestamp": { "physical_ms": 7000, "logical": 0 }
        });
        assert!(decode_conflict_declaration_payload(&actor, wrong_actor).is_err());

        let zero_timestamp = serde_json::json!({
            "declarant_did": actor,
            "nature": "financial ownership",
            "related_dids": ["did:exo:tenant-a"],
            "timestamp": { "physical_ms": 0, "logical": 0 }
        });
        assert!(decode_conflict_declaration_payload(&actor, zero_timestamp).is_err());
    }

    #[tokio::test]
    async fn gateway_global_concurrency_limit_queues_excess_requests() {
        #[derive(Clone)]
        struct HoldState {
            entered: Arc<Notify>,
            release: Arc<Notify>,
        }

        async fn hold(State(state): State<HoldState>) -> StatusCode {
            state.entered.notify_one();
            state.release.notified().await;
            StatusCode::OK
        }

        async fn probe() -> StatusCode {
            StatusCode::OK
        }

        let hold_state = HoldState {
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        let app = apply_gateway_layers(
            Router::new()
                .route("/hold", get(hold))
                .route("/probe", get(probe))
                .with_state(hold_state.clone()),
            state(),
            1,
        );

        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::builder().uri("/hold").body(Body::empty()).unwrap()),
        );
        hold_state.entered.notified().await;

        let queued = tokio::time::timeout(
            Duration::from_millis(50),
            app.clone().oneshot(
                Request::builder()
                    .uri("/probe")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await;
        assert!(
            queued.is_err(),
            "request must queue while the limit is held"
        );

        hold_state.release.notify_one();
        let first_response = first.await.unwrap().unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);

        let next_response = tokio::time::timeout(
            Duration::from_secs(1),
            app.oneshot(
                Request::builder()
                    .uri("/probe")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(next_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn gateway_rejects_requests_over_default_per_client_rate_budget() {
        let app = build_router(state());

        for _ in 0..GATEWAY_RATE_LIMIT_REQUESTS_PER_WINDOW {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
    }

    #[tokio::test]
    async fn gateway_rate_limit_resets_after_hlc_window() {
        let wall = Arc::new(AtomicU64::new(10_000));
        let state = rate_limited_state(1, 60_000, Arc::clone(&wall));
        let app = apply_gateway_layers(
            Router::new().route("/probe", get(probe)),
            state,
            GLOBAL_CONCURRENCY_LIMIT,
        );

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        wall.store(70_000, Ordering::Relaxed);

        let third = app
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(third.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn gateway_rate_limit_uses_socket_ip_not_spoofable_forwarded_headers() {
        let wall = Arc::new(AtomicU64::new(25_000));
        let state = rate_limited_state(1, 60_000, wall);
        let app = apply_gateway_layers(
            Router::new().route("/probe", get(probe)),
            state,
            GLOBAL_CONCURRENCY_LIMIT,
        );

        let same_ip_first = app
            .clone()
            .oneshot(request_from(
                "/probe",
                "192.0.2.10:1000".parse().unwrap(),
                "203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(same_ip_first.status(), StatusCode::OK);

        let same_ip_new_port = app
            .clone()
            .oneshot(request_from(
                "/probe",
                "192.0.2.10:2000".parse().unwrap(),
                "203.0.113.88",
            ))
            .await
            .unwrap();
        assert_eq!(same_ip_new_port.status(), StatusCode::TOO_MANY_REQUESTS);

        let different_socket_ip_same_forwarded_header = app
            .oneshot(request_from(
                "/probe",
                "192.0.2.11:1000".parse().unwrap(),
                "203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(
            different_socket_ip_same_forwarded_header.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn gateway_extra_routes_receive_rate_limit_layers() {
        let wall = Arc::new(AtomicU64::new(40_000));
        let state = rate_limited_state(1, 60_000, wall);
        let app = build_router_with_extra_routes(
            state,
            Some(Router::new().route("/metrics", get(probe))),
        );

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn gateway_rate_limit_source_uses_hlc_btreemap_and_socket_identity() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            production.contains("BTreeMap<"),
            "gateway rate limiter must use deterministic BTreeMap storage"
        );
        assert!(
            production.contains("from_fn_with_state")
                && production.contains("enforce_gateway_rate_limit"),
            "gateway router must install a stateful request-rate middleware"
        );
        assert!(
            production.contains("HybridClock") && !production.contains("Instant::now()"),
            "gateway rate limiting must use the gateway HLC source, not system Instant"
        );
        assert!(
            production.contains("ConnectInfo<SocketAddr>")
                && !production.contains("x-forwarded-for"),
            "gateway rate limiting must key clients from socket identity, not spoofable forwarding headers"
        );
    }

    #[tokio::test]
    async fn gateway_layers_attach_security_headers() {
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

        let headers = resp.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers
                .get("strict-transport-security")
                .and_then(|v| v.to_str().ok()),
            Some("max-age=63072000; includeSubDomains")
        );
        assert_eq!(
            headers
                .get("content-security-policy")
                .and_then(|v| v.to_str().ok()),
            Some("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        );
        assert_eq!(
            headers
                .get("permissions-policy")
                .and_then(|v| v.to_str().ok()),
            Some(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            )
        );
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

    async fn insert_test_session(pool: &sqlx::PgPool, token: &str, actor_did: &str) {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind(token)
        .bind(actor_did)
        .bind(10_000_i64)
        .bind(20_000_i64)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_test_user(pool: &sqlx::PgPool, did: &str, tenant_id: &str) {
        let email = format!("{did}@example.invalid");
        sqlx::query("DELETE FROM users WHERE did = $1 OR email = $2")
            .bind(did)
            .bind(&email)
            .execute(pool)
            .await
            .unwrap();
        db::insert_user(
            pool,
            did,
            "Reader",
            &email,
            &serde_json::json!(["reader"]),
            tenant_id,
            10_000_i64,
            "Active",
            "Unenrolled",
            "redacted-test-hash",
            "redacted-test-salt",
            false,
        )
        .await
        .unwrap();
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

    #[test]
    fn start_tls_rejects_empty_certificate_or_key_paths() {
        for tls_config in [
            TlsConfig {
                cert_path: String::new(),
                key_path: "key.pem".into(),
            },
            TlsConfig {
                cert_path: "cert.pem".into(),
                key_path: String::new(),
            },
            TlsConfig {
                cert_path: "  ".into(),
                key_path: "key.pem".into(),
            },
            TlsConfig {
                cert_path: "cert.pem".into(),
                key_path: "\t".into(),
            },
        ] {
            let config = GatewayConfig {
                tls_config: Some(tls_config),
                ..Default::default()
            };

            assert!(
                start(config).is_err(),
                "configured TLS must require non-empty cert and key paths"
            );
        }
    }

    #[test]
    fn serve_with_tls_uses_rustls_instead_of_plain_tcp() {
        let source = include_str!("server.rs");
        let serve = source_between(
            source,
            "pub async fn serve_with_extra_routes",
            "// ---------------------------------------------------------------------------\n// Tests",
        );

        assert!(
            serve.contains("RustlsConfig::from_pem_file"),
            "TLS-configured gateway startup must load the configured certificate and key"
        );
        assert!(
            serve.contains("bind_rustls"),
            "TLS-configured gateway startup must bind a Rustls HTTPS server"
        );
        assert!(
            serve.contains("config.tls_config.as_ref()"),
            "gateway startup must branch on tls_config instead of ignoring it"
        );
        assert!(
            serve.contains("TcpListener::bind(&config.bind_address)"),
            "plaintext startup remains available only when tls_config is absent"
        );
    }

    #[test]
    fn serve_with_tls_installs_rustls_provider_before_loading_pem() {
        let source = include_str!("server.rs");
        let serve = source_between(
            source,
            "pub async fn serve_with_extra_routes",
            "// ---------------------------------------------------------------------------\n// Tests",
        );

        let provider = serve
            .find("default_provider")
            .expect("TLS branch must select the Rustls ring crypto provider explicitly");
        let provider_install = provider
            + serve[provider..]
                .find("install_default")
                .expect("TLS branch must install the Rustls crypto provider explicitly");
        let pem_load = serve
            .find("RustlsConfig::from_pem_file")
            .expect("TLS branch must load the configured PEM material");

        assert!(
            provider_install < pem_load,
            "Rustls provider must be installed before loading PEM TLS configuration"
        );
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
    async fn auth_register_returns_503_when_local_did_registry_capacity_is_exhausted() {
        let (pk, _) = generate_keypair();
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        {
            let mut guard = registry.write().unwrap();
            for i in 0..exo_identity::registry::MAX_LOCAL_DID_REGISTRY_DOCUMENTS {
                let mut doc = minimal_doc(&format!("did:exo:capacity-{i:05}"));
                doc.public_keys.push(pk);
                guard.register(doc).unwrap();
            }
        }

        let st = AppState::new(None, registry);
        let body = serde_json::to_string(&minimal_doc("did:exo:capacity-overflow")).unwrap();
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

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn auth_me_missing_bearer_returns_401() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_me_x_actor_did_header_without_session_is_rejected() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_me_unknown_x_actor_did_header_without_session_is_rejected() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_me_uses_session_actor_not_spoofed_header() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        sqlx::query("DELETE FROM sessions WHERE token IN ($1, $2)")
            .bind("auth-me-alice-token")
            .bind("auth-me-bob-token")
            .execute(&pool)
            .await
            .unwrap();

        let alice_doc = minimal_doc("did:exo:auth-me-alice");
        let bob_doc = minimal_doc("did:exo:auth-me-bob");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        {
            let mut guard = registry.write().unwrap();
            guard.register(alice_doc).unwrap();
            guard.register(bob_doc).unwrap();
        }
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind("auth-me-alice-token")
        .bind("did:exo:auth-me-alice")
        .bind(10_000_i64)
        .bind(20_000_i64)
        .execute(&pool)
        .await
        .unwrap();

        let app = build_router(AppState::new(Some(pool.clone()), registry));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/me")
                    .header("authorization", "Bearer auth-me-alice-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .header("x-actor-did", "did:exo:auth-me-bob")
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
        assert_eq!(val["id"], "did:exo:auth-me-alice");

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("auth-me-alice-token")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn auth_me_handler_uses_session_actor_not_x_actor_did() {
        let source = include_str!("server.rs");
        let handler = source_between(source, "async fn handle_auth_me", "/// GET /api/v1/agents");

        assert!(
            handler.contains("require_authenticated_session_actor_from_header"),
            "auth/me must resolve the DID from the authenticated bearer session"
        );
        assert!(
            !handler.contains("x-actor-did"),
            "auth/me must not trust spoofable x-actor-did headers"
        );
    }

    #[test]
    fn sensitive_read_handlers_require_session_before_state_reads() {
        let source = include_str!("server.rs");
        let agents_list = source_between(
            source,
            "async fn handle_agents_list",
            "/// GET /api/v1/agents/:did",
        );
        let agent_get = source_between(
            source,
            "async fn handle_agent_get",
            "/// GET /api/v1/identity/:did/score",
        );
        let users_list = source_between(
            source,
            "async fn handle_users_list",
            "/// GET /api/v1/decisions/:id",
        );
        let decision_get = source_between(
            source,
            "async fn handle_decision_get",
            "/// GET /api/v1/audit/:decision_id",
        );
        let audit_trail = source_between(
            source,
            "async fn handle_audit_trail",
            "/// POST /api/v1/agents/enroll",
        );

        for (name, handler, state_read) in [
            ("agents list", agents_list, "registry_list_dids"),
            ("agent get", agent_get, "registry_resolve_document"),
            ("users list", users_list, "registry_list_dids"),
            ("decision get", decision_get, "state.require_db"),
            ("audit trail", audit_trail, "state.require_db"),
        ] {
            let auth = handler
                .find("require_authenticated_session_actor_from_header")
                .or_else(|| handler.find("require_authenticated_session_user_from_header"))
                .unwrap_or_else(|| panic!("{name} must authenticate the bearer session"));
            let read = handler
                .find(state_read)
                .unwrap_or_else(|| panic!("{name} must read protected state through {state_read}"));
            assert!(
                auth < read,
                "{name} must authenticate before reading protected gateway state"
            );
        }
    }

    #[test]
    fn decision_get_uses_authenticated_actor_tenant_for_lookup() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_decision_get",
            "/// GET /api/v1/audit/:decision_id",
        );

        assert!(
            handler.contains("require_authenticated_session_user_from_header"),
            "decision get must load the authenticated session actor's tenant profile"
        );
        assert!(
            handler.contains("db::find_decision(db, &id, &actor.tenant_id)"),
            "decision get must query decisions using the authenticated actor tenant"
        );
        assert!(
            !handler.contains("SELECT payload FROM decisions WHERE id_hash = $1"),
            "decision get must not perform an unscoped id_hash lookup"
        );
    }

    #[test]
    fn async_registry_handlers_do_not_block_workers_or_leak_register_errors() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        for needle in [
            "state.registry.read().unwrap_or_else",
            "state.registry.write().unwrap_or_else",
        ] {
            assert!(
                !production.contains(needle),
                "async handlers must not acquire std::sync::RwLock on Tokio workers: {needle}"
            );
        }
        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "std registry access must run on the blocking pool when used by async handlers"
        );

        for (start, end) in [
            ("async fn handle_auth_register", "/// GET /api/v1/auth/me"),
            (
                "async fn handle_agents_enroll",
                "// ---------------------------------------------------------------------------\n// Session auth handlers",
            ),
        ] {
            let handler = source_between(source, start, end);
            assert!(
                !handler.contains("e.to_string()"),
                "registration conflict responses must not expose registry internals"
            );
        }
    }

    #[test]
    fn did_document_routes_have_explicit_tight_body_limits() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");
        let router = source_between(source, "pub fn build_router", "fn apply_gateway_layers");
        let compact_router: String = router.chars().filter(|ch| !ch.is_whitespace()).collect();

        assert!(
            production.contains("const MAX_DID_DOCUMENT_BODY_BYTES: usize = 64 * 1024;"),
            "DID document JSON must have a tighter route-local body budget"
        );
        assert!(
            compact_router.contains(
                "\"/api/v1/auth/register\",post(handle_auth_register).layer(DefaultBodyLimit::max(MAX_DID_DOCUMENT_BODY_BYTES))"
            ),
            "auth/register must apply the DID document body budget at the route"
        );
        assert!(
            compact_router.contains(
                "\"/api/v1/agents/enroll\",post(handle_agents_enroll).layer(DefaultBodyLimit::max(MAX_DID_DOCUMENT_BODY_BYTES))"
            ),
            "agents/enroll must apply the DID document body budget at the route"
        );
    }

    #[test]
    fn database_unavailable_responses_do_not_expose_env_config_details() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        for needle in [
            "start with DATABASE_URL",
            "Start the gateway with DATABASE_URL",
            "\"error\": \"database not configured\"",
            "no database configured",
        ] {
            assert!(
                !production.contains(needle),
                "database-unavailable responses must not expose deployment config details: {needle}"
            );
        }
        assert!(
            production.contains("\"error\": \"database unavailable\""),
            "database-unavailable responses should use a generic client-facing error"
        );
    }

    #[test]
    fn internal_http_errors_do_not_expose_display_strings_to_clients() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        for needle in [
            "Json(serde_json::json!({ \"error\": e.to_string() }))",
            "Json(serde_json::json!({ \"error\": other.to_string() }))",
        ] {
            assert!(
                !production.contains(needle),
                "gateway HTTP 5xx responses must log internal errors and return generic client messages: {needle}"
            );
        }
    }

    #[tokio::test]
    async fn agents_list_missing_session_returns_401_before_registry_read() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_get_missing_session_returns_401_before_registry_read() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn users_list_missing_session_returns_401_before_registry_read() {
        let doc = minimal_doc("did:exo:user-listed");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(None, registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn decision_get_missing_session_returns_401_before_db_lookup() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_trail_missing_session_returns_401_before_db_lookup() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agents_list_returns_registered_dids() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_session(&pool, "agents-list-token", "did:exo:reader").await;
        let doc = minimal_doc("did:exo:listed");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(Some(pool.clone()), registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents")
                    .header("authorization", "Bearer agents-list-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
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
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("agents-list-token")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn agent_get_known_did_returns_200() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_session(&pool, "agent-get-token", "did:exo:reader").await;
        let doc = minimal_doc("did:exo:agent-get");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(Some(pool.clone()), registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:agent-get")
                    .header("authorization", "Bearer agent-get-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("agent-get-token")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn agent_get_unknown_returns_404() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_session(&pool, "agent-get-unknown-token", "did:exo:reader").await;
        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:nobody")
                    .header("authorization", "Bearer agent-get-unknown-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("agent-get-unknown-token")
            .execute(&pool)
            .await
            .unwrap();
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

    #[cfg(not(feature = "unaudited-gateway-graphql-api"))]
    #[tokio::test]
    async fn graphql_get_default_off_returns_403_with_initiative() {
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
    async fn graphql_post_feature_on_refuses_mutations_without_verified_authz_context() {
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
        let errors = val["errors"].as_array().expect("GraphQL errors array");
        assert!(
            errors.iter().any(|error| error["message"]
                .as_str()
                .is_some_and(|message| message.contains("unaudited_graphql_mutations_disabled"))),
            "feature-on GraphQL mutations must fail closed without verified authz context: {val}"
        );
    }

    #[tokio::test]
    async fn vote_route_missing_session_returns_401_before_conflict_register_lookup() {
        let body = serde_json::to_string(&serde_json::json!({
            "decision_id": "d1",
            "voter_did": "did:exo:alice",
            "affected_dids": ["did:exo:tenant-a"],
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

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_session(&pool, "users-list-token", "did:exo:reader").await;
        let doc = minimal_doc("did:exo:user-listed");
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let app = build_router(AppState::new(Some(pool.clone()), registry));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/users")
                    .header("authorization", "Bearer users-list-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
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
            val["users"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("did:exo:user-listed"))
        );
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("users-list-token")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decision_get_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/decisions/some-decision-id")
                    .header("authorization", "Bearer some-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn decision_get_authenticated_session_returns_payload() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_user(&pool, "did:exo:decision-reader", "tenant-read").await;
        insert_test_session(&pool, "decision-get-token", "did:exo:decision-reader").await;
        sqlx::query("DELETE FROM decisions WHERE id_hash = $1")
            .bind("decision-get-authenticated")
            .execute(&pool)
            .await
            .unwrap();
        let payload = serde_json::json!({
            "id": "decision-get-authenticated",
            "tenant_id": "tenant-read",
            "status": "Open",
        });
        db::insert_decision(
            &pool,
            "decision-get-authenticated",
            "tenant-read",
            "Open",
            "Authenticated read",
            "Routine",
            "did:exo:author",
            10_000,
            "exochain-constitution-v1",
            &payload,
        )
        .await
        .unwrap();

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/decisions/decision-get-authenticated")
                    .header("authorization", "Bearer decision-get-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
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
        assert_eq!(val, payload);

        sqlx::query("DELETE FROM decisions WHERE id_hash = $1")
            .bind("decision-get-authenticated")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("decision-get-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind("did:exo:decision-reader")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decision_get_rejects_cross_tenant_session_actor() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_user(&pool, "did:exo:tenant-b-reader", "tenant-b").await;
        insert_test_session(
            &pool,
            "decision-get-cross-tenant-token",
            "did:exo:tenant-b-reader",
        )
        .await;
        sqlx::query("DELETE FROM decisions WHERE id_hash = $1")
            .bind("decision-get-cross-tenant")
            .execute(&pool)
            .await
            .unwrap();
        let payload = serde_json::json!({
            "id": "decision-get-cross-tenant",
            "tenant_id": "tenant-a",
            "status": "Open",
        });
        db::insert_decision(
            &pool,
            "decision-get-cross-tenant",
            "tenant-a",
            "Open",
            "Cross-tenant read",
            "Routine",
            "did:exo:author",
            11_000,
            "exochain-constitution-v1",
            &payload,
        )
        .await
        .unwrap();

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/decisions/decision-get-cross-tenant")
                    .header("authorization", "Bearer decision-get-cross-tenant-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        sqlx::query("DELETE FROM decisions WHERE id_hash = $1")
            .bind("decision-get-cross-tenant")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("decision-get-cross-tenant-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind("did:exo:tenant-b-reader")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn audit_trail_without_db_returns_503() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit/decision-123")
                    .header("authorization", "Bearer some-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn audit_trail_authenticated_session_returns_entries() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_session(&pool, "audit-trail-token", "did:exo:reader").await;
        sqlx::query("DELETE FROM audit_entries WHERE sequence = $1 OR decision_id = $2")
            .bind(901_004_i64)
            .bind("audit-authenticated-decision")
            .execute(&pool)
            .await
            .unwrap();
        db::insert_audit_entry(
            &pool,
            901_004,
            "prev",
            "event",
            "VoteCast",
            "did:exo:reader",
            "tenant-read",
            "audit-authenticated-decision",
            10_000,
            0,
            "entry",
        )
        .await
        .unwrap();

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/audit/audit-authenticated-decision")
                    .header("authorization", "Bearer audit-trail-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
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
        assert_eq!(val["decision_id"], "audit-authenticated-decision");
        assert_eq!(val["audit_entries"].as_array().unwrap().len(), 1);
        assert_eq!(val["audit_entries"][0]["actor"], "did:exo:reader");

        sqlx::query("DELETE FROM audit_entries WHERE sequence = $1 OR decision_id = $2")
            .bind(901_004_i64)
            .bind("audit-authenticated-decision")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("audit-trail-token")
            .execute(&pool)
            .await
            .unwrap();
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
            "signature": hex::encode(signature.to_bytes())
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

    #[tokio::test]
    async fn dashboard_persistence_routes_reject_missing_bearer_before_db() {
        let requests = [
            (
                Method::PUT,
                "/api/v1/layout-templates",
                Some(serde_json::json!({
                    "id": "layout-1",
                    "name": "Layout",
                    "layout": [],
                    "hiddenPanels": [],
                    "createdAt": 10_000,
                    "updatedAt": 10_001
                })),
            ),
            (Method::GET, "/api/v1/layout-templates", None),
            (Method::DELETE, "/api/v1/layout-templates/layout-1", None),
            (
                Method::POST,
                "/api/v1/feedback-issues",
                Some(serde_json::json!({
                    "id": "issue-1",
                    "title": "Bad panel state",
                    "sourceWidgetId": "panel-1",
                    "createdAt": 10_000
                })),
            ),
            (Method::GET, "/api/v1/feedback-issues", None),
            (
                Method::PATCH,
                "/api/v1/feedback-issues/issue-1",
                Some(serde_json::json!({
                    "status": "triaged",
                    "updatedAt": 10_001
                })),
            ),
        ];

        for (method, uri, body) in requests {
            let app = build_router(state());
            let request_body = body
                .map(|value| Body::from(value.to_string()))
                .unwrap_or_else(Body::empty);
            let response = app
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(request_body)
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} must reject missing bearer before DB access"
            );
        }
    }

    #[test]
    fn dashboard_persistence_handlers_do_not_trust_body_identity_scope() {
        let source = include_str!("server.rs");
        let layout_put = source_between(
            source,
            "async fn handle_layout_template_put",
            "/// DELETE /api/v1/layout-templates/:id",
        );
        let feedback_create = source_between(
            source,
            "async fn handle_feedback_issue_create",
            "/// GET /api/v1/feedback-issues",
        );

        assert!(
            !layout_put.contains(".get(\"userDid\")"),
            "layout user_did must come from the authenticated session actor"
        );
        assert!(
            !layout_put.contains(".get(\"isBuiltIn\")"),
            "callers must not be able to persist code-owned built-in templates"
        );
        assert!(
            !feedback_create.contains(".get(\"reporterDid\")"),
            "feedback reporter_did must come from the authenticated session actor"
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

    #[test]
    fn advance_pace_handler_authenticates_session_actor_before_adjudication() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_advance_pace",
            "// ---------------------------------------------------------------------------\n// Legal / eDiscovery handlers",
        );
        let auth_index = handler
            .find("require_authenticated_session_actor_from_header")
            .expect("advance_pace must authenticate a bearer session");
        let context_index = handler
            .find("build_adjudication_context(&actor)")
            .expect("advance_pace must adjudicate the authenticated session actor");
        let kernel_index = handler
            .find("state.kernel.adjudicate")
            .expect("advance_pace must retain kernel adjudication");

        assert!(
            auth_index < context_index && context_index < kernel_index,
            "advance_pace must authenticate before building the adjudication context"
        );
        assert!(
            handler.contains("if actor != did"),
            "advance_pace must reject path-DID spoofing"
        );
        assert!(
            !handler.contains("actor: did.clone()"),
            "advance_pace must not use the caller-controlled path DID as the action actor"
        );
    }

    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_index = source.find(start).expect("source start marker");
        let after_start = &source[start_index..];
        let end_index = after_start.find(end).expect("source end marker");
        &after_start[..end_index]
    }

    #[tokio::test]
    async fn advance_pace_without_authority_returns_403() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("advance-no-authority-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind("advance-no-authority-token")
        .bind("did:exo:alice")
        .bind(1_000_i64)
        .bind(20_000_i64)
        .execute(&pool)
        .await
        .unwrap();

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/did:exo:alice/advance-pace")
                    .header("authorization", "Bearer advance-no-authority-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "10000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Kernel rejects before DB check: no consent + no authority chain.
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("advance-no-authority-token")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn advance_pace_missing_session_returns_401_before_trusting_path_did() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/did:exo:pace-target/advance-pace")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"queuedAt":9000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn user_advance_pace_missing_session_returns_401() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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

    #[tokio::test]
    async fn csrf_cookie_without_header_rejects_mutating_request() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .header(header::COOKIE, "XSRF-TOKEN=tok-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_cookie_with_wrong_header_rejects_mutating_request() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .header(header::COOKIE, "session=abc; XSRF-TOKEN=tok-123")
                    .header(CSRF_HEADER_NAME, "other-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_cookie_with_matching_header_allows_mutating_request() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .header(header::COOKIE, "session=abc; XSRF-TOKEN=tok-123")
                    .header(CSRF_HEADER_NAME, "tok-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_cookie_with_percent_encoding_compares_decoded_value() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .header(
                        header::COOKIE,
                        "session=abc; XSRF-TOKEN=tok%2Fwith%2Bspecial%3Dchars",
                    )
                    .header(CSRF_HEADER_NAME, "tok/with+special=chars")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_absent_cookie_preserves_bearer_api_requests() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_header_not_required_for_read_only_request() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header(header::COOKIE, "XSRF-TOKEN=tok-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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
        authority_link_signature_message,
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
    fn signed_authority_link(grantor: &Did, grantee: &Did) -> AuthorityLink {
        let (public_key, secret_key) = generate_keypair();
        let permissions = PermissionSet::new(vec![Permission::new("vote")]);

        let mut link = AuthorityLink {
            grantor: grantor.clone(),
            grantee: grantee.clone(),
            permissions,
            signature: Vec::new(),
            grantor_public_key: Some(public_key.as_bytes().to_vec()),
        };
        let message = authority_link_signature_message(&link).expect("canonical link payload");
        let signature = sign(message.as_bytes(), &secret_key);
        link.signature = signature.to_bytes().to_vec();
        link
    }

    fn valid_db_context(actor: &Did) -> AdjudicationContext {
        let root = Did::new("did:exo:root-grantor").unwrap();
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "voter".to_string(),
                branch: GovernmentBranch::Executive,
            }],
            authority_chain: AuthorityChain {
                links: vec![signed_authority_link(&root, actor)],
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

    fn db_role_row(actor: &Did, branch: &str) -> crate::db::AgentRoleRow {
        crate::db::AgentRoleRow {
            agent_did: actor.as_str().to_string(),
            role: "voter".to_string(),
            branch: branch.to_string(),
            granted_by: "did:exo:root-grantor".to_string(),
            valid_from: 1,
            expires_at: None,
        }
    }

    fn db_consent_row(actor: &Did, subject_did: &str) -> crate::db::ConsentRecordRow {
        crate::db::ConsentRecordRow {
            subject_did: subject_did.to_string(),
            actor_did: actor.as_str().to_string(),
            scope: "data:vote".to_string(),
            bailment_type: "standard".to_string(),
            status: "active".to_string(),
            created_at: 1,
            expires_at: None,
        }
    }

    fn db_authority_chain_row(
        actor: &Did,
        chain_json: serde_json::Value,
    ) -> crate::db::AuthorityChainRow {
        crate::db::AuthorityChainRow {
            actor_did: actor.as_str().to_string(),
            chain_json,
            valid_from: 1,
            expires_at: None,
        }
    }

    fn assert_internal_error_contains(result: Result<AdjudicationContext>, expected: &str) {
        match result {
            Err(GatewayError::Internal(reason)) => {
                assert!(
                    reason.contains(expected),
                    "error reason {reason:?} did not contain {expected:?}"
                );
            }
            Err(other) => panic!("expected internal error, got {other}"),
            Ok(_) => panic!("expected internal error, got adjudication context"),
        }
    }

    #[test]
    fn adjudication_context_rows_reject_unknown_role_branch() {
        let actor = Did::new("did:exo:alice").unwrap();
        let role_rows = vec![db_role_row(&actor, "tribunal")];

        let result = build_adjudication_context_from_rows(&actor, &role_rows, &[], None);

        assert_internal_error_contains(result, "unknown role branch");
    }

    #[test]
    fn adjudication_context_rows_reject_malformed_consent_subject_did() {
        let actor = Did::new("did:exo:alice").unwrap();
        let consent_rows = vec![db_consent_row(&actor, "not-a-did")];

        let result = build_adjudication_context_from_rows(&actor, &[], &consent_rows, None);

        assert_internal_error_contains(result, "consent subject DID");
    }

    #[test]
    fn adjudication_context_rows_reject_malformed_authority_chain_json() {
        let actor = Did::new("did:exo:alice").unwrap();
        let chain_row = db_authority_chain_row(
            &actor,
            serde_json::json!({
                "links": "not-an-array"
            }),
        );

        let result = build_adjudication_context_from_rows(&actor, &[], &[], Some(&chain_row));

        assert_internal_error_contains(result, "authority chain JSON");
    }

    #[test]
    fn adjudication_context_rows_build_valid_db_context() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let valid_context = valid_db_context(&actor);
        let role_rows = vec![db_role_row(&actor, "executive")];
        let consent_rows = vec![db_consent_row(&actor, "did:exo:root-grantor")];
        let chain_row = db_authority_chain_row(
            &actor,
            serde_json::to_value(&valid_context.authority_chain).unwrap(),
        );

        let ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            Some(&chain_row),
        )
        .unwrap();
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);

        assert_eq!(ctx.actor_roles.len(), 1);
        assert_eq!(ctx.consent_records.len(), 1);
        assert!(matches!(ctx.bailment_state, BailmentState::Active { .. }));
        assert!(verdict.is_permitted(), "valid DB rows must be permitted");
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
