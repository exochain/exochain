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

//! HTTP server skeleton — gateway configuration, lifecycle, and axum routing.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use decision_forum::decision_object::{
    ActorKind, DecisionClass, DecisionObject, DecisionObjectInput, Vote,
};
use exo_core::{Did, Hash256, Signature, Timestamp, hash::hash_structured, hlc::HybridClock};
use exo_gatekeeper::{
    invariants::InvariantSet,
    kernel::{ActionRequest as GkActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{
        AuthorityChain, BailmentState, Permission, PermissionSet, Provenance, TrustedAuthorityKeys,
        TrustedProvenanceKeys,
    },
};
use exo_governance::conflict::ConflictDeclaration;
#[cfg(feature = "production-db")]
use exo_identity::did_verification::validate_verification_method_document_binding;
use exo_identity::{
    did::{DidDocument, DidRegistrationProof},
    error::IdentityError,
    registry::{DidRegistry, LocalDidRegistry},
};
use exo_legal::{
    ediscovery::{self, DiscoveryRequest},
    evidence::Evidence,
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

#[cfg(test)]
use crate::auth::request_signing_payload;
use crate::{
    auth::{
        AuthenticatedActor, AuthenticationMetadata, FRESHNESS_WINDOW_MS, Request as AuthRequest,
        authenticate,
    },
    db,
    error::{GatewayError, Result},
    graphql,
    handlers::health_handler as db_health_handler,
    rest::HealthResponse,
};

const XSRF_COOKIE_PREFIX: &str = "XSRF-TOKEN=";
const CSRF_HEADER_NAME: &str = "x-csrf-token";
#[cfg(test)]
const AUTH_OBSERVED_AT_MS_HEADER: &str = "x-exo-auth-observed-at-ms";
const GLOBAL_CONCURRENCY_LIMIT: usize = 1024;
const GATEWAY_RATE_LIMIT_REQUESTS_PER_WINDOW: u32 = 120;
const GATEWAY_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const GATEWAY_RATE_LIMIT_MAX_CLIENTS: usize = 16_384;
const GATEWAY_RATE_LIMIT_DB_CLOCK_REFRESH_MS: u64 = 1_000;
const STRICT_TRANSPORT_SECURITY_VALUE: &str = "max-age=63072000; includeSubDomains";
const CONTENT_SECURITY_POLICY_VALUE: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const CONTENT_SECURITY_POLICY_DASHBOARD_VALUE: &str = "default-src 'none'; style-src 'self' 'sha256-ZDDfCKNMflVt9qZTlgUze2dLGpfks/qtzWrtNola/68='; script-src 'self' 'sha256-wqJx2WnF4s7cGuMU+qEdtcl5ls/KZFFMvWf6rcHbxtc='; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const PERMISSIONS_POLICY_VALUE: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const LAYOUT_TEMPLATE_MAX_ID_BYTES: usize = 128;
const LAYOUT_TEMPLATE_MAX_NAME_BYTES: usize = 256;
const LAYOUT_TEMPLATE_MAX_ITEMS: usize = 128;
const LAYOUT_TEMPLATE_MAX_HIDDEN_PANELS: usize = 128;
const LAYOUT_TEMPLATE_GRID_COLS: u64 = 24;
const LAYOUT_TEMPLATE_MAX_ROWS: u64 = 1024;
const LAYOUT_TEMPLATE_MAX_HEIGHT: u64 = 128;
const ADVANCED_PACE_STATUS: &str = "Advanced";
const MAX_EDISCOVERY_SCOPE_BYTES: usize = 512;
const MAX_EDISCOVERY_CUSTODIANS: usize = 128;
const MAX_EDISCOVERY_SEARCH_TERMS: usize = 64;
const MAX_EDISCOVERY_SEARCH_TERM_BYTES: usize = 256;
const MAX_EDISCOVERY_CORPUS_DOCUMENTS: usize = 1_000;

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

    fn preflight_limit(
        &mut self,
        client_key: &str,
        now_ms: u64,
    ) -> Option<GatewayRateLimitOutcome> {
        if self.max_requests_per_window == 0 || self.window_ms == 0 {
            return Some(GatewayRateLimitOutcome::Limited {
                retry_after_ms: self.window_ms.max(1),
            });
        }

        self.prune_stale(now_ms);

        if let Some(bucket) = self.clients.get(client_key) {
            let elapsed_ms = now_ms.saturating_sub(bucket.window_start_ms);
            if elapsed_ms < self.window_ms && bucket.request_count >= self.max_requests_per_window {
                return Some(GatewayRateLimitOutcome::Limited {
                    retry_after_ms: self.window_ms.saturating_sub(elapsed_ms).max(1),
                });
            }
            return None;
        }

        if self.clients.len() >= self.max_tracked_clients {
            return Some(GatewayRateLimitOutcome::Limited {
                retry_after_ms: self.window_ms,
            });
        }

        None
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
    pub trusted_rate_limit_proxy_ips: BTreeSet<IpAddr>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8443".into(),
            tls_config: None,
            max_connections: 1024,
            trusted_rate_limit_proxy_ips: BTreeSet::new(),
        }
    }
}

pub fn parse_trusted_rate_limit_proxy_ips(raw: &str) -> Result<BTreeSet<IpAddr>> {
    let mut trusted_proxies = BTreeSet::new();
    for value in raw.split(',') {
        let candidate = value.trim();
        if candidate.is_empty() {
            continue;
        }
        let proxy_ip = candidate.parse::<IpAddr>().map_err(|error| {
            GatewayError::BadRequest(format!(
                "trusted_rate_limit_proxy_ips contains invalid IP '{candidate}': {error}"
            ))
        })?;
        trusted_proxies.insert(proxy_ip);
    }
    Ok(trusted_proxies)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionTimeSource {
    DatabaseWhenAvailable,
    InjectedClock,
}

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
    /// Trusted time boundary for DB-backed bearer-session expiry checks.
    session_time_source: SessionTimeSource,
    /// Default-on per-client request-rate admission state.
    rate_limiter: Arc<Mutex<GatewayRateLimiter>>,
    /// Last trusted database clock sample used by the gateway rate limiter.
    trusted_rate_limit_epoch_ms: Arc<AtomicU64>,
    /// Explicitly trusted immediate peer IPs whose forwarded client identity may
    /// be used for gateway rate limiting.
    trusted_rate_limit_proxy_ips: BTreeSet<IpAddr>,
}

/// Non-secret authenticated session profile used to carry tenant scope across
/// gateway runtime adapter boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSessionUser {
    pub did: Did,
    pub tenant_id: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionCreateRequest {
    id: String,
    title: String,
    decision_class: String,
    constitutional_hash: String,
    created_at_physical_ms: u64,
    created_at_logical: u32,
    constitution_version: String,
    provenance_timestamp_physical_ms: Option<u64>,
    provenance_timestamp_logical: Option<u32>,
    provenance_public_key: Option<String>,
    provenance_signature: Option<String>,
}

const DECISION_CREATE_PROVENANCE_HASH_DOMAIN: &str = "exo.gateway.decision_create.action.v1";
const DECISION_CREATE_PROVENANCE_HASH_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct DecisionCreateActionHashInput<'a> {
    domain: &'static str,
    schema_version: u16,
    actor: &'a Did,
    tenant_id: &'a str,
    id: &'a uuid::Uuid,
    title: &'a str,
    decision_class: &'a str,
    constitutional_hash: &'a Hash256,
    created_at: &'a Timestamp,
    constitution_version: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecisionCreateProvenanceMetadata {
    provenance_timestamp: Timestamp,
    provenance_public_key: Vec<u8>,
    provenance_signature: Signature,
}

impl DecisionCreateProvenanceMetadata {
    fn from_request(request: &DecisionCreateRequest) -> Result<Self> {
        let physical_ms = request.provenance_timestamp_physical_ms.ok_or_else(|| {
            metadata_error("provenance_timestamp_physical_ms must be caller-supplied")
        })?;
        if physical_ms == 0 {
            return Err(metadata_error(
                "provenance_timestamp_physical_ms must be a positive non-zero HLC physical millisecond",
            ));
        }
        let logical = request.provenance_timestamp_logical.ok_or_else(|| {
            metadata_error("provenance_timestamp_logical must be caller-supplied")
        })?;
        let public_key = request
            .provenance_public_key
            .as_deref()
            .ok_or_else(|| metadata_error("provenance_public_key must be caller-supplied"))
            .and_then(|value| parse_ed25519_public_key_hex(value, "provenance_public_key"))?;
        let signature = request
            .provenance_signature
            .as_deref()
            .ok_or_else(|| metadata_error("provenance_signature must be caller-supplied"))
            .and_then(|value| parse_ed25519_signature_hex(value, "provenance_signature"))?;

        Ok(Self {
            provenance_timestamp: Timestamp::new(physical_ms, logical),
            provenance_public_key: public_key.to_vec(),
            provenance_signature: signature,
        })
    }

    fn provenance_timestamp_string(&self) -> String {
        format!(
            "hlc:{}:{}",
            self.provenance_timestamp.physical_ms, self.provenance_timestamp.logical
        )
    }
}

impl AppState {
    /// Create a new `AppState` with an optional database pool and a shared DID registry.
    pub fn new(pool: Option<sqlx::PgPool>, registry: Arc<RwLock<LocalDidRegistry>>) -> Self {
        Self::new_with_clock_and_session_time_source(
            pool,
            registry,
            HybridClock::new(),
            SessionTimeSource::DatabaseWhenAvailable,
            BTreeSet::new(),
        )
    }

    pub fn new_with_trusted_rate_limit_proxy_ips(
        pool: Option<sqlx::PgPool>,
        registry: Arc<RwLock<LocalDidRegistry>>,
        trusted_rate_limit_proxy_ips: BTreeSet<IpAddr>,
    ) -> Self {
        Self::new_with_clock_and_session_time_source(
            pool,
            registry,
            HybridClock::new(),
            SessionTimeSource::DatabaseWhenAvailable,
            trusted_rate_limit_proxy_ips,
        )
    }

    /// Create a new `AppState` with an explicit HLC source.
    pub fn new_with_clock(
        pool: Option<sqlx::PgPool>,
        registry: Arc<RwLock<LocalDidRegistry>>,
        clock: HybridClock,
    ) -> Self {
        Self::new_with_clock_and_session_time_source(
            pool,
            registry,
            clock,
            SessionTimeSource::InjectedClock,
            BTreeSet::new(),
        )
    }

    fn new_with_clock_and_session_time_source(
        pool: Option<sqlx::PgPool>,
        registry: Arc<RwLock<LocalDidRegistry>>,
        mut clock: HybridClock,
        session_time_source: SessionTimeSource,
        trusted_rate_limit_proxy_ips: BTreeSet<IpAddr>,
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
            session_time_source,
            rate_limiter: Arc::new(Mutex::new(GatewayRateLimiter::default())),
            trusted_rate_limit_epoch_ms: Arc::new(AtomicU64::new(0)),
            trusted_rate_limit_proxy_ips,
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

    fn try_rate_limit_hlc_ms(&self) -> std::result::Result<u64, &'static str> {
        let mut clock = self.clock.lock().map_err(
            |_| "Gateway AppState HLC mutex poisoned while reading rate-limit timestamp",
        )?;
        let timestamp = clock
            .now()
            .map_err(|_| "Gateway AppState HLC exhausted while reading rate-limit timestamp")?;
        timestamp
            .physical_ms
            .checked_add(u64::from(timestamp.logical))
            .ok_or("Gateway AppState HLC rate-limit timestamp overflowed")
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

    fn cached_trusted_rate_limit_time_ms(&self) -> Option<u64> {
        match self.trusted_rate_limit_epoch_ms.load(Ordering::Relaxed) {
            0 => None,
            now_ms => Some(now_ms),
        }
    }

    fn store_trusted_rate_limit_time_ms(&self, now_ms: u64) {
        if now_ms != 0 {
            self.trusted_rate_limit_epoch_ms
                .store(now_ms, Ordering::Relaxed);
        }
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
        require_authenticated_session_actor_for_token(self, &token).await
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
            status: user.status,
        })
    }

    /// Return the number of registered DIDs without blocking a Tokio worker
    /// on the synchronous registry lock.
    pub async fn registry_len(&self) -> Result<usize> {
        registry_len(Arc::clone(&self.registry))
            .await
            .map_err(|e| GatewayError::Internal(e.to_string()))
    }

    /// Return tenant-scoped quorum eligibility counts from persisted gateway
    /// identity records.
    pub async fn quorum_eligible_voter_counts(
        &self,
        tenant_id: &str,
        decision_class: DecisionClass,
    ) -> Result<db::QuorumEligibilityCounts> {
        let pool = self.require_db()?;
        db::count_quorum_eligible_voters(pool, tenant_id, decision_class)
            .await
            .map_err(|e| {
                GatewayError::Internal(format!("failed to count quorum eligible voters: {e}"))
            })
    }

    /// Derive the trusted human voter set for decision-forum votes from active
    /// tenant user records. Caller-supplied `Vote.actor_kind` is only a selector
    /// for candidate DIDs; it is not treated as proof.
    pub async fn verified_human_voter_dids(
        &self,
        tenant_id: &str,
        votes: &[Vote],
    ) -> Result<BTreeSet<Did>> {
        let pool = self.require_db()?;
        let voter_dids = votes
            .iter()
            .filter(|vote| matches!(vote.actor_kind, ActorKind::Human))
            .map(|vote| vote.voter_did.as_str().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let rows = db::active_human_user_dids_for_votes(pool, tenant_id, &voter_dids)
            .await
            .map_err(|e| {
                GatewayError::Internal(format!("failed to derive verified human voters: {e}"))
            })?;
        rows.into_iter()
            .map(|did| {
                Did::new(&did).map_err(|e| {
                    GatewayError::Internal(format!(
                        "active human voter DID from database is invalid: {e}"
                    ))
                })
            })
            .collect()
    }

    /// Load conflict declarations for an actor from the DB-backed standing
    /// conflict register.
    ///
    /// This method is capped for list/display surfaces. Vote recusal
    /// enforcement must use `load_blocking_conflict_declarations_for_vote`.
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

    /// Load blocking conflict declarations for vote recusal enforcement, scoped
    /// to the trusted affected DIDs from the stored decision state.
    pub async fn load_blocking_conflict_declarations_for_vote(
        &self,
        actor: &Did,
        affected_dids: &[Did],
    ) -> std::result::Result<Vec<ConflictDeclaration>, GatewayError> {
        if affected_dids.is_empty() {
            return Err(GatewayError::Internal(
                "conflict recusal lookup requires at least one affected DID".into(),
            ));
        }

        let pool = self.require_db()?;
        let affected_did_strings = affected_dids
            .iter()
            .map(|did| did.as_str().to_owned())
            .collect::<Vec<String>>();
        let candidates = db::list_blocking_conflict_declaration_recusal_candidates_db(
            pool,
            actor.as_str(),
            &affected_did_strings,
        )
        .await
        .map_err(|e| {
            GatewayError::Internal(format!("failed to load conflict declarations: {e}"))
        })?;

        candidates
            .into_iter()
            .map(|candidate| {
                decode_conflict_declaration_recusal_candidate(actor, affected_dids, candidate)
            })
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
    pub async fn build_adjudication_context(
        &self,
        actor: &Did,
        requested_permissions: &PermissionSet,
    ) -> AdjudicationContext {
        // Production path — compiled only when the feature flag is set.
        #[cfg(feature = "production-db")]
        if let Some(pool) = &self.pool {
            let now = match self.try_now_ms() {
                Ok(now_ms) => match i64::try_from(now_ms) {
                    Ok(now) => now,
                    Err(_) => {
                        tracing::warn!(
                            "Gateway adjudication timestamp exceeds database range; falling back to WO-009 scaffold"
                        );
                        return deny_all_adjudication_context();
                    }
                },
                Err(message) => {
                    tracing::warn!(
                        message,
                        "Gateway adjudication timestamp unavailable; falling back to WO-009 scaffold"
                    );
                    return deny_all_adjudication_context();
                }
            };
            match build_adjudication_context_from_db(pool, actor, now, requested_permissions).await
            {
                Ok(ctx) => return ctx,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "DB adjudication context query failed; falling back to WO-009 scaffold"
                    );
                }
            }
        }

        // WO-009 deny-all scaffold (dev/test default and production fallback).
        deny_all_adjudication_context()
    }
}

fn deny_all_adjudication_context() -> AdjudicationContext {
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

#[derive(Debug)]
enum RegistryBlockingError {
    Registration(IdentityError),
    Authentication(String),
    Persistence(String),
    Join(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DidRegistrationRequest {
    document: DidDocument,
    proof: DidRegistrationProof,
}

fn identity_registration_log_reason(error: &IdentityError) -> &'static str {
    match error {
        IdentityError::DuplicateDid(_) => "duplicate_did",
        IdentityError::RegistryCapacityExceeded { .. } => "registry_capacity_exceeded",
        IdentityError::InvalidDidDocumentField { .. } => "invalid_did_document_field",
        IdentityError::DidDocumentFieldTooLarge { .. } => "did_document_field_too_large",
        IdentityError::InvalidRegistrationProof { .. } => "invalid_registration_proof",
        IdentityError::RegistrationProofPayloadEncoding { .. } => {
            "registration_proof_payload_encoding_failed"
        }
        IdentityError::DidRevoked(_) => "did_revoked",
        IdentityError::NonMonotonicTimestamp { .. } => "non_monotonic_timestamp",
        IdentityError::DuplicatePaceDid(_) => "duplicate_pace_did",
        _ => "identity_registration_failed",
    }
}

impl fmt::Display for RegistryBlockingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(error) => write!(
                f,
                "registry registration failed: {}",
                identity_registration_log_reason(error)
            ),
            Self::Authentication(error) => write!(f, "registry authentication failed: {error}"),
            Self::Persistence(error) => write!(f, "registry persistence failed: {error}"),
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
        IdentityError::InvalidRegistrationProof { .. }
        | IdentityError::RegistrationProofPayloadEncoding { .. } => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid DID registration proof" })),
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
    proof: DidRegistrationProof,
) -> std::result::Result<(), RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
        reg.register_with_proof(doc, &proof)
            .map_err(RegistryBlockingError::Registration)
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

async fn registry_cache_document(
    registry: Arc<RwLock<LocalDidRegistry>>,
    doc: DidDocument,
) -> std::result::Result<(), RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
        match reg.register(doc) {
            Ok(()) | Err(IdentityError::DuplicateDid(_)) => Ok(()),
            Err(IdentityError::RegistryCapacityExceeded { .. }) => Ok(()),
            Err(error) => Err(RegistryBlockingError::Registration(error)),
        }
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

async fn register_did_document(
    state: &AppState,
    doc: DidDocument,
    proof: DidRegistrationProof,
) -> std::result::Result<(), RegistryBlockingError> {
    if let Some(pool) = state.pool.as_ref() {
        exo_identity::registry::verify_did_registration_proof(&doc, &proof)
            .map_err(RegistryBlockingError::Registration)?;
        let inserted = match db::insert_did_document(pool, &doc).await {
            Ok(inserted) => inserted,
            Err(db::DidDocumentPersistenceError::RegistryCapacityExceeded {
                max_documents,
                attempted_documents,
            }) => {
                return Err(RegistryBlockingError::Registration(
                    IdentityError::RegistryCapacityExceeded {
                        max_documents,
                        attempted_documents,
                    },
                ));
            }
            Err(e) => return Err(RegistryBlockingError::Persistence(e.to_string())),
        };
        if !inserted {
            return Err(RegistryBlockingError::Registration(
                IdentityError::DuplicateDid(doc.id.clone()),
            ));
        }
        registry_cache_document(Arc::clone(&state.registry), doc).await
    } else {
        registry_register_document(Arc::clone(&state.registry), doc, proof).await
    }
}

async fn resolve_did_document(
    state: &AppState,
    did: Did,
) -> std::result::Result<Option<DidDocument>, RegistryBlockingError> {
    if let Some(pool) = state.pool.as_ref() {
        let did_str = did.as_str().to_owned();
        let Some(doc) = db::find_did_document(pool, &did_str)
            .await
            .map_err(|e| RegistryBlockingError::Persistence(e.to_string()))?
        else {
            return Ok(None);
        };
        registry_cache_document(Arc::clone(&state.registry), doc.clone()).await?;
        Ok(Some(doc))
    } else {
        registry_resolve_document(Arc::clone(&state.registry), did).await
    }
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
    trusted_observed_at: Timestamp,
) -> std::result::Result<(), RegistryBlockingError> {
    tokio::task::spawn_blocking(move || {
        let reg = registry.read().unwrap_or_else(|e| e.into_inner());
        authenticate_session_login_against_trusted_time(
            &did,
            &metadata,
            &proof,
            &*reg,
            trusted_observed_at,
        )
        .map(|_| ())
        .map_err(|e| RegistryBlockingError::Authentication(e.to_string()))
    })
    .await
    .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
}

async fn authenticate_session_login_with_state(
    state: &AppState,
    did: String,
    metadata: SessionIssueMetadata,
    proof: SessionLoginProof,
) -> std::result::Result<(), RegistryBlockingError> {
    let trusted_observed_at = trusted_session_login_observed_at(state)
        .await
        .map_err(|e| RegistryBlockingError::Persistence(e.to_string()))?;
    if let Some(pool) = state.pool.as_ref() {
        let Some(doc) = db::find_did_document(pool, &did)
            .await
            .map_err(|e| RegistryBlockingError::Persistence(e.to_string()))?
        else {
            return Err(RegistryBlockingError::Authentication(
                "DID is not registered".to_owned(),
            ));
        };
        registry_cache_document(Arc::clone(&state.registry), doc.clone()).await?;
        tokio::task::spawn_blocking(move || {
            let mut registry = LocalDidRegistry::with_max_documents(1);
            registry
                .register(doc)
                .map_err(RegistryBlockingError::Registration)?;
            authenticate_session_login_against_trusted_time(
                &did,
                &metadata,
                &proof,
                &registry,
                trusted_observed_at,
            )
            .map(|_| ())
            .map_err(|e| RegistryBlockingError::Authentication(e.to_string()))
        })
        .await
        .map_err(|e| RegistryBlockingError::Join(e.to_string()))?
    } else {
        registry_authenticate_session_login(
            Arc::clone(&state.registry),
            did,
            metadata,
            proof,
            trusted_observed_at,
        )
        .await
    }
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

fn decode_conflict_declaration_recusal_candidate(
    actor: &Did,
    affected_dids: &[Did],
    candidate: db::ConflictDeclarationRecusalCandidate,
) -> std::result::Result<ConflictDeclaration, GatewayError> {
    if candidate.declarant_did != actor.as_str() {
        return Err(GatewayError::Internal(
            "stored conflict declaration scalar declarant does not match requested actor".into(),
        ));
    }

    let scalar_related_dids = parse_conflict_related_dids(&candidate.related_dids)?;
    if !affected_dids
        .iter()
        .any(|affected| scalar_related_dids.contains(affected.as_str()))
    {
        return Err(GatewayError::Internal(
            "stored conflict declaration scalar related DIDs do not match affected DIDs".into(),
        ));
    }

    let declaration = decode_conflict_declaration_payload(actor, candidate.payload)?;
    if declaration.nature != candidate.nature {
        return Err(GatewayError::Internal(
            "stored conflict declaration scalar nature does not match payload".into(),
        ));
    }

    let payload_related_dids = declaration
        .related_dids
        .iter()
        .map(|did| did.as_str().to_owned())
        .collect::<BTreeSet<String>>();
    if payload_related_dids != scalar_related_dids {
        return Err(GatewayError::Internal(
            "stored conflict declaration scalar related DIDs do not match payload".into(),
        ));
    }
    if !affected_dids
        .iter()
        .any(|affected| declaration.related_dids.contains(affected))
    {
        return Err(GatewayError::Internal(
            "stored conflict declaration payload does not match affected DIDs".into(),
        ));
    }

    Ok(declaration)
}

fn parse_conflict_related_dids(
    related_dids: &serde_json::Value,
) -> std::result::Result<BTreeSet<String>, GatewayError> {
    let values = serde_json::from_value::<Vec<String>>(related_dids.clone()).map_err(|e| {
        GatewayError::Internal(format!(
            "invalid stored conflict declaration scalar related DIDs: {e}"
        ))
    })?;
    if values.is_empty() {
        return Err(GatewayError::Internal(
            "stored conflict declaration scalar related DIDs are empty".into(),
        ));
    }
    Ok(values.into_iter().collect())
}

fn validate_conflict_declaration(
    actor: &Did,
    declaration: ConflictDeclaration,
) -> std::result::Result<ConflictDeclaration, GatewayError> {
    if &declaration.declarant_did != actor {
        return Err(GatewayError::Internal(
            "stored conflict declaration was returned for a different declarant".into(),
        ));
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
const MAX_GATEWAY_SESSION_TTL_MS: i64 = 60 * 60 * 1000;

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
        let requested_ttl_ms = expires_at
            .checked_sub(created_at)
            .ok_or_else(|| metadata_error("session expiresAt overflows createdAt delta"))?;
        if requested_ttl_ms > MAX_GATEWAY_SESSION_TTL_MS {
            return Err(metadata_error(
                "session expiresAt must be within one hour of session creation",
            ));
        }
        Ok(Self {
            created_at,
            expires_at,
        })
    }
}

fn validate_session_expires_at_within_gateway_ttl(
    expires_at: i64,
    trusted_gateway_time_ms: i64,
) -> Result<()> {
    if expires_at <= trusted_gateway_time_ms {
        return Err(metadata_error(
            "session expiresAt must be greater than trusted gateway validation time",
        ));
    }
    let max_expires_at = trusted_gateway_time_ms
        .checked_add(MAX_GATEWAY_SESSION_TTL_MS)
        .ok_or_else(|| metadata_error("trusted gateway session TTL upper bound overflow"))?;
    if expires_at > max_expires_at {
        return Err(metadata_error(
            "session expiresAt must be within one hour of trusted gateway time",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionLoginProof {
    timestamp: Timestamp,
    signature: Signature,
}

impl SessionLoginProof {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let timestamp = Timestamp::new(
            required_nonzero_u64(body, "authTimestampPhysicalMs")?,
            required_u32(body, "authTimestampLogical")?,
        );
        Ok(Self {
            timestamp,
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
    expires_at: i64,
}

impl SessionRefreshMetadata {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let expires_at = required_nonzero_i64(body, "expiresAt")?;
        Ok(Self { expires_at })
    }

    fn from_optional_body(body: Option<&serde_json::Value>) -> Result<Self> {
        let body =
            body.ok_or_else(|| metadata_error("session refresh requires expiresAt metadata"))?;
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

#[derive(Debug, Clone, PartialEq)]
struct LayoutTemplateUpsert {
    id: String,
    name: String,
    layout_json: serde_json::Value,
    hidden_panels: serde_json::Value,
}

impl LayoutTemplateUpsert {
    fn from_body(body: &serde_json::Value) -> Result<Self> {
        let object = body
            .as_object()
            .ok_or_else(|| metadata_error("layout template request body must be a JSON object"))?;
        validate_layout_template_top_level_fields(object)?;
        validate_layout_template_builtin_claim(object)?;

        let id = required_layout_template_identifier(body, "id")?;
        let name = required_layout_template_name(body)?;
        validate_layout_template_layout(body)?;
        validate_layout_template_hidden_panels(body)?;

        Ok(Self {
            id,
            name,
            layout_json: body["layout"].clone(),
            hidden_panels: body["hiddenPanels"].clone(),
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

const ADVANCE_PACE_PROVENANCE_HASH_DOMAIN: &str = "exo.gateway.advance_pace.provenance.v1";
const ADVANCE_PACE_PROVENANCE_HASH_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct AdvancePaceActionHashInput<'a> {
    domain: &'static str,
    schema_version: u16,
    actor: &'a Did,
    target: &'a Did,
    subject_kind: &'static str,
    action: &'static str,
    required_permissions: Vec<&'static str>,
    queued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvancePaceMetadata {
    queued_at: i64,
    provenance_timestamp: Timestamp,
    provenance_public_key: Vec<u8>,
    provenance_signature: Signature,
}

impl AdvancePaceMetadata {
    fn from_optional_body(body: Option<&serde_json::Value>) -> Result<Self> {
        let body = body.ok_or_else(|| {
            metadata_error("advance pace requires caller-supplied queuedAt metadata")
        })?;
        Ok(Self {
            queued_at: required_nonzero_i64(body, "queuedAt")?,
            provenance_timestamp: Timestamp::new(
                required_nonzero_u64(body, "provenanceTimestampPhysicalMs")?,
                required_u32(body, "provenanceTimestampLogical")?,
            ),
            provenance_public_key: required_ed25519_public_key_hex(body, "provenancePublicKey")?
                .to_vec(),
            provenance_signature: required_ed25519_signature_hex(body, "provenanceSignature")?,
        })
    }

    fn provenance_timestamp_string(&self) -> String {
        format!(
            "hlc:{}:{}",
            self.provenance_timestamp.physical_ms, self.provenance_timestamp.logical
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdentityErasureMetadata {
    erased_at: i64,
}

impl IdentityErasureMetadata {
    fn from_optional_body(body: Option<&serde_json::Value>) -> Result<Self> {
        let body = body.ok_or_else(|| {
            metadata_error("identity erasure requires caller-supplied erasedAt metadata")
        })?;
        Ok(Self {
            erased_at: required_nonzero_i64(body, "erasedAt")?,
        })
    }
}

fn validate_layout_template_top_level_fields(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "id" | "name" | "layout" | "hiddenPanels" | "isBuiltIn" | "createdAt" | "updatedAt"
        ) {
            return Err(metadata_error(format!(
                "layout template field {field} is not part of the accepted request schema"
            )));
        }
    }
    Ok(())
}

fn validate_layout_template_builtin_claim(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let Some(value) = object.get("isBuiltIn") else {
        return Ok(());
    };
    match value.as_bool() {
        Some(false) => Ok(()),
        Some(true) => Err(metadata_error(
            "built-in layout templates are code-owned and cannot be persisted by callers",
        )),
        None => Err(metadata_error(
            "isBuiltIn must be false when supplied by a layout template caller",
        )),
    }
}

fn required_layout_template_identifier(body: &serde_json::Value, field: &str) -> Result<String> {
    let value = required_nonempty_string(body, field)?;
    validate_layout_template_identifier(&value, field)
}

fn validate_layout_template_identifier(raw: &str, field: &str) -> Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(metadata_error(format!("{field} must not be empty")));
    }
    if value.len() > LAYOUT_TEMPLATE_MAX_ID_BYTES {
        return Err(metadata_error(format!(
            "{field} must be no more than {LAYOUT_TEMPLATE_MAX_ID_BYTES} ASCII bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(metadata_error(format!(
            "{field} must contain only ASCII letters, digits, '-', '_', '.', or ':'"
        )));
    }
    Ok(value.to_owned())
}

fn required_layout_template_name(body: &serde_json::Value) -> Result<String> {
    let value = required_nonempty_string(body, "name")?;
    let trimmed = value.trim();
    if trimmed.len() > LAYOUT_TEMPLATE_MAX_NAME_BYTES {
        return Err(metadata_error(format!(
            "name must be no more than {LAYOUT_TEMPLATE_MAX_NAME_BYTES} UTF-8 bytes"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(metadata_error("name must not contain control characters"));
    }
    Ok(trimmed.to_owned())
}

fn validate_layout_template_layout(body: &serde_json::Value) -> Result<()> {
    let layout = body
        .get("layout")
        .and_then(|value| value.as_array())
        .ok_or_else(|| metadata_error("layout must be a caller-supplied JSON array"))?;
    if layout.len() > LAYOUT_TEMPLATE_MAX_ITEMS {
        return Err(metadata_error(format!(
            "layout must contain no more than {LAYOUT_TEMPLATE_MAX_ITEMS} grid items"
        )));
    }

    let mut seen_ids = BTreeSet::new();
    for (index, item) in layout.iter().enumerate() {
        validate_layout_template_item(item, index, &mut seen_ids)?;
    }
    Ok(())
}

fn validate_layout_template_item(
    item: &serde_json::Value,
    index: usize,
    seen_ids: &mut BTreeSet<String>,
) -> Result<()> {
    let object = item
        .as_object()
        .ok_or_else(|| metadata_error(format!("layout[{index}] must be a JSON object")))?;
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "i" | "x"
                | "y"
                | "w"
                | "h"
                | "minW"
                | "minH"
                | "maxW"
                | "maxH"
                | "static"
                | "isDraggable"
                | "isResizable"
        ) {
            return Err(metadata_error(format!(
                "layout[{index}].{field} is not part of the accepted layout item schema"
            )));
        }
    }

    let id = object
        .get("i")
        .and_then(|value| value.as_str())
        .ok_or_else(|| metadata_error(format!("layout[{index}].i must be a string")))?;
    let id = validate_layout_template_identifier(id, &format!("layout[{index}].i"))?;
    if !seen_ids.insert(id) {
        return Err(metadata_error(format!(
            "layout[{index}].i duplicates another layout item"
        )));
    }

    let x = required_layout_template_u64(object, "x", index)?;
    let y = required_layout_template_u64(object, "y", index)?;
    let w = required_layout_template_u64(object, "w", index)?;
    let h = required_layout_template_u64(object, "h", index)?;
    validate_layout_template_item_geometry(index, x, y, w, h)?;

    let min_w = optional_layout_template_u64(object, "minW", index)?;
    let min_h = optional_layout_template_u64(object, "minH", index)?;
    let max_w = optional_layout_template_u64(object, "maxW", index)?;
    let max_h = optional_layout_template_u64(object, "maxH", index)?;
    validate_layout_template_optional_dimension(
        index,
        "minW",
        min_w,
        1,
        LAYOUT_TEMPLATE_GRID_COLS,
    )?;
    validate_layout_template_optional_dimension(
        index,
        "minH",
        min_h,
        1,
        LAYOUT_TEMPLATE_MAX_HEIGHT,
    )?;
    validate_layout_template_optional_dimension(
        index,
        "maxW",
        max_w,
        1,
        LAYOUT_TEMPLATE_GRID_COLS,
    )?;
    validate_layout_template_optional_dimension(
        index,
        "maxH",
        max_h,
        1,
        LAYOUT_TEMPLATE_MAX_HEIGHT,
    )?;
    if let Some(min_w) = min_w
        && min_w > w
    {
        return Err(metadata_error(format!(
            "layout[{index}].minW must not exceed layout[{index}].w"
        )));
    }
    if let Some(min_h) = min_h
        && min_h > h
    {
        return Err(metadata_error(format!(
            "layout[{index}].minH must not exceed layout[{index}].h"
        )));
    }
    if let Some(max_w) = max_w
        && max_w < w
    {
        return Err(metadata_error(format!(
            "layout[{index}].maxW must not be less than layout[{index}].w"
        )));
    }
    if let Some(max_h) = max_h
        && max_h < h
    {
        return Err(metadata_error(format!(
            "layout[{index}].maxH must not be less than layout[{index}].h"
        )));
    }

    validate_layout_template_optional_bool(object, "static", index)?;
    validate_layout_template_optional_bool(object, "isDraggable", index)?;
    validate_layout_template_optional_bool(object, "isResizable", index)?;
    Ok(())
}

fn required_layout_template_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    index: usize,
) -> Result<u64> {
    object
        .get(field)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            metadata_error(format!(
                "layout[{index}].{field} must be an unsigned integer"
            ))
        })
}

fn optional_layout_template_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    index: usize,
) -> Result<Option<u64>> {
    object
        .get(field)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                metadata_error(format!(
                    "layout[{index}].{field} must be an unsigned integer"
                ))
            })
        })
        .transpose()
}

fn validate_layout_template_item_geometry(
    index: usize,
    x: u64,
    y: u64,
    w: u64,
    h: u64,
) -> Result<()> {
    if w == 0 || w > LAYOUT_TEMPLATE_GRID_COLS {
        return Err(metadata_error(format!(
            "layout[{index}].w must be between 1 and {LAYOUT_TEMPLATE_GRID_COLS}"
        )));
    }
    if h == 0 || h > LAYOUT_TEMPLATE_MAX_HEIGHT {
        return Err(metadata_error(format!(
            "layout[{index}].h must be between 1 and {LAYOUT_TEMPLATE_MAX_HEIGHT}"
        )));
    }
    if x >= LAYOUT_TEMPLATE_GRID_COLS {
        return Err(metadata_error(format!(
            "layout[{index}].x must be less than {LAYOUT_TEMPLATE_GRID_COLS}"
        )));
    }
    if x.checked_add(w)
        .is_none_or(|end| end > LAYOUT_TEMPLATE_GRID_COLS)
    {
        return Err(metadata_error(format!(
            "layout[{index}] must fit within the {LAYOUT_TEMPLATE_GRID_COLS}-column grid"
        )));
    }
    if y > LAYOUT_TEMPLATE_MAX_ROWS {
        return Err(metadata_error(format!(
            "layout[{index}].y must be no more than {LAYOUT_TEMPLATE_MAX_ROWS}"
        )));
    }
    Ok(())
}

fn validate_layout_template_optional_dimension(
    index: usize,
    field: &str,
    value: Option<u64>,
    min: u64,
    max: u64,
) -> Result<()> {
    if let Some(value) = value
        && (value < min || value > max)
    {
        return Err(metadata_error(format!(
            "layout[{index}].{field} must be between {min} and {max}"
        )));
    }
    Ok(())
}

fn validate_layout_template_optional_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    index: usize,
) -> Result<()> {
    if object
        .get(field)
        .is_some_and(|value| value.as_bool().is_none())
    {
        return Err(metadata_error(format!(
            "layout[{index}].{field} must be a boolean"
        )));
    }
    Ok(())
}

fn validate_layout_template_hidden_panels(body: &serde_json::Value) -> Result<()> {
    let hidden_panels = body
        .get("hiddenPanels")
        .and_then(|value| value.as_array())
        .ok_or_else(|| metadata_error("hiddenPanels must be a caller-supplied JSON array"))?;
    if hidden_panels.len() > LAYOUT_TEMPLATE_MAX_HIDDEN_PANELS {
        return Err(metadata_error(format!(
            "hiddenPanels must contain no more than {LAYOUT_TEMPLATE_MAX_HIDDEN_PANELS} entries"
        )));
    }

    let mut seen_ids = BTreeSet::new();
    for (index, value) in hidden_panels.iter().enumerate() {
        let id = value
            .as_str()
            .ok_or_else(|| metadata_error(format!("hiddenPanels[{index}] must be a string")))?;
        let id = validate_layout_template_identifier(id, &format!("hiddenPanels[{index}]"))?;
        if !seen_ids.insert(id) {
            return Err(metadata_error(format!(
                "hiddenPanels[{index}] duplicates another hidden panel"
            )));
        }
    }
    Ok(())
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

fn parse_ed25519_signature_hex(encoded: &str, field: &str) -> Result<Signature> {
    let bytes = hex::decode(encoded)
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

fn required_ed25519_signature_hex(body: &serde_json::Value, field: &str) -> Result<Signature> {
    let encoded = required_nonempty_string(body, field)?;
    parse_ed25519_signature_hex(&encoded, field)
}

fn parse_ed25519_public_key_hex(encoded: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(encoded)
        .map_err(|e| metadata_error(format!("{field} must be hex-encoded Ed25519: {e}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        metadata_error(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

fn required_ed25519_public_key_hex(body: &serde_json::Value, field: &str) -> Result<[u8; 32]> {
    let encoded = required_nonempty_string(body, field)?;
    parse_ed25519_public_key_hex(&encoded, field)
}

fn parse_decision_uuid(raw: &str, field: &str) -> Result<uuid::Uuid> {
    let uuid = uuid::Uuid::parse_str(raw.trim())
        .map_err(|e| metadata_error(format!("{field} must be a valid UUID: {e}")))?;
    if uuid.is_nil() {
        return Err(metadata_error(format!("{field} must not be the nil UUID")));
    }
    Ok(uuid)
}

fn parse_decision_class(raw: &str) -> Result<DecisionClass> {
    match raw.trim() {
        "Routine" => Ok(DecisionClass::Routine),
        "Operational" => Ok(DecisionClass::Operational),
        "Strategic" => Ok(DecisionClass::Strategic),
        "Constitutional" => Ok(DecisionClass::Constitutional),
        other => Err(metadata_error(format!(
            "decision_class must be one of Routine, Operational, Strategic, Constitutional; got {other}"
        ))),
    }
}

fn parse_hash256_hex(raw: &str, field: &str) -> Result<Hash256> {
    let encoded = raw.trim();
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|e| metadata_error(format!("{field} must be 32 bytes of hex: {e}")))?;
    let hash = Hash256::from_bytes(bytes);
    if hash == Hash256::ZERO {
        return Err(metadata_error(format!("{field} must not be all-zero")));
    }
    Ok(hash)
}

fn required_nonempty_trimmed(raw: &str, field: &str) -> Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(metadata_error(format!("{field} must not be empty")));
    }
    Ok(value.to_owned())
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

fn session_login_auth_request(
    did: &str,
    metadata: &SessionIssueMetadata,
    timestamp: Timestamp,
    signature: Signature,
) -> Result<AuthRequest> {
    let body_hash = session_login_payload_hash(did, metadata, &timestamp)?;
    Ok(AuthRequest {
        actor_did: did.to_owned(),
        action: "gateway_session_login".to_owned(),
        body_hash,
        signature,
        timestamp,
    })
}

#[cfg(test)]
fn session_login_auth_signing_payload(
    did: &str,
    metadata: &SessionIssueMetadata,
    timestamp: Timestamp,
) -> Result<Vec<u8>> {
    let request = session_login_auth_request(did, metadata, timestamp, Signature::Empty)?;
    request_signing_payload(&request)
}

fn authenticate_session_login(
    did: &str,
    metadata: &SessionIssueMetadata,
    proof: &SessionLoginProof,
    registry: &dyn DidRegistry,
    trusted_observed_at: Timestamp,
) -> Result<AuthenticatedActor> {
    let request =
        session_login_auth_request(did, metadata, proof.timestamp, proof.signature.clone())?;
    let auth_metadata = AuthenticationMetadata::new(trusted_observed_at)?;
    authenticate(&request, registry, auth_metadata)
}

fn authenticate_session_login_against_trusted_time(
    did: &str,
    metadata: &SessionIssueMetadata,
    proof: &SessionLoginProof,
    registry: &dyn DidRegistry,
    trusted_observed_at: Timestamp,
) -> Result<AuthenticatedActor> {
    let actor = authenticate_session_login(did, metadata, proof, registry, trusted_observed_at)?;
    validate_session_login_freshness_against_trusted_time(proof, trusted_observed_at)?;
    Ok(actor)
}

fn validate_session_login_freshness_against_trusted_time(
    proof: &SessionLoginProof,
    trusted_observed_at: Timestamp,
) -> Result<()> {
    let skew_ms = trusted_observed_at
        .physical_ms
        .abs_diff(proof.timestamp.physical_ms);
    if skew_ms > FRESHNESS_WINDOW_MS {
        return Err(GatewayError::AuthenticationFailed {
            reason: format!(
                "request timestamp outside freshness window: skew {skew_ms}ms (max {FRESHNESS_WINDOW_MS}ms)"
            ),
        });
    }
    Ok(())
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
    requested_permissions: &PermissionSet,
    chain_row: Option<&crate::db::AuthorityChainRow>,
    trusted_authority_keys: TrustedAuthorityKeys,
    trusted_provenance_keys: TrustedProvenanceKeys,
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
                        "adjudication role row unknown role branch for role '{}': '{}'",
                        r.role, other
                    )));
                }
            };
            Role::try_new(r.role.clone(), branch)
                .map_err(|e| GatewayError::Internal(format!("adjudication role row invalid: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;

    let consent_records: Vec<ConsentRecord> = consent_rows
        .iter()
        .map(|r| {
            let subject = Did::new(&r.subject_did).map_err(|_| {
                GatewayError::Internal(format!(
                    "adjudication consent subject DID invalid for scope '{}'",
                    r.scope
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

    let bailment_state = match select_active_bailment_row(consent_rows, requested_permissions) {
        Some(r) => {
            let bailor = Did::new(&r.subject_did).map_err(|_| {
                GatewayError::Internal(format!(
                    "adjudication consent subject DID invalid for active bailment scope '{}'",
                    r.scope
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
            GatewayError::Internal(format!("adjudication authority chain JSON invalid: {e}"))
        })?,
        None => GkChain::default(),
    };
    let actor_permissions = effective_authority_permissions(&authority_chain);

    Ok(AdjudicationContext {
        actor_roles,
        authority_chain,
        consent_records,
        bailment_state,
        human_override_preserved: true,
        actor_permissions,
        trusted_authority_keys,
        trusted_provenance_keys,
        // Provenance is per-action, not per-actor; callers that need full
        // ProvenanceVerifiable enforcement must attach it before adjudication.
        provenance: None,
        quorum_evidence: None,
        active_challenge_reason: None,
    })
}

#[cfg(any(test, feature = "production-db"))]
fn select_active_bailment_row<'a>(
    consent_rows: &'a [crate::db::ConsentRecordRow],
    requested_permissions: &PermissionSet,
) -> Option<&'a crate::db::ConsentRecordRow> {
    consent_rows
        .iter()
        .filter(|row| row.status == "active")
        .filter(|row| {
            exo_gatekeeper::invariants::consent_scope_covers_permissions(
                &row.scope,
                requested_permissions,
            )
        })
        .min_by(|left, right| compare_consent_rows_for_bailment_selection(left, right))
}

#[cfg(any(test, feature = "production-db"))]
fn compare_consent_rows_for_bailment_selection(
    left: &crate::db::ConsentRecordRow,
    right: &crate::db::ConsentRecordRow,
) -> std::cmp::Ordering {
    right
        .created_at
        .cmp(&left.created_at)
        .then_with(|| left.subject_did.cmp(&right.subject_did))
        .then_with(|| left.scope.cmp(&right.scope))
        .then_with(|| left.bailment_type.cmp(&right.bailment_type))
        .then_with(|| left.expires_at.cmp(&right.expires_at))
}

#[cfg(any(test, feature = "production-db"))]
fn effective_authority_permissions(
    authority_chain: &exo_gatekeeper::types::AuthorityChain,
) -> PermissionSet {
    let Some(first_link) = authority_chain.links.first() else {
        return PermissionSet::default();
    };

    let mut effective_permissions = Vec::new();
    for permission in &first_link.permissions.permissions {
        if effective_permissions.contains(permission) {
            continue;
        }
        if authority_chain
            .links
            .iter()
            .all(|link| link.permissions.contains(permission))
        {
            effective_permissions.push(permission.clone());
        }
    }

    PermissionSet::new(effective_permissions)
}

#[cfg(feature = "production-db")]
fn active_did_document_ed25519_keys(doc: &DidDocument, key_context: &str) -> Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    for method in &doc.verification_methods {
        if !method.active {
            continue;
        }
        let key = validate_verification_method_document_binding(doc, method).map_err(|e| {
            GatewayError::Internal(format!(
                "{key_context} DID document key '{}' is not trusted: {e}",
                method.id,
            ))
        })?;
        let key = key.as_bytes().to_vec();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    Ok(keys)
}

#[cfg(feature = "production-db")]
async fn load_trusted_authority_keys(
    pool: &sqlx::PgPool,
    authority_chain: &AuthorityChain,
) -> Result<TrustedAuthorityKeys> {
    let mut trusted_keys = TrustedAuthorityKeys::default();
    for link in &authority_chain.links {
        if trusted_keys.contains_key(&link.grantor) {
            continue;
        }
        let Some(doc) = db::find_did_document(pool, link.grantor.as_str())
            .await
            .map_err(|e| {
                GatewayError::Internal(format!(
                    "authority grantor DID document lookup failed for '{}': {e}",
                    link.grantor
                ))
            })?
        else {
            continue;
        };
        let keys = active_did_document_ed25519_keys(&doc, "authority grantor")?;
        if !keys.is_empty() {
            trusted_keys.insert(link.grantor.clone(), keys);
        }
    }
    Ok(trusted_keys)
}

#[cfg(feature = "production-db")]
async fn load_trusted_provenance_keys(
    pool: &sqlx::PgPool,
    actor: &Did,
) -> Result<TrustedProvenanceKeys> {
    let mut trusted_keys = TrustedProvenanceKeys::default();
    let Some(doc) = db::find_did_document(pool, actor.as_str())
        .await
        .map_err(|e| {
            GatewayError::Internal(format!(
                "provenance actor DID document lookup failed for '{}': {e}",
                actor
            ))
        })?
    else {
        return Ok(trusted_keys);
    };
    let keys = active_did_document_ed25519_keys(&doc, "provenance actor")?;
    if !keys.is_empty() {
        trusted_keys.insert(actor.clone(), keys);
    }
    Ok(trusted_keys)
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
    requested_permissions: &PermissionSet,
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

    let trusted_authority_keys = match &chain_row {
        Some(row) => {
            let authority_chain = serde_json::from_value::<AuthorityChain>(row.chain_json.clone())
                .map_err(|e| {
                    GatewayError::Internal(format!(
                        "adjudication authority chain JSON invalid: {e}"
                    ))
                })?;
            load_trusted_authority_keys(pool, &authority_chain).await?
        }
        None => TrustedAuthorityKeys::default(),
    };
    let trusted_provenance_keys = load_trusted_provenance_keys(pool, actor).await?;

    build_adjudication_context_from_rows(
        actor,
        &role_rows,
        &consent_rows,
        requested_permissions,
        chain_row.as_ref(),
        trusted_authority_keys,
        trusted_provenance_keys,
    )
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

fn render_gateway_metrics(state: &AppState) -> std::result::Result<String, &'static str> {
    let db_configured = usize::from(state.pool.is_some());
    let uptime_seconds = state.uptime_seconds();

    Ok(format!(
        concat!(
            "# HELP exo_gateway_up Whether the EXOCHAIN gateway is serving requests.\n",
            "# TYPE exo_gateway_up gauge\n",
            "exo_gateway_up 1\n",
            "# HELP exo_gateway_uptime_seconds HLC-derived gateway uptime in seconds.\n",
            "# TYPE exo_gateway_uptime_seconds gauge\n",
            "exo_gateway_uptime_seconds {uptime_seconds}\n",
            "# HELP exo_gateway_db_configured Whether durable storage is configured.\n",
            "# TYPE exo_gateway_db_configured gauge\n",
            "exo_gateway_db_configured {db_configured}\n",
        ),
        uptime_seconds = uptime_seconds,
        db_configured = db_configured,
    ))
}

async fn handle_metrics(State(state): State<AppState>) -> Response {
    match render_gateway_metrics(&state) {
        Ok(body) => ([(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)], body).into_response(),
        Err(message) => {
            tracing::error!(message, "Gateway metrics unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)],
                "gateway metrics unavailable\n",
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// DID / Auth / Agent handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/auth/register — register a new DID document.
///
/// Body: a DID document plus proof that the caller controls a declared document
/// key. Returns 201 on success, 409 if the DID is already registered.
async fn handle_auth_register(
    State(state): State<AppState>,
    Json(request): Json<DidRegistrationRequest>,
) -> impl IntoResponse {
    let doc = request.document;
    let did_str = doc.id.as_str().to_owned();
    match register_did_document(&state, doc, request.proof).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "did": did_str, "status": "registered" })),
        )
            .into_response(),
        Err(RegistryBlockingError::Registration(e)) => {
            tracing::warn!(
                reason = identity_registration_log_reason(&e),
                "DID registration rejected"
            );
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
/// Requires `Authorization: Bearer <token>`. The actor DID is resolved from the
/// session token using the gateway HLC; caller-supplied DID and time headers are
/// ignored.
async fn handle_auth_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let did = match require_authenticated_session_actor_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    match resolve_did_document(&state, did).await {
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

/// GET /api/v1/agents — list tenant-scoped agent DID identifiers.
///
/// Requires a DB-backed bearer session and derives tenant scope from the
/// authenticated user profile before reading agent directory state.
async fn handle_agents_list(
    State(state): State<AppState>,
    headers: HeaderMap,
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
    match db::list_agents_db(db, actor.tenant_id.as_str()).await {
        Ok(rows) => {
            let agents: Vec<String> = rows.into_iter().map(|row| row.did).collect();
            Json(serde_json::json!({ "agents": agents })).into_response()
        }
        Err(e) => internal_error_response(e, "agents list query", "agents list unavailable"),
    }
}

/// GET /api/v1/agents/:did — resolve a single DID document by its identifier.
///
/// Requires a DB-backed bearer session and proves tenant membership before
/// reading registry state.
async fn handle_agent_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(did_str): Path<String>,
) -> impl IntoResponse {
    let actor = match require_authenticated_session_user_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
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
    let db = match state.require_db() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response();
        }
    };
    match db::find_agent_by_did(db, did.as_str(), actor.tenant_id.as_str()).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "DID not found" })),
            )
                .into_response();
        }
        Err(e) => return internal_error_response(e, "agent lookup query", "agent lookup failed"),
    }
    match resolve_did_document(&state, did).await {
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
    headers: HeaderMap,
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
        .require_authenticated_session_user_from_header(&headers)
        .await
    {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let db = match state.require_db() {
        Ok(pool) => pool,
        Err(e) => return auth_boundary_error_response(e),
    };
    let target_user = match db::find_user_by_did(db, did.as_str()).await {
        Ok(row) => row,
        Err(e) => return internal_error_response(e, "identity score", "identity score failed"),
    };
    let target_is_same_tenant_user = target_user
        .as_ref()
        .is_some_and(|user| user.tenant_id.as_str() == actor.tenant_id.as_str());
    let target_is_same_tenant_agent = if target_is_same_tenant_user {
        false
    } else {
        match db::find_agent_by_did(db, did.as_str(), actor.tenant_id.as_str()).await {
            Ok(row) => row.is_some(),
            Err(e) => {
                return internal_error_response(e, "identity score", "identity score failed");
            }
        }
    };
    if !target_is_same_tenant_user && !target_is_same_tenant_agent {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "identity score not found" })),
        )
            .into_response();
    }
    match resolve_did_document(&state, did).await {
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

/// DELETE /api/v1/identity/:did — erase DB-backed gateway identity records.
///
/// Requires a DB-backed bearer session whose actor DID exactly matches the path
/// DID, plus caller-supplied `erasedAt` metadata. The DID document is
/// tombstoned so the erased DID remains permanently unusable after restart.
async fn handle_identity_erasure(
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
                "message": "authenticated session actor does not match identity erasure target"
            })),
        )
            .into_response();
    }
    let body_ref = body.as_ref().map(|Json(value)| value);
    let metadata = match IdentityErasureMetadata::from_optional_body(body_ref) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
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
    let summary = match db::erase_gateway_identity_records(db, did.as_str(), metadata.erased_at)
        .await
    {
        Ok(summary) => summary,
        Err(db::GatewayIdentityErasureError::InvalidTimestamp { .. }) => {
            return metadata_error_response(metadata_error(
                "identity erasure erasedAt must be a positive non-zero epoch millisecond",
            ));
        }
        Err(e) => return internal_error_response(e, "identity erasure", "identity erasure failed"),
    };

    let mut erased_records = BTreeMap::new();
    erased_records.insert("did_documents_tombstoned", summary.did_documents_tombstoned);
    erased_records.insert("users_deleted", summary.users_deleted);
    erased_records.insert("agents_deleted", summary.agents_deleted);
    erased_records.insert("sessions_deleted", summary.sessions_deleted);
    erased_records.insert("identity_scores_deleted", summary.identity_scores_deleted);
    erased_records.insert("enrollment_log_deleted", summary.enrollment_log_deleted);
    erased_records.insert(
        "livesafe_identities_deleted",
        summary.livesafe_identities_deleted,
    );
    erased_records.insert("scan_receipts_deleted", summary.scan_receipts_deleted);
    erased_records.insert("consent_anchors_deleted", summary.consent_anchors_deleted);
    erased_records.insert("trustee_shards_deleted", summary.trustee_shards_deleted);
    erased_records.insert("agent_roles_deleted", summary.agent_roles_deleted);
    erased_records.insert("consent_records_deleted", summary.consent_records_deleted);
    erased_records.insert("authority_chains_deleted", summary.authority_chains_deleted);
    erased_records.insert("delegations_deleted", summary.delegations_deleted);
    erased_records.insert("layout_templates_deleted", summary.layout_templates_deleted);
    erased_records.insert("feedback_issues_deleted", summary.feedback_issues_deleted);
    erased_records.insert(
        "conflict_declarations_deleted",
        summary.conflict_declarations_deleted,
    );

    Json(serde_json::json!({
        "status": "identity_erased",
        "subject_did": did_str,
        "erased_at": metadata.erased_at,
        "records": erased_records,
    }))
    .into_response()
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

/// GET /api/v1/users — list tenant-scoped user DIDs.
///
/// Requires a DB-backed bearer session and derives tenant scope from the
/// authenticated user profile before reading user directory state.
async fn handle_users_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
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
    match db::list_users_db(db, &actor.tenant_id).await {
        Ok(rows) => {
            let users: Vec<String> = rows.into_iter().map(|row| row.did).collect();
            Json(serde_json::json!({ "users": users })).into_response()
        }
        Err(e) => internal_error_response(e, "users list query", "users list unavailable"),
    }
}

fn decision_create_action_hash(
    actor: &Did,
    tenant_id: &str,
    decision: &DecisionObject,
    constitutional_hash: &Hash256,
    constitution_version: &str,
) -> Result<Hash256> {
    hash_structured(&DecisionCreateActionHashInput {
        domain: DECISION_CREATE_PROVENANCE_HASH_DOMAIN,
        schema_version: DECISION_CREATE_PROVENANCE_HASH_SCHEMA_VERSION,
        actor,
        tenant_id,
        id: &decision.id,
        title: &decision.title,
        decision_class: decision.class.quorum_policy_key(),
        constitutional_hash,
        created_at: &decision.created_at,
        constitution_version,
    })
    .map_err(|e| GatewayError::Internal(format!("decision create action hash failed: {e}")))
}

fn decision_create_action_provenance(
    actor: &Did,
    tenant_id: &str,
    decision: &DecisionObject,
    constitutional_hash: &Hash256,
    constitution_version: &str,
    metadata: &DecisionCreateProvenanceMetadata,
) -> Result<Provenance> {
    let action_hash = decision_create_action_hash(
        actor,
        tenant_id,
        decision,
        constitutional_hash,
        constitution_version,
    )?;
    Ok(Provenance {
        actor: actor.clone(),
        timestamp: metadata.provenance_timestamp_string(),
        action_hash: action_hash.as_bytes().to_vec(),
        signature: metadata.provenance_signature.to_bytes(),
        public_key: Some(metadata.provenance_public_key.clone()),
        voice_kind: None,
        independence: None,
        review_order: None,
    })
}

/// POST /api/v1/decisions — create a new tenant-scoped decision record.
///
/// Requires a DB-backed bearer session. The tenant and author are derived from
/// that session, while the decision id, constitutional hash, and HLC timestamp
/// are caller-supplied to keep the runtime adapter deterministic.
async fn handle_decision_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let actor = match require_authenticated_session_user_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let request = match serde_json::from_slice::<DecisionCreateRequest>(&body) {
        Ok(request) => request,
        Err(e) => {
            return metadata_error_response(metadata_error(format!(
                "decision create request must be valid JSON: {e}"
            )));
        }
    };
    let id = match parse_decision_uuid(&request.id, "id") {
        Ok(id) => id,
        Err(e) => return metadata_error_response(e),
    };
    let title = match required_nonempty_trimmed(&request.title, "title") {
        Ok(title) => title,
        Err(e) => return metadata_error_response(e),
    };
    let class = match parse_decision_class(&request.decision_class) {
        Ok(class) => class,
        Err(e) => return metadata_error_response(e),
    };
    let constitutional_hash =
        match parse_hash256_hex(&request.constitutional_hash, "constitutional_hash") {
            Ok(hash) => hash,
            Err(e) => return metadata_error_response(e),
        };
    let created_at = Timestamp::new(request.created_at_physical_ms, request.created_at_logical);
    if request.created_at_physical_ms == 0 {
        return metadata_error_response(metadata_error(
            "created_at_physical_ms must be caller-supplied and non-zero",
        ));
    }
    let created_at_ms = match i64::try_from(created_at.physical_ms) {
        Ok(value) => value,
        Err(_) => {
            return metadata_error_response(metadata_error(
                "created_at_physical_ms must fit in PostgreSQL BIGINT",
            ));
        }
    };
    let constitution_version =
        match required_nonempty_trimmed(&request.constitution_version, "constitution_version") {
            Ok(version) => version,
            Err(e) => return metadata_error_response(e),
        };
    let metadata = match DecisionCreateProvenanceMetadata::from_request(&request) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };

    let decision = match DecisionObject::new(DecisionObjectInput {
        id,
        title,
        class,
        constitutional_hash,
        created_at,
    }) {
        Ok(decision) => decision,
        Err(e) => {
            return metadata_error_response(metadata_error(format!(
                "invalid decision object: {e}"
            )));
        }
    };
    let content_hash = match decision.content_hash() {
        Ok(hash) => hash,
        Err(e) => {
            return internal_error_response(e, "decision content hash", "decision creation failed");
        }
    };
    let id_hash = content_hash.to_string();
    let decision_class = decision.class.quorum_policy_key();
    let status = decision.state.as_str();
    let author = actor.did.as_str();
    let payload = serde_json::json!({
        "schema": "exo.gateway.decision_create.v1",
        "id_hash": id_hash.as_str(),
        "id": decision.id.to_string(),
        "tenant_id": actor.tenant_id.as_str(),
        "status": status,
        "title": decision.title.as_str(),
        "decision_class": decision_class,
        "author": author,
        "created_at": {
            "physical_ms": decision.created_at.physical_ms,
            "logical": decision.created_at.logical
        },
        "constitutional_hash": constitutional_hash.to_string(),
        "constitution_version": constitution_version.as_str(),
        "content_hash": id_hash.as_str()
    });
    let action = GkActionRequest {
        actor: actor.did.clone(),
        action: "create_decision".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("create_decision")]),
        is_self_grant: false,
        modifies_kernel: false,
    };
    let mut ctx = state
        .build_adjudication_context(&actor.did, &action.required_permissions)
        .await;
    let provenance = match decision_create_action_provenance(
        &actor.did,
        &actor.tenant_id,
        &decision,
        &constitutional_hash,
        &constitution_version,
        &metadata,
    ) {
        Ok(provenance) => provenance,
        Err(e) => {
            return internal_error_response(
                e,
                "decision create provenance",
                "decision creation failed",
            );
        }
    };
    ctx.provenance = Some(provenance);
    match state.kernel.adjudicate(&action, &ctx) {
        Verdict::Permitted => {}
        Verdict::Denied { .. } | Verdict::Escalated { .. } => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "forbidden",
                    "message": "Kernel rejected decision creation: provenance, authority, or consent validation failed."
                })),
            )
                .into_response();
        }
    }
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
    match db::create_decision(
        db,
        &id_hash,
        &actor.tenant_id,
        status,
        &decision.title,
        decision_class,
        author,
        created_at_ms,
        &constitution_version,
        &payload,
    )
    .await
    {
        Ok(()) => (StatusCode::CREATED, Json(payload)).into_response(),
        Err(db::DecisionCreateError::AlreadyExists { .. }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "decision already exists" })),
        )
            .into_response(),
        Err(db::DecisionCreateError::Query { source }) => {
            internal_error_response(source, "decision create query", "decision creation failed")
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
    let actor = match require_authenticated_session_user_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    let db = match state.require_db() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response();
        }
    };
    match db::list_audit_entries_for_decision(db, &decision_id, &actor.tenant_id).await {
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
    Json(request): Json<DidRegistrationRequest>,
) -> impl IntoResponse {
    let doc = request.document;
    let did_str = doc.id.as_str().to_owned();
    match register_did_document(&state, doc, request.proof).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "did": did_str, "status": "enrolled" })),
        )
            .into_response(),
        Err(RegistryBlockingError::Registration(e)) => {
            tracing::warn!(
                reason = identity_registration_log_reason(&e),
                "agent enrollment rejected"
            );
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
/// and an Ed25519 `signature` hex string over the canonical gateway
/// authentication envelope for the domain-tagged session-login payload hash.
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
    match authenticate_session_login_with_state(&state, did_str.clone(), metadata, proof).await {
        Ok(()) => {}
        Err(RegistryBlockingError::Authentication(e)) => {
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
    let issue_at_ms = match trusted_session_validation_time_ms(&state).await {
        Ok(issue_at_ms) => issue_at_ms,
        Err(e) => return internal_error_response(e, "session login issue time", "login failed"),
    };
    if let Err(e) = validate_session_expires_at_within_gateway_ttl(metadata.expires_at, issue_at_ms)
    {
        return metadata_error_response(e);
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
/// Requires `Authorization: Bearer <token>` plus a JSON body with replacement
/// `expiresAt` metadata. The existing token expiry is checked against the
/// gateway HLC, not caller-supplied body time.
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
    let validation_at_ms = match trusted_session_validation_time_ms(&state).await {
        Ok(validation_at_ms) => validation_at_ms,
        Err(e) => {
            return internal_error_response(
                e,
                "session refresh validation time",
                "session refresh failed",
            );
        }
    };
    if let Err(e) =
        validate_session_expires_at_within_gateway_ttl(metadata.expires_at, validation_at_ms)
    {
        return metadata_error_response(e);
    }
    match sqlx::query(
        "UPDATE sessions SET expires_at = $1 \
         WHERE token = $2 AND expires_at > $3 AND revoked = false",
    )
    .bind(metadata.expires_at)
    .bind(&token)
    .bind(validation_at_ms)
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

// ---------------------------------------------------------------------------
// Constitutional action handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaceSubjectKind {
    Agent,
    User,
}

impl PaceSubjectKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::User => "user",
        }
    }
}

fn advance_pace_action_hash(
    actor: &Did,
    target: &Did,
    subject_kind: PaceSubjectKind,
    metadata: &AdvancePaceMetadata,
) -> Result<Hash256> {
    hash_structured(&AdvancePaceActionHashInput {
        domain: ADVANCE_PACE_PROVENANCE_HASH_DOMAIN,
        schema_version: ADVANCE_PACE_PROVENANCE_HASH_SCHEMA_VERSION,
        actor,
        target,
        subject_kind: subject_kind.as_str(),
        action: "advance_pace",
        required_permissions: vec!["advance_pace"],
        queued_at: metadata.queued_at,
    })
    .map_err(|e| GatewayError::Internal(format!("advance pace action hash failed: {e}")))
}

fn advance_pace_action_provenance(
    actor: &Did,
    target: &Did,
    subject_kind: PaceSubjectKind,
    metadata: &AdvancePaceMetadata,
) -> Result<Provenance> {
    let action_hash = advance_pace_action_hash(actor, target, subject_kind, metadata)?;
    Ok(Provenance {
        actor: actor.clone(),
        timestamp: metadata.provenance_timestamp_string(),
        action_hash: action_hash.as_bytes().to_vec(),
        signature: metadata.provenance_signature.to_bytes(),
        public_key: Some(metadata.provenance_public_key.clone()),
        voice_kind: None,
        independence: None,
        review_order: None,
    })
}

/// POST /api/v1/agents/:did/advance-pace — advance a constitutional pacing token.
///
/// Adjudicated by the Kernel before any DB write.  Without a valid authority
/// chain the Kernel returns 403.  Without a DB pool the handler returns 503.
/// On success returns 202 Accepted.
async fn handle_agent_advance_pace(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    handle_advance_pace(state, path, headers, body, PaceSubjectKind::Agent).await
}

/// POST /api/v1/users/:did/advance-pace — advance a constitutional pacing token.
///
/// Adjudicated by the Kernel before any DB write.  Without a valid authority
/// chain the Kernel returns 403.  Without a DB pool the handler returns 503.
/// On success returns 202 Accepted.
async fn handle_user_advance_pace(
    state: State<AppState>,
    path: Path<String>,
    headers: HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    handle_advance_pace(state, path, headers, body, PaceSubjectKind::User).await
}

async fn handle_advance_pace(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
    headers: HeaderMap,
    body: Option<Json<serde_json::Value>>,
    subject_kind: PaceSubjectKind,
) -> Response {
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
    let body_ref = body.as_ref().map(|Json(value)| value);
    let metadata = match AdvancePaceMetadata::from_optional_body(body_ref) {
        Ok(metadata) => metadata,
        Err(e) => return metadata_error_response(e),
    };
    let action = GkActionRequest {
        actor: actor.clone(),
        action: "advance_pace".into(),
        required_permissions: PermissionSet::new(vec![Permission::new("advance_pace")]),
        is_self_grant: false,
        modifies_kernel: false,
    };
    // Build an adjudication context for this actor.
    let mut ctx = state
        .build_adjudication_context(&actor, &action.required_permissions)
        .await;
    let provenance = match advance_pace_action_provenance(&actor, &did, subject_kind, &metadata) {
        Ok(provenance) => provenance,
        Err(e) => {
            return internal_error_response(e, "advance pace provenance", "advance pace failed");
        }
    };
    ctx.provenance = Some(provenance);
    match state.kernel.adjudicate(&action, &ctx) {
        Verdict::Permitted => {}
        Verdict::Denied { .. } | Verdict::Escalated { .. } => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "forbidden",
                    "message": "Kernel rejected advance-pace: provenance, authority, or \
                                consent validation failed."
                })),
            )
                .into_response();
        }
    }
    // Require DB for the pace record.
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
    let pace_update = match subject_kind {
        PaceSubjectKind::Agent => db::update_agent_pace(db, &did_str, ADVANCED_PACE_STATUS).await,
        PaceSubjectKind::User => db::update_user_pace(db, &did_str, ADVANCED_PACE_STATUS).await,
    };
    if let Err(error) = pace_update {
        return match error {
            sqlx::Error::RowNotFound => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "pace target not found",
                    "actor_did": did_str
                })),
            )
                .into_response(),
            other => internal_error_response(other, "pace update", "advance pace failed"),
        };
    }
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

#[derive(Debug, Deserialize)]
struct EDiscoveryExportRequest {
    requester: Did,
    scope: String,
    date_start: Timestamp,
    date_end: Timestamp,
    custodians: Vec<Did>,
    search_terms: Vec<String>,
    corpus: Vec<Evidence>,
}

impl EDiscoveryExportRequest {
    fn into_search_inputs(
        self,
        authenticated_requester: Did,
    ) -> Result<(DiscoveryRequest, Vec<Evidence>)> {
        if self.requester != authenticated_requester {
            return Err(GatewayError::BadRequest(
                "ediscovery requester must match authenticated session actor".into(),
            ));
        }
        if self.scope.trim().is_empty() {
            return Err(GatewayError::BadRequest(
                "ediscovery scope must not be empty".into(),
            ));
        }
        if self.scope.len() > MAX_EDISCOVERY_SCOPE_BYTES {
            return Err(GatewayError::BadRequest(format!(
                "ediscovery scope may contain at most {MAX_EDISCOVERY_SCOPE_BYTES} bytes"
            )));
        }
        if self.date_start > self.date_end {
            return Err(GatewayError::BadRequest(
                "ediscovery date_start must be less than or equal to date_end".into(),
            ));
        }
        if self.custodians.len() > MAX_EDISCOVERY_CUSTODIANS {
            return Err(GatewayError::BadRequest(format!(
                "ediscovery custodians may contain at most {MAX_EDISCOVERY_CUSTODIANS} entries"
            )));
        }
        if self.search_terms.len() > MAX_EDISCOVERY_SEARCH_TERMS {
            return Err(GatewayError::BadRequest(format!(
                "ediscovery search_terms may contain at most {MAX_EDISCOVERY_SEARCH_TERMS} entries"
            )));
        }
        for term in &self.search_terms {
            if term.len() > MAX_EDISCOVERY_SEARCH_TERM_BYTES {
                return Err(GatewayError::BadRequest(format!(
                    "ediscovery search term may contain at most {MAX_EDISCOVERY_SEARCH_TERM_BYTES} bytes"
                )));
            }
        }
        if self.corpus.len() > MAX_EDISCOVERY_CORPUS_DOCUMENTS {
            return Err(GatewayError::BadRequest(format!(
                "ediscovery corpus may contain at most {MAX_EDISCOVERY_CORPUS_DOCUMENTS} documents"
            )));
        }
        for evidence in &self.corpus {
            if evidence.id.is_nil() {
                return Err(GatewayError::BadRequest(
                    "ediscovery evidence id must be non-nil".into(),
                ));
            }
            if evidence.type_tag.trim().is_empty() {
                return Err(GatewayError::BadRequest(
                    "ediscovery evidence type_tag must not be empty".into(),
                ));
            }
            if evidence.hash == Hash256::ZERO {
                return Err(GatewayError::BadRequest(
                    "ediscovery evidence hash must not be Hash256::ZERO".into(),
                ));
            }
            if evidence.timestamp == Timestamp::ZERO {
                return Err(GatewayError::BadRequest(
                    "ediscovery evidence timestamp must not be Timestamp::ZERO".into(),
                ));
            }
        }

        Ok((
            DiscoveryRequest {
                requester: authenticated_requester,
                scope: self.scope,
                date_range: (self.date_start, self.date_end),
                custodians: self.custodians,
                search_terms: self.search_terms,
            },
            self.corpus,
        ))
    }
}

/// POST /api/v1/ediscovery/export — legal hold / eDiscovery export request.
///
/// Requires a DB-backed bearer session. Runs the caller-supplied evidence
/// corpus through `exo-legal` eDiscovery filtering and returns the
/// deterministic production hash for the result set.
async fn handle_ediscovery_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EDiscoveryExportRequest>,
) -> Response {
    let requester = match require_authenticated_session_actor_from_header(&state, &headers).await {
        Ok(actor) => actor,
        Err(error) => return auth_boundary_error_response(error),
    };

    let (request, corpus) = match body.into_search_inputs(requester) {
        Ok(inputs) => inputs,
        Err(GatewayError::BadRequest(reason)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "bad_request",
                    "message": reason
                })),
            )
                .into_response();
        }
        Err(error) => return internal_error_response(error, "ediscovery request", "export failed"),
    };

    match ediscovery::search(&request, &corpus) {
        Ok(response) => Json(response).into_response(),
        Err(error) => internal_error_response(error, "ediscovery export", "export failed"),
    }
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

async fn trusted_database_epoch_ms(db: &sqlx::PgPool) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(
        "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
    )
    .fetch_one(db)
    .await
    .map_err(|e| GatewayError::Internal(format!("database session clock lookup failed: {e}")))
}

async fn trusted_session_validation_time_ms(state: &AppState) -> Result<i64> {
    if matches!(
        state.session_time_source,
        SessionTimeSource::DatabaseWhenAvailable
    ) {
        if let Some(db) = state.pool.as_ref() {
            return trusted_database_epoch_ms(db).await;
        }
    }

    trusted_session_validation_time_ms_from_hlc(state)
}

async fn trusted_gateway_rate_limit_time_ms(state: &AppState) -> Result<u64> {
    if let Some(cached_now_ms) = state.cached_trusted_rate_limit_time_ms() {
        return Ok(cached_now_ms);
    }

    if let Some(db) = state.pool.as_ref() {
        let now_ms = trusted_database_epoch_ms(db).await?;
        let now_ms = u64::try_from(now_ms).map_err(|_| {
            GatewayError::Internal("gateway rate-limit database time is negative".to_owned())
        })?;
        state.store_trusted_rate_limit_time_ms(now_ms);
        return Ok(now_ms);
    }

    trusted_gateway_rate_limit_time_ms_from_hlc(state)
}

fn spawn_gateway_rate_limit_clock_refresh(
    pool: sqlx::PgPool,
    trusted_rate_limit_epoch_ms: Arc<AtomicU64>,
) {
    std::mem::drop(tokio::spawn(async move {
        loop {
            match trusted_database_epoch_ms(&pool).await {
                Ok(now_ms) => match u64::try_from(now_ms) {
                    Ok(now_ms) if now_ms != 0 => {
                        trusted_rate_limit_epoch_ms.store(now_ms, Ordering::Relaxed);
                    }
                    Ok(_) => {
                        tracing::error!("Gateway rate-limit database clock returned zero");
                    }
                    Err(_) => {
                        tracing::error!("Gateway rate-limit database clock returned negative time");
                    }
                },
                Err(error) => {
                    tracing::error!(%error, "Gateway rate-limit database clock refresh failed");
                }
            }
            tokio::time::sleep(Duration::from_millis(
                GATEWAY_RATE_LIMIT_DB_CLOCK_REFRESH_MS,
            ))
            .await;
        }
    }));
}

fn trusted_gateway_rate_limit_time_ms_from_hlc(state: &AppState) -> Result<u64> {
    let now_ms = state
        .try_rate_limit_hlc_ms()
        .map_err(|message| GatewayError::Internal(message.to_owned()))?;
    if now_ms == 0 {
        return Err(GatewayError::Internal(
            "gateway rate-limit HLC returned zero".to_owned(),
        ));
    }
    Ok(now_ms)
}

fn trusted_session_validation_time_ms_from_hlc(state: &AppState) -> Result<i64> {
    let validation_at_ms = state
        .try_now_ms()
        .map_err(|message| GatewayError::Internal(message.to_owned()))?;
    if validation_at_ms == 0 {
        return Err(GatewayError::Internal(
            "gateway session validation HLC returned zero".to_owned(),
        ));
    }
    i64::try_from(validation_at_ms).map_err(|_| {
        GatewayError::Internal(
            "gateway session validation time exceeds database timestamp range".to_owned(),
        )
    })
}

async fn trusted_session_login_observed_at(state: &AppState) -> Result<Timestamp> {
    let observed_at_ms = trusted_session_validation_time_ms(state).await?;
    if observed_at_ms == 0 {
        return Err(GatewayError::Internal(
            "gateway session login trusted time returned zero".to_owned(),
        ));
    }
    let observed_at_ms = u64::try_from(observed_at_ms)
        .map_err(|_| GatewayError::Internal("gateway session login time is negative".to_owned()))?;
    Ok(Timestamp::new(observed_at_ms, 0))
}

async fn require_authenticated_session_actor_from_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Did> {
    let token = require_bearer_token(headers)?;
    require_authenticated_session_actor_for_token(state, &token).await
}

async fn require_authenticated_session_user_from_header(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSessionUser> {
    state
        .require_authenticated_session_user_from_header(headers)
        .await
}

async fn require_authenticated_session_actor(state: &AppState, headers: &HeaderMap) -> Result<Did> {
    let token = require_bearer_token(headers)?;
    require_authenticated_session_actor_for_token(state, &token).await
}

async fn require_authenticated_session_actor_for_token(
    state: &AppState,
    token: &str,
) -> Result<Did> {
    let validation_at_ms = trusted_session_validation_time_ms(state).await?;
    let db = state.require_db()?;
    let actor_did: Option<String> = sqlx::query_scalar(
        "SELECT actor_did FROM sessions \
         WHERE token = $1 AND revoked = false AND expires_at > $2",
    )
    .bind(token)
    .bind(validation_at_ms)
    .fetch_optional(db)
    .await
    .map_err(|e| GatewayError::Internal(format!("session actor lookup failed: {e}")))?;

    let actor_did = actor_did.ok_or_else(|| GatewayError::AuthenticationFailed {
        reason: "session token expired, revoked, or not found".to_owned(),
    })?;
    Did::new(&actor_did).map_err(|_| {
        GatewayError::Internal("session actor DID stored in database is invalid".into())
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
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let content_security_policy = if path == "/" {
        CONTENT_SECURITY_POLICY_DASHBOARD_VALUE
    } else {
        CONTENT_SECURITY_POLICY_VALUE
    };

    insert_static_response_header(headers, "x-content-type-options", "nosniff");
    insert_static_response_header(headers, "x-frame-options", "DENY");
    insert_static_response_header(headers, "referrer-policy", "no-referrer");
    insert_static_response_header(
        headers,
        "strict-transport-security",
        STRICT_TRANSPORT_SECURITY_VALUE,
    );
    insert_static_response_header(headers, "content-security-policy", content_security_policy);
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
    let actor = match require_authenticated_session_actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return auth_boundary_error_response(e),
    };
    if let Err(e) = reject_caller_supplied_identity_field(&body, "userDid") {
        return metadata_error_response(e);
    }
    if let Err(e) = reject_caller_supplied_builtin_layout(&body) {
        return metadata_error_response(e);
    }
    let template = match LayoutTemplateUpsert::from_body(&body) {
        Ok(template) => template,
        Err(e) => return metadata_error_response(e),
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

    match crate::db::upsert_layout_template(
        db,
        &template.id,
        Some(actor.as_str()),
        &template.name,
        &template.layout_json,
        &template.hidden_panels,
        false,
        metadata.created_at,
        metadata.updated_at,
    )
    .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": template.id, "status": "saved" })),
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
    let actor = match require_authenticated_session_actor(&state, &headers).await {
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
    let actor = match require_authenticated_session_actor(&state, &headers).await {
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
/// All non-GraphQL `RestRoute` endpoints are registered. Unimplemented
/// handlers return 501 while preserving the public contract.
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
        .route("/gateway/metrics", get(handle_metrics))
        // DB health deep probe (requires pool to be configured)
        .route("/health/db", get(db_health_handler))
        // Decisions — create and read tenant-scoped governance records.
        .route("/api/v1/decisions/:id", get(handle_decision_get))
        .route("/api/v1/decisions", post(handle_decision_create))
        // Auth
        .route("/api/v1/auth/token", post(handle_auth_token))
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
            post(handle_agent_advance_pace),
        )
        // Identity
        .route("/api/v1/identity/:did/score", get(handle_identity_score))
        .route(
            "/api/v1/identity/:did",
            axum::routing::delete(handle_identity_erasure),
        )
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
        .route(
            "/api/v1/users/:did/advance-pace",
            post(handle_user_advance_pace),
        )
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

fn gateway_socket_rate_limit_ip(request: &Request<Body>) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip())
}

fn forwarded_rate_limit_client_ip(
    request: &Request<Body>,
    trusted_rate_limit_proxy_ips: &BTreeSet<IpAddr>,
) -> Option<IpAddr> {
    let mut forwarded_headers = request.headers().get_all("x-forwarded-for").iter();
    let header_value = forwarded_headers.next()?.to_str().ok()?;
    if forwarded_headers.next().is_some() {
        return None;
    }

    let mut parsed_ips = Vec::new();
    for candidate in header_value.split(',') {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return None;
        }
        let ip = trimmed.parse::<IpAddr>().ok()?;
        parsed_ips.push(ip);
    }

    parsed_ips
        .iter()
        .rev()
        .copied()
        .find(|ip| !trusted_rate_limit_proxy_ips.contains(ip))
}

fn gateway_rate_limit_key(
    request: &Request<Body>,
    trusted_rate_limit_proxy_ips: &BTreeSet<IpAddr>,
) -> String {
    let Some(socket_ip) = gateway_socket_rate_limit_ip(request) else {
        return "unknown-client".to_owned();
    };

    if trusted_rate_limit_proxy_ips.contains(&socket_ip) {
        if let Some(client_ip) =
            forwarded_rate_limit_client_ip(request, trusted_rate_limit_proxy_ips)
        {
            return client_ip.to_string();
        }
    }

    socket_ip.to_string()
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
    let client_key = gateway_rate_limit_key(&request, &state.trusted_rate_limit_proxy_ips);
    let preflight_now_ms = if let Some(cached_now_ms) = state.cached_trusted_rate_limit_time_ms() {
        Some(cached_now_ms)
    } else {
        match state.try_rate_limit_hlc_ms() {
            Ok(now_ms) => Some(now_ms),
            Err(message) => {
                tracing::error!(
                    message,
                    "Gateway rate limiter preflight timestamp unavailable"
                );
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway rate limiter unavailable",
                )
                    .into_response();
            }
        }
    };

    if let Some(preflight_now_ms) = preflight_now_ms {
        let preflight_outcome = match state.rate_limiter.lock() {
            Ok(mut limiter) => limiter.preflight_limit(&client_key, preflight_now_ms),
            Err(_) => {
                tracing::error!("Gateway rate limiter mutex poisoned");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway rate limiter unavailable",
                )
                    .into_response();
            }
        };
        if let Some(GatewayRateLimitOutcome::Limited { retry_after_ms }) = preflight_outcome {
            return gateway_rate_limit_response(retry_after_ms);
        }
    }

    let now_ms = match trusted_gateway_rate_limit_time_ms(&state).await {
        Ok(now_ms) => now_ms,
        Err(error) => {
            tracing::error!(%error, "Gateway rate limiter timestamp unavailable");
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
/// injected endpoints share the same admission controls.
pub async fn serve_with_extra_routes(
    config: GatewayConfig,
    pool: Option<sqlx::PgPool>,
    extra: Option<Router>,
) -> Result<()> {
    validate_tls_config(config.tls_config.as_ref())?;
    let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
    let state = AppState::new_with_trusted_rate_limit_proxy_ips(
        pool,
        registry,
        config.trusted_rate_limit_proxy_ips.clone(),
    );
    if let Some(pool) = state.pool.clone() {
        spawn_gateway_rate_limit_clock_refresh(
            pool,
            Arc::clone(&state.trusted_rate_limit_epoch_ms),
        );
    }
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
        net::{IpAddr, SocketAddr},
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
        crypto::{KeyPair, generate_keypair, sign},
        hlc::HybridClock,
    };
    use exo_identity::did::{DidDocument, VerificationMethod};
    use sha2::{Digest, Sha256};
    use sqlx::Row;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use super::*; // for .oneshot()

    fn state() -> AppState {
        AppState::new(None, Arc::new(RwLock::new(LocalDidRegistry::new())))
    }

    async fn probe() -> StatusCode {
        StatusCode::OK
    }

    fn base64_standard(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);

            encoded.push(char::from(TABLE[usize::from(first >> 2)]));
            encoded.push(char::from(
                TABLE[usize::from(((first & 0b0000_0011) << 4) | (second >> 4))],
            ));

            if chunk.len() > 1 {
                encoded.push(char::from(
                    TABLE[usize::from(((second & 0b0000_1111) << 2) | (third >> 6))],
                ));
            } else {
                encoded.push('=');
            }

            if chunk.len() > 2 {
                encoded.push(char::from(TABLE[usize::from(third & 0b0011_1111)]));
            } else {
                encoded.push('=');
            }
        }
        encoded
    }

    fn inline_block(source: &str, open: &str, close: &str) -> String {
        let (_, after_open) = source.split_once(open).expect("inline block open marker");
        let (block, _) = after_open
            .split_once(close)
            .expect("inline block close marker");
        block.to_string()
    }

    fn csp_sha256_hash(source: &str) -> String {
        let digest = Sha256::digest(source.as_bytes());
        format!("sha256-{}", base64_standard(digest.as_slice()))
    }

    fn dashboard_inline_asset_hashes() -> (String, String) {
        let dashboard_source = include_str!("../../exo-node/src/dashboard.rs");
        let dashboard_html = inline_block(
            dashboard_source,
            "const DASHBOARD_HTML: &str = r##\"",
            "\"##;",
        );
        let style = inline_block(&dashboard_html, "<style>", "</style>");
        let script = inline_block(&dashboard_html, "<script>", "</script>");
        (csp_sha256_hash(&style), csp_sha256_hash(&script))
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

    fn rate_limited_state_with_trusted_proxies(
        max_requests_per_window: u32,
        window_ms: u64,
        wall: Arc<AtomicU64>,
        trusted_proxies: &[IpAddr],
    ) -> AppState {
        let mut state = rate_limited_state(max_requests_per_window, window_ms, wall);
        state.trusted_rate_limit_proxy_ips = trusted_proxies.iter().copied().collect();
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

    fn request_from_duplicate_forwarded_headers(
        path: &str,
        address: SocketAddr,
        first_forwarded_for: &str,
        second_forwarded_for: &str,
    ) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header("x-forwarded-for", first_forwarded_for)
            .header("x-forwarded-for", second_forwarded_for)
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
    fn adjudication_db_context_does_not_use_zero_timestamp_fallback() {
        let source = include_str!("server.rs");
        let adjudication_block = source
            .split("pub async fn build_adjudication_context")
            .nth(1)
            .and_then(|section| section.split("// WO-009 deny-all scaffold").next())
            .expect("adjudication context builder present");

        assert!(
            adjudication_block.contains("self.try_now_ms()"),
            "DB adjudication must use the fallible HLC path before querying state"
        );
        assert!(
            !adjudication_block.contains("self.now_ms()"),
            "DB adjudication must not query consent/authority state with the zero timestamp fallback"
        );
    }

    #[test]
    fn adjudication_db_context_resolves_authority_grantor_keys() {
        let source = include_str!("server.rs");
        let db_resolver = source
            .split("async fn build_adjudication_context_from_db")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------").next())
            .expect("DB adjudication resolver source present");
        let row_builder = source
            .split("fn build_adjudication_context_from_rows")
            .nth(1)
            .and_then(|section| section.split("fn effective_authority_permissions").next())
            .expect("DB row builder source present");

        assert!(
            db_resolver.contains("load_trusted_authority_keys(pool, &authority_chain).await"),
            "production DB adjudication must resolve trusted grantor keys from DID documents"
        );
        assert!(
            row_builder.contains("trusted_authority_keys"),
            "DB row builder must carry resolved grantor keys into AdjudicationContext"
        );
        assert!(
            db_resolver.find("load_trusted_authority_keys").unwrap()
                < db_resolver
                    .find("build_adjudication_context_from_rows")
                    .unwrap(),
            "trusted grantor keys must be resolved before returning the adjudication context"
        );
    }

    #[test]
    fn adjudication_db_context_resolves_provenance_actor_keys() {
        let source = include_str!("server.rs");
        let db_resolver = source
            .split("async fn build_adjudication_context_from_db")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------").next())
            .expect("DB adjudication resolver source present");
        let row_builder = source
            .split("fn build_adjudication_context_from_rows")
            .nth(1)
            .and_then(|section| section.split("fn effective_authority_permissions").next())
            .expect("DB row builder source present");

        assert!(
            db_resolver.contains("load_trusted_provenance_keys(pool, actor).await"),
            "production DB adjudication must resolve trusted provenance actor keys from DID documents"
        );
        assert!(
            row_builder.contains("trusted_provenance_keys"),
            "DB row builder must carry resolved actor keys into AdjudicationContext"
        );
        assert!(
            db_resolver.find("load_trusted_provenance_keys").unwrap()
                < db_resolver
                    .find("build_adjudication_context_from_rows")
                    .unwrap(),
            "trusted provenance keys must be resolved before returning the adjudication context"
        );
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
        let affected = Did::new("did:exo:tenant-a").expect("valid DID");
        let err = state
            .load_conflict_declarations(&actor)
            .await
            .expect_err("missing conflict register must fail closed");
        assert!(
            err.to_string().contains("database"),
            "error should identify missing DB-backed conflict register, got: {err}"
        );
        let err = state
            .load_blocking_conflict_declarations_for_vote(&actor, &[affected])
            .await
            .expect_err("missing recusal register must fail closed");
        assert!(
            err.to_string().contains("database"),
            "error should identify missing DB-backed recusal register, got: {err}"
        );
    }

    #[tokio::test]
    async fn conflict_declaration_loader_rejects_empty_recusal_context() {
        let state = state();
        let actor = Did::new("did:exo:alice").expect("valid DID");
        let err = state
            .load_blocking_conflict_declarations_for_vote(&actor, &[])
            .await
            .expect_err("empty affected DID context must fail closed");
        assert!(
            err.to_string().contains("affected DID"),
            "error should identify missing trusted affected DID context, got: {err}"
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

    #[test]
    fn conflict_recusal_candidate_validation_rejects_scalar_payload_shadowing() {
        let actor = Did::new("did:exo:alice").expect("valid DID");
        let affected = Did::new("did:exo:tenant-a").expect("valid DID");
        let unrelated = Did::new("did:exo:tenant-b").expect("valid DID");

        let nature_shadow = db::ConflictDeclarationRecusalCandidate {
            declarant_did: actor.as_str().to_owned(),
            nature: "financial ownership".to_owned(),
            related_dids: serde_json::json!([affected.as_str()]),
            payload: serde_json::json!({
                "declarant_did": actor.as_str(),
                "nature": "advisory",
                "related_dids": [affected.as_str()],
                "timestamp": { "physical_ms": 7000, "logical": 0 }
            }),
        };
        assert!(
            decode_conflict_declaration_recusal_candidate(
                &actor,
                std::slice::from_ref(&affected),
                nature_shadow
            )
            .is_err(),
            "scalar-blocking rows must fail closed when the canonical payload is advisory"
        );

        let related_shadow = db::ConflictDeclarationRecusalCandidate {
            declarant_did: actor.as_str().to_owned(),
            nature: "financial ownership".to_owned(),
            related_dids: serde_json::json!([affected.as_str()]),
            payload: serde_json::json!({
                "declarant_did": actor.as_str(),
                "nature": "financial ownership",
                "related_dids": [unrelated.as_str()],
                "timestamp": { "physical_ms": 7000, "logical": 0 }
            }),
        };
        assert!(
            decode_conflict_declaration_recusal_candidate(&actor, &[affected], related_shadow)
                .is_err(),
            "scalar-blocking rows must fail closed when the canonical payload does not name the affected DID"
        );
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

    #[test]
    fn gateway_rate_limit_preflight_blocks_known_over_budget_client() {
        let mut limiter = GatewayRateLimiter::with_limits(1, 60_000, 8);
        assert_eq!(
            limiter.preflight_limit("client-a", 10_000),
            None,
            "new clients require the trusted time boundary before admission state is mutated"
        );
        assert_eq!(
            limiter.check("client-a", 10_000),
            GatewayRateLimitOutcome::Allowed
        );

        assert_eq!(
            limiter.preflight_limit("client-a", 10_000),
            Some(GatewayRateLimitOutcome::Limited {
                retry_after_ms: 60_000
            }),
            "known over-budget clients must be rejected from memory before DB time is requested"
        );
    }

    #[test]
    fn gateway_rate_limit_preflight_prunes_stale_clients_before_max_client_rejection() {
        let mut limiter = GatewayRateLimiter::with_limits(10, 10, 2);
        assert_eq!(
            limiter.check("client-a", 10_000),
            GatewayRateLimitOutcome::Allowed
        );
        assert_eq!(
            limiter.check("client-b", 10_000),
            GatewayRateLimitOutcome::Allowed
        );

        assert_eq!(
            limiter.preflight_limit("client-c", 10_021),
            None,
            "preflight must prune stale tracked clients before rejecting a new client at the max-client boundary"
        );
    }

    #[tokio::test]
    async fn gateway_rate_limit_trusted_time_uses_cached_database_clock_sample() {
        let state = state();
        state.store_trusted_rate_limit_time_ms(88_000);

        let now_ms = trusted_gateway_rate_limit_time_ms(&state)
            .await
            .expect("cached trusted rate-limit time should be available");
        assert_eq!(now_ms, 88_000);
    }

    #[tokio::test]
    async fn gateway_default_hlc_rate_limit_window_resets_from_hlc_progress() {
        let mut state = state();
        state.rate_limiter = Arc::new(Mutex::new(GatewayRateLimiter::with_limits(1, 2, 8)));
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

        wall.store(70_005, Ordering::Relaxed);

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
    async fn gateway_rate_limit_trusted_proxy_uses_verified_forwarded_client_ip() {
        let wall = Arc::new(AtomicU64::new(25_000));
        let trusted_proxy = "10.0.0.10".parse::<IpAddr>().unwrap();
        let state = rate_limited_state_with_trusted_proxies(1, 60_000, wall, &[trusted_proxy]);
        let app = apply_gateway_layers(
            Router::new().route("/probe", get(probe)),
            state,
            GLOBAL_CONCURRENCY_LIMIT,
        );

        let first_client = app
            .clone()
            .oneshot(request_from(
                "/probe",
                "10.0.0.10:1000".parse().unwrap(),
                "198.51.100.200, 203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(first_client.status(), StatusCode::OK);

        let second_client_same_proxy = app
            .clone()
            .oneshot(request_from(
                "/probe",
                "10.0.0.10:2000".parse().unwrap(),
                "198.51.100.200, 203.0.113.88",
            ))
            .await
            .unwrap();
        assert_eq!(second_client_same_proxy.status(), StatusCode::OK);

        let first_client_again = app
            .oneshot(request_from(
                "/probe",
                "10.0.0.10:3000".parse().unwrap(),
                "198.51.100.200, 203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(first_client_again.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn gateway_rate_limit_trusted_proxy_duplicate_forwarding_falls_back_to_socket_ip() {
        let wall = Arc::new(AtomicU64::new(25_000));
        let trusted_proxy = "10.0.0.10".parse::<IpAddr>().unwrap();
        let state = rate_limited_state_with_trusted_proxies(1, 60_000, wall, &[trusted_proxy]);
        let app = apply_gateway_layers(
            Router::new().route("/probe", get(probe)),
            state,
            GLOBAL_CONCURRENCY_LIMIT,
        );

        let first = app
            .clone()
            .oneshot(request_from_duplicate_forwarded_headers(
                "/probe",
                "10.0.0.10:1000".parse().unwrap(),
                "198.51.100.201",
                "203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(request_from_duplicate_forwarded_headers(
                "/probe",
                "10.0.0.10:2000".parse().unwrap(),
                "198.51.100.202",
                "203.0.113.77",
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
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
    async fn gateway_rate_limit_trusted_proxy_malformed_forwarding_falls_back_to_socket_ip() {
        let wall = Arc::new(AtomicU64::new(25_000));
        let trusted_proxy = "10.0.0.10".parse::<IpAddr>().unwrap();
        let state = rate_limited_state_with_trusted_proxies(1, 60_000, wall, &[trusted_proxy]);
        let app = apply_gateway_layers(
            Router::new().route("/probe", get(probe)),
            state,
            GLOBAL_CONCURRENCY_LIMIT,
        );

        let first = app
            .clone()
            .oneshot(request_from(
                "/probe",
                "10.0.0.10:1000".parse().unwrap(),
                "not-an-ip",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(request_from(
                "/probe",
                "10.0.0.10:2000".parse().unwrap(),
                "also-not-an-ip",
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn gateway_extra_routes_receive_rate_limit_layers() {
        let wall = Arc::new(AtomicU64::new(40_000));
        let state = rate_limited_state(1, 60_000, wall);
        let app = build_router_with_extra_routes(
            state,
            Some(Router::new().route("/internal/probe", get(probe))),
        );

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/probe")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/internal/probe")
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
            "gateway rate limiting must use trusted gateway time sources, not system Instant"
        );
        let rate_limit_middleware = source_between(
            production,
            "async fn enforce_gateway_rate_limit",
            "fn apply_gateway_layers",
        );
        let preflight_index = rate_limit_middleware
            .find("preflight_limit(&client_key, preflight_now_ms)")
            .expect("production rate limiting must preflight known over-budget clients");
        let trusted_time_index = rate_limit_middleware
            .find("trusted_gateway_rate_limit_time_ms(&state).await")
            .expect("production rate limiting must request trusted time for admitted clients");
        assert!(
            preflight_index < trusted_time_index,
            "production rate limiting must reject known over-budget clients before DB-backed time lookup"
        );
        assert!(
            rate_limit_middleware.contains("trusted_gateway_rate_limit_time_ms(&state).await"),
            "production rate limiting must use the trusted runtime time boundary"
        );
        assert!(
            rate_limit_middleware.contains("state.try_rate_limit_hlc_ms()"),
            "production rate limiting may use HLC logical progress for non-admitting preflight checks"
        );
        let rate_limit_time_boundary = source_between(
            production,
            "async fn trusted_gateway_rate_limit_time_ms",
            "fn trusted_gateway_rate_limit_time_ms_from_hlc",
        );
        assert!(
            rate_limit_time_boundary.contains("cached_trusted_rate_limit_time_ms"),
            "production rate limiting must use the cached DB clock sample before querying the database"
        );
        assert!(
            rate_limit_time_boundary.contains("trusted_database_epoch_ms(db).await"),
            "production rate limiting may query the trusted database clock only when no cached sample is available"
        );
        assert!(
            production.contains("checked_add(u64::from(timestamp.logical))"),
            "no-DB gateway rate limiting must include HLC logical progress so buckets can reset deterministically"
        );
        let serve_entrypoint = source_between(
            production,
            "pub async fn serve_with_extra_routes",
            "if let Some(tls_config)",
        );
        assert!(
            serve_entrypoint.contains("spawn_gateway_rate_limit_clock_refresh"),
            "production serve entrypoint must refresh the trusted DB rate-limit clock out of band"
        );
        assert!(
            production.contains("ConnectInfo<SocketAddr>")
                && production.contains("trusted_rate_limit_proxy_ips")
                && production.contains("x-forwarded-for"),
            "gateway rate limiting must keep socket identity as the default and gate forwarded client identity behind trusted proxy configuration"
        );
        let key_derivation = source_between(
            production,
            "fn gateway_rate_limit_key",
            "fn gateway_rate_limit_response",
        );
        let trusted_proxy_check = key_derivation
            .find("trusted_rate_limit_proxy_ips.contains(&socket_ip)")
            .expect("forwarded headers must be gated by trusted proxy membership");
        let forwarded_header_read = key_derivation
            .find("forwarded_rate_limit_client_ip")
            .expect("trusted proxy handling must delegate forwarded client parsing");
        assert!(
            trusted_proxy_check < forwarded_header_read,
            "gateway must prove the peer is trusted before reading forwarded client identity"
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

    #[tokio::test]
    async fn gateway_root_path_allows_dashboard_assets_csp() {
        let app = build_router(state());

        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let headers = resp.headers();
        assert_eq!(
            headers
                .get("content-security-policy")
                .and_then(|v| v.to_str().ok()),
            Some(
                "default-src 'none'; style-src 'self' 'sha256-ZDDfCKNMflVt9qZTlgUze2dLGpfks/qtzWrtNola/68='; script-src 'self' 'sha256-wqJx2WnF4s7cGuMU+qEdtcl5ls/KZFFMvWf6rcHbxtc='; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            )
        );
    }

    #[test]
    fn dashboard_csp_hashes_match_inline_assets() {
        let (style_hash, script_hash) = dashboard_inline_asset_hashes();

        assert!(
            CONTENT_SECURITY_POLICY_DASHBOARD_VALUE.contains(&format!("'{style_hash}'")),
            "dashboard CSP must contain current style hash {style_hash}"
        );
        assert!(
            CONTENT_SECURITY_POLICY_DASHBOARD_VALUE.contains(&format!("'{script_hash}'")),
            "dashboard CSP must contain current script hash {script_hash}"
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

    fn canonical_keyed_doc(public_key: exo_core::PublicKey) -> DidDocument {
        let did = exo_identity::did::did_from_public_key(&public_key).expect("canonical DID");
        did_document_with_ed25519_key(&did, &public_key)
    }

    #[derive(serde::Serialize)]
    struct TestDidRegistrationProofPayload<'a> {
        domain: &'static str,
        document: &'a DidDocument,
        signing_public_key: &'a [u8; 32],
    }

    fn registration_request_body(
        doc: &DidDocument,
        public_key: &exo_core::PublicKey,
        secret_key: &exo_core::SecretKey,
    ) -> String {
        let payload = TestDidRegistrationProofPayload {
            domain: "exo.identity.did_registry.registration.v1",
            document: doc,
            signing_public_key: public_key.as_bytes(),
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&payload, &mut encoded).expect("registration proof payload");
        let signature = sign(&encoded, secret_key);
        serde_json::to_string(&serde_json::json!({
            "document": doc,
            "proof": {
                "public_key": public_key,
                "signature": signature,
            }
        }))
        .expect("registration request JSON")
    }

    fn did_document_with_ed25519_key(did: &Did, public_key: &exo_core::PublicKey) -> DidDocument {
        let multibase = format!("z{}", bs58::encode(public_key.as_bytes()).into_string());
        DidDocument {
            id: did.clone(),
            public_keys: vec![*public_key],
            authentication: vec![],
            verification_methods: vec![VerificationMethod {
                id: format!("{}#key-1", did.as_str()),
                key_type: "Ed25519VerificationKey2020".into(),
                controller: did.clone(),
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
        }
    }

    #[cfg(feature = "production-db")]
    #[test]
    fn active_did_document_ed25519_keys_rejects_unbound_active_method() {
        let did = Did::new("did:exo:db-trust-actor").unwrap();
        let (declared_pk, _) = generate_keypair();
        let (method_pk, _) = generate_keypair();
        let mut doc = did_document_with_ed25519_key(&did, &declared_pk);
        doc.verification_methods[0].public_key_multibase =
            format!("z{}", bs58::encode(method_pk.as_bytes()).into_string());

        let err = active_did_document_ed25519_keys(&doc, "test trust key")
            .expect_err("DB trust-key extraction must reject unbound active methods");

        assert!(
            err.to_string().contains("not declared"),
            "error should identify the unbound active method: {err}"
        );
    }

    fn signing_registry() -> (Arc<RwLock<LocalDidRegistry>>, exo_core::SecretKey) {
        let did = Did::new("did:exo:login-alice").unwrap();
        let (pk, sk) = generate_keypair();
        let doc = did_document_with_ed25519_key(&did, &pk);
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

    fn db_state_at(
        pool: sqlx::PgPool,
        registry: Arc<RwLock<LocalDidRegistry>>,
        now_ms: u64,
    ) -> AppState {
        AppState::new_with_clock(
            Some(pool),
            registry,
            HybridClock::with_wall_clock(move || now_ms),
        )
    }

    async fn database_epoch_ms(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    const TEST_ACTIVE_SESSION_EXPIRES_AT_MS: i64 = 4_102_444_800_000;

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
        .bind(TEST_ACTIVE_SESSION_EXPIRES_AT_MS)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_test_did_document(pool: &sqlx::PgPool, did: &str) -> DidDocument {
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(did)
            .execute(pool)
            .await
            .unwrap();
        let doc = minimal_doc(did);
        assert!(
            db::insert_did_document(pool, &doc).await.unwrap(),
            "test DID document should insert into the live DB fixture"
        );
        doc
    }

    fn signed_advance_pace_body(
        actor_did: &str,
        target_did: &str,
        subject_kind: PaceSubjectKind,
        queued_at: i64,
    ) -> serde_json::Value {
        let actor = Did::new(actor_did).unwrap();
        let target = Did::new(target_did).unwrap();
        let (public_key, secret_key) = advance_pace_provenance_keypair(actor_did);
        let timestamp = Timestamp::new(u64::try_from(queued_at).unwrap(), 0);
        let metadata = AdvancePaceMetadata {
            queued_at,
            provenance_timestamp: timestamp,
            provenance_public_key: public_key.as_bytes().to_vec(),
            provenance_signature: Signature::empty(),
        };
        let action_hash =
            advance_pace_action_hash(&actor, &target, subject_kind, &metadata).unwrap();
        let mut provenance = Provenance {
            actor,
            timestamp: metadata.provenance_timestamp_string(),
            action_hash: action_hash.as_bytes().to_vec(),
            signature: Vec::new(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message = exo_gatekeeper::provenance_signature_message(&provenance)
            .expect("canonical provenance payload");
        let signature = sign(message.as_bytes(), &secret_key);
        provenance.signature = signature.to_bytes();

        serde_json::json!({
            "queuedAt": queued_at,
            "provenanceTimestampPhysicalMs": timestamp.physical_ms,
            "provenanceTimestampLogical": timestamp.logical,
            "provenancePublicKey": hex::encode(public_key.as_bytes()),
            "provenanceSignature": hex::encode(provenance.signature),
        })
    }

    struct DecisionCreateBodyFixture<'a> {
        actor_did: &'a str,
        tenant_id: &'a str,
        id: &'a str,
        title: &'a str,
        decision_class: &'a str,
        constitutional_hash: &'a str,
        created_at_physical_ms: u64,
        created_at_logical: u32,
        constitution_version: &'a str,
    }

    fn signed_decision_create_body(fixture: DecisionCreateBodyFixture<'_>) -> serde_json::Value {
        let actor = Did::new(fixture.actor_did).unwrap();
        let class = parse_decision_class(fixture.decision_class).unwrap();
        let constitutional_hash =
            parse_hash256_hex(fixture.constitutional_hash, "constitutional_hash").unwrap();
        let created_at = Timestamp::new(fixture.created_at_physical_ms, fixture.created_at_logical);
        let decision = DecisionObject::new(DecisionObjectInput {
            id: parse_decision_uuid(fixture.id, "id").unwrap(),
            title: fixture.title.to_owned(),
            class,
            constitutional_hash,
            created_at,
        })
        .unwrap();
        let (public_key, secret_key) = decision_create_provenance_keypair(fixture.actor_did);
        let metadata = DecisionCreateProvenanceMetadata {
            provenance_timestamp: created_at,
            provenance_public_key: public_key.as_bytes().to_vec(),
            provenance_signature: Signature::empty(),
        };
        let action_hash = decision_create_action_hash(
            &actor,
            fixture.tenant_id,
            &decision,
            &constitutional_hash,
            fixture.constitution_version,
        )
        .unwrap();
        let mut provenance = Provenance {
            actor,
            timestamp: metadata.provenance_timestamp_string(),
            action_hash: action_hash.as_bytes().to_vec(),
            signature: Vec::new(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message = exo_gatekeeper::provenance_signature_message(&provenance)
            .expect("canonical provenance payload");
        provenance.signature = sign(message.as_bytes(), &secret_key).to_bytes();

        serde_json::json!({
            "id": fixture.id,
            "title": fixture.title,
            "decision_class": fixture.decision_class,
            "constitutional_hash": constitutional_hash.to_string(),
            "created_at_physical_ms": fixture.created_at_physical_ms,
            "created_at_logical": fixture.created_at_logical,
            "constitution_version": fixture.constitution_version,
            "provenance_timestamp_physical_ms": created_at.physical_ms,
            "provenance_timestamp_logical": created_at.logical,
            "provenance_public_key": hex::encode(public_key.as_bytes()),
            "provenance_signature": hex::encode(provenance.signature),
        })
    }

    fn decision_create_provenance_keypair(
        actor_did: &str,
    ) -> (exo_core::PublicKey, exo_core::SecretKey) {
        let seed_hash = Hash256::digest(
            format!("exo.gateway.decision_create.test.provenance-key.v1:{actor_did}").as_bytes(),
        );
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_hash.as_bytes());
        let keypair = KeyPair::from_secret_bytes(seed).unwrap();
        (*keypair.public_key(), keypair.secret_key().clone())
    }

    fn advance_pace_provenance_keypair(
        actor_did: &str,
    ) -> (exo_core::PublicKey, exo_core::SecretKey) {
        let seed_hash = Hash256::digest(
            format!("exo.gateway.advance_pace.test.provenance-key.v1:{actor_did}").as_bytes(),
        );
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_hash.as_bytes());
        let keypair = KeyPair::from_secret_bytes(seed).unwrap();
        (*keypair.public_key(), keypair.secret_key().clone())
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

    async fn cleanup_identity_erasure_route_fixture(pool: &sqlx::PgPool, did: &str) {
        for statement in [
            "DELETE FROM did_documents WHERE did = $1",
            "DELETE FROM sessions WHERE actor_did = $1",
            "DELETE FROM users WHERE did = $1",
            "DELETE FROM identity_scores WHERE did = $1",
        ] {
            sqlx::query(statement)
                .bind(did)
                .execute(pool)
                .await
                .unwrap();
        }
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
        assert!(r.trusted_rate_limit_proxy_ips.is_empty());
    }

    #[test]
    fn parse_trusted_rate_limit_proxy_ips_accepts_unique_comma_separated_ips() {
        let parsed = parse_trusted_rate_limit_proxy_ips("10.0.0.10, 192.0.2.10,10.0.0.10").unwrap();

        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&"10.0.0.10".parse::<IpAddr>().unwrap()));
        assert!(parsed.contains(&"192.0.2.10".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_trusted_rate_limit_proxy_ips_rejects_malformed_ips() {
        let err = parse_trusted_rate_limit_proxy_ips("10.0.0.10,not-an-ip")
            .expect_err("malformed trusted proxy configuration must fail closed");

        assert!(
            err.to_string().contains("not-an-ip"),
            "error should identify the malformed trusted proxy entry: {err}"
        );
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
    async fn gateway_metrics_endpoint_returns_prometheus_text_without_secrets() {
        let app = build_router(state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/gateway/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("metrics response must declare a content type");
        assert!(
            content_type.starts_with("text/plain"),
            "Prometheus metrics should be text/plain, got {content_type}"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(body.contains("# HELP exo_gateway_up"));
        assert!(body.contains("exo_gateway_up 1"));
        assert!(body.contains("exo_gateway_db_configured 0"));
        assert!(body.contains("exo_gateway_uptime_seconds"));
        for forbidden_metric in [
            "exo_gateway_did_registry_documents",
            "exo_gateway_rate_limit_tracked_clients",
        ] {
            assert!(
                !body.contains(forbidden_metric),
                "unauthenticated gateway metrics must not expose operational counts: {forbidden_metric}"
            );
        }
        for forbidden in ["DATABASE_URL", "POSTGRES", "password", "secret", "token"] {
            assert!(
                !body
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "gateway metrics must not expose secret-bearing labels or values: {forbidden}"
            );
        }
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
            "/api/v1/identity/did:exo:route-exists/score",
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
    async fn auth_register_rejects_bare_did_document_without_registration_proof() {
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
        assert!(resp.status().is_client_error());
    }

    #[tokio::test]
    async fn auth_register_accepts_valid_registration_proof() {
        let (public_key, secret_key) = generate_keypair();
        let doc = canonical_keyed_doc(public_key);
        let body = registration_request_body(&doc, &public_key, &secret_key);
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
    async fn auth_register_rejects_non_self_certifying_did_claim() {
        let (public_key, secret_key) = generate_keypair();
        let mut doc = minimal_doc("did:exo:claimed-by-attacker-key");
        doc.public_keys.push(public_key);
        let body = registration_request_body(&doc, &public_key, &secret_key);
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

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_register_rejects_registration_proof_from_unlisted_key() {
        let (document_public_key, _) = generate_keypair();
        let (attacker_public_key, attacker_secret_key) = generate_keypair();
        let attacker_did =
            exo_identity::did::did_from_public_key(&attacker_public_key).expect("canonical DID");
        let doc = did_document_with_ed25519_key(&attacker_did, &document_public_key);
        let body = registration_request_body(&doc, &attacker_public_key, &attacker_secret_key);
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

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn auth_register_duplicate_returns_409() {
        let (public_key, secret_key) = generate_keypair();
        let doc = canonical_keyed_doc(public_key);
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc.clone()).unwrap();
        let st = AppState::new(None, registry);
        let body = registration_request_body(&doc, &public_key, &secret_key);
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
        let (pk, sk) = generate_keypair();
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
        let overflow_doc = canonical_keyed_doc(pk);
        let body = registration_request_body(&overflow_doc, &pk, &sk);
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

        let alice_doc = insert_test_did_document(&pool, "did:exo:auth-me-alice").await;
        let bob_doc = insert_test_did_document(&pool, "did:exo:auth-me-bob").await;
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
        .bind(TEST_ACTIVE_SESSION_EXPIRES_AT_MS)
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
        sqlx::query("DELETE FROM did_documents WHERE did IN ($1, $2)")
            .bind("did:exo:auth-me-alice")
            .bind("did:exo:auth-me-bob")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn session_auth_rejects_expired_token_despite_backdated_header_time() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let token = "auth-me-expired-token";
        let did = "did:exo:auth-me-expired";
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind(token)
        .bind(did)
        .bind(10_000_i64)
        .bind(20_000_i64)
        .execute(&pool)
        .await
        .unwrap();

        let state = db_state_at(
            pool.clone(),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            30_000,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers.insert(AUTH_OBSERVED_AT_MS_HEADER, "15000".parse().unwrap());

        let err = require_authenticated_session_actor_from_header(&state, &headers)
            .await
            .expect_err("expired session token must fail even with a backdated header");
        assert!(
            matches!(err, GatewayError::AuthenticationFailed { .. }),
            "expected authentication failure for expired session, got {err}"
        );

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn production_session_auth_rejects_epoch_expired_token() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let token = "auth-production-epoch-expired-token";
        let did = "did:exo:auth-production-expired";
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();

        let now_ms = database_epoch_ms(&pool).await;
        let expires_at = now_ms
            .checked_sub(60_000)
            .expect("database epoch is after the Unix epoch");
        let created_at = expires_at
            .checked_sub(60_000)
            .expect("expired session still has a valid creation time");
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind(token)
        .bind(did)
        .bind(created_at)
        .bind(expires_at)
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        let err = require_authenticated_session_actor_from_header(&state, &headers)
            .await
            .expect_err("epoch-expired production session token must fail closed");
        assert!(
            matches!(err, GatewayError::AuthenticationFailed { .. }),
            "expected authentication failure for epoch-expired production session, got {err}"
        );

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
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
        let identity_score = source_between(
            source,
            "async fn handle_identity_score",
            "/// DELETE /api/v1/identity/:did",
        );
        let users_list = source_between(
            source,
            "async fn handle_users_list",
            "/// POST /api/v1/decisions",
        );
        let decision_create = source_between(
            source,
            "async fn handle_decision_create",
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
            ("agents list", agents_list, "state.require_db"),
            ("agent get", agent_get, "resolve_did_document"),
            ("identity score", identity_score, "resolve_did_document"),
            ("users list", users_list, "state.require_db"),
            ("decision create", decision_create, "state.require_db"),
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
    fn audit_trail_uses_authenticated_actor_tenant_for_lookup() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_audit_trail",
            "/// POST /api/v1/agents/enroll",
        );

        assert!(
            handler.contains("require_authenticated_session_user_from_header"),
            "audit trail must load the authenticated session actor's tenant profile"
        );
        assert!(
            handler.contains(
                "db::list_audit_entries_for_decision(db, &decision_id, &actor.tenant_id)"
            ),
            "audit trail must query audit entries using the authenticated actor tenant"
        );
        assert!(
            !handler.contains("db::list_audit_entries_for_decision(pool, &decision_id)"),
            "audit trail must not perform an unscoped decision_id lookup"
        );
    }

    #[test]
    fn directory_list_handlers_use_authenticated_tenant_scope() {
        let source = include_str!("server.rs");
        let agents_list = source_between(
            source,
            "async fn handle_agents_list",
            "/// GET /api/v1/agents/:did",
        );
        let users_list = source_between(
            source,
            "async fn handle_users_list",
            "/// POST /api/v1/decisions",
        );

        assert!(
            agents_list.contains("require_authenticated_session_user_from_header"),
            "agents list must load the authenticated session actor's tenant profile"
        );
        assert!(
            agents_list.contains("state.require_db()"),
            "agents list must fail closed without the DB-backed tenant directory"
        );
        assert!(
            agents_list.contains("db::list_agents_db(db, actor.tenant_id.as_str())"),
            "agents list must query agents using the authenticated actor tenant"
        );
        assert!(
            !agents_list.contains("list_dids(&state).await"),
            "agents list must not enumerate global DID ids across tenants"
        );

        assert!(
            users_list.contains("require_authenticated_session_user_from_header"),
            "users list must load the authenticated session actor's tenant profile"
        );
        assert!(
            users_list.contains("state.require_db()"),
            "users list must fail closed without the DB-backed tenant directory"
        );
        assert!(
            users_list.contains("db::list_users_db(db, &actor.tenant_id)"),
            "users list must query users using the authenticated actor tenant"
        );
        assert!(
            !users_list.contains("list_dids(&state).await"),
            "users list must not enumerate global DID ids across tenants"
        );
    }

    #[test]
    fn agent_get_uses_authenticated_actor_tenant_for_lookup() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_agent_get",
            "/// GET /api/v1/identity/:did/score",
        );

        assert!(
            handler.contains("require_authenticated_session_user_from_header"),
            "agent get must load the authenticated session actor's tenant profile"
        );
        assert!(
            handler.contains("state.require_db()"),
            "agent get must fail closed without the DB-backed tenant directory"
        );
        assert!(
            handler.contains("db::find_agent_by_did(db, did.as_str(), actor.tenant_id.as_str())"),
            "agent get must query agents using the authenticated actor tenant"
        );
        let agent_lookup = handler
            .find("db::find_agent_by_did(db, did.as_str(), actor.tenant_id.as_str())")
            .expect("agent lookup must exist");
        let did_resolution = handler
            .find("resolve_did_document(&state, did).await")
            .expect("tenant-proven agent lookup must resolve the persisted DID document");
        assert!(
            agent_lookup < did_resolution,
            "agent get must prove tenant membership before resolving any DID document"
        );
    }

    #[test]
    fn decision_post_route_dispatches_to_create_handler_not_vote_handler() {
        let source = include_str!("server.rs");
        let router = source_between(
            source,
            "fn build_unlayered_router",
            "fn gateway_rate_limit_key",
        );
        let compact_router: String = router.chars().filter(|ch| !ch.is_whitespace()).collect();

        assert!(
            compact_router.contains(".route(\"/api/v1/decisions\",post(handle_decision_create))"),
            "POST /api/v1/decisions must create a decision, matching RestRoute::CreateDecision"
        );
        assert!(
            !compact_router.contains(".route(\"/api/v1/decisions\",post(vote_handler))"),
            "POST /api/v1/decisions must not dispatch create requests to the vote handler"
        );
    }

    #[test]
    fn decision_create_handler_adjudicates_before_db_write() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_decision_create",
            "/// GET /api/v1/decisions/:id",
        );
        let auth = handler
            .find("require_authenticated_session_user_from_header")
            .expect("decision create must authenticate the bearer session");
        let provenance = handler
            .find("ctx.provenance = Some")
            .expect("decision create must attach signed action provenance");
        let adjudicate = handler
            .find("state.kernel.adjudicate")
            .expect("decision create must invoke the constitutional kernel");
        let write = handler
            .find("db::create_decision")
            .expect("decision create must persist the decision");

        assert!(
            auth < provenance,
            "authentication must precede provenance binding"
        );
        assert!(
            provenance < adjudicate,
            "signed provenance must be attached before adjudication"
        );
        assert!(
            adjudicate < write,
            "decision create must adjudicate before writing the decision row"
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
    fn db_configured_identity_paths_do_not_depend_on_local_did_memory() {
        let source = include_str!("server.rs");

        let register_did_document = source_between(
            source,
            "async fn register_did_document",
            "async fn resolve_did_document",
        );
        assert!(
            register_did_document
                .contains("db::DidDocumentPersistenceError::RegistryCapacityExceeded"),
            "DB-backed DID registration must map durable capacity exhaustion into the registry rejection path"
        );
        assert!(
            register_did_document.contains("IdentityError::RegistryCapacityExceeded"),
            "durable DID capacity exhaustion must reuse the same fail-closed response as LocalDidRegistry capacity"
        );

        let auth_register = source_between(
            source,
            "async fn handle_auth_register",
            "/// GET /api/v1/auth/me",
        );
        assert!(
            auth_register.contains("Json(request): Json<DidRegistrationRequest>"),
            "auth/register must parse a proof-bearing registration envelope, not a bare DID document"
        );
        assert!(
            auth_register.contains("register_did_document(&state, doc, request.proof).await"),
            "auth/register must persist through the AppState DB-backed DID path when a pool is configured"
        );
        assert!(
            !auth_register.contains("registry_register_document(Arc::clone(&state.registry), doc)"),
            "auth/register must not write only to LocalDidRegistry"
        );

        let auth_me = source_between(
            source,
            "async fn handle_auth_me",
            "/// GET /api/v1/auth/agents",
        );
        assert!(
            auth_me.contains("resolve_did_document(&state, did).await"),
            "auth/me must resolve persisted DID documents after a restart"
        );

        let agents_list = source_between(
            source,
            "async fn handle_agents_list",
            "/// GET /api/v1/agents/:did",
        );
        assert!(
            agents_list.contains("db::list_agents_db(db, actor.tenant_id.as_str())"),
            "agents list must read tenant-scoped DB agent ids when a DB pool is configured"
        );
        assert!(
            !agents_list.contains("list_dids(&state).await"),
            "agents list must not read the global DID directory"
        );

        let agent_get = source_between(
            source,
            "async fn handle_agent_get",
            "/// GET /api/v1/identity/:did/score",
        );
        assert!(
            agent_get.contains("resolve_did_document(&state, did).await"),
            "agent lookup must resolve persisted DID documents after a restart"
        );

        let agents_enroll = source_between(
            source,
            "async fn handle_agents_enroll",
            "// ---------------------------------------------------------------------------\n// Session auth handlers",
        );
        assert!(
            agents_enroll.contains("Json(request): Json<DidRegistrationRequest>"),
            "agents/enroll must parse a proof-bearing registration envelope, not a bare DID document"
        );
        assert!(
            agents_enroll.contains("register_did_document(&state, doc, request.proof).await"),
            "agents/enroll must share the DB-backed DID persistence path"
        );

        let auth_login = source_between(
            source,
            "async fn handle_auth_login",
            "/// POST /api/v1/auth/token",
        );
        assert!(
            auth_login.contains("authenticate_session_login_with_state(&state,"),
            "login proof verification must use the persisted DID document path when a DB pool is configured"
        );

        let identity_score = source_between(
            source,
            "async fn handle_identity_score",
            "/// DELETE /api/v1/identity/:did",
        );
        assert!(
            identity_score.contains("resolve_did_document(&state, did).await"),
            "identity score must resolve persisted DID documents after a restart"
        );
        assert!(
            identity_score.contains("require_authenticated_session_user_from_header"),
            "identity score must authenticate a DB-backed tenant user before resolving DID state"
        );
        assert!(
            identity_score.contains("db::find_user_by_did(db, did.as_str())"),
            "identity score must check whether target users are in the authenticated tenant"
        );
        assert!(
            identity_score
                .contains("db::find_agent_by_did(db, did.as_str(), actor.tenant_id.as_str())"),
            "identity score must check whether target agents are in the authenticated tenant"
        );
        let auth = identity_score
            .find("require_authenticated_session_user_from_header")
            .expect("identity score must authenticate a DB-backed tenant user");
        let target_user = identity_score
            .find("db::find_user_by_did(db, did.as_str())")
            .expect("identity score must check target user tenant membership");
        let target_agent = identity_score
            .find("db::find_agent_by_did(db, did.as_str(), actor.tenant_id.as_str())")
            .expect("identity score must check target agent tenant membership");
        let resolve = identity_score
            .find("resolve_did_document(&state, did).await")
            .expect("identity score must resolve persisted DID documents after tenant check");
        assert!(
            auth < target_user
                && auth < target_agent
                && target_user < resolve
                && target_agent < resolve,
            "identity score must authenticate and prove tenant membership before DID resolution"
        );

        let users_list = source_between(
            source,
            "async fn handle_users_list",
            "/// POST /api/v1/decisions",
        );
        assert!(
            users_list.contains("db::list_users_db(db, &actor.tenant_id)"),
            "users list must read tenant-scoped DB user ids when a DB pool is configured"
        );
        assert!(
            !users_list.contains("list_dids(&state).await"),
            "users list must not read the global DID directory"
        );
    }

    #[test]
    fn identity_erasure_route_requires_authenticated_self_session_before_db_write() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_identity_erasure",
            "/// GET /api/v1/tenants/:id/constitution",
        );
        let router = source_between(
            source,
            "fn build_unlayered_router",
            "fn gateway_rate_limit_key",
        );
        let compact_router: String = router.chars().filter(|ch| !ch.is_whitespace()).collect();

        let auth = handler
            .find("require_authenticated_session_actor_from_header")
            .expect("identity erasure must authenticate a bearer session");
        let self_check = handler
            .find("if actor != did")
            .expect("identity erasure must reject path-DID spoofing");
        let metadata = handler
            .find("IdentityErasureMetadata::from_optional_body")
            .expect("identity erasure must require caller-supplied erasure metadata");
        let db_write = handler
            .find("db::erase_gateway_identity_records")
            .expect("identity erasure must call the durable DB erasure helper");

        assert!(
            auth < self_check && self_check < metadata && metadata < db_write,
            "identity erasure must authenticate, enforce owner-only path DID, require deterministic metadata, then erase durable records"
        );
        assert!(
            compact_router.contains(
                "\"/api/v1/identity/:did\",axum::routing::delete(handle_identity_erasure)"
            ),
            "gateway must expose a DELETE identity erasure route, not only an in-memory 0dentity route"
        );
    }

    #[test]
    fn gateway_production_logs_do_not_emit_raw_did_identifiers() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        for pattern in [
            "actor = %actor",
            "did = %did_str",
            "actor_did = %",
            "subject_did = %",
            "declarant_did = %",
        ] {
            assert!(
                !production.contains(pattern),
                "gateway logs must not emit raw DID identifiers: {pattern}"
            );
        }
    }

    #[test]
    fn gateway_internal_errors_do_not_display_raw_did_identifiers() {
        let actor = Did::new("did:exo:privacy-sensitive-actor").unwrap();
        let related = Did::new("did:exo:privacy-sensitive-related").unwrap();
        let declaration = ConflictDeclaration {
            declarant_did: related.clone(),
            nature: "financial conflict".into(),
            related_dids: vec![actor.clone()],
            timestamp: Timestamp::new(1, 0),
        };
        let conflict_error = validate_conflict_declaration(&actor, declaration)
            .expect_err("mismatched stored declaration must be rejected")
            .to_string();
        assert!(
            !conflict_error.contains(actor.as_str()) && !conflict_error.contains(related.as_str()),
            "stored conflict declaration errors must not expose raw DID identifiers: {conflict_error}"
        );

        let role_rows = vec![crate::db::AgentRoleRow {
            agent_did: actor.as_str().to_owned(),
            role: "voter".to_owned(),
            branch: "tribunal".to_owned(),
            granted_by: related.as_str().to_owned(),
            valid_from: 1,
            expires_at: None,
        }];
        let role_error = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &[],
            &PermissionSet::default(),
            None,
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        )
        .expect_err("unknown role branch must be rejected")
        .to_string();
        assert!(
            !role_error.contains(actor.as_str()) && !role_error.contains(related.as_str()),
            "adjudication role errors must not expose raw DID identifiers: {role_error}"
        );

        let consent_rows = vec![crate::db::ConsentRecordRow {
            subject_did: related.as_str().to_owned(),
            actor_did: actor.as_str().to_owned(),
            scope: "data:vote".to_owned(),
            bailment_type: "standard".to_owned(),
            status: "active".to_owned(),
            created_at: 1,
            expires_at: None,
        }];
        let chain_row = crate::db::AuthorityChainRow {
            actor_did: actor.as_str().to_owned(),
            chain_json: serde_json::json!({ "links": "not-an-array" }),
            valid_from: 1,
            expires_at: None,
        };
        let chain_error = build_adjudication_context_from_rows(
            &actor,
            &[],
            &consent_rows,
            &PermissionSet::default(),
            Some(&chain_row),
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        )
        .expect_err("malformed authority chain JSON must be rejected")
        .to_string();
        assert!(
            !chain_error.contains(actor.as_str()) && !chain_error.contains(related.as_str()),
            "adjudication chain errors must not expose raw DID identifiers: {chain_error}"
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
        let reader = "did:exo:agent-list-reader";
        let listed_agent = "did:exo:listed-agent";
        insert_test_user(&pool, reader, "tenant-agents-list").await;
        insert_test_session(&pool, "agents-list-token", reader).await;
        insert_test_agent(
            &pool,
            listed_agent,
            "did:exo:listed-agent-owner",
            "tenant-agents-list",
        )
        .await;
        let st = AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        );
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
                .contains(&serde_json::json!(listed_agent))
        );
        sqlx::query("DELETE FROM agents WHERE did = $1")
            .bind(listed_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("agents-list-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn agents_list_filters_to_authenticated_actor_tenant() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let reader = "did:exo:agent-directory-reader";
        let tenant_agent = "did:exo:tenant-agent-visible";
        let other_agent = "did:exo:tenant-agent-hidden";
        insert_test_user(&pool, reader, "tenant-agent-directory-a").await;
        insert_test_session(&pool, "agents-list-tenant-token", reader).await;
        insert_test_agent(
            &pool,
            tenant_agent,
            "did:exo:tenant-agent-owner",
            "tenant-agent-directory-a",
        )
        .await;
        insert_test_agent(
            &pool,
            other_agent,
            "did:exo:other-agent-owner",
            "tenant-agent-directory-b",
        )
        .await;
        let app = build_router(db_state_at(
            pool.clone(),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            10_000,
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents")
                    .header("authorization", "Bearer agents-list-tenant-token")
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
        let agents = val["agents"].as_array().expect("agents array");
        assert!(agents.contains(&serde_json::json!(tenant_agent)));
        assert!(
            !agents.contains(&serde_json::json!(other_agent)),
            "agents list must not disclose agents from another tenant"
        );

        sqlx::query("DELETE FROM agents WHERE did = $1 OR did = $2")
            .bind(tenant_agent)
            .bind(other_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("agents-list-tenant-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
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
        let reader = "did:exo:agent-get-reader";
        let agent = "did:exo:agent-get";
        let token = "agent-get-token";
        let tenant = "tenant-agent-get";
        insert_test_user(&pool, reader, tenant).await;
        insert_test_session(&pool, token, reader).await;
        insert_test_agent(&pool, agent, "did:exo:agent-get-owner", tenant).await;
        let doc = insert_test_did_document(&pool, agent).await;
        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry.write().unwrap().register(doc).unwrap();
        let st = AppState::new(Some(pool.clone()), registry);
        let app = build_router(st);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/agents/{agent}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM agents WHERE did = $1 OR owner_did = $2")
            .bind(agent)
            .bind("did:exo:agent-get-owner")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(agent)
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
        let reader = "did:exo:agent-get-unknown-reader";
        let token = "agent-get-unknown-token";
        insert_test_user(&pool, reader, "tenant-agent-get-unknown").await;
        insert_test_session(&pool, token, reader).await;
        let app = build_router(db_state_at(
            pool.clone(),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            10_000,
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
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn agents_enroll_returns_201() {
        let (public_key, secret_key) = generate_keypair();
        let doc = canonical_keyed_doc(public_key);
        let body = registration_request_body(&doc, &public_key, &secret_key);
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
    async fn agents_enroll_rejects_bare_did_document_without_registration_proof() {
        let body = serde_json::to_string(&minimal_doc("did:exo:enrollee-bare")).unwrap();
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
        assert!(resp.status().is_client_error());
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
    async fn decision_create_shape_missing_session_returns_401_not_vote_schema_error() {
        let body = serde_json::to_string(&serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000060",
            "title": "F-060 route contract regression",
            "decision_class": "Routine",
            "constitutional_hash": "1111111111111111111111111111111111111111111111111111111111111111",
            "created_at_physical_ms": 7000,
            "created_at_logical": 0,
            "constitution_version": "exochain-constitution-v1"
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

    #[tokio::test]
    async fn decision_create_authenticated_session_persists_tenant_scoped_record() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:decision-creator";
        let tenant_id = "tenant-create";
        let title = "F-060 authenticated create";
        insert_decision_create_authorization(&pool, did, tenant_id, "decision-create-token").await;
        sqlx::query("DELETE FROM decisions WHERE author = $1 AND title = $2")
            .bind(did)
            .bind(title)
            .execute(&pool)
            .await
            .unwrap();
        let body = serde_json::to_string(&signed_decision_create_body(DecisionCreateBodyFixture {
            actor_did: did,
            tenant_id,
            id: "00000000-0000-0000-0000-000000000601",
            title,
            decision_class: "Routine",
            constitutional_hash: "2222222222222222222222222222222222222222222222222222222222222222",
            created_at_physical_ms: 8000,
            created_at_logical: 1,
            constitution_version: "exochain-constitution-v1",
        }))
        .unwrap();
        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/decisions")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer decision-create-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let id_hash = val["content_hash"].as_str().unwrap();
        assert_eq!(val["tenant_id"], tenant_id);
        assert_eq!(val["author"], did);
        assert_eq!(val["status"], "Draft");
        assert_eq!(val["title"], title);
        assert_eq!(val["decision_class"], "Routine");

        let row = db::find_decision(&pool, id_hash, tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.tenant_id, tenant_id);
        assert_eq!(row.author, did);
        assert_eq!(row.status, "Draft");
        assert_eq!(row.payload, val);

        sqlx::query("DELETE FROM decisions WHERE id_hash = $1")
            .bind(id_hash)
            .execute(&pool)
            .await
            .unwrap();
        cleanup_decision_create_fixture(&pool, did, "decision-create-token").await;
    }

    #[tokio::test]
    async fn decision_create_authenticated_session_without_provenance_rejects_before_persisting() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:decision-create-no-provenance";
        let tenant_id = "tenant-create-no-provenance";
        let token = "decision-create-no-provenance-token";
        let title = "F-061 missing provenance create";
        insert_decision_create_authorization(&pool, did, tenant_id, token).await;
        sqlx::query("DELETE FROM decisions WHERE author = $1 AND title = $2")
            .bind(did)
            .bind(title)
            .execute(&pool)
            .await
            .unwrap();
        let body = serde_json::to_string(&serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000611",
            "title": title,
            "decision_class": "Routine",
            "constitutional_hash": "3333333333333333333333333333333333333333333333333333333333333333",
            "created_at_physical_ms": 8100,
            "created_at_logical": 0,
            "constitution_version": "exochain-constitution-v1"
        }))
        .unwrap();
        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/decisions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM decisions WHERE author = $1 AND title = $2")
                .bind(did)
                .bind(title)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0);

        cleanup_decision_create_fixture(&pool, did, token).await;
    }

    // --- Identity score endpoint tests ---

    #[tokio::test]
    async fn identity_score_unregistered_did_without_session_returns_401() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn identity_score_registered_did_without_session_returns_401() {
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn identity_score_same_tenant_registered_did_returns_200() {
        let Some(pool) = gateway_test_pool().await else {
            return;
        };
        let reader = "did:exo:identity-score-reader";
        let target = "did:exo:identity-score-target";
        let token = "identity-score-reader-token";
        let tenant = "tenant-identity-score";
        cleanup_identity_erasure_route_fixture(&pool, reader).await;
        cleanup_identity_erasure_route_fixture(&pool, target).await;
        insert_test_user(&pool, reader, tenant).await;
        insert_test_session(&pool, token, reader).await;
        insert_test_user(&pool, target, tenant).await;
        insert_test_did_document(&pool, target).await;

        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        let app = build_router(AppState::new(Some(pool.clone()), registry));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/identity/{target}/score"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
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
        assert_eq!(val["did"], target);
        assert_eq!(val["registered"], true);
        assert!(val["score_bps"].as_u64().unwrap() > 0);

        cleanup_identity_erasure_route_fixture(&pool, reader).await;
        cleanup_identity_erasure_route_fixture(&pool, target).await;
    }

    #[tokio::test]
    async fn identity_score_cross_tenant_registered_did_returns_404() {
        let Some(pool) = gateway_test_pool().await else {
            return;
        };
        let reader = "did:exo:identity-score-tenant-a-reader";
        let target = "did:exo:identity-score-tenant-b-target";
        let token = "identity-score-tenant-a-token";
        cleanup_identity_erasure_route_fixture(&pool, reader).await;
        cleanup_identity_erasure_route_fixture(&pool, target).await;
        insert_test_user(&pool, reader, "tenant-identity-score-a").await;
        insert_test_session(&pool, token, reader).await;
        insert_test_user(&pool, target, "tenant-identity-score-b").await;
        insert_test_did_document(&pool, target).await;

        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        let app = build_router(AppState::new(Some(pool.clone()), registry));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/identity/{target}/score"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup_identity_erasure_route_fixture(&pool, reader).await;
        cleanup_identity_erasure_route_fixture(&pool, target).await;
    }

    #[tokio::test]
    async fn identity_erasure_route_tombstones_did_and_invalidates_session() {
        use sqlx::Row;

        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:erasure-route-subject";
        cleanup_identity_erasure_route_fixture(&pool, did).await;
        db::insert_did_document(&pool, &minimal_doc(did))
            .await
            .unwrap();
        insert_test_user(&pool, did, "tenant-erasure-route").await;
        db::upsert_identity_score(
            &pool,
            did,
            7_500,
            "Trusted",
            &serde_json::json!({"registered": true}),
            10_000,
        )
        .await
        .unwrap();
        insert_test_session(&pool, "identity-erasure-route-token", did).await;

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/identity/{did}"))
                    .header("authorization", "Bearer identity-erasure-route-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"erasedAt":16000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["status"], "identity_erased");
        assert_eq!(val["subject_did"], did);
        assert_eq!(val["records"]["did_documents_tombstoned"], 1);
        assert_eq!(val["records"]["sessions_deleted"], 1);
        assert_eq!(val["records"]["users_deleted"], 1);
        assert_eq!(val["records"]["identity_scores_deleted"], 1);

        assert!(db::find_did_document(&pool, did).await.unwrap().is_none());
        let tombstone =
            sqlx::query("SELECT revoked, erased_at_ms FROM did_documents WHERE did = $1")
                .bind(did)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(tombstone.get::<bool, _>("revoked"));
        assert_eq!(
            tombstone.get::<Option<i64>, _>("erased_at_ms"),
            Some(16_000)
        );
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE actor_did = $1")
                .bind(did)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(session_count, 0);

        cleanup_identity_erasure_route_fixture(&pool, did).await;
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
        let reader = "did:exo:user-list-reader";
        let listed_user = "did:exo:user-listed";
        insert_test_user(&pool, reader, "tenant-users-list").await;
        insert_test_user(&pool, listed_user, "tenant-users-list").await;
        insert_test_session(&pool, "users-list-token", reader).await;
        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
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
                .contains(&serde_json::json!(listed_user))
        );
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("users-list-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1 OR did = $2")
            .bind(reader)
            .bind(listed_user)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn users_list_filters_to_authenticated_actor_tenant() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let reader = "did:exo:user-directory-reader";
        let tenant_user = "did:exo:tenant-user-visible";
        let other_user = "did:exo:tenant-user-hidden";
        insert_test_user(&pool, reader, "tenant-user-directory-a").await;
        insert_test_user(&pool, tenant_user, "tenant-user-directory-a").await;
        insert_test_user(&pool, other_user, "tenant-user-directory-b").await;
        insert_test_session(&pool, "users-list-tenant-token", reader).await;

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/users")
                    .header("authorization", "Bearer users-list-tenant-token")
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
        let users = val["users"].as_array().expect("users array");
        assert!(users.contains(&serde_json::json!(reader)));
        assert!(users.contains(&serde_json::json!(tenant_user)));
        assert!(
            !users.contains(&serde_json::json!(other_user)),
            "users list must not disclose users from another tenant"
        );

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("users-list-tenant-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1 OR did = $2 OR did = $3")
            .bind(reader)
            .bind(tenant_user)
            .bind(other_user)
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
        insert_test_user(&pool, "did:exo:reader", "tenant-read").await;
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
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind("did:exo:reader")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn audit_trail_filters_entries_to_authenticated_actor_tenant() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        insert_test_user(&pool, "did:exo:audit-tenant-b-reader", "tenant-b").await;
        insert_test_session(
            &pool,
            "audit-trail-cross-tenant-token",
            "did:exo:audit-tenant-b-reader",
        )
        .await;
        sqlx::query("DELETE FROM audit_entries WHERE decision_id = $1")
            .bind("audit-cross-tenant-decision")
            .execute(&pool)
            .await
            .unwrap();

        db::insert_audit_entry(
            &pool,
            901_014,
            "prev-a",
            "event-a",
            "VoteCast",
            "did:exo:tenant-a-reader",
            "tenant-a",
            "audit-cross-tenant-decision",
            10_001,
            0,
            "entry-a",
        )
        .await
        .unwrap();
        db::insert_audit_entry(
            &pool,
            901_015,
            "prev-b",
            "event-b",
            "VoteCast",
            "did:exo:audit-tenant-b-reader",
            "tenant-b",
            "audit-cross-tenant-decision",
            10_002,
            0,
            "entry-b",
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
                    .uri("/api/v1/audit/audit-cross-tenant-decision")
                    .header("authorization", "Bearer audit-trail-cross-tenant-token")
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
        let entries = val["audit_entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["tenant_id"], "tenant-b");
        assert_eq!(entries[0]["actor"], "did:exo:audit-tenant-b-reader");

        sqlx::query("DELETE FROM audit_entries WHERE decision_id = $1")
            .bind("audit-cross-tenant-decision")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind("audit-trail-cross-tenant-token")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind("did:exo:audit-tenant-b-reader")
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
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();

        let (registry, sk) = signing_registry();
        let did_key = Did::new(did).unwrap();
        let doc = registry
            .read()
            .unwrap()
            .resolve(&did_key)
            .expect("signing DID document")
            .clone();
        db::insert_did_document(&pool, &doc)
            .await
            .expect("persist signing DID document");
        let metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 20_000,
        };
        let timestamp = Timestamp::new(10_000, 0);
        let trusted_gateway_time = Timestamp::new(10_000, 0);
        let signature = sign(
            &session_login_auth_signing_payload(did, &metadata, timestamp).unwrap(),
            &sk,
        );
        let body = serde_json::json!({
            "did": did,
            "createdAt": metadata.created_at,
            "expiresAt": metadata.expires_at,
            "authTimestampPhysicalMs": timestamp.physical_ms,
            "authTimestampLogical": timestamp.logical,
            "signature": hex::encode(signature.to_bytes())
        });

        let response = handle_auth_login(
            State(db_state_at(
                pool.clone(),
                Arc::new(RwLock::new(LocalDidRegistry::new())),
                trusted_gateway_time.physical_ms,
            )),
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
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn auth_login_rejects_session_expiry_beyond_trusted_gateway_ttl() {
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
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();

        let (registry, sk) = signing_registry();
        let did_key = Did::new(did).unwrap();
        let doc = registry
            .read()
            .unwrap()
            .resolve(&did_key)
            .expect("signing DID document")
            .clone();
        db::insert_did_document(&pool, &doc)
            .await
            .expect("persist signing DID document");

        let gateway_now_ms = 10_000_u64;
        let gateway_now_ms_i64 = 10_000_i64;
        let metadata = SessionIssueMetadata {
            created_at: gateway_now_ms_i64,
            expires_at: gateway_now_ms_i64 + 3_600_001,
        };
        let timestamp = Timestamp::new(gateway_now_ms, 0);
        let signature = sign(
            &session_login_auth_signing_payload(did, &metadata, timestamp).unwrap(),
            &sk,
        );
        let body = serde_json::json!({
            "did": did,
            "createdAt": metadata.created_at,
            "expiresAt": metadata.expires_at,
            "authTimestampPhysicalMs": timestamp.physical_ms,
            "authTimestampLogical": timestamp.logical,
            "signature": hex::encode(signature.to_bytes())
        });

        let response = handle_auth_login(
            State(db_state_at(
                pool.clone(),
                Arc::new(RwLock::new(LocalDidRegistry::new())),
                gateway_now_ms,
            )),
            Json(body),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE actor_did = $1")
                .bind(did)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(session_count, 0);

        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind(did)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn session_login_proof_rejects_missing_signature() {
        let body = serde_json::json!({
            "authTimestampPhysicalMs": 10_000,
            "authTimestampLogical": 0
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
        let signature = sign(
            &session_login_auth_signing_payload("did:exo:login-alice", &metadata, timestamp)
                .unwrap(),
            &sk,
        );
        let proof = SessionLoginProof {
            timestamp,
            signature,
        };
        let guard = registry.read().unwrap();
        let actor = authenticate_session_login(
            "did:exo:login-alice",
            &metadata,
            &proof,
            &*guard,
            timestamp,
        )
        .unwrap();

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
        let payload =
            session_login_auth_signing_payload("did:exo:login-alice", &metadata, timestamp)
                .unwrap();
        let proof = SessionLoginProof {
            timestamp,
            signature: sign(&payload, &wrong_sk),
        };
        let guard = registry.read().unwrap();

        assert!(
            authenticate_session_login(
                "did:exo:login-alice",
                &metadata,
                &proof,
                &*guard,
                timestamp
            )
            .is_err()
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
        let payload =
            session_login_auth_signing_payload("did:exo:login-alice", &signed_metadata, timestamp)
                .unwrap();
        let proof = SessionLoginProof {
            timestamp,
            signature: sign(&payload, &sk),
        };
        let guard = registry.read().unwrap();

        assert!(
            authenticate_session_login(
                "did:exo:login-alice",
                &tampered_metadata,
                &proof,
                &*guard,
                timestamp
            )
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
        let payload =
            session_login_auth_signing_payload("did:exo:login-alice", &metadata, timestamp)
                .unwrap();
        let proof = SessionLoginProof {
            timestamp,
            signature: sign(&payload, &sk),
        };
        let guard = registry.read().unwrap();
        let err = authenticate_session_login(
            "did:exo:login-alice",
            &metadata,
            &proof,
            &*guard,
            observed_at,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("freshness window"),
            "expected stale timestamp refusal, got {err}"
        );
    }

    #[tokio::test]
    async fn session_login_authentication_rejects_stale_timestamp_against_gateway_clock() {
        let (registry, sk) = signing_registry();
        let metadata = SessionIssueMetadata {
            created_at: 10_000,
            expires_at: 500_000,
        };
        let timestamp = Timestamp::new(10_000, 0);
        let payload =
            session_login_auth_signing_payload("did:exo:login-alice", &metadata, timestamp)
                .unwrap();
        let proof = SessionLoginProof {
            timestamp,
            signature: sign(&payload, &sk),
        };
        let state =
            AppState::new_with_clock(None, registry, HybridClock::with_wall_clock(|| 400_000));

        let err = authenticate_session_login_with_state(
            &state,
            "did:exo:login-alice".to_owned(),
            metadata,
            proof,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("freshness window"),
            "expected stale timestamp refusal against gateway clock, got {err}"
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
    async fn auth_refresh_rejects_expired_session_despite_backdated_body_time() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let token = "auth-refresh-expired-token";
        let did = "did:exo:auth-refresh-expired";
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind(token)
        .bind(did)
        .bind(10_000_i64)
        .bind(20_000_i64)
        .execute(&pool)
        .await
        .unwrap();

        let app = build_router(db_state_at(
            pool.clone(),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            30_000,
        ));
        let body = serde_json::to_string(&serde_json::json!({
            "observedAt": 15_000,
            "expiresAt": 40_000
        }))
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/refresh")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn auth_refresh_rejects_session_expiry_beyond_trusted_gateway_ttl() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let token = "auth-refresh-ttl-token";
        let did = "did:exo:auth-refresh-ttl";
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sessions (token, actor_did, created_at, expires_at, revoked) \
             VALUES ($1, $2, $3, $4, false)",
        )
        .bind(token)
        .bind(did)
        .bind(10_000_i64)
        .bind(50_000_i64)
        .execute(&pool)
        .await
        .unwrap();

        let app = build_router(db_state_at(
            pool.clone(),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            10_000,
        ));
        let body = serde_json::to_string(&serde_json::json!({
            "expiresAt": 3_610_001
        }))
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/refresh")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let stored_expires_at: i64 =
            sqlx::query_scalar("SELECT expires_at FROM sessions WHERE token = $1")
                .bind(token)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored_expires_at, 50_000);

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
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
    async fn auth_saml_callback_is_not_registered_without_sso_adapter() {
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
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
    fn session_issue_metadata_rejects_expiry_beyond_one_hour() {
        let body = serde_json::json!({
            "did": "did:exo:alice",
            "createdAt": 10_000,
            "expiresAt": 3_610_001
        });
        let err = SessionIssueMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("one hour")),
            "expected one-hour session TTL refusal, got {err}"
        );
    }

    #[test]
    fn session_refresh_metadata_requires_expires_at() {
        let body = serde_json::json!({
            "observedAt": 4_600_000
        });
        let err = SessionRefreshMetadata::from_body(&body).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("expiresAt")),
            "expected expiresAt refusal, got {err}"
        );
    }

    #[test]
    fn session_validation_uses_gateway_clock_not_caller_header_time() {
        let source = include_str!("server.rs");
        let app_state_method = source_between(
            source,
            "pub async fn require_authenticated_session_actor_from_header",
            "/// Resolve the authenticated actor and its tenant scope",
        );
        let free_function = source_between(
            source,
            "async fn require_authenticated_session_actor_from_header",
            "async fn require_authenticated_session_user_from_header",
        );
        let token_lookup = source_between(
            source,
            "async fn require_authenticated_session_actor_for_token",
            "fn reject_caller_supplied_identity_field",
        );

        assert!(
            !app_state_method.contains("required_observed_at_ms_header"),
            "AppState session auth must not derive expiry validation time from caller headers"
        );
        assert!(
            !free_function.contains("required_observed_at_ms_header"),
            "session auth helper must not derive expiry validation time from caller headers"
        );
        assert!(
            token_lookup.contains("trusted_session_validation_time_ms(state)"),
            "session token lookup must use the gateway HLC validation time"
        );
        assert!(
            !token_lookup.contains("observed_at_ms"),
            "session token lookup must not accept caller-supplied observation time"
        );
    }

    #[test]
    fn auth_refresh_uses_gateway_clock_not_caller_body_time() {
        let source = include_str!("server.rs");
        let refresh_handler = source_between(
            source,
            "async fn handle_auth_refresh",
            "/// POST /api/v1/auth/logout",
        );

        assert!(
            refresh_handler.contains("trusted_session_validation_time_ms(&state)"),
            "session refresh must compute expiry validation time from the gateway HLC"
        );
        assert!(
            refresh_handler.contains(".bind(validation_at_ms)"),
            "session refresh update must compare stored expiry against trusted gateway time"
        );
        assert!(
            !refresh_handler.contains(".bind(metadata.observed_at)"),
            "session refresh update must not compare expiry against caller body time"
        );
    }

    #[test]
    fn auth_refresh_enforces_one_hour_ttl_from_trusted_gateway_time() {
        let source = include_str!("server.rs");
        let refresh_handler = source_between(
            source,
            "async fn handle_auth_refresh",
            "/// POST /api/v1/auth/logout",
        );

        assert!(
            refresh_handler.contains("validate_session_expires_at_within_gateway_ttl"),
            "session refresh must cap caller-supplied expiresAt using trusted gateway time"
        );
        assert!(
            refresh_handler.contains("validation_at_ms"),
            "session refresh TTL cap must be computed from gateway validation time"
        );
    }

    #[test]
    fn production_app_state_uses_database_time_for_db_backed_session_expiry() {
        let source = include_str!("server.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");
        let constructor = source_between(
            production,
            "pub fn new(pool: Option<sqlx::PgPool>, registry: Arc<RwLock<LocalDidRegistry>>) -> Self",
            "/// Create a new `AppState` with an explicit HLC source.",
        );

        assert!(
            constructor.contains("SessionTimeSource::DatabaseWhenAvailable"),
            "production AppState::new must mark DB-backed session expiry as database-time authoritative"
        );
        assert!(
            production.contains("trusted_database_epoch_ms"),
            "DB-backed session expiry must compare against a trusted database epoch source"
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

    fn valid_layout_template_body() -> serde_json::Value {
        serde_json::json!({
            "id": "layout-1",
            "name": "Layout One",
            "layout": [
                {
                    "i": "panel-1",
                    "x": 0,
                    "y": 0,
                    "w": 6,
                    "h": 4,
                    "minW": 4,
                    "minH": 2,
                    "isResizable": true
                }
            ],
            "hiddenPanels": ["panel-2"],
            "isBuiltIn": false,
            "createdAt": 10_000,
            "updatedAt": 10_001
        })
    }

    #[test]
    fn layout_template_upsert_accepts_canonical_array_payload() {
        let body = valid_layout_template_body();

        let template = LayoutTemplateUpsert::from_body(&body).unwrap();

        assert_eq!(template.id, "layout-1");
        assert_eq!(template.name, "Layout One");
        assert!(template.layout_json.as_array().is_some());
        assert!(template.hidden_panels.as_array().is_some());
    }

    #[test]
    fn layout_template_upsert_rejects_defaulted_or_unvalidated_shapes() {
        let cases = [
            (
                "missing name",
                serde_json::json!({
                    "id": "layout-1",
                    "layout": [],
                    "hiddenPanels": [],
                    "createdAt": 10_000,
                    "updatedAt": 10_001
                }),
                "name",
            ),
            (
                "string layout",
                serde_json::json!({
                    "id": "layout-1",
                    "name": "Layout One",
                    "layout": "[{\"i\":\"panel-1\",\"x\":0,\"y\":0,\"w\":6,\"h\":4}]",
                    "hiddenPanels": [],
                    "createdAt": 10_000,
                    "updatedAt": 10_001
                }),
                "layout",
            ),
            (
                "object hidden panels",
                serde_json::json!({
                    "id": "layout-1",
                    "name": "Layout One",
                    "layout": [],
                    "hiddenPanels": {"panel-1": true},
                    "createdAt": 10_000,
                    "updatedAt": 10_001
                }),
                "hiddenPanels",
            ),
        ];

        for (case, body, expected_reason) in cases {
            let err = LayoutTemplateUpsert::from_body(&body).unwrap_err();
            assert!(
                matches!(&err, GatewayError::BadRequest(reason) if reason.contains(expected_reason)),
                "{case} should reject with {expected_reason}, got {err}"
            );
        }
    }

    #[test]
    fn layout_template_upsert_rejects_malformed_layout_items() {
        let cases = [
            (
                "unknown item field",
                serde_json::json!([
                    {"i": "panel-1", "x": 0, "y": 0, "w": 6, "h": 4, "html": "<script>"}
                ]),
                "not part of the accepted layout item schema",
            ),
            (
                "duplicate item id",
                serde_json::json!([
                    {"i": "panel-1", "x": 0, "y": 0, "w": 6, "h": 4},
                    {"i": "panel-1", "x": 6, "y": 0, "w": 6, "h": 4}
                ]),
                "duplicates",
            ),
            (
                "grid overflow",
                serde_json::json!([
                    {"i": "panel-1", "x": 20, "y": 0, "w": 6, "h": 4}
                ]),
                "24-column grid",
            ),
            (
                "fractional coordinate",
                serde_json::json!([
                    {"i": "panel-1", "x": 0.5, "y": 0, "w": 6, "h": 4}
                ]),
                "unsigned integer",
            ),
        ];

        for (case, layout, expected_reason) in cases {
            let mut body = valid_layout_template_body();
            body["layout"] = layout;
            let err = LayoutTemplateUpsert::from_body(&body).unwrap_err();
            assert!(
                matches!(&err, GatewayError::BadRequest(reason) if reason.contains(expected_reason)),
                "{case} should reject with {expected_reason}, got {err}"
            );
        }
    }

    #[test]
    fn layout_template_upsert_rejects_top_level_extras_builtin_and_hidden_duplicates() {
        let mut extra_field = valid_layout_template_body();
        extra_field["rawHtml"] = serde_json::json!("<script>");
        let extra_err = LayoutTemplateUpsert::from_body(&extra_field).unwrap_err();
        assert!(
            matches!(&extra_err, GatewayError::BadRequest(reason) if reason.contains("not part of the accepted request schema")),
            "unexpected extra field error: {extra_err}"
        );

        let mut builtin_claim = valid_layout_template_body();
        builtin_claim["isBuiltIn"] = serde_json::json!(true);
        let builtin_err = LayoutTemplateUpsert::from_body(&builtin_claim).unwrap_err();
        assert!(
            matches!(&builtin_err, GatewayError::BadRequest(reason) if reason.contains("code-owned")),
            "unexpected built-in claim error: {builtin_err}"
        );

        let mut duplicate_hidden = valid_layout_template_body();
        duplicate_hidden["hiddenPanels"] = serde_json::json!(["panel-1", "panel-1"]);
        let duplicate_err = LayoutTemplateUpsert::from_body(&duplicate_hidden).unwrap_err();
        assert!(
            matches!(&duplicate_err, GatewayError::BadRequest(reason) if reason.contains("duplicates")),
            "unexpected hidden-panel duplicate error: {duplicate_err}"
        );
    }

    #[tokio::test]
    async fn layout_template_put_rejects_stringified_layout_and_persists_canonical_array() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:layout-shape";
        let token = "layout-shape-token";
        let id = "layout-shape-regression";
        insert_test_session(&pool, token, did).await;
        sqlx::query("DELETE FROM layout_templates WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let stringified_body = serde_json::to_string(&serde_json::json!({
            "id": id,
            "name": "Layout Shape Regression",
            "layout": "[{\"i\":\"panel-1\",\"x\":0,\"y\":0,\"w\":6,\"h\":4}]",
            "hiddenPanels": [],
            "createdAt": 10_000,
            "updatedAt": 10_001
        }))
        .unwrap();
        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/layout-templates")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(stringified_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let count_after_reject: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM layout_templates WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count_after_reject, 0);

        let mut canonical = valid_layout_template_body();
        canonical["id"] = serde_json::json!(id);
        let accepted = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/layout-templates")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(canonical.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        let row = sqlx::query(
            "SELECT user_did, layout_json, hidden_panels FROM layout_templates WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row.get::<Option<String>, _>("user_did"),
            Some(did.to_owned())
        );
        assert!(
            row.get::<serde_json::Value, _>("layout_json")
                .as_array()
                .is_some()
        );
        assert!(
            row.get::<serde_json::Value, _>("hidden_panels")
                .as_array()
                .is_some()
        );

        sqlx::query("DELETE FROM layout_templates WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn layout_template_put_must_not_default_or_persist_unvalidated_json() {
        let source = include_str!("server.rs");
        let layout_put = source_between(
            source,
            "async fn handle_layout_template_put",
            "/// DELETE /api/v1/layout-templates/:id",
        );

        assert!(
            layout_put.contains("LayoutTemplateUpsert::from_body(&body)"),
            "layout template PUT must validate the full request schema before persistence"
        );
        assert!(
            !layout_put.contains("unwrap_or(\"Untitled\")"),
            "layout template PUT must reject a missing name instead of fabricating one"
        );
        assert!(
            !layout_put.contains("unwrap_or(serde_json::json!([]))"),
            "layout template PUT must reject missing layout arrays instead of fabricating them"
        );
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
    fn advance_pace_metadata_requires_signed_action_provenance() {
        let body = serde_json::json!({"queuedAt": 10_000});
        let err = AdvancePaceMetadata::from_optional_body(Some(&body)).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("provenanceTimestampPhysicalMs")),
            "expected provenance timestamp refusal, got {err}"
        );
    }

    #[test]
    fn advance_pace_action_hash_binds_target_and_subject_kind() {
        let actor = Did::new("did:exo:pace-actor").unwrap();
        let target = Did::new("did:exo:pace-target").unwrap();
        let other_target = Did::new("did:exo:pace-other").unwrap();
        let body = signed_advance_pace_body(
            actor.as_str(),
            target.as_str(),
            PaceSubjectKind::Agent,
            10_000,
        );
        let metadata = AdvancePaceMetadata::from_optional_body(Some(&body)).unwrap();

        let agent_hash =
            advance_pace_action_hash(&actor, &target, PaceSubjectKind::Agent, &metadata).unwrap();
        let user_hash =
            advance_pace_action_hash(&actor, &target, PaceSubjectKind::User, &metadata).unwrap();
        let other_target_hash =
            advance_pace_action_hash(&actor, &other_target, PaceSubjectKind::Agent, &metadata)
                .unwrap();

        assert_ne!(agent_hash, user_hash);
        assert_ne!(agent_hash, other_target_hash);
    }

    #[test]
    fn decision_create_metadata_requires_signed_action_provenance() {
        let request = DecisionCreateRequest {
            id: "00000000-0000-0000-0000-000000000061".into(),
            title: "missing provenance".into(),
            decision_class: "Routine".into(),
            constitutional_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                .into(),
            created_at_physical_ms: 7000,
            created_at_logical: 0,
            constitution_version: "exochain-constitution-v1".into(),
            provenance_timestamp_physical_ms: None,
            provenance_timestamp_logical: None,
            provenance_public_key: None,
            provenance_signature: None,
        };
        let err = DecisionCreateProvenanceMetadata::from_request(&request).unwrap_err();
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("provenance_timestamp_physical_ms")),
            "expected provenance timestamp refusal, got {err}"
        );
    }

    #[test]
    fn decision_create_action_hash_binds_tenant_and_decision_id() {
        let actor = Did::new("did:exo:decision-hash-actor").unwrap();
        let body = signed_decision_create_body(DecisionCreateBodyFixture {
            actor_did: actor.as_str(),
            tenant_id: "tenant-a",
            id: "00000000-0000-0000-0000-000000000062",
            title: "hash binding",
            decision_class: "Routine",
            constitutional_hash: "4444444444444444444444444444444444444444444444444444444444444444",
            created_at_physical_ms: 8200,
            created_at_logical: 0,
            constitution_version: "exochain-constitution-v1",
        });
        let request: DecisionCreateRequest = serde_json::from_value(body).unwrap();
        let class = parse_decision_class(&request.decision_class).unwrap();
        let constitutional_hash =
            parse_hash256_hex(&request.constitutional_hash, "constitutional_hash").unwrap();
        let created_at = Timestamp::new(request.created_at_physical_ms, request.created_at_logical);
        let decision = DecisionObject::new(DecisionObjectInput {
            id: parse_decision_uuid(&request.id, "id").unwrap(),
            title: request.title.clone(),
            class,
            constitutional_hash,
            created_at,
        })
        .unwrap();
        let tenant_a = decision_create_action_hash(
            &actor,
            "tenant-a",
            &decision,
            &constitutional_hash,
            &request.constitution_version,
        )
        .unwrap();
        let tenant_b = decision_create_action_hash(
            &actor,
            "tenant-b",
            &decision,
            &constitutional_hash,
            &request.constitution_version,
        )
        .unwrap();
        let other_decision = DecisionObject::new(DecisionObjectInput {
            id: parse_decision_uuid("00000000-0000-0000-0000-000000000063", "id").unwrap(),
            title: request.title,
            class,
            constitutional_hash,
            created_at,
        })
        .unwrap();
        let other_id = decision_create_action_hash(
            &actor,
            "tenant-a",
            &other_decision,
            &constitutional_hash,
            &request.constitution_version,
        )
        .unwrap();

        assert_ne!(tenant_a, tenant_b);
        assert_ne!(tenant_a, other_id);
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
            .find("build_adjudication_context(&actor, &action.required_permissions)")
            .expect("advance_pace must adjudicate the authenticated session actor");
        let kernel_index = handler
            .find("state.kernel.adjudicate")
            .expect("advance_pace must retain kernel adjudication");
        let provenance_index = handler
            .find("ctx.provenance = Some(provenance)")
            .expect("advance_pace must attach action provenance before adjudication");

        assert!(
            auth_index < context_index && context_index < kernel_index,
            "advance_pace must authenticate before building the adjudication context"
        );
        assert!(
            context_index < provenance_index && provenance_index < kernel_index,
            "advance_pace must attach signed action provenance before kernel adjudication"
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

    #[test]
    fn advance_pace_handler_persists_authorized_result_to_matched_subject_table() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_advance_pace",
            "// ---------------------------------------------------------------------------\n// Legal / eDiscovery handlers",
        );
        let router = source_between(
            source,
            "pub fn build_router",
            "// ---------------------------------------------------------------------------\n// Tests",
        );

        assert!(
            source.contains("enum PaceSubjectKind"),
            "advance-pace routes must classify agent and user targets before persistence"
        );
        assert!(
            handler.contains("db::update_agent_pace") && handler.contains("db::update_user_pace"),
            "advance_pace must persist successful adjudication through the matched PACE table"
        );
        assert!(
            handler.contains("sqlx::Error::RowNotFound"),
            "advance_pace must fail closed when the authenticated DID has no matching subject row"
        );
        assert!(
            router.contains("post(handle_agent_advance_pace)")
                && router.contains("post(handle_user_advance_pace)"),
            "agent and user advance-pace routes must not share an indistinguishable persistence path"
        );
    }

    #[test]
    fn advance_pace_authorization_fixture_registers_trusted_grantor_document() {
        let source = include_str!("server.rs");
        let start_index = source
            .rfind("async fn insert_advance_pace_authorization")
            .expect("fixture function marker present");
        let after_start = &source[start_index..];
        let end_index = after_start
            .find("    async fn insert_test_agent")
            .expect("fixture end marker present");
        let fixture = &after_start[..end_index];

        assert!(
            fixture.contains("db::insert_did_document(pool, &grantor_doc)"),
            "DB-backed advance-pace fixture must register the authority grantor DID document so trusted grantor keys are resolved from durable state"
        );
        assert!(
            fixture.contains("db::insert_did_document(pool, &actor_doc)"),
            "DB-backed advance-pace fixture must register the actor DID document so action provenance keys are resolved from durable state"
        );
    }

    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_index = source.find(start).expect("source start marker");
        let after_start = &source[start_index..];
        let end_index = after_start.find(end).expect("source end marker");
        &after_start[..end_index]
    }

    async fn cleanup_pace_route_fixture(pool: &sqlx::PgPool, did: &str, token: &str) {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(pool)
            .await
            .unwrap();

        for statement in [
            "DELETE FROM agents WHERE did = $1 OR owner_did = $1",
            "DELETE FROM users WHERE did = $1",
            "DELETE FROM agent_roles WHERE agent_did = $1 OR granted_by = $1",
            "DELETE FROM consent_records WHERE subject_did = $1 OR actor_did = $1",
            "DELETE FROM authority_chains WHERE actor_did = $1",
            "DELETE FROM did_documents WHERE did = $1",
        ] {
            sqlx::query(statement)
                .bind(did)
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind("did:exo:advance-pace-root")
            .execute(pool)
            .await
            .unwrap();
    }

    async fn insert_advance_pace_authorization(pool: &sqlx::PgPool, did: &str, token: &str) {
        cleanup_pace_route_fixture(pool, did, token).await;
        insert_test_session(pool, token, did).await;

        let actor = Did::new(did).unwrap();
        let root = Did::new("did:exo:advance-pace-root").unwrap();
        sqlx::query(
            "INSERT INTO agent_roles (agent_did, role, branch, granted_by, valid_from, expires_at) \
             VALUES ($1, $2, $3, $4, $5, NULL)",
        )
        .bind(did)
        .bind("worker")
        .bind("executive")
        .bind(root.to_string())
        .bind(1_000_i64)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO consent_records \
             (subject_did, actor_did, scope, bailment_type, status, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        )
        .bind(root.to_string())
        .bind(did)
        .bind("pace:advance")
        .bind("constitutional_pace")
        .bind("active")
        .bind(1_000_i64)
        .execute(pool)
        .await
        .unwrap();

        let chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let grantor_public_key = chain.links[0]
            .grantor_public_key
            .as_ref()
            .and_then(|key| <[u8; 32]>::try_from(key.as_slice()).ok())
            .map(exo_core::PublicKey::from_bytes)
            .expect("test authority link includes a 32-byte Ed25519 grantor key");
        let grantor_doc = did_document_with_ed25519_key(&root, &grantor_public_key);
        assert!(
            db::insert_did_document(pool, &grantor_doc).await.unwrap(),
            "advance-pace root DID document should insert into the live DB fixture"
        );
        let (actor_public_key, _) = advance_pace_provenance_keypair(did);
        let actor_doc = did_document_with_ed25519_key(&actor, &actor_public_key);
        assert!(
            db::insert_did_document(pool, &actor_doc).await.unwrap(),
            "advance-pace actor DID document should insert into the live DB fixture"
        );
        sqlx::query(
            "INSERT INTO authority_chains (actor_did, chain_json, valid_from, expires_at) \
             VALUES ($1, $2, $3, NULL)",
        )
        .bind(did)
        .bind(serde_json::to_value(chain).unwrap())
        .bind(1_000_i64)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn cleanup_decision_create_fixture(pool: &sqlx::PgPool, did: &str, token: &str) {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(pool)
            .await
            .unwrap();

        for query in [
            "DELETE FROM users WHERE did = $1",
            "DELETE FROM agent_roles WHERE agent_did = $1 OR granted_by = $1",
            "DELETE FROM consent_records WHERE subject_did = $1 OR actor_did = $1",
            "DELETE FROM authority_chains WHERE actor_did = $1",
            "DELETE FROM did_documents WHERE did = $1",
        ] {
            sqlx::query(query).bind(did).execute(pool).await.unwrap();
        }
        sqlx::query("DELETE FROM did_documents WHERE did = $1")
            .bind("did:exo:decision-create-root")
            .execute(pool)
            .await
            .unwrap();
    }

    async fn insert_decision_create_authorization(
        pool: &sqlx::PgPool,
        did: &str,
        tenant_id: &str,
        token: &str,
    ) {
        cleanup_decision_create_fixture(pool, did, token).await;
        insert_test_user(pool, did, tenant_id).await;
        insert_test_session(pool, token, did).await;

        let actor = Did::new(did).unwrap();
        let root = Did::new("did:exo:decision-create-root").unwrap();
        sqlx::query(
            "INSERT INTO agent_roles (agent_did, role, branch, granted_by, valid_from, expires_at) \
             VALUES ($1, $2, $3, $4, $5, NULL)",
        )
        .bind(did)
        .bind("worker")
        .bind("executive")
        .bind(root.to_string())
        .bind(1_000_i64)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO consent_records \
             (subject_did, actor_did, scope, bailment_type, status, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        )
        .bind(root.to_string())
        .bind(did)
        .bind("create_decision")
        .bind("constitutional_decision")
        .bind("active")
        .bind(1_000_i64)
        .execute(pool)
        .await
        .unwrap();

        let chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("create_decision")]),
            )],
        };
        let grantor_public_key = chain.links[0]
            .grantor_public_key
            .as_ref()
            .and_then(|key| <[u8; 32]>::try_from(key.as_slice()).ok())
            .map(exo_core::PublicKey::from_bytes)
            .expect("test authority link includes a 32-byte Ed25519 grantor key");
        let grantor_doc = did_document_with_ed25519_key(&root, &grantor_public_key);
        assert!(
            db::insert_did_document(pool, &grantor_doc).await.unwrap(),
            "decision-create root DID document should insert into the live DB fixture"
        );
        let (actor_public_key, _) = decision_create_provenance_keypair(did);
        let actor_doc = did_document_with_ed25519_key(&actor, &actor_public_key);
        assert!(
            db::insert_did_document(pool, &actor_doc).await.unwrap(),
            "decision-create actor DID document should insert into the live DB fixture"
        );
        sqlx::query(
            "INSERT INTO authority_chains (actor_did, chain_json, valid_from, expires_at) \
             VALUES ($1, $2, $3, NULL)",
        )
        .bind(did)
        .bind(serde_json::to_value(chain).unwrap())
        .bind(1_000_i64)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_test_agent(pool: &sqlx::PgPool, did: &str, owner_did: &str, tenant_id: &str) {
        sqlx::query("DELETE FROM agents WHERE did = $1 OR owner_did = $2")
            .bind(did)
            .bind(owner_did)
            .execute(pool)
            .await
            .unwrap();
        db::insert_agent(
            pool,
            did,
            "Pace Agent",
            "governance",
            owner_did,
            tenant_id,
            &serde_json::json!(["pace"]),
            "standard",
            10_000,
            None,
            "Unenrolled",
            10_000_i64,
            "Active",
            "routine",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn agent_get_rejects_cross_tenant_registered_did() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let reader = "did:exo:agent-get-tenant-b-reader";
        let agent = "did:exo:agent-get-tenant-a-agent";
        let token = "agent-get-cross-tenant-token";
        insert_test_user(&pool, reader, "tenant-agent-get-b").await;
        insert_test_session(&pool, token, reader).await;
        insert_test_agent(
            &pool,
            agent,
            "did:exo:agent-get-tenant-a-owner",
            "tenant-agent-get-a",
        )
        .await;

        let registry = Arc::new(RwLock::new(LocalDidRegistry::new()));
        registry
            .write()
            .unwrap()
            .register(minimal_doc(agent))
            .unwrap();
        let app = build_router(AppState::new(Some(pool.clone()), registry));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/agents/{agent}"))
                    .header("authorization", format!("Bearer {token}"))
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "15000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "agent get must not disclose a DID document for an agent outside the authenticated actor tenant"
        );

        sqlx::query("DELETE FROM agents WHERE did = $1 OR owner_did = $2")
            .bind(agent)
            .bind("did:exo:agent-get-tenant-a-owner")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(reader)
            .execute(&pool)
            .await
            .unwrap();
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

        let app = build_router(db_state_at(
            pool.clone(),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
            10_000,
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agents/did:exo:alice/advance-pace")
                    .header("authorization", "Bearer advance-no-authority-token")
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "10000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        signed_advance_pace_body(
                            "did:exo:alice",
                            "did:exo:alice",
                            PaceSubjectKind::Agent,
                            10_000,
                        )
                        .to_string(),
                    ))
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
    async fn agent_advance_pace_persists_agent_pace_status_after_kernel_permit() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:advance-pace-agent";
        let token = "advance-pace-agent-token";

        insert_advance_pace_authorization(&pool, did, token).await;
        insert_test_agent(
            &pool,
            did,
            "did:exo:advance-pace-owner",
            "tenant-pace-agent",
        )
        .await;

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/agents/{did}/advance-pace"))
                    .header("authorization", format!("Bearer {token}"))
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "10000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        signed_advance_pace_body(did, did, PaceSubjectKind::Agent, 10_000)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let persisted = db::find_agent_by_did(&pool, did, "tenant-pace-agent")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.pace_status, "Advanced");

        cleanup_pace_route_fixture(&pool, did, token).await;
        sqlx::query("DELETE FROM agents WHERE owner_did = $1")
            .bind("did:exo:advance-pace-owner")
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn user_advance_pace_persists_user_pace_status_after_kernel_permit() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let did = "did:exo:advance-pace-user";
        let token = "advance-pace-user-token";

        insert_advance_pace_authorization(&pool, did, token).await;
        insert_test_user(&pool, did, "tenant-pace-user").await;

        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/users/{did}/advance-pace"))
                    .header("authorization", format!("Bearer {token}"))
                    .header(AUTH_OBSERVED_AT_MS_HEADER, "10000")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        signed_advance_pace_body(did, did, PaceSubjectKind::User, 10_000)
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let persisted = db::find_user_by_did(&pool, did).await.unwrap().unwrap();
        assert_eq!(persisted.pace_status, "Advanced");

        cleanup_pace_route_fixture(&pool, did, token).await;
    }

    #[tokio::test]
    async fn ediscovery_export_requires_authenticated_session() {
        let app = build_router(state());
        let body = serde_json::json!({
            "requester": "did:exo:counsel",
            "scope": "matter-42",
            "date_start": { "physical_ms": 1, "logical": 0 },
            "date_end": { "physical_ms": 500, "logical": 0 },
            "custodians": ["did:exo:alice"],
            "search_terms": ["contract"],
            "corpus": [
                {
                    "id": "00000000-0000-0000-0000-000000000501",
                    "type_tag": "contract",
                    "hash": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                    "creator": "did:exo:alice",
                    "timestamp": { "physical_ms": 100, "logical": 0 },
                    "chain_of_custody": [],
                    "admissibility_status": "Pending"
                }
            ]
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/ediscovery/export")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn ediscovery_export_requester_must_match_authenticated_session_actor() {
        let body = EDiscoveryExportRequest {
            requester: Did::new("did:exo:spoofed-counsel").unwrap(),
            scope: "matter-42".to_owned(),
            date_start: Timestamp::new(1, 0),
            date_end: Timestamp::new(500, 0),
            custodians: vec![Did::new("did:exo:alice").unwrap()],
            search_terms: vec!["contract".to_owned()],
            corpus: vec![Evidence {
                id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000501").unwrap(),
                type_tag: "contract".to_owned(),
                hash: Hash256::from_bytes([1; 32]),
                creator: Did::new("did:exo:alice").unwrap(),
                timestamp: Timestamp::new(100, 0),
                chain_of_custody: vec![],
                admissibility_status: exo_legal::evidence::AdmissibilityStatus::Pending,
            }],
        };

        let err = body
            .into_search_inputs(Did::new("did:exo:authenticated-counsel").unwrap())
            .expect_err("caller must not be able to spoof the eDiscovery requester DID");
        assert!(
            matches!(&err, GatewayError::BadRequest(reason) if reason.contains("authenticated session actor")),
            "unexpected requester binding error: {err}"
        );
    }

    #[tokio::test]
    async fn ediscovery_export_uses_legal_engine_instead_of_501() {
        let pool = match gateway_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let token = "ediscovery-route-token";
        insert_test_session(&pool, token, "did:exo:counsel").await;
        let app = build_router(AppState::new(
            Some(pool.clone()),
            Arc::new(RwLock::new(LocalDidRegistry::new())),
        ));
        let body = serde_json::json!({
            "requester": "did:exo:counsel",
            "scope": "matter-42",
            "date_start": { "physical_ms": 1, "logical": 0 },
            "date_end": { "physical_ms": 500, "logical": 0 },
            "custodians": ["did:exo:alice"],
            "search_terms": ["contract"],
            "corpus": [
                {
                    "id": "00000000-0000-0000-0000-000000000501",
                    "type_tag": "contract",
                    "hash": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                    "creator": "did:exo:alice",
                    "timestamp": { "physical_ms": 100, "logical": 0 },
                    "chain_of_custody": [],
                    "admissibility_status": "Pending"
                },
                {
                    "id": "00000000-0000-0000-0000-000000000502",
                    "type_tag": "memo",
                    "hash": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                    "creator": "did:exo:bob",
                    "timestamp": { "physical_ms": 200, "logical": 0 },
                    "chain_of_custody": [],
                    "admissibility_status": "Pending"
                }
            ]
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/ediscovery/export")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["documents"].as_array().unwrap().len(), 1);
        assert_eq!(value["documents"][0]["type_tag"], "contract");
        assert_eq!(value["privilege_log"].as_array().unwrap().len(), 0);
        assert_eq!(value["production_hash"].as_array().unwrap().len(), 32);

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn ediscovery_export_handler_authenticates_before_searching_corpus() {
        let source = include_str!("server.rs");
        let handler = source_between(
            source,
            "async fn handle_ediscovery_export",
            "// ---------------------------------------------------------------------------\n// Helpers",
        );
        let auth_index = handler
            .find("require_authenticated_session_actor_from_header")
            .expect("eDiscovery export must authenticate the bearer session");
        let parse_index = handler
            .find("body.into_search_inputs")
            .expect("eDiscovery export must validate the request after authentication");
        let search_index = handler
            .find("ediscovery::search")
            .expect("eDiscovery export must call the legal search engine");
        assert!(
            auth_index < parse_index && parse_index < search_index,
            "eDiscovery export must authenticate before parsing trusted request inputs and searching caller-supplied evidence"
        );
    }

    #[test]
    fn gateway_server_production_has_no_enterprise_501_stubs() {
        let source = include_str!("server.rs");
        let production = source
            .split("\nmod tests {")
            .next()
            .expect("server production section must be present");

        for forbidden in [
            "StatusCode::NOT_IMPLEMENTED",
            "Stub endpoint",
            "saml_not_configured",
            "ediscovery_not_configured",
        ] {
            assert!(
                !production.contains(forbidden),
                "gateway production must not expose enterprise stub marker: {forbidden}"
            );
        }
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
        provenance_signature_message,
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
    fn signed_authority_link_for_permissions(
        grantor: &Did,
        grantee: &Did,
        permissions: PermissionSet,
    ) -> AuthorityLink {
        let (public_key, secret_key) = generate_keypair();

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

    fn signed_authority_link(grantor: &Did, grantee: &Did) -> AuthorityLink {
        signed_authority_link_for_permissions(
            grantor,
            grantee,
            PermissionSet::new(vec![Permission::new("vote")]),
        )
    }

    fn trusted_authority_keys_for_test_chain(
        authority_chain: &AuthorityChain,
    ) -> TrustedAuthorityKeys {
        let mut trusted_keys = TrustedAuthorityKeys::default();
        for link in &authority_chain.links {
            let Some(public_key) = link.grantor_public_key.clone() else {
                continue;
            };
            trusted_keys
                .entry(link.grantor.clone())
                .or_default()
                .push(public_key);
        }
        trusted_keys
    }

    fn signed_action_provenance_for_test(actor: &Did) -> (Provenance, TrustedProvenanceKeys) {
        let (public_key, secret_key) = generate_keypair();
        let mut provenance = Provenance {
            actor: actor.clone(),
            timestamp: Timestamp::new(1_700_000_000_000, 0).to_string(),
            action_hash: Hash256::digest(b"advance_pace").as_bytes().to_vec(),
            signature: Vec::new(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message = provenance_signature_message(&provenance)
            .expect("canonical provenance signature payload");
        provenance.signature = sign(message.as_bytes(), &secret_key).to_bytes().to_vec();
        let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
        trusted_provenance_keys.insert(actor.clone(), vec![public_key.as_bytes().to_vec()]);
        (provenance, trusted_provenance_keys)
    }

    fn valid_db_context(actor: &Did) -> AdjudicationContext {
        let root = Did::new("did:exo:root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link(&root, actor)],
        };
        let trusted_authority_keys = trusted_authority_keys_for_test_chain(&authority_chain);
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "voter".to_string(),
                branch: GovernmentBranch::Legislative,
            }],
            authority_chain,
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
            trusted_authority_keys,
            trusted_provenance_keys: TrustedProvenanceKeys::default(),
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

    fn action_for_permission(actor: &Did, permission: &str) -> GkActionRequest {
        GkActionRequest {
            actor: actor.clone(),
            action: permission.to_string(),
            required_permissions: PermissionSet::new(vec![Permission::new(permission)]),
            is_self_grant: false,
            modifies_kernel: false,
        }
    }

    fn db_role_row(actor: &Did, role: &str, branch: &str) -> crate::db::AgentRoleRow {
        crate::db::AgentRoleRow {
            agent_did: actor.as_str().to_string(),
            role: role.to_string(),
            branch: branch.to_string(),
            granted_by: "did:exo:root-grantor".to_string(),
            valid_from: 1,
            expires_at: None,
        }
    }

    fn db_consent_row(actor: &Did, subject_did: &str) -> crate::db::ConsentRecordRow {
        db_consent_row_with_scope(actor, subject_did, "data:vote")
    }

    fn db_consent_row_with_scope(
        actor: &Did,
        subject_did: &str,
        scope: &str,
    ) -> crate::db::ConsentRecordRow {
        crate::db::ConsentRecordRow {
            subject_did: subject_did.to_string(),
            actor_did: actor.as_str().to_string(),
            scope: scope.to_string(),
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
        let role_rows = vec![db_role_row(&actor, "voter", "tribunal")];

        let result = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &[],
            &PermissionSet::default(),
            None,
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        );

        assert_internal_error_contains(result, "unknown role branch");
    }

    #[test]
    fn adjudication_context_rows_reject_unknown_role_name() {
        let actor = Did::new("did:exo:alice").unwrap();
        let role_rows = vec![db_role_row(&actor, "root", "judicial")];

        let result = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &[],
            &PermissionSet::default(),
            None,
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        );

        assert_internal_error_contains(result, "unknown governed role name");
    }

    #[test]
    fn adjudication_context_rows_reject_role_name_branch_mismatch() {
        let actor = Did::new("did:exo:alice").unwrap();
        let role_rows = vec![db_role_row(&actor, "judge", "executive")];

        let result = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &[],
            &PermissionSet::default(),
            None,
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        );

        assert_internal_error_contains(result, "does not match governed branch");
    }

    #[test]
    fn adjudication_context_rows_reject_malformed_consent_subject_did() {
        let actor = Did::new("did:exo:alice").unwrap();
        let consent_rows = vec![db_consent_row(&actor, "not-a-did")];

        let result = build_adjudication_context_from_rows(
            &actor,
            &[],
            &consent_rows,
            &PermissionSet::default(),
            None,
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        );

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

        let result = build_adjudication_context_from_rows(
            &actor,
            &[],
            &[],
            &PermissionSet::default(),
            Some(&chain_row),
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        );

        assert_internal_error_contains(result, "authority chain JSON");
    }

    #[test]
    fn adjudication_context_rows_build_valid_db_context() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:alice").unwrap();
        let valid_context = valid_db_context(&actor);
        let role_rows = vec![db_role_row(&actor, "voter", "legislative")];
        let consent_rows = vec![db_consent_row(&actor, "did:exo:root-grantor")];
        let chain_row = db_authority_chain_row(
            &actor,
            serde_json::to_value(&valid_context.authority_chain).unwrap(),
        );

        let ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            &vote_action(&actor).required_permissions,
            Some(&chain_row),
            valid_context.trusted_authority_keys.clone(),
            valid_context.trusted_provenance_keys.clone(),
        )
        .unwrap();
        let verdict = kernel.adjudicate(&vote_action(&actor), &ctx);

        assert_eq!(ctx.actor_roles.len(), 1);
        assert_eq!(ctx.consent_records.len(), 1);
        assert!(matches!(ctx.bailment_state, BailmentState::Active { .. }));
        assert!(verdict.is_permitted(), "valid DB rows must be permitted");
    }

    #[test]
    fn adjudication_context_rows_derive_actor_permissions_from_authority_chain_scope() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:pace-agent").unwrap();
        let root = Did::new("did:exo:root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let role_rows = vec![db_role_row(&actor, "worker", "executive")];
        let consent_rows = vec![db_consent_row_with_scope(
            &actor,
            root.as_str(),
            "pace:advance",
        )];
        let chain_row =
            db_authority_chain_row(&actor, serde_json::to_value(&authority_chain).unwrap());
        let trusted_authority_keys = trusted_authority_keys_for_test_chain(&authority_chain);

        let ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            &action_for_permission(&actor, "advance_pace").required_permissions,
            Some(&chain_row),
            trusted_authority_keys,
            TrustedProvenanceKeys::default(),
        )
        .unwrap();
        let verdict = kernel.adjudicate(&action_for_permission(&actor, "advance_pace"), &ctx);

        assert!(
            ctx.actor_permissions
                .contains(&Permission::new("advance_pace"))
        );
        assert!(
            !ctx.actor_permissions.contains(&Permission::new("vote")),
            "F-010: DB adjudication context must not synthesize vote permission"
        );
        assert!(
            verdict.is_permitted(),
            "F-010: action permission backed by DB authority-chain scope must be permitted"
        );
    }

    #[test]
    fn adjudication_context_rows_reject_consent_scope_that_does_not_cover_action_permission() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:pace-agent").unwrap();
        let root = Did::new("did:exo:root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let role_rows = vec![db_role_row(&actor, "worker", "executive")];
        let consent_rows = vec![db_consent_row_with_scope(
            &actor,
            root.as_str(),
            "data:profile",
        )];
        let chain_row =
            db_authority_chain_row(&actor, serde_json::to_value(&authority_chain).unwrap());
        let trusted_authority_keys = trusted_authority_keys_for_test_chain(&authority_chain);

        let ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            &action_for_permission(&actor, "advance_pace").required_permissions,
            Some(&chain_row),
            trusted_authority_keys,
            TrustedProvenanceKeys::default(),
        )
        .unwrap();
        let verdict = kernel.adjudicate(&action_for_permission(&actor, "advance_pace"), &ctx);

        assert!(
            !verdict.is_permitted(),
            "advance_pace authority must not convert unrelated profile consent into action consent"
        );
    }

    #[test]
    fn adjudication_context_rows_bind_consent_to_requested_permission_independent_of_row_order() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:pace-agent").unwrap();
        let root = Did::new("did:exo:root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let role_rows = vec![db_role_row(&actor, "worker", "executive")];
        let unrelated_consent = db_consent_row_with_scope(&actor, root.as_str(), "data:profile");
        let matching_consent = db_consent_row_with_scope(&actor, root.as_str(), "pace:advance");
        let chain_row =
            db_authority_chain_row(&actor, serde_json::to_value(&authority_chain).unwrap());
        let trusted_authority_keys = trusted_authority_keys_for_test_chain(&authority_chain);
        let action = action_for_permission(&actor, "advance_pace");

        for consent_rows in [
            vec![unrelated_consent.clone(), matching_consent.clone()],
            vec![matching_consent, unrelated_consent],
        ] {
            let ctx = build_adjudication_context_from_rows(
                &actor,
                &role_rows,
                &consent_rows,
                &action.required_permissions,
                Some(&chain_row),
                trusted_authority_keys.clone(),
                TrustedProvenanceKeys::default(),
            )
            .unwrap();
            let verdict = kernel.adjudicate(&action, &ctx);

            assert!(
                verdict.is_permitted(),
                "active matching consent must authorize the action regardless of DB row order: {verdict:?}"
            );
        }
    }

    #[test]
    fn adjudication_context_rows_reject_unresolved_authority_grantor_public_key() {
        let kernel = adjudication_kernel();
        let actor = Did::new("did:exo:pace-agent").unwrap();
        let unresolved_root = Did::new("did:exo:unresolved-root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &unresolved_root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let role_rows = vec![db_role_row(&actor, "worker", "executive")];
        let consent_rows = vec![db_consent_row(&actor, unresolved_root.as_str())];
        let chain_row =
            db_authority_chain_row(&actor, serde_json::to_value(&authority_chain).unwrap());

        let ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            &action_for_permission(&actor, "advance_pace").required_permissions,
            Some(&chain_row),
            TrustedAuthorityKeys::default(),
            TrustedProvenanceKeys::default(),
        )
        .unwrap();
        let verdict = kernel.adjudicate(&action_for_permission(&actor, "advance_pace"), &ctx);

        assert!(
            !verdict.is_permitted(),
            "DB-loaded authority chains must not trust self-attested unresolved grantor keys"
        );
    }

    #[test]
    fn adjudication_context_rows_reject_unresolved_provenance_actor_public_key() {
        let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
        let actor = Did::new("did:exo:pace-agent").unwrap();
        let root = Did::new("did:exo:root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let role_rows = vec![db_role_row(&actor, "worker", "executive")];
        let consent_rows = vec![db_consent_row_with_scope(
            &actor,
            root.as_str(),
            "pace:advance",
        )];
        let chain_row =
            db_authority_chain_row(&actor, serde_json::to_value(&authority_chain).unwrap());
        let trusted_authority_keys = trusted_authority_keys_for_test_chain(&authority_chain);
        let (provenance, _trusted_provenance_keys) = signed_action_provenance_for_test(&actor);

        let mut ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            &action_for_permission(&actor, "advance_pace").required_permissions,
            Some(&chain_row),
            trusted_authority_keys,
            TrustedProvenanceKeys::default(),
        )
        .unwrap();
        ctx.provenance = Some(provenance);
        let verdict = kernel.adjudicate(&action_for_permission(&actor, "advance_pace"), &ctx);

        match verdict {
            Verdict::Denied { violations } => {
                assert!(violations.iter().any(|violation| {
                    violation.description.contains("unresolved for actor DID")
                }))
            }
            other => panic!("unresolved provenance actor key must deny, got {other:?}"),
        }
    }

    #[test]
    fn adjudication_context_rows_permit_bound_provenance_actor_public_key() {
        let kernel = Kernel::new(b"exochain-constitution-v1", InvariantSet::all());
        let actor = Did::new("did:exo:pace-agent").unwrap();
        let root = Did::new("did:exo:root-grantor").unwrap();
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link_for_permissions(
                &root,
                &actor,
                PermissionSet::new(vec![Permission::new("advance_pace")]),
            )],
        };
        let role_rows = vec![db_role_row(&actor, "worker", "executive")];
        let consent_rows = vec![db_consent_row_with_scope(
            &actor,
            root.as_str(),
            "pace:advance",
        )];
        let chain_row =
            db_authority_chain_row(&actor, serde_json::to_value(&authority_chain).unwrap());
        let trusted_authority_keys = trusted_authority_keys_for_test_chain(&authority_chain);
        let (provenance, trusted_provenance_keys) = signed_action_provenance_for_test(&actor);

        let mut ctx = build_adjudication_context_from_rows(
            &actor,
            &role_rows,
            &consent_rows,
            &action_for_permission(&actor, "advance_pace").required_permissions,
            Some(&chain_row),
            trusted_authority_keys,
            trusted_provenance_keys,
        )
        .unwrap();
        ctx.provenance = Some(provenance);
        let verdict = kernel.adjudicate(&action_for_permission(&actor, "advance_pace"), &ctx);

        assert!(
            verdict.is_permitted(),
            "DB-loaded action provenance must pass when its key is bound to actor DID"
        );
    }

    /// [APE-53 test 1] Scaffold remains deny-all regardless of feature flag.
    #[tokio::test]
    async fn scaffold_context_is_still_deny_all() {
        // The default `AppState` (no pool, no production-db feature) must always
        // produce a deny-all context — this is the WO-009 preservation check.
        let st = state();
        let actor = Did::new("did:exo:alice").unwrap();
        let action = vote_action(&actor);
        let ctx = st
            .build_adjudication_context(&actor, &action.required_permissions)
            .await;
        let verdict = st.kernel.adjudicate(&action, &ctx);
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
                name: "worker".to_string(),
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
