//! HTTP server skeleton — gateway configuration, lifecycle, and axum routing.
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::error::{GatewayError, Result};
use crate::rest::HealthResponse;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

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
    /// Wall-clock milliseconds at server start, used to compute uptime.
    start_ms: u64,
}

impl AppState {
    pub fn new(pool: Option<sqlx::PgPool>) -> Self {
        Self {
            pool,
            start_ms: now_ms(),
        }
    }

    fn uptime_seconds(&self) -> u64 {
        now_ms().saturating_sub(self.start_ms) / 1000
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
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
async fn handle_ready(
    State(state): State<AppState>,
) -> (StatusCode, Json<HealthResponse>) {
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

/// Placeholder for endpoints that are defined but not yet fully implemented.
async fn handle_not_implemented() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "not_implemented",
            "message": "This endpoint is defined but not yet fully implemented. See EXOCHAIN-REM-001."
        })),
    )
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the axum `Router` with all constitutional middleware wired.
///
/// All 20 `RestRoute` paths are registered.  Unimplemented handlers return
/// 501 until the full handler stack lands in a follow-up PR.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Probes
        .route("/health", get(handle_health))
        .route("/ready", get(handle_ready))
        // Decisions
        .route("/api/v1/decisions/:id", get(handle_not_implemented))
        .route("/api/v1/decisions", post(handle_not_implemented))
        // Auth
        .route("/api/v1/auth/token", post(handle_not_implemented))
        .route("/api/v1/auth/saml/callback", post(handle_not_implemented))
        .route("/api/v1/auth/register", post(handle_not_implemented))
        .route("/api/v1/auth/login", post(handle_not_implemented))
        .route("/api/v1/auth/refresh", post(handle_not_implemented))
        .route("/api/v1/auth/me", get(handle_not_implemented))
        .route("/api/v1/auth/logout", post(handle_not_implemented))
        // Agents (static route before parameterised to avoid ambiguity)
        .route("/api/v1/agents/enroll", post(handle_not_implemented))
        .route("/api/v1/agents", get(handle_not_implemented))
        .route("/api/v1/agents/:did", get(handle_not_implemented))
        .route("/api/v1/agents/:did/advance-pace", post(handle_not_implemented))
        // Identity
        .route("/api/v1/identity/:did/score", get(handle_not_implemented))
        // Tenant
        .route("/api/v1/tenants/:id/constitution", get(handle_not_implemented))
        // Legal
        .route("/api/v1/ediscovery/export", post(handle_not_implemented))
        // Audit
        .route("/api/v1/audit/:decision_id", get(handle_not_implemented))
        // Users
        .route("/api/v1/users", get(handle_not_implemented))
        .route("/api/v1/users/:did/advance-pace", post(handle_not_implemented))
        .with_state(state)
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
        let mut stream =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
    let state = AppState::new(pool);
    let app = build_router(state);

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
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for .oneshot()

    fn state() -> AppState {
        AppState::new(None)
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
        let paths = [
            "/api/v1/decisions/some-id",
            "/api/v1/auth/me",
            "/api/v1/agents",
            "/api/v1/agents/did:exo:bot",
            "/api/v1/identity/did:exo:alice/score",
            "/api/v1/users",
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
}
