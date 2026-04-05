//! Node API authentication and rate limiting.
//!
//! **Bearer auth**: On startup the node generates a random 256-bit admin token
//! (displayed once in the logs).  Every mutating endpoint (`POST`) requires
//! this token in the `Authorization: Bearer <token>` header.  Read-only
//! endpoints (`GET`) are public — the data on a constitutional network is
//! transparent by design.
//!
//! **Rate limiting**: Per-IP sliding-window rate limiter for write endpoints.
//! Protects governance API from brute-force or accidental request storms.
//! Read-only GET endpoints are not limited to preserve public transparency.
//!
//! When the node identity module gains a full DID-document registry, this
//! layer will be upgraded to Ed25519 DID-signature authentication (as already
//! implemented in `exo-gateway/src/auth.rs`).

#![allow(clippy::expect_used)]

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use tokio::sync::Mutex;

/// Shared bearer token state for the auth middleware.
#[derive(Clone)]
pub struct BearerAuth {
    /// The expected bearer token (hex-encoded 256-bit random value).
    pub token: Arc<String>,
}

/// Generate a cryptographically random admin token (hex-encoded 32 bytes).
#[must_use]
pub fn generate_admin_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("entropy source");
    hex::encode(bytes)
}

/// axum middleware: require bearer token on mutating requests.
///
/// `GET` and `HEAD` requests pass through without authentication.
/// All other methods (`POST`, `PUT`, `DELETE`, `PATCH`) require
/// `Authorization: Bearer <token>`.
pub async fn require_bearer_on_writes(
    auth: BearerAuth,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Read-only methods pass through.
    let method = request.method().clone();
    if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        return Ok(next.run(request).await);
    }

    // Extract the Authorization header.
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match header {
        Some(value) if value.starts_with("Bearer ") => {
            let provided = &value["Bearer ".len()..];
            if provided == auth.token.as_str() {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Per-IP write-request rate limiter.
///
/// Tracks request counts per IP address within a sliding window. When the
/// count exceeds the maximum, returns `429 Too Many Requests`.
#[derive(Clone)]
pub struct WriteRateLimiter {
    state: Arc<Mutex<RateLimiterState>>,
    max_per_window: u32,
    window_secs: u64,
}

struct RateLimiterState {
    counts: HashMap<IpAddr, (u32, Instant)>,
}

impl WriteRateLimiter {
    /// Create a new rate limiter.
    ///
    /// * `max_per_window` — maximum write requests per IP per window.
    /// * `window_secs` — sliding window duration in seconds.
    #[must_use]
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimiterState {
                counts: HashMap::new(),
            })),
            max_per_window,
            window_secs,
        }
    }

    /// Check if the given IP is within rate limits. Returns `Ok(())` if
    /// allowed, or `Err(())` if the limit is exceeded.
    async fn check(&self, ip: IpAddr) -> Result<(), ()> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let entry = state.counts.entry(ip).or_insert((0, now));
        // Reset window if expired.
        if now.duration_since(entry.1) >= window {
            entry.0 = 0;
            entry.1 = now;
        }
        if entry.0 >= self.max_per_window {
            return Err(());
        }
        entry.0 += 1;
        Ok(())
    }
}

/// axum middleware: rate-limit write requests by client IP.
///
/// `GET` and `HEAD` requests pass through without rate limiting.
/// Write methods are limited to `max_per_window` requests per IP per
/// sliding window. Returns `429 Too Many Requests` when exceeded.
pub async fn rate_limit_writes(
    limiter: WriteRateLimiter,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        return Ok(next.run(request).await);
    }

    // Extract client IP from X-Forwarded-For or connection info.
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip())
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    match limiter.check(ip).await {
        Ok(()) => Ok(next.run(request).await),
        Err(()) => {
            tracing::warn!(%ip, "Rate limit exceeded for write endpoint");
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::{get, post},
    };
    use tower::ServiceExt;

    use super::*;

    fn test_auth() -> BearerAuth {
        BearerAuth {
            token: Arc::new("test-token-abc123".to_string()),
        }
    }

    fn test_app() -> Router {
        let auth = test_auth();
        Router::new()
            .route("/read", get(|| async { "ok" }))
            .route("/write", post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let a = auth.clone();
                require_bearer_on_writes(a, req, next)
            }))
    }

    #[tokio::test]
    async fn get_requests_pass_without_token() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_with_wrong_token_forbidden() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .header("Authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_correct_token_passes() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .header("Authorization", "Bearer test-token-abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_generation_is_unique() {
        let t1 = generate_admin_token();
        let t2 = generate_admin_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes hex-encoded
    }

    // -----------------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------------

    fn rate_limited_app(max: u32) -> Router {
        let limiter = WriteRateLimiter::new(max, 60);
        Router::new()
            .route("/read", get(|| async { "ok" }))
            .route("/write", post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let l = limiter.clone();
                rate_limit_writes(l, req, next)
            }))
    }

    #[tokio::test]
    async fn rate_limiter_allows_reads_unlimited() {
        let app = rate_limited_app(1);
        // Multiple GETs should all pass.
        for _ in 0..10 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/read")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        let limiter = WriteRateLimiter::new(3, 60);
        let app = Router::new()
            .route("/write", post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let l = limiter.clone();
                rate_limit_writes(l, req, next)
            }));

        for i in 0..3 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/write")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
        }
    }

    #[tokio::test]
    async fn rate_limiter_rejects_over_limit() {
        let limiter = WriteRateLimiter::new(2, 60);
        let app = Router::new()
            .route("/write", post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let l = limiter.clone();
                rate_limit_writes(l, req, next)
            }));

        // First two pass.
        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/write")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        // Third should be rate limited.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/write")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
