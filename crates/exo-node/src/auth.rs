//! Node API authentication — bearer-token guard for write operations.
//!
//! On startup the node generates a random 256-bit admin token (displayed once
//! in the logs).  Every mutating endpoint (`POST`) requires this token in the
//! `Authorization: Bearer <token>` header.  Read-only endpoints (`GET`) are
//! public — the data on a constitutional network is transparent by design.
//!
//! When the node identity module gains a full DID-document registry, this
//! layer will be upgraded to Ed25519 DID-signature authentication (as already
//! implemented in `exo-gateway/src/auth.rs`).

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

/// Shared bearer token state for the auth middleware.
#[derive(Clone)]
pub struct BearerAuth {
    /// The expected bearer token (hex-encoded 256-bit random value).
    pub token: Arc<String>,
}

/// Generate a cryptographically random admin token (hex-encoded 32 bytes).
#[must_use]
#[allow(clippy::expect_used)] // OS entropy failure is unrecoverable.
pub fn generate_admin_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS entropy source unavailable");
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
            if constant_time_eq(provided.as_bytes(), auth.token.as_bytes()) {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Constant-time byte-slice equality.
///
/// Returns `false` on length mismatch immediately (length is not a
/// secret; the distinguishing side-channel we care about is content).
/// For equal-length slices, performs a branchless XOR-accumulate over
/// every byte so the total work is independent of where the first
/// differing byte is located.
///
/// We inline this instead of pulling in `subtle` or `constant_time_eq`
/// to avoid adding a dependency for one comparison. The implementation
/// is the standard XOR-OR-fold and is sufficient against timing
/// attacks on a bearer-token comparison.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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

    #[test]
    fn constant_time_eq_matches_equal() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn constant_time_eq_rejects_different() {
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"short", b"different-length"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn constant_time_eq_distinguishes_byte_differences() {
        // Difference at the first byte
        assert!(!constant_time_eq(b"xbcdef", b"abcdef"));
        // Difference at the last byte
        assert!(!constant_time_eq(b"abcdex", b"abcdef"));
        // Multiple differences
        assert!(!constant_time_eq(b"xxxxxx", b"abcdef"));
    }
}
