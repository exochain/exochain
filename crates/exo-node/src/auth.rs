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

//! Node API authentication — bearer-token guard for write operations.
//!
//! On startup the node generates a random 256-bit admin token, persists it to
//! a restrictive local file, and never writes token material to logs. Every
//! mutating endpoint requires this token in the `Authorization:
//! Bearer <token>` header unless the route has a stricter local verifier.
//! Public status and dashboard reads remain unauthenticated, while trust-object
//! reads that disclose receipts, provenance, economy records, or credentials
//! also require the bearer token. Exact 0dentity signed-write routes pass
//! through so their handlers can verify DID-scoped session tokens and request
//! signatures. The LiveSafe public adapter-output authorization route may also
//! accept its own scoped bearer token; that token is bound to the exact public
//! output route and is never accepted for other mutating or sensitive routes.

use std::{
    io::{ErrorKind, Write},
    path::Path,
    sync::Arc,
};

use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use zeroize::{Zeroize, Zeroizing};

pub const LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ROUTE: &str =
    "/api/v1/avc/livesafe/public-adapter-output-authorization";

/// Shared bearer token state for the auth middleware.
#[derive(Clone)]
pub struct BearerAuth {
    /// The expected bearer token (hex-encoded 256-bit random value).
    pub token: Arc<Zeroizing<String>>,
}

/// Optional route-scoped bearer tokens that never inherit admin authority.
#[derive(Clone, Default)]
pub struct ScopedBearerAuth {
    livesafe_public_adapter_output_authorization: Option<Arc<Zeroizing<String>>>,
}

impl ScopedBearerAuth {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn livesafe_public_adapter_output_authorization(token: Zeroizing<String>) -> Self {
        Self {
            livesafe_public_adapter_output_authorization: Some(Arc::new(token)),
        }
    }

    pub fn livesafe_public_adapter_output_authorization_configured(&self) -> bool {
        self.livesafe_public_adapter_output_authorization
            .as_ref()
            .is_some()
    }
}

/// Generate a cryptographically random admin token (hex-encoded 32 bytes).
///
/// # Errors
///
/// Returns the OS entropy error if secure random bytes cannot be obtained.
pub fn generate_admin_token() -> Result<Zeroizing<String>, getrandom::Error> {
    generate_admin_token_with_entropy(|bytes| getrandom::getrandom(bytes))
}

fn generate_admin_token_with_entropy<E, F>(fill_entropy: F) -> Result<Zeroizing<String>, E>
where
    F: FnOnce(&mut [u8; 32]) -> Result<(), E>,
{
    let mut bytes = [0u8; 32];
    fill_entropy(&mut bytes)?;
    let token = Zeroizing::new(hex::encode(bytes));
    bytes.zeroize();
    Ok(token)
}

/// Persist an admin token with restrictive file permissions from creation.
///
/// The temporary file is created with `create_new`, and on Unix the `0600` mode
/// is applied atomically during open rather than by chmod after plaintext has
/// already hit the filesystem. The final rename preserves restart behavior by
/// replacing any prior token file.
pub fn write_admin_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    let tmp_path = path.with_extension("tmp");
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
    }

    if let Err(error) = std::fs::rename(&tmp_path, path) {
        return match std::fs::remove_file(&tmp_path) {
            Ok(()) => Err(error),
            Err(cleanup_error) if cleanup_error.kind() == ErrorKind::NotFound => Err(error),
            Err(cleanup_error) => Err(std::io::Error::new(
                cleanup_error.kind(),
                format!(
                    "failed to remove temporary admin token file {} after rename failure: {cleanup_error}; rename failure: {error}",
                    tmp_path.display()
                ),
            )),
        };
    }

    Ok(())
}

fn bearer_header_value(headers: &HeaderMap) -> Result<&str, StatusCode> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match header {
        Some(value) if value.starts_with("Bearer ") => Ok(&value["Bearer ".len()..]),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn verify_bearer_header(headers: &HeaderMap, auth: &BearerAuth) -> Result<(), StatusCode> {
    let provided = bearer_header_value(headers)?;
    if constant_time_eq(provided.as_bytes(), auth.token.as_bytes()) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn verify_admin_or_livesafe_public_output_bearer(
    headers: &HeaderMap,
    auth: &BearerAuth,
    scoped_auth: &ScopedBearerAuth,
) -> Result<(), StatusCode> {
    let provided = bearer_header_value(headers)?;
    if constant_time_eq(provided.as_bytes(), auth.token.as_bytes()) {
        return Ok(());
    }

    if let Some(token) = &scoped_auth.livesafe_public_adapter_output_authorization {
        if constant_time_eq(provided.as_bytes(), token.as_bytes()) {
            return Ok(());
        }
    }

    Err(StatusCode::FORBIDDEN)
}

/// axum middleware: require bearer token on every request.
pub async fn require_bearer(
    auth: BearerAuth,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    verify_bearer_header(request.headers(), &auth)?;
    Ok(next.run(request).await)
}

fn is_sensitive_read_path(path: &str) -> bool {
    path == "/api/v1/receipts"
        || path.starts_with("/api/v1/receipts/")
        || path.starts_with("/api/v1/provenance/")
        || path.starts_with("/api/v1/avc/")
        || path == "/api/v1/challenges"
        || path.starts_with("/api/v1/challenges/")
        || path == "/exoforge"
        || path.starts_with("/api/v1/forge/")
        || (path.starts_with("/api/v1/economy/") && path != "/api/v1/economy/policy/active")
        || (path.starts_with("/api/v1/agents/") && path.ends_with("/avcs"))
}

fn is_zerodentity_local_signed_write(method: &axum::http::Method, path: &str) -> bool {
    const PREFIX: &str = "/api/v1/0dentity/";

    let Some(rest) = path.strip_prefix(PREFIX) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }

    let mut segments = rest.split('/');
    let Some(did_segment) = segments.next() else {
        return false;
    };
    if did_segment.is_empty() {
        return false;
    }

    if method == axum::http::Method::POST {
        return matches!((segments.next(), segments.next()), (Some("attest"), None));
    }

    method == axum::http::Method::DELETE && segments.next().is_none()
}

/// Route-shape check for the AVC subject-signed receipt-emission write
/// (VCG-006a / #737).
///
/// This only recognizes exact AVC subject-signed receipt emission routes by
/// method and path — mirroring `is_zerodentity_local_signed_write`'s
/// route-shape style. It makes no claim about authority; it just identifies
/// which routes may be eligible for the carve-out in
/// `require_bearer_on_writes`, which independently confirms a genuine
/// (non-empty) subject signature is present before admitting the request.
fn is_avc_receipts_emit_route(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::POST
        && matches!(
            path,
            "/api/v1/avc/receipts/emit" | "/api/v1/avc/llm-usage/receipts/emit"
        )
}

fn is_livesafe_public_adapter_output_authorization_route(
    method: &axum::http::Method,
    path: &str,
) -> bool {
    method == axum::http::Method::POST && path == LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ROUTE
}

/// Maximum body size read while peeking for a subject signature on the AVC
/// receipt-emission carve-out. Matches the AVC router's own request body cap
/// (`MAX_AVC_API_BODY_BYTES` in `avc.rs`) so this check never admits a body
/// the downstream router would have rejected anyway.
const AVC_EMIT_RECEIPT_CARVE_OUT_MAX_BODY_BYTES: usize = 64 * 1024;

/// Determine whether an AVC subject-signed receipt-emission request carries a
/// genuine (non-empty) subject signature, without weakening the real
/// authority check.
///
/// This buffers the request body (bounded to
/// `AVC_EMIT_RECEIPT_CARVE_OUT_MAX_BODY_BYTES`) and parses it as
/// the route-specific request DTO, reusing the exact same type and
/// `Signature::is_empty()` predicate the handlers and
/// `verify_subject_action_signature` use — no duplicated signature-shape
/// logic. It reconstructs an equivalent request from the buffered bytes so
/// the downstream handler still receives the original body.
///
/// This function never performs cryptographic signature verification —
/// that remains exclusively `verify_subject_action_signature` inside
/// the AVC emit handlers. A body that merely contains a non-empty signature
/// field is let through to the handler, which is the actual authority gate
/// and can still reject an invalid signature. A body with no signature
/// (empty, missing, or unparseable) is never let through — this carve-out
/// must never open an unauthenticated hole.
async fn avc_emit_receipt_carve_out(request: Request<Body>) -> (Request<Body>, bool) {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let bytes = match axum::body::to_bytes(body, AVC_EMIT_RECEIPT_CARVE_OUT_MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Body could not be buffered (too large or a read error).
            // Reconstruct an empty-bodied request and fall through to the
            // bearer-token check — never admit on a body we could not
            // inspect.
            return (Request::from_parts(parts, Body::empty()), false);
        }
    };

    let has_subject_signature = match path.as_str() {
        "/api/v1/avc/receipts/emit" => {
            serde_json::from_slice::<crate::avc::EmitReceiptRequest>(&bytes)
                .is_ok_and(|parsed| !parsed.subject_signature.is_empty())
        }
        "/api/v1/avc/llm-usage/receipts/emit" => {
            serde_json::from_slice::<crate::avc::LlmUsageReceiptEmitRequest>(&bytes)
                .is_ok_and(|parsed| !parsed.subject_signature.is_empty())
        }
        _ => false,
    };

    let rebuilt = Request::from_parts(parts, Body::from(bytes));
    (rebuilt, has_subject_signature)
}

/// axum middleware: require bearer token on mutating requests and sensitive
/// trust-object reads.
///
/// Public `GET` and `HEAD` requests pass through without authentication unless
/// they target receipts, provenance, AVCs, challenge holds, economy trust
/// objects, ExoForge build-orchestration state, or agent credential listings.
/// The active economy policy remains public. All other methods (`POST`, `PUT`,
/// `DELETE`, `PATCH`) require
/// `Authorization: Bearer <token>` unless they are exact 0dentity signed-write
/// routes whose handlers perform identity-session and request-signature
/// checks, or the exact AVC `/receipts/emit` route carrying a genuine
/// (non-empty) subject signature, whose handler verifies that signature
/// cryptographically.
pub async fn require_bearer_on_writes(
    auth: BearerAuth,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    require_bearer_on_writes_with_scoped_bearers(auth, ScopedBearerAuth::none(), request, next)
        .await
}

pub async fn require_bearer_on_writes_with_scoped_bearers(
    auth: BearerAuth,
    scoped_auth: ScopedBearerAuth,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let is_public_read = (method == axum::http::Method::GET || method == axum::http::Method::HEAD)
        && !is_sensitive_read_path(&path);
    if is_public_read || is_zerodentity_local_signed_write(&method, &path) {
        return Ok(next.run(request).await);
    }

    if is_livesafe_public_adapter_output_authorization_route(&method, &path) {
        verify_admin_or_livesafe_public_output_bearer(request.headers(), &auth, &scoped_auth)?;
        return Ok(next.run(request).await);
    }

    if is_avc_receipts_emit_route(&method, &path) {
        let (request, has_subject_signature) = avc_emit_receipt_carve_out(request).await;
        if has_subject_signature {
            return Ok(next.run(request).await);
        }
        verify_bearer_header(request.headers(), &auth)?;
        return Ok(next.run(request).await);
    }

    verify_bearer_header(request.headers(), &auth)?;
    Ok(next.run(request).await)
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
        routing::{delete, get, post},
    };
    use tower::ServiceExt;

    use super::*;

    fn test_auth() -> BearerAuth {
        BearerAuth {
            token: Arc::new(Zeroizing::new("test-token-abc123".to_string())),
        }
    }

    fn test_app() -> Router {
        let auth = test_auth();
        Router::new()
            .route("/read", get(|| async { "ok" }))
            .route("/api/v1/receipts/:hash", get(|| async { "receipt" }))
            .route("/api/v1/receipts", get(|| async { "receipts" }))
            .route("/api/v1/provenance/:hash", get(|| async { "provenance" }))
            .route("/api/v1/avc/:id", get(|| async { "credential" }))
            .route("/api/v1/agents/:did/avcs", get(|| async { "credentials" }))
            .route("/api/v1/challenges", get(|| async { "challenges" }))
            .route("/api/v1/challenges/:id", get(|| async { "challenge" }))
            .route("/exoforge", get(|| async { "forge dashboard" }))
            .route("/api/v1/forge/tasks", get(|| async { "forge tasks" }))
            .route("/api/v1/forge/stats", get(|| async { "forge stats" }))
            .route("/api/v1/forge/activity", get(|| async { "forge activity" }))
            .route(
                "/api/v1/economy/bailment-terms/:id",
                get(|| async { "bailment terms" }),
            )
            .route(
                "/api/v1/economy/policy/active",
                get(|| async { "active policy" }),
            )
            .route(
                "/api/v1/0dentity/:did/attest",
                post(|| async { "signed-attest" }),
            )
            .route(
                "/api/v1/0dentity/:did",
                delete(|| async { "signed-delete" }),
            )
            .route(
                "/api/v1/0dentity/:did/score",
                post(|| async { "unexpected-write" }),
            )
            .route("/write", post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let a = auth.clone();
                require_bearer_on_writes(a, req, next)
            }))
    }

    fn livesafe_public_output_scoped_bearer_test_app(scoped_bearer: Option<&str>) -> Router {
        let auth = test_auth();
        let scoped_auth = scoped_bearer
            .map(|token| {
                ScopedBearerAuth::livesafe_public_adapter_output_authorization(Zeroizing::new(
                    token.to_owned(),
                ))
            })
            .unwrap_or_else(ScopedBearerAuth::none);
        Router::new()
            .route(
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ROUTE,
                post(|| async { "public-output" }),
            )
            .route("/api/v1/avc/issue", post(|| async { "issue" }))
            .route("/api/v1/receipts/:hash", get(|| async { "receipt" }))
            .layer(middleware::from_fn(move |req, next| {
                let a = auth.clone();
                let scoped = scoped_auth.clone();
                require_bearer_on_writes_with_scoped_bearers(a, scoped, req, next)
            }))
    }

    fn strict_test_app() -> Router {
        let auth = test_auth();
        Router::new()
            .route("/read", get(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let a = auth.clone();
                require_bearer(a, req, next)
            }))
    }

    #[tokio::test]
    async fn strict_get_without_token_rejected() {
        let app = strict_test_app();
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn strict_get_with_correct_token_passes() {
        let app = strict_test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/read")
                    .header("authorization", "Bearer test-token-abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn livesafe_public_output_scoped_bearer_accepts_exact_public_output_route_when_configured()
     {
        let app = livesafe_public_output_scoped_bearer_test_app(Some(
            "livesafe-public-output-scoped-token",
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/avc/livesafe/public-adapter-output-authorization")
                    .header(
                        "Authorization",
                        "Bearer livesafe-public-output-scoped-token",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn livesafe_public_output_scoped_bearer_does_not_authorize_avc_issue() {
        let app = livesafe_public_output_scoped_bearer_test_app(Some(
            "livesafe-public-output-scoped-token",
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/avc/issue")
                    .header(
                        "Authorization",
                        "Bearer livesafe-public-output-scoped-token",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn livesafe_public_output_scoped_bearer_does_not_authorize_sensitive_receipt_read() {
        let app = livesafe_public_output_scoped_bearer_test_app(Some(
            "livesafe-public-output-scoped-token",
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/receipts/0000000000000000000000000000000000000000000000000000000000000000")
                    .header(
                        "Authorization",
                        "Bearer livesafe-public-output-scoped-token",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn livesafe_public_output_scoped_bearer_rejects_wrong_token_on_exact_route() {
        let app = livesafe_public_output_scoped_bearer_test_app(Some(
            "livesafe-public-output-scoped-token",
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/avc/livesafe/public-adapter-output-authorization")
                    .header("Authorization", "Bearer wrong-livesafe-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn livesafe_public_output_scoped_bearer_absent_preserves_admin_only_behavior() {
        let admin_app = livesafe_public_output_scoped_bearer_test_app(None);
        let admin_resp = admin_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/avc/livesafe/public-adapter-output-authorization")
                    .header("Authorization", "Bearer test-token-abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_resp.status(), StatusCode::OK);

        let scoped_app = livesafe_public_output_scoped_bearer_test_app(None);
        let scoped_resp = scoped_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/avc/livesafe/public-adapter-output-authorization")
                    .header(
                        "Authorization",
                        "Bearer livesafe-public-output-scoped-token",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scoped_resp.status(), StatusCode::FORBIDDEN);
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
    async fn receipt_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/receipts/0000000000000000000000000000000000000000000000000000000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn receipt_list_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/receipts?actor=did:exo:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn provenance_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/provenance/0000000000000000000000000000000000000000000000000000000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn avc_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/avc/0000000000000000000000000000000000000000000000000000000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn agent_avc_list_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/agents/did:exo:alice/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn challenge_list_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/challenges")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn challenge_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/challenges/00000000-0000-0000-0000-000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exoforge_dashboard_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/exoforge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exoforge_tasks_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/forge/tasks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exoforge_stats_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/forge/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exoforge_activity_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/forge/activity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn exoforge_read_get_with_correct_token_passes() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/forge/tasks")
                    .header("authorization", "Bearer test-token-abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn sensitive_read_paths_include_exoforge_surfaces() {
        assert!(is_sensitive_read_path("/exoforge"));
        assert!(is_sensitive_read_path("/api/v1/forge/tasks"));
        assert!(is_sensitive_read_path("/api/v1/forge/stats"));
        assert!(is_sensitive_read_path("/api/v1/forge/activity"));
    }

    #[tokio::test]
    async fn economy_trust_object_get_without_token_rejected() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/economy/bailment-terms/0000000000000000000000000000000000000000000000000000000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn economy_active_policy_get_without_token_passes() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/economy/policy/active")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sensitive_get_with_correct_token_passes() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/provenance/0000000000000000000000000000000000000000000000000000000000000000")
                    .header("Authorization", "Bearer test-token-abc123")
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
    async fn zerodentity_attest_post_with_identity_session_bearer_reaches_local_signed_verifier() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/0dentity/did:exo:alice/attest")
                    .header("Authorization", "Bearer identity-session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn zerodentity_delete_with_identity_session_bearer_reaches_local_signed_verifier() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/0dentity/did:exo:alice")
                    .header("Authorization", "Bearer identity-session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_zerodentity_write_still_requires_admin_bearer() {
        let app = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/0dentity/did:exo:alice/score")
                    .header("Authorization", "Bearer identity-session-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn token_generation_is_unique() {
        let t1 = generate_admin_token().expect("admin token generation");
        let t2 = generate_admin_token().expect("admin token generation");
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn token_generation_propagates_entropy_failure_without_panic() {
        let err = generate_admin_token_with_entropy(|_| Err("entropy unavailable"))
            .expect_err("entropy failure must propagate");

        assert_eq!(err, "entropy unavailable");
    }

    #[test]
    fn admin_token_writer_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin_token");

        std::fs::write(&path, "old-token").unwrap();
        write_admin_token_file(&path, "new-token").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-token");
        assert!(!path.with_extension("tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn admin_token_writer_creates_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin_token");

        write_admin_token_file(&path, "secret-token").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret-token");
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

    #[test]
    fn production_source_uses_zeroizing_admin_token_storage() {
        let source = include_str!("auth.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("Zeroizing<String>"),
            "bearer admin token must be stored in zeroize-on-drop storage"
        );
        assert!(
            !production.contains("Arc<String>"),
            "bearer admin token must not be held in a plain Arc<String>"
        );
        assert!(
            production.contains("bytes.zeroize()"),
            "raw random token bytes must be wiped after hex encoding"
        );
        assert!(
            !production.contains("expect(\"OS entropy source unavailable\")"),
            "admin token generation must propagate entropy failures instead of panicking"
        );
        assert!(
            production.contains(
                "pub fn generate_admin_token() -> Result<Zeroizing<String>, getrandom::Error>"
            ),
            "admin token generation must return a typed entropy error"
        );
        assert!(
            !production.contains("let _ = std::fs::remove_file(&tmp_path)"),
            "temporary admin token cleanup failures must propagate"
        );
    }

    #[test]
    fn main_persists_admin_token_through_restrictive_auth_writer() {
        let source = include_str!("main.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("auth::write_admin_token_file"),
            "startup must persist admin tokens through the restrictive auth writer"
        );
        assert!(
            !production.contains("std::fs::write(&token_path, &admin_token)"),
            "startup must not write the admin token before restrictive permissions are set"
        );
    }

    #[test]
    fn startup_does_not_log_admin_token_material() {
        let main_source = include_str!("main.rs");
        let main_production = main_source
            .split("#[cfg(test)]")
            .next()
            .expect("tests marker present");
        let auth_source = include_str!("auth.rs");
        let auth_production = auth_source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            !main_production.contains("token_prefix"),
            "startup logs must not include even partial admin bearer token material"
        );
        assert!(
            !main_production.contains("admin_token.chars().take"),
            "startup must not derive loggable substrings from the admin bearer token"
        );
        assert!(
            !auth_production.contains("displayed once"),
            "auth documentation must not normalize logging bearer-token material"
        );
    }

    #[test]
    fn livesafe_public_output_scoped_bearer_startup_guard_wires_env_without_logging_material() {
        let main_source = include_str!("main.rs");
        let main_production = main_source
            .split("#[cfg(test)]")
            .next()
            .expect("tests marker present");
        let auth_source = include_str!("auth.rs");
        let auth_production = auth_source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            main_production
                .contains("EXOCHAIN_LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER"),
            "startup must read the scoped LiveSafe public-output bearer env var"
        );
        assert!(
            auth_production.contains("/api/v1/avc/livesafe/public-adapter-output-authorization"),
            "auth middleware must bind the scoped bearer to the exact public-output route"
        );
        assert!(
            !main_production.contains("livesafe-public-output-scoped-token"),
            "startup source must not embed scoped bearer material"
        );
        assert!(
            !auth_production.contains("livesafe-public-output-scoped-token"),
            "auth source must not embed scoped bearer material"
        );
        assert!(
            !main_production.contains("scoped_token.chars().take"),
            "startup logs must not include even partial scoped bearer token material"
        );
    }
}
