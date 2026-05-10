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

//! Node API surface for Autonomous Volition Credentials.
//!
//! Routes are merged into the gateway's axum router via the same
//! `serve_with_extra_routes` pattern used by governance, passport, and
//! provenance. Mutating endpoints (`POST`) inherit bearer-token auth
//! from the merged write guard; ordinary AVC denials return HTTP `200`
//! with `decision: Deny` rather than `403` so callers see structured
//! reason codes.
//!
//! ## Routes
//!
//! | Method | Path | Purpose |
//! |--------|------|---------|
//! | `POST` | `/api/v1/avc/issue` | Register a signed credential. |
//! | `POST` | `/api/v1/avc/validate` | Validate a credential and optional action. |
//! | `POST` | `/api/v1/avc/delegate` | Register a signed child credential. |
//! | `POST` | `/api/v1/avc/revoke` | Register a signed revocation. |
//! | `GET`  | `/api/v1/avc/:id` | Fetch a registered credential by hex ID. |
//! | `GET`  | `/api/v1/agents/:did/avcs` | List credentials for a subject DID. |
//!
//! ## State
//!
//! The handlers operate against a shared [`AvcApiState`] that wraps an
//! `InMemoryAvcRegistry` behind `Arc<Mutex<_>>`. All synchronous store
//! access is performed inside `tokio::task::spawn_blocking` so async
//! workers are not held under the registry lock.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_avc::{
    AutonomousVolitionCredential, AvcRegistryRead, AvcRegistryWrite, AvcRevocation,
    AvcValidationRequest, AvcValidationResult, InMemoryAvcRegistry, validate_avc,
};
use exo_core::{Did, Hash256};
use serde::{Deserialize, Serialize};
use tower::limit::ConcurrencyLimitLayer;

const MAX_AVC_API_BODY_BYTES: usize = 64 * 1024;
const MAX_AVC_API_CONCURRENT_REQUESTS: usize = 64;

/// Shared state for AVC route handlers.
#[derive(Clone)]
pub struct AvcApiState {
    pub registry: Arc<Mutex<InMemoryAvcRegistry>>,
}

impl AvcApiState {
    /// Wrap a fresh registry in the standard `Arc<Mutex<_>>` envelope.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
        }
    }
}

impl Default for AvcApiState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Request / Response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueRequest {
    pub credential: AutonomousVolitionCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueResponse {
    pub credential_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateRequest {
    pub child_credential: AutonomousVolitionCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateResponse {
    pub credential_id: String,
    pub parent_avc_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub revocation: AvcRevocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeResponse {
    pub credential_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvcSummary {
    pub credential_id: String,
    pub subject_did: String,
    pub issuer_did: String,
    pub principal_did: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAvcResponse {
    pub did: String,
    pub credentials: Vec<AvcSummary>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ApiError = (StatusCode, String);
type ApiResult<T> = Result<T, ApiError>;

fn parse_did(raw: &str) -> ApiResult<Did> {
    Did::new(raw).map_err(|err| {
        tracing::warn!(%err, "rejected malformed AVC DID");
        (StatusCode::BAD_REQUEST, "Invalid DID".into())
    })
}

fn parse_hash(raw: &str) -> ApiResult<Hash256> {
    let bytes = hex::decode(raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "credential id must be lowercase hex".into(),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "credential id must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(buf))
}

async fn with_registry_blocking<T, F>(state: Arc<AvcApiState>, op: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut InMemoryAvcRegistry) -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut guard = state.registry.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "AVC registry unavailable".into(),
            )
        })?;
        op(&mut guard)
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "AVC registry task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "AVC registry task failed".into(),
        )
    })?
}

fn map_avc_error(err: exo_avc::AvcError) -> ApiError {
    tracing::warn!(?err, "AVC operation rejected");
    match err {
        exo_avc::AvcError::EmptyField { .. }
        | exo_avc::AvcError::UnsupportedSchema { .. }
        | exo_avc::AvcError::BasisPointOutOfRange { .. }
        | exo_avc::AvcError::InvalidTimestamp { .. }
        | exo_avc::AvcError::DelegationWidens { .. }
        | exo_avc::AvcError::DelegationRejected { .. }
        | exo_avc::AvcError::InvalidInput { .. } => (StatusCode::BAD_REQUEST, err.to_string()),
        exo_avc::AvcError::Registry { .. } | exo_avc::AvcError::Serialization { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "AVC error".into())
        }
    }
}

fn summary_of(credential: &AutonomousVolitionCredential) -> ApiResult<AvcSummary> {
    let id = credential.id().map_err(map_avc_error)?;
    Ok(AvcSummary {
        credential_id: format!("{id}"),
        subject_did: credential.subject_did.to_string(),
        issuer_did: credential.issuer_did.to_string(),
        principal_did: credential.principal_did.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_issue(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<IssueRequest>,
) -> ApiResult<Json<IssueResponse>> {
    let credential = payload.credential;
    let id = with_registry_blocking(state, move |registry| {
        registry.put_credential(credential).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(IssueResponse {
        credential_id: format!("{id}"),
        status: "registered".into(),
    }))
}

async fn handle_validate(
    State(state): State<Arc<AvcApiState>>,
    Json(request): Json<AvcValidationRequest>,
) -> ApiResult<Json<AvcValidationResult>> {
    let result = with_registry_blocking(state, move |registry| {
        validate_avc(&request, registry).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(result))
}

async fn handle_delegate(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<DelegateRequest>,
) -> ApiResult<Json<DelegateResponse>> {
    let credential = payload.child_credential;
    let parent_avc_id = credential.parent_avc_id.map(|h| format!("{h}"));
    let id = with_registry_blocking(state, move |registry| {
        registry.put_credential(credential).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(DelegateResponse {
        credential_id: format!("{id}"),
        parent_avc_id,
        status: "registered".into(),
    }))
}

async fn handle_revoke(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<RevokeRequest>,
) -> ApiResult<Json<RevokeResponse>> {
    let revocation = payload.revocation;
    let id = revocation.credential_id;
    with_registry_blocking(state, move |registry| {
        registry.put_revocation(revocation).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(RevokeResponse {
        credential_id: format!("{id}"),
        status: "revoked".into(),
    }))
}

async fn handle_get(
    State(state): State<Arc<AvcApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<AutonomousVolitionCredential>> {
    let hash = parse_hash(&id)?;
    let credential = with_registry_blocking(state, move |registry| {
        registry
            .get_credential(&hash)
            .ok_or((StatusCode::NOT_FOUND, "credential not found".into()))
    })
    .await?;
    Ok(Json(credential))
}

async fn handle_list_for_subject(
    State(state): State<Arc<AvcApiState>>,
    Path(did_str): Path<String>,
) -> ApiResult<Json<ListAvcResponse>> {
    let did = parse_did(&did_str)?;
    let did_for_response = did.to_string();
    let did_for_lookup = did.clone();
    let credentials = with_registry_blocking(state, move |registry| {
        let creds = registry.list_credentials_for_subject(&did_for_lookup);
        let mut summaries = Vec::with_capacity(creds.len());
        for c in &creds {
            summaries.push(summary_of(c)?);
        }
        // Deterministic ordering by credential ID.
        summaries.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
        Ok(summaries)
    })
    .await?;
    Ok(Json(ListAvcResponse {
        did: did_for_response,
        credentials,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the AVC API router. POST routes inherit bearer-token auth
/// from the merged write guard in `main.rs`. Trust denials surface as
/// `200 OK` with `decision: Deny` rather than `403`.
pub fn avc_router(state: Arc<AvcApiState>) -> Router {
    Router::new()
        .route("/api/v1/avc/issue", post(handle_issue))
        .route("/api/v1/avc/validate", post(handle_validate))
        .route("/api/v1/avc/delegate", post(handle_delegate))
        .route("/api/v1/avc/revoke", post(handle_revoke))
        .route("/api/v1/avc/:id", get(handle_get))
        .route("/api/v1/agents/:did/avcs", get(handle_list_for_subject))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_AVC_API_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_AVC_API_CONCURRENT_REQUESTS))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::{
        body::{self, Body},
        http::{Method, Request},
    };
    use exo_authority::permission::Permission;
    use exo_avc::{
        AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel, AvcConstraints, AvcDecision, AvcDraft,
        AvcRevocationReason, AvcSubjectKind, DelegatedIntent, issue_avc, revoke_avc,
    };
    use exo_core::{Hash256, Signature, Timestamp, crypto::KeyPair};
    use tower::ServiceExt;

    use super::*;

    const ISSUER_SEED: [u8; 32] = [0x11; 32];

    fn issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ISSUER_SEED).expect("valid seed")
    }

    fn fresh_state() -> Arc<AvcApiState> {
        let state = AvcApiState::new();
        // Seed the issuer key so validate paths succeed.
        let kp = issuer_keypair();
        let did = Did::new("did:exo:issuer").unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_public_key(did, kp.public);
        Arc::new(state)
    }

    fn baseline_draft() -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: Did::new("did:exo:issuer").unwrap(),
            principal_did: Did::new("did:exo:issuer").unwrap(),
            subject_did: Did::new("did:exo:agent").unwrap(),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: None,
            },
            created_at: Timestamp::new(1_000_000, 0),
            expires_at: Some(Timestamp::new(2_000_000, 0)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([0xAA; 32]),
                purpose: "research".into(),
                allowed_objectives: vec!["primary".into()],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::Draft,
                delegation_allowed: false,
            },
            authority_scope: AuthorityScope {
                permissions: vec![Permission::Read],
                tools: vec![],
                data_classes: vec![],
                counterparties: vec![],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints::permissive(),
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        }
    }

    fn baseline_credential() -> AutonomousVolitionCredential {
        let kp = issuer_keypair();
        issue_avc(baseline_draft(), |bytes| kp.sign(bytes)).unwrap()
    }

    async fn read_body(response: axum::response::Response) -> Vec<u8> {
        body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn issue_registers_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let cred_id = credential.id().unwrap();
        let body = serde_json::to_vec(&IssueRequest { credential }).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_bytes = read_body(response).await;
        let parsed: IssueResponse = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(parsed.credential_id, format!("{cred_id}"));
        assert_eq!(parsed.status, "registered");
    }

    #[tokio::test]
    async fn validate_returns_allow_for_valid_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_bytes = read_body(response).await;
        let parsed: AvcValidationResult = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(parsed.decision, AvcDecision::Allow);
    }

    #[tokio::test]
    async fn validate_returns_200_with_deny_for_revoked() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        // Pre-register and revoke.
        {
            let kp = issuer_keypair();
            let mut reg = state.registry.lock().unwrap();
            reg.put_credential(credential.clone()).unwrap();
            let revocation = revoke_avc(
                id,
                Did::new("did:exo:issuer").unwrap(),
                AvcRevocationReason::IssuerRevoked,
                Timestamp::new(2, 0),
                |bytes| kp.sign(bytes),
            )
            .unwrap();
            reg.put_revocation(revocation).unwrap();
        }
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: AvcValidationResult =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.decision, AvcDecision::Deny);
    }

    #[tokio::test]
    async fn revoke_marks_credential_revoked() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        // Pre-register so we can revoke.
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential)
            .unwrap();
        let kp = issuer_keypair();
        let revocation = revoke_avc(
            id,
            Did::new("did:exo:issuer").unwrap(),
            AvcRevocationReason::IssuerRevoked,
            Timestamp::new(2, 0),
            |bytes| kp.sign(bytes),
        )
        .unwrap();
        let body = serde_json::to_vec(&RevokeRequest { revocation }).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.registry.lock().unwrap().is_revoked(&id));
    }

    #[tokio::test]
    async fn revoke_rejects_unsigned_revocation_without_marking_credential_revoked() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential)
            .unwrap();
        let kp = issuer_keypair();
        let mut revocation = revoke_avc(
            id,
            Did::new("did:exo:issuer").unwrap(),
            AvcRevocationReason::IssuerRevoked,
            Timestamp::new(2, 0),
            |bytes| kp.sign(bytes),
        )
        .unwrap();
        revocation.signature = Signature::empty();

        let body = serde_json::to_vec(&RevokeRequest { revocation }).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !state.registry.lock().unwrap().is_revoked(&id),
            "unsigned revocation must not create a tombstone"
        );
    }

    #[tokio::test]
    async fn get_returns_404_when_unknown() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/{}", "11".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_returns_credential_when_known() {
        let state = fresh_state();
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: AutonomousVolitionCredential =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed, credential);
    }

    #[tokio::test]
    async fn get_returns_400_for_bad_hex() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_returns_400_for_invalid_did() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/agents/not-a-did/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_returns_credentials_for_subject() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/agents/did:exo:agent/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: ListAvcResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.did, "did:exo:agent");
        assert_eq!(parsed.credentials.len(), 1);
    }

    #[test]
    fn router_uses_blocking_store_access() {
        let source = include_str!("avc.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "AVC handlers must isolate synchronous registry access from Tokio workers"
        );
        assert!(
            production.contains("DefaultBodyLimit::max(MAX_AVC_API_BODY_BYTES)"),
            "AVC router must cap request body size locally"
        );
        assert!(
            production.contains("ConcurrencyLimitLayer::new(MAX_AVC_API_CONCURRENT_REQUESTS)"),
            "AVC router must apply local request admission control"
        );
    }
}
