//! Challenge/dispute API — runtime-accessible Sybil challenge endpoints.
//!
//! Exposes the `exo-escalation` challenge system as HTTP endpoints so that
//! any participant can file a challenge, query active holds, and inspect
//! audit trails at runtime.
//!
//! ## Endpoints
//!
//! - `GET  /api/v1/challenges`        — list all challenge holds
//! - `GET  /api/v1/challenges/:id`    — get a single challenge by UUID
//! - `POST /api/v1/challenges`        — file a new Sybil challenge
//! - `POST /api/v1/challenges/:id/review` — advance to under-review
//! - `POST /api/v1/challenges/:id/resolve` — resolve a challenge
//! - `POST /api/v1/challenges/:id/dismiss` — dismiss a challenge

#![allow(clippy::needless_borrows_for_generic_args)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_core::types::Timestamp;
use exo_escalation::challenge::{self, ContestHold, SignedChallengeAdmission};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// In-memory challenge store.
///
/// Challenges are stored in memory and backed by the append-only audit log
/// on each `ContestHold`.  A durable SQLite table would be the production
/// next step — the in-memory store is sufficient for tier-one runtime
/// exposure.
#[derive(Debug, Default, Clone)]
pub struct ChallengeStore {
    holds: BTreeMap<Uuid, ContestHold>,
}

impl ChallengeStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            holds: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, hold: ContestHold) {
        self.holds.insert(hold.id, hold);
    }

    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<&ContestHold> {
        self.holds.get(id)
    }

    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut ContestHold> {
        self.holds.get_mut(id)
    }

    #[must_use]
    pub fn list(&self) -> Vec<&ContestHold> {
        self.holds.values().collect()
    }
}

/// Shared state for challenge endpoints.
pub type SharedChallengeStore = Arc<Mutex<ChallengeStore>>;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Response representing a challenge hold.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub id: String,
    pub action_id: String,
    pub ground: String,
    pub status: String,
    pub admitted_at_ms: u64,
    pub admitted_by: String,
    pub evidence_hash: String,
    pub authority_chain_hash: String,
    pub admission_signature_algorithm: String,
    pub audit_log: Vec<String>,
}

impl From<&ContestHold> for ChallengeResponse {
    fn from(hold: &ContestHold) -> Self {
        Self {
            id: hold.id.to_string(),
            action_id: hex::encode(hold.action_id),
            ground: hold.ground.to_string(),
            status: format!("{:?}", hold.status),
            admitted_at_ms: hold.admitted_at.physical_ms,
            admitted_by: hold.admitted_by.to_string(),
            evidence_hash: hex::encode(hold.evidence_hash),
            authority_chain_hash: hex::encode(hold.authority_chain_hash),
            admission_signature_algorithm: hold.admission_signature.algorithm().to_string(),
            audit_log: hold.audit_log.clone(),
        }
    }
}

/// Request body for beginning review.
#[derive(Debug, Deserialize)]
pub struct ReviewChallengeRequest {
    pub at: Timestamp,
}

/// Request body for resolving a challenge.
#[derive(Debug, Deserialize)]
pub struct ResolveChallengeRequest {
    pub at: Timestamp,
    pub outcome: String,
}

/// Request body for dismissing a challenge.
#[derive(Debug, Deserialize)]
pub struct DismissChallengeRequest {
    pub at: Timestamp,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/challenges` — list all challenge holds.
async fn handle_list(
    State(store): State<SharedChallengeStore>,
) -> Result<Json<Vec<ChallengeResponse>>, (StatusCode, String)> {
    let st = store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge store unavailable".to_string(),
        )
    })?;
    Ok(Json(
        st.list()
            .iter()
            .map(|h| ChallengeResponse::from(*h))
            .collect(),
    ))
}

/// `GET /api/v1/challenges/:id` — get a single challenge.
async fn handle_get(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;
    let st = store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge store unavailable".to_string(),
        )
    })?;
    match st.get(&id) {
        Some(hold) => Ok(Json(ChallengeResponse::from(hold))),
        None => Err((StatusCode::NOT_FOUND, "challenge not found".into())),
    }
}

/// `POST /api/v1/challenges` — file a new Sybil challenge.
async fn handle_file(
    State(store): State<SharedChallengeStore>,
    Json(req): Json<SignedChallengeAdmission>,
) -> Result<(StatusCode, Json<ChallengeResponse>), (StatusCode, String)> {
    let hold =
        challenge::admit_challenge(req).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let resp = ChallengeResponse::from(&hold);

    {
        let mut st = store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Challenge store unavailable".to_string(),
            )
        })?;
        st.insert(hold);
    }

    Ok((StatusCode::CREATED, Json(resp)))
}

/// `POST /api/v1/challenges/:id/review` — begin review.
async fn handle_begin_review(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
    Json(req): Json<ReviewChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;

    let mut st = store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge store unavailable".to_string(),
        )
    })?;
    let hold = st
        .get_mut(&id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;

    challenge::begin_review(hold, req.at).map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    Ok(Json(ChallengeResponse::from(&*hold)))
}

/// `POST /api/v1/challenges/:id/resolve` — resolve a challenge.
async fn handle_resolve(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
    Json(req): Json<ResolveChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;

    let mut st = store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge store unavailable".to_string(),
        )
    })?;
    let hold = st
        .get_mut(&id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;

    challenge::resolve_hold(hold, req.at, &req.outcome)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    Ok(Json(ChallengeResponse::from(&*hold)))
}

/// `POST /api/v1/challenges/:id/dismiss` — dismiss a challenge.
async fn handle_dismiss(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
    Json(req): Json<DismissChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;

    let mut st = store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge store unavailable".to_string(),
        )
    })?;
    let hold = st
        .get_mut(&id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;

    challenge::dismiss_hold(hold, req.at, &req.reason)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    Ok(Json(ChallengeResponse::from(&*hold)))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the challenge API router.
pub fn challenge_router(store: SharedChallengeStore) -> Router {
    Router::new()
        .route("/api/v1/challenges", get(handle_list))
        .route("/api/v1/challenges", post(handle_file))
        .route("/api/v1/challenges/:id", get(handle_get))
        .route("/api/v1/challenges/:id/review", post(handle_begin_review))
        .route("/api/v1/challenges/:id/resolve", post(handle_resolve))
        .route("/api/v1/challenges/:id/dismiss", post(handle_dismiss))
        .with_state(store)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::{body::Body, http::Request};
    use exo_core::{Did, Signature};
    use exo_escalation::challenge::{
        ChallengeAdmission, SybilChallengeGround, sign_challenge_admission,
    };
    use tower::ServiceExt;

    use super::*;

    fn test_store() -> SharedChallengeStore {
        Arc::new(Mutex::new(ChallengeStore::new()))
    }

    fn action_id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn did(s: &str) -> Did {
        Did::new(s).unwrap()
    }

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn keypair(seed: u8) -> exo_core::crypto::KeyPair {
        exo_core::crypto::KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }

    fn signed_challenge(
        hold_marker: u8,
        action_id: [u8; 32],
        ground: SybilChallengeGround,
        admitted_at: Timestamp,
    ) -> SignedChallengeAdmission {
        let keypair = keypair(7);
        sign_challenge_admission(
            ChallengeAdmission {
                hold_id: uuid(hold_marker),
                action_id,
                ground,
                admitted_at,
                admitted_by: did("did:exo:reviewer"),
                admitter_public_key: *keypair.public_key(),
                evidence_hash: [0xEEu8; 32],
                authority_chain_hash: [0xACu8; 32],
            },
            keypair.secret_key(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn list_empty() {
        let store = test_store();
        let app = challenge_router(store);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/challenges")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let results: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn file_and_retrieve_challenge() {
        let store = test_store();
        let app = challenge_router(Arc::clone(&store));

        let body = signed_challenge(
            1,
            action_id(7),
            SybilChallengeGround::QuorumContamination,
            ts(1000),
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: ChallengeResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result.ground, "QuorumContamination");
        assert_eq!(result.status, "PauseEligible");
        assert_eq!(result.id, uuid(1).to_string());
        assert_eq!(result.admitted_by, "did:exo:reviewer");
        assert_eq!(result.admission_signature_algorithm, "Ed25519");
        assert!(!result.audit_log.is_empty());

        // Retrieve it by ID.
        let app2 = challenge_router(Arc::clone(&store));
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/challenges/{}", result.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn full_lifecycle() {
        let store = test_store();

        // File challenge.
        let hold = challenge::admit_challenge(signed_challenge(
            2,
            action_id(1),
            SybilChallengeGround::ConcealedCommonControl,
            ts(1000),
        ))
        .unwrap();
        let hold_id = hold.id;
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        // Begin review.
        let app = challenge_router(Arc::clone(&store));
        let review_body = serde_json::json!({ "at": ts(1100) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/challenges/{hold_id}/review"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&review_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: ChallengeResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(result.status, "UnderReview");

        // Resolve.
        let app2 = challenge_router(Arc::clone(&store));
        let resolve_body = serde_json::json!({ "at": ts(1200), "outcome": "challenge sustained" });
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/challenges/{hold_id}/resolve"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&resolve_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();
        let result2: ChallengeResponse = serde_json::from_slice(&body2).unwrap();
        assert_eq!(result2.status, "Resolved");
        assert_eq!(result2.audit_log.len(), 3);
    }

    #[tokio::test]
    async fn dismiss_challenge() {
        let store = test_store();
        let hold = challenge::admit_challenge(signed_challenge(
            3,
            action_id(2),
            SybilChallengeGround::SyntheticHumanMisrepresentation,
            ts(500),
        ))
        .unwrap();
        let hold_id = hold.id;
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        let app = challenge_router(Arc::clone(&store));
        let body = serde_json::json!({ "at": ts(600), "reason": "insufficient evidence" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/challenges/{hold_id}/dismiss"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: ChallengeResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result.status, "Dismissed");
    }

    #[tokio::test]
    async fn invalid_signature_rejected() {
        let store = test_store();
        let app = challenge_router(store);

        let mut body = signed_challenge(
            4,
            action_id(7),
            SybilChallengeGround::QuorumContamination,
            ts(1000),
        );
        body.admission_signature = Signature::Ed25519([0xABu8; 64]);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_404() {
        let store = test_store();
        let app = challenge_router(store);
        let fake_id = uuid(0xFE);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/challenges/{fake_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn resolve_already_resolved_conflicts() {
        let store = test_store();
        let mut hold = challenge::admit_challenge(signed_challenge(
            5,
            action_id(3),
            SybilChallengeGround::CoordinatedManipulation,
            ts(100),
        ))
        .unwrap();
        let hold_id = hold.id;
        challenge::resolve_hold(&mut hold, ts(200), "done").unwrap();
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        let app = challenge_router(store);
        let body = serde_json::json!({ "at": ts(300), "outcome": "again" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/challenges/{hold_id}/resolve"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
