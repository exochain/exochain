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
use exo_escalation::challenge::{self, ContestHold, SybilChallengeGround};
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
            audit_log: hold.audit_log.clone(),
        }
    }
}

/// Request body for filing a new challenge.
#[derive(Debug, Deserialize)]
pub struct FileChallengeRequest {
    /// Hex-encoded 32-byte action identifier being challenged.
    pub action_id_hex: String,
    /// Challenge ground: one of "ConcealedCommonControl",
    /// "CoordinatedManipulation", "QuorumContamination",
    /// "SyntheticHumanMisrepresentation".
    pub ground: String,
}

/// Request body for resolving a challenge.
#[derive(Debug, Deserialize)]
pub struct ResolveChallengeRequest {
    pub outcome: String,
}

/// Request body for dismissing a challenge.
#[derive(Debug, Deserialize)]
pub struct DismissChallengeRequest {
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn parse_ground(s: &str) -> Result<SybilChallengeGround, String> {
    match s {
        "ConcealedCommonControl" => Ok(SybilChallengeGround::ConcealedCommonControl),
        "CoordinatedManipulation" => Ok(SybilChallengeGround::CoordinatedManipulation),
        "QuorumContamination" => Ok(SybilChallengeGround::QuorumContamination),
        "SyntheticHumanMisrepresentation" => {
            Ok(SybilChallengeGround::SyntheticHumanMisrepresentation)
        }
        other => Err(format!("unknown challenge ground: {other}")),
    }
}

fn now_timestamp() -> Timestamp {
    #[allow(clippy::as_conversions)]
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Timestamp {
        physical_ms: ms,
        logical: 0,
    }
}

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
    Json(req): Json<FileChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeResponse>), (StatusCode, String)> {
    let action_bytes = hex::decode(&req.action_id_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")))?;
    if action_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("action_id must be 32 bytes, got {}", action_bytes.len()),
        ));
    }
    let mut action_id = [0u8; 32];
    action_id.copy_from_slice(&action_bytes);

    let ground = parse_ground(&req.ground).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let hold = challenge::admit_challenge(&action_id, ground, now_timestamp());
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

    challenge::begin_review(hold, now_timestamp())
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

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

    challenge::resolve_hold(hold, now_timestamp(), &req.outcome)
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

    challenge::dismiss_hold(hold, now_timestamp(), &req.reason)
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
    use tower::ServiceExt;

    use super::*;

    fn test_store() -> SharedChallengeStore {
        Arc::new(Mutex::new(ChallengeStore::new()))
    }

    fn action_id_hex() -> String {
        hex::encode([7u8; 32])
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

        let body = serde_json::json!({
            "action_id_hex": action_id_hex(),
            "ground": "QuorumContamination",
        });

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
        let hold = challenge::admit_challenge(
            &[1u8; 32],
            SybilChallengeGround::ConcealedCommonControl,
            Timestamp::new(1000, 0),
        );
        let hold_id = hold.id;
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        // Begin review.
        let app = challenge_router(Arc::clone(&store));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/challenges/{hold_id}/review"))
                    .header("content-type", "application/json")
                    .body(Body::empty())
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
        let resolve_body = serde_json::json!({ "outcome": "challenge sustained" });
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
        let hold = challenge::admit_challenge(
            &[2u8; 32],
            SybilChallengeGround::SyntheticHumanMisrepresentation,
            Timestamp::new(500, 0),
        );
        let hold_id = hold.id;
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        let app = challenge_router(Arc::clone(&store));
        let body = serde_json::json!({ "reason": "insufficient evidence" });
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
    async fn invalid_ground_rejected() {
        let store = test_store();
        let app = challenge_router(store);

        let body = serde_json::json!({
            "action_id_hex": action_id_hex(),
            "ground": "InvalidGround",
        });

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
        let fake_id = Uuid::new_v4();

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
        let mut hold = challenge::admit_challenge(
            &[3u8; 32],
            SybilChallengeGround::CoordinatedManipulation,
            Timestamp::new(100, 0),
        );
        let hold_id = hold.id;
        challenge::resolve_hold(&mut hold, Timestamp::new(200, 0), "done").unwrap();
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        let app = challenge_router(store);
        let body = serde_json::json!({ "outcome": "again" });
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
