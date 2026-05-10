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
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_core::{Did, PublicKey, Signature, crypto, types::Timestamp};
use exo_escalation::challenge::{self, ContestHold, SignedChallengeAdmission};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower::limit::ConcurrencyLimitLayer;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const MAX_CHALLENGE_API_BODY_BYTES: usize = 64 * 1024;
const MAX_CHALLENGE_API_CONCURRENT_REQUESTS: usize = 64;
const MAX_CHALLENGE_STORE_HOLDS: usize = 1024;
const MAX_ACTIVE_CHALLENGES_PER_ACTOR: usize = 32;
const MAX_ACTIVE_CHALLENGES_PER_ACTION: usize = 64;
const CHALLENGE_TRANSITION_DOMAIN: &str = "exo.node.challenge.transition.v1";
const CHALLENGE_TRANSITION_SCHEMA_VERSION: u16 = 1;
const CHALLENGE_TRANSITION_REVIEW: &str = "review";
const CHALLENGE_TRANSITION_RESOLVE: &str = "resolve";
const CHALLENGE_TRANSITION_DISMISS: &str = "dismiss";

fn contest_status_label(status: &challenge::ContestStatus) -> &'static str {
    status.as_str()
}

fn is_active_contest_status(status: &challenge::ContestStatus) -> bool {
    matches!(
        status,
        challenge::ContestStatus::PauseEligible | challenge::ContestStatus::UnderReview
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChallengeAdmissionLimitError {
    #[error("challenge hold {id} already exists")]
    DuplicateHold { id: Uuid },
    #[error("challenge store capacity reached: {current_holds}/{max_holds} holds")]
    StoreCapacity {
        current_holds: usize,
        max_holds: usize,
    },
    #[error(
        "active challenge admission limit reached for actor {actor}: {active_holds}/{max_holds}"
    )]
    ActorActiveLimit {
        actor: Did,
        active_holds: usize,
        max_holds: usize,
    },
    #[error(
        "active challenge admission limit reached for action {action_hash}: {active_holds}/{max_holds}"
    )]
    ActionActiveLimit {
        action_hash: String,
        active_holds: usize,
        max_holds: usize,
    },
}

impl ChallengeAdmissionLimitError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::DuplicateHold { .. } => StatusCode::CONFLICT,
            Self::StoreCapacity { .. }
            | Self::ActorActiveLimit { .. }
            | Self::ActionActiveLimit { .. } => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

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

    #[cfg(test)]
    pub fn insert(&mut self, hold: ContestHold) {
        self.holds.insert(hold.id, hold);
    }

    pub fn try_insert_admitted_hold(
        &mut self,
        hold: ContestHold,
    ) -> Result<(), ChallengeAdmissionLimitError> {
        if self.holds.contains_key(&hold.id) {
            return Err(ChallengeAdmissionLimitError::DuplicateHold { id: hold.id });
        }

        if self.holds.len() >= MAX_CHALLENGE_STORE_HOLDS {
            return Err(ChallengeAdmissionLimitError::StoreCapacity {
                current_holds: self.holds.len(),
                max_holds: MAX_CHALLENGE_STORE_HOLDS,
            });
        }

        let actor_active_holds = self
            .holds
            .values()
            .filter(|existing| {
                existing.admitted_by == hold.admitted_by
                    && is_active_contest_status(&existing.status)
            })
            .count();
        if actor_active_holds >= MAX_ACTIVE_CHALLENGES_PER_ACTOR {
            return Err(ChallengeAdmissionLimitError::ActorActiveLimit {
                actor: hold.admitted_by,
                active_holds: actor_active_holds,
                max_holds: MAX_ACTIVE_CHALLENGES_PER_ACTOR,
            });
        }

        let action_active_holds = self
            .holds
            .values()
            .filter(|existing| {
                existing.action_id == hold.action_id && is_active_contest_status(&existing.status)
            })
            .count();
        if action_active_holds >= MAX_ACTIVE_CHALLENGES_PER_ACTION {
            return Err(ChallengeAdmissionLimitError::ActionActiveLimit {
                action_hash: hex::encode(hold.action_id),
                active_holds: action_active_holds,
                max_holds: MAX_ACTIVE_CHALLENGES_PER_ACTION,
            });
        }

        self.holds.insert(hold.id, hold);
        Ok(())
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
type ChallengeError = (StatusCode, String);
type ChallengeResult<T> = Result<T, ChallengeError>;

async fn with_challenge_store_blocking<T, F>(
    store: SharedChallengeStore,
    operation: F,
) -> ChallengeResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut ChallengeStore) -> ChallengeResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut store = store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Challenge store unavailable".to_string(),
            )
        })?;
        operation(&mut store)
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "challenge store task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Challenge store task failed".to_string(),
        )
    })?
}

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
            status: contest_status_label(&hold.status).to_owned(),
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
    #[serde(flatten)]
    pub authorization: ChallengeTransitionAuthorization,
}

/// Request body for resolving a challenge.
#[derive(Debug, Deserialize)]
pub struct ResolveChallengeRequest {
    pub at: Timestamp,
    pub outcome: String,
    #[serde(flatten)]
    pub authorization: ChallengeTransitionAuthorization,
}

/// Request body for dismissing a challenge.
#[derive(Debug, Deserialize)]
pub struct DismissChallengeRequest {
    pub at: Timestamp,
    pub reason: String,
    #[serde(flatten)]
    pub authorization: ChallengeTransitionAuthorization,
}

/// Signed authority fields required for challenge state transitions.
#[derive(Debug, Default, Deserialize)]
pub struct ChallengeTransitionAuthorization {
    #[serde(default)]
    pub actor_did: Option<Did>,
    #[serde(default)]
    pub public_key: Option<PublicKey>,
    #[serde(default)]
    pub signature: Option<Signature>,
}

#[derive(Serialize)]
struct ChallengeTransitionSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    hold_id: &'a Uuid,
    action_id: &'a [u8; 32],
    current_status: &'a str,
    transition: &'static str,
    actor_did: &'a Did,
    at: &'a Timestamp,
    detail: &'a str,
    authority_chain_hash: &'a [u8; 32],
}

fn challenge_transition_signing_payload(
    hold: &ContestHold,
    transition: &'static str,
    actor_did: &Did,
    at: &Timestamp,
    detail: &str,
) -> ChallengeResult<Vec<u8>> {
    let payload = ChallengeTransitionSigningPayload {
        domain: CHALLENGE_TRANSITION_DOMAIN,
        schema_version: CHALLENGE_TRANSITION_SCHEMA_VERSION,
        hold_id: &hold.id,
        action_id: &hold.action_id,
        current_status: hold.status.as_str(),
        transition,
        actor_did,
        at,
        detail,
        authority_chain_hash: &hold.authority_chain_hash,
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        tracing::error!(
            err = %e,
            transition,
            hold_id = %hold.id,
            "challenge transition signing payload encoding failed"
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "challenge transition authorization unavailable".to_owned(),
        )
    })?;
    Ok(encoded)
}

fn verify_transition_authorization(
    hold: &ContestHold,
    transition: &'static str,
    at: &Timestamp,
    detail: &str,
    authorization: &ChallengeTransitionAuthorization,
) -> ChallengeResult<()> {
    if *at == Timestamp::ZERO {
        return Err((
            StatusCode::BAD_REQUEST,
            "challenge transition timestamp must be caller-supplied and non-zero".to_owned(),
        ));
    }

    let actor_did = authorization.actor_did.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "challenge transition requires signed authorization".to_owned(),
        )
    })?;
    let public_key = authorization.public_key.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "challenge transition requires signed authorization".to_owned(),
        )
    })?;
    let signature = authorization.signature.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "challenge transition requires signed authorization".to_owned(),
        )
    })?;

    if actor_did != &hold.admitted_by || public_key != &hold.admitter_public_key {
        return Err((
            StatusCode::FORBIDDEN,
            "challenge transition signer is not authorized for this hold".to_owned(),
        ));
    }

    if signature.is_empty() || signature.ed25519_component_is_zero() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "challenge transition signature is invalid".to_owned(),
        ));
    }

    let payload = challenge_transition_signing_payload(hold, transition, actor_did, at, detail)?;
    if !crypto::verify(&payload, signature, public_key) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "challenge transition signature is invalid".to_owned(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/challenges` — list all challenge holds.
async fn handle_list(
    State(store): State<SharedChallengeStore>,
) -> Result<Json<Vec<ChallengeResponse>>, (StatusCode, String)> {
    let challenges = with_challenge_store_blocking(store, |st| {
        Ok(st
            .list()
            .iter()
            .map(|h| ChallengeResponse::from(*h))
            .collect())
    })
    .await?;
    Ok(Json(challenges))
}

/// `GET /api/v1/challenges/:id` — get a single challenge.
async fn handle_get(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;
    let challenge = with_challenge_store_blocking(store, move |st| {
        st.get(&id)
            .map(ChallengeResponse::from)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))
    })
    .await?;
    Ok(Json(challenge))
}

/// `POST /api/v1/challenges` — file a new Sybil challenge.
async fn handle_file(
    State(store): State<SharedChallengeStore>,
    Json(req): Json<SignedChallengeAdmission>,
) -> Result<(StatusCode, Json<ChallengeResponse>), (StatusCode, String)> {
    let hold =
        challenge::admit_challenge(req).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let resp = ChallengeResponse::from(&hold);

    with_challenge_store_blocking(store, move |st| {
        st.try_insert_admitted_hold(hold)
            .map_err(|e| (e.status_code(), e.to_string()))
    })
    .await?;

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
    let ReviewChallengeRequest { at, authorization } = req;

    let challenge = with_challenge_store_blocking(store, move |st| {
        let hold = st
            .get_mut(&id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;
        verify_transition_authorization(
            hold,
            CHALLENGE_TRANSITION_REVIEW,
            &at,
            "",
            &authorization,
        )?;
        challenge::begin_review(hold, at).map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
        Ok(ChallengeResponse::from(&*hold))
    })
    .await?;

    Ok(Json(challenge))
}

/// `POST /api/v1/challenges/:id/resolve` — resolve a challenge.
async fn handle_resolve(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
    Json(req): Json<ResolveChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;
    let ResolveChallengeRequest {
        at,
        outcome,
        authorization,
    } = req;

    let challenge = with_challenge_store_blocking(store, move |st| {
        let hold = st
            .get_mut(&id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;
        verify_transition_authorization(
            hold,
            CHALLENGE_TRANSITION_RESOLVE,
            &at,
            &outcome,
            &authorization,
        )?;
        challenge::resolve_hold(hold, at, &outcome)
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
        Ok(ChallengeResponse::from(&*hold))
    })
    .await?;

    Ok(Json(challenge))
}

/// `POST /api/v1/challenges/:id/dismiss` — dismiss a challenge.
async fn handle_dismiss(
    State(store): State<SharedChallengeStore>,
    Path(id_str): Path<String>,
    Json(req): Json<DismissChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid UUID: {e}")))?;
    let DismissChallengeRequest {
        at,
        reason,
        authorization,
    } = req;

    let challenge = with_challenge_store_blocking(store, move |st| {
        let hold = st
            .get_mut(&id)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "challenge not found".into()))?;
        verify_transition_authorization(
            hold,
            CHALLENGE_TRANSITION_DISMISS,
            &at,
            &reason,
            &authorization,
        )?;
        challenge::dismiss_hold(hold, at, &reason)
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
        Ok(ChallengeResponse::from(&*hold))
    })
    .await?;

    Ok(Json(challenge))
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
        .layer(DefaultBodyLimit::max(MAX_CHALLENGE_API_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(
            MAX_CHALLENGE_API_CONCURRENT_REQUESTS,
        ))
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

    #[test]
    fn challenge_async_handlers_use_blocking_store_access() {
        let source = include_str!("challenges.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "challenge handlers must isolate synchronous store access from Tokio workers"
        );

        let handlers = production
            .split("// Handlers\n// ---------------------------------------------------------------------------")
            .nth(1)
            .and_then(|section| {
                section
                    .split("// ---------------------------------------------------------------------------\n// Router")
                    .next()
            })
            .unwrap();
        assert!(
            !handlers.contains(".lock()"),
            "challenge async handlers must not lock std::sync::Mutex values directly"
        );
    }

    #[test]
    fn challenge_router_applies_local_admission_layers() {
        let source = include_str!("challenges.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let router = production
            .split("pub fn challenge_router")
            .nth(1)
            .unwrap()
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        assert!(
            router.contains("DefaultBodyLimit::max(MAX_CHALLENGE_API_BODY_BYTES)"),
            "challenge routes must bound JSON request bodies locally instead of relying on outer gateway composition"
        );
        assert!(
            router.contains("ConcurrencyLimitLayer::new(")
                && router.contains("MAX_CHALLENGE_API_CONCURRENT_REQUESTS"),
            "challenge routes must apply a local concurrency limit before admitting signed disputes"
        );
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

    fn signed_transition_body(
        mut body: serde_json::Value,
        hold: &ContestHold,
        transition: &'static str,
        at: Timestamp,
        detail: &str,
    ) -> serde_json::Value {
        let keypair = keypair(7);
        let actor = did("did:exo:reviewer");
        let payload =
            challenge_transition_signing_payload(hold, transition, &actor, &at, detail).unwrap();
        let signature = exo_core::crypto::sign(&payload, keypair.secret_key());
        let fields = body.as_object_mut().unwrap();
        fields.insert("actor_did".into(), serde_json::to_value(actor).unwrap());
        fields.insert(
            "public_key".into(),
            serde_json::to_value(*keypair.public_key()).unwrap(),
        );
        fields.insert("signature".into(), serde_json::to_value(signature).unwrap());
        body
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
        let review_at = ts(1100);
        let review_hold = {
            let st = store.lock().unwrap();
            st.get(&hold_id).unwrap().clone()
        };
        let review_body = signed_transition_body(
            serde_json::json!({ "at": review_at }),
            &review_hold,
            CHALLENGE_TRANSITION_REVIEW,
            review_at,
            "",
        );
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
        let resolve_at = ts(1200);
        let outcome = "challenge sustained";
        let resolve_hold = {
            let st = store.lock().unwrap();
            st.get(&hold_id).unwrap().clone()
        };
        let resolve_body = signed_transition_body(
            serde_json::json!({ "at": resolve_at, "outcome": outcome }),
            &resolve_hold,
            CHALLENGE_TRANSITION_RESOLVE,
            resolve_at,
            outcome,
        );
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
        let dismiss_at = ts(600);
        let reason = "insufficient evidence";
        let dismiss_hold = {
            let st = store.lock().unwrap();
            st.get(&hold_id).unwrap().clone()
        };
        let body = signed_transition_body(
            serde_json::json!({ "at": dismiss_at, "reason": reason }),
            &dismiss_hold,
            CHALLENGE_TRANSITION_DISMISS,
            dismiss_at,
            reason,
        );
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
    async fn unsigned_transition_request_is_rejected_without_mutating_hold() {
        let store = test_store();
        let hold = challenge::admit_challenge(signed_challenge(
            9,
            action_id(9),
            SybilChallengeGround::ConcealedCommonControl,
            ts(500),
        ))
        .unwrap();
        let hold_id = hold.id;
        {
            let mut st = store.lock().unwrap();
            st.insert(hold);
        }

        let app = challenge_router(Arc::clone(&store));
        let body = serde_json::json!({ "at": ts(600) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/v1/challenges/{hold_id}/review"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let stored_status = {
            let st = store.lock().unwrap();
            st.get(&hold_id).unwrap().status.clone()
        };
        assert_eq!(stored_status, challenge::ContestStatus::PauseEligible);
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
    async fn file_challenge_rejects_oversized_body_locally() {
        let store = test_store();
        let app = challenge_router(store);
        let body = format!(
            "{{\"oversized\":\"{}\"}}",
            "a".repeat(MAX_CHALLENGE_API_BODY_BYTES + 1)
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn file_challenge_rejects_actor_admission_quota_without_storing_extra_hold() {
        let store = test_store();
        {
            let mut st = store.lock().unwrap();
            for marker in 10..42 {
                st.insert(
                    challenge::admit_challenge(signed_challenge(
                        marker,
                        action_id(marker),
                        SybilChallengeGround::QuorumContamination,
                        ts(u64::from(marker) * 100),
                    ))
                    .unwrap(),
                );
            }
        }

        let app = challenge_router(Arc::clone(&store));
        let body = signed_challenge(
            42,
            action_id(42),
            SybilChallengeGround::QuorumContamination,
            ts(4200),
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

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let stored_count = {
            let st = store.lock().unwrap();
            st.list().len()
        };
        assert_eq!(stored_count, 32);
    }

    #[tokio::test]
    async fn file_challenge_rejects_duplicate_hold_id_without_replacing_existing_hold() {
        let store = test_store();
        {
            let mut st = store.lock().unwrap();
            st.insert(
                challenge::admit_challenge(signed_challenge(
                    50,
                    action_id(1),
                    SybilChallengeGround::ConcealedCommonControl,
                    ts(1000),
                ))
                .unwrap(),
            );
        }

        let app = challenge_router(Arc::clone(&store));
        let body = signed_challenge(
            50,
            action_id(2),
            SybilChallengeGround::SyntheticHumanMisrepresentation,
            ts(2000),
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

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let stored = {
            let st = store.lock().unwrap();
            st.get(&uuid(50)).unwrap().clone()
        };
        assert_eq!(stored.action_id, action_id(1));
        assert_eq!(stored.ground, SybilChallengeGround::ConcealedCommonControl);
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

        let app = challenge_router(Arc::clone(&store));
        let resolve_at = ts(300);
        let outcome = "again";
        let resolved_hold = {
            let st = store.lock().unwrap();
            st.get(&hold_id).unwrap().clone()
        };
        let body = signed_transition_body(
            serde_json::json!({ "at": resolve_at, "outcome": outcome }),
            &resolved_hold,
            CHALLENGE_TRANSITION_RESOLVE,
            resolve_at,
            outcome,
        );
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

    #[test]
    fn challenge_response_uses_stable_status_labels() {
        let source = include_str!("challenges.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        assert!(
            !production.contains("format!(\"{:?}\", hold.status)"),
            "challenge API status output must not depend on Rust Debug output"
        );
    }
}
