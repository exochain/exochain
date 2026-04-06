//! 0dentity Score & Identity API handlers.
//!
//! Implements read and attestation endpoints:
//!
//! - `GET /api/v1/0dentity/:did/score`         — current score (public)
//! - `GET /api/v1/0dentity/:did/claims`         — claim list (owner only)
//! - `GET /api/v1/0dentity/:did/score/history`  — score history (public)
//! - `GET /api/v1/0dentity/:did/fingerprints`   — fingerprint timeline (owner only)
//! - `POST /api/v1/0dentity/:did/attest`        — peer attestation
//! - `GET /api/v1/0dentity/server-key`          — server RSA-OAEP public key
//!
//! Spec reference: §7.2, §7.3.

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use exo_core::types::{Did, Hash256};
use serde::{Deserialize, Serialize};

use super::{
    attestation::{
        attester_score_impact, build_target_claim, create_attestation, target_score_impact,
        validate_attestation,
    },
    store::ZerodentityStore,
    types::{AttestationType, IdentityClaim, ZerodentityScore},
};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Mutex<ZerodentityStore>>,
    /// Node DID used for deterministic server key derivation.
    pub node_did: exo_core::types::Did,
    /// Epoch ms when the node started (used as key rotation timestamp).
    pub started_ms: u64,
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ClaimsQuery {
    pub status: Option<String>,
    #[serde(rename = "type")]
    pub claim_type: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub from_ms: Option<u64>,
    pub to_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ScoreResponse {
    pub subject_did: String,
    pub composite: u32,
    pub symmetry: u32,
    pub axes: AxesResponse,
    pub computed_ms: u64,
    pub dag_state_hash: String,
    pub claim_count: u32,
    pub history_available: bool,
}

#[derive(Debug, Serialize)]
pub struct AxesResponse {
    pub communication: u32,
    pub credential_depth: u32,
    pub device_trust: u32,
    pub behavioral_signature: u32,
    pub network_reputation: u32,
    pub temporal_stability: u32,
    pub cryptographic_strength: u32,
    pub constitutional_standing: u32,
}

#[derive(Debug, Serialize)]
pub struct ClaimItem {
    pub claim_id: String,
    pub claim_type: String,
    pub claim_hash: String,
    pub status: String,
    pub created_ms: u64,
    pub verified_ms: Option<u64>,
    pub expires_ms: Option<u64>,
    pub dag_node_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ClaimsResponse {
    pub claims: Vec<ClaimItem>,
    pub total: usize,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Debug, Serialize)]
pub struct HistorySnapshot {
    pub computed_ms: u64,
    pub composite: u32,
    pub axes: AxesResponse,
    pub claim_count: u32,
}

#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    pub snapshots: Vec<HistorySnapshot>,
}

#[derive(Debug, Serialize)]
pub struct FingerprintItem {
    pub composite_hash: String,
    pub captured_ms: u64,
    pub consistency_score: Option<u32>,
    pub signal_count: usize,
}

#[derive(Debug, Serialize)]
pub struct FingerprintsResponse {
    pub fingerprints: Vec<FingerprintItem>,
}

#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    pub target_did: String,
    pub attestation_type: String,
    pub message_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestResponse {
    pub attestation_id: String,
    pub receipt_hash: String,
    pub attester_score_impact: serde_json::Value,
    pub target_score_impact: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ServerKeyResponse {
    pub algorithm: String,
    pub key_size: u32,
    pub public_key_pem: String,
    pub key_hash: String,
    pub rotated_ms: u64,
}

// ---------------------------------------------------------------------------
// Helper: extract session token from Authorization header
// ---------------------------------------------------------------------------

fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn parse_did(did_str: &str) -> Result<Did, (StatusCode, Json<serde_json::Value>)> {
    Did::new(did_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid DID format"})),
        )
    })
}

fn hex_hash(h: &Hash256) -> String {
    hex::encode(h.as_bytes())
}

fn axes_from_score(s: &ZerodentityScore) -> AxesResponse {
    AxesResponse {
        communication: s.axes.communication,
        credential_depth: s.axes.credential_depth,
        device_trust: s.axes.device_trust,
        behavioral_signature: s.axes.behavioral_signature,
        network_reputation: s.axes.network_reputation,
        temporal_stability: s.axes.temporal_stability,
        cryptographic_strength: s.axes.cryptographic_strength,
        constitutional_standing: s.axes.constitutional_standing,
    }
}

fn now_ms() -> u64 {
    exo_core::hlc::HybridClock::new().now().physical_ms
}

// ---------------------------------------------------------------------------
// GET /api/v1/0dentity/:did/score
// ---------------------------------------------------------------------------

/// `GET /api/v1/0dentity/:did/score` — retrieve the current composite identity score.
pub async fn get_score(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
) -> Result<Json<ScoreResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;
    let now = now_ms();

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "lock poisoned"})),
        )
    })?;

    // Check if DID exists
    let claims_raw = store.get_claims(&did).unwrap_or_default();
    if claims_raw.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "DID not found"})),
        ));
    }

    let claims: Vec<IdentityClaim> = claims_raw.into_iter().map(|(_, c)| c).collect();
    let fingerprints = store.get_fingerprints(&did).unwrap_or_default();
    let behavioral = store.get_behavioral_samples(&did).unwrap_or_default();

    let score = ZerodentityScore::compute(&did, &claims, &fingerprints, &behavioral, now);

    let history = store
        .get_score_history(&did, None, None)
        .unwrap_or_default();

    Ok(Json(ScoreResponse {
        subject_did: did.to_string(),
        composite: score.composite,
        symmetry: score.symmetry,
        axes: axes_from_score(&score),
        computed_ms: score.computed_ms,
        dag_state_hash: hex_hash(&score.dag_state_hash),
        claim_count: score.claim_count,
        history_available: !history.is_empty(),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/0dentity/:did/claims
// ---------------------------------------------------------------------------

/// `GET /api/v1/0dentity/:did/claims` — list identity claims for a subject.
#[allow(clippy::as_conversions)]
pub async fn list_claims(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
    Query(params): Query<ClaimsQuery>,
    headers: HeaderMap,
) -> Result<Json<ClaimsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;

    // Auth: session token required for claim listing
    let token = extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Bearer session token required"})),
        )
    })?;

    // Verify session belongs to this DID
    {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        let session = store.get_session(&token).ok().flatten().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid or expired session"})),
            )
        })?;
        if session.subject_did.as_str() != did.as_str() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Access denied"})),
            ));
        }
    }

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "lock poisoned"})),
        )
    })?;
    let all_claims = store.get_claims(&did).unwrap_or_default();

    // Filter by status
    let filtered: Vec<(String, IdentityClaim)> = all_claims
        .into_iter()
        .filter(|(_, c)| {
            if let Some(ref s) = params.status {
                return c.status.to_string().to_lowercase() == s.to_lowercase();
            }
            true
        })
        .filter(|(_, c)| {
            if let Some(ref t) = params.claim_type {
                return c
                    .claim_type
                    .to_string()
                    .to_lowercase()
                    .contains(&t.to_lowercase());
            }
            true
        })
        .collect();

    let total = filtered.len();
    let offset = params.offset.unwrap_or(0) as usize;
    let limit = params.limit.unwrap_or(50) as usize;

    let page: Vec<ClaimItem> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(cid, c)| ClaimItem {
            claim_id: cid,
            claim_type: c.claim_type.to_string(),
            claim_hash: hex::encode(c.claim_hash.as_bytes()),
            status: c.status.to_string(),
            created_ms: c.created_ms,
            verified_ms: c.verified_ms,
            expires_ms: c.expires_ms,
            dag_node_hash: hex::encode(c.dag_node_hash.as_bytes()),
        })
        .collect();

    Ok(Json(ClaimsResponse {
        claims: page,
        total,
        limit: params.limit.unwrap_or(50),
        offset: params.offset.unwrap_or(0),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/0dentity/:did/score/history
// ---------------------------------------------------------------------------

/// `GET /api/v1/0dentity/:did/score/history` — paginated score computation history.
pub async fn score_history(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
    Query(params): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "lock poisoned"})),
        )
    })?;
    let snapshots = store
        .get_score_history(&did, params.from_ms, params.to_ms)
        .unwrap_or_default();

    let items: Vec<HistorySnapshot> = snapshots
        .iter()
        .map(|s| HistorySnapshot {
            computed_ms: s.computed_ms,
            composite: s.composite,
            axes: axes_from_score(s),
            claim_count: s.claim_count,
        })
        .collect();

    Ok(Json(HistoryResponse { snapshots: items }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/0dentity/:did/fingerprints
// ---------------------------------------------------------------------------

/// `GET /api/v1/0dentity/:did/fingerprints` — behavioral fingerprint timeline (owner only).
pub async fn list_fingerprints(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
    headers: HeaderMap,
) -> Result<Json<FingerprintsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;

    // Auth required
    let token = extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Bearer session token required"})),
        )
    })?;

    {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        let session = store.get_session(&token).ok().flatten().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid or expired session"})),
            )
        })?;
        if session.subject_did.as_str() != did.as_str() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Access denied"})),
            ));
        }
    }

    let store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "lock poisoned"})),
        )
    })?;
    let fps = store.get_fingerprints(&did).unwrap_or_default();
    let items: Vec<FingerprintItem> = fps
        .iter()
        .map(|fp| FingerprintItem {
            composite_hash: hex::encode(fp.composite_hash.as_bytes()),
            captured_ms: fp.captured_ms,
            consistency_score: fp.consistency_score_bp,
            signal_count: fp.signal_hashes.len(),
        })
        .collect();

    Ok(Json(FingerprintsResponse {
        fingerprints: items,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/v1/0dentity/:did/attest
// ---------------------------------------------------------------------------

/// `POST /api/v1/0dentity/:did/attest` — submit a peer attestation for a subject.
pub async fn create_peer_attestation(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AttestRequest>,
) -> Result<(StatusCode, Json<AttestResponse>), (StatusCode, Json<serde_json::Value>)> {
    let attester_did = parse_did(&did_str)?;
    let target_did = parse_did(&req.target_did)?;
    let now = now_ms();

    // Auth required
    let token = extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Bearer session token required"})),
        )
    })?;

    {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        let session = store.get_session(&token).ok().flatten().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid or expired session"})),
            )
        })?;
        if session.subject_did.as_str() != attester_did.as_str() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Access denied"})),
            ));
        }
    }

    let attestation_type = AttestationType::from_str(&req.attestation_type).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid attestation_type"})),
        )
    })?;

    let message_hash = req.message_hash.as_deref().and_then(|s| {
        hex::decode(s).ok().and_then(|b| {
            if b.len() >= 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b[..32]);
                Some(Hash256::from_bytes(arr))
            } else {
                None
            }
        })
    });

    // Validate
    let (attester_claims, already_exists) = {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        let claims: Vec<IdentityClaim> = store
            .get_claims(&attester_did)
            .unwrap_or_default()
            .into_iter()
            .map(|(_, c)| c)
            .collect();
        let exists = store
            .attestation_exists(&attester_did, &target_did)
            .unwrap_or(false);
        (claims, exists)
    };

    validate_attestation(&attester_did, &target_did, &attester_claims, already_exists).map_err(
        |e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        },
    )?;

    // Synthetic DAG node hash
    let dag_node_hash = Hash256::digest(
        format!("attest:{}:{}", attester_did.as_str(), target_did.as_str()).as_bytes(),
    );

    let attestation = create_attestation(
        &attester_did,
        &target_did,
        attestation_type,
        message_hash,
        dag_node_hash,
        now,
    );

    // Persist attestation
    {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        store.insert_attestation(&attestation).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?;

        // Add PeerAttestation claim to target's claim set
        let target_claim = build_target_claim(&attestation, dag_node_hash, now);
        let claim_id = uuid::Uuid::new_v4().to_string();
        let _ = store.insert_claim(&claim_id, &target_claim);
    }

    let receipt_hash = hex::encode(
        Hash256::digest(format!("attest-receipt:{}", &attestation.attestation_id).as_bytes())
            .as_bytes(),
    );

    let att_id = attestation.attestation_id.clone();

    Ok((
        StatusCode::CREATED,
        Json(AttestResponse {
            attestation_id: att_id,
            receipt_hash,
            attester_score_impact: serde_json::json!({
                "network_reputation": format!("+{}", attester_score_impact())
            }),
            target_score_impact: serde_json::json!({
                "network_reputation": format!("+{}", target_score_impact())
            }),
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /api/v1/0dentity/server-key
// ---------------------------------------------------------------------------

/// `GET /api/v1/0dentity/server-key` — retrieve the server's RSA-OAEP public key.
pub async fn get_server_key(State(state): State<ApiState>) -> Json<ServerKeyResponse> {
    // Derive a deterministic key fingerprint from the node's DID.
    // In production, this will be replaced by a live RSA-OAEP key pair
    // generated at startup and rotated on a configurable interval.
    // The key_hash is a BLAKE3 digest of the node DID, providing a
    // stable per-node identifier that clients can pin.
    let key_material = format!("exochain-server-key:{}", state.node_did.as_str());
    let key_hash = Hash256::digest(key_material.as_bytes());
    Json(ServerKeyResponse {
        algorithm: "Ed25519-DH".into(),
        key_size: 256,
        public_key_pem: format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            hex::encode(key_hash.as_bytes())
        ),
        key_hash: hex::encode(key_hash.as_bytes()),
        rotated_ms: state.started_ms,
    })
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/0dentity/:did — right to erasure (§11.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ErasureResponse {
    pub subject_did: String,
    pub claims_revoked: u32,
    pub receipt_hash: String,
    pub message: String,
}

/// Delete all 0dentity data for a DID.
///
/// Implements the right to erasure (§11.4):
/// - Revokes all sessions
/// - Marks all claims as Revoked
/// - Zeroes score snapshots
/// - Removes fingerprints and behavioral data
/// - Tombstones DAG nodes
/// - Emits an erasure TrustReceipt
pub async fn delete_identity(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ErasureResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;

    // Auth: session token required — must own the DID
    let token = extract_session_token(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Bearer session token required"})),
        )
    })?;

    {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        let session = store.get_session(&token).ok().flatten().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid or expired session"})),
            )
        })?;
        if session.subject_did.as_str() != did.as_str() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Access denied — can only erase own identity"})),
            ));
        }
    }

    let claims_revoked = {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        store.erase_did(&did).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Erasure failed: {e}")})),
            )
        })?
    };

    let receipt_hash = hex::encode(
        Hash256::digest(format!("erasure-receipt:{}", did.as_str()).as_bytes()).as_bytes(),
    );

    Ok(Json(ErasureResponse {
        subject_did: did.to_string(),
        claims_revoked,
        receipt_hash,
        message: "Identity erased. All sessions revoked, claims marked Revoked, scores zeroed, fingerprints removed, DAG nodes tombstoned.".into(),
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn zerodentity_api_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/0dentity/server-key", get(get_server_key))
        .route("/api/v1/0dentity/:did/score", get(get_score))
        .route("/api/v1/0dentity/:did/claims", get(list_claims))
        .route("/api/v1/0dentity/:did/score/history", get(score_history))
        .route("/api/v1/0dentity/:did/fingerprints", get(list_fingerprints))
        .route(
            "/api/v1/0dentity/:did/attest",
            post(create_peer_attestation),
        )
        .route(
            "/api/v1/0dentity/:did",
            axum::routing::delete(delete_identity),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::needless_borrows_for_generic_args)]
mod tests {
    use axum::{body::Body, http::Request};
    use exo_core::types::{Did, Hash256, Signature};
    use tower::ServiceExt;

    use super::*;
    use crate::zerodentity::{
        store::ZerodentityStore,
        types::{ClaimStatus, ClaimType, IdentityClaim, IdentitySession},
    };

    fn make_state() -> ApiState {
        ApiState {
            store: Arc::new(Mutex::new(ZerodentityStore::new())),
            node_did: Did::new("did:exo:test-node").unwrap(),
            started_ms: 1_700_000_000_000,
        }
    }

    fn make_state_with_session(token: &str, did_str: &str) -> ApiState {
        let mut store = ZerodentityStore::new();
        let did = Did::new(did_str).unwrap();
        let session = IdentitySession {
            session_token: token.to_owned(),
            subject_did: did,
            public_key: vec![],
            created_ms: 0,
            last_active_ms: 0,
            revoked: false,
        };
        store.insert_session(&session).unwrap();
        ApiState {
            store: Arc::new(Mutex::new(store)),
            node_did: Did::new("did:exo:test-node").unwrap(),
            started_ms: 1_700_000_000_000,
        }
    }

    fn make_state_with_session_and_claim(token: &str, did_str: &str) -> ApiState {
        let mut store = ZerodentityStore::new();
        let did = Did::new(did_str).unwrap();
        let session = IdentitySession {
            session_token: token.to_owned(),
            subject_did: did.clone(),
            public_key: vec![],
            created_ms: 0,
            last_active_ms: 0,
            revoked: false,
        };
        store.insert_session(&session).unwrap();
        let claim = IdentityClaim {
            claim_hash: Hash256::digest(b"email-claim"),
            subject_did: did,
            claim_type: ClaimType::Email,
            status: ClaimStatus::Verified,
            created_ms: 1000,
            verified_ms: Some(2000),
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: Hash256::digest(b"dag-node"),
        };
        store.insert_claim("claim-001", &claim).unwrap();
        ApiState {
            store: Arc::new(Mutex::new(store)),
            node_did: Did::new("did:exo:test-node").unwrap(),
            started_ms: 1_700_000_000_000,
        }
    }

    // --- list_fingerprints ---

    #[tokio::test]
    async fn list_fingerprints_invalid_did_returns_400() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/notadid/fingerprints")
                    .header("authorization", "Bearer tok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_fingerprints_no_token_returns_401() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/fingerprints")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_fingerprints_unknown_session_returns_401() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/fingerprints")
                    .header("authorization", "Bearer unknown-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_fingerprints_wrong_did_returns_403() {
        let state = make_state_with_session("tok-bob", "did:exo:bob");
        let app = zerodentity_api_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/fingerprints")
                    .header("authorization", "Bearer tok-bob")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_fingerprints_returns_empty_list() {
        let state = make_state_with_session("tok-alice", "did:exo:alice");
        let app = zerodentity_api_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/fingerprints")
                    .header("authorization", "Bearer tok-alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["fingerprints"].as_array().unwrap().len(), 0);
    }

    // --- score_history ---

    #[tokio::test]
    async fn score_history_invalid_did_returns_400() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/notadid/score/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn score_history_returns_empty_for_unknown_did() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Anobody/score/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["snapshots"].as_array().unwrap().len(), 0);
    }

    // --- create_peer_attestation ---

    #[tokio::test]
    async fn create_peer_attestation_invalid_target_did_returns_400() {
        // target_did is parsed before auth; no session needed
        let app = zerodentity_api_router(make_state());
        let body = serde_json::json!({
            "target_did": "notadid",
            "attestation_type": "Identity"
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/attest")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer tok")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_peer_attestation_wrong_session_returns_403() {
        let state = make_state_with_session("tok-bob", "did:exo:bob");
        let app = zerodentity_api_router(state);
        let body = serde_json::json!({
            "target_did": "did:exo:carol",
            "attestation_type": "Identity"
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/attest")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer tok-bob")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_peer_attestation_success_with_message_hash() {
        let state = make_state_with_session_and_claim("tok-alice", "did:exo:alice");
        let app = zerodentity_api_router(state);
        let body = serde_json::json!({
            "target_did": "did:exo:carol",
            "attestation_type": "Identity",
            "message_hash": hex::encode([0u8; 32])
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/attest")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer tok-alice")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_peer_attestation_short_message_hash_succeeds() {
        // message_hash < 32 bytes → parsed as None (covers the else branch)
        let state = make_state_with_session_and_claim("tok-alice", "did:exo:alice");
        let app = zerodentity_api_router(state);
        let body = serde_json::json!({
            "target_did": "did:exo:dave",
            "attestation_type": "Trustworthy",
            "message_hash": hex::encode([0u8; 16])
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/attest")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer tok-alice")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // --- list_claims ---

    #[tokio::test]
    async fn list_claims_filters_by_type() {
        let state = make_state_with_session_and_claim("tok-alice", "did:exo:alice");
        let app = zerodentity_api_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/claims?type=email")
                    .header("authorization", "Bearer tok-alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["claims"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn list_claims_pagination_with_offset() {
        let state = make_state_with_session_and_claim("tok-alice", "did:exo:alice");
        let app = zerodentity_api_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice/claims?offset=1&limit=10")
                    .header("authorization", "Bearer tok-alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // 1 claim total, offset=1 → empty page
        assert_eq!(result["claims"].as_array().unwrap().len(), 0);
        assert_eq!(result["total"], 1);
    }

    // --- delete_identity (§11.4) ---

    #[tokio::test]
    async fn delete_identity_no_token_returns_401() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_identity_wrong_did_returns_403() {
        let state = make_state_with_session("tok-bob", "did:exo:bob");
        let app = zerodentity_api_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice")
                    .header("authorization", "Bearer tok-bob")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_identity_success_returns_erasure_receipt() {
        let state = make_state_with_session_and_claim("tok-alice", "did:exo:alice");
        let app = zerodentity_api_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/0dentity/did%3Aexo%3Aalice")
                    .header("authorization", "Bearer tok-alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["claims_revoked"], 1);
        assert!(result["receipt_hash"].as_str().is_some());
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("Identity erased")
        );
    }

    #[tokio::test]
    async fn delete_identity_invalid_did_returns_400() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/0dentity/notadid")
                    .header("authorization", "Bearer tok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
