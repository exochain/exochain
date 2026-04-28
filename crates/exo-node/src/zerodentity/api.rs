//! 0dentity Score & Identity API handlers.
//!
//! Implements read and attestation endpoints:
//!
//! - `GET /api/v1/0dentity/:did/score`         — current score (public)
//! - `GET /api/v1/0dentity/:did/claims`         — claim list (owner only)
//! - `GET /api/v1/0dentity/:did/score/history`  — score history (public)
//! - `GET /api/v1/0dentity/:did/fingerprints`   — fingerprint timeline (owner only)
//! - `POST /api/v1/0dentity/:did/attest`        — peer attestation
//!
//! Spec reference: §7.2, §7.3.

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use exo_core::{
    crypto,
    types::{Did, Hash256, PublicKey, Signature, Timestamp},
};
use serde::{Deserialize, Serialize};

use super::{
    DEVICE_BEHAVIORAL_AXES_FEATURE, DEVICE_BEHAVIORAL_AXES_INITIATIVE,
    attestation::{
        CreateAttestationInput, attester_score_impact, build_target_claim, create_attestation,
        target_claim_hash, target_claim_id, target_score_impact, validate_attestation,
    },
    device_behavioral_axes_enabled,
    session_auth::{public_key_from_session_bytes, request_signing_payload, signature_from_hex},
    store::ZerodentityStore,
    types::{
        AttestationType, BehavioralSample, DeviceFingerprint, IdentityClaim, ZerodentityScore,
    },
};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Mutex<ZerodentityStore>>,
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
pub struct ScoreQuery {
    pub as_of_ms: Option<u64>,
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
    pub created_ms: Option<u64>,
    pub attester_public_key: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestResponse {
    pub attestation_id: String,
    pub receipt_hash: String,
    pub attester_score_impact: serde_json::Value,
    pub target_score_impact: serde_json::Value,
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

fn json_error(
    status: StatusCode,
    error: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": error.into() })))
}

fn path_and_query(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| uri.path().to_owned(), |value| value.as_str().to_owned())
}

fn require_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    missing: &str,
) -> Result<&'a str, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, missing))
}

fn validate_nonce(nonce: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if nonce.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X-Exo-Nonce is required",
        ));
    }
    if nonce.len() > 128 || !nonce.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X-Exo-Nonce must be 1-128 visible ASCII bytes",
        ));
    }
    Ok(())
}

fn verify_signed_write(
    state: &ApiState,
    headers: &HeaderMap,
    expected_did: &Did,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_session_token(headers)
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "Bearer session token required"))?;

    let mut store = state
        .store
        .lock()
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned"))?;
    let session = store
        .get_session(&token)
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Store error: {e}"),
            )
        })?
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "Invalid or expired session"))?;

    if session.subject_did.as_str() != expected_did.as_str() {
        return Err(json_error(StatusCode::FORBIDDEN, "Access denied"));
    }

    let nonce = require_header(headers, "x-exo-nonce", "X-Exo-Nonce header required")?;
    validate_nonce(nonce)?;
    let signature_hex = require_header(headers, "x-exo-sig", "X-Exo-Sig header required")?;
    let signature =
        signature_from_hex(signature_hex).map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;
    if signature.is_empty() {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "X-Exo-Sig must not be empty",
        ));
    }

    let public_key = public_key_from_session_bytes(&session.public_key)
        .map_err(|e| json_error(StatusCode::UNAUTHORIZED, e))?;
    let body_hash = Hash256::digest(body);
    let payload = request_signing_payload(method, path_and_query, &token, nonce, &body_hash)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if !crypto::verify(&payload, &signature, &public_key) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "X-Exo-Sig verification failed",
        ));
    }

    let nonce_is_new = store.consume_session_nonce(&token, nonce).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Store error: {e}"),
        )
    })?;
    if !nonce_is_new {
        return Err(json_error(
            StatusCode::CONFLICT,
            "X-Exo-Nonce has already been used for this session",
        ));
    }

    Ok(token)
}

fn hex_hash(h: &Hash256) -> String {
    hex::encode(h.as_bytes())
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message })),
    )
}

fn parse_hex_exact<const N: usize>(
    field: &str,
    value: &str,
) -> Result<[u8; N], (StatusCode, Json<serde_json::Value>)> {
    let bytes =
        hex::decode(value).map_err(|_| bad_request(&format!("{field} must be hex-encoded")))?;
    if bytes.len() != N {
        return Err(bad_request(&format!("{field} must be exactly {N} bytes")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_message_hash(
    value: Option<&str>,
) -> Result<Option<Hash256>, (StatusCode, Json<serde_json::Value>)> {
    value
        .map(|s| parse_hex_exact::<32>("message_hash", s).map(Hash256::from_bytes))
        .transpose()
}

fn parse_public_key(
    value: Option<&str>,
) -> Result<PublicKey, (StatusCode, Json<serde_json::Value>)> {
    let Some(value) = value else {
        return Err(bad_request("attester_public_key is required"));
    };
    parse_hex_exact::<32>("attester_public_key", value).map(PublicKey::from_bytes)
}

fn parse_signature(
    value: Option<&str>,
) -> Result<Signature, (StatusCode, Json<serde_json::Value>)> {
    let Some(value) = value else {
        return Err(bad_request("signature is required"));
    };
    parse_hex_exact::<64>("signature", value).map(Signature::from_bytes)
}

fn device_behavioral_axes_refusal(
    refusal_source: &'static str,
) -> (StatusCode, Json<serde_json::Value>) {
    tracing::warn!(
        feature_flag = DEVICE_BEHAVIORAL_AXES_FEATURE,
        initiative = DEVICE_BEHAVIORAL_AXES_INITIATIVE,
        refusal_source,
        "refusing unaudited 0dentity device/behavioral axis surface"
    );
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "zerodentity_device_behavioral_axes_disabled",
            "message": "0dentity device fingerprint and behavioral biometric axes are disabled by default because the ingestion path is not wired to persist client-collected samples.",
            "feature_flag": DEVICE_BEHAVIORAL_AXES_FEATURE,
            "initiative": DEVICE_BEHAVIORAL_AXES_INITIATIVE,
            "refusal_source": refusal_source,
        })),
    )
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

fn score_as_of_ms(
    claims: &[IdentityClaim],
    fingerprints: &[DeviceFingerprint],
    behavioral: &[BehavioralSample],
    requested_as_of_ms: Option<u64>,
) -> Result<u64, (StatusCode, Json<serde_json::Value>)> {
    if let Some(as_of_ms) = requested_as_of_ms {
        if as_of_ms == 0 {
            return Err(bad_request("as_of_ms must be greater than 0"));
        }
        return Ok(as_of_ms);
    }

    let mut horizon_ms = 0u64;
    for claim in claims {
        horizon_ms = horizon_ms.max(claim.created_ms);
        if let Some(verified_ms) = claim.verified_ms {
            horizon_ms = horizon_ms.max(verified_ms);
        }
    }
    for fingerprint in fingerprints {
        horizon_ms = horizon_ms.max(fingerprint.captured_ms);
    }
    for sample in behavioral {
        horizon_ms = horizon_ms.max(sample.captured_ms);
    }

    Ok(horizon_ms)
}

// ---------------------------------------------------------------------------
// GET /api/v1/0dentity/:did/score
// ---------------------------------------------------------------------------

/// `GET /api/v1/0dentity/:did/score` — retrieve the current composite identity score.
pub async fn get_score(
    State(state): State<ApiState>,
    Path(did_str): Path<String>,
    Query(params): Query<ScoreQuery>,
) -> Result<Json<ScoreResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;

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
    let as_of_ms = score_as_of_ms(&claims, &fingerprints, &behavioral, params.as_of_ms)?;

    let score = ZerodentityScore::compute(&did, &claims, &fingerprints, &behavioral, as_of_ms);

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
    if !device_behavioral_axes_enabled() {
        return Err(device_behavioral_axes_refusal(
            "exo-node/zerodentity/api.rs::list_fingerprints",
        ));
    }

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
    OriginalUri(uri): OriginalUri,
    Path(did_str): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AttestResponse>), (StatusCode, Json<serde_json::Value>)> {
    let attester_did = parse_did(&did_str)?;
    let req: AttestRequest = serde_json::from_slice(&body)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "Invalid JSON body"))?;
    let target_did = parse_did(&req.target_did)?;

    let request_path = path_and_query(&uri);
    let _token = verify_signed_write(
        &state,
        &headers,
        &attester_did,
        "POST",
        &request_path,
        &body,
    )?;

    let attestation_type = AttestationType::from_str(&req.attestation_type).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid attestation_type"})),
        )
    })?;

    let message_hash = parse_message_hash(req.message_hash.as_deref())?;
    let created_ms = req
        .created_ms
        .ok_or_else(|| bad_request("created_ms is required"))?;
    let attester_public_key = parse_public_key(req.attester_public_key.as_deref())?;
    let signature = parse_signature(req.signature.as_deref())?;

    let mut store = state.store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "lock poisoned"})),
        )
    })?;
    let attester_claims: Vec<IdentityClaim> = store
        .get_claims(&attester_did)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, c)| c)
        .collect();
    let already_exists = store
        .attestation_exists(&attester_did, &target_did)
        .unwrap_or(false);

    validate_attestation(&attester_did, &target_did, &attester_claims, already_exists).map_err(
        |e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        },
    )?;

    let target_claim_hash = target_claim_hash(&attester_did, &target_did).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let dag_node_hash = store
        .next_claim_dag_node_hash(target_claim_hash, Timestamp::new(created_ms, 0))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?;

    let attestation = create_attestation(CreateAttestationInput {
        attester_did: &attester_did,
        target_did: &target_did,
        attestation_type,
        message_hash,
        dag_node_hash,
        created_ms,
        attester_public_key,
        signature,
    })
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let target_claim =
        build_target_claim(&attestation, dag_node_hash, created_ms).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
    let claim_id = target_claim_id(&attestation).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    let evidence = store
        .save_claim_with_evidence(&claim_id, &target_claim)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?;
    store.insert_attestation(&attestation).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Store error: {e}")})),
        )
    })?;
    let receipt_hash = evidence.receipt_hash.ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Store error: verified attestation claim did not emit a trust receipt"})),
        )
    })?;
    let receipt_hash = hex::encode(receipt_hash.as_bytes());

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
// DELETE /api/v1/0dentity/:did — right to erasure (§11.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ErasureResponse {
    pub subject_did: String,
    pub claims_revoked: u32,
    pub receipt_hash: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ErasureRequest {
    pub erased_ms: Option<u64>,
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
    OriginalUri(uri): OriginalUri,
    Path(did_str): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ErasureResponse>, (StatusCode, Json<serde_json::Value>)> {
    let did = parse_did(&did_str)?;

    let request_path = path_and_query(&uri);
    let _token = verify_signed_write(&state, &headers, &did, "DELETE", &request_path, &body)?;
    let req: ErasureRequest = serde_json::from_slice(&body)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "Invalid JSON body"))?;
    let erased_ms = req
        .erased_ms
        .ok_or_else(|| bad_request("erased_ms is required"))?;
    if erased_ms == 0 {
        return Err(bad_request("erased_ms must be greater than 0"));
    }

    let erasure_evidence = {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "lock poisoned"})),
            )
        })?;
        store
            .erase_did_with_evidence(&did, Timestamp::new(erased_ms, 0))
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Erasure failed: {e}")})),
                )
            })?
    };

    let receipt_hash = hex::encode(erasure_evidence.receipt_hash.as_bytes());

    Ok(Json(ErasureResponse {
        subject_did: did.to_string(),
        claims_revoked: erasure_evidence.claims_revoked,
        receipt_hash,
        message: "Identity erased. All sessions revoked, claims marked Revoked, scores zeroed, fingerprints removed, DAG nodes tombstoned.".into(),
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn zerodentity_api_router(state: ApiState) -> Router {
    Router::new()
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
    use exo_core::{
        crypto::{self, KeyPair},
        types::{Did, Hash256, PublicKey, SecretKey, Signature},
    };
    use tower::ServiceExt;

    use super::*;
    use crate::zerodentity::{
        attestation::attestation_signing_payload,
        store::ZerodentityStore,
        types::{ClaimStatus, ClaimType, IdentityClaim, IdentitySession},
    };

    fn test_store() -> ZerodentityStore {
        let keypair = KeyPair::from_secret_bytes([31u8; 32]).unwrap();
        let signer = Arc::new(move |payload: &[u8]| keypair.sign(payload));
        let mut store = ZerodentityStore::new();
        store.set_receipt_signer(Did::new("did:exo:test-node").unwrap(), signer);
        store
    }

    fn make_state() -> ApiState {
        ApiState {
            store: Arc::new(Mutex::new(test_store())),
        }
    }

    #[test]
    fn attestation_write_path_does_not_fabricate_claim_ids_or_receipts() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        let uuid_new_v4 = format!("{}{}", "Uuid::", "new_v4()");
        let qualified_uuid_new_v4 = format!("{}{}", "uuid::Uuid::", "new_v4()");
        let fabricated_receipt = format!("{}{}", "attest-", "receipt");

        assert!(!production.contains(&uuid_new_v4));
        assert!(!production.contains(&qualified_uuid_new_v4));
        assert!(!production.contains(&fabricated_receipt));
    }

    #[test]
    fn erasure_write_path_does_not_fabricate_receipt_hashes() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let fabricated_receipt = format!("{}{}", "erasure-", "receipt");

        assert!(!production.contains(&fabricated_receipt));
    }

    #[test]
    fn attestation_write_path_uses_caller_supplied_time() {
        let source = include_str!("api.rs");
        let attestation_section = source
            .split("// POST /api/v1/0dentity/:did/attest\n// ---------------------------------------------------------------------------")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------").next())
            .unwrap();

        assert!(!attestation_section.contains("now_ms()"));
    }

    #[test]
    fn score_read_path_does_not_fabricate_runtime_time() {
        let source = include_str!("api.rs");
        let score_section = source
            .split("// GET /api/v1/0dentity/:did/score\n// ---------------------------------------------------------------------------")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------").next())
            .unwrap();

        assert!(!score_section.contains("now_ms()"));
    }

    #[test]
    fn erasure_write_path_does_not_fabricate_runtime_time() {
        let source = include_str!("api.rs");
        let erasure_section = source
            .split("// DELETE /api/v1/0dentity/:did")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------\n// Router").next())
            .unwrap();

        assert!(!erasure_section.contains("now_ms()"));
    }

    fn test_keypair(seed: u8) -> KeyPair {
        KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }

    fn make_state_with_session(token: &str, did_str: &str) -> ApiState {
        let mut store = test_store();
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
        }
    }

    fn make_state_with_session_and_claim(token: &str, did_str: &str) -> ApiState {
        let mut store = test_store();
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
        }
    }

    fn make_state_with_signed_session_and_claim(
        token: &str,
        did_str: &str,
        keypair: &KeyPair,
    ) -> ApiState {
        let mut store = test_store();
        let did = Did::new(did_str).unwrap();
        let session = IdentitySession {
            session_token: token.to_owned(),
            subject_did: did.clone(),
            public_key: keypair.public_key().as_bytes().to_vec(),
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
        }
    }

    fn request_signature_headers(
        method: &str,
        uri: &str,
        token: &str,
        nonce: &str,
        body: &[u8],
        keypair: &KeyPair,
    ) -> (String, String) {
        let body_hash = Hash256::digest(body);
        let payload = crate::zerodentity::session_auth::request_signing_payload(
            method, uri, token, nonce, &body_hash,
        )
        .unwrap();
        let signature = keypair.sign(&payload);
        (nonce.to_owned(), hex::encode(signature.to_bytes()))
    }

    async fn signed_post(
        app: Router,
        uri: &str,
        token: &str,
        nonce: &str,
        body: serde_json::Value,
        keypair: &KeyPair,
    ) -> axum::response::Response {
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let (nonce, signature) =
            request_signature_headers("POST", uri, token, nonce, &body_bytes, keypair);
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-exo-nonce", nonce)
                .header("x-exo-sig", signature)
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn signed_delete(
        app: Router,
        uri: &str,
        token: &str,
        nonce: &str,
        body: serde_json::Value,
        keypair: &KeyPair,
    ) -> axum::response::Response {
        let body = serde_json::to_vec(&body).unwrap();
        let (nonce, signature) =
            request_signature_headers("DELETE", uri, token, nonce, &body, keypair);
        app.oneshot(
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-exo-nonce", nonce)
                .header("x-exo-sig", signature)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn keypair(seed: u8) -> (PublicKey, SecretKey) {
        let pair = crypto::KeyPair::from_secret_bytes([seed; 32]).unwrap();
        (*pair.public_key(), pair.secret_key().clone())
    }

    fn signed_attest_body(
        attester: &Did,
        target: &Did,
        attestation_type: AttestationType,
        message_hash: Option<Hash256>,
        created_ms: u64,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> serde_json::Value {
        let payload = attestation_signing_payload(
            attester,
            target,
            &attestation_type,
            message_hash.as_ref(),
            created_ms,
        )
        .unwrap();
        let signature = crypto::sign(&payload, secret_key);
        serde_json::json!({
            "target_did": target.as_str(),
            "attestation_type": attestation_type.to_string(),
            "message_hash": message_hash.map(|h| hex::encode(h.as_bytes())),
            "created_ms": created_ms,
            "attester_public_key": hex::encode(public_key.as_bytes()),
            "signature": hex::encode(signature.to_bytes())
        })
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

    #[cfg(not(feature = "unaudited-zerodentity-device-behavioral-axes"))]
    #[tokio::test]
    async fn list_fingerprints_refused_without_device_behavioral_feature_flag() {
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            result["feature_flag"],
            "unaudited-zerodentity-device-behavioral-axes"
        );
        assert_eq!(result["initiative"], "fix-onyx-4-r3-unwired-axes.md");
    }

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
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

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
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

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
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

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
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
        let session_keypair = test_keypair(41);
        let state = make_state_with_signed_session_and_claim(
            "tok-alice",
            "did:exo:alice",
            &session_keypair,
        );
        let app = zerodentity_api_router(state);
        let attester = Did::new("did:exo:alice").unwrap();
        let target = Did::new("did:exo:carol").unwrap();
        let message_hash = Hash256::from_bytes([0u8; 32]);
        let (public_key, secret_key) = keypair(51);
        let uri = "/api/v1/0dentity/did%3Aexo%3Aalice/attest";
        let body = signed_attest_body(
            &attester,
            &target,
            AttestationType::Identity,
            Some(message_hash),
            1_700_000_100_000,
            &public_key,
            &secret_key,
        );
        let resp = signed_post(
            app,
            uri,
            "tok-alice",
            "nonce-api-attest-1",
            body,
            &session_keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_peer_attestation_short_message_hash_returns_400() {
        let session_keypair = test_keypair(42);
        let state = make_state_with_signed_session_and_claim(
            "tok-alice",
            "did:exo:alice",
            &session_keypair,
        );
        let app = zerodentity_api_router(state);
        let attester = Did::new("did:exo:alice").unwrap();
        let target = Did::new("did:exo:dave").unwrap();
        let (public_key, secret_key) = keypair(53);
        let uri = "/api/v1/0dentity/did%3Aexo%3Aalice/attest";
        let mut body = signed_attest_body(
            &attester,
            &target,
            AttestationType::Trustworthy,
            None,
            1_700_000_200_000,
            &public_key,
            &secret_key,
        );
        body["message_hash"] = serde_json::Value::String(hex::encode([0u8; 16]));
        let resp = signed_post(
            app,
            uri,
            "tok-alice",
            "nonce-api-attest-2",
            body,
            &session_keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn server_key_get_does_not_return_key_material() {
        let app = zerodentity_api_router(make_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/0dentity/server-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
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
        let keypair = test_keypair(43);
        let state =
            make_state_with_signed_session_and_claim("tok-alice", "did:exo:alice", &keypair);
        let store = state.store.clone();
        let app = zerodentity_api_router(state);
        let resp = signed_delete(
            app,
            "/api/v1/0dentity/did%3Aexo%3Aalice",
            "tok-alice",
            "nonce-api-delete-1",
            serde_json::json!({ "erased_ms": 7_777_000 }),
            &keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["claims_revoked"], 1);
        assert!(result["receipt_hash"].as_str().is_some());
        let guard = store.lock().unwrap();
        let receipts = guard.trust_receipts();
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.action_type == "zerodentity.identity_erased")
            .expect("erasure receipt");
        assert_eq!(
            result["receipt_hash"].as_str().unwrap(),
            hex::encode(receipt.receipt_hash.as_bytes())
        );
        assert_eq!(receipt.timestamp.physical_ms, 7_777_000);
        let nodes = guard.dag_nodes();
        let erasure_node = nodes.last().expect("erasure dag node");
        assert_eq!(erasure_node.timestamp.physical_ms, 7_777_000);
        assert!(receipt.verify_hash());
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("Identity erased")
        );
    }

    #[tokio::test]
    async fn delete_identity_requires_erasure_timestamp() {
        let keypair = test_keypair(44);
        let state =
            make_state_with_signed_session_and_claim("tok-alice", "did:exo:alice", &keypair);
        let app = zerodentity_api_router(state);
        let resp = signed_delete(
            app,
            "/api/v1/0dentity/did%3Aexo%3Aalice",
            "tok-alice",
            "nonce-api-delete-missing-time",
            serde_json::json!({}),
            &keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["error"].as_str().unwrap(), "erased_ms is required");
    }

    #[tokio::test]
    async fn delete_identity_rejects_zero_erasure_timestamp() {
        let keypair = test_keypair(45);
        let state =
            make_state_with_signed_session_and_claim("tok-alice", "did:exo:alice", &keypair);
        let app = zerodentity_api_router(state);
        let resp = signed_delete(
            app,
            "/api/v1/0dentity/did%3Aexo%3Aalice",
            "tok-alice",
            "nonce-api-delete-zero-time",
            serde_json::json!({ "erased_ms": 0 }),
            &keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            result["error"].as_str().unwrap(),
            "erased_ms must be greater than 0"
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
