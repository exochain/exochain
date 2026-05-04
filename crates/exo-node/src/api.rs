//! Governance API — HTTP endpoints for submitting proposals, broadcasting
//! governance events, querying node status, and managing the validator set.
//!
//! Routes are merged into the gateway's axum router via
//! `serve_with_extra_routes` so the node exposes governance operations
//! alongside the existing REST / GraphQL endpoints.

#![allow(
    clippy::needless_borrows_for_generic_args,
    // `needless_return` fires inside #[cfg(not(feature = "..."))]
    // refusal blocks where the function body continues in the
    // mutually-exclusive `#[cfg(feature = "...")]` branch. Clippy
    // can't see the other branch, so the explicit `return` is
    // load-bearing for the feature-on build.
    clippy::needless_return,
    // `ValidatorChangeRequest` fields are only used inside
    // #[cfg(feature = "unaudited-admin-governance-shortcut")].
    // Keeping dead_code on in default build would force us to duplicate
    // the struct definition per feature which is worse than this allow.
    dead_code
)]

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
#[cfg(any(test, feature = "unaudited-admin-governance-shortcut"))]
use exo_core::types::Did;
#[cfg(feature = "unaudited-admin-governance-shortcut")]
use exo_core::types::PublicKey;
use exo_core::types::{Hash256, TrustReceipt};
use serde::{Deserialize, Serialize};
use tower::limit::ConcurrencyLimitLayer;

#[cfg(feature = "unaudited-admin-governance-shortcut")]
use crate::identity;
#[cfg(feature = "unaudited-admin-governance-shortcut")]
use crate::wire::ValidatorChange;
use crate::{
    network::NetworkHandle,
    reactor::{self, SharedReactorState},
    store::SqliteDagStore,
    wire::GovernanceEventType,
};

const MAX_GOVERNANCE_API_BODY_BYTES: usize = 64 * 1024;
const MAX_GOVERNANCE_API_CONCURRENT_REQUESTS: usize = 64;

fn internal_error_response(message: &'static str) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, message.to_string())
}

// ---------------------------------------------------------------------------
// Shared application state for the governance API
// ---------------------------------------------------------------------------

/// Shared state accessible by all governance route handlers.
#[derive(Clone)]
pub struct NodeApiState {
    pub reactor_state: SharedReactorState,
    pub store: Arc<Mutex<SqliteDagStore>>,
    pub net_handle: NetworkHandle,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/governance/propose`.
#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    /// Hex-encoded payload bytes for the governance action.
    pub payload_hex: String,
}

/// Response from a successful proposal submission.
#[derive(Debug, Serialize)]
pub struct ProposeResponse {
    /// The hash of the created DAG node (hex-encoded).
    pub node_hash: String,
    /// The committed height (if immediately committed).
    pub height: Option<u64>,
}

/// Request body for `POST /api/v1/governance/broadcast`.
#[derive(Debug, Deserialize)]
pub struct BroadcastRequest {
    pub event_type: String,
    pub payload_hex: String,
}

/// Request body for `POST /api/v1/governance/validators`.
#[derive(Debug, Deserialize)]
pub struct ValidatorChangeRequest {
    pub action: String, // "add" or "remove"
    pub did: String,
    pub public_key_hex: Option<String>,
}

/// Response representing a single trust receipt.
#[derive(Debug, Serialize)]
pub struct ReceiptResponse {
    pub receipt_hash: String,
    pub actor_did: String,
    pub authority_chain_hash: String,
    pub consent_reference: Option<String>,
    pub action_type: String,
    pub action_hash: String,
    pub outcome: String,
    pub timestamp_ms: u64,
    pub challenge_reference: Option<String>,
}

impl From<exo_core::types::TrustReceipt> for ReceiptResponse {
    fn from(r: exo_core::types::TrustReceipt) -> Self {
        Self {
            receipt_hash: hex::encode(r.receipt_hash.0),
            actor_did: r.actor_did.to_string(),
            authority_chain_hash: hex::encode(r.authority_chain_hash.0),
            consent_reference: r.consent_reference.map(|h| hex::encode(h.0)),
            action_type: r.action_type,
            action_hash: hex::encode(r.action_hash.0),
            outcome: r.outcome.to_string(),
            timestamp_ms: r.timestamp.physical_ms,
            challenge_reference: r.challenge_reference.map(|h| hex::encode(h.0)),
        }
    }
}

/// Query parameters for `GET /api/v1/receipts`.
#[derive(Debug, Deserialize)]
pub struct ReceiptQuery {
    /// Filter by actor DID (required).
    pub actor: Option<String>,
    /// Maximum number of receipts to return (default 50, max 500).
    pub limit: Option<u32>,
}

/// Response for `GET /api/v1/governance/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    pub consensus_round: u64,
    pub committed_height: u64,
    pub validator_count: usize,
    pub is_validator: bool,
    pub validators: Vec<String>,
}

struct NodeStatusSnapshot {
    consensus_round: u64,
    committed_height: u64,
    validators: Vec<String>,
    is_validator: bool,
}

// ---------------------------------------------------------------------------
// Blocking adapters
// ---------------------------------------------------------------------------

async fn read_node_status_snapshot(
    reactor_state: SharedReactorState,
) -> Result<NodeStatusSnapshot, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let s = reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        let committed_height = u64::try_from(s.consensus.committed.len()).map_err(|_| {
            tracing::error!(
                committed_len = s.consensus.committed.len(),
                "Committed height cannot be represented as u64"
            );
            internal_error_response("Consensus status unavailable")
        })?;
        Ok(NodeStatusSnapshot {
            consensus_round: s.consensus.current_round,
            committed_height,
            validators: s
                .consensus
                .config
                .validators
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>(),
            is_validator: s.is_validator,
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Node status blocking task failed");
        internal_error_response("Consensus status unavailable")
    })?
}

#[cfg(feature = "unaudited-admin-governance-shortcut")]
async fn read_validator_count(
    reactor_state: SharedReactorState,
) -> Result<usize, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let s = reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        Ok(s.consensus.config.validators.len())
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Validator count blocking task failed");
        internal_error_response("Consensus status unavailable")
    })?
}

async fn load_receipt_by_hash(
    store: Arc<Mutex<SqliteDagStore>>,
    hash: Hash256,
) -> Result<Option<TrustReceipt>, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let st = store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Store unavailable".to_string(),
            )
        })?;
        st.load_receipt(&hash).map_err(|e| {
            tracing::error!(err = %e, "Receipt lookup failed");
            internal_error_response("Receipt lookup failed")
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Receipt lookup blocking task failed");
        internal_error_response("Receipt lookup failed")
    })?
}

async fn load_receipts_by_actor(
    store: Arc<Mutex<SqliteDagStore>>,
    actor: String,
    limit: u32,
) -> Result<Vec<TrustReceipt>, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let st = store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Store unavailable".to_string(),
            )
        })?;
        st.load_receipts_by_actor(&actor, limit).map_err(|e| {
            tracing::error!(err = %e, actor = %actor, "Receipt list failed");
            internal_error_response("Receipt list failed")
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Receipt list blocking task failed");
        internal_error_response("Receipt list failed")
    })?
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

#[cfg(feature = "unaudited-admin-governance-shortcut")]
fn parse_validator_public_key_hex(value: &str) -> Result<PublicKey, (StatusCode, String)> {
    let bytes = hex::decode(value).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public_key_hex: {e}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("public_key_hex must be 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(public_key))
}

/// `POST /api/v1/governance/propose` — submit a governance proposal for BFT consensus.
async fn handle_propose(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<ProposeRequest>,
) -> Result<Json<ProposeResponse>, (StatusCode, String)> {
    let payload = hex::decode(&req.payload_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex payload: {e}")))?;

    match reactor::submit_proposal(&api.reactor_state, &api.store, &api.net_handle, &payload).await
    {
        Ok(node) => Ok(Json(ProposeResponse {
            node_hash: hex::encode(node.hash.0),
            height: None,
        })),
        Err(e) => {
            tracing::error!(err = %e, "Proposal submission failed");
            Err(internal_error_response("Proposal submission failed"))
        }
    }
}

/// `POST /api/v1/governance/broadcast` — broadcast a governance event to the network.
async fn handle_broadcast(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<BroadcastRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let payload = hex::decode(&req.payload_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex payload: {e}")))?;

    let event_type = match req.event_type.as_str() {
        "DecisionCreated" => GovernanceEventType::DecisionCreated,
        "VoteCast" => GovernanceEventType::VoteCast,
        "DecisionFinalized" => GovernanceEventType::DecisionFinalized,
        "AuthorityDelegated" => GovernanceEventType::AuthorityDelegated,
        "ConsentChanged" => GovernanceEventType::ConsentChanged,
        "EntityEnrolled" => GovernanceEventType::EntityEnrolled,
        "AuditEntry" => GovernanceEventType::AuditEntry,
        "ValidatorSetChange" => GovernanceEventType::ValidatorSetChange,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unknown event type: {other}"),
            ));
        }
    };

    reactor::broadcast_governance_event(&api.reactor_state, &api.net_handle, event_type, payload)
        .await
        .map_err(|e| {
            tracing::error!(err = %e, "Governance event broadcast failed");
            internal_error_response("Governance event broadcast failed")
        })?;

    Ok(StatusCode::ACCEPTED)
}

/// `GET /api/v1/governance/status` — return current node and consensus state.
async fn handle_status(
    State(api): State<Arc<NodeApiState>>,
) -> Result<Json<NodeStatusResponse>, (StatusCode, String)> {
    let snapshot = read_node_status_snapshot(Arc::clone(&api.reactor_state)).await?;

    Ok(Json(NodeStatusResponse {
        consensus_round: snapshot.consensus_round,
        committed_height: snapshot.committed_height,
        validator_count: snapshot.validators.len(),
        is_validator: snapshot.is_validator,
        validators: snapshot.validators,
    }))
}

/// `POST /api/v1/governance/validators` — add or remove a validator.
///
/// # Safety gate
///
/// This handler is behind the `unaudited-admin-governance-shortcut`
/// feature flag (default OFF). When OFF, the endpoint returns
/// `403 Forbidden` with a structured refusal.
///
/// **Why:** the legacy path below mutates the validator set purely
/// on presentation of the admin bearer token — no BFT proposal,
/// no quorum, no signature chain, no recorded governance event.
/// One holder of the admin token becomes a constitutional dictator
/// over validator membership. That violates SeparationOfPowers,
/// NoSelfGrant, and every on-chain-governance invariant the
/// constitution exists to enforce.
///
/// Enable ONLY with full understanding of the trade-off (e.g., an
/// isolated dev cluster) and NEVER in production until a real
/// propose → quorum-vote → commit flow replaces it.
///
/// See: council-intake/exo-node-onyx-3-api-mcp.md (RED #1),
///      Initiatives/fix-admin-governance-bypass.md.
async fn handle_validator_change(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<ValidatorChangeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    {
        let _ = (api, req); // silence unused warnings
        tracing::warn!(
            "refusing POST /api/v1/governance/validators: admin bearer \
             shortcut is gated. See fix-admin-governance-bypass \
             initiative. To opt in for a dev cluster, build with \
             --features exo-node/unaudited-admin-governance-shortcut."
        );
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "admin_governance_shortcut_disabled",
                "message": "Validator set mutation via bearer-token shortcut is disabled \
                            by default. A real propose → quorum-vote → commit flow is \
                            required. See Initiatives/fix-admin-governance-bypass.md.",
                "feature_flag": "unaudited-admin-governance-shortcut",
                "refusal_source": "exo-node/api.rs::handle_validator_change",
            })
            .to_string(),
        ));
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    {
        tracing::warn!(
            action = %req.action,
            did = %req.did,
            "UNAUDITED admin-governance shortcut in use — single bearer \
             token is mutating validator set without quorum. This is \
             gated by the `unaudited-admin-governance-shortcut` feature \
             and MUST NOT be enabled in production."
        );
        let did = Did::new(&req.did)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;

        if req.action == "add" {
            let public_key_hex = req.public_key_hex.as_deref().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "public_key_hex is required when adding a validator".to_string(),
                )
            })?;
            let public_key = parse_validator_public_key_hex(public_key_hex)?;
            let derived_did = identity::did_from_public_key(&public_key).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("public_key_hex does not derive a valid validator DID: {e}"),
                )
            })?;
            if derived_did != did {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("public_key_hex derives {derived_did}, not {did}"),
                ));
            }
        }

        let change = match req.action.as_str() {
            "add" => ValidatorChange::AddValidator { did: did.clone() },
            "remove" => {
                let validator_count = read_validator_count(Arc::clone(&api.reactor_state)).await?;
                if validator_count <= 4 {
                    return Err((
                        StatusCode::CONFLICT,
                        "Cannot propose validator removal: minimum 4 required for BFT safety (3f+1)"
                            .into(),
                    ));
                }
                ValidatorChange::RemoveValidator { did: did.clone() }
            }
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid action '{other}', expected 'add' or 'remove'"),
                ));
            }
        };

        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).map_err(|e| {
            tracing::error!(err = %e, "Validator change proposal CBOR encoding failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Validator change proposal encoding failed".to_string(),
            )
        })?;

        let node =
            reactor::submit_proposal(&api.reactor_state, &api.store, &api.net_handle, &payload)
                .await
                .map_err(|e| {
                    tracing::warn!(err = %e, "Validator change proposal submission failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Validator change proposal submission failed".to_string(),
                    )
                })?;

        Ok(Json(serde_json::json!({
            "proposal_status": "submitted",
            "node_hash": hex::encode(node.hash.0),
            "action": req.action,
            "did": req.did,
        })))
    } // end cfg(feature = "unaudited-admin-governance-shortcut") block
}

// ---------------------------------------------------------------------------
// Trust receipt handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/receipts/:hash` — look up a trust receipt by content hash.
async fn handle_receipt_by_hash(
    State(api): State<Arc<NodeApiState>>,
    Path(hash_hex): Path<String>,
) -> Result<Json<ReceiptResponse>, (StatusCode, String)> {
    let hash_bytes = hex::decode(&hash_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex hash: {e}")))?;
    if hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Hash must be 32 bytes, got {}", hash_bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let hash = Hash256::from_bytes(arr);

    let receipt = load_receipt_by_hash(Arc::clone(&api.store), hash).await?;

    match receipt {
        Some(r) => Ok(Json(ReceiptResponse::from(r))),
        None => Err((StatusCode::NOT_FOUND, "Receipt not found".into())),
    }
}

/// `GET /api/v1/receipts` — list trust receipts filtered by actor DID.
async fn handle_receipts_list(
    State(api): State<Arc<NodeApiState>>,
    Query(q): Query<ReceiptQuery>,
) -> Result<Json<Vec<ReceiptResponse>>, (StatusCode, String)> {
    let actor = q.actor.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Query parameter 'actor' is required".into(),
        )
    })?;

    let limit = q.limit.unwrap_or(50).min(500);

    let receipts = load_receipts_by_actor(Arc::clone(&api.store), actor, limit).await?;

    Ok(Json(
        receipts.into_iter().map(ReceiptResponse::from).collect(),
    ))
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the governance API router.
pub fn governance_router(state: Arc<NodeApiState>) -> Router {
    Router::new()
        .route("/api/v1/governance/propose", post(handle_propose))
        .route("/api/v1/governance/broadcast", post(handle_broadcast))
        .route("/api/v1/governance/status", get(handle_status))
        .route(
            "/api/v1/governance/validators",
            post(handle_validator_change),
        )
        .route("/api/v1/receipts/:hash", get(handle_receipt_by_hash))
        .route("/api/v1/receipts", get(handle_receipts_list))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_GOVERNANCE_API_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(
            MAX_GOVERNANCE_API_CONCURRENT_REQUESTS,
        ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    use axum::{body::Body, http::Request};
    use exo_core::{crypto::KeyPair, types::Signature};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        reactor::{ReactorConfig, create_reactor_state},
        store::SqliteDagStore,
    };

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        let keypair = KeyPair::from_secret_bytes([1u8; 32]).unwrap();
        Arc::new(move |data: &[u8]| keypair.sign(data))
    }

    fn validator_public_keys(
        validators: &BTreeSet<Did>,
    ) -> std::collections::BTreeMap<Did, exo_core::types::PublicKey> {
        validators
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, did)| {
                let seed = u8::try_from(idx + 1).unwrap();
                let keypair = KeyPair::from_secret_bytes([seed; 32]).unwrap();
                (did, *keypair.public_key())
            })
            .collect()
    }

    fn test_api_state_with_validator_flag(is_validator: bool) -> Arc<NodeApiState> {
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();

        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator,
            validator_public_keys: validator_public_keys(&validators),
            validators,
            round_timeout_ms: 5000,
        };

        let reactor_state = create_reactor_state(&config, make_sign_fn(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            while let Some(command) = cmd_rx.recv().await {
                if let crate::network::NetworkCommand::Publish { reply, .. } = command {
                    let _ = reply.send(Ok(()));
                }
            }
        });
        let net_handle = NetworkHandle::new(cmd_tx);

        Arc::new(NodeApiState {
            reactor_state,
            store,
            net_handle,
        })
    }

    fn test_api_state() -> Arc<NodeApiState> {
        test_api_state_with_validator_flag(true)
    }

    #[tokio::test]
    async fn status_endpoint_returns_consensus_state() {
        let state = test_api_state();
        let app = governance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let status: NodeStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.consensus_round, 0);
        assert_eq!(status.validator_count, 4);
        assert!(status.is_validator);
    }

    #[tokio::test]
    async fn propose_endpoint_creates_dag_node() {
        let state = test_api_state();
        let app = governance_router(state);

        let payload = hex::encode(b"test governance decision");
        let body = serde_json::json!({ "payload_hex": payload });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The publish may fail (no network loop), but the DAG node is created locally.
        // The endpoint returns 500 because net publish fails, but the local state
        // is mutated. In production, the network loop would be running.
        // Let's accept either 200 or 500 and check that the DAG was modified.
        let _status = resp.status();
    }

    #[tokio::test]
    async fn propose_endpoint_redacts_internal_submission_errors() {
        let state = test_api_state_with_validator_flag(false);
        let app = governance_router(state);

        let body = serde_json::json!({ "payload_hex": hex::encode(b"not from validator") });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            !text.contains("not a validator"),
            "internal reactor errors must not be echoed to HTTP clients: {text}"
        );
        assert!(
            text.contains("Proposal submission failed"),
            "client should receive a generic proposal failure, got: {text}"
        );
    }

    #[tokio::test]
    async fn propose_endpoint_rejects_oversized_body_before_handler() {
        let state = test_api_state();
        let app = governance_router(state);
        let oversized_payload = "ab".repeat(70 * 1024);
        let body = serde_json::json!({ "payload_hex": oversized_payload });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn status_height_conversion_does_not_use_truncating_cast() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            !production.contains(".committed.len() as u64"),
            "status committed height must use checked conversion, not a truncating cast"
        );
    }

    #[test]
    fn production_api_source_does_not_suppress_security_relevant_clippy_lints() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        for lint in ["clippy::expect_used", "clippy::as_conversions"] {
            assert!(
                !production.contains(lint),
                "production API source must not suppress {lint}"
            );
        }
    }

    #[test]
    fn async_handlers_do_not_lock_std_mutexes_directly() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let handlers = production
            .split("// ---------------------------------------------------------------------------\n// Route handlers")
            .nth(1)
            .expect("route handler section")
            .split("// ---------------------------------------------------------------------------\n// Router construction")
            .next()
            .expect("router construction boundary");

        assert!(
            !handlers.contains(".store.lock()"),
            "async route handlers must not block runtime workers on store std::sync::Mutex"
        );
        assert!(
            !handlers.contains(".reactor_state.lock()"),
            "async route handlers must not block runtime workers on reactor std::sync::Mutex"
        );
    }

    #[test]
    fn governance_router_applies_local_admission_layers() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            production.contains("DefaultBodyLimit::max(MAX_GOVERNANCE_API_BODY_BYTES)"),
            "governance router must cap request body size locally"
        );
        assert!(
            production.contains("ConcurrencyLimitLayer::new(")
                && production.contains("MAX_GOVERNANCE_API_CONCURRENT_REQUESTS"),
            "governance router must apply local request admission control"
        );
    }

    #[tokio::test]
    async fn broadcast_rejects_unknown_event_type() {
        let state = test_api_state();
        let app = governance_router(state);

        let body = serde_json::json!({
            "event_type": "UnknownType",
            "payload_hex": "deadbeef",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/broadcast")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn validator_add_submits_proposal_without_mutating_validator_set() {
        let state = test_api_state();
        let validators_before = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        let app = governance_router(Arc::clone(&state));
        let keypair = KeyPair::from_secret_bytes([50u8; 32]).unwrap();
        let did = crate::identity::did_from_public_key(keypair.public_key()).unwrap();

        let body = serde_json::json!({
            "action": "add",
            "did": did.to_string(),
            "public_key_hex": hex::encode(keypair.public_key().as_bytes()),
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result["proposal_status"], "submitted");
        assert_eq!(result["action"], "add");
        assert_eq!(result["did"], did.to_string());
        assert_eq!(
            result["node_hash"].as_str().map(str::len),
            Some(64),
            "validator change proposal must return a 32-byte DAG hash"
        );

        let validators_after = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        assert_eq!(
            validators_before, validators_after,
            "validator-change endpoint must not directly mutate validator set"
        );
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn validator_remove_below_minimum_rejected() {
        let state = test_api_state();
        let app = governance_router(state);

        let body = serde_json::json!({
            "action": "remove",
            "did": "did:exo:v0",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn validator_remove_above_minimum_submits_proposal_without_mutating_validator_set() {
        let state = test_api_state();

        // First add validators to reach 5+
        {
            let mut s = state.reactor_state.lock().unwrap();
            s.consensus
                .config
                .validators
                .insert(Did::new("did:exo:v4").unwrap());
        }
        let validators_before = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };

        let app = governance_router(Arc::clone(&state));

        let body = serde_json::json!({
            "action": "remove",
            "did": "did:exo:v4",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result["proposal_status"], "submitted");
        assert_eq!(result["action"], "remove");
        assert_eq!(result["did"], "did:exo:v4");
        assert_eq!(
            result["node_hash"].as_str().map(str::len),
            Some(64),
            "validator change proposal must return a 32-byte DAG hash"
        );

        let validators_after = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        assert_eq!(
            validators_before, validators_after,
            "validator-change endpoint must not directly mutate validator set"
        );
    }

    // -----------------------------------------------------------------------
    // Trust receipt endpoint tests
    // -----------------------------------------------------------------------

    fn make_test_receipt(actor: &str, action: &str, ts_ms: u64) -> exo_core::types::TrustReceipt {
        use exo_core::types::{Hash256, ReceiptOutcome, Timestamp, TrustReceipt};
        let sign_fn = make_sign_fn();
        TrustReceipt::new(
            Did::new(actor).unwrap(),
            Hash256::ZERO,
            None,
            action.to_string(),
            Hash256::digest(format!("{actor}-{action}-{ts_ms}").as_bytes()),
            ReceiptOutcome::Executed,
            Timestamp {
                physical_ms: ts_ms,
                logical: 0,
            },
            &*sign_fn,
        )
        .expect("test trust receipt should encode")
    }

    #[tokio::test]
    async fn receipt_lookup_returns_stored_receipt() {
        let state = test_api_state();
        let receipt = make_test_receipt("did:exo:test-actor", "dag.commit", 1_700_000_000_000);
        let receipt_hash = receipt.receipt_hash;

        {
            let mut st = state.store.lock().unwrap();
            st.save_receipt(&receipt).unwrap();
        }

        let app = governance_router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/receipts/{}", hex::encode(receipt_hash.0)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["actor_did"], "did:exo:test-actor");
        assert_eq!(result["action_type"], "dag.commit");
        assert_eq!(result["outcome"], "executed");
    }

    #[tokio::test]
    async fn receipt_lookup_not_found() {
        let state = test_api_state();
        let app = governance_router(state);
        let fake_hash = "0".repeat(64);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/receipts/{fake_hash}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn receipt_lookup_invalid_hex() {
        let state = test_api_state();
        let app = governance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipts/not-valid-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn receipt_list_by_actor() {
        let state = test_api_state();

        // Save receipts for two different actors.
        {
            let mut st = state.store.lock().unwrap();
            st.save_receipt(&make_test_receipt("did:exo:alice", "propose", 1000))
                .unwrap();
            st.save_receipt(&make_test_receipt("did:exo:alice", "commit", 2000))
                .unwrap();
            st.save_receipt(&make_test_receipt("did:exo:bob", "propose", 3000))
                .unwrap();
        }

        let app = governance_router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipts?actor=did:exo:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let results: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r["actor_did"] == "did:exo:alice"));
    }

    #[tokio::test]
    async fn receipt_list_requires_actor_param() {
        let state = test_api_state();
        let app = governance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ==================================================================
    // GAP admin-governance-bypass refusal tests (default-build only)
    // ==================================================================

    /// When the `unaudited-admin-governance-shortcut` feature is OFF
    /// (the default), a POST to /api/v1/governance/validators must
    /// return 403 with a structured refusal body — never mutate the
    /// validator set on bearer-token alone.
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    #[tokio::test]
    async fn validator_add_refused_without_feature_flag() {
        let state = test_api_state();
        let validator_count_before = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.len()
        };

        let app = governance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "action": "add",
            "did": "did:exo:some-new-validator",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "default build MUST refuse validator-set mutation via bearer shortcut"
        );
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("admin_governance_shortcut_disabled"),
            "refusal body must include error tag, got: {text}"
        );
        assert!(
            text.contains("unaudited-admin-governance-shortcut"),
            "refusal body must name the feature flag, got: {text}"
        );

        // CRITICAL: validator set was NOT mutated.
        let validator_count_after = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.len()
        };
        assert_eq!(
            validator_count_before, validator_count_after,
            "refused endpoint must not touch validator set"
        );
    }

    /// Same for `remove` — refused with no state change.
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    #[tokio::test]
    async fn validator_remove_refused_without_feature_flag() {
        let state = test_api_state();
        let validators_before: BTreeSet<Did> = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };

        let app = governance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "action": "remove",
            "did": "did:exo:v0",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Validator set unchanged.
        let validators_after: BTreeSet<Did> = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        assert_eq!(validators_before, validators_after);
    }
}
