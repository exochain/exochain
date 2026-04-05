//! Provenance API — DAG lineage query endpoints.
//!
//! Every committed action has a cryptographic ancestry traceable back to
//! genesis through the DAG.  These endpoints expose that lineage so any
//! participant can verify provenance of any action at runtime.
//!
//! ## Endpoints
//!
//! - `GET /api/v1/provenance/:hash` — full lineage for a DAG node

#![allow(clippy::expect_used, clippy::needless_borrows_for_generic_args)]

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use exo_core::types::Hash256;
use exo_dag::store::DagStore;
use serde::Serialize;

use crate::store::SqliteDagStore;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Shared state for provenance endpoints.
#[derive(Clone)]
pub struct ProvenanceState {
    pub store: Arc<Mutex<SqliteDagStore>>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Full provenance response for a DAG node.
#[derive(Debug, Serialize)]
pub struct ProvenanceResponse {
    /// The queried node hash (hex).
    pub hash: String,
    /// Creator DID.
    pub creator: String,
    /// Parent hashes (hex).
    pub parents: Vec<String>,
    /// Child hashes (hex) — nodes that reference this as a parent.
    pub children: Vec<String>,
    /// Whether this node has been committed via BFT consensus.
    pub committed: bool,
    /// Committed height (if committed).
    pub committed_height: Option<u64>,
    /// Timestamp (physical_ms from HLC).
    pub timestamp_ms: u64,
    /// Payload size in bytes.
    pub payload_size: usize,
    /// Depth: number of hops to reach a root (node with no parents).
    pub depth: u32,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/provenance/:hash` — full lineage for a DAG node.
async fn handle_provenance(
    State(state): State<Arc<ProvenanceState>>,
    Path(hash_hex): Path<String>,
) -> Result<Json<ProvenanceResponse>, (StatusCode, String)> {
    let hash_bytes = hex::decode(&hash_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")))?;
    if hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("hash must be 32 bytes, got {}", hash_bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let hash = Hash256::from_bytes(arr);

    let st = state.store.lock().expect("store lock");

    let node = st
        .get(&hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "node not found in DAG".into()))?;

    let children = st
        .children(&hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let committed_height = st
        .committed_height_for(&hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Walk parents to compute depth (max 1000 to avoid infinite loops).
    let mut depth = 0u32;
    let mut frontier = node.parents.clone();
    let mut max_iters = 1000u32;
    while !frontier.is_empty() && max_iters > 0 {
        depth += 1;
        max_iters -= 1;
        let mut next_frontier = Vec::new();
        for parent_hash in &frontier {
            if let Ok(Some(parent_node)) = st.get(parent_hash) {
                next_frontier.extend_from_slice(&parent_node.parents);
            }
        }
        frontier = next_frontier;
    }

    Ok(Json(ProvenanceResponse {
        hash: hex::encode(node.hash.0),
        creator: node.creator_did.to_string(),
        parents: node.parents.iter().map(|h| hex::encode(h.0)).collect(),
        children: children.iter().map(|h| hex::encode(h.0)).collect(),
        committed: committed_height.is_some(),
        committed_height,
        timestamp_ms: node.timestamp.physical_ms,
        payload_size: 32, // payload_hash is 32 bytes
        depth,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the provenance API router.
pub fn provenance_router(state: Arc<ProvenanceState>) -> Router {
    Router::new()
        .route("/api/v1/provenance/:hash", get(handle_provenance))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::{body::Body, http::Request};
    use exo_core::types::{Did, Signature};
    use exo_dag::dag::{Dag, HybridClock, append};
    use tower::ServiceExt;

    use super::*;

    fn make_sign_fn() -> Box<dyn Fn(&[u8]) -> Signature> {
        Box::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn test_state_with_dag() -> (Arc<ProvenanceState>, Hash256, Hash256) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteDagStore::open(dir.path()).unwrap();

        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = Did::new("did:exo:test").unwrap();
        let sign_fn = make_sign_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let child = append(
            &mut dag,
            &[genesis.hash],
            b"child",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        store.put(genesis.clone()).unwrap();
        store.put(child.clone()).unwrap();
        store.mark_committed(&genesis.hash, 1).unwrap();

        let state = Arc::new(ProvenanceState {
            store: Arc::new(Mutex::new(store)),
        });
        // Keep tempdir alive by leaking it (test only)
        std::mem::forget(dir);

        (state, genesis.hash, child.hash)
    }

    #[tokio::test]
    async fn provenance_returns_lineage() {
        let (state, genesis_hash, child_hash) = test_state_with_dag();
        let app = provenance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/provenance/{}", hex::encode(child_hash.0)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(result["creator"], "did:exo:test");
        assert_eq!(result["depth"], 1);
        assert!(!result["committed"].as_bool().unwrap());
        let parents = result["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0], hex::encode(genesis_hash.0));
    }

    #[tokio::test]
    async fn provenance_shows_committed_status() {
        let (state, genesis_hash, _) = test_state_with_dag();
        let app = provenance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!(
                        "/api/v1/provenance/{}",
                        hex::encode(genesis_hash.0)
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(result["committed"].as_bool().unwrap());
        assert_eq!(result["committed_height"], 1);
        assert_eq!(result["depth"], 0); // genesis has no parents
        // Genesis should have child
        let children = result["children"].as_array().unwrap();
        assert_eq!(children.len(), 1);
    }

    #[tokio::test]
    async fn provenance_not_found() {
        let (state, _, _) = test_state_with_dag();
        let app = provenance_router(state);
        let fake = "0".repeat(64);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/provenance/{fake}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn provenance_invalid_hex() {
        let (state, _, _) = test_state_with_dag();
        let app = provenance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/provenance/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
