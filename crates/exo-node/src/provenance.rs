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

//! Provenance API — DAG lineage query endpoints.
//!
//! Every committed action has a cryptographic ancestry traceable back to
//! genesis through the DAG.  These endpoints expose that lineage so any
//! participant can verify provenance of any action at runtime.
//!
//! ## Endpoints
//!
//! - `GET /api/v1/provenance/:hash` — full lineage for a DAG node

#![allow(clippy::needless_borrows_for_generic_args)]

use std::{
    collections::BTreeSet,
    fmt::Display,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use exo_core::types::Hash256;
use serde::Serialize;

use crate::store::SqliteDagStore;

const MAX_PROVENANCE_TRAVERSAL_HASHES: usize = 1024;
const MAX_PROVENANCE_DEPTH: u32 = 1000;

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
    /// Size in bytes of the stored payload hash.
    pub payload_hash_size: usize,
    /// Depth: number of hops to reach a root (node with no parents).
    pub depth: u32,
}

fn build_provenance_response(
    store: &SqliteDagStore,
    hash: &Hash256,
) -> Result<ProvenanceResponse, (StatusCode, String)> {
    let node = store
        .get_sync(hash)
        .map_err(|error| provenance_store_error("Store read failed", error))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "node not found in DAG".into()))?;
    ensure_provenance_hash_count("parent", node.parents.len())?;

    let children = store
        .children(hash)
        .map_err(|error| provenance_store_error("Store child lookup failed", error))?;
    ensure_provenance_hash_count("child", children.len())?;

    let committed_height = store
        .committed_height_for(hash)
        .map_err(|error| provenance_store_error("Store commit lookup failed", error))?;

    let depth = compute_provenance_depth(store, &node.parents)?;

    Ok(ProvenanceResponse {
        hash: hex::encode(node.hash.0),
        creator: node.creator_did.to_string(),
        parents: node.parents.iter().map(|h| hex::encode(h.0)).collect(),
        children: children.iter().map(|h| hex::encode(h.0)).collect(),
        committed: committed_height.is_some(),
        committed_height,
        timestamp_ms: node.timestamp.physical_ms,
        payload_hash_size: node.payload_hash.as_bytes().len(),
        depth,
    })
}

fn compute_provenance_depth(
    store: &SqliteDagStore,
    parent_hashes: &[Hash256],
) -> Result<u32, (StatusCode, String)> {
    let mut depth = 0u32;
    let mut visited = BTreeSet::new();
    let mut frontier = parent_hashes.iter().copied().collect::<BTreeSet<_>>();

    while !frontier.is_empty() {
        if depth >= MAX_PROVENANCE_DEPTH {
            return Err(provenance_traversal_limit_error("maximum depth exceeded"));
        }
        depth += 1;

        let mut next_frontier = BTreeSet::new();
        for parent_hash in &frontier {
            if !visited.insert(*parent_hash) {
                continue;
            }
            ensure_provenance_hash_count("ancestor", visited.len())?;

            let Some(parent_node) = store
                .get_sync(parent_hash)
                .map_err(|error| provenance_store_error("Store traversal failed", error))?
            else {
                continue;
            };
            ensure_provenance_hash_count("ancestor parent", parent_node.parents.len())?;

            for grandparent_hash in parent_node.parents {
                if visited.contains(&grandparent_hash) {
                    continue;
                }
                next_frontier.insert(grandparent_hash);
                ensure_provenance_hash_count("frontier", next_frontier.len())?;
            }
        }
        frontier = next_frontier;
    }

    Ok(depth)
}

fn ensure_provenance_hash_count(label: &str, count: usize) -> Result<(), (StatusCode, String)> {
    if count > MAX_PROVENANCE_TRAVERSAL_HASHES {
        return Err(provenance_traversal_limit_error(&format!(
            "{label} hash count exceeds {MAX_PROVENANCE_TRAVERSAL_HASHES}: {count}"
        )));
    }
    Ok(())
}

fn provenance_traversal_limit_error(detail: &str) -> (StatusCode, String) {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("provenance traversal limit exceeded: {detail}"),
    )
}

fn provenance_store_error(context: &'static str, error: impl Display) -> (StatusCode, String) {
    tracing::error!(%error, context, "provenance store operation failed");
    (StatusCode::INTERNAL_SERVER_ERROR, context.to_string())
}

async fn load_provenance_response(
    state: Arc<ProvenanceState>,
    hash: Hash256,
) -> Result<ProvenanceResponse, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Store unavailable".to_string(),
            )
        })?;
        build_provenance_response(&store, &hash)
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "provenance store task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Store task failed".to_string(),
        )
    })?
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

    load_provenance_response(state, hash).await.map(Json)
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
    use exo_core::types::{Did, Signature, Timestamp};
    use exo_dag::dag::{Dag, DagNode, DeterministicDagClock, append};
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

    fn indexed_hash(index: usize) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(
            &u64::try_from(index)
                .expect("test index fits in u64")
                .to_be_bytes(),
        );
        Hash256::from_bytes(bytes)
    }

    fn test_node(hash: Hash256, parents: Vec<Hash256>) -> DagNode {
        DagNode {
            hash,
            parents,
            payload_hash: indexed_hash(9_000),
            creator_did: Did::new("did:exo:test").unwrap(),
            timestamp: Timestamp::new(1_000, 1),
            signature: Signature::from_bytes([7u8; 64]),
        }
    }

    #[test]
    fn provenance_handler_store_access_uses_spawn_blocking() {
        let source = include_str!("provenance.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "provenance handler must isolate synchronous store I/O from Tokio workers"
        );
        let handler = production
            .split("async fn handle_provenance")
            .nth(1)
            .expect("handler present")
            .split("// ---------------------------------------------------------------------------\n// Router")
            .next()
            .expect("router marker present");
        assert!(
            !handler.contains("state.store.lock()"),
            "provenance async handler must not directly block on the store mutex"
        );
    }

    #[test]
    fn provenance_store_errors_are_not_reflected_to_clients() {
        let source = include_str!("provenance.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            !production.contains("e.to_string()"),
            "store error internals must be logged, not reflected to HTTP clients"
        );
        assert!(
            !production.contains("format!(\"Store task failed: {e}\")"),
            "spawn_blocking join errors must be redacted from HTTP clients"
        );
    }

    fn test_state_with_dag() -> (Arc<ProvenanceState>, Hash256, Hash256) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteDagStore::open(dir.path()).unwrap();

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
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

        store.put_sync(genesis.clone()).unwrap();
        store.put_sync(child.clone()).unwrap();
        store.mark_committed_sync(&genesis.hash, 1).unwrap();

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
        assert!(result.get("payload_size").is_none());
        assert_eq!(result["payload_hash_size"], 32);
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

    #[tokio::test]
    async fn provenance_rejects_excessive_parent_fanout_during_depth_walk() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteDagStore::open(dir.path()).unwrap();

        let fanout_parent_hash = indexed_hash(42);
        let fanout_parents = (10_000..11_025).map(indexed_hash).collect();
        let fanout_parent = test_node(fanout_parent_hash, fanout_parents);
        let queried = test_node(indexed_hash(43), vec![fanout_parent_hash]);

        store.put_sync(fanout_parent).unwrap();
        store.put_sync(queried.clone()).unwrap();

        let state = Arc::new(ProvenanceState {
            store: Arc::new(Mutex::new(store)),
        });
        let app = provenance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!(
                        "/api/v1/provenance/{}",
                        hex::encode(queried.hash.0)
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let body_text = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_text.contains("provenance traversal limit"));
    }
}
