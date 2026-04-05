//! State synchronization — catch-up protocol for new or lagging nodes.
//!
//! When a node joins the network (or falls behind), it needs to obtain all
//! committed DAG nodes it's missing. This module implements:
//!
//! 1. **Initial sync** — request a state snapshot from a peer with higher
//!    committed height, receive chunks of committed DAG nodes, store them
//!    locally, and mark them as committed.
//!
//! 2. **Incremental sync** — request missing DAG nodes by exchanging tip
//!    hashes with a peer.
//!
//! 3. **Snapshot serving** — respond to sync requests from other nodes.
//!
//! The sync protocol uses the existing wire messages
//! (`StateSnapshotRequest`/`StateSnapshotChunk` and `DagSyncRequest`/
//! `DagSyncResponse`) and operates over the gossipsub + direct messaging
//! layer.

#![allow(
    clippy::expect_used,
    clippy::as_conversions,
    clippy::manual_clamp,
    clippy::single_match
)]

use std::sync::{Arc, Mutex};

use exo_core::types::Did;
use exo_dag::store::DagStore;
use tokio::sync::mpsc;

use crate::{
    network::{NetworkEvent, NetworkHandle},
    store::SqliteDagStore,
    wire::{
        DagSyncRequestMsg, DagSyncResponseMsg, StateSnapshotChunkMsg, StateSnapshotRequestMsg,
        WireMessage, topics,
    },
};

// ---------------------------------------------------------------------------
// Sync configuration
// ---------------------------------------------------------------------------

/// Configuration for the sync engine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// This node's DID.
    pub node_did: Did,
    /// Maximum number of nodes per snapshot chunk.
    pub chunk_size: u32,
    /// Maximum number of nodes per DAG sync response.
    pub max_sync_nodes: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            node_did: Did::new("did:exo:default").expect("default DID"),
            chunk_size: 100,
            max_sync_nodes: 200,
        }
    }
}

// ---------------------------------------------------------------------------
// Sync events (sent to application layer)
// ---------------------------------------------------------------------------

/// Events the sync engine reports to the application layer.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// Sync progress update.
    Progress {
        from_height: u64,
        to_height: u64,
        total_nodes: usize,
    },
    /// Sync completed — node is caught up.
    Complete { committed_height: u64 },
    /// A sync request was served to a peer.
    ServedSnapshot {
        peer: Did,
        from_height: u64,
        nodes_sent: usize,
    },
}

// ---------------------------------------------------------------------------
// Sync engine
// ---------------------------------------------------------------------------

/// State sync engine — processes sync-related wire messages.
pub struct SyncEngine {
    config: SyncConfig,
    store: Arc<Mutex<SqliteDagStore>>,
    net_handle: NetworkHandle,
    event_tx: mpsc::Sender<SyncEvent>,
    /// Whether an initial sync is in progress.
    syncing: bool,
    /// The height we're syncing to (from the peer).
    sync_target_height: u64,
}

impl SyncEngine {
    /// Create a new sync engine.
    pub fn new(
        config: SyncConfig,
        store: Arc<Mutex<SqliteDagStore>>,
        net_handle: NetworkHandle,
        event_tx: mpsc::Sender<SyncEvent>,
    ) -> Self {
        Self {
            config,
            store,
            net_handle,
            event_tx,
            syncing: false,
            sync_target_height: 0,
        }
    }

    /// Request a state snapshot from the network.
    ///
    /// Called when a node first joins or detects it's behind.
    pub async fn request_sync(&mut self) -> anyhow::Result<()> {
        let local_height = {
            let st = self.store.lock().expect("store lock");
            st.committed_height_value()
        };

        tracing::info!(local_height, "Requesting state snapshot from network");

        self.syncing = true;

        let request = WireMessage::StateSnapshotRequest(StateSnapshotRequestMsg {
            sender: self.config.node_did.clone(),
            from_height: local_height + 1,
            chunk_size: self.config.chunk_size,
        });

        // Broadcast the request — peers with higher committed height will respond.
        self.net_handle
            .publish(topics::PEER_EXCHANGE, request)
            .await
            .map_err(|e| anyhow::anyhow!("broadcast sync request: {e}"))?;

        Ok(())
    }

    /// Request incremental DAG sync by exchanging tip hashes.
    pub async fn request_dag_sync(&self) -> anyhow::Result<()> {
        let tips = {
            let st = self.store.lock().expect("store lock");
            st.tips().map_err(|e| anyhow::anyhow!("tips: {e}"))?
        };

        let request = WireMessage::DagSyncRequest(DagSyncRequestMsg {
            sender: self.config.node_did.clone(),
            tip_hashes: tips,
            max_nodes: self.config.max_sync_nodes,
        });

        self.net_handle
            .publish(topics::PEER_EXCHANGE, request)
            .await
            .map_err(|e| anyhow::anyhow!("broadcast dag sync request: {e}"))?;

        Ok(())
    }

    /// Handle an incoming sync-related wire message.
    pub async fn handle_message(&mut self, message: WireMessage) {
        match message {
            WireMessage::StateSnapshotRequest(msg) => {
                self.handle_snapshot_request(msg).await;
            }
            WireMessage::StateSnapshotChunk(msg) => {
                self.handle_snapshot_chunk(msg).await;
            }
            WireMessage::DagSyncRequest(msg) => {
                self.handle_dag_sync_request(msg).await;
            }
            WireMessage::DagSyncResponse(msg) => {
                self.handle_dag_sync_response(msg).await;
            }
            _ => {} // Not a sync message
        }
    }

    /// Serve a state snapshot to a requesting peer.
    async fn handle_snapshot_request(&self, msg: StateSnapshotRequestMsg) {
        let local_height = {
            let st = self.store.lock().expect("store lock");
            st.committed_height_value()
        };

        // Only respond if we have data the peer needs.
        if local_height < msg.from_height {
            tracing::debug!(
                requester = %msg.sender,
                from_height = msg.from_height,
                local_height,
                "Cannot serve snapshot — our height is lower"
            );
            return;
        }

        tracing::info!(
            requester = %msg.sender,
            from_height = msg.from_height,
            local_height,
            "Serving state snapshot"
        );

        // Send committed nodes in chunks.
        let mut current_from = msg.from_height;
        let chunk_size = msg.chunk_size.max(1).min(500); // Clamp to [1, 500]

        loop {
            let to_height = (current_from + u64::from(chunk_size) - 1).min(local_height);

            let nodes = {
                let st = self.store.lock().expect("store lock");
                match st.committed_dag_nodes_in_range(current_from, to_height) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(err = %e, "Failed to query committed nodes");
                        return;
                    }
                }
            };

            let has_more = to_height < local_height;
            let nodes_count = nodes.len();

            let chunk = WireMessage::StateSnapshotChunk(StateSnapshotChunkMsg {
                sender: self.config.node_did.clone(),
                from_height: current_from,
                nodes,
                to_height,
                has_more,
            });

            if let Err(e) = self.net_handle.publish(topics::PEER_EXCHANGE, chunk).await {
                tracing::warn!(err = %e, "Failed to send snapshot chunk");
                return;
            }

            tracing::debug!(
                from = current_from,
                to = to_height,
                nodes = nodes_count,
                has_more,
                "Sent snapshot chunk"
            );

            let _ = self
                .event_tx
                .send(SyncEvent::ServedSnapshot {
                    peer: msg.sender.clone(),
                    from_height: current_from,
                    nodes_sent: nodes_count,
                })
                .await;

            if !has_more {
                break;
            }
            current_from = to_height + 1;
        }
    }

    /// Receive and apply a state snapshot chunk.
    async fn handle_snapshot_chunk(&mut self, msg: StateSnapshotChunkMsg) {
        if !self.syncing && msg.nodes.is_empty() {
            return;
        }

        let nodes_count = msg.nodes.len();

        tracing::info!(
            from = msg.from_height,
            to = msg.to_height,
            nodes = nodes_count,
            has_more = msg.has_more,
            "Received snapshot chunk"
        );

        // Store the nodes and mark them as committed.
        {
            let mut st = self.store.lock().expect("store lock");
            for (i, node) in msg.nodes.into_iter().enumerate() {
                let hash = node.hash;

                if let Err(e) = st.put(node) {
                    tracing::warn!(err = %e, %hash, "Failed to store synced node");
                    continue;
                }

                let height = msg.from_height + i as u64;
                if let Err(e) = st.mark_committed(&hash, height) {
                    tracing::warn!(err = %e, %hash, height, "Failed to mark committed");
                }
            }
        }

        if msg.to_height > self.sync_target_height {
            self.sync_target_height = msg.to_height;
        }

        let _ = self
            .event_tx
            .send(SyncEvent::Progress {
                from_height: msg.from_height,
                to_height: msg.to_height,
                total_nodes: nodes_count,
            })
            .await;

        if !msg.has_more {
            self.syncing = false;

            let committed_height = {
                let st = self.store.lock().expect("store lock");
                st.committed_height_value()
            };

            tracing::info!(committed_height, "State sync complete");

            let _ = self
                .event_tx
                .send(SyncEvent::Complete { committed_height })
                .await;
        }
    }

    /// Serve missing DAG nodes to a requesting peer.
    async fn handle_dag_sync_request(&self, msg: DagSyncRequestMsg) {
        let (nodes, has_more) = {
            let st = self.store.lock().expect("store lock");

            // Find nodes the requester is missing by comparing tips.
            // Strategy: send all our committed nodes that are not in the
            // requester's tip set (simple but effective for small DAGs).
            let our_tips = match st.tips() {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(err = %e, "Failed to get tips for sync");
                    return;
                }
            };

            // If our tips are the same, nothing to sync.
            if our_tips == msg.tip_hashes {
                return;
            }

            // Get nodes the peer is missing — nodes we have that descend
            // from their tips. For simplicity, we send our committed nodes
            // above the peer's implicit height.
            let local_height = st.committed_height_value();
            let max_nodes = msg.max_nodes.min(500) as u64;
            let send_height = if local_height > max_nodes {
                local_height - max_nodes
            } else {
                1
            };

            let nodes = match st.committed_dag_nodes_in_range(send_height, local_height) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(err = %e, "Failed to query nodes for sync");
                    return;
                }
            };

            let total = nodes.len();
            let truncated = total > msg.max_nodes as usize;
            let nodes = if truncated {
                nodes.into_iter().take(msg.max_nodes as usize).collect()
            } else {
                nodes
            };

            (nodes, truncated)
        };

        let nodes_count = nodes.len();

        let response = WireMessage::DagSyncResponse(DagSyncResponseMsg {
            sender: self.config.node_did.clone(),
            nodes,
            has_more,
        });

        if let Err(e) = self
            .net_handle
            .publish(topics::PEER_EXCHANGE, response)
            .await
        {
            tracing::warn!(err = %e, "Failed to send sync response");
            return;
        }

        tracing::debug!(
            requester = %msg.sender,
            nodes = nodes_count,
            has_more,
            "Served DAG sync response"
        );
    }

    /// Receive and apply DAG sync response (incremental catch-up).
    async fn handle_dag_sync_response(&mut self, msg: DagSyncResponseMsg) {
        if msg.nodes.is_empty() {
            return;
        }

        let nodes_count = msg.nodes.len();

        tracing::info!(
            nodes = nodes_count,
            has_more = msg.has_more,
            "Received DAG sync response"
        );

        {
            let mut st = self.store.lock().expect("store lock");
            for node in msg.nodes {
                let hash = node.hash;
                if let Err(e) = st.put(node) {
                    tracing::warn!(err = %e, %hash, "Failed to store synced node");
                }
            }
        }

        // If there are more nodes, request the next batch.
        if msg.has_more {
            if let Err(e) = self.request_dag_sync().await {
                tracing::warn!(err = %e, "Failed to request next sync batch");
            }
        }
    }

    /// Check if this node needs syncing (called periodically).
    #[allow(dead_code)] // Used in tests; will be wired into health monitor
    pub fn needs_sync(&self) -> bool {
        self.syncing
    }
}

/// Run the sync engine as a background task.
///
/// Listens for sync-related network events and processes them.
pub async fn run_sync_engine(mut engine: SyncEngine, mut net_events: mpsc::Receiver<NetworkEvent>) {
    loop {
        match net_events.recv().await {
            Some(NetworkEvent::MessageReceived { message, .. }) => {
                // Only process sync-related messages.
                match &message {
                    WireMessage::StateSnapshotRequest(_)
                    | WireMessage::StateSnapshotChunk(_)
                    | WireMessage::DagSyncRequest(_)
                    | WireMessage::DagSyncResponse(_) => {
                        engine.handle_message(message).await;
                    }
                    _ => {} // Other messages handled by reactor
                }
            }
            Some(_) => {} // Connection events
            None => {
                tracing::info!("Sync engine shutting down — channel closed");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::types::{Did, Signature};
    use exo_dag::dag::{Dag, HybridClock, append};
    use tokio::sync::mpsc;

    use super::*;

    fn make_sign_fn() -> Box<dyn Fn(&[u8]) -> Signature> {
        Box::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn test_did() -> Did {
        Did::new("did:exo:test-sync").unwrap()
    }

    /// Build a store with `n` committed DAG nodes and return it.
    fn build_store_with_committed_nodes(
        n: usize,
    ) -> (SqliteDagStore, Vec<exo_core::types::Hash256>) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteDagStore::open(dir.path()).unwrap();
        let sign_fn = make_sign_fn();
        let did = test_did();

        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let mut hashes = Vec::new();

        let mut parents = vec![];
        for i in 0..n {
            let payload = format!("node-{i}");
            let node = append(
                &mut dag,
                &parents,
                payload.as_bytes(),
                &did,
                &*sign_fn,
                &mut clock,
            )
            .unwrap();
            let hash = node.hash;
            store.put(node).unwrap();
            store.mark_committed(&hash, (i + 1) as u64).unwrap();
            hashes.push(hash);
            parents = vec![hash];
        }

        // Leak the tempdir so the store remains valid.
        std::mem::forget(dir);
        (store, hashes)
    }

    #[test]
    fn committed_nodes_in_range_returns_ordered() {
        let (store, hashes) = build_store_with_committed_nodes(5);

        let range = store.committed_nodes_in_range(2, 4).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].0, hashes[1]); // height 2
        assert_eq!(range[1].0, hashes[2]); // height 3
        assert_eq!(range[2].0, hashes[3]); // height 4
        assert_eq!(range[0].1, 2);
        assert_eq!(range[2].1, 4);
    }

    #[test]
    fn committed_dag_nodes_in_range_returns_full_nodes() {
        let (store, _hashes) = build_store_with_committed_nodes(3);

        let nodes = store.committed_dag_nodes_in_range(1, 3).unwrap();
        assert_eq!(nodes.len(), 3);
        // DagNode stores payload_hash, not raw payload — verify nodes are valid.
        for node in &nodes {
            assert_ne!(node.hash, exo_core::types::Hash256::ZERO);
            assert_ne!(node.payload_hash, exo_core::types::Hash256::ZERO);
        }
    }

    #[test]
    fn committed_nodes_in_range_empty_range() {
        let (store, _) = build_store_with_committed_nodes(3);
        let range = store.committed_nodes_in_range(10, 20).unwrap();
        assert!(range.is_empty());
    }

    #[tokio::test]
    async fn sync_engine_serves_snapshot() {
        let (store, _hashes) = build_store_with_committed_nodes(10);
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(
            SyncConfig {
                node_did: test_did(),
                chunk_size: 5,
                max_sync_nodes: 200,
            },
            store,
            net_handle,
            event_tx,
        );

        // Simulate a snapshot request from a peer.
        let request = StateSnapshotRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            from_height: 1,
            chunk_size: 5,
        };

        engine.handle_snapshot_request(request).await;

        // Collect published messages.
        let mut published = Vec::new();
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                crate::network::NetworkCommand::Publish { message, .. } => {
                    published.push(message);
                }
                _ => {}
            }
        }

        // Should have 2 chunks (5 nodes each, total 10).
        assert_eq!(
            published.len(),
            2,
            "Should send 2 chunks for 10 nodes with chunk_size=5"
        );

        // First chunk: heights 1-5
        match &published[0] {
            WireMessage::StateSnapshotChunk(chunk) => {
                assert_eq!(chunk.from_height, 1);
                assert_eq!(chunk.to_height, 5);
                assert_eq!(chunk.nodes.len(), 5);
                assert!(chunk.has_more);
            }
            _ => panic!("Expected StateSnapshotChunk"),
        }

        // Second chunk: heights 6-10
        match &published[1] {
            WireMessage::StateSnapshotChunk(chunk) => {
                assert_eq!(chunk.from_height, 6);
                assert_eq!(chunk.to_height, 10);
                assert_eq!(chunk.nodes.len(), 5);
                assert!(!chunk.has_more);
            }
            _ => panic!("Expected StateSnapshotChunk"),
        }

        // Check sync events were emitted.
        let mut events = Vec::new();
        while let Ok(ev) = event_rx.try_recv() {
            events.push(ev);
        }
        assert_eq!(events.len(), 2, "Should emit 2 ServedSnapshot events");
    }

    #[tokio::test]
    async fn sync_engine_receives_and_applies_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            SyncConfig {
                node_did: test_did(),
                chunk_size: 100,
                max_sync_nodes: 200,
            },
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        // Build some nodes to send in a chunk.
        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();

        let node1 = append(&mut dag, &[], b"synced-1", &did, &*sign_fn, &mut clock).unwrap();
        let node2 = append(
            &mut dag,
            &[node1.hash],
            b"synced-2",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        // Simulate receiving a snapshot chunk.
        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node1.clone(), node2.clone()],
            to_height: 2,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        // Verify nodes were stored and committed.
        {
            let st = store.lock().unwrap();
            assert!(st.contains(&node1.hash).unwrap());
            assert!(st.contains(&node2.hash).unwrap());
            assert_eq!(st.committed_height_value(), 2);
        }

        // Verify sync completed.
        assert!(!engine.needs_sync());

        // Check events.
        let mut events = Vec::new();
        while let Ok(ev) = event_rx.try_recv() {
            events.push(ev);
        }
        assert!(events.len() >= 2); // Progress + Complete

        // Should have a Complete event.
        let complete = events
            .iter()
            .any(|e| matches!(e, SyncEvent::Complete { .. }));
        assert!(complete, "Should emit SyncEvent::Complete");
    }

    #[tokio::test]
    async fn sync_engine_skips_request_when_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, _event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(
            SyncConfig {
                node_did: test_did(),
                chunk_size: 100,
                max_sync_nodes: 200,
            },
            store,
            net_handle,
            event_tx,
        );

        // Request snapshot from height 5, but our store is empty (height 0).
        let request = StateSnapshotRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            from_height: 5,
            chunk_size: 10,
        };

        engine.handle_snapshot_request(request).await;

        // Should not publish anything since we're behind.
        assert!(
            cmd_rx.try_recv().is_err(),
            "Should not serve snapshot when behind"
        );
    }

    #[tokio::test]
    async fn request_sync_publishes_request() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            SyncConfig {
                node_did: test_did(),
                chunk_size: 50,
                max_sync_nodes: 200,
            },
            store,
            net_handle,
            event_tx,
        );

        engine.request_sync().await.unwrap();
        assert!(engine.needs_sync());

        // Check that a request was published.
        let cmd = cmd_rx.try_recv().unwrap();
        match cmd {
            crate::network::NetworkCommand::Publish { message, .. } => {
                match message {
                    WireMessage::StateSnapshotRequest(req) => {
                        assert_eq!(req.from_height, 1); // height 0 + 1
                        assert_eq!(req.chunk_size, 50);
                    }
                    _ => panic!("Expected StateSnapshotRequest"),
                }
            }
            _ => panic!("Expected Publish command"),
        }
    }

    #[tokio::test]
    async fn dag_sync_request_served() {
        let (store, _hashes) = build_store_with_committed_nodes(5);
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, _event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(
            SyncConfig {
                node_did: test_did(),
                chunk_size: 100,
                max_sync_nodes: 200,
            },
            store,
            net_handle,
            event_tx,
        );

        // Request DAG sync with different tips (triggers response).
        let request = DagSyncRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            tip_hashes: vec![], // Empty tips = we have nothing
            max_nodes: 10,
        };

        engine.handle_dag_sync_request(request).await;

        // Should respond with some nodes.
        let cmd = cmd_rx.try_recv().unwrap();
        match cmd {
            crate::network::NetworkCommand::Publish { message, .. } => match message {
                WireMessage::DagSyncResponse(resp) => {
                    assert!(!resp.nodes.is_empty(), "Should send some nodes");
                    assert!(resp.nodes.len() <= 10);
                }
                _ => panic!("Expected DagSyncResponse"),
            },
            _ => panic!("Expected Publish command"),
        }
    }
}
