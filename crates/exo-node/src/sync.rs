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

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use exo_core::{
    crypto,
    hlc::HybridClock,
    types::{Did, Hash256, PublicKey, Timestamp},
};
use exo_dag::{
    append::verify_node_creator_signature,
    consensus::{CommitCertificate, ConsensusConfig},
    dag::{DagNode, compute_node_hash},
    error::{DagError, Result as DagResult},
};
use tokio::sync::mpsc;

use crate::{
    identity,
    network::{NetworkEvent, NetworkHandle},
    store::SqliteDagStore,
    wire::{
        DagSyncRequestMsg, DagSyncResponseMsg, HlcSyncMsg, StateSnapshotChunkMsg,
        StateSnapshotRequestMsg, WireMessage, topics,
    },
};

const MAX_SNAPSHOT_CHUNK_SIZE: u32 = 500;
const MAX_HLC_ANOMALY_EVIDENCE: usize = 1024;

// ---------------------------------------------------------------------------
// Distributed HLC sync anomaly evidence (VCG-012 / D6)
// ---------------------------------------------------------------------------
//
// Per ratified decision D6 (2026-07-02), any drift, replay, or partition
// anomaly detected while syncing HLC timestamps over the wire is a
// constitutional event — it must be recorded as a retrievable DAG evidence
// object, never only emitted as a log line, because deliberation order is
// legitimacy-relevant.

/// A recorded HLC anomaly — a constitutional event describing a rejected or
/// suspect remote timestamp observed during distributed HLC sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlcAnomalyEvidence {
    /// The physical millisecond component of the anomalous remote timestamp.
    pub anomaly_physical_ms: u64,
    /// The logical counter of the anomalous remote timestamp.
    pub anomaly_logical: u32,
    /// Human-readable reason the timestamp was flagged (drift, overflow, etc.).
    pub reason: String,
}

/// Bounded recorder for HLC anomaly evidence objects.
///
/// This is intentionally the minimal, in-process DAG-evidence surface for
/// VCG-012: every anomaly recorded here is retrievable, ordered, and never
/// only a log line. Production wiring may persist these into the durable DAG
/// evidence store; the in-process recorder keeps a bounded latest-evidence
/// window so unauthenticated or drifted network traffic cannot exhaust memory.
#[derive(Debug, Default)]
pub struct HlcAnomalyRecorder {
    evidence: Mutex<VecDeque<HlcAnomalyEvidence>>,
}

impl HlcAnomalyRecorder {
    /// Create an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new anomaly evidence object.
    fn record(&self, evidence: HlcAnomalyEvidence) {
        let mut guard = self
            .evidence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() == MAX_HLC_ANOMALY_EVIDENCE {
            guard.pop_front();
        }
        guard.push_back(evidence);
    }

    /// Return all recorded anomaly evidence objects, in recording order.
    #[must_use]
    pub fn recorded_evidence(&self) -> Vec<HlcAnomalyEvidence> {
        self.evidence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

fn validate_hlc_sync_authority(msg: &HlcSyncMsg) -> Result<(), String> {
    let derived_did = identity::did_from_public_key(&msg.public_key)
        .map_err(|error| format!("HLC sync public key did derivation failed: {error}"))?;
    if derived_did != msg.sender {
        return Err(format!(
            "HLC sync sender {} does not match signing public key DID {}",
            msg.sender, derived_did
        ));
    }

    let payload = msg.payload_to_verify()?;
    if !crypto::verify(&payload, &msg.signature, &msg.public_key) {
        return Err("HLC sync signature verification failed".to_owned());
    }

    Ok(())
}

/// Observe a remote HLC timestamp received over the wire: merge it into
/// `clock` via [`HybridClock::update`], recording a DAG evidence object via
/// `recorder` if the merge fails (excessive drift, overflow, etc.) instead of
/// only logging the failure.
///
/// # Errors
///
/// Propagates the same error `HybridClock::update` returns — the clock
/// layer's fail-closed guards are never weakened or bypassed here; this
/// function only adds constitutional-evidence recording around them.
pub fn observe_remote_hlc_timestamp(
    clock: &mut HybridClock,
    remote: &Timestamp,
    recorder: &HlcAnomalyRecorder,
) -> exo_core::Result<Timestamp> {
    match clock.update(remote) {
        Ok(advanced) => Ok(advanced),
        Err(err) => {
            recorder.record(HlcAnomalyEvidence {
                anomaly_physical_ms: remote.physical_ms,
                anomaly_logical: remote.logical,
                reason: err.to_string(),
            });
            Err(err)
        }
    }
}

fn static_did(value: &'static str) -> Did {
    match Did::new(value) {
        Ok(did) => did,
        Err(error) => unreachable!("hardcoded sync DID {value} must be valid: {error}"),
    }
}

fn normalized_snapshot_chunk_size(chunk_size: u32) -> u32 {
    chunk_size.clamp(1, MAX_SNAPSHOT_CHUNK_SIZE)
}

fn next_sync_from_height(local_height: u64) -> anyhow::Result<u64> {
    local_height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("cannot advance committed height past u64::MAX"))
}

fn snapshot_chunk_to_height(current_from: u64, chunk_size: u32, local_height: u64) -> u64 {
    let span = u64::from(normalized_snapshot_chunk_size(chunk_size)).saturating_sub(1);
    current_from.saturating_add(span).min(local_height)
}

fn next_snapshot_from_height(to_height: u64) -> Option<u64> {
    to_height.checked_add(1)
}

fn snapshot_node_height(from_height: u64, index: usize) -> anyhow::Result<u64> {
    let offset = u64::try_from(index)
        .map_err(|_| anyhow::anyhow!("snapshot node index does not fit in u64"))?;
    let height = from_height.checked_add(offset).ok_or_else(|| {
        anyhow::anyhow!("snapshot node height overflow: from_height {from_height} + index {index}")
    })?;
    i64::try_from(height).map_err(|_| {
        anyhow::anyhow!("snapshot node height {height} exceeds SQLite INTEGER maximum")
    })?;
    Ok(height)
}

// ---------------------------------------------------------------------------
// Sync configuration
// ---------------------------------------------------------------------------

/// Configuration for the sync engine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// This node's DID.
    pub node_did: Did,
    /// Public keys authorized to sign externally synced DAG nodes.
    pub validator_public_keys: BTreeMap<Did, PublicKey>,
    /// Maximum number of nodes per snapshot chunk.
    pub chunk_size: u32,
    /// Maximum number of nodes per DAG sync response.
    pub max_sync_nodes: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            node_did: static_did("did:exo:default"),
            validator_public_keys: BTreeMap::new(),
            chunk_size: 100,
            max_sync_nodes: 200,
        }
    }
}

fn validate_incoming_sync_node(
    store: &SqliteDagStore,
    accepted_nodes: &BTreeMap<exo_core::types::Hash256, DagNode>,
    node: &DagNode,
    public_keys: &BTreeMap<Did, PublicKey>,
) -> DagResult<()> {
    let mut sorted_parents = node.parents.clone();
    sorted_parents.sort();
    sorted_parents.dedup();
    if sorted_parents != node.parents {
        return Err(DagError::InvalidSignature(node.hash));
    }

    let expected_hash = compute_node_hash(
        &node.parents,
        &node.payload_hash,
        &node.creator_did,
        &node.timestamp,
    )?;
    if expected_hash != node.hash {
        return Err(DagError::InvalidSignature(node.hash));
    }

    for parent_hash in &node.parents {
        let stored_parent = if let Some(parent) = accepted_nodes.get(parent_hash) {
            Some(parent.clone())
        } else {
            store.get_sync(parent_hash)?
        };
        let parent = stored_parent.ok_or(DagError::ParentNotFound(*parent_hash))?;
        if node.timestamp <= parent.timestamp {
            return Err(DagError::StoreError(format!(
                "causality violation: synced node timestamp {:?} <= parent timestamp {:?}",
                node.timestamp, parent.timestamp
            )));
        }
    }

    let resolver = |did: &Did| public_keys.get(did).copied();
    verify_node_creator_signature(node, &resolver)
}

fn validate_snapshot_commit_certificates(
    nodes_with_heights: &[(DagNode, u64)],
    certificates: &[CommitCertificate],
    public_keys: &BTreeMap<Did, PublicKey>,
) -> DagResult<()> {
    if certificates.len() != nodes_with_heights.len() {
        return Err(DagError::StoreError(format!(
            "snapshot chunk must include one commit certificate per node: got {} certificates for {} nodes",
            certificates.len(),
            nodes_with_heights.len()
        )));
    }

    for ((node, _height), certificate) in nodes_with_heights.iter().zip(certificates) {
        validate_snapshot_commit_certificate(certificate, &node.hash, public_keys)?;
    }

    Ok(())
}

fn validate_snapshot_commit_certificate(
    certificate: &CommitCertificate,
    node_hash: &Hash256,
    public_keys: &BTreeMap<Did, PublicKey>,
) -> DagResult<()> {
    if certificate.node_hash != *node_hash {
        return Err(DagError::StoreError(format!(
            "snapshot commit certificate node_hash {} does not match DAG node hash {}",
            certificate.node_hash, node_hash
        )));
    }

    let validators: BTreeSet<Did> = public_keys.keys().cloned().collect();
    let quorum = ConsensusConfig::new(validators.clone(), 0).quorum_size();
    if quorum == 0 {
        return Err(DagError::StoreError(
            "snapshot commit certificate cannot be validated with an empty validator set".into(),
        ));
    }

    let mut distinct_voters = BTreeSet::new();
    for vote in &certificate.votes {
        if !validators.contains(&vote.voter) {
            return Err(DagError::StoreError(format!(
                "snapshot commit certificate contains vote from non-validator {}",
                vote.voter
            )));
        }
        if vote.round != certificate.round {
            return Err(DagError::StoreError(format!(
                "snapshot commit certificate vote from {} is for round {}, expected {}",
                vote.voter, vote.round, certificate.round
            )));
        }
        if vote.node_hash != certificate.node_hash {
            return Err(DagError::StoreError(format!(
                "snapshot commit certificate vote from {} references wrong node hash",
                vote.voter
            )));
        }
        if !distinct_voters.insert(vote.voter.clone()) {
            return Err(DagError::StoreError(format!(
                "snapshot commit certificate contains duplicate vote from {} in round {}",
                vote.voter, vote.round
            )));
        }

        let Some(public_key) = public_keys.get(&vote.voter) else {
            return Err(DagError::StoreError(format!(
                "snapshot commit certificate vote from {} has no configured public key",
                vote.voter
            )));
        };
        if !vote.verify_signature(public_key) {
            return Err(DagError::StoreError(format!(
                "snapshot commit certificate vote from {} has invalid signature",
                vote.voter
            )));
        }
    }

    if distinct_voters.len() < quorum {
        return Err(DagError::StoreError(format!(
            "snapshot commit certificate has insufficient quorum: required {}, got {}",
            quorum,
            distinct_voters.len()
        )));
    }

    Ok(())
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
    /// This node's Hybrid Logical Clock, advanced by `HlcSync` wire messages
    /// received over the existing DAG-sync gossipsub channel (VCG-012 / D6).
    /// `Mutex`-wrapped (rather than held by value) so `SyncEngine` stays
    /// `Send + Sync`, matching `HlcAnomalyRecorder` below — `HybridClock`'s
    /// physical source is a boxed `Fn` that is `Send` but not `Sync`.
    hlc: Arc<Mutex<HybridClock>>,
    /// Records HLC drift/replay anomalies as DAG evidence objects rather
    /// than silent log lines (D6: time anomalies are constitutional events).
    hlc_anomalies: Arc<HlcAnomalyRecorder>,
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
            hlc: Arc::new(Mutex::new(HybridClock::new())),
            hlc_anomalies: Arc::new(HlcAnomalyRecorder::new()),
        }
    }

    /// This node's recorded HLC anomaly evidence (drift/replay events
    /// detected while processing `HlcSync` messages).
    #[must_use]
    #[allow(dead_code)] // Constitutional-evidence introspection API; wired to observability once the DAG evidence store lands.
    pub fn hlc_anomalies(&self) -> Vec<HlcAnomalyEvidence> {
        self.hlc_anomalies.recorded_evidence()
    }

    /// This node's current HLC state, after any `HlcSync` updates.
    ///
    /// # Panics
    ///
    /// Panics if the internal HLC mutex is poisoned by a prior panic while
    /// held — the same fail-loud posture the store helpers use elsewhere in
    /// this module.
    #[must_use]
    #[allow(dead_code)] // Introspection API for callers that need this node's post-sync HLC state.
    pub fn hlc_current(&self) -> Timestamp {
        self.hlc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current()
    }

    /// Handle an inbound `HlcSync` wire message: merge the remote timestamp
    /// into this node's `HybridClock`. A drift/replay anomaly is recorded as
    /// a DAG evidence object (D6) rather than only logged.
    async fn handle_hlc_sync(&mut self, msg: HlcSyncMsg) {
        if let Err(err) = validate_hlc_sync_authority(&msg) {
            self.hlc_anomalies.record(HlcAnomalyEvidence {
                anomaly_physical_ms: msg.timestamp.physical_ms,
                anomaly_logical: msg.timestamp.logical,
                reason: err,
            });
            return;
        }

        let mut clock = self
            .hlc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(err) =
            observe_remote_hlc_timestamp(&mut clock, &msg.timestamp, &self.hlc_anomalies)
        {
            tracing::warn!(
                sender = %msg.sender,
                err = %err,
                "HLC sync anomaly recorded as DAG evidence"
            );
        }
    }

    /// Request a state snapshot from the network.
    ///
    /// Called when a node first joins or detects it's behind.
    pub async fn request_sync(&mut self) -> anyhow::Result<()> {
        let local_height = with_store_blocking(Arc::clone(&self.store), "request_sync", |store| {
            store
                .committed_height_value()
                .map_err(|e| anyhow::anyhow!("committed height: {e}"))
        })
        .await?;

        tracing::info!(local_height, "Requesting state snapshot from network");

        let from_height = next_sync_from_height(local_height)?;
        self.syncing = true;

        let request = WireMessage::StateSnapshotRequest(StateSnapshotRequestMsg {
            sender: self.config.node_did.clone(),
            from_height,
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
        let tips = with_store_blocking(Arc::clone(&self.store), "request_dag_sync", |store| {
            store.tips_sync().map_err(|e| anyhow::anyhow!("tips: {e}"))
        })
        .await?;

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
            WireMessage::HlcSync(msg) => {
                self.handle_hlc_sync(msg).await;
            }
            _ => {} // Not a sync message
        }
    }

    /// Serve a state snapshot to a requesting peer.
    async fn handle_snapshot_request(&self, msg: StateSnapshotRequestMsg) {
        let local_height = match with_store_blocking(
            Arc::clone(&self.store),
            "handle_snapshot_request",
            |store| {
                store
                    .committed_height_value()
                    .map_err(|e| anyhow::anyhow!("committed height: {e}"))
            },
        )
        .await
        {
            Ok(height) => height,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to read committed height for snapshot request");
                return;
            }
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
        let chunk_size = normalized_snapshot_chunk_size(msg.chunk_size);

        loop {
            let to_height = snapshot_chunk_to_height(current_from, chunk_size, local_height);

            let (nodes, certificates) = match with_store_blocking(
                Arc::clone(&self.store),
                "handle_snapshot_request_chunk",
                move |store| {
                    let nodes = store
                        .committed_dag_nodes_in_range(current_from, to_height)
                        .map_err(|e| {
                            anyhow::anyhow!("committed nodes {current_from}..={to_height}: {e}")
                        })?;
                    let mut certificates = Vec::with_capacity(nodes.len());
                    for node in &nodes {
                        let certificate =
                            store
                                .load_certificate_for_hash(&node.hash)?
                                .ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "missing commit certificate for snapshot node {}",
                                        node.hash
                                    )
                                })?;
                        certificates.push(certificate);
                    }
                    Ok((nodes, certificates))
                },
            )
            .await
            {
                Ok(nodes_and_certificates) => nodes_and_certificates,
                Err(e) => {
                    tracing::warn!(err = %e, "Failed to query committed nodes and certificates");
                    return;
                }
            };

            let has_more = to_height < local_height;
            let nodes_count = nodes.len();

            let chunk = WireMessage::StateSnapshotChunk(StateSnapshotChunkMsg {
                sender: self.config.node_did.clone(),
                from_height: current_from,
                nodes,
                certificates,
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

            if self
                .event_tx
                .send(SyncEvent::ServedSnapshot {
                    peer: msg.sender.clone(),
                    from_height: current_from,
                    nodes_sent: nodes_count,
                })
                .await
                .is_err()
            {
                tracing::warn!("Sync event receiver dropped (ServedSnapshot)");
            }

            if !has_more {
                break;
            }
            let Some(next_from) = next_snapshot_from_height(to_height) else {
                tracing::warn!(to_height, "Snapshot range cannot advance without overflow");
                break;
            };
            current_from = next_from;
        }
    }

    /// Receive and apply a state snapshot chunk.
    async fn handle_snapshot_chunk(&mut self, msg: StateSnapshotChunkMsg) {
        if !self.syncing {
            tracing::warn!(
                sender = %msg.sender,
                from = msg.from_height,
                to = msg.to_height,
                nodes = msg.nodes.len(),
                "Rejecting unsolicited snapshot chunk"
            );
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
        let from_height = msg.from_height;
        let nodes = msg.nodes;
        let certificates = msg.certificates;
        let public_keys = self.config.validator_public_keys.clone();
        if let Err(e) = with_store_blocking(
            Arc::clone(&self.store),
            "handle_snapshot_chunk",
            move |store| {
                let mut nodes_with_heights = Vec::with_capacity(nodes.len());
                for (i, node) in nodes.into_iter().enumerate() {
                    let height = snapshot_node_height(from_height, i)?;
                    nodes_with_heights.push((node, height));
                }

                let mut accepted_nodes = BTreeMap::new();
                for (node, _) in &nodes_with_heights {
                    validate_incoming_sync_node(store, &accepted_nodes, node, &public_keys)?;
                    accepted_nodes.insert(node.hash, node.clone());
                }

                validate_snapshot_commit_certificates(
                    &nodes_with_heights,
                    &certificates,
                    &public_keys,
                )?;
                store.put_committed_many_with_certificates_sync(
                    &nodes_with_heights,
                    &certificates,
                )?;
                Ok(())
            },
        )
        .await
        {
            tracing::error!(err = %e, "Store access failed in handle_snapshot_chunk");
            return;
        }

        if msg.to_height > self.sync_target_height {
            self.sync_target_height = msg.to_height;
        }

        if self
            .event_tx
            .send(SyncEvent::Progress {
                from_height: msg.from_height,
                to_height: msg.to_height,
                total_nodes: nodes_count,
            })
            .await
            .is_err()
        {
            tracing::warn!("Sync event receiver dropped (Progress)");
        }

        if !msg.has_more {
            self.syncing = false;

            let committed_height = match with_store_blocking(
                Arc::clone(&self.store),
                "handle_snapshot_chunk_complete",
                |store| {
                    store
                        .committed_height_value()
                        .map_err(|e| anyhow::anyhow!("committed height after snapshot: {e}"))
                },
            )
            .await
            {
                Ok(height) => height,
                Err(e) => {
                    tracing::warn!(err = %e, "Failed to read committed height after snapshot");
                    return;
                }
            };

            tracing::info!(committed_height, "State sync complete");

            if self
                .event_tx
                .send(SyncEvent::Complete { committed_height })
                .await
                .is_err()
            {
                tracing::warn!("Sync event receiver dropped (Complete)");
            }
        }
    }

    /// Serve missing DAG nodes to a requesting peer.
    async fn handle_dag_sync_request(&self, msg: DagSyncRequestMsg) {
        let tip_hashes = msg.tip_hashes.clone();
        let max_nodes = msg.max_nodes;
        let (nodes, has_more) = match with_store_blocking(
            Arc::clone(&self.store),
            "handle_dag_sync_request",
            move |store| {
                // Find nodes the requester is missing by comparing tips.
                // Strategy: send all our committed nodes that are not in the
                // requester's tip set (simple but effective for small DAGs).
                let our_tips = store
                    .tips_sync()
                    .map_err(|e| anyhow::anyhow!("tips for sync: {e}"))?;

                // If our tips are the same, nothing to sync.
                if our_tips == tip_hashes {
                    return Ok(None);
                }

                // Get nodes the peer is missing — nodes we have that descend
                // from their tips. For simplicity, we send our committed nodes
                // above the peer's implicit height.
                let local_height = store
                    .committed_height_value()
                    .map_err(|e| anyhow::anyhow!("committed height for DAG sync: {e}"))?;
                let max_nodes_u64 = u64::from(max_nodes.min(500));
                let send_height = if local_height > max_nodes_u64 {
                    local_height - max_nodes_u64
                } else {
                    1
                };

                let nodes = store
                    .committed_dag_nodes_in_range(send_height, local_height)
                    .map_err(|e| anyhow::anyhow!("nodes for sync: {e}"))?;

                let total = nodes.len();
                let max_nodes_usize = usize::try_from(max_nodes).unwrap_or(usize::MAX);
                let truncated = total > max_nodes_usize;
                let nodes = if truncated {
                    nodes.into_iter().take(max_nodes_usize).collect()
                } else {
                    nodes
                };

                Ok(Some((nodes, truncated)))
            },
        )
        .await
        {
            Ok(Some(response)) => response,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to prepare sync response");
                return;
            }
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

        let has_more = msg.has_more;
        let nodes = msg.nodes;
        let public_keys = self.config.validator_public_keys.clone();
        if let Err(e) = with_store_blocking(
            Arc::clone(&self.store),
            "handle_dag_sync_response",
            move |store| {
                let mut accepted_nodes = BTreeMap::new();
                for node in &nodes {
                    validate_incoming_sync_node(store, &accepted_nodes, node, &public_keys)?;
                    accepted_nodes.insert(node.hash, node.clone());
                }

                store.put_many_sync(&nodes)?;
                Ok(())
            },
        )
        .await
        {
            tracing::error!(err = %e, "Store access failed in handle_dag_sync_response");
            return;
        }

        // If there are more nodes, request the next batch.
        if has_more {
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

async fn with_store_blocking<T, F>(
    store: Arc<Mutex<SqliteDagStore>>,
    context: &'static str,
    operation: F,
) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut SqliteDagStore) -> anyhow::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("Store mutex poisoned in {context}"))?;
        operation(&mut store)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Store blocking task failed in {context}: {e}"))?
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
                    | WireMessage::DagSyncResponse(_)
                    | WireMessage::HlcSync(_) => {
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
    use exo_core::{
        crypto::KeyPair,
        types::{Did, Hash256, PublicKey, Signature},
    };
    use exo_dag::{
        consensus::Vote,
        dag::{Dag, DeterministicDagClock, append},
    };
    use tokio::sync::mpsc;

    use super::*;

    fn test_keypair() -> KeyPair {
        KeyPair::from_secret_bytes([0x5C; 32]).expect("valid test secret key")
    }

    fn test_public_key() -> PublicKey {
        *test_keypair().public_key()
    }

    fn test_validator_public_keys() -> BTreeMap<Did, PublicKey> {
        BTreeMap::from([(test_did(), test_public_key())])
    }

    fn sync_config(chunk_size: u32, max_sync_nodes: u32) -> SyncConfig {
        SyncConfig {
            node_did: test_did(),
            validator_public_keys: test_validator_public_keys(),
            chunk_size,
            max_sync_nodes,
        }
    }

    fn signed_hlc_sync(seed: u8, timestamp: Timestamp) -> HlcSyncMsg {
        let keypair = KeyPair::from_secret_bytes([seed; 32]).expect("valid HLC sync keypair");
        let sender = identity::did_from_public_key(keypair.public_key()).unwrap();
        let payload =
            HlcSyncMsg::signing_payload(&sender, &timestamp, keypair.public_key()).unwrap();
        HlcSyncMsg {
            sender,
            timestamp,
            public_key: *keypair.public_key(),
            signature: keypair.sign(&payload),
        }
    }

    fn make_sign_fn() -> Box<dyn Fn(&[u8]) -> Signature> {
        let keypair = test_keypair();
        Box::new(move |data: &[u8]| keypair.sign(data))
    }

    fn commit_certificate_for(node_hash: Hash256, round: u64) -> CommitCertificate {
        let mut vote = Vote {
            voter: test_did(),
            round,
            node_hash,
            signature: Signature::Empty,
        };
        let payload = vote.signing_payload().unwrap();
        vote.signature = test_keypair().sign(&payload);
        CommitCertificate {
            node_hash,
            votes: vec![vote],
            round,
        }
    }

    fn invalid_commit_certificate_for(node_hash: Hash256, round: u64) -> CommitCertificate {
        let mut certificate = commit_certificate_for(node_hash, round);
        certificate.votes[0].signature = Signature::from_bytes([9u8; 64]);
        certificate
    }

    fn test_did() -> Did {
        Did::new("did:exo:test-sync").unwrap()
    }

    fn acking_network_handle() -> (NetworkHandle, Arc<Mutex<Vec<WireMessage>>>) {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let published = Arc::new(Mutex::new(Vec::new()));
        let published_for_task = Arc::clone(&published);

        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    crate::network::NetworkCommand::Publish { message, reply, .. } => {
                        published_for_task.lock().unwrap().push(message);
                        let _ = reply.send(Ok(()));
                    }
                    crate::network::NetworkCommand::PeerCount { reply } => {
                        let _ = reply.send(0);
                    }
                    _ => {}
                }
            }
        });

        (NetworkHandle::new(cmd_tx), published)
    }

    #[test]
    fn sync_engine_store_access_uses_spawn_blocking() {
        let source = include_str!("sync.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "sync engine must isolate synchronous store I/O from Tokio workers"
        );
        assert!(
            !production.contains("self.store.lock()"),
            "async sync-engine paths must not directly block on the store mutex"
        );
    }

    #[test]
    fn production_sync_source_does_not_suppress_security_relevant_clippy_lints() {
        let source = include_str!("sync.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        for lint in [
            "clippy::as_conversions",
            "clippy::single_match",
            "clippy::expect_used",
        ] {
            assert!(
                !production.contains(lint),
                "production sync source must not suppress {lint}"
            );
        }
    }

    #[test]
    fn production_snapshot_sync_requires_commit_certificate_persistence() {
        let source = include_str!("sync.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("validate_snapshot_commit_certificates"),
            "snapshot sync must validate commit certificates before accepting committed nodes"
        );
        assert!(
            production.contains("put_committed_many_with_certificates_sync"),
            "snapshot sync must persist nodes, commit markers, and certificates atomically"
        );
        assert!(
            !production.contains("put_committed_many_sync(&nodes_with_heights)"),
            "snapshot sync must not mark externally supplied nodes committed without certificates"
        );
    }

    #[test]
    fn hlc_anomaly_recorder_keeps_bounded_latest_evidence() {
        let recorder = HlcAnomalyRecorder::new();

        for idx in 0..(MAX_HLC_ANOMALY_EVIDENCE + 17) {
            recorder.record(HlcAnomalyEvidence {
                anomaly_physical_ms: u64::try_from(idx).unwrap(),
                anomaly_logical: 0,
                reason: "test anomaly".to_owned(),
            });
        }

        let evidence = recorder.recorded_evidence();
        assert_eq!(evidence.len(), MAX_HLC_ANOMALY_EVIDENCE);
        assert_eq!(evidence[0].anomaly_physical_ms, 17);
        assert_eq!(
            evidence[MAX_HLC_ANOMALY_EVIDENCE - 1].anomaly_physical_ms,
            u64::try_from(MAX_HLC_ANOMALY_EVIDENCE + 16).unwrap()
        );
    }

    #[tokio::test]
    async fn hlc_sync_rejects_sender_not_bound_to_signing_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));
        let (net_handle, _) = acking_network_handle();
        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(sync_config(50, 200), store, net_handle, event_tx);
        let original_clock = engine.hlc_current();
        let mut forged = signed_hlc_sync(42, Timestamp::new(original_clock.physical_ms + 100, 1));
        forged.sender = Did::new("did:exo:forged-hlc-sender").unwrap();

        engine.handle_message(WireMessage::HlcSync(forged)).await;

        assert_eq!(
            engine.hlc_current(),
            original_clock,
            "forged HLC sync must not advance the local clock"
        );
        let anomalies = engine.hlc_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert!(
            anomalies[0]
                .reason
                .contains("does not match signing public key DID"),
            "forged HLC sync rejection must be recorded as evidence"
        );
    }

    #[test]
    fn next_sync_from_height_rejects_u64_max() {
        let err = next_sync_from_height(u64::MAX).expect_err("u64::MAX cannot advance");

        assert!(err.to_string().contains("cannot advance committed height"));
    }

    #[test]
    fn snapshot_chunk_to_height_saturates_without_overflow() {
        let to_height = snapshot_chunk_to_height(u64::MAX - 1, 500, u64::MAX);

        assert_eq!(to_height, u64::MAX);
    }

    #[test]
    fn next_snapshot_from_height_rejects_u64_max() {
        assert_eq!(next_snapshot_from_height(u64::MAX), None);
        assert_eq!(next_snapshot_from_height(41), Some(42));
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
        let mut clock = DeterministicDagClock::new();
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
            store.put_sync(node).unwrap();
            let committed_height = u64::try_from(i + 1).expect("test height fits in u64");
            store.mark_committed_sync(&hash, committed_height).unwrap();
            store
                .save_certificate(&commit_certificate_for(hash, committed_height))
                .unwrap();
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

        let (net_handle, published) = acking_network_handle();

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(sync_config(5, 200), store, net_handle, event_tx);

        // Simulate a snapshot request from a peer.
        let request = StateSnapshotRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            from_height: 1,
            chunk_size: 5,
        };

        engine.handle_snapshot_request(request).await;

        // Collect published messages.
        let published = published.lock().unwrap().clone();

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
                assert_eq!(chunk.certificates.len(), 5);
                for (node, certificate) in chunk.nodes.iter().zip(&chunk.certificates) {
                    assert_eq!(certificate.node_hash, node.hash);
                }
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
                assert_eq!(chunk.certificates.len(), 5);
                for (node, certificate) in chunk.nodes.iter().zip(&chunk.certificates) {
                    assert_eq!(certificate.node_hash, node.hash);
                }
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
    async fn sync_engine_refuses_to_serve_snapshot_node_without_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteDagStore::open(dir.path()).unwrap();
        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"uncertified-local-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        store.put_sync(node.clone()).unwrap();
        store.mark_committed_sync(&node.hash, 1).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(sync_config(5, 200), store, net_handle, event_tx);

        let request = StateSnapshotRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            from_height: 1,
            chunk_size: 5,
        };

        engine.handle_snapshot_request(request).await;

        assert!(
            published.lock().unwrap().is_empty(),
            "snapshot serving must fail closed when a committed node lacks a certificate"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "failed snapshot serving must not emit served events"
        );
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
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        // Build some nodes to send in a chunk.
        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();

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
            certificates: vec![
                commit_certificate_for(node1.hash, 1),
                commit_certificate_for(node2.hash, 2),
            ],
            to_height: 2,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        // Verify nodes were stored and committed.
        {
            let st = store.lock().unwrap();
            assert!(st.contains_sync(&node1.hash).unwrap());
            assert!(st.contains_sync(&node2.hash).unwrap());
            assert_eq!(st.committed_height_value().unwrap(), 2);
            assert_eq!(st.load_certificates().unwrap().len(), 2);
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
    async fn snapshot_chunk_without_commit_certificate_is_rejected_without_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"certless-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node.clone()],
            certificates: vec![],
            to_height: 1,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        let st = store.lock().unwrap();
        assert!(
            !st.contains_sync(&node.hash).unwrap(),
            "certificate-less snapshot chunks must not persist DAG nodes"
        );
        assert_eq!(st.committed_height_value().unwrap(), 0);
        assert!(
            event_rx.try_recv().is_err(),
            "certificate-less snapshot chunks must not emit progress or completion"
        );
    }

    #[tokio::test]
    async fn snapshot_chunk_rejects_certificate_for_different_node_without_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"mismatched-certificate-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node.clone()],
            certificates: vec![commit_certificate_for(Hash256::digest(b"wrong-node"), 1)],
            to_height: 1,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        let st = store.lock().unwrap();
        assert!(
            !st.contains_sync(&node.hash).unwrap(),
            "snapshot chunks with mismatched certificates must not persist DAG nodes"
        );
        assert_eq!(st.committed_height_value().unwrap(), 0);
        assert!(
            event_rx.try_recv().is_err(),
            "mismatched certificates must not emit progress or completion"
        );
    }

    #[tokio::test]
    async fn snapshot_chunk_rejects_invalid_commit_certificate_without_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"invalid-certificate-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node.clone()],
            certificates: vec![invalid_commit_certificate_for(node.hash, 1)],
            to_height: 1,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        let st = store.lock().unwrap();
        assert!(
            !st.contains_sync(&node.hash).unwrap(),
            "snapshot chunks with invalid certificates must not persist DAG nodes"
        );
        assert_eq!(st.committed_height_value().unwrap(), 0);
        assert!(
            event_rx.try_recv().is_err(),
            "invalid certificates must not emit progress or completion"
        );
    }

    #[tokio::test]
    async fn snapshot_chunk_rejects_forged_node_signature() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let mut node = append(
            &mut dag,
            &[],
            b"forged-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        node.signature = Signature::from_bytes([0u8; 64]);

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node.clone()],
            certificates: vec![commit_certificate_for(node.hash, 1)],
            to_height: 1,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        let st = store.lock().unwrap();
        assert!(
            !st.contains_sync(&node.hash).unwrap(),
            "sync must reject forged DAG nodes before persistence"
        );
        assert_eq!(st.committed_height_value().unwrap(), 0);
        assert!(
            event_rx.try_recv().is_err(),
            "rejected forged chunks must not emit progress or completion"
        );
    }

    #[tokio::test]
    async fn dag_sync_response_rejects_forged_node_signature() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let mut node = append(
            &mut dag,
            &[],
            b"forged-dag-sync-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        node.signature = Signature::from_bytes([0u8; 64]);

        let response = DagSyncResponseMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            nodes: vec![node.clone()],
            has_more: false,
        };

        engine.handle_dag_sync_response(response).await;

        let st = store.lock().unwrap();
        assert!(
            !st.contains_sync(&node.hash).unwrap(),
            "DAG sync responses must reject forged nodes before persistence"
        );
    }

    #[tokio::test]
    async fn unsolicited_snapshot_chunk_is_rejected_without_mutating_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"unsolicited-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:unsolicited-sender").unwrap(),
            from_height: 1,
            nodes: vec![node.clone()],
            certificates: vec![],
            to_height: 1,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        {
            let st = store.lock().unwrap();
            assert!(
                !st.contains_sync(&node.hash).unwrap(),
                "unsolicited snapshot chunks must not write DAG nodes"
            );
            assert_eq!(
                st.committed_height_value().unwrap(),
                0,
                "unsolicited snapshot chunks must not mark committed heights"
            );
        }
        assert!(
            event_rx.try_recv().is_err(),
            "rejected unsolicited chunks must not emit sync progress or completion"
        );
    }

    #[tokio::test]
    async fn snapshot_chunk_with_overflowing_node_height_is_rejected_without_partial_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();

        let node1 = append(&mut dag, &[], b"overflow-1", &did, &*sign_fn, &mut clock).unwrap();
        let node2 = append(
            &mut dag,
            &[node1.hash],
            b"overflow-2",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let node3 = append(
            &mut dag,
            &[node2.hash],
            b"overflow-3",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: u64::MAX - 1,
            nodes: vec![node1.clone(), node2.clone(), node3.clone()],
            certificates: vec![
                commit_certificate_for(node1.hash, 1),
                commit_certificate_for(node2.hash, 2),
                commit_certificate_for(node3.hash, 3),
            ],
            to_height: u64::MAX,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        let st = store.lock().unwrap();
        assert!(
            !st.contains_sync(&node1.hash).unwrap(),
            "overflowing snapshot chunks must be rejected before writing node 1"
        );
        assert!(
            !st.contains_sync(&node2.hash).unwrap(),
            "overflowing snapshot chunks must be rejected before writing node 2"
        );
        assert!(
            !st.contains_sync(&node3.hash).unwrap(),
            "overflowing snapshot chunks must be rejected before writing node 3"
        );
        assert_eq!(st.committed_height_value().unwrap(), 0);
        assert!(
            event_rx.try_recv().is_err(),
            "rejected chunks must not emit progress or completion events"
        );
    }

    #[tokio::test]
    async fn snapshot_chunk_storage_failure_does_not_emit_progress_or_complete() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let db_path = dir.path().join("dag.db");
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"storage-failure-snapshot-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_synced_snapshot_node
                 BEFORE INSERT ON dag_nodes
                 BEGIN
                   SELECT RAISE(FAIL, 'reject synced snapshot node');
                 END;",
            )
            .unwrap();

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node.clone()],
            certificates: vec![commit_certificate_for(node.hash, 1)],
            to_height: 1,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        assert!(
            engine.needs_sync(),
            "snapshot storage failure must keep sync incomplete"
        );
        assert!(
            event_rx.try_recv().is_err(),
            "snapshot storage failure must not emit progress or completion events"
        );
    }

    #[tokio::test]
    async fn snapshot_chunk_storage_failure_rolls_back_partial_batch() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let db_path = dir.path().join("dag.db");
        let store = Arc::new(Mutex::new(store));

        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node1 = append(
            &mut dag,
            &[],
            b"partial-storage-snapshot-node-1",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let node2 = append(
            &mut dag,
            &[node1.hash],
            b"partial-storage-snapshot-node-2",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let rejected_hash = hex::encode(node2.hash.0);
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TRIGGER reject_second_snapshot_node
                 BEFORE INSERT ON dag_nodes
                 WHEN NEW.hash = X'{rejected_hash}'
                 BEGIN
                   SELECT RAISE(FAIL, 'reject second snapshot node');
                 END;"
            ))
            .unwrap();

        engine.syncing = true;
        let chunk = StateSnapshotChunkMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            from_height: 1,
            nodes: vec![node1.clone(), node2.clone()],
            certificates: vec![
                commit_certificate_for(node1.hash, 1),
                commit_certificate_for(node2.hash, 2),
            ],
            to_height: 2,
            has_more: false,
        };

        engine.handle_snapshot_chunk(chunk).await;

        {
            let st = store.lock().unwrap();
            assert!(
                !st.contains_sync(&node1.hash).unwrap(),
                "snapshot batch failure must roll back node 1"
            );
            assert!(
                !st.contains_sync(&node2.hash).unwrap(),
                "snapshot batch failure must not persist node 2"
            );
            assert_eq!(st.committed_height_value().unwrap(), 0);
        }
        assert!(engine.needs_sync());
        assert!(
            event_rx.try_recv().is_err(),
            "rolled-back snapshot chunks must not emit progress or completion events"
        );
    }

    #[tokio::test]
    async fn dag_sync_response_storage_failure_does_not_request_next_batch() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let db_path = dir.path().join("dag.db");
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();
        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"storage-failure-dag-response-node",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_synced_dag_response_node
                 BEFORE INSERT ON dag_nodes
                 BEGIN
                   SELECT RAISE(FAIL, 'reject synced dag response node');
                 END;",
            )
            .unwrap();

        let response = DagSyncResponseMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            nodes: vec![node],
            has_more: true,
        };

        engine.handle_dag_sync_response(response).await;

        assert!(
            published.lock().unwrap().is_empty(),
            "DAG sync storage failure must not request the next batch"
        );
    }

    #[tokio::test]
    async fn dag_sync_response_storage_failure_rolls_back_partial_batch() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let db_path = dir.path().join("dag.db");
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();
        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(
            sync_config(100, 200),
            Arc::clone(&store),
            net_handle,
            event_tx,
        );

        let sign_fn = make_sign_fn();
        let did = test_did();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node1 = append(
            &mut dag,
            &[],
            b"partial-storage-dag-response-node-1",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let node2 = append(
            &mut dag,
            &[node1.hash],
            b"partial-storage-dag-response-node-2",
            &did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let rejected_hash = hex::encode(node2.hash.0);
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TRIGGER reject_second_dag_response_node
                 BEFORE INSERT ON dag_nodes
                 WHEN NEW.hash = X'{rejected_hash}'
                 BEGIN
                   SELECT RAISE(FAIL, 'reject second dag response node');
                 END;"
            ))
            .unwrap();

        let response = DagSyncResponseMsg {
            sender: Did::new("did:exo:sender").unwrap(),
            nodes: vec![node1.clone(), node2.clone()],
            has_more: true,
        };

        engine.handle_dag_sync_response(response).await;

        {
            let st = store.lock().unwrap();
            assert!(
                !st.contains_sync(&node1.hash).unwrap(),
                "DAG sync batch failure must roll back node 1"
            );
            assert!(
                !st.contains_sync(&node2.hash).unwrap(),
                "DAG sync batch failure must not persist node 2"
            );
        }
        assert!(
            published.lock().unwrap().is_empty(),
            "rolled-back DAG sync failure must not request the next batch"
        );
    }

    #[tokio::test]
    async fn sync_engine_skips_request_when_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();

        let (event_tx, _event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(sync_config(100, 200), store, net_handle, event_tx);

        // Request snapshot from height 5, but our store is empty (height 0).
        let request = StateSnapshotRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            from_height: 5,
            chunk_size: 10,
        };

        engine.handle_snapshot_request(request).await;

        // Should not publish anything since we're behind.
        assert!(
            published.lock().unwrap().is_empty(),
            "Should not serve snapshot when behind"
        );
    }

    #[tokio::test]
    async fn request_sync_publishes_request() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();

        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(sync_config(50, 200), store, net_handle, event_tx);

        engine.request_sync().await.unwrap();
        assert!(engine.needs_sync());

        // Check that a request was published.
        let published = published.lock().unwrap();
        match published.first().expect("snapshot request published") {
            WireMessage::StateSnapshotRequest(req) => {
                assert_eq!(req.from_height, 1); // height 0 + 1
                assert_eq!(req.chunk_size, 50);
            }
            _ => panic!("Expected StateSnapshotRequest"),
        }
    }

    #[tokio::test]
    async fn request_sync_fails_closed_on_store_height_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("dag.db")).unwrap();
        let hash = [0xA5u8; 32];
        conn.execute(
            "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
            rusqlite::params![hash.as_slice(), -1_i64],
        )
        .unwrap();
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();
        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut engine = SyncEngine::new(sync_config(50, 200), store, net_handle, event_tx);

        let err = engine.request_sync().await.unwrap_err();

        assert!(err.to_string().contains("committed.height"));
        assert!(!engine.needs_sync());
        assert!(published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dag_sync_request_served() {
        let (store, _hashes) = build_store_with_committed_nodes(5);
        let store = Arc::new(Mutex::new(store));

        let (net_handle, published) = acking_network_handle();

        let (event_tx, _event_rx) = mpsc::channel(32);
        let engine = SyncEngine::new(sync_config(100, 200), store, net_handle, event_tx);

        // Request DAG sync with different tips (triggers response).
        let request = DagSyncRequestMsg {
            sender: Did::new("did:exo:requester").unwrap(),
            tip_hashes: vec![], // Empty tips = we have nothing
            max_nodes: 10,
        };

        engine.handle_dag_sync_request(request).await;

        // Should respond with some nodes.
        let published = published.lock().unwrap();
        match published.first().expect("DAG sync response published") {
            WireMessage::DagSyncResponse(resp) => {
                assert!(!resp.nodes.is_empty(), "Should send some nodes");
                assert!(resp.nodes.len() <= 10);
            }
            _ => panic!("Expected DagSyncResponse"),
        }
    }
}
