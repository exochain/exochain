//! Consensus reactor — drives DAG-BFT consensus over the P2P network.
//!
//! The reactor is a Tokio task that:
//! 1. Receives consensus messages (proposals, votes, commits) from the network
//! 2. Validates them through the existing `exo-dag::consensus` protocol
//! 3. Applies committed state to the local `DagStore`
//! 4. Broadcasts outbound consensus messages via the network handle
//! 5. Drives round advancement on timeout
//!
//! This module wires the existing fully-tested consensus code (`propose()`,
//! `vote()`, `check_commit()`, `commit()`) into a network-aware reactor
//! without modifying the consensus protocol itself.

#![allow(clippy::as_conversions, clippy::type_complexity, clippy::single_match)]

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use exo_core::types::{Did, Hash256, ReceiptOutcome, Signature, Timestamp, TrustReceipt};
use exo_dag::{
    consensus::{self, ConsensusConfig, ConsensusState, Vote},
    dag::{Dag, DagNode, HybridClock, append},
};
use tokio::sync::mpsc;

use crate::{
    network::NetworkHandle,
    store::SqliteDagStore,
    wire::{
        ConsensusCommitMsg, ConsensusProposalMsg, ConsensusVoteMsg, GovernanceEventMsg,
        GovernanceEventType, WireMessage, topics,
    },
};

// ---------------------------------------------------------------------------
// Reactor state
// ---------------------------------------------------------------------------

/// Shared state for the consensus reactor, accessible from the API layer.
pub struct ReactorState {
    /// The BFT consensus state (rounds, votes, certificates).
    pub consensus: ConsensusState,
    /// The local DAG — used by submit_proposal via struct destructuring.
    #[allow(dead_code)]
    pub dag: Dag,
    /// The hybrid logical clock — used by submit_proposal via struct destructuring.
    #[allow(dead_code)]
    pub clock: HybridClock,
    /// This node's DID.
    pub node_did: Did,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Sign function using this node's key.
    sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
}

impl std::fmt::Debug for ReactorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReactorState")
            .field("consensus", &self.consensus)
            .field("node_did", &self.node_did)
            .field("is_validator", &self.is_validator)
            .finish_non_exhaustive()
    }
}

/// Thread-safe handle to reactor state.
pub type SharedReactorState = Arc<Mutex<ReactorState>>;

/// Events the reactor sends to the application layer.
#[derive(Debug, Clone)]
pub enum ReactorEvent {
    /// A DAG node was committed with a BFT certificate.
    NodeCommitted {
        hash: Hash256,
        height: u64,
        round: u64,
    },
    /// A new round started.
    RoundAdvanced { round: u64 },
    /// A governance event was received from the network.
    GovernanceEventReceived { event: GovernanceEventMsg },
}

/// Configuration for the reactor.
#[derive(Debug, Clone)]
pub struct ReactorConfig {
    /// This node's DID.
    pub node_did: Did,
    /// Whether this node participates as a BFT validator.
    pub is_validator: bool,
    /// Initial validator set DIDs.
    pub validators: BTreeSet<Did>,
    /// Round timeout in milliseconds.
    pub round_timeout_ms: u64,
}

// ---------------------------------------------------------------------------
// Reactor construction
// ---------------------------------------------------------------------------

/// Create the initial reactor state, restoring persisted round and
/// committed certificates from the store if available.
pub fn create_reactor_state(
    config: &ReactorConfig,
    sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    store: Option<&Arc<Mutex<SqliteDagStore>>>,
) -> SharedReactorState {
    let consensus_config = ConsensusConfig::new(config.validators.clone(), config.round_timeout_ms);
    let mut consensus_state = ConsensusState::new(consensus_config);

    // Restore persisted consensus state if a store is provided.
    if let Some(store_arc) = store {
        let st = match store_arc.lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("Store mutex poisoned during reactor state restore");
                return Arc::new(Mutex::new(ReactorState {
                    consensus: consensus_state,
                    dag: Dag::new(),
                    clock: HybridClock::new(),
                    node_did: config.node_did.clone(),
                    is_validator: config.is_validator,
                    sign_fn,
                }));
            }
        };

        // Restore the round number.
        if let Ok(round) = st.load_consensus_round() {
            if round > 0 {
                while consensus_state.current_round < round {
                    consensus_state.advance_round();
                }
                tracing::info!(round, "Restored consensus round from store");
            }
        }

        // Restore commit certificates.
        if let Ok(certs) = st.load_certificates() {
            let count = certs.len();
            for cert in certs {
                if !consensus::is_finalized(&consensus_state, &cert.node_hash) {
                    consensus::commit(&mut consensus_state, cert);
                }
            }
            if count > 0 {
                tracing::info!(count, "Restored commit certificates from store");
            }
        }

        // Restore votes for the current round (pending quorum).
        if let Ok(votes) = st.load_votes_for_round(consensus_state.current_round) {
            let count = votes.len();
            for vote in votes {
                let _ = consensus::vote(&mut consensus_state, vote);
            }
            if count > 0 {
                tracing::info!(
                    count,
                    round = consensus_state.current_round,
                    "Restored pending votes"
                );
            }
        }

        // Restore persisted validator set (may have been changed via governance).
        if let Ok(persisted_validators) = st.load_validator_set() {
            if !persisted_validators.is_empty() {
                consensus_state.config.validators = persisted_validators;
                tracing::info!(
                    validators = consensus_state.config.validators.len(),
                    "Restored validator set from store"
                );
            }
        }
    }

    Arc::new(Mutex::new(ReactorState {
        consensus: consensus_state,
        dag: Dag::new(),
        clock: HybridClock::new(),
        node_did: config.node_did.clone(),
        is_validator: config.is_validator,
        sign_fn,
    }))
}

// ---------------------------------------------------------------------------
// Reactor event loop
// ---------------------------------------------------------------------------

/// Run the consensus reactor as a Tokio task.
///
/// Processes network events and drives the BFT consensus protocol.
pub async fn run_reactor(
    state: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
    net_handle: NetworkHandle,
    mut net_events: mpsc::Receiver<crate::network::NetworkEvent>,
    reactor_tx: mpsc::Sender<ReactorEvent>,
) {
    let round_timeout = {
        let s = match state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("Reactor state mutex poisoned — cannot start reactor");
                return;
            }
        };
        Duration::from_millis(s.consensus.config.round_timeout_ms)
    };

    let mut round_timer = tokio::time::interval(round_timeout);
    // Don't try to catch up on missed ticks.
    round_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Process network events
            Some(event) = net_events.recv() => {
                match event {
                    crate::network::NetworkEvent::MessageReceived { message, .. } => {
                        handle_wire_message(
                            &state,
                            &store,
                            &net_handle,
                            &reactor_tx,
                            message,
                        ).await;
                    }
                    _ => {} // Connection events handled by network layer
                }
            }

            // Round timeout — advance to next round
            _ = round_timer.tick() => {
                let round = {
                    let Ok(mut s) = state.lock() else {
                        tracing::error!("Reactor state mutex poisoned in round tick");
                        continue;
                    };
                    s.consensus.advance_round();
                    s.consensus.current_round
                };

                // Persist the new round number.
                {
                    let Ok(mut st) = store.lock() else {
                        tracing::error!("Store mutex poisoned in round persist");
                        continue;
                    };
                    if let Err(e) = st.save_consensus_round(round) {
                        tracing::warn!(err = %e, "Failed to persist round");
                    }
                }

                tracing::debug!(round, "Consensus round advanced");
                if reactor_tx
                    .send(ReactorEvent::RoundAdvanced { round })
                    .await
                    .is_err()
                {
                    tracing::warn!("Reactor event receiver dropped (RoundAdvanced)");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wire message validation — reject before processing
// ---------------------------------------------------------------------------

/// Validate a consensus proposal before processing.
///
/// Checks: proposer is in the current validator set, the attached
/// signature is non-empty, is not a zero-byte sentinel, and the
/// node hash matches the proposal's node_hash.
///
/// **Note (GAP-014 defense-in-depth):** This function is a structural
/// guard only. Until the reactor is wired to a real
/// `PublicKeyResolver` (see initiative
/// `fix-gap-014-consensus-sig-verify.md`), the actual cryptographic
/// verification lives in `consensus::*_verified` but is NOT yet called
/// from this reactor. This validator does the maximum amount of
/// structural filtering possible without a resolver: it rejects
/// empty and all-zero signatures, blocking the most obvious forgery
/// shapes. It does NOT yet reject forgeries that use arbitrary
/// non-zero bytes.
fn validate_proposal(msg: &ConsensusProposalMsg, validators: &BTreeSet<Did>) -> Result<(), String> {
    if !validators.contains(&msg.proposal.proposer) {
        return Err(format!(
            "proposer {} is not in the validator set",
            msg.proposal.proposer
        ));
    }
    if msg.signature.is_empty() {
        return Err("proposal carries empty signature".into());
    }
    // GAP-014 defense-in-depth: reject the null-signature attack shape.
    let raw = msg.signature.as_bytes();
    if !raw.is_empty() && raw.iter().all(|b| *b == 0) {
        return Err("proposal carries zero-byte signature (null-sig attack shape)".into());
    }
    if msg.node.hash != msg.proposal.node_hash {
        return Err(format!(
            "proposal node_hash {} does not match attached node {}",
            msg.proposal.node_hash, msg.node.hash
        ));
    }
    Ok(())
}

/// Validate a consensus vote before processing.
///
/// Checks: voter is a known validator, signature is non-empty, and
/// signature is not a zero-byte sentinel.
///
/// See `validate_proposal` for the GAP-014 caveat.
fn validate_vote(msg: &ConsensusVoteMsg, validators: &BTreeSet<Did>) -> Result<(), String> {
    if !validators.contains(&msg.vote.voter) {
        return Err(format!(
            "voter {} is not in the validator set",
            msg.vote.voter
        ));
    }
    if msg.vote.signature.is_empty() {
        return Err("vote carries empty signature".into());
    }
    // GAP-014 defense-in-depth: reject the null-signature attack shape.
    let raw = msg.vote.signature.as_bytes();
    if !raw.is_empty() && raw.iter().all(|b| *b == 0) {
        return Err("vote carries zero-byte signature (null-sig attack shape)".into());
    }
    Ok(())
}

/// Validate a commit certificate before processing.
///
/// Checks: every vote in the certificate is from a known validator,
/// carries a non-empty, non-zero-sentinel signature, and references
/// the certificate's node hash.
///
/// See `validate_proposal` for the GAP-014 caveat.
fn validate_commit(msg: &ConsensusCommitMsg, validators: &BTreeSet<Did>) -> Result<(), String> {
    for vote in &msg.certificate.votes {
        if !validators.contains(&vote.voter) {
            return Err(format!(
                "certificate contains vote from non-validator {}",
                vote.voter
            ));
        }
        if vote.signature.is_empty() {
            return Err(format!(
                "certificate vote from {} has empty signature",
                vote.voter
            ));
        }
        // GAP-014 defense-in-depth: reject the null-signature attack shape.
        let raw = vote.signature.as_bytes();
        if !raw.is_empty() && raw.iter().all(|b| *b == 0) {
            return Err(format!(
                "certificate vote from {} has zero-byte signature (null-sig attack shape)",
                vote.voter
            ));
        }
        if vote.node_hash != msg.certificate.node_hash {
            return Err(format!(
                "certificate vote from {} references wrong node hash",
                vote.voter
            ));
        }
    }
    Ok(())
}

/// Handle an incoming wire message.
async fn handle_wire_message(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    net_handle: &NetworkHandle,
    reactor_tx: &mpsc::Sender<ReactorEvent>,
    message: WireMessage,
) {
    match message {
        WireMessage::ConsensusProposal(msg) => {
            handle_proposal(state, store, net_handle, reactor_tx, msg).await;
        }
        WireMessage::ConsensusVote(msg) => {
            handle_vote(state, store, net_handle, reactor_tx, msg).await;
        }
        WireMessage::ConsensusCommit(msg) => {
            handle_commit(state, store, reactor_tx, msg).await;
        }
        WireMessage::GovernanceEvent(msg) => {
            if reactor_tx
                .send(ReactorEvent::GovernanceEventReceived { event: msg })
                .await
                .is_err()
            {
                tracing::warn!("Reactor event receiver dropped (GovernanceEvent)");
            }
        }
        // DAG persistence layer shipped (GAP-001). State sync TBD.
        _ => {}
    }
}

/// Handle a consensus proposal from the network.
async fn handle_proposal(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    net_handle: &NetworkHandle,
    reactor_tx: &mpsc::Sender<ReactorEvent>,
    msg: ConsensusProposalMsg,
) {
    // Validate the proposal before any processing.
    {
        let Ok(s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_proposal (validate)");
            return;
        };
        if let Err(reason) = validate_proposal(&msg, &s.consensus.config.validators) {
            tracing::warn!(err = %reason, "Rejected invalid proposal from network");
            return;
        }
    }

    // All synchronous work in a block so MutexGuard is dropped before any .await.
    let vote_msg_opt = {
        let Ok(mut s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_proposal (process)");
            return;
        };

        // Store the proposed DAG node locally.
        {
            let Ok(mut st) = store.lock() else {
                tracing::error!("Store mutex poisoned in handle_proposal");
                return;
            };
            if let Err(e) = st.put_sync(msg.node.clone()) {
                tracing::warn!(err = %e, "Failed to store proposed node");
                return;
            }
        }

        // Register the proposal in consensus state.
        if let Err(e) = consensus::propose(&mut s.consensus, &msg.node, &msg.proposal.proposer) {
            tracing::warn!(err = %e, proposer = %msg.proposal.proposer, "Invalid proposal");
            return;
        }

        tracing::info!(
            round = msg.proposal.round,
            proposer = %msg.proposal.proposer,
            node = %msg.node.hash,
            "Received proposal"
        );

        // If we are a validator, vote for the proposal.
        if s.is_validator {
            let vote = Vote {
                voter: s.node_did.clone(),
                round: s.consensus.current_round,
                node_hash: msg.node.hash,
                signature: (s.sign_fn)(msg.node.hash.0.as_slice()),
            };

            if let Err(e) = consensus::vote(&mut s.consensus, vote.clone()) {
                tracing::warn!(err = %e, "Failed to cast own vote");
                return;
            }

            Some(WireMessage::ConsensusVote(ConsensusVoteMsg { vote }))
        } else {
            None
        }
    }; // MutexGuard dropped here

    // Async network operations happen outside the lock.
    if let Some(vote_msg) = vote_msg_opt {
        if let Err(e) = net_handle.publish(topics::CONSENSUS, vote_msg).await {
            tracing::warn!(err = %e, "Failed to broadcast vote");
        }

        // Check if our vote completed a quorum.
        check_and_commit(state, store, net_handle, reactor_tx, &msg.node.hash).await;
    }
}

/// Handle a consensus vote from the network.
async fn handle_vote(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    net_handle: &NetworkHandle,
    reactor_tx: &mpsc::Sender<ReactorEvent>,
    msg: ConsensusVoteMsg,
) {
    // Validate the vote before processing.
    {
        let Ok(s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_vote (validate)");
            return;
        };
        if let Err(reason) = validate_vote(&msg, &s.consensus.config.validators) {
            tracing::warn!(err = %reason, "Rejected invalid vote from network");
            return;
        }
    }

    {
        let Ok(mut s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_vote (process)");
            return;
        };

        if let Err(e) = consensus::vote(&mut s.consensus, msg.vote.clone()) {
            tracing::debug!(
                err = %e,
                voter = %msg.vote.voter,
                round = msg.vote.round,
                "Vote rejected"
            );
            return;
        }

        tracing::debug!(
            voter = %msg.vote.voter,
            round = msg.vote.round,
            node = %msg.vote.node_hash,
            "Received vote"
        );
    }

    // Persist the vote.
    {
        let Ok(mut st) = store.lock() else {
            tracing::error!("Store mutex poisoned in handle_vote (persist)");
            return;
        };
        if let Err(e) = st.save_vote(&msg.vote) {
            tracing::warn!(err = %e, "Failed to persist vote");
        }
    }

    // Check if this vote completed a quorum.
    check_and_commit(state, store, net_handle, reactor_tx, &msg.vote.node_hash).await;
}

/// Handle a commit certificate from the network.
async fn handle_commit(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    reactor_tx: &mpsc::Sender<ReactorEvent>,
    msg: ConsensusCommitMsg,
) {
    // Validate the commit certificate before processing.
    {
        let Ok(s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_commit (validate)");
            return;
        };
        if let Err(reason) = validate_commit(&msg, &s.consensus.config.validators) {
            tracing::warn!(err = %reason, "Rejected invalid commit certificate from network");
            return;
        }
    }

    let commit_info = {
        let Ok(mut s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_commit (process)");
            return;
        };
        let cert = msg.certificate;

        // Skip if already finalized.
        if consensus::is_finalized(&s.consensus, &cert.node_hash) {
            return;
        }

        // Apply the commit certificate.
        let round = cert.round;
        let hash = cert.node_hash;
        consensus::commit(&mut s.consensus, cert);

        let height = s.consensus.committed.len() as u64;
        (hash, height, round)
    }; // MutexGuard dropped here

    let (hash, height, round) = commit_info;

    // Mark committed in the persistent store.
    {
        let Ok(mut st) = store.lock() else {
            tracing::error!("Store mutex poisoned in handle_commit (mark)");
            return;
        };
        if let Err(e) = st.mark_committed_sync(&hash, height) {
            tracing::warn!(err = %e, "Failed to mark committed in store");
        }
    }

    // Emit a trust receipt for the network-received commit.
    let receipt = {
        let Ok(s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in handle_commit (receipt)");
            return;
        };
        #[allow(clippy::as_conversions)]
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let ts = Timestamp {
            physical_ms: now_ms,
            logical: 0,
        };
        TrustReceipt::new(
            s.node_did.clone(),
            Hash256::ZERO,
            None,
            "dag.commit".to_string(),
            hash,
            ReceiptOutcome::Executed,
            ts,
            &*s.sign_fn,
        )
    };
    {
        let Ok(mut st) = store.lock() else {
            tracing::error!("Store mutex poisoned in handle_commit (save receipt)");
            return;
        };
        if let Err(e) = st.save_receipt(&receipt) {
            tracing::warn!(err = %e, "Failed to persist trust receipt for network commit");
        }
    }

    tracing::info!(
        %hash,
        height,
        round,
        "Node committed via network certificate"
    );

    if reactor_tx
        .send(ReactorEvent::NodeCommitted {
            hash,
            height,
            round,
        })
        .await
        .is_err()
    {
        tracing::warn!("Reactor event receiver dropped (NodeCommitted via network)");
    }
}

/// Check if a node has reached quorum and commit if so.
async fn check_and_commit(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    net_handle: &NetworkHandle,
    reactor_tx: &mpsc::Sender<ReactorEvent>,
    node_hash: &Hash256,
) {
    let cert = {
        let Ok(s) = state.lock() else {
            tracing::error!("Reactor state mutex poisoned in check_and_commit");
            return;
        };
        consensus::check_commit(&s.consensus, node_hash)
    };

    if let Some(cert) = cert {
        let round = cert.round;
        let hash = cert.node_hash;

        // Commit locally.
        {
            let Ok(mut s) = state.lock() else {
                tracing::error!("Reactor state mutex poisoned in check_and_commit (commit)");
                return;
            };
            if !consensus::is_finalized(&s.consensus, &hash) {
                consensus::commit(&mut s.consensus, cert.clone());
            }
        }

        let height = {
            let Ok(s) = state.lock() else {
                tracing::error!("Reactor state mutex poisoned in check_and_commit (height)");
                return;
            };
            s.consensus.committed.len() as u64
        };

        // Persist to store.
        {
            let Ok(mut st) = store.lock() else {
                tracing::error!("Store mutex poisoned in check_and_commit (persist)");
                return;
            };
            if let Err(e) = st.mark_committed_sync(&hash, height) {
                tracing::warn!(err = %e, "Failed to mark committed");
            }
            if let Err(e) = st.save_certificate(&cert) {
                tracing::warn!(err = %e, "Failed to persist certificate");
            }
        }

        // Emit a trust receipt recording the commit action.
        let receipt = {
            let Ok(s) = state.lock() else {
                tracing::error!("Reactor state mutex poisoned in check_and_commit (receipt)");
                return;
            };
            #[allow(clippy::as_conversions)]
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let ts = Timestamp {
                physical_ms: now_ms,
                logical: 0,
            };
            TrustReceipt::new(
                s.node_did.clone(),
                Hash256::ZERO,
                None,
                "dag.commit".to_string(),
                hash,
                ReceiptOutcome::Executed,
                ts,
                &*s.sign_fn,
            )
        };
        {
            let Ok(mut st) = store.lock() else {
                tracing::error!("Store mutex poisoned in check_and_commit (save receipt)");
                return;
            };
            if let Err(e) = st.save_receipt(&receipt) {
                tracing::warn!(err = %e, "Failed to persist trust receipt for commit");
            }
        }

        tracing::info!(%hash, height, round, "Node committed — quorum reached");

        // Broadcast the commit certificate so all nodes learn.
        let commit_msg = WireMessage::ConsensusCommit(ConsensusCommitMsg { certificate: cert });
        if let Err(e) = net_handle.publish(topics::CONSENSUS, commit_msg).await {
            tracing::warn!(err = %e, "Failed to broadcast commit certificate");
        }

        if reactor_tx
            .send(ReactorEvent::NodeCommitted {
                hash,
                height,
                round,
            })
            .await
            .is_err()
        {
            tracing::warn!("Reactor event receiver dropped (NodeCommitted via quorum)");
        }
    }
}

// ---------------------------------------------------------------------------
// Proposal submission (application layer)
// ---------------------------------------------------------------------------

/// Submit a governance mutation as a DAG node and propose it for consensus.
///
/// Called by the API layer when a new governance action is requested.
pub async fn submit_proposal(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    net_handle: &NetworkHandle,
    payload: &[u8],
) -> anyhow::Result<DagNode> {
    let (node, proposal, signature) = {
        let mut s = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Reactor state mutex poisoned in submit_proposal"))?;

        if !s.is_validator {
            anyhow::bail!("This node is not a validator — cannot propose");
        }

        // Get current tips as parents.
        let tips = {
            let st = store
                .lock()
                .map_err(|_| anyhow::anyhow!("Store mutex poisoned in submit_proposal (tips)"))?;
            st.tips_sync().map_err(|e| anyhow::anyhow!("tips: {e}"))?
        };
        let parents: Vec<Hash256> = if tips.is_empty() {
            vec![] // genesis
        } else {
            tips
        };

        // Destructure to avoid borrow conflicts: `append` needs &mut dag
        // and &mut clock simultaneously, which can't be done through `s`.
        let ReactorState {
            ref mut dag,
            ref mut clock,
            ref node_did,
            ref sign_fn,
            ..
        } = *s;

        // Create the DAG node.
        let node = append(dag, &parents, payload, node_did, &**sign_fn, clock)
            .map_err(|e| anyhow::anyhow!("append: {e}"))?;

        // Store it locally.
        {
            let mut st = store
                .lock()
                .map_err(|_| anyhow::anyhow!("Store mutex poisoned in submit_proposal (put)"))?;
            st.put_sync(node.clone())
                .map_err(|e| anyhow::anyhow!("put: {e}"))?;
        }

        // Create the proposal.
        let proposer_did = s.node_did.clone();
        let proposal = consensus::propose(&mut s.consensus, &node, &proposer_did)
            .map_err(|e| anyhow::anyhow!("propose: {e}"))?;

        // Vote for our own proposal.
        let vote = Vote {
            voter: s.node_did.clone(),
            round: s.consensus.current_round,
            node_hash: node.hash,
            signature: (s.sign_fn)(node.hash.0.as_slice()),
        };
        consensus::vote(&mut s.consensus, vote).map_err(|e| anyhow::anyhow!("self-vote: {e}"))?;

        let sig = (s.sign_fn)(node.hash.0.as_slice());
        (node, proposal, sig)
    };

    // Broadcast the proposal.
    let proposal_msg = WireMessage::ConsensusProposal(ConsensusProposalMsg {
        proposal,
        node: node.clone(),
        signature,
    });

    net_handle
        .publish(topics::CONSENSUS, proposal_msg)
        .await
        .map_err(|e| anyhow::anyhow!("broadcast proposal: {e}"))?;

    tracing::info!(hash = %node.hash, "Submitted proposal");

    Ok(node)
}

/// Broadcast a governance event to the network.
pub async fn broadcast_governance_event(
    state: &SharedReactorState,
    net_handle: &NetworkHandle,
    event_type: GovernanceEventType,
    payload: Vec<u8>,
) -> anyhow::Result<()> {
    let (sender, timestamp, signature) = {
        let s = state
            .lock()
            .map_err(|_| anyhow::anyhow!("Reactor state mutex poisoned in broadcast_governance"))?;
        let sig = (s.sign_fn)(&payload);
        (s.node_did.clone(), Timestamp::ZERO, sig)
    };

    let msg = WireMessage::GovernanceEvent(GovernanceEventMsg {
        sender,
        event_type,
        payload,
        timestamp,
        signature,
    });

    net_handle
        .publish(topics::GOVERNANCE, msg)
        .await
        .map_err(|e| anyhow::anyhow!("broadcast governance: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        Arc::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn make_validators(n: usize) -> BTreeSet<Did> {
        (0..n)
            .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid"))
            .collect()
    }

    #[test]
    fn create_reactor_state_initializes() {
        let validators = make_validators(4);
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators: validators.clone(),
            round_timeout_ms: 5000,
        };

        let state = create_reactor_state(&config, make_sign_fn(), None);
        let s = state.lock().unwrap();
        assert_eq!(s.consensus.current_round, 0);
        assert_eq!(s.consensus.config.validators.len(), 4);
        assert_eq!(s.consensus.config.quorum_size(), 3);
        assert!(s.is_validator);
    }

    #[test]
    fn reactor_state_round_advancement() {
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators: make_validators(4),
            round_timeout_ms: 5000,
        };

        let state = create_reactor_state(&config, make_sign_fn(), None);
        {
            let mut s = state.lock().unwrap();
            assert_eq!(s.consensus.current_round, 0);
            s.consensus.advance_round();
            assert_eq!(s.consensus.current_round, 1);
        }
    }

    #[tokio::test]
    async fn submit_proposal_creates_dag_node() {
        let validators = make_validators(4);
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            round_timeout_ms: 5000,
        };

        let state = create_reactor_state(&config, make_sign_fn(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        // Create a network handle (will fail on publish, but we test the local logic)
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);

        let _result = submit_proposal(&state, &store, &net_handle, b"test payload").await;
        // The publish will fail because no network loop is running, but the DAG node
        // and proposal should still be created locally.
        // In this test setup, the channel receiver is dropped so publish returns Err.
        // That's expected — we verify the local state was updated.

        let s = state.lock().unwrap();
        assert_eq!(s.dag.len(), 1, "DAG should have one node");

        let st = store.lock().unwrap();
        assert_eq!(
            st.tips_sync().unwrap().len(),
            1,
            "Store should have one tip"
        );
    }

    #[tokio::test]
    async fn submit_proposal_non_validator_rejected() {
        let validators = make_validators(4);
        let config = ReactorConfig {
            node_did: Did::new("did:exo:outsider").unwrap(),
            is_validator: false,
            validators,
            round_timeout_ms: 5000,
        };

        let state = create_reactor_state(&config, make_sign_fn(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);

        let result = submit_proposal(&state, &store, &net_handle, b"test").await;
        assert!(result.is_err(), "Non-validator should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("not a validator"),
            "Error should mention validator"
        );
    }

    #[test]
    fn full_consensus_flow_local() {
        // Simulate a 4-validator consensus flow entirely in-process
        let validators = make_validators(4);
        let sign_fn = make_sign_fn();
        let v: Vec<Did> = validators.iter().cloned().collect();

        let config = ConsensusConfig::new(validators.clone(), 5000);
        let mut consensus_state = ConsensusState::new(config);
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();

        // Create a DAG node
        let node = append(
            &mut dag,
            &[],
            b"governance-decision-001",
            &v[0],
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        // Propose
        let _proposal = consensus::propose(&mut consensus_state, &node, &v[0]).unwrap();

        // 3 out of 4 validators vote (quorum = 3)
        for voter in &v[0..3] {
            let vote = Vote {
                voter: voter.clone(),
                round: 0,
                node_hash: node.hash,
                signature: sign_fn(node.hash.0.as_slice()),
            };
            consensus::vote(&mut consensus_state, vote).unwrap();
        }

        // Check commit — should reach quorum
        let cert = consensus::check_commit(&consensus_state, &node.hash);
        assert!(cert.is_some(), "Should reach quorum with 3/4 votes");

        let cert = cert.unwrap();
        assert_eq!(cert.votes.len(), 3);
        assert_eq!(cert.round, 0);

        // Commit
        consensus::commit(&mut consensus_state, cert);
        assert!(consensus::is_finalized(&consensus_state, &node.hash));
        assert_eq!(consensus_state.committed.len(), 1);

        // Advance round and do another
        consensus_state.advance_round();
        let node2 = append(
            &mut dag,
            &[node.hash],
            b"governance-decision-002",
            &v[1],
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let _proposal2 = consensus::propose(&mut consensus_state, &node2, &v[1]).unwrap();
        for voter in v.iter().take(4) {
            let vote = Vote {
                voter: voter.clone(),
                round: 1,
                node_hash: node2.hash,
                signature: sign_fn(node2.hash.0.as_slice()),
            };
            consensus::vote(&mut consensus_state, vote).unwrap();
        }

        let cert2 = consensus::check_commit(&consensus_state, &node2.hash).unwrap();
        consensus::commit(&mut consensus_state, cert2);
        assert!(consensus::is_finalized(&consensus_state, &node2.hash));
        assert_eq!(consensus_state.committed.len(), 2);
    }

    #[test]
    fn consensus_byzantine_tolerance() {
        // 7-validator set, 2 Byzantine nodes try to commit a conflicting proposal
        let validators = make_validators(7);
        let sign_fn = make_sign_fn();
        let v: Vec<Did> = validators.iter().cloned().collect();

        let config = ConsensusConfig::new(validators, 5000);
        let mut state = ConsensusState::new(config); // quorum = 5

        let mut honest_dag = Dag::new();
        let mut honest_clock = HybridClock::new();
        let mut byzantine_dag = Dag::new();
        let mut byzantine_clock = HybridClock::new();

        let honest_node = append(
            &mut honest_dag,
            &[],
            b"honest",
            &v[0],
            &*sign_fn,
            &mut honest_clock,
        )
        .unwrap();
        let byzantine_node = append(
            &mut byzantine_dag,
            &[],
            b"evil",
            &v[5],
            &*sign_fn,
            &mut byzantine_clock,
        )
        .unwrap();

        // Both get proposed
        consensus::propose(&mut state, &honest_node, &v[0]).unwrap();
        consensus::propose(&mut state, &byzantine_node, &v[5]).unwrap();

        // 5 honest validators vote for honest_node
        for voter in &v[0..5] {
            let vote = Vote {
                voter: voter.clone(),
                round: 0,
                node_hash: honest_node.hash,
                signature: sign_fn(honest_node.hash.0.as_slice()),
            };
            consensus::vote(&mut state, vote).unwrap();
        }

        // 2 Byzantine validators vote for byzantine_node
        for voter in &v[5..7] {
            let vote = Vote {
                voter: voter.clone(),
                round: 0,
                node_hash: byzantine_node.hash,
                signature: sign_fn(byzantine_node.hash.0.as_slice()),
            };
            consensus::vote(&mut state, vote).unwrap();
        }

        // Honest node reaches quorum
        assert!(consensus::check_commit(&state, &honest_node.hash).is_some());
        // Byzantine node does not
        assert!(consensus::check_commit(&state, &byzantine_node.hash).is_none());

        let cert = consensus::check_commit(&state, &honest_node.hash).unwrap();
        #[allow(deprecated)]
        consensus::commit(&mut state, cert);
        assert!(consensus::is_finalized(&state, &honest_node.hash));
        assert!(!consensus::is_finalized(&state, &byzantine_node.hash));
    }

    // ==== GAP-014 defense-in-depth regression tests ====================

    fn make_node_for_test() -> exo_dag::dag::DagNode {
        use exo_dag::dag::{Dag, append};
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let did = Did::new("did:exo:v0").unwrap();
        let sf = make_sign_fn();
        append(&mut dag, &[], b"x", &did, &*sf, &mut clock).unwrap()
    }

    #[test]
    fn validate_proposal_rejects_zero_byte_signature() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let node = make_node_for_test();
        let msg = ConsensusProposalMsg {
            proposal: exo_dag::consensus::Proposal {
                proposer: proposer.clone(),
                round: 0,
                node_hash: node.hash,
            },
            node,
            signature: Signature::from_bytes([0u8; 64]),
        };
        let err = validate_proposal(&msg, &validators).unwrap_err();
        // Signature::Ed25519([0u8; 64]) hits is_empty() first (ex_core types.rs:325)
        // so the "empty" message fires before the explicit null-sig check.
        // Either message proves rejection — both are defense in depth.
        assert!(err.contains("empty") || err.contains("zero-byte"));
    }

    #[test]
    fn validate_vote_rejects_zero_byte_signature() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let msg = ConsensusVoteMsg {
            vote: exo_dag::consensus::Vote {
                voter,
                round: 0,
                node_hash: exo_core::types::Hash256([9u8; 32]),
                signature: Signature::from_bytes([0u8; 64]),
            },
        };
        let err = validate_vote(&msg, &validators).unwrap_err();
        assert!(err.contains("empty") || err.contains("zero-byte"));
    }

    #[test]
    fn validate_commit_rejects_zero_byte_vote_in_cert() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let hash = exo_core::types::Hash256([7u8; 32]);
        let cert = exo_dag::consensus::CommitCertificate {
            node_hash: hash,
            votes: vec![exo_dag::consensus::Vote {
                voter,
                round: 0,
                node_hash: hash,
                signature: Signature::from_bytes([0u8; 64]),
            }],
            round: 0,
        };
        let msg = ConsensusCommitMsg { certificate: cert };
        let err = validate_commit(&msg, &validators).unwrap_err();
        assert!(err.contains("empty") || err.contains("zero-byte"));
    }

    #[test]
    fn validate_vote_rejects_empty_signature() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let msg = ConsensusVoteMsg {
            vote: exo_dag::consensus::Vote {
                voter,
                round: 0,
                node_hash: exo_core::types::Hash256([9u8; 32]),
                signature: Signature::empty(),
            },
        };
        let err = validate_vote(&msg, &validators).unwrap_err();
        assert!(err.contains("empty signature"));
    }
}
