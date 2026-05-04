//! Consensus reactor — drives DAG-BFT consensus over the P2P network.
//!
//! The reactor is a Tokio task that:
//! 1. Receives consensus messages (proposals, votes, commits) from the network
//! 2. Validates them through the existing `exo-dag::consensus` protocol
//! 3. Applies committed state to the local `DagStore`
//! 4. Broadcasts outbound consensus messages via the network handle
//! 5. Drives round advancement on timeout
//!
//! This module wires the fully-tested verified consensus API
//! (`propose_verified()`, `vote_verified()`, `check_commit()`,
//! `commit_verified()`) into a network-aware reactor.
//!
//! # GAP-014 note
//!
//! The reactor keeps an explicit validator DID → Ed25519 public-key map and
//! rejects proposals, votes, and commit certificates that cannot be verified
//! against that resolver. Local proposal and self-vote signatures are produced
//! over the canonical CBOR payloads defined by `exo-dag::consensus`.

#![allow(clippy::type_complexity, clippy::single_match)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use exo_core::{
    hash::hash_structured,
    types::{Did, Hash256, PublicKey, ReceiptOutcome, Signature, Timestamp, TrustReceipt},
};
use exo_dag::{
    append::verify_node_creator_signature,
    consensus::{self, CommitCertificate, ConsensusConfig, ConsensusState, Proposal, Vote},
    dag::{Dag, DagNode, DeterministicDagClock, append},
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

#[derive(serde::Serialize)]
struct CommitReceiptAuthorityPayload<'a> {
    domain: &'static str,
    certificate: &'a CommitCertificate,
}

fn commit_receipt_authority_hash(cert: &CommitCertificate) -> Result<Hash256, String> {
    hash_structured(&CommitReceiptAuthorityPayload {
        domain: "exo.reactor.commit_certificate_authority.v1",
        certificate: cert,
    })
    .map_err(|e| format!("commit certificate authority hash: {e}"))
}

fn checked_committed_height(committed_len: usize) -> Result<u64, String> {
    u64::try_from(committed_len).map_err(|_| {
        format!("committed height {committed_len} exceeds maximum representable u64 height")
    })
}

async fn with_store_blocking<T, F>(
    store: Arc<Mutex<SqliteDagStore>>,
    context: &'static str,
    operation: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut SqliteDagStore) -> Result<T, String> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut store = store
            .lock()
            .map_err(|_| format!("Store mutex poisoned in {context}"))?;
        operation(&mut store)
    })
    .await
    .map_err(|e| format!("Store blocking task failed in {context}: {e}"))?
}

async fn with_reactor_state_blocking<T, F>(
    shared: SharedReactorState,
    context: &'static str,
    operation: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut ReactorState) -> Result<T, String> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut guard = shared
            .lock()
            .map_err(|_| format!("Reactor state mutex poisoned in {context}"))?;
        operation(&mut guard)
    })
    .await
    .map_err(|e| format!("Reactor state blocking task failed in {context}: {e}"))?
}

async fn stored_node_timestamp_for_receipt(
    store: &Arc<Mutex<SqliteDagStore>>,
    hash: &Hash256,
) -> Result<Timestamp, String> {
    let hash = *hash;
    let node = with_store_blocking(
        Arc::clone(store),
        "stored_node_timestamp_for_receipt",
        move |store| {
            store
                .get_sync(&hash)
                .map_err(|e| format!("load committed DAG node {hash}: {e}"))?
                .ok_or_else(|| format!("committed DAG node {hash} not found for trust receipt"))
        },
    )
    .await?;

    Ok(node.timestamp)
}

async fn commit_receipt_from_certificate(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    cert: &CommitCertificate,
) -> Result<TrustReceipt, String> {
    let timestamp = stored_node_timestamp_for_receipt(store, &cert.node_hash).await?;
    let authority_hash = commit_receipt_authority_hash(cert)?;
    let node_hash = cert.node_hash;
    with_reactor_state_blocking(
        Arc::clone(state),
        "commit_receipt_from_certificate",
        move |s| {
            TrustReceipt::new(
                s.node_did.clone(),
                authority_hash,
                None,
                "dag.commit".to_string(),
                node_hash,
                ReceiptOutcome::Executed,
                timestamp,
                &*s.sign_fn,
            )
            .map_err(|e| format!("build commit trust receipt: {e}"))
        },
    )
    .await
}

fn sign_proposal(
    proposal: &Proposal,
    sign_fn: &(dyn Fn(&[u8]) -> Signature + Send + Sync),
) -> Result<Signature, String> {
    let payload = proposal
        .signing_payload()
        .map_err(|e| format!("proposal signing payload: {e}"))?;
    Ok(sign_fn(&payload))
}

fn signed_vote(
    voter: Did,
    round: u64,
    node_hash: Hash256,
    sign_fn: &(dyn Fn(&[u8]) -> Signature + Send + Sync),
) -> Result<Vote, String> {
    let mut vote = Vote {
        voter,
        round,
        node_hash,
        signature: Signature::empty(),
    };
    let payload = vote
        .signing_payload()
        .map_err(|e| format!("vote signing payload: {e}"))?;
    vote.signature = sign_fn(&payload);
    Ok(vote)
}

// ---------------------------------------------------------------------------
// Reactor state
// ---------------------------------------------------------------------------

/// Deterministic validator public-key resolver used by the reactor.
///
/// Consensus verification must resolve keys from explicit configuration or
/// persisted governance state; it cannot infer a public key from a DID.
#[derive(Debug, Clone, Default)]
pub struct ValidatorPublicKeys {
    keys: BTreeMap<Did, PublicKey>,
}

impl ValidatorPublicKeys {
    #[must_use]
    pub fn new(keys: BTreeMap<Did, PublicKey>) -> Self {
        Self { keys }
    }

    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<Did, PublicKey> {
        &self.keys
    }

    #[must_use]
    pub fn missing_for(&self, validators: &BTreeSet<Did>) -> Vec<Did> {
        validators
            .iter()
            .filter(|did| !self.keys.contains_key(*did))
            .cloned()
            .collect()
    }
}

impl consensus::PublicKeyResolver for ValidatorPublicKeys {
    fn resolve(&self, did: &Did) -> Option<PublicKey> {
        self.keys.get(did).copied()
    }
}

/// Shared state for the consensus reactor, accessible from the API layer.
pub struct ReactorState {
    /// The BFT consensus state (rounds, votes, certificates).
    pub consensus: ConsensusState,
    /// The local DAG — used by submit_proposal via struct destructuring.
    #[allow(dead_code)]
    pub dag: Dag,
    /// The deterministic DAG append clock — used by submit_proposal via struct destructuring.
    #[allow(dead_code)]
    pub clock: DeterministicDagClock,
    /// This node's DID.
    pub node_did: Did,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Sign function using this node's key.
    sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    /// Public keys for validators in the current consensus set.
    pub validator_public_keys: ValidatorPublicKeys,
}

impl std::fmt::Debug for ReactorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReactorState")
            .field("consensus", &self.consensus)
            .field("node_did", &self.node_did)
            .field("is_validator", &self.is_validator)
            .field(
                "validator_public_keys",
                &self
                    .validator_public_keys
                    .as_map()
                    .keys()
                    .collect::<Vec<_>>(),
            )
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
    /// Ed25519 public keys for every validator DID.
    pub validator_public_keys: BTreeMap<Did, PublicKey>,
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
    let validator_public_keys = ValidatorPublicKeys::new(config.validator_public_keys.clone());

    // Restore persisted consensus state if a store is provided.
    if let Some(store_arc) = store {
        let st = match store_arc.lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("Store mutex poisoned during reactor state restore");
                return Arc::new(Mutex::new(ReactorState {
                    consensus: consensus_state,
                    dag: Dag::new(),
                    clock: DeterministicDagClock::new(),
                    node_did: config.node_did.clone(),
                    is_validator: config.is_validator,
                    sign_fn,
                    validator_public_keys,
                }));
            }
        };

        // Restore the round number.
        if let Ok(round) = st.load_consensus_round() {
            if round > 0 {
                while consensus_state.current_round < round {
                    if let Err(err) = consensus_state.advance_round() {
                        tracing::error!(
                            err = %err,
                            target_round = round,
                            "Failed to restore consensus round"
                        );
                        break;
                    }
                }
                tracing::info!(round, "Restored consensus round from store");
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

        let missing_public_keys =
            validator_public_keys.missing_for(&consensus_state.config.validators);
        if !missing_public_keys.is_empty() {
            tracing::warn!(
                missing = ?missing_public_keys,
                "Consensus validator public-key resolver is incomplete; \
                 unverifiable restored votes/certificates and network messages will be rejected"
            );
        }

        // Restore commit certificates.
        if let Ok(certs) = st.load_certificates() {
            let count = certs.len();
            for cert in certs {
                if !consensus::is_finalized(&consensus_state, &cert.node_hash) {
                    if let Err(e) = consensus::commit_verified(
                        &mut consensus_state,
                        cert,
                        &validator_public_keys,
                    ) {
                        tracing::warn!(err = %e, "Skipped unverifiable restored commit certificate");
                    }
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
                if let Err(e) =
                    consensus::vote_verified(&mut consensus_state, vote, &validator_public_keys)
                {
                    tracing::warn!(err = %e, "Skipped unverifiable restored pending vote");
                }
            }
            if count > 0 {
                tracing::info!(
                    count,
                    round = consensus_state.current_round,
                    "Restored pending votes"
                );
            }
        }
    }

    Arc::new(Mutex::new(ReactorState {
        consensus: consensus_state,
        dag: Dag::new(),
        clock: DeterministicDagClock::new(),
        node_did: config.node_did.clone(),
        is_validator: config.is_validator,
        sign_fn,
        validator_public_keys,
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
    let round_timeout =
        match with_reactor_state_blocking(Arc::clone(&state), "reactor_start_config", |s| {
            Ok(Duration::from_millis(s.consensus.config.round_timeout_ms))
        })
        .await
        {
            Ok(round_timeout) => round_timeout,
            Err(e) => {
                tracing::error!(err = %e, "Cannot start reactor");
                return;
            }
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
                let round = match with_reactor_state_blocking(
                    Arc::clone(&state),
                    "reactor_round_tick",
                    |s| {
                        s.consensus.advance_round().map_err(|err| err.to_string())?;
                        Ok(s.consensus.current_round)
                    },
                )
                .await
                {
                    Ok(round) => round,
                    Err(e) => {
                        tracing::error!(err = %e, "Failed to advance reactor round");
                        continue;
                    }
                };

                // Persist the new round number.
                if let Err(e) = with_store_blocking(
                    Arc::clone(&store),
                    "reactor_round_persist",
                    move |store| {
                        store
                            .save_consensus_round(round)
                            .map_err(|e| format!("persist round {round}: {e}"))
                    },
                )
                .await
                {
                    tracing::warn!(err = %e, "Failed to persist round");
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
/// Checks: proposer is in the current validator set, the attached signature
/// verifies against the configured proposer public key, and the node hash
/// matches the proposal's node_hash.
fn validate_proposal<R: consensus::PublicKeyResolver>(
    msg: &ConsensusProposalMsg,
    validators: &BTreeSet<Did>,
    resolver: &R,
) -> Result<(), String> {
    if !validators.contains(&msg.proposal.proposer) {
        return Err(format!(
            "proposer {} is not in the validator set",
            msg.proposal.proposer
        ));
    }
    let Some(public_key) = resolver.resolve(&msg.proposal.proposer) else {
        return Err(format!(
            "proposer {} has no configured public key",
            msg.proposal.proposer
        ));
    };
    if !msg.proposal.verify_signature(&public_key, &msg.signature) {
        return Err("proposal carries invalid signature".into());
    }
    if msg.node.hash != msg.proposal.node_hash {
        return Err(format!(
            "proposal node_hash {} does not match attached node {}",
            msg.proposal.node_hash, msg.node.hash
        ));
    }
    verify_node_creator_signature(&msg.node, resolver)
        .map_err(|e| format!("proposal DAG node creator signature invalid: {e}"))?;
    Ok(())
}

/// Validate a consensus vote before processing.
///
/// Checks: voter is a known validator and the signature verifies against the
/// configured voter public key.
fn validate_vote<R: consensus::PublicKeyResolver>(
    msg: &ConsensusVoteMsg,
    validators: &BTreeSet<Did>,
    resolver: &R,
) -> Result<(), String> {
    if !validators.contains(&msg.vote.voter) {
        return Err(format!(
            "voter {} is not in the validator set",
            msg.vote.voter
        ));
    }
    let Some(public_key) = resolver.resolve(&msg.vote.voter) else {
        return Err(format!(
            "voter {} has no configured public key",
            msg.vote.voter
        ));
    };
    if !msg.vote.verify_signature(&public_key) {
        return Err("vote carries invalid signature".into());
    }
    Ok(())
}

/// Validate a commit certificate before processing.
///
/// Checks: every vote in the certificate is from a known validator, references
/// the certificate node hash, and verifies against the configured voter public
/// key.
fn validate_commit<R: consensus::PublicKeyResolver>(
    msg: &ConsensusCommitMsg,
    validators: &BTreeSet<Did>,
    resolver: &R,
) -> Result<(), String> {
    let quorum = ConsensusConfig::new(validators.clone(), 0).quorum_size();
    if quorum == 0 {
        return Err("commit certificate cannot be validated with an empty validator set".into());
    }

    let mut distinct_voters = BTreeSet::new();
    for vote in &msg.certificate.votes {
        if !validators.contains(&vote.voter) {
            return Err(format!(
                "certificate contains vote from non-validator {}",
                vote.voter
            ));
        }
        if vote.round != msg.certificate.round {
            return Err(format!(
                "certificate vote from {} is for round {}, expected {}",
                vote.voter, vote.round, msg.certificate.round
            ));
        }
        if vote.node_hash != msg.certificate.node_hash {
            return Err(format!(
                "certificate vote from {} references wrong node hash",
                vote.voter
            ));
        }
        if !distinct_voters.insert(vote.voter.clone()) {
            return Err(format!(
                "certificate contains duplicate vote from {} in round {}",
                vote.voter, vote.round
            ));
        }
        let Some(public_key) = resolver.resolve(&vote.voter) else {
            return Err(format!(
                "certificate vote from {} has no configured public key",
                vote.voter
            ));
        };
        if !vote.verify_signature(&public_key) {
            return Err(format!(
                "certificate vote from {} has invalid signature",
                vote.voter
            ));
        }
    }

    if distinct_voters.len() < quorum {
        return Err(format!(
            "commit certificate has insufficient quorum: required {}, got {}",
            quorum,
            distinct_voters.len()
        ));
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
            // Collapsed to satisfy clippy::collapsible_if. Cheaper to
            // read than the nested `if` form.
            if let Err(_send_err) = reactor_tx
                .send(ReactorEvent::GovernanceEventReceived { event: msg })
                .await
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
    let proposal_for_validation = msg.clone();
    if let Err(reason) =
        with_reactor_state_blocking(Arc::clone(state), "handle_proposal_validate", move |s| {
            validate_proposal(
                &proposal_for_validation,
                &s.consensus.config.validators,
                &s.validator_public_keys,
            )
        })
        .await
    {
        tracing::warn!(err = %reason, "Rejected invalid proposal from network");
        return;
    }

    if let Err(e) = with_store_blocking(Arc::clone(store), "handle_proposal_put", {
        let node = msg.node.clone();
        move |store| {
            store
                .put_sync(node)
                .map_err(|e| format!("store proposed node: {e}"))
        }
    })
    .await
    {
        tracing::warn!(err = %e, "Failed to store proposed node");
        return;
    }

    let proposal_for_process = msg.clone();
    let vote_msg_opt =
        match with_reactor_state_blocking(Arc::clone(state), "handle_proposal_process", move |s| {
            // Register the proposal in consensus state after cryptographic verification.
            let resolver = s.validator_public_keys.clone();
            if let Err(e) = consensus::propose_verified(
                &mut s.consensus,
                &proposal_for_process.node,
                &proposal_for_process.proposal.proposer,
                &proposal_for_process.signature,
                &resolver,
            ) {
                return Err(format!(
                    "invalid proposal from {}: {e}",
                    proposal_for_process.proposal.proposer
                ));
            }

            tracing::info!(
                round = proposal_for_process.proposal.round,
                proposer = %proposal_for_process.proposal.proposer,
                node = %proposal_for_process.node.hash,
                "Received proposal"
            );

            // If we are a validator, vote for the proposal.
            if s.is_validator {
                let vote = signed_vote(
                    s.node_did.clone(),
                    s.consensus.current_round,
                    proposal_for_process.node.hash,
                    &*s.sign_fn,
                )
                .map_err(|e| format!("sign own consensus vote: {e}"))?;

                let resolver = s.validator_public_keys.clone();
                consensus::vote_verified(&mut s.consensus, vote.clone(), &resolver)
                    .map_err(|e| format!("cast own vote: {e}"))?;

                Ok(Some(WireMessage::ConsensusVote(ConsensusVoteMsg { vote })))
            } else {
                Ok(None)
            }
        })
        .await
        {
            Ok(vote_msg_opt) => vote_msg_opt,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to process proposal");
                return;
            }
        };

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
    let vote_for_validation = msg.clone();
    if let Err(reason) =
        with_reactor_state_blocking(Arc::clone(state), "handle_vote_validate", move |s| {
            validate_vote(
                &vote_for_validation,
                &s.consensus.config.validators,
                &s.validator_public_keys,
            )
        })
        .await
    {
        tracing::warn!(err = %reason, "Rejected invalid vote from network");
        return;
    }

    let vote_for_process = msg.vote.clone();
    if let Err(e) =
        with_reactor_state_blocking(Arc::clone(state), "handle_vote_process", move |s| {
            let resolver = s.validator_public_keys.clone();
            consensus::vote_verified(&mut s.consensus, vote_for_process.clone(), &resolver)
                .map_err(|e| {
                    format!(
                        "vote from {} in round {} rejected: {e}",
                        vote_for_process.voter, vote_for_process.round
                    )
                })?;

            tracing::debug!(
                voter = %vote_for_process.voter,
                round = vote_for_process.round,
                node = %vote_for_process.node_hash,
                "Received vote"
            );
            Ok(())
        })
        .await
    {
        tracing::debug!(err = %e, "Vote rejected");
        return;
    }

    // Persist the vote.
    if let Err(e) = with_store_blocking(Arc::clone(store), "handle_vote_persist", {
        let vote = msg.vote.clone();
        move |store| {
            store
                .save_vote(&vote)
                .map_err(|e| format!("persist vote: {e}"))
        }
    })
    .await
    {
        tracing::warn!(err = %e, "Failed to persist vote");
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
    let commit_for_validation = msg.clone();
    if let Err(reason) =
        with_reactor_state_blocking(Arc::clone(state), "handle_commit_validate", move |s| {
            validate_commit(
                &commit_for_validation,
                &s.consensus.config.validators,
                &s.validator_public_keys,
            )
        })
        .await
    {
        tracing::warn!(err = %reason, "Rejected invalid commit certificate from network");
        return;
    }

    let cert_for_process = msg.certificate;
    let commit_result =
        match with_reactor_state_blocking(Arc::clone(state), "handle_commit_process", move |s| {
            let cert = cert_for_process;

            // Skip if already finalized.
            if consensus::is_finalized(&s.consensus, &cert.node_hash) {
                return Ok(None);
            }

            // Apply the commit certificate after verifying every certificate vote.
            let round = cert.round;
            let hash = cert.node_hash;
            let resolver = s.validator_public_keys.clone();
            consensus::commit_verified(&mut s.consensus, cert.clone(), &resolver)
                .map_err(|e| format!("invalid commit certificate: {e}"))?;

            let height = checked_committed_height(s.consensus.committed.len())?;
            Ok(Some((cert, (hash, height, round))))
        })
        .await
        {
            Ok(commit_info) => commit_info,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to process commit certificate");
                return;
            }
        };
    let Some((cert, commit_info)) = commit_result else {
        return;
    };

    let (hash, height, round) = commit_info;

    // Mark committed in the persistent store.
    if let Err(e) = with_store_blocking(Arc::clone(store), "handle_commit_mark", move |store| {
        store
            .mark_committed_sync(&hash, height)
            .map_err(|e| format!("mark committed {hash} at height {height}: {e}"))
    })
    .await
    {
        tracing::warn!(err = %e, "Failed to mark committed in store");
        return;
    }

    // Emit a trust receipt for the network-received commit.
    let receipt = match commit_receipt_from_certificate(state, store, &cert).await {
        Ok(receipt) => receipt,
        Err(e) => {
            tracing::warn!(err = %e, "Failed to build trust receipt for network commit");
            return;
        }
    };
    if let Err(e) = with_store_blocking(Arc::clone(store), "handle_commit_save_receipt", {
        let receipt = receipt.clone();
        move |store| {
            store
                .save_receipt(&receipt)
                .map_err(|e| format!("save network commit receipt: {e}"))
        }
    })
    .await
    {
        tracing::warn!(err = %e, "Failed to persist trust receipt for network commit");
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
    let node_hash_for_check = *node_hash;
    let cert =
        match with_reactor_state_blocking(Arc::clone(state), "check_and_commit_check", move |s| {
            Ok(consensus::check_commit(&s.consensus, &node_hash_for_check))
        })
        .await
        {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!(err = %e, "Failed to check commit quorum");
                return;
            }
        };

    if let Some(cert) = cert {
        let round = cert.round;
        let hash = cert.node_hash;

        let cert_for_commit = cert.clone();
        let height = match with_reactor_state_blocking(
            Arc::clone(state),
            "check_and_commit_commit",
            move |s| {
                if !consensus::is_finalized(&s.consensus, &hash) {
                    let resolver = s.validator_public_keys.clone();
                    consensus::commit_verified(&mut s.consensus, cert_for_commit, &resolver)
                        .map_err(|e| format!("verify local commit certificate: {e}"))?;
                }
                checked_committed_height(s.consensus.committed.len())
            },
        )
        .await
        {
            Ok(height) => height,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to apply local commit certificate");
                return;
            }
        };

        // Persist to store.
        if let Err(e) = with_store_blocking(Arc::clone(store), "check_and_commit_persist", {
            let cert = cert.clone();
            move |store| {
                store
                    .mark_committed_sync(&hash, height)
                    .map_err(|e| format!("mark committed {hash} at height {height}: {e}"))?;
                store
                    .save_certificate(&cert)
                    .map_err(|e| format!("persist certificate for {hash}: {e}"))
            }
        })
        .await
        {
            tracing::warn!(err = %e, "Failed to persist commit state");
            return;
        }

        // Emit a trust receipt recording the commit action.
        let receipt = match commit_receipt_from_certificate(state, store, &cert).await {
            Ok(receipt) => receipt,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to build trust receipt for commit");
                return;
            }
        };
        if let Err(e) = with_store_blocking(Arc::clone(store), "check_and_commit_save_receipt", {
            let receipt = receipt.clone();
            move |store| {
                store
                    .save_receipt(&receipt)
                    .map_err(|e| format!("save local commit receipt: {e}"))
            }
        })
        .await
        {
            tracing::warn!(err = %e, "Failed to persist trust receipt for commit");
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
    with_reactor_state_blocking(Arc::clone(state), "submit_proposal_validate", |s| {
        if !s.is_validator {
            return Err("This node is not a validator — cannot propose".to_string());
        }
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Get current tips as parents.
    let tips = with_store_blocking(Arc::clone(store), "submit_proposal_tips", |store| {
        store.tips_sync().map_err(|e| format!("tips: {e}"))
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let parents: Vec<Hash256> = if tips.is_empty() {
        vec![] // genesis
    } else {
        tips
    };

    let payload_for_node = payload.to_vec();
    let node = with_reactor_state_blocking(Arc::clone(state), "submit_proposal_append", move |s| {
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
        append(
            dag,
            &parents,
            &payload_for_node,
            node_did,
            &**sign_fn,
            clock,
        )
        .map_err(|e| format!("append: {e}"))
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Store it locally.
    with_store_blocking(Arc::clone(store), "submit_proposal_put", {
        let node = node.clone();
        move |store| store.put_sync(node).map_err(|e| format!("put: {e}"))
    })
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let node_for_proposal = node.clone();
    let (proposal, signature) =
        with_reactor_state_blocking(Arc::clone(state), "submit_proposal_consensus", move |s| {
            if !s.is_validator {
                return Err("This node is not a validator — cannot propose".to_string());
            }
            // Create and sign the proposal over the canonical consensus payload.
            let proposer_did = s.node_did.clone();
            let proposal_to_sign = Proposal {
                proposer: proposer_did.clone(),
                round: s.consensus.current_round,
                node_hash: node_for_proposal.hash,
            };
            let sig = sign_proposal(&proposal_to_sign, &*s.sign_fn)
                .map_err(|e| format!("proposal signature: {e}"))?;
            let resolver = s.validator_public_keys.clone();
            let proposal = consensus::propose_verified(
                &mut s.consensus,
                &node_for_proposal,
                &proposer_did,
                &sig,
                &resolver,
            )
            .map_err(|e| format!("propose: {e}"))?;

            // Vote for our own proposal.
            let vote = signed_vote(
                s.node_did.clone(),
                s.consensus.current_round,
                node_for_proposal.hash,
                &*s.sign_fn,
            )
            .map_err(|e| format!("self-vote signature: {e}"))?;
            let resolver = s.validator_public_keys.clone();
            consensus::vote_verified(&mut s.consensus, vote, &resolver)
                .map_err(|e| format!("self-vote: {e}"))?;

            Ok((proposal, sig))
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
    let payload_for_signature = payload.clone();
    let (sender, timestamp, signature) =
        with_reactor_state_blocking(Arc::clone(state), "broadcast_governance", move |s| {
            let sig = (s.sign_fn)(&payload_for_signature);
            let timestamp = s
                .clock
                .try_tick()
                .map_err(|e| format!("governance event timestamp: {e}"))?;
            Ok((s.node_did.clone(), timestamp, sig))
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
#[allow(clippy::unwrap_used, clippy::expect_used, deprecated)]
mod tests {
    use exo_core::crypto::KeyPair;

    use super::*;

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        let keypair = validator_keypair(0);
        Arc::new(move |data: &[u8]| keypair.sign(data))
    }

    fn validator_keypair(index: usize) -> KeyPair {
        let seed = u8::try_from(index + 1).expect("test validator index fits in u8");
        KeyPair::from_secret_bytes([seed; 32]).expect("deterministic validator keypair")
    }

    fn make_validator_public_keys(validators: &BTreeSet<Did>) -> BTreeMap<Did, PublicKey> {
        validators
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, did)| {
                let keypair = validator_keypair(idx);
                (did, *keypair.public_key())
            })
            .collect()
    }

    fn sign_vote_for_index(mut vote: Vote, index: usize) -> Vote {
        let keypair = validator_keypair(index);
        let payload = vote.signing_payload().expect("vote payload");
        vote.signature = keypair.sign(&payload);
        vote
    }

    fn sign_proposal_for_index(proposal: &Proposal, index: usize) -> Signature {
        let keypair = validator_keypair(index);
        let payload = proposal.signing_payload().expect("proposal payload");
        keypair.sign(&payload)
    }

    fn config_for(node_did: Did, is_validator: bool, validators: BTreeSet<Did>) -> ReactorConfig {
        ReactorConfig {
            node_did,
            is_validator,
            validator_public_keys: make_validator_public_keys(&validators),
            validators,
            round_timeout_ms: 5000,
        }
    }

    fn vote_for(did: &Did, index: usize, round: u64, node_hash: Hash256) -> Vote {
        sign_vote_for_index(
            Vote {
                voter: did.clone(),
                round,
                node_hash,
                signature: Signature::empty(),
            },
            index,
        )
    }

    fn proposal_msg_for(
        proposer: Did,
        proposer_index: usize,
        round: u64,
        node: DagNode,
    ) -> ConsensusProposalMsg {
        let proposal = Proposal {
            proposer,
            round,
            node_hash: node.hash,
        };
        let signature = sign_proposal_for_index(&proposal, proposer_index);
        ConsensusProposalMsg {
            proposal,
            node,
            signature,
        }
    }

    fn validator_keys_for_single(did: &Did, public_key: PublicKey) -> ValidatorPublicKeys {
        let mut keys = BTreeMap::new();
        keys.insert(did.clone(), public_key);
        ValidatorPublicKeys::new(keys)
    }

    fn key_for_validator_index(index: usize) -> PublicKey {
        *validator_keypair(index).public_key()
    }

    fn sign_with_wrong_key(payload: &[u8]) -> Signature {
        let wrong_keypair = KeyPair::from_secret_bytes([91u8; 32]).unwrap();
        wrong_keypair.sign(payload)
    }

    fn signature_is_invalid_error(err: &str) -> bool {
        err.contains("invalid signature") || err.contains("empty") || err.contains("zero-byte")
    }

    fn make_validators(n: usize) -> BTreeSet<Did> {
        (0..n)
            .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid"))
            .collect()
    }

    #[test]
    fn reactor_async_store_access_uses_spawn_blocking() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "reactor must isolate synchronous store I/O from Tokio workers"
        );
        for forbidden in [
            "let Ok(mut st) = store.lock()",
            "let Ok(st) = store.lock()",
            "store\n                .lock()",
            "store.lock().map_err",
        ] {
            assert!(
                !production.contains(forbidden),
                "async reactor path still directly locks the store: {forbidden}"
            );
        }
    }

    #[test]
    fn reactor_async_state_access_uses_spawn_blocking() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("async fn with_reactor_state_blocking"),
            "async reactor state access must be isolated from Tokio workers"
        );
        for forbidden in [
            "state.lock()",
            "state\n        .lock()",
            "state\n            .lock()",
            "state\n                .lock()",
        ] {
            assert!(
                !production.contains(forbidden),
                "async reactor path still directly locks reactor state: {forbidden}"
            );
        }
    }

    #[test]
    fn reactor_production_uses_checked_committed_height_conversion() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            !production.contains("clippy::as_conversions"),
            "reactor production code must not suppress checked conversion linting"
        );
        assert!(
            !production.contains("committed.len() as u64"),
            "reactor commit height must use a checked conversion from committed length"
        );
        assert!(
            production.contains("checked_committed_height"),
            "reactor commit paths must route height conversion through the checked helper"
        );
    }

    #[test]
    fn broadcast_governance_event_source_does_not_emit_placeholder_timestamp() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");
        let broadcaster = production
            .split("pub async fn broadcast_governance_event")
            .nth(1)
            .expect("governance broadcaster present")
            .split("// ---------------------------------------------------------------------------")
            .next()
            .expect("governance broadcaster end");

        assert!(
            !broadcaster.contains("Timestamp::ZERO"),
            "governance broadcasts must use the reactor monotonic timestamp source, not Timestamp::ZERO"
        );
    }

    #[test]
    fn create_reactor_state_initializes() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators.clone());

        let state = create_reactor_state(&config, make_sign_fn(), None);
        let s = state.lock().unwrap();
        assert_eq!(s.consensus.current_round, 0);
        assert_eq!(s.consensus.config.validators.len(), 4);
        assert_eq!(s.consensus.config.quorum_size(), 3);
        assert!(s.is_validator);
    }

    #[test]
    fn reactor_state_round_advancement() {
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, make_validators(4));

        let state = create_reactor_state(&config, make_sign_fn(), None);
        {
            let mut s = state.lock().unwrap();
            assert_eq!(s.consensus.current_round, 0);
            s.consensus.advance_round().expect("round advances");
            assert_eq!(s.consensus.current_round, 1);
        }
    }

    #[tokio::test]
    async fn submit_proposal_creates_dag_node() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);

        let state = create_reactor_state(&config, make_sign_fn(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        // Create a network handle (will fail on publish, but we test the local logic)
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        drop(cmd_rx);
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
        let config = config_for(Did::new("did:exo:outsider").unwrap(), false, validators);

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

    #[tokio::test]
    async fn commit_receipt_uses_certificate_authority_and_node_timestamp() {
        let validators = make_validators(4);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let node_did = validator_vec[0].clone();
        let config = config_for(node_did.clone(), true, validators);
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, sign_fn.clone(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::with_time(42_000);
        let node = append(
            &mut dag,
            &[],
            b"receipt-timestamp-source",
            &node_did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();

        let cert = CommitCertificate {
            node_hash: node.hash,
            votes: validator_vec
                .iter()
                .take(3)
                .map(|voter| Vote {
                    voter: voter.clone(),
                    round: 0,
                    node_hash: node.hash,
                    signature: sign_fn(node.hash.0.as_slice()),
                })
                .collect(),
            round: 0,
        };

        let receipt = commit_receipt_from_certificate(&state, &store, &cert)
            .await
            .unwrap();
        let expected_authority = commit_receipt_authority_hash(&cert).unwrap();

        assert_eq!(receipt.timestamp, node.timestamp);
        assert_eq!(receipt.authority_chain_hash, expected_authority);
        assert_ne!(receipt.authority_chain_hash, Hash256::ZERO);
        assert_eq!(receipt.action_hash, node.hash);
        assert!(!receipt.signature.is_empty());
    }

    #[tokio::test]
    async fn broadcast_governance_event_publishes_nonzero_timestamp() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);

        let broadcast_task = {
            let state = Arc::clone(&state);
            let net_handle = net_handle.clone();
            tokio::spawn(async move {
                broadcast_governance_event(
                    &state,
                    &net_handle,
                    GovernanceEventType::AuditEntry,
                    b"audit".to_vec(),
                )
                .await
            })
        };

        let command = cmd_rx.recv().await.expect("published network command");
        let crate::network::NetworkCommand::Publish {
            topic,
            message,
            reply,
        } = command
        else {
            panic!("expected publish command");
        };
        reply.send(Ok(())).expect("publish ack receiver active");
        broadcast_task
            .await
            .expect("broadcast task joins")
            .expect("governance event broadcast");

        assert_eq!(topic, topics::GOVERNANCE);

        let WireMessage::GovernanceEvent(event) = message else {
            panic!("expected governance event");
        };
        assert_ne!(
            event.timestamp,
            Timestamp::ZERO,
            "governance broadcasts must carry a non-placeholder monotonic timestamp"
        );
    }

    #[tokio::test]
    async fn commit_receipt_timestamp_rejects_missing_node() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let err = stored_node_timestamp_for_receipt(&store, &Hash256::ZERO)
            .await
            .unwrap_err();

        assert!(err.contains("not found for trust receipt"));
    }

    #[test]
    fn full_consensus_flow_local() {
        // Simulate a 4-validator consensus flow entirely in-process
        let validators = make_validators(4);
        let sign_fn = make_sign_fn();
        let v: Vec<Did> = validators.iter().cloned().collect();
        let resolver = ValidatorPublicKeys::new(make_validator_public_keys(&validators));

        let config = ConsensusConfig::new(validators.clone(), 5000);
        let mut consensus_state = ConsensusState::new(config);
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();

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
        let proposal = Proposal {
            proposer: v[0].clone(),
            round: 0,
            node_hash: node.hash,
        };
        let proposal_sig = sign_proposal_for_index(&proposal, 0);
        let _proposal = consensus::propose_verified(
            &mut consensus_state,
            &node,
            &v[0],
            &proposal_sig,
            &resolver,
        )
        .unwrap();

        // 3 out of 4 validators vote (quorum = 3)
        for (index, voter) in v.iter().enumerate().take(3) {
            let vote = vote_for(voter, index, 0, node.hash);
            consensus::vote_verified(&mut consensus_state, vote, &resolver).unwrap();
        }

        // Check commit — should reach quorum
        let cert = consensus::check_commit(&consensus_state, &node.hash);
        assert!(cert.is_some(), "Should reach quorum with 3/4 votes");

        let cert = cert.unwrap();
        assert_eq!(cert.votes.len(), 3);
        assert_eq!(cert.round, 0);

        // Commit
        consensus::commit_verified(&mut consensus_state, cert, &resolver).unwrap();
        assert!(consensus::is_finalized(&consensus_state, &node.hash));
        assert_eq!(consensus_state.committed.len(), 1);

        // Advance round and do another
        consensus_state.advance_round().expect("round advances");
        let node2 = append(
            &mut dag,
            &[node.hash],
            b"governance-decision-002",
            &v[1],
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let proposal2 = Proposal {
            proposer: v[1].clone(),
            round: 1,
            node_hash: node2.hash,
        };
        let proposal2_sig = sign_proposal_for_index(&proposal2, 1);
        let _proposal2 = consensus::propose_verified(
            &mut consensus_state,
            &node2,
            &v[1],
            &proposal2_sig,
            &resolver,
        )
        .unwrap();
        for (index, voter) in v.iter().enumerate().take(4) {
            let vote = vote_for(voter, index, 1, node2.hash);
            consensus::vote_verified(&mut consensus_state, vote, &resolver).unwrap();
        }

        let cert2 = consensus::check_commit(&consensus_state, &node2.hash).unwrap();
        consensus::commit_verified(&mut consensus_state, cert2, &resolver).unwrap();
        assert!(consensus::is_finalized(&consensus_state, &node2.hash));
        assert_eq!(consensus_state.committed.len(), 2);
    }

    #[test]
    fn consensus_byzantine_tolerance() {
        // 7-validator set, 2 Byzantine nodes try to commit a conflicting proposal
        let validators = make_validators(7);
        let sign_fn = make_sign_fn();
        let v: Vec<Did> = validators.iter().cloned().collect();
        let resolver = ValidatorPublicKeys::new(make_validator_public_keys(&validators));

        let config = ConsensusConfig::new(validators.clone(), 5000);
        let mut state = ConsensusState::new(config); // quorum = 5

        let mut honest_dag = Dag::new();
        let mut honest_clock = DeterministicDagClock::new();
        let mut byzantine_dag = Dag::new();
        let mut byzantine_clock = DeterministicDagClock::new();

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
        let honest_proposal = Proposal {
            proposer: v[0].clone(),
            round: 0,
            node_hash: honest_node.hash,
        };
        let honest_sig = sign_proposal_for_index(&honest_proposal, 0);
        consensus::propose_verified(&mut state, &honest_node, &v[0], &honest_sig, &resolver)
            .unwrap();
        let byzantine_proposal = Proposal {
            proposer: v[5].clone(),
            round: 0,
            node_hash: byzantine_node.hash,
        };
        let byzantine_sig = sign_proposal_for_index(&byzantine_proposal, 5);
        consensus::propose_verified(
            &mut state,
            &byzantine_node,
            &v[5],
            &byzantine_sig,
            &resolver,
        )
        .unwrap();

        // 5 honest validators vote for honest_node
        for (index, voter) in v.iter().enumerate().take(5) {
            let vote = vote_for(voter, index, 0, honest_node.hash);
            consensus::vote_verified(&mut state, vote, &resolver).unwrap();
        }

        // 2 Byzantine validators vote for byzantine_node
        for (index, voter) in v.iter().enumerate().skip(5).take(2) {
            let vote = vote_for(voter, index, 0, byzantine_node.hash);
            consensus::vote_verified(&mut state, vote, &resolver).unwrap();
        }

        // Honest node reaches quorum
        assert!(consensus::check_commit(&state, &honest_node.hash).is_some());
        // Byzantine node does not
        assert!(consensus::check_commit(&state, &byzantine_node.hash).is_none());

        let cert = consensus::check_commit(&state, &honest_node.hash).unwrap();
        consensus::commit_verified(&mut state, cert, &resolver).unwrap();
        assert!(consensus::is_finalized(&state, &honest_node.hash));
        assert!(!consensus::is_finalized(&state, &byzantine_node.hash));
    }

    // ==== GAP-014 defense-in-depth regression tests ====================

    fn make_node_for_test() -> exo_dag::dag::DagNode {
        use exo_dag::dag::{Dag, append};
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let did = Did::new("did:exo:v0").unwrap();
        let sf = make_sign_fn();
        append(&mut dag, &[], b"x", &did, &*sf, &mut clock).unwrap()
    }

    #[test]
    fn validate_proposal_rejects_zero_byte_signature() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
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
        let err = validate_proposal(&msg, &validators, &resolver).unwrap_err();
        // Signature::Ed25519([0u8; 64]) hits is_empty() first (ex_core types.rs:325)
        // so the "empty" message fires before the explicit null-sig check.
        // Either message proves rejection — both are defense in depth.
        assert!(signature_is_invalid_error(&err));
    }

    #[test]
    fn validate_proposal_accepts_signed_message() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
        let node = make_node_for_test();
        let msg = proposal_msg_for(proposer, 0, 0, node);

        validate_proposal(&msg, &validators, &resolver).unwrap();
    }

    #[test]
    fn validate_proposal_rejects_forged_node_signature() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
        let mut node = make_node_for_test();
        node.signature = Signature::from_bytes([0u8; 64]);
        let msg = proposal_msg_for(proposer, 0, 0, node);

        let err = validate_proposal(&msg, &validators, &resolver).unwrap_err();

        assert!(
            err.contains("proposal DAG node creator signature invalid"),
            "network proposals must reject forged attached DAG nodes, got: {err}"
        );
    }

    #[test]
    fn validate_vote_rejects_zero_byte_signature() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&voter, key_for_validator_index(0));
        let msg = ConsensusVoteMsg {
            vote: exo_dag::consensus::Vote {
                voter,
                round: 0,
                node_hash: exo_core::types::Hash256([9u8; 32]),
                signature: Signature::from_bytes([0u8; 64]),
            },
        };
        let err = validate_vote(&msg, &validators, &resolver).unwrap_err();
        assert!(signature_is_invalid_error(&err));
    }

    #[test]
    fn validate_vote_accepts_signed_vote() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&voter, key_for_validator_index(0));
        let msg = ConsensusVoteMsg {
            vote: vote_for(&voter, 0, 0, exo_core::types::Hash256([9u8; 32])),
        };

        validate_vote(&msg, &validators, &resolver).unwrap();
    }

    #[test]
    fn validate_commit_rejects_zero_byte_vote_in_cert() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&voter, key_for_validator_index(0));
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
        let err = validate_commit(&msg, &validators, &resolver).unwrap_err();
        assert!(signature_is_invalid_error(&err));
    }

    #[test]
    fn validate_vote_rejects_empty_signature() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&voter, key_for_validator_index(0));
        let msg = ConsensusVoteMsg {
            vote: exo_dag::consensus::Vote {
                voter,
                round: 0,
                node_hash: exo_core::types::Hash256([9u8; 32]),
                signature: Signature::empty(),
            },
        };
        let err = validate_vote(&msg, &validators, &resolver).unwrap_err();
        assert!(signature_is_invalid_error(&err));
    }

    #[test]
    fn validate_vote_rejects_forged_nonzero_signature() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&voter, key_for_validator_index(0));
        let mut vote = exo_dag::consensus::Vote {
            voter,
            round: 0,
            node_hash: exo_core::types::Hash256([9u8; 32]),
            signature: Signature::empty(),
        };
        let payload = vote.signing_payload().unwrap();
        vote.signature = sign_with_wrong_key(&payload);

        let msg = ConsensusVoteMsg { vote };
        let err = validate_vote(&msg, &validators, &resolver).unwrap_err();
        assert!(err.contains("signature"));
    }

    #[test]
    fn reactor_commit_receipts_do_not_use_local_wall_clock() {
        let source = include_str!("reactor.rs");
        let forbidden = concat!("System", "Time::now");

        assert!(
            !source.contains(forbidden),
            "reactor commit receipts must derive timestamps from protocol or stored DAG metadata"
        );
    }

    #[test]
    fn reactor_production_paths_do_not_call_legacy_consensus_api() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("reactor source has production section");

        assert!(
            !production.contains("consensus::propose("),
            "production reactor paths must call propose_verified"
        );
        assert!(
            !production.contains("consensus::vote("),
            "production reactor paths must call vote_verified"
        );
        assert!(
            !production.contains("consensus::commit("),
            "production reactor paths must call commit_verified"
        );
    }
}
