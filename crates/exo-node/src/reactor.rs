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
//!
//! ## Locking model
//!
//! The reactor has two shared synchronous mutexes: `SharedReactorState` for
//! consensus state and `Arc<Mutex<SqliteDagStore>>` for local DAG persistence.
//! Async paths must enter these mutexes only through `with_reactor_state_blocking`
//! or `with_store_blocking`, which move the synchronous critical section onto
//! `tokio::task::spawn_blocking`. Never hold both mutexes at the same time.
//! Workflows that need data from both sides must snapshot, release, then acquire
//! the other mutex in a separate blocking section before performing any async
//! send, broadcast, or timer operation.

#![allow(clippy::type_complexity, clippy::single_match)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use exo_core::{
    crypto,
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
        GovernanceEventType, ValidatorChange, WireMessage, topics,
    },
};

#[derive(serde::Serialize)]
struct CommitReceiptAuthorityPayload<'a> {
    domain: &'static str,
    certificate: &'a CommitCertificate,
}

#[derive(serde::Serialize)]
struct GovernanceEventSigningPayload<'a> {
    domain: &'static str,
    sender: &'a Did,
    event_type: &'a GovernanceEventType,
    payload_hash: &'a Hash256,
    timestamp: &'a Timestamp,
}

#[derive(serde::Deserialize)]
struct AuditEntryPayload {
    actor_did: String,
    action_type: String,
    outcome: String,
}

fn commit_receipt_authority_hash(cert: &CommitCertificate) -> Result<Hash256, String> {
    hash_structured(&CommitReceiptAuthorityPayload {
        domain: "exo.reactor.commit_certificate_authority.v1",
        certificate: cert,
    })
    .map_err(|e| format!("commit certificate authority hash: {e}"))
}

fn governance_event_signing_payload(event: &GovernanceEventMsg) -> Result<Vec<u8>, String> {
    let payload_hash = Hash256::digest(&event.payload);
    let payload = GovernanceEventSigningPayload {
        domain: "exo.reactor.governance_event.v1",
        sender: &event.sender,
        event_type: &event.event_type,
        payload_hash: &payload_hash,
        timestamp: &event.timestamp,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut bytes)
        .map_err(|e| format!("governance event signing payload: {e}"))?;
    Ok(bytes)
}

fn validate_governance_proposal_payload(payload: &[u8]) -> Result<ValidatorChange, String> {
    let change: ValidatorChange = ciborium::from_reader(payload)
        .map_err(|e| format!("proposal payload must be canonical ValidatorChange CBOR: {e}"))?;
    match &change {
        ValidatorChange::AddValidator { did, public_key } => {
            if did.as_str().trim().is_empty() {
                return Err("proposal payload validator DID must not be empty".into());
            }
            // VCG-015: fail-closed cross-check. The wire payload carries
            // both the claimed DID and the validator's real Ed25519 public
            // key; a DID is a one-way hash of its owning key
            // (`identity::did_from_public_key`), so we can and must verify
            // the two actually correspond before accepting the change. A
            // key that does not hash to the claimed DID is rejected
            // outright — never substituted with a placeholder.
            let derived_did = crate::identity::did_from_public_key(public_key)
                .map_err(|e| format!("proposal payload AddValidator public key is invalid: {e}"))?;
            if &derived_did != did {
                return Err(format!(
                    "proposal payload AddValidator public key derives DID {derived_did}, \
                     which does not match the claimed DID {did}"
                ));
            }
        }
        ValidatorChange::RemoveValidator { did } => {
            if did.as_str().trim().is_empty() {
                return Err("proposal payload validator DID must not be empty".into());
            }
        }
    }
    Ok(change)
}

/// Decode a committed node's governance payload and, if it is a canonical
/// `ValidatorChange`, mutate live consensus state (`s.consensus.config.validators`)
/// and the validator public-key resolver in place.
///
/// Pure in-memory mutation only — callers persist the resulting set via
/// `store.save_validator_set` in a separate step, respecting this module's
/// locking discipline (never hold the reactor-state mutex and the store
/// mutex at the same time; see the module doc comment).
///
/// Returns `Some(ValidatorChange)` describing what changed if the payload
/// decoded as a `ValidatorChange`, or `None` if the committed node was not a
/// governance proposal (the common case for ordinary DAG nodes) or the
/// payload failed the fail-closed validation in
/// `validate_governance_proposal_payload` (e.g. an `AddValidator` whose
/// supplied public key does not hash to its claimed DID — no validator is
/// added and no key, placeholder or otherwise, is ever registered in that
/// case).
fn apply_committed_validator_change_in_memory(
    s: &mut ReactorState,
    payload: &[u8],
) -> Option<ValidatorChange> {
    let change = validate_governance_proposal_payload(payload).ok()?;

    match &change {
        ValidatorChange::AddValidator { did, public_key } => {
            // VCG-015: register the SUPPLIED, validated public key — never
            // a placeholder. `validate_governance_proposal_payload` has
            // already confirmed `public_key` hashes to `did`, so the key
            // registered here is one the new validator can genuinely sign
            // against.
            s.consensus.config.validators.insert(did.clone());
            let mut keys = s.validator_public_keys.as_map().clone();
            keys.insert(did.clone(), *public_key);
            s.validator_public_keys = ValidatorPublicKeys::new(keys);
        }
        ValidatorChange::RemoveValidator { did } => {
            // W3(A)/R1.5: BFT min-4 validator floor, enforced HERE at
            // apply-on-commit time — not just at api.rs's propose-time
            // pre-check (`validator_count <= 4` in
            // `handle_validator_change`), which only fast-fails the UX for
            // a single proposer and is not the safety boundary. Two
            // `RemoveValidator` proposals can each individually pass that
            // pre-check (each sees the count still at or above the floor
            // when submitted) and both reach quorum; applied sequentially
            // through the same lock with no re-check here, the set would
            // drop 5 -> 4 -> 3, one below the 3f+1=4 safety floor. This
            // whole match arm already runs inside the single
            // `with_reactor_state_blocking` critical section entered via
            // the `Mutex<ReactorState>`, so the two concurrent apply tasks
            // are serialized: whichever runs second observes the
            // already-decremented count below and refuses here, closing
            // the race without needing any new lock or coordination
            // mechanism.
            //
            // `BFT_MIN_VALIDATORS` also exists in `sentinels.rs` (detective
            // health-check, not importable — it's a private module-level
            // const there). This local copy must stay in sync with that
            // value (4).
            const BFT_MIN_VALIDATORS: usize = 4;
            if s.consensus.config.validators.len() <= BFT_MIN_VALIDATORS {
                tracing::warn!(
                    %did,
                    current_count = s.consensus.config.validators.len(),
                    floor = BFT_MIN_VALIDATORS,
                    "Refusing to apply quorum-certified RemoveValidator commit: \
                     validator set is at or below the BFT minimum floor. \
                     Discarding this already-committed change as a no-op to \
                     preserve the 3f+1 safety invariant."
                );
                return None;
            }
            s.consensus.config.validators.remove(did);
            let mut keys = s.validator_public_keys.as_map().clone();
            keys.remove(did);
            s.validator_public_keys = ValidatorPublicKeys::new(keys);
        }
    }

    Some(change)
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

/// Load the committed node's governance payload (if any was persisted via
/// `save_governance_payload`) and, if it decodes as a canonical
/// `ValidatorChange`, apply it to live consensus state and the validator
/// public-key resolver, then persist the resulting set via
/// `store.save_validator_set`.
///
/// Called only after the commit certificate has verified and the commit
/// trust receipt has been durably persisted — the ordering that keeps
/// validator-set mutation strictly downstream of a quorum-gated,
/// evidence-backed commit. The already-persisted commit trust receipt
/// (`receipt`) is the audit record for the commit itself; a companion
/// `tracing::info!` event here records the specific validator-set delta so
/// the audit trail reflects *what* changed, not just *that* something
/// committed.
///
/// CLOSED (W3(A)/R1.5, was: concurrent-remove BFT floor race): the
/// minimum-validator BFT floor is now re-enforced *here*, at apply-on-commit
/// time, inside `apply_committed_validator_change_in_memory`'s
/// `RemoveValidator` arm — not only at proposal-submission time in
/// `api.rs::handle_validator_change` (which checks the *current* live
/// validator count before accepting a removal proposal, and remains a
/// fast-fail UX pre-check, not the safety boundary). Previously, two
/// `RemoveValidator` proposals that each individually passed that
/// propose-time check — because each saw a validator count still at or
/// above the floor at the moment it was submitted — could both
/// independently reach quorum and commit here in sequence, jointly dropping
/// the live set below the BFT-safe minimum even though neither commit
/// violated the floor on its own. The apply-time re-check closes this: it
/// runs inside the same `with_reactor_state_blocking` critical section as
/// the mutation, so the single `Mutex<ReactorState>` serializes concurrent
/// apply tasks and whichever runs second observes the already-decremented
/// count and discards its already-quorum-certified commit as a no-op. See
/// `apply_committed_validator_change_in_memory`'s `RemoveValidator` arm for
/// the guard itself, and the `remove_validator_at_floor_refused_at_apply_time_even_bypassing_http_handler`
/// / `concurrent_removals_cannot_drop_validator_set_below_floor` tests below
/// for RED-before/GREEN-after evidence. VCG-005 remediation notes updated
/// accordingly in GAP-REGISTRY.md.
async fn apply_committed_validator_change_after_commit(
    state: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    hash: &Hash256,
    receipt: &TrustReceipt,
) {
    let hash = *hash;

    // Step 1: load the governance payload under the store lock only.
    let payload = match with_store_blocking(
        Arc::clone(store),
        "commit_load_governance_payload",
        move |store| {
            store
                .load_governance_payload(&hash)
                .map_err(|e| format!("load governance payload for committed node {hash}: {e}"))
        },
    )
    .await
    {
        Ok(Some(payload)) => payload,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(err = %e, %hash, "Failed to load governance payload for committed node");
            return;
        }
    };

    // Step 2: decode and mutate live consensus state under the reactor-state
    // lock only, then release it before touching the store again.
    let (change, validators_snapshot) = match with_reactor_state_blocking(
        Arc::clone(state),
        "commit_apply_validator_change",
        move |s| {
            let change = apply_committed_validator_change_in_memory(s, &payload);
            Ok((change, s.consensus.config.validators.clone()))
        },
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(err = %e, %hash, "Failed to apply committed ValidatorChange in memory");
            return;
        }
    };

    let Some(change) = change else {
        // Not a canonical ValidatorChange payload — an ordinary committed
        // DAG node, not a governance proposal. Nothing more to do.
        return;
    };

    // Step 3: persist the resulting validator set under the store lock only.
    if let Err(e) = with_store_blocking(Arc::clone(store), "commit_persist_validator_set", {
        move |store| {
            store
                .save_validator_set(&validators_snapshot)
                .map_err(|e| format!("persist committed validator set: {e}"))
        }
    })
    .await
    {
        tracing::warn!(err = %e, %hash, "Failed to persist committed validator set");
        return;
    }

    // Companion audit event: the commit trust receipt (already persisted by
    // the caller) is the evidentiary record that a commit happened; this
    // event records specifically what the commit changed.
    tracing::info!(
        %hash,
        receipt_hash = %receipt.receipt_hash,
        change = ?change,
        "Applied committed ValidatorChange to live consensus config and persisted validator set"
    );
}

// Reachable in production only via `submit_proposal` under the
// `unaudited-admin-governance-shortcut` feature (see `api.rs`); the
// infrastructure-Holon Scaling path no longer calls `submit_proposal` as of
// VCG-010/D5 (recommendation-only, full stop — it never submits a DAG
// proposal). Exercised directly by `reactor::tests` regardless of feature.
#[cfg_attr(not(feature = "unaudited-admin-governance-shortcut"), allow(dead_code))]
fn sign_proposal(
    proposal: &Proposal,
    sign_fn: &(dyn Fn(&[u8]) -> Signature + Send + Sync),
) -> Result<Signature, String> {
    let payload = proposal
        .signing_payload()
        .map_err(|e| format!("proposal signing payload: {e}"))?;
    Ok(sign_fn(&payload))
}

fn parse_audit_receipt_outcome(value: &str) -> Result<ReceiptOutcome, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "executed" | "success" | "succeeded" | "ok" => Ok(ReceiptOutcome::Executed),
        "denied" | "rejected" | "failed" | "failure" => Ok(ReceiptOutcome::Denied),
        "escalated" => Ok(ReceiptOutcome::Escalated),
        "pending" => Ok(ReceiptOutcome::Pending),
        other => Err(format!("unsupported audit receipt outcome: {other}")),
    }
}

async fn verify_governance_event_signature(
    state: &SharedReactorState,
    event: &GovernanceEventMsg,
) -> Result<(), String> {
    let event = event.clone();
    with_reactor_state_blocking(
        Arc::clone(state),
        "governance_event_signature_verify",
        move |s| {
            let public_key = s
                .validator_public_keys
                .as_map()
                .get(&event.sender)
                .copied()
                .ok_or_else(|| {
                    format!(
                        "governance event sender {} is not a validator",
                        event.sender
                    )
                })?;
            let payload = governance_event_signing_payload(&event)?;
            if !crypto::verify(&payload, &event.signature, &public_key) {
                return Err(format!(
                    "governance event signature failed verification for sender {}",
                    event.sender
                ));
            }
            Ok(())
        },
    )
    .await
}

fn validate_audit_event_payload(event: &GovernanceEventMsg) -> Result<(), String> {
    let payload: AuditEntryPayload = serde_json::from_slice(&event.payload)
        .map_err(|e| format!("audit entry payload must be JSON: {e}"))?;
    Did::new(payload.actor_did.trim()).map_err(|e| format!("audit actor DID: {e}"))?;
    if payload.action_type.trim().is_empty() {
        return Err("audit action_type must not be empty".into());
    }
    parse_audit_receipt_outcome(&payload.outcome)?;
    Ok(())
}

async fn apply_governance_event_locally(
    state: &SharedReactorState,
    event: &GovernanceEventMsg,
) -> Result<(), String> {
    verify_governance_event_signature(state, event).await?;
    if !matches!(event.event_type, GovernanceEventType::AuditEntry) {
        return Ok(());
    }
    validate_audit_event_payload(event)
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
        if let Ok(round) = st.load_consensus_round()
            && round > 0
        {
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

        // Restore persisted validator set (may have been changed via governance).
        if let Ok(persisted_validators) = st.load_validator_set()
            && !persisted_validators.is_empty()
        {
            consensus_state.config.validators = persisted_validators;
            tracing::info!(
                validators = consensus_state.config.validators.len(),
                "Restored validator set from store"
            );
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
                if !consensus::is_finalized(&consensus_state, &cert.node_hash)
                    && let Err(e) = consensus::commit_verified(
                        &mut consensus_state,
                        cert,
                        &validator_public_keys,
                    )
                {
                    tracing::warn!(err = %e, "Skipped unverifiable restored commit certificate");
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
    let payload_hash = Hash256::digest(&msg.payload);
    if payload_hash != msg.node.payload_hash {
        return Err(format!(
            "proposal payload hash {} does not match attached node payload hash {}",
            payload_hash, msg.node.payload_hash
        ));
    }
    validate_governance_proposal_payload(&msg.payload)?;
    verify_node_creator_signature(&msg.node, resolver)
        .map_err(|e| format!("proposal DAG node creator signature invalid: {e}"))?;
    Ok(())
}

/// Validate external proposal DAG append rules against local persistent state.
fn validate_external_proposal_append(store: &SqliteDagStore, node: &DagNode) -> Result<(), String> {
    for parent_hash in &node.parents {
        let parent = store
            .get_sync(parent_hash)
            .map_err(|e| format!("load proposal parent {parent_hash}: {e}"))?
            .ok_or_else(|| format!("proposal parent {parent_hash} is absent from local DAG"))?;

        if node.timestamp <= parent.timestamp {
            return Err(format!(
                "proposal node timestamp {:?} must exceed parent {} timestamp {:?}",
                node.timestamp, parent_hash, parent.timestamp
            ));
        }
    }

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
            if let Err(e) = apply_governance_event_locally(state, &msg).await {
                tracing::warn!(err = %e, "Rejected governance event from network");
                return;
            }
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
        let payload = msg.payload.clone();
        move |store| {
            validate_external_proposal_append(store, &node)?;
            let node_hash = node.hash;
            store
                .put_sync(node)
                .map_err(|e| format!("store proposed node: {e}"))?;
            // Persist the raw governance payload so a later commit can
            // decode and apply it (the DAG node itself only commits to a
            // one-way payload_hash digest).
            store
                .save_governance_payload(&node_hash, &payload)
                .map_err(|e| format!("store proposed node governance payload: {e}"))
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

            // Verify on a clone first; durable receipt persistence must succeed
            // before the live consensus state is advanced.
            let round = cert.round;
            let hash = cert.node_hash;
            let resolver = s.validator_public_keys.clone();
            let mut preview = s.consensus.clone();
            consensus::commit_verified(&mut preview, cert.clone(), &resolver)
                .map_err(|e| format!("invalid commit certificate: {e}"))?;

            let height = checked_committed_height(preview.committed.len())?;
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

    // Build and persist the trust receipt before advancing live consensus state.
    let receipt = match commit_receipt_from_certificate(state, store, &cert).await {
        Ok(receipt) => receipt,
        Err(e) => {
            tracing::warn!(err = %e, "Failed to build trust receipt for network commit");
            return;
        }
    };
    if let Err(e) = with_store_blocking(Arc::clone(store), "handle_commit_persist", {
        let receipt = receipt.clone();
        move |store| {
            store
                .mark_committed_with_receipt_sync(&hash, height, &receipt)
                .map_err(|e| {
                    format!(
                        "persist network commit marker and receipt for {hash} at height {height}: {e}"
                    )
                })
        }
    })
    .await
    {
        tracing::warn!(err = %e, "Failed to persist network commit state");
        return;
    }

    let cert_for_commit = cert.clone();
    if let Err(e) =
        with_reactor_state_blocking(Arc::clone(state), "handle_commit_apply", move |s| {
            if !consensus::is_finalized(&s.consensus, &hash) {
                let resolver = s.validator_public_keys.clone();
                consensus::commit_verified(&mut s.consensus, cert_for_commit, &resolver)
                    .map_err(|e| format!("apply persisted network commit certificate: {e}"))?;
            }
            checked_committed_height(s.consensus.committed.len()).and_then(|actual_height| {
                if actual_height == height {
                    Ok(())
                } else {
                    Err(format!(
                        "persisted network commit height {height} does not match consensus height {actual_height}"
                    ))
                }
            })
        })
        .await
    {
        tracing::warn!(err = %e, "Failed to apply persisted network commit certificate");
        return;
    }

    // Apply a committed ValidatorChange to live consensus state and persist
    // it, strictly after the commit certificate has verified and the trust
    // receipt has been durably written above. Ordinary (non-governance)
    // committed nodes are a no-op here.
    apply_committed_validator_change_after_commit(state, store, &hash, &receipt).await;

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
            "check_and_commit_preview",
            move |s| {
                let mut preview = s.consensus.clone();
                if !consensus::is_finalized(&preview, &hash) {
                    let resolver = s.validator_public_keys.clone();
                    consensus::commit_verified(&mut preview, cert_for_commit, &resolver)
                        .map_err(|e| format!("verify local commit certificate: {e}"))?;
                }
                checked_committed_height(preview.committed.len())
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

        // Build and persist the trust receipt before advancing live consensus state.
        let receipt = match commit_receipt_from_certificate(state, store, &cert).await {
            Ok(receipt) => receipt,
            Err(e) => {
                tracing::warn!(err = %e, "Failed to build trust receipt for commit");
                return;
            }
        };
        if let Err(e) = with_store_blocking(Arc::clone(store), "check_and_commit_persist", {
            let receipt = receipt.clone();
            let cert = cert.clone();
            move |store| {
                store
                    .persist_commit_certificate_with_receipt_sync(&hash, height, &cert, &receipt)
                    .map_err(|e| {
                        format!(
                            "persist local commit certificate and receipt for {hash} at height {height}: {e}"
                        )
                    })
            }
        })
        .await
        {
            tracing::warn!(err = %e, "Failed to persist commit state");
            return;
        }

        let cert_for_commit = cert.clone();
        if let Err(e) =
            with_reactor_state_blocking(Arc::clone(state), "check_and_commit_apply", move |s| {
                if !consensus::is_finalized(&s.consensus, &hash) {
                    let resolver = s.validator_public_keys.clone();
                    consensus::commit_verified(&mut s.consensus, cert_for_commit, &resolver)
                        .map_err(|e| format!("apply persisted local commit certificate: {e}"))?;
                }
                checked_committed_height(s.consensus.committed.len()).and_then(|actual_height| {
                    if actual_height == height {
                        Ok(())
                    } else {
                        Err(format!(
                            "persisted local commit height {height} does not match consensus height {actual_height}"
                        ))
                    }
                })
            })
            .await
        {
            tracing::warn!(err = %e, "Failed to apply persisted local commit certificate");
            return;
        }

        // Apply a committed ValidatorChange to live consensus state and
        // persist it, strictly after the commit certificate has verified
        // and the trust receipt has been durably written above. Ordinary
        // (non-governance) committed nodes are a no-op here.
        apply_committed_validator_change_after_commit(state, store, &hash, &receipt).await;

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
/// Called by the API layer when a new governance action is requested, behind
/// the `unaudited-admin-governance-shortcut` feature (see `api.rs`). The
/// infrastructure-Holon Scaling path no longer calls this as of VCG-010/D5
/// (recommendation-only, full stop — it emits a `RecommendationOnly`
/// governance event via `broadcast_governance_event` instead of submitting a
/// DAG proposal). Exercised directly by `reactor::tests` regardless of
/// feature.
#[cfg_attr(not(feature = "unaudited-admin-governance-shortcut"), allow(dead_code))]
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

    validate_governance_proposal_payload(payload).map_err(|e| anyhow::anyhow!("{e}"))?;

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

    // Store it locally, along with the raw governance payload so a later
    // commit can decode and apply it (the DAG node itself only commits to a
    // one-way payload_hash digest).
    with_store_blocking(Arc::clone(store), "submit_proposal_put", {
        let node = node.clone();
        let payload = payload.to_vec();
        move |store| {
            let node_hash = node.hash;
            store.put_sync(node).map_err(|e| format!("put: {e}"))?;
            store
                .save_governance_payload(&node_hash, &payload)
                .map_err(|e| format!("store proposed node governance payload: {e}"))
        }
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
        payload: payload.to_vec(),
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
    let (sender, timestamp) = with_reactor_state_blocking(
        Arc::clone(state),
        "broadcast_governance_timestamp",
        move |s| {
            let timestamp = s
                .clock
                .try_tick()
                .map_err(|e| format!("governance event timestamp: {e}"))?;
            Ok((s.node_did.clone(), timestamp))
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut event = GovernanceEventMsg {
        sender,
        event_type,
        payload,
        timestamp,
        signature: Signature::empty(),
    };
    let signing_payload =
        governance_event_signing_payload(&event).map_err(|e| anyhow::anyhow!("{e}"))?;
    event.signature = with_reactor_state_blocking(
        Arc::clone(state),
        "broadcast_governance_signature",
        move |s| Ok((s.sign_fn)(&signing_payload)),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = WireMessage::GovernanceEvent(event.clone());

    match net_handle.publish(topics::GOVERNANCE, msg.clone()).await {
        Ok(()) => Ok(()),
        Err(e) if is_single_validator(state).await? && is_no_peers_subscribed(&e.to_string()) => {
            tracing::warn!(
                event_type = ?event.event_type,
                "single-validator governance broadcast has no peers; applying event locally"
            );
            apply_governance_event_locally(state, &event)
                .await
                .map_err(|e| anyhow::anyhow!("apply governance event locally: {e}"))
        }
        Err(e) => Err(anyhow::anyhow!("broadcast governance: {e}")),
    }
}

async fn is_single_validator(state: &SharedReactorState) -> anyhow::Result<bool> {
    with_reactor_state_blocking(
        Arc::clone(state),
        "governance_broadcast_single_validator_check",
        |s| Ok(s.is_validator && s.consensus.config.validators.len() == 1),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))
}

fn is_no_peers_subscribed(error: &str) -> bool {
    error.contains("NoPeersSubscribedToTopic")
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

    fn sign_governance_event_for_index(event: &GovernanceEventMsg, index: usize) -> Signature {
        let payload = governance_event_signing_payload(event).expect("governance event payload");
        validator_keypair(index).sign(&payload)
    }

    fn sign_governance_payload_for_index(payload: &[u8], index: usize) -> Signature {
        validator_keypair(index).sign(payload)
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

    fn single_validator_certificate(node_hash: Hash256, voter: &Did) -> CommitCertificate {
        CommitCertificate {
            node_hash,
            round: 0,
            votes: vec![vote_for(voter, 0, 0, node_hash)],
        }
    }

    /// Deterministic keypair for the "new validator v4" fixture used by the
    /// shared `validator_change_payload_for_test` helper below. Distinct
    /// seed from the VCG-015-specific fixtures (200, 201) further down this
    /// module.
    fn new_validator_v4_keypair() -> KeyPair {
        KeyPair::from_secret_bytes([199u8; 32]).expect("deterministic new-validator-v4 keypair")
    }

    /// DID derived from `new_validator_v4_keypair`'s real public key.
    /// VCG-015 requires an `AddValidator` payload's DID to actually hash
    /// from its accompanying public key, so this fixture's "new validator"
    /// identity can no longer be an arbitrary hand-picked string like the
    /// pre-VCG-015 `"did:exo:v4"` literal.
    fn new_validator_v4_did() -> Did {
        crate::identity::did_from_public_key(new_validator_v4_keypair().public_key())
            .expect("derive DID from new-validator-v4 public key")
    }

    fn validator_change_payload_for_test() -> Vec<u8> {
        let change = crate::wire::ValidatorChange::AddValidator {
            did: new_validator_v4_did(),
            public_key: *new_validator_v4_keypair().public_key(),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).unwrap();
        payload
    }

    fn validator_remove_payload_for_test() -> Vec<u8> {
        let change = crate::wire::ValidatorChange::RemoveValidator {
            did: Did::new("did:exo:v4").unwrap(),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).unwrap();
        payload
    }

    fn proposal_msg_for(
        proposer: Did,
        proposer_index: usize,
        round: u64,
        node: DagNode,
    ) -> ConsensusProposalMsg {
        proposal_msg_for_payload(
            proposer,
            proposer_index,
            round,
            node,
            validator_change_payload_for_test(),
        )
    }

    fn proposal_msg_for_payload(
        proposer: Did,
        proposer_index: usize,
        round: u64,
        node: DagNode,
        payload: Vec<u8>,
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
            payload,
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

    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_idx = source.find(start).expect("source start marker");
        let rest = &source[start_idx..];
        let end_idx = rest.find(end).expect("source end marker");
        &rest[..end_idx]
    }

    fn make_validators(n: usize) -> BTreeSet<Did> {
        (0..n)
            .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid"))
            .collect()
    }

    fn make_single_validator() -> BTreeSet<Did> {
        let mut validators = BTreeSet::new();
        validators.insert(Did::new("did:exo:v0").unwrap());
        validators
    }

    fn temp_store() -> (tempfile::TempDir, Arc<Mutex<SqliteDagStore>>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));
        (dir, store)
    }

    fn audit_payload(actor: &str, action_type: &str, outcome: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "avc.trust_receipt.v1",
            "actor_did": actor,
            "action_type": action_type,
            "outcome": outcome,
            "timestamp_ms": 1_700_000_000_000_u64
        }))
        .unwrap()
    }

    async fn reply_no_peers_to_publish_retries(
        cmd_rx: &mut mpsc::Receiver<crate::network::NetworkCommand>,
    ) {
        for _ in 0..crate::network::NETWORK_PUBLISH_MAX_ATTEMPTS {
            let command = cmd_rx.recv().await.expect("published network command");
            let crate::network::NetworkCommand::Publish { reply, .. } = command else {
                panic!("expected publish command");
            };
            reply
                .send(Err(
                    "gossipsub publish failed: NoPeersSubscribedToTopic".into()
                ))
                .expect("publish ack receiver active");
        }
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
    fn reactor_documents_locking_model_and_single_mutex_sections() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("## Locking model"),
            "reactor docs must spell out the store/state locking model"
        );
        assert!(
            production.contains("Never hold both mutexes at the same time"),
            "reactor docs must require single-mutex critical sections"
        );
        assert!(
            production.contains("snapshot, release, then acquire"),
            "reactor docs must define the safe order for workflows needing store and state"
        );
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
    fn reactor_commit_paths_persist_receipts_atomically_with_commit_state() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");
        let handle_commit_body = production
            .split("async fn handle_commit")
            .nth(1)
            .expect("handle_commit present")
            .split("/// Check if a node has reached quorum")
            .next()
            .expect("handle_commit body present");
        let check_and_commit_body = production
            .split("async fn check_and_commit")
            .nth(1)
            .expect("check_and_commit present")
            .split("// ---------------------------------------------------------------------------\n// Proposal submission")
            .next()
            .expect("check_and_commit body present");

        for (name, body, atomic_call) in [
            (
                "handle_commit",
                handle_commit_body,
                "mark_committed_with_receipt_sync",
            ),
            (
                "check_and_commit",
                check_and_commit_body,
                "persist_commit_certificate_with_receipt_sync",
            ),
        ] {
            assert!(
                body.contains(atomic_call),
                "{name} must use the atomic commit/receipt persistence helper"
            );
            assert!(
                !body.contains(".mark_committed_sync("),
                "{name} must not persist a commit marker separately from its receipt"
            );
            assert!(
                !body.contains(".save_receipt(&receipt)"),
                "{name} must not persist commit receipts separately from commit state"
            );
        }
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
    fn broadcast_governance_event_source_signs_event_envelope() {
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
            broadcaster.contains("governance_event_signing_payload(&event)"),
            "governance broadcasts must sign the canonical event envelope"
        );
        assert!(
            !broadcaster.contains("payload_for_signature"),
            "governance broadcasts must not sign only raw event payload bytes"
        );
    }

    #[test]
    fn governance_audit_apply_path_does_not_persist_receipts() {
        let source = include_str!("reactor.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");
        let apply_body = source_between(
            production,
            "async fn apply_governance_event_locally",
            "fn signed_vote",
        );

        assert!(
            apply_body.contains("validate_audit_event_payload(event)"),
            "audit governance events should be schema-validated before emission"
        );
        assert!(
            !apply_body.contains("TrustReceipt::new"),
            "governance audit events must not mint trust receipts"
        );
        assert!(
            !apply_body.contains(".save_receipt("),
            "governance audit events must not persist trust receipts"
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

        let payload = validator_change_payload_for_test();
        let _result = submit_proposal(&state, &store, &net_handle, &payload).await;
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
    async fn submit_proposal_rejects_untyped_payload_without_mutating_state() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);

        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);

        let result = submit_proposal(
            &state,
            &store,
            &net_handle,
            b"not a typed governance proposal",
        )
        .await;

        assert!(
            result.unwrap_err().to_string().contains("proposal payload"),
            "opaque proposal payloads must fail before append/store/vote"
        );
        assert_eq!(state.lock().unwrap().dag.len(), 0);
        assert!(store.lock().unwrap().tips_sync().unwrap().is_empty());
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
        let keypair = validator_keypair(0);
        let signing_payload = governance_event_signing_payload(&event).unwrap();
        assert!(
            crypto::verify(&signing_payload, &event.signature, keypair.public_key()),
            "governance broadcasts must sign the full event envelope"
        );
        assert!(
            !crypto::verify(&event.payload, &event.signature, keypair.public_key()),
            "governance event signatures must not validate against raw payload bytes"
        );
    }

    #[tokio::test]
    async fn single_validator_no_peers_applies_audit_event_without_minting_receipt() {
        let validators = make_single_validator();
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let payload = audit_payload("did:exo:archon", "archon.workflow.success", "success");

        let broadcast_task = {
            let state = Arc::clone(&state);
            let net_handle = net_handle.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                broadcast_governance_event(
                    &state,
                    &net_handle,
                    GovernanceEventType::AuditEntry,
                    payload,
                )
                .await
            })
        };

        reply_no_peers_to_publish_retries(&mut cmd_rx).await;
        broadcast_task
            .await
            .expect("broadcast task joins")
            .expect("single-validator local apply succeeds");

        let receipts = store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:archon", 10)
            .unwrap();
        assert!(
            receipts.is_empty(),
            "single-validator governance fallback must not mint trust receipts"
        );
    }

    #[tokio::test]
    async fn multi_validator_no_peers_still_fails_closed() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
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
                    audit_payload("did:exo:archon", "archon.workflow.success", "success"),
                )
                .await
            })
        };

        reply_no_peers_to_publish_retries(&mut cmd_rx).await;
        let err = broadcast_task
            .await
            .expect("broadcast task joins")
            .unwrap_err();
        assert!(err.to_string().contains("NoPeersSubscribedToTopic"));
        assert!(
            store
                .lock()
                .unwrap()
                .load_receipts_by_actor("did:exo:archon", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn inbound_governance_audit_event_emits_without_minting_receipt() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let mut event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::AuditEntry,
            payload: audit_payload("did:exo:archon", "archon.workflow.success", "success"),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::empty(),
        };
        event.signature = sign_governance_event_for_index(&event, 1);

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        let ReactorEvent::GovernanceEventReceived { event } =
            reactor_rx.recv().await.expect("reactor event emitted")
        else {
            panic!("expected governance event");
        };
        assert!(matches!(event.event_type, GovernanceEventType::AuditEntry));
        let receipts = store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:archon", 10)
            .unwrap();
        assert!(
            receipts.is_empty(),
            "governance audit events must not mint durable trust receipts"
        );
    }

    #[tokio::test]
    async fn inbound_governance_audit_event_cannot_mint_receipt_without_commit_certificate() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let mut event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::AuditEntry,
            payload: audit_payload("did:exo:archon", "archon.workflow.success", "success"),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::empty(),
        };
        event.signature = sign_governance_event_for_index(&event, 1);

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        let ReactorEvent::GovernanceEventReceived { event } =
            reactor_rx.recv().await.expect("reactor event emitted")
        else {
            panic!("expected governance event");
        };
        assert!(matches!(event.event_type, GovernanceEventType::AuditEntry));
        assert!(
            store
                .lock()
                .unwrap()
                .load_receipts_by_actor("did:exo:archon", 10)
                .unwrap()
                .is_empty(),
            "governance audit events must not mint durable trust receipts without a commit certificate"
        );
    }

    #[tokio::test]
    async fn single_validator_fallback_cannot_mint_audit_receipt_without_commit_certificate() {
        let validators = make_single_validator();
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
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
                    audit_payload("did:exo:archon", "archon.workflow.success", "success"),
                )
                .await
            })
        };

        reply_no_peers_to_publish_retries(&mut cmd_rx).await;
        broadcast_task
            .await
            .expect("broadcast task joins")
            .expect("single-validator local apply succeeds");

        assert!(
            store
                .lock()
                .unwrap()
                .load_receipts_by_actor("did:exo:archon", 10)
                .unwrap()
                .is_empty(),
            "single-validator governance fallback must not mint trust receipts"
        );
    }

    #[tokio::test]
    async fn inbound_governance_audit_event_rejects_bad_signature() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::AuditEntry,
            payload: audit_payload("did:exo:archon", "archon.workflow.success", "success"),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::from_bytes([4u8; 64]),
        };

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        assert!(reactor_rx.try_recv().is_err());
        assert!(
            store
                .lock()
                .unwrap()
                .load_receipts_by_actor("did:exo:archon", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn inbound_governance_non_audit_event_rejects_empty_signature() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::DecisionCreated,
            payload: b"decision-created".to_vec(),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::empty(),
        };

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        assert!(
            reactor_rx.try_recv().is_err(),
            "unsigned non-audit governance events must not be emitted"
        );
    }

    #[tokio::test]
    async fn inbound_governance_non_audit_event_accepts_envelope_signature() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let mut event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::DecisionCreated,
            payload: b"decision-created".to_vec(),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::empty(),
        };
        event.signature = sign_governance_event_for_index(&event, 1);

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        let ReactorEvent::GovernanceEventReceived { event } =
            reactor_rx.recv().await.expect("reactor event emitted")
        else {
            panic!("expected governance event");
        };
        assert!(matches!(
            event.event_type,
            GovernanceEventType::DecisionCreated
        ));
    }

    #[tokio::test]
    async fn inbound_governance_event_rejects_signature_replayed_to_other_type() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let mut event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::DecisionCreated,
            payload: b"decision-created".to_vec(),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::empty(),
        };
        event.signature = sign_governance_event_for_index(&event, 1);
        event.event_type = GovernanceEventType::VoteCast;

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        assert!(
            reactor_rx.try_recv().is_err(),
            "governance event signatures must bind event_type"
        );
    }

    #[tokio::test]
    async fn inbound_governance_audit_event_rejects_payload_only_signature() {
        let validators = make_validators(4);
        let config = config_for(Did::new("did:exo:v0").unwrap(), true, validators);
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let mut event = GovernanceEventMsg {
            sender: Did::new("did:exo:v1").unwrap(),
            event_type: GovernanceEventType::AuditEntry,
            payload: audit_payload("did:exo:archon", "archon.workflow.success", "success"),
            timestamp: Timestamp::new(1_700, 0),
            signature: Signature::empty(),
        };
        event.signature = sign_governance_payload_for_index(&event.payload, 1);

        handle_wire_message(
            &state,
            &store,
            &net_handle,
            &reactor_tx,
            WireMessage::GovernanceEvent(event),
        )
        .await;

        assert!(
            reactor_rx.try_recv().is_err(),
            "payload-only signatures must not authenticate governance event envelopes"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .load_receipts_by_actor("did:exo:archon", 10)
                .unwrap()
                .is_empty()
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

    #[tokio::test]
    async fn local_commit_does_not_advance_without_persisted_trust_receipt() {
        let validators = make_single_validator();
        let node_did = Did::new("did:exo:v0").unwrap();
        let config = config_for(node_did.clone(), true, validators);
        let state = create_reactor_state(&config, Arc::new(|_| Signature::empty()), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let valid_sign_fn = make_sign_fn();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"must-not-commit-without-receipt",
            &node_did,
            &*valid_sign_fn,
            &mut clock,
        )
        .unwrap();
        let node_hash = node.hash;

        store.lock().unwrap().put_sync(node.clone()).unwrap();
        {
            let mut s = state.lock().unwrap();
            let resolver = s.validator_public_keys.clone();
            let proposal = Proposal {
                proposer: node_did.clone(),
                round: s.consensus.current_round,
                node_hash: node.hash,
            };
            let proposal_sig = sign_proposal_for_index(&proposal, 0);
            consensus::propose_verified(
                &mut s.consensus,
                &node,
                &node_did,
                &proposal_sig,
                &resolver,
            )
            .unwrap();
            consensus::vote_verified(
                &mut s.consensus,
                vote_for(&node_did, 0, 0, node.hash),
                &resolver,
            )
            .unwrap();
            assert!(
                consensus::check_commit(&s.consensus, &node.hash).is_some(),
                "test setup must form a valid quorum certificate before exercising the receipt boundary"
            );
        }

        check_and_commit(&state, &store, &net_handle, &reactor_tx, &node_hash).await;

        assert!(
            reactor_rx.try_recv().is_err(),
            "commit event must not be emitted when the trust receipt cannot be persisted"
        );
        {
            let s = state.lock().unwrap();
            assert!(
                !consensus::is_finalized(&s.consensus, &node.hash),
                "consensus state must not finalize a node without a durable trust receipt"
            );
            assert!(
                s.consensus.committed.is_empty(),
                "commit order must not advance without a durable trust receipt"
            );
        }
        {
            let st = store.lock().unwrap();
            assert!(
                !st.is_committed(&node.hash).unwrap(),
                "store commit marker must roll back when receipt persistence rejects the signature"
            );
            assert!(
                st.load_receipts_by_actor("did:exo:v0", 10)
                    .unwrap()
                    .is_empty(),
                "failed receipt persistence must not leave a partial receipt row"
            );
        }
    }

    #[tokio::test]
    async fn network_commit_does_not_advance_without_persisted_trust_receipt() {
        let validators = make_single_validator();
        let node_did = Did::new("did:exo:v0").unwrap();
        let config = config_for(node_did.clone(), true, validators);
        let state = create_reactor_state(&config, Arc::new(|_| Signature::empty()), None);
        let (_dir, store) = temp_store();
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let valid_sign_fn = make_sign_fn();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"network-commit-must-not-outpace-receipt",
            &node_did,
            &*valid_sign_fn,
            &mut clock,
        )
        .unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();
        let msg = ConsensusCommitMsg {
            certificate: single_validator_certificate(node.hash, &node_did),
        };

        handle_commit(&state, &store, &reactor_tx, msg).await;

        assert!(
            reactor_rx.try_recv().is_err(),
            "network commit event must not be emitted when the trust receipt cannot be persisted"
        );
        {
            let s = state.lock().unwrap();
            assert!(
                !consensus::is_finalized(&s.consensus, &node.hash),
                "network certificate must not finalize consensus without a durable trust receipt"
            );
            assert!(
                s.consensus.committed.is_empty(),
                "network certificate must not advance commit order without a durable trust receipt"
            );
        }
        {
            let st = store.lock().unwrap();
            assert!(
                !st.is_committed(&node.hash).unwrap(),
                "network certificate must not persist a commit marker without its receipt"
            );
            assert!(
                st.load_receipts_by_actor("did:exo:v0", 10)
                    .unwrap()
                    .is_empty(),
                "failed network receipt persistence must not leave a partial receipt row"
            );
        }
    }

    #[tokio::test]
    async fn local_commit_persists_certificate_receipt_and_emits_event() {
        let validators = make_single_validator();
        let node_did = Did::new("did:exo:v0").unwrap();
        let config = config_for(node_did.clone(), true, validators);
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            b"valid-local-commit-with-receipt",
            &node_did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let node_hash = node.hash;

        store.lock().unwrap().put_sync(node.clone()).unwrap();
        {
            let mut s = state.lock().unwrap();
            let resolver = s.validator_public_keys.clone();
            let proposal = Proposal {
                proposer: node_did.clone(),
                round: s.consensus.current_round,
                node_hash: node.hash,
            };
            let proposal_sig = sign_proposal_for_index(&proposal, 0);
            consensus::propose_verified(
                &mut s.consensus,
                &node,
                &node_did,
                &proposal_sig,
                &resolver,
            )
            .unwrap();
            consensus::vote_verified(
                &mut s.consensus,
                vote_for(&node_did, 0, 0, node.hash),
                &resolver,
            )
            .unwrap();
        }

        let commit_task = {
            let state = Arc::clone(&state);
            let store = Arc::clone(&store);
            let net_handle = net_handle.clone();
            let reactor_tx = reactor_tx.clone();
            tokio::spawn(async move {
                check_and_commit(&state, &store, &net_handle, &reactor_tx, &node_hash).await;
            })
        };
        let command = cmd_rx.recv().await.expect("commit certificate publish");
        let crate::network::NetworkCommand::Publish {
            topic,
            message,
            reply,
        } = command
        else {
            panic!("expected publish command");
        };
        assert_eq!(topic, topics::CONSENSUS);
        assert!(matches!(message, WireMessage::ConsensusCommit(_)));
        reply.send(Ok(())).expect("publish ack receiver active");
        commit_task.await.expect("commit task joins");

        let ReactorEvent::NodeCommitted {
            hash,
            height,
            round,
        } = reactor_rx.recv().await.expect("commit event emitted")
        else {
            panic!("expected commit event");
        };
        assert_eq!(hash, node.hash);
        assert_eq!(height, 1);
        assert_eq!(round, 0);
        {
            let s = state.lock().unwrap();
            assert!(consensus::is_finalized(&s.consensus, &node.hash));
        }
        {
            let st = store.lock().unwrap();
            assert!(st.is_committed(&node.hash).unwrap());
            assert_eq!(st.load_certificates().unwrap().len(), 1);
            let receipts = st.load_receipts_by_actor("did:exo:v0", 10).unwrap();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].action_hash, node.hash);
            assert!(!receipts[0].signature.is_empty());
        }
    }

    // VCG-005 RED: the BFT propose/vote/commit machinery mints a receipt and
    // advances committed height, but a committed `ValidatorChange` payload is
    // never decoded or applied to live consensus state or persistence. These
    // two tests must fail today because `check_and_commit`/`handle_commit`
    // have no code path that calls `store.save_validator_set` or mutates
    // `s.consensus.config.validators` / `s.validator_public_keys`.
    #[tokio::test]
    async fn validator_set_change_applies_to_live_config_after_quorum_commit() {
        let validators = make_validators(4);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let proposer_did = validator_vec[0].clone();
        let config = config_for(proposer_did.clone(), true, validators.clone());
        // Proposer signs with its own key (index 0), matching `make_sign_fn`.
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        drop(cmd_rx);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);

        let new_validator = new_validator_v4_did();
        let payload = validator_change_payload_for_test();

        // Build the canonical ValidatorChange DAG node the same way
        // submit_proposal would, and persist it locally.
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            &payload,
            &proposer_did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();
        // submit_proposal also persists the raw governance payload
        // alongside the node — the node itself only commits to a one-way
        // payload_hash digest, so the committed path needs the original
        // bytes back to decode and apply the ValidatorChange.
        store
            .lock()
            .unwrap()
            .save_governance_payload(&node.hash, &payload)
            .unwrap();

        // Register the proposal and cross the quorum threshold (3 of 4
        // validators) by voting directly against consensus state — this
        // mirrors submit_proposal's self-vote plus two more validators.
        {
            let mut s = state.lock().unwrap();
            let resolver = s.validator_public_keys.clone();
            let proposal = Proposal {
                proposer: proposer_did.clone(),
                round: s.consensus.current_round,
                node_hash: node.hash,
            };
            let proposal_sig = sign_proposal_for_index(&proposal, 0);
            consensus::propose_verified(
                &mut s.consensus,
                &node,
                &proposer_did,
                &proposal_sig,
                &resolver,
            )
            .expect("proposal verifies");
            for (index, voter) in validator_vec.iter().enumerate().take(3) {
                let vote = vote_for(voter, index, s.consensus.current_round, node.hash);
                consensus::vote_verified(&mut s.consensus, vote, &resolver)
                    .expect("validator votes verify");
            }
        }

        let net_handle_for_commit = net_handle.clone();
        check_and_commit(
            &state,
            &store,
            &net_handle_for_commit,
            &reactor_tx,
            &node.hash,
        )
        .await;

        let _event = reactor_rx
            .try_recv()
            .expect("commit event emitted after quorum");

        // Expected red: the live consensus validator set does not yet contain
        // the new validator because nothing decodes the committed payload.
        {
            let s = state.lock().unwrap();
            assert!(
                s.consensus.config.validators.contains(&new_validator),
                "committed ValidatorSetChange must mutate live consensus config.validators"
            );
            assert!(
                s.validator_public_keys
                    .as_map()
                    .contains_key(&new_validator),
                "committed ValidatorSetChange must extend the live validator public-key resolver"
            );
        }

        // Expected red: store.save_validator_set is never called after commit,
        // so the persisted set still reflects genesis membership only.
        {
            let st = store.lock().unwrap();
            let persisted = st
                .load_validator_set()
                .expect("load_validator_set succeeds");
            assert!(
                persisted.contains(&new_validator),
                "committed ValidatorSetChange must be persisted via store.save_validator_set"
            );
        }
    }

    #[tokio::test]
    async fn validator_set_change_without_quorum_does_not_mutate() {
        let validators = make_validators(4);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let proposer_did = validator_vec[0].clone();
        let config = config_for(proposer_did.clone(), true, validators.clone());
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        drop(cmd_rx);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);

        let new_validator = new_validator_v4_did();
        let payload = validator_change_payload_for_test();

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            &payload,
            &proposer_did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();
        // submit_proposal also persists the raw governance payload
        // alongside the node — see the comment in the sibling quorum test
        // above for why this is required for the committed path to decode
        // and apply a ValidatorChange.
        store
            .lock()
            .unwrap()
            .save_governance_payload(&node.hash, &payload)
            .unwrap();

        // Only the proposer's self-vote is cast — no quorum in a 4-validator set.
        {
            let mut s = state.lock().unwrap();
            let resolver = s.validator_public_keys.clone();
            let proposal = Proposal {
                proposer: proposer_did.clone(),
                round: s.consensus.current_round,
                node_hash: node.hash,
            };
            let proposal_sig = sign_proposal_for_index(&proposal, 0);
            consensus::propose_verified(
                &mut s.consensus,
                &node,
                &proposer_did,
                &proposal_sig,
                &resolver,
            )
            .expect("proposal verifies");
            let round = s.consensus.current_round;
            consensus::vote_verified(
                &mut s.consensus,
                vote_for(&proposer_did, 0, round, node.hash),
                &resolver,
            )
            .expect("self-vote verifies");
        }

        check_and_commit(&state, &store, &net_handle, &reactor_tx, &node.hash).await;

        assert!(
            reactor_rx.try_recv().is_err(),
            "no commit event should be emitted without quorum"
        );
        {
            let s = state.lock().unwrap();
            assert!(
                !consensus::is_finalized(&s.consensus, &node.hash),
                "node must not be finalized without quorum"
            );
            assert!(
                !s.consensus.config.validators.contains(&new_validator),
                "validator set must not mutate without quorum-gated commit"
            );
            assert!(
                !s.validator_public_keys
                    .as_map()
                    .contains_key(&new_validator),
                "validator public-key resolver must not extend without quorum-gated commit"
            );
        }
        {
            let st = store.lock().unwrap();
            let persisted = st
                .load_validator_set()
                .expect("load_validator_set succeeds");
            assert!(
                !persisted.contains(&new_validator),
                "persisted validator set must not change without quorum-gated commit"
            );
        }
    }

    // ------------------------------------------------------------------
    // W3(A)/R1.5: BFT min-4 validator floor enforced at apply-on-commit,
    // not just at api.rs's propose-time pre-check. See the module-level
    // `apply_committed_validator_change_in_memory` doc comment for the
    // concurrent-remove race this closes.

    /// Minimal `TrustReceipt` fixture for driving
    /// `apply_committed_validator_change_after_commit` directly in tests,
    /// bypassing the full propose/vote/commit machinery already covered by
    /// the sibling tests above. Content doesn't matter for these tests —
    /// the function only reads `receipt.receipt_hash` for a log field.
    fn dummy_receipt_for_test(
        node_hash: Hash256,
        sign_fn: &Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    ) -> TrustReceipt {
        TrustReceipt::new(
            Did::new("did:exo:v0").unwrap(),
            Hash256::digest(b"test-authority-chain"),
            None,
            "dag.commit".to_string(),
            node_hash,
            ReceiptOutcome::Executed,
            Timestamp::new(1_700_000_000, 0),
            &**sign_fn,
        )
        .expect("dummy trust receipt builds")
    }

    /// Persist a `RemoveValidator` governance payload for `target` as a
    /// committed DAG node, returning its hash. Mirrors the persistence the
    /// real propose → quorum → commit path performs (`store.put_sync` +
    /// `store.save_governance_payload`) without needing to actually drive
    /// consensus voting — these tests target
    /// `apply_committed_validator_change_after_commit` directly, which only
    /// needs the committed node + governance payload to already exist.
    fn persist_remove_validator_node(
        store: &Arc<Mutex<SqliteDagStore>>,
        dag: &mut Dag,
        clock: &mut DeterministicDagClock,
        parents: &[Hash256],
        creator: &Did,
        sign_fn: &dyn Fn(&[u8]) -> Signature,
        target: &Did,
    ) -> Hash256 {
        let change = crate::wire::ValidatorChange::RemoveValidator {
            did: target.clone(),
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).unwrap();

        let node = append(dag, parents, &payload, creator, sign_fn, clock).unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();
        store
            .lock()
            .unwrap()
            .save_governance_payload(&node.hash, &payload)
            .unwrap();
        node.hash
    }

    #[tokio::test]
    async fn remove_validator_at_floor_refused_at_apply_time_even_bypassing_http_handler() {
        // Exactly at the BFT floor (4 validators). A RemoveValidator commit
        // reaching the apply step here must be refused as a no-op — this
        // is the invariant api.rs's propose-time `validator_count <= 4`
        // check cannot enforce for any caller that reaches
        // `apply_committed_validator_change_after_commit` directly (e.g. a
        // future internal caller, or the second half of the concurrent
        // race exercised by the sibling test below).
        let validators = make_validators(4);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let target = validator_vec[3].clone();
        let config = config_for(validator_vec[0].clone(), true, validators.clone());
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();

        let hash = persist_remove_validator_node(
            &store,
            &mut dag,
            &mut clock,
            &[],
            &validator_vec[0],
            &*sign_fn,
            &target,
        );
        let receipt = dummy_receipt_for_test(hash, &sign_fn);

        apply_committed_validator_change_after_commit(&state, &store, &hash, &receipt).await;

        let s = state.lock().unwrap();
        assert_eq!(
            s.consensus.config.validators.len(),
            4,
            "validator set must stay at the BFT floor — apply-time refusal is a no-op"
        );
        assert!(
            s.consensus.config.validators.contains(&target),
            "target validator must still be present — the removal must have been refused"
        );
        assert!(
            s.validator_public_keys.as_map().contains_key(&target),
            "target validator's public key must not be dropped when the removal is refused"
        );
    }

    #[tokio::test]
    async fn concurrent_removals_cannot_drop_validator_set_below_floor() {
        // THE RACE (VCG-005 concurrent-remove gap): 5 validators, two
        // independent RemoveValidator commits for two different DIDs, each
        // individually legitimate (5 > 4 at the moment either is proposed).
        // Applied sequentially through the same lock with no re-check, the
        // set would drop 5 -> 4 -> 3, one below the 3f+1=4 safety floor.
        // Before the fix this test observes exactly that: both removals
        // apply and the set drops to 3. After the fix, the single
        // `Mutex<ReactorState>` (entered via `with_reactor_state_blocking`)
        // serializes the two apply tasks, and whichever runs second sees
        // the already-decremented count and refuses.
        let validators = make_validators(5);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let target_a = validator_vec[3].clone();
        let target_b = validator_vec[4].clone();
        let config = config_for(validator_vec[0].clone(), true, validators.clone());
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();

        // Two independently committed RemoveValidator nodes, each targeting
        // a different DID. Both are persisted up front (mirroring two
        // proposals that each already reached quorum before either applied)
        // — the race under test is in the apply step, not the propose/vote
        // machinery already covered by the sibling quorum tests above.
        let hash_a = persist_remove_validator_node(
            &store,
            &mut dag,
            &mut clock,
            &[],
            &validator_vec[0],
            &*sign_fn,
            &target_a,
        );
        let hash_b = persist_remove_validator_node(
            &store,
            &mut dag,
            &mut clock,
            &[hash_a],
            &validator_vec[0],
            &*sign_fn,
            &target_b,
        );
        let receipt_a = dummy_receipt_for_test(hash_a, &sign_fn);
        let receipt_b = dummy_receipt_for_test(hash_b, &sign_fn);

        let state_a = Arc::clone(&state);
        let store_a = Arc::clone(&store);
        let task_a = tokio::spawn(async move {
            apply_committed_validator_change_after_commit(&state_a, &store_a, &hash_a, &receipt_a)
                .await;
        });

        let state_b = Arc::clone(&state);
        let store_b = Arc::clone(&store);
        let task_b = tokio::spawn(async move {
            apply_committed_validator_change_after_commit(&state_b, &store_b, &hash_b, &receipt_b)
                .await;
        });

        let (joined_a, joined_b) = tokio::join!(task_a, task_b);
        joined_a.expect("apply task A joins");
        joined_b.expect("apply task B joins");

        let s = state.lock().unwrap();
        assert_eq!(
            s.consensus.config.validators.len(),
            4,
            "concurrent removals must never drop the live validator set below the BFT floor of 4"
        );
        let a_present = s.consensus.config.validators.contains(&target_a);
        let b_present = s.consensus.config.validators.contains(&target_b);
        assert_ne!(
            a_present, b_present,
            "exactly one of the two concurrent removals must have applied — the other refused"
        );
    }

    #[tokio::test]
    async fn remove_validator_above_floor_still_applies() {
        // The new `<=` floor guard must not block a legitimate removal that
        // keeps the set at or above the BFT minimum: 5 validators, single
        // removal, set must drop to 4 with the target's key gone.
        let validators = make_validators(5);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let target = validator_vec[4].clone();
        let config = config_for(validator_vec[0].clone(), true, validators.clone());
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();

        let hash = persist_remove_validator_node(
            &store,
            &mut dag,
            &mut clock,
            &[],
            &validator_vec[0],
            &*sign_fn,
            &target,
        );
        let receipt = dummy_receipt_for_test(hash, &sign_fn);

        apply_committed_validator_change_after_commit(&state, &store, &hash, &receipt).await;

        let s = state.lock().unwrap();
        assert_eq!(
            s.consensus.config.validators.len(),
            4,
            "a legitimate above-floor removal must still apply"
        );
        assert!(
            !s.consensus.config.validators.contains(&target),
            "removed validator must be gone from the live set"
        );
        assert!(
            !s.validator_public_keys.as_map().contains_key(&target),
            "removed validator's public key must be gone from the resolver"
        );
    }

    // ------------------------------------------------------------------
    // VCG-015: added validators must register a REAL public key, not the
    // deterministic-but-cryptographically-inert placeholder minted by
    // `placeholder_validator_public_key`. A validator admitted via a
    // committed `ValidatorChange::AddValidator` must be able to cast a
    // vote / commit certificate that `crypto::verify` (transitively, via
    // the `ValidatorPublicKeys` resolver) ACCEPTS against the key
    // registered for its DID.
    // ------------------------------------------------------------------

    /// Build a canonical `AddValidator` CBOR payload carrying the target
    /// validator's REAL Ed25519 public key (VCG-015 wire extension), keyed
    /// to `did`. Compile-red until `ValidatorChange::AddValidator` grows a
    /// `public_key` field.
    fn validator_change_payload_with_key(did: &Did, public_key: PublicKey) -> Vec<u8> {
        let change = crate::wire::ValidatorChange::AddValidator {
            did: did.clone(),
            public_key,
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).unwrap();
        payload
    }

    #[tokio::test]
    async fn added_validator_real_key_is_registered_and_accepts_its_own_vote_signature() {
        let validators = make_validators(4);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let proposer_did = validator_vec[0].clone();
        let config = config_for(proposer_did.clone(), true, validators.clone());
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        drop(cmd_rx);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);

        // A genuine, freshly-generated Ed25519 keypair for the incoming
        // validator — NOT one of the four genesis `validator_keypair(index)`
        // fixtures, and its DID is derived (not hand-picked), matching how a
        // real node would onboard.
        let new_validator_keypair =
            KeyPair::from_secret_bytes([200u8; 32]).expect("deterministic new-validator keypair");
        let new_validator_public_key = *new_validator_keypair.public_key();
        let new_validator_did = crate::identity::did_from_public_key(&new_validator_public_key)
            .expect("derive DID from new validator's real public key");

        let payload =
            validator_change_payload_with_key(&new_validator_did, new_validator_public_key);

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            &payload,
            &proposer_did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();
        store
            .lock()
            .unwrap()
            .save_governance_payload(&node.hash, &payload)
            .unwrap();

        // Cross quorum (3 of 4) exactly as the sibling VCG-005 test does.
        {
            let mut s = state.lock().unwrap();
            let resolver = s.validator_public_keys.clone();
            let proposal = Proposal {
                proposer: proposer_did.clone(),
                round: s.consensus.current_round,
                node_hash: node.hash,
            };
            let proposal_sig = sign_proposal_for_index(&proposal, 0);
            consensus::propose_verified(
                &mut s.consensus,
                &node,
                &proposer_did,
                &proposal_sig,
                &resolver,
            )
            .expect("proposal verifies");
            for (index, voter) in validator_vec.iter().enumerate().take(3) {
                let vote = vote_for(voter, index, s.consensus.current_round, node.hash);
                consensus::vote_verified(&mut s.consensus, vote, &resolver)
                    .expect("validator votes verify");
            }
        }

        check_and_commit(&state, &store, &net_handle, &reactor_tx, &node.hash).await;
        let _event = reactor_rx
            .try_recv()
            .expect("commit event emitted after quorum");

        // The REAL public key — not a placeholder — must be registered
        // against the new validator's DID.
        let registered_key = {
            let s = state.lock().unwrap();
            assert!(
                s.consensus.config.validators.contains(&new_validator_did),
                "committed AddValidator must mutate live consensus config.validators"
            );
            *s.validator_public_keys
                .as_map()
                .get(&new_validator_did)
                .expect("committed AddValidator must register a public key for the new validator")
        };
        assert_eq!(
            registered_key, new_validator_public_key,
            "registered key must be the validator's REAL supplied public key, not a placeholder"
        );

        // The newly-added validator now signs a vote of its own — this is
        // the crux of VCG-015: the key registered for its DID must be able
        // to verify a signature it genuinely produced.
        let new_round = {
            let s = state.lock().unwrap();
            s.consensus.current_round
        };
        let mut vote = Vote {
            voter: new_validator_did.clone(),
            round: new_round,
            node_hash: node.hash,
            signature: Signature::empty(),
        };
        let vote_payload = vote.signing_payload().expect("vote signing payload");
        vote.signature = new_validator_keypair.sign(&vote_payload);

        assert!(
            crypto::verify(&vote_payload, &vote.signature, &registered_key),
            "crypto::verify must ACCEPT a genuine vote signed by the newly-added validator \
             against the key registered in s.validator_public_keys — a placeholder key can \
             never satisfy this because no secret key corresponds to it"
        );

        {
            let s = state.lock().unwrap();
            let resolver = &s.validator_public_keys;
            consensus::vote_verified(&mut s.consensus.clone(), vote, resolver)
                .expect("consensus::vote_verified must accept the new validator's genuine vote");
        }
    }

    #[tokio::test]
    async fn add_validator_with_key_not_matching_claimed_did_is_rejected_fail_closed() {
        let validators = make_validators(4);
        let validator_vec: Vec<Did> = validators.iter().cloned().collect();
        let proposer_did = validator_vec[0].clone();
        let config = config_for(proposer_did.clone(), true, validators.clone());
        let sign_fn = make_sign_fn();
        let state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        drop(cmd_rx);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);

        // Claimed DID belongs to nobody in particular ("did:exo:v4", the
        // shared fixture DID), but the supplied key is a real, unrelated
        // keypair — i.e. `did != did_from_public_key(public_key)`. A
        // fail-closed implementation must reject this outright: no
        // validator added, no placeholder substituted.
        let claimed_did = Did::new("did:exo:v4").unwrap();
        let mismatched_keypair =
            KeyPair::from_secret_bytes([201u8; 32]).expect("deterministic mismatched keypair");
        let mismatched_public_key = *mismatched_keypair.public_key();
        assert_ne!(
            crate::identity::did_from_public_key(&mismatched_public_key)
                .expect("derive DID from mismatched key"),
            claimed_did,
            "test fixture invariant: the supplied key must NOT hash to the claimed DID"
        );

        let payload = validator_change_payload_with_key(&claimed_did, mismatched_public_key);

        // Fail-closed validation must happen in
        // `validate_governance_proposal_payload` itself.
        assert!(
            validate_governance_proposal_payload(&payload).is_err(),
            "an AddValidator whose public key does not hash to its claimed DID must be \
             rejected by validate_governance_proposal_payload, never accepted or placeholdered"
        );

        // End-to-end: even if such a payload reached the commit path, no
        // validator may be added and no key may be registered.
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let node = append(
            &mut dag,
            &[],
            &payload,
            &proposer_did,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        store.lock().unwrap().put_sync(node.clone()).unwrap();
        store
            .lock()
            .unwrap()
            .save_governance_payload(&node.hash, &payload)
            .unwrap();

        {
            let mut s = state.lock().unwrap();
            let resolver = s.validator_public_keys.clone();
            let proposal = Proposal {
                proposer: proposer_did.clone(),
                round: s.consensus.current_round,
                node_hash: node.hash,
            };
            let proposal_sig = sign_proposal_for_index(&proposal, 0);
            consensus::propose_verified(
                &mut s.consensus,
                &node,
                &proposer_did,
                &proposal_sig,
                &resolver,
            )
            .expect("proposal verifies");
            for (index, voter) in validator_vec.iter().enumerate().take(3) {
                let vote = vote_for(voter, index, s.consensus.current_round, node.hash);
                consensus::vote_verified(&mut s.consensus, vote, &resolver)
                    .expect("validator votes verify");
            }
        }

        check_and_commit(&state, &store, &net_handle, &reactor_tx, &node.hash).await;
        let _event = reactor_rx
            .try_recv()
            .expect("commit event still emitted — the DAG node itself commits under quorum");

        {
            let s = state.lock().unwrap();
            assert!(
                !s.consensus.config.validators.contains(&claimed_did),
                "a mismatched-key AddValidator must NEVER add the claimed DID to the validator set"
            );
            assert!(
                !s.validator_public_keys.as_map().contains_key(&claimed_did),
                "a mismatched-key AddValidator must NEVER register any key (placeholder or \
                 otherwise) for the claimed DID"
            );
        }
        {
            let st = store.lock().unwrap();
            let persisted = st
                .load_validator_set()
                .expect("load_validator_set succeeds");
            assert!(
                !persisted.contains(&claimed_did),
                "a mismatched-key AddValidator must never be persisted via save_validator_set"
            );
        }
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
        make_node_for_payload(&validator_change_payload_for_test())
    }

    fn make_node_for_payload(payload: &[u8]) -> exo_dag::dag::DagNode {
        use exo_dag::dag::{Dag, append};
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let did = Did::new("did:exo:v0").unwrap();
        let sf = make_sign_fn();
        append(&mut dag, &[], payload, &did, &*sf, &mut clock).unwrap()
    }

    fn make_signed_external_node_for_payload(
        parents: Vec<Hash256>,
        payload: &[u8],
        timestamp: Timestamp,
    ) -> exo_dag::dag::DagNode {
        let creator = Did::new("did:exo:v0").unwrap();
        let payload_hash = Hash256::digest(payload);
        let hash =
            exo_dag::dag::compute_node_hash(&parents, &payload_hash, &creator, &timestamp).unwrap();
        let signature = make_sign_fn()(hash.as_bytes());
        exo_dag::dag::DagNode {
            hash,
            parents,
            payload_hash,
            creator_did: creator,
            timestamp,
            signature,
        }
    }

    #[tokio::test]
    async fn handle_proposal_rejects_missing_parent_before_store_or_vote() {
        let validators = make_single_validator();
        let proposer = Did::new("did:exo:v0").unwrap();
        let config = config_for(
            Did::new("did:exo:observer").unwrap(),
            false,
            validators.clone(),
        );
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let payload = validator_change_payload_for_test();
        let missing_parent = Hash256::digest(b"missing parent");
        let node = make_signed_external_node_for_payload(
            vec![missing_parent],
            &payload,
            Timestamp::new(10, 0),
        );
        let msg = proposal_msg_for_payload(proposer, 0, 0, node.clone(), payload);

        handle_proposal(&state, &store, &net_handle, &reactor_tx, msg).await;

        assert!(
            !store.lock().unwrap().contains_sync(&node.hash).unwrap(),
            "network proposals must not store nodes whose parents are absent"
        );
        assert!(
            cmd_rx.try_recv().is_err(),
            "network proposals rejected at the DAG append boundary must not emit votes"
        );
        assert!(
            reactor_rx.try_recv().is_err(),
            "network proposals rejected at the DAG append boundary must not emit commit events"
        );
    }

    #[tokio::test]
    async fn handle_proposal_rejects_parent_causality_violation_before_store_or_vote() {
        let validators = make_single_validator();
        let proposer = Did::new("did:exo:v0").unwrap();
        let config = config_for(
            Did::new("did:exo:observer").unwrap(),
            false,
            validators.clone(),
        );
        let state = create_reactor_state(&config, make_sign_fn(), None);
        let (_dir, store) = temp_store();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let net_handle = NetworkHandle::new(cmd_tx);
        let (reactor_tx, mut reactor_rx) = mpsc::channel(8);
        let parent_payload = validator_remove_payload_for_test();
        let parent = make_node_for_payload(&parent_payload);
        store.lock().unwrap().put_sync(parent.clone()).unwrap();
        let payload = validator_change_payload_for_test();
        let node =
            make_signed_external_node_for_payload(vec![parent.hash], &payload, parent.timestamp);
        let msg = proposal_msg_for_payload(proposer, 0, 0, node.clone(), payload);

        handle_proposal(&state, &store, &net_handle, &reactor_tx, msg).await;

        assert!(
            !store.lock().unwrap().contains_sync(&node.hash).unwrap(),
            "network proposals must not store nodes whose timestamp does not exceed every parent"
        );
        assert!(
            cmd_rx.try_recv().is_err(),
            "network proposals rejected at the DAG append boundary must not emit votes"
        );
        assert!(
            reactor_rx.try_recv().is_err(),
            "network proposals rejected at the DAG append boundary must not emit commit events"
        );
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
            payload: validator_change_payload_for_test(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let err = validate_proposal(&msg, &validators, &resolver).unwrap_err();
        // Signature::Ed25519([0u8; 64]) hits is_empty() first (ex_core types.rs:325)
        // so the "empty" message fires before the explicit null-sig check.
        // Either message proves rejection — both are defense in depth.
        assert!(signature_is_invalid_error(&err));
    }

    #[test]
    fn validate_proposal_rejects_forged_nonzero_signature() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
        let payload = validator_change_payload_for_test();
        let node = make_node_for_payload(&payload);
        let proposal = exo_dag::consensus::Proposal {
            proposer,
            round: 0,
            node_hash: node.hash,
        };
        let signing_payload = proposal.signing_payload().unwrap();
        let msg = ConsensusProposalMsg {
            proposal,
            node,
            payload,
            signature: sign_with_wrong_key(&signing_payload),
        };

        let err = validate_proposal(&msg, &validators, &resolver).unwrap_err();
        assert!(
            err.contains("signature"),
            "network proposals must reject arbitrary nonzero signatures, got: {err}"
        );
    }

    #[test]
    fn validate_proposal_accepts_signed_message() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
        let payload = validator_change_payload_for_test();
        let node = make_node_for_payload(&payload);
        let msg = proposal_msg_for_payload(proposer, 0, 0, node, payload);

        validate_proposal(&msg, &validators, &resolver).unwrap();
    }

    #[test]
    fn validate_proposal_rejects_untyped_governance_payload() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
        let payload = b"not a typed governance proposal".to_vec();
        let node = make_node_for_payload(&payload);
        let msg = proposal_msg_for_payload(proposer, 0, 0, node, payload);

        let err = validate_proposal(&msg, &validators, &resolver).unwrap_err();

        assert!(
            err.contains("proposal payload"),
            "network proposals must reject opaque governance payloads before voting, got: {err}"
        );
    }

    #[test]
    fn validate_proposal_rejects_payload_hash_mismatch() {
        let validators = make_validators(1);
        let proposer = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&proposer, key_for_validator_index(0));
        let node_payload = validator_change_payload_for_test();
        let node = make_node_for_payload(&node_payload);
        let msg_payload = validator_remove_payload_for_test();
        let msg = proposal_msg_for_payload(proposer, 0, 0, node, msg_payload);

        let err = validate_proposal(&msg, &validators, &resolver).unwrap_err();

        assert!(
            err.contains("proposal payload hash"),
            "network proposals must bind supplied payload bytes to the DAG node hash, got: {err}"
        );
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
    fn handle_proposal_validates_external_append_before_store() {
        let source = include_str!("reactor.rs");
        let handler = source_between(
            source,
            "async fn handle_proposal",
            "/// Handle a consensus vote from the network.",
        );
        let append_validation = handler
            .find("validate_external_proposal_append")
            .expect("network proposal handler must validate external DAG append rules");
        let store_write = handler
            .find(".put_sync(node)")
            .expect("network proposal handler must persist the proposed node");

        assert!(
            append_validation < store_write,
            "network proposals must validate parent existence and HLC causality before storage"
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
    fn validate_commit_rejects_forged_nonzero_vote_in_cert() {
        let validators = make_validators(1);
        let voter = Did::new("did:exo:v0").unwrap();
        let resolver = validator_keys_for_single(&voter, key_for_validator_index(0));
        let hash = exo_core::types::Hash256([7u8; 32]);
        let mut vote = exo_dag::consensus::Vote {
            voter,
            round: 0,
            node_hash: hash,
            signature: Signature::empty(),
        };
        let signing_payload = vote.signing_payload().unwrap();
        vote.signature = sign_with_wrong_key(&signing_payload);
        let cert = exo_dag::consensus::CommitCertificate {
            node_hash: hash,
            votes: vec![vote],
            round: 0,
        };
        let msg = ConsensusCommitMsg { certificate: cert };

        let err = validate_commit(&msg, &validators, &resolver).unwrap_err();
        assert!(
            err.contains("invalid signature"),
            "network commit certificates must reject arbitrary nonzero vote signatures, got: {err}"
        );
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
