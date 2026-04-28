//! DAG-BFT consensus -- Byzantine fault tolerant commitment over the DAG.
//!
//! Tolerates f < n/3 Byzantine validators. Nodes are finalized when a
//! commit certificate gathers >2/3 validator votes.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{
    crypto,
    types::{Did, Hash256, PublicKey, Signature},
};
use serde::{Deserialize, Serialize};

use crate::{
    dag::DagNode,
    error::{DagError, Result},
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the BFT consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Set of validator DIDs.
    pub validators: BTreeSet<Did>,
    /// Maximum number of tolerable faults (default: n/3).
    pub fault_tolerance: usize,
    /// Timeout for a round in milliseconds.
    pub round_timeout_ms: u64,
}

impl ConsensusConfig {
    /// Create a new consensus config.
    ///
    /// `fault_tolerance` is automatically clamped to `(validators.len() - 1) / 3`.
    #[must_use]
    pub fn new(validators: BTreeSet<Did>, round_timeout_ms: u64) -> Self {
        let n = validators.len();
        let fault_tolerance = if n == 0 { 0 } else { (n - 1) / 3 };
        Self {
            validators,
            fault_tolerance,
            round_timeout_ms,
        }
    }

    /// The quorum size required for a commit: > 2/3 of validators.
    #[must_use]
    pub fn quorum_size(&self) -> usize {
        let n = self.validators.len();
        if n == 0 {
            return 0;
        }
        (2 * n / 3) + 1
    }
}

// ---------------------------------------------------------------------------
// Vote & Proposal
// ---------------------------------------------------------------------------

/// A vote for a node in a consensus round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// The voting validator's DID.
    pub voter: Did,
    /// The consensus round number.
    pub round: u64,
    /// The hash of the node being voted on.
    pub node_hash: Hash256,
    /// Signature over (round || node_hash) by the voter.
    pub signature: Signature,
}

/// A proposal to commit a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// The proposer's DID.
    pub proposer: Did,
    /// The round of this proposal.
    pub round: u64,
    /// The proposed node.
    pub node_hash: Hash256,
}

/// A commit certificate proving >2/3 validators agreed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitCertificate {
    /// The committed node hash.
    pub node_hash: Hash256,
    /// The votes that formed the certificate.
    pub votes: Vec<Vote>,
    /// The round in which commitment was achieved.
    pub round: u64,
}

// ---------------------------------------------------------------------------
// Canonical signing payloads + signature verification (GAP-014)
// ---------------------------------------------------------------------------

impl Vote {
    /// Canonical CBOR payload that the voter signs.
    ///
    /// Domain tag prevents cross-context reuse. The tuple
    /// `(tag, voter, round, node_hash)` binds the signature to
    /// exactly one voter, round, and node.
    ///
    /// # Errors
    /// Returns `DagError::StoreError` on CBOR encoding failure.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let tuple = (
            "exo.dag.consensus.vote.v1",
            &self.voter,
            self.round,
            &self.node_hash,
        );
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
            DagError::StoreError(format!("vote signing payload encoding failed: {e}"))
        })?;
        Ok(buf)
    }

    /// Verify the voter's signature over the canonical payload.
    ///
    /// Rejects empty signatures AND all-zero sentinels AND signatures
    /// that do not verify under `voter_public_key`.
    #[must_use]
    pub fn verify_signature(&self, voter_public_key: &PublicKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        if self.signature.ed25519_component_is_zero() {
            return false;
        }
        let Ok(payload) = self.signing_payload() else {
            return false;
        };
        crypto::verify(&payload, &self.signature, voter_public_key)
    }
}

impl Proposal {
    /// Canonical CBOR payload that the proposer signs.
    ///
    /// # Errors
    /// Returns `DagError::StoreError` on CBOR encoding failure.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let tuple = (
            "exo.dag.consensus.proposal.v1",
            &self.proposer,
            self.round,
            &self.node_hash,
        );
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
            DagError::StoreError(format!("proposal signing payload encoding failed: {e}"))
        })?;
        Ok(buf)
    }

    /// Verify the proposer's signature (supplied separately — `Proposal`
    /// itself has no signature field; the wire envelope carries it).
    #[must_use]
    pub fn verify_signature(&self, proposer_public_key: &PublicKey, signature: &Signature) -> bool {
        if signature.is_empty() {
            return false;
        }
        if signature.ed25519_component_is_zero() {
            return false;
        }
        let Ok(payload) = self.signing_payload() else {
            return false;
        };
        crypto::verify(&payload, signature, proposer_public_key)
    }
}

/// Resolve a validator DID to its current public key.
///
/// Production implementations should back this with the identity
/// registry (`exo-identity`) and must refuse resolution for revoked
/// or rotated keys.
pub trait PublicKeyResolver {
    fn resolve(&self, did: &Did) -> Option<PublicKey>;
}

impl<F> PublicKeyResolver for F
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    fn resolve(&self, did: &Did) -> Option<PublicKey> {
        (self)(did)
    }
}

// ---------------------------------------------------------------------------
// Consensus State
// ---------------------------------------------------------------------------

/// Mutable state for the consensus protocol.
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// The consensus configuration.
    pub config: ConsensusConfig,
    /// Current round number.
    pub current_round: u64,
    /// Committed node hashes in order.
    pub committed: Vec<Hash256>,
    /// Pending votes: round -> node_hash -> set of votes.
    pub pending: BTreeMap<u64, BTreeMap<Hash256, Vec<Vote>>>,
    /// Committed certificates.
    pub certificates: BTreeMap<Hash256, CommitCertificate>,
    /// Track which validators have voted in each round to prevent double-voting.
    pub voted_in_round: BTreeMap<u64, BTreeSet<Did>>,
}

impl ConsensusState {
    /// Create a new consensus state.
    #[must_use]
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            config,
            current_round: 0,
            committed: Vec::new(),
            pending: BTreeMap::new(),
            certificates: BTreeMap::new(),
            voted_in_round: BTreeMap::new(),
        }
    }

    /// Advance to the next round.
    pub fn advance_round(&mut self) {
        self.current_round += 1;
    }
}

/// Propose a node for commitment.
///
/// **⚠️ DEPRECATED (GAP-014):** This function does not verify the
/// proposer's signature. Use [`propose_verified`] instead, which
/// requires a [`PublicKeyResolver`] and refuses forged signatures.
///
/// Retained only to avoid breaking the legacy test suite; production
/// callers MUST migrate. Will be removed in a future release.
#[deprecated(
    note = "GAP-014: use propose_verified; this variant does not verify the proposer signature"
)]
pub fn propose(state: &mut ConsensusState, node: &DagNode, proposer: &Did) -> Result<Proposal> {
    if !state.config.validators.contains(proposer) {
        return Err(DagError::NotAValidator(proposer.to_string()));
    }

    let proposal = Proposal {
        proposer: proposer.clone(),
        round: state.current_round,
        node_hash: node.hash,
    };

    state
        .pending
        .entry(state.current_round)
        .or_default()
        .entry(node.hash)
        .or_default();

    Ok(proposal)
}

/// Cast a vote for a node in the current round.
///
/// **⚠️ DEPRECATED (GAP-014):** This function does not verify the
/// voter's signature. Use [`vote_verified`] instead.
#[deprecated(note = "GAP-014: use vote_verified; this variant does not verify the voter signature")]
pub fn vote(state: &mut ConsensusState, v: Vote) -> Result<()> {
    if !state.config.validators.contains(&v.voter) {
        return Err(DagError::NotAValidator(v.voter.to_string()));
    }

    if v.round != state.current_round {
        return Err(DagError::InvalidRound {
            expected: state.current_round,
            got: v.round,
        });
    }

    let round_voters = state.voted_in_round.entry(v.round).or_default();
    if round_voters.contains(&v.voter) {
        return Err(DagError::DuplicateVote {
            voter: v.voter.to_string(),
            round: v.round,
        });
    }

    round_voters.insert(v.voter.clone());

    state
        .pending
        .entry(v.round)
        .or_default()
        .entry(v.node_hash)
        .or_default()
        .push(v);

    Ok(())
}

/// Check if a node has enough votes to be committed.
#[must_use]
pub fn check_commit(state: &ConsensusState, node_hash: &Hash256) -> Option<CommitCertificate> {
    let quorum = state.config.quorum_size();
    if quorum == 0 {
        return None;
    }

    if let Some(round_votes) = state.pending.get(&state.current_round) {
        if let Some(votes) = round_votes.get(node_hash) {
            if votes.len() >= quorum {
                return Some(CommitCertificate {
                    node_hash: *node_hash,
                    votes: votes.clone(),
                    round: state.current_round,
                });
            }
        }
    }

    None
}

/// Commit a node with a certificate.
///
/// **⚠️ DEPRECATED (GAP-014):** This function does not verify any
/// vote signatures in the certificate. Use [`commit_verified`] instead.
#[deprecated(
    note = "GAP-014: use commit_verified; this variant does not verify certificate signatures"
)]
pub fn commit(state: &mut ConsensusState, cert: CommitCertificate) {
    let hash = cert.node_hash;
    state.committed.push(hash);
    state.certificates.insert(hash, cert);
}

// ---------------------------------------------------------------------------
// Verified consensus API (GAP-014) — signature-checking variants
// ---------------------------------------------------------------------------

/// Register a proposal after verifying the proposer's signature.
///
/// Closes GAP-014 for the proposal path. In addition to the membership
/// check `propose` performs, this verifies that `signature` is a valid
/// signature by `proposer` over `Proposal::signing_payload()`. Rejects
/// empty, all-zero, or unverifiable signatures.
///
/// The caller supplies the proposer's public key via `resolver`. A
/// resolver returning `None` for the proposer is treated as "unknown
/// key" and the proposal is rejected.
///
/// # Errors
/// - `NotAValidator` if `proposer` is not in the validator set.
/// - `InvalidSignature` if the signature is empty / zero / wrong key /
///   over the wrong payload.
pub fn propose_verified<R: PublicKeyResolver>(
    state: &mut ConsensusState,
    node: &DagNode,
    proposer: &Did,
    signature: &Signature,
    resolver: &R,
) -> Result<Proposal> {
    if !state.config.validators.contains(proposer) {
        return Err(DagError::NotAValidator(proposer.to_string()));
    }

    let proposal = Proposal {
        proposer: proposer.clone(),
        round: state.current_round,
        node_hash: node.hash,
    };

    let Some(key) = resolver.resolve(proposer) else {
        return Err(DagError::InvalidSignature(node.hash));
    };
    if !proposal.verify_signature(&key, signature) {
        return Err(DagError::InvalidSignature(node.hash));
    }

    state
        .pending
        .entry(state.current_round)
        .or_default()
        .entry(node.hash)
        .or_default();

    Ok(proposal)
}

/// Cast a vote after verifying the voter's signature.
///
/// Closes GAP-014 for the vote path.
///
/// # Errors
/// - `NotAValidator` if `v.voter` is not in the validator set.
/// - `InvalidRound` if `v.round` does not match the current round.
/// - `DuplicateVote` if this voter has already voted this round.
/// - `InvalidSignature` if the signature does not verify against
///   the public key returned by `resolver` for `v.voter`, or the
///   resolver returns `None`.
pub fn vote_verified<R: PublicKeyResolver>(
    state: &mut ConsensusState,
    v: Vote,
    resolver: &R,
) -> Result<()> {
    if !state.config.validators.contains(&v.voter) {
        return Err(DagError::NotAValidator(v.voter.to_string()));
    }

    if v.round != state.current_round {
        return Err(DagError::InvalidRound {
            expected: state.current_round,
            got: v.round,
        });
    }

    let Some(key) = resolver.resolve(&v.voter) else {
        return Err(DagError::InvalidSignature(v.node_hash));
    };
    if !v.verify_signature(&key) {
        return Err(DagError::InvalidSignature(v.node_hash));
    }

    let round_voters = state.voted_in_round.entry(v.round).or_default();
    if round_voters.contains(&v.voter) {
        return Err(DagError::DuplicateVote {
            voter: v.voter.to_string(),
            round: v.round,
        });
    }

    round_voters.insert(v.voter.clone());

    state
        .pending
        .entry(v.round)
        .or_default()
        .entry(v.node_hash)
        .or_default()
        .push(v);

    Ok(())
}

/// Commit a node with a certificate after verifying every vote's signature.
///
/// Closes GAP-014 for the commit path. Every vote in the certificate
/// must:
///   - reference `cert.node_hash`
///   - come from a validator in the current set
///   - carry a signature that verifies against the voter's current key
///
/// # Errors
/// - `InvalidSignature(cert.node_hash)` if any vote fails verification
///   or references a different node.
/// - `NotAValidator` if any voter is not in the validator set.
pub fn commit_verified<R: PublicKeyResolver>(
    state: &mut ConsensusState,
    cert: CommitCertificate,
    resolver: &R,
) -> Result<()> {
    for v in &cert.votes {
        if v.node_hash != cert.node_hash {
            return Err(DagError::InvalidSignature(cert.node_hash));
        }
        if !state.config.validators.contains(&v.voter) {
            return Err(DagError::NotAValidator(v.voter.to_string()));
        }
        let Some(key) = resolver.resolve(&v.voter) else {
            return Err(DagError::InvalidSignature(cert.node_hash));
        };
        if !v.verify_signature(&key) {
            return Err(DagError::InvalidSignature(cert.node_hash));
        }
    }
    let hash = cert.node_hash;
    state.committed.push(hash);
    state.certificates.insert(hash, cert);
    Ok(())
}

/// Check if a node has been finalized (committed with a certificate).
#[must_use]
pub fn is_finalized(state: &ConsensusState, hash: &Hash256) -> bool {
    state.certificates.contains_key(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// Tests exercise both the legacy (deprecated-by-GAP-014) API and
// the `_verified` counterparts. The deprecated path stays tested to
// confirm (a) regression safety for existing callers and (b) the
// reactor defense-in-depth that rejects zero-byte signature
// sentinels. Silencing the deprecation lint only for this test
// module; library+binary code still fails CI on any new use.
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::dag::{Dag, DeterministicDagClock, append};

    type SignFn = Box<dyn Fn(&[u8]) -> Signature>;

    fn make_validators(n: usize) -> BTreeSet<Did> {
        (0..n)
            .map(|i| Did::new(&format!("did:exo:v{i}")).expect("valid"))
            .collect()
    }

    fn make_sign_fn() -> SignFn {
        Box::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn make_vote(voter: &Did, round: u64, node_hash: &Hash256) -> Vote {
        Vote {
            voter: voter.clone(),
            round,
            node_hash: *node_hash,
            signature: Signature::from_bytes([1u8; 64]),
        }
    }

    fn setup_dag_with_node() -> (Dag, DagNode) {
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:proposer").expect("valid");
        let sign_fn = make_sign_fn();
        let node = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        (dag, node)
    }

    #[test]
    fn config_quorum_sizes() {
        let c1 = ConsensusConfig::new(make_validators(1), 1000);
        assert_eq!(c1.quorum_size(), 1);
        assert_eq!(c1.fault_tolerance, 0);

        let c3 = ConsensusConfig::new(make_validators(3), 1000);
        assert_eq!(c3.quorum_size(), 3);
        assert_eq!(c3.fault_tolerance, 0);

        let c4 = ConsensusConfig::new(make_validators(4), 1000);
        assert_eq!(c4.quorum_size(), 3);
        assert_eq!(c4.fault_tolerance, 1);

        let c7 = ConsensusConfig::new(make_validators(7), 1000);
        assert_eq!(c7.quorum_size(), 5);
        assert_eq!(c7.fault_tolerance, 2);

        let c0 = ConsensusConfig::new(BTreeSet::new(), 1000);
        assert_eq!(c0.quorum_size(), 0);
        assert_eq!(c0.fault_tolerance, 0);
    }

    #[test]
    fn happy_path_propose_vote_commit() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();

        let proposal = propose(&mut state, &node, &v[0]).unwrap();
        assert_eq!(proposal.round, 0);
        assert_eq!(proposal.node_hash, node.hash);

        for voter in &v[0..3] {
            let vt = make_vote(voter, 0, &node.hash);
            vote(&mut state, vt).unwrap();
        }

        let cert = check_commit(&state, &node.hash);
        assert!(cert.is_some());
        let cert = cert.unwrap();
        assert_eq!(cert.votes.len(), 3);
        assert_eq!(cert.round, 0);

        commit(&mut state, cert);
        assert!(is_finalized(&state, &node.hash));
        assert_eq!(state.committed.len(), 1);
    }

    #[test]
    fn insufficient_votes_no_commit() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();
        let _proposal = propose(&mut state, &node, &v[0]).unwrap();

        for voter in &v[0..2] {
            let vt = make_vote(voter, 0, &node.hash);
            vote(&mut state, vt).unwrap();
        }

        assert!(check_commit(&state, &node.hash).is_none());
        assert!(!is_finalized(&state, &node.hash));
    }

    #[test]
    fn byzantine_minority_cannot_commit() {
        let validators = make_validators(7);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();
        let _proposal = propose(&mut state, &node, &v[0]).unwrap();

        // 2 byzantine
        for voter in &v[0..2] {
            let vt = make_vote(voter, 0, &node.hash);
            vote(&mut state, vt).unwrap();
        }
        assert!(check_commit(&state, &node.hash).is_none());

        // 2 more honest (total 4, need 5)
        for voter in &v[2..4] {
            let vt = make_vote(voter, 0, &node.hash);
            vote(&mut state, vt).unwrap();
        }
        assert!(check_commit(&state, &node.hash).is_none());

        // One more reaches quorum
        let vt = make_vote(&v[4], 0, &node.hash);
        vote(&mut state, vt).unwrap();
        assert!(check_commit(&state, &node.hash).is_some());
    }

    #[test]
    fn duplicate_vote_rejected() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();
        let _proposal = propose(&mut state, &node, &v[0]).unwrap();

        let vt = make_vote(&v[0], 0, &node.hash);
        vote(&mut state, vt).unwrap();

        let vt2 = make_vote(&v[0], 0, &node.hash);
        let err = vote(&mut state, vt2).unwrap_err();
        assert!(matches!(err, DagError::DuplicateVote { .. }));
    }

    #[test]
    fn non_validator_rejected() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators, 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let outsider = Did::new("did:exo:outsider").expect("valid");

        let err = propose(&mut state, &node, &outsider).unwrap_err();
        assert!(matches!(err, DagError::NotAValidator(_)));

        let vt = make_vote(&outsider, 0, &node.hash);
        let err = vote(&mut state, vt).unwrap_err();
        assert!(matches!(err, DagError::NotAValidator(_)));
    }

    #[test]
    fn wrong_round_rejected() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();

        let vt = make_vote(&v[0], 999, &node.hash);
        let err = vote(&mut state, vt).unwrap_err();
        assert!(matches!(err, DagError::InvalidRound { .. }));
    }

    #[test]
    fn round_advancement() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators, 1000);
        let mut state = ConsensusState::new(config);
        assert_eq!(state.current_round, 0);

        state.advance_round();
        assert_eq!(state.current_round, 1);

        state.advance_round();
        assert_eq!(state.current_round, 2);
    }

    #[test]
    fn vote_in_advanced_round() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();

        state.advance_round();
        let _proposal = propose(&mut state, &node, &v[0]).unwrap();

        let vt = make_vote(&v[0], 1, &node.hash);
        vote(&mut state, vt).unwrap();

        let vt2 = make_vote(&v[1], 0, &node.hash);
        let err = vote(&mut state, vt2).unwrap_err();
        assert!(matches!(err, DagError::InvalidRound { .. }));
    }

    #[test]
    fn not_finalized_without_commit() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators, 1000);
        let state = ConsensusState::new(config);

        assert!(!is_finalized(&state, &Hash256::ZERO));
    }

    #[test]
    fn check_commit_no_pending() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators, 1000);
        let state = ConsensusState::new(config);

        assert!(check_commit(&state, &Hash256::ZERO).is_none());
    }

    // -----------------------------------------------------------------------
    // BFT integration tests: conflicting proposals
    // -----------------------------------------------------------------------

    /// 4-validator quorum (quorum = 3). Two competing proposals in the same
    /// round. Three validators vote for node A; one votes for node B.
    /// Only node A reaches quorum and is committed; node B is not finalized.
    #[test]
    fn conflicting_proposals_quorum_winner_commits() {
        let validators = make_validators(4); // quorum = 3
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:proposer").expect("valid");
        let sign_fn = make_sign_fn();

        let node_a = append(&mut dag, &[], b"event-A", &creator, &*sign_fn, &mut clock).unwrap();
        let node_b = append(
            &mut dag,
            &[node_a.hash],
            b"event-B",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let v: Vec<Did> = validators.iter().cloned().collect();

        // Both proposals are admitted to the pending set
        propose(&mut state, &node_a, &v[0]).unwrap();
        propose(&mut state, &node_b, &v[1]).unwrap();

        // Three validators vote for A → quorum
        for voter in &v[0..3] {
            vote(&mut state, make_vote(voter, 0, &node_a.hash)).unwrap();
        }

        // One validator votes for B → insufficient
        vote(&mut state, make_vote(&v[3], 0, &node_b.hash)).unwrap();

        assert!(
            check_commit(&state, &node_a.hash).is_some(),
            "A must reach quorum"
        );
        assert!(
            check_commit(&state, &node_b.hash).is_none(),
            "B must not reach quorum"
        );

        let cert = check_commit(&state, &node_a.hash).unwrap();
        commit(&mut state, cert);

        assert!(is_finalized(&state, &node_a.hash));
        assert!(!is_finalized(&state, &node_b.hash));
        assert_eq!(state.committed.len(), 1);
    }

    /// 7-validator quorum (quorum = 5). Split 3-vs-3 across two conflicting
    /// proposals. Neither reaches quorum; the round ends with no commit.
    #[test]
    fn split_vote_neither_proposal_commits() {
        let validators = make_validators(7); // quorum = 5
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:proposer").expect("valid");
        let sign_fn = make_sign_fn();

        let node_x = append(&mut dag, &[], b"event-X", &creator, &*sign_fn, &mut clock).unwrap();
        let node_y = append(
            &mut dag,
            &[node_x.hash],
            b"event-Y",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let v: Vec<Did> = validators.iter().cloned().collect();

        propose(&mut state, &node_x, &v[0]).unwrap();
        propose(&mut state, &node_y, &v[1]).unwrap();

        // v[0..3] vote for X (3 votes)
        for voter in &v[0..3] {
            vote(&mut state, make_vote(voter, 0, &node_x.hash)).unwrap();
        }
        // v[3..6] vote for Y (3 votes) — v[6] abstains
        for voter in &v[3..6] {
            vote(&mut state, make_vote(voter, 0, &node_y.hash)).unwrap();
        }

        // Neither X nor Y has the required 5 votes
        assert!(
            check_commit(&state, &node_x.hash).is_none(),
            "X must not reach quorum with 3/5 votes"
        );
        assert!(
            check_commit(&state, &node_y.hash).is_none(),
            "Y must not reach quorum with 3/5 votes"
        );
        assert!(state.committed.is_empty());
    }

    /// After a split round, advancing to the next round and reaching quorum on
    /// a new proposal produces a valid commit certificate.
    #[test]
    fn commit_succeeds_in_next_round_after_split() {
        let validators = make_validators(7); // quorum = 5
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:proposer").expect("valid");
        let sign_fn = make_sign_fn();

        let node_x = append(&mut dag, &[], b"event-X", &creator, &*sign_fn, &mut clock).unwrap();
        let node_r1 = append(
            &mut dag,
            &[node_x.hash],
            b"round1",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let v: Vec<Did> = validators.iter().cloned().collect();

        // Round 0: split → no commit
        propose(&mut state, &node_x, &v[0]).unwrap();
        for voter in &v[0..3] {
            vote(&mut state, make_vote(voter, 0, &node_x.hash)).unwrap();
        }
        assert!(check_commit(&state, &node_x.hash).is_none());

        // Advance to round 1
        state.advance_round();

        // Round 1: quorum on a new proposal
        propose(&mut state, &node_r1, &v[0]).unwrap();
        for voter in v.iter().take(5) {
            vote(&mut state, make_vote(voter, 1, &node_r1.hash)).unwrap();
        }

        let cert = check_commit(&state, &node_r1.hash);
        assert!(cert.is_some(), "round 1 proposal must reach quorum");
        commit(&mut state, cert.unwrap());

        assert!(is_finalized(&state, &node_r1.hash));
        assert_eq!(state.current_round, 1);
        assert_eq!(state.committed.len(), 1);
    }

    #[test]
    fn multiple_proposals_same_round() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:proposer").expect("valid");
        let sign_fn = make_sign_fn();

        let n1 = append(&mut dag, &[], b"n1", &creator, &*sign_fn, &mut clock).unwrap();
        let n2 = append(&mut dag, &[n1.hash], b"n2", &creator, &*sign_fn, &mut clock).unwrap();

        let v: Vec<Did> = validators.iter().cloned().collect();

        let _p1 = propose(&mut state, &n1, &v[0]).unwrap();
        let _p2 = propose(&mut state, &n2, &v[0]).unwrap();

        for voter in &v[0..3] {
            let vt = make_vote(voter, 0, &n1.hash);
            vote(&mut state, vt).unwrap();
        }

        assert!(check_commit(&state, &n1.hash).is_some());
        assert!(check_commit(&state, &n2.hash).is_none());
    }

    // ===================================================================
    // GAP-014 fix regression tests — verified consensus path
    // ===================================================================

    use exo_core::crypto;

    /// Build a minimal DagNode for tests. We don't run append() here
    /// because we want the test to own the node-hash determinism and
    /// not depend on signing details.
    fn make_node(seed: &str) -> (DagNode, (), ()) {
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let did = Did::new("did:exo:proposer").unwrap();
        let sf = make_sign_fn();
        let node = append(&mut dag, &[], seed.as_bytes(), &did, &*sf, &mut clock)
            .expect("append test node");
        (node, (), ())
    }

    /// Build a signed vote over its canonical payload.
    fn signed_vote(
        voter: &Did,
        round: u64,
        node_hash: Hash256,
        sk: &exo_core::types::SecretKey,
    ) -> Vote {
        let mut v = Vote {
            voter: voter.clone(),
            round,
            node_hash,
            signature: Signature::empty(),
        };
        let payload = v.signing_payload().expect("payload");
        v.signature = crypto::sign(&payload, sk);
        v
    }

    #[test]
    fn verified_vote_accepts_properly_signed() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let vote = signed_vote(&a, 0, n.hash, &sk_a);
        let resolver = |d: &Did| -> Option<exo_core::types::PublicKey> {
            if *d == a { Some(pk_a) } else { None }
        };
        assert!(vote_verified(&mut state, vote, &resolver).is_ok());
    }

    #[test]
    fn verified_vote_rejects_forged_signature_with_valid_voter() {
        // The exact GAP-014 attack: voter is in the validator set, but
        // the signature is junk bytes (the shape the old `vote()` let
        // through silently).
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let forged = Vote {
            voter: a.clone(),
            round: 0,
            node_hash: n.hash,
            signature: Signature::from_bytes([1u8; 64]),
        };
        let resolver = |_d: &Did| Some(pk_a);
        let res = vote_verified(&mut state, forged, &resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
        // Crucially: state must not have accepted the forged vote.
        assert!(state.pending.get(&0).is_none_or(|m| m.is_empty()));
        assert!(state.voted_in_round.get(&0).is_none_or(|s| s.is_empty()));
    }

    #[test]
    fn verified_vote_rejects_zero_byte_signature() {
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let zeros = Vote {
            voter: a.clone(),
            round: 0,
            node_hash: n.hash,
            signature: Signature::from_bytes([0u8; 64]),
        };
        let resolver = |_d: &Did| Some(pk_a);
        let res = vote_verified(&mut state, zeros, &resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
    }

    #[test]
    fn verified_vote_rejects_signature_by_wrong_validator_key() {
        // Alice is the voter in the message, but the signature was
        // actually produced by Mallory's key. Resolver returns Alice's
        // pubkey. Verification must fail.
        let (pk_alice, _sk_alice) = crypto::generate_keypair();
        let (_, sk_mallory) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        // Sign with Mallory's key but claim voter = Alice.
        let mut bad = Vote {
            voter: a.clone(),
            round: 0,
            node_hash: n.hash,
            signature: Signature::empty(),
        };
        let payload = bad.signing_payload().unwrap();
        bad.signature = crypto::sign(&payload, &sk_mallory);
        let resolver = |_d: &Did| Some(pk_alice);
        let res = vote_verified(&mut state, bad, &resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
    }

    #[test]
    fn verified_vote_rejects_when_resolver_returns_none() {
        // Voter is in validator set but no public key is known.
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let (_, sk) = crypto::generate_keypair();
        let v = signed_vote(&a, 0, n.hash, &sk);
        let null_resolver = |_d: &Did| None;
        let res = vote_verified(&mut state, v, &null_resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
    }

    #[test]
    fn verified_vote_rejects_replay_from_different_round() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        state.advance_round(); // now at round 1
        let (n, _, _) = make_node("x");
        // Signed for round 0 but state is at round 1.
        let v = signed_vote(&a, 0, n.hash, &sk_a);
        let resolver = |_d: &Did| Some(pk_a);
        let res = vote_verified(&mut state, v, &resolver);
        assert!(matches!(res, Err(DagError::InvalidRound { .. })));
    }

    #[test]
    fn verified_propose_rejects_forged_signature() {
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let forged_sig = Signature::from_bytes([1u8; 64]);
        let resolver = |_d: &Did| Some(pk_a);
        let res = propose_verified(&mut state, &n, &a, &forged_sig, &resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
    }

    #[test]
    fn verified_propose_accepts_properly_signed() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let proposal_shape = Proposal {
            proposer: a.clone(),
            round: 0,
            node_hash: n.hash,
        };
        let payload = proposal_shape.signing_payload().unwrap();
        let sig = crypto::sign(&payload, &sk_a);
        let resolver = |_d: &Did| Some(pk_a);
        let res = propose_verified(&mut state, &n, &a, &sig, &resolver);
        assert!(res.is_ok());
    }

    #[test]
    fn verified_commit_rejects_forged_vote_in_cert() {
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let forged_vote = Vote {
            voter: a.clone(),
            round: 0,
            node_hash: n.hash,
            signature: Signature::from_bytes([2u8; 64]),
        };
        let cert = CommitCertificate {
            node_hash: n.hash,
            votes: vec![forged_vote],
            round: 0,
        };
        let resolver = |_d: &Did| Some(pk_a);
        let res = commit_verified(&mut state, cert, &resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
        assert!(state.committed.is_empty());
    }

    #[test]
    fn verified_commit_accepts_properly_signed_cert() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let (pk_b, sk_b) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let b = Did::new("did:exo:bob").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        vs.insert(b.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let va = signed_vote(&a, 0, n.hash, &sk_a);
        let vb = signed_vote(&b, 0, n.hash, &sk_b);
        let cert = CommitCertificate {
            node_hash: n.hash,
            votes: vec![va, vb],
            round: 0,
        };
        let resolver = move |d: &Did| -> Option<exo_core::types::PublicKey> {
            if *d == a {
                Some(pk_a)
            } else if *d == b {
                Some(pk_b)
            } else {
                None
            }
        };
        assert!(commit_verified(&mut state, cert, &resolver).is_ok());
        assert_eq!(state.committed.len(), 1);
    }

    #[test]
    fn verified_commit_rejects_cert_with_wrong_hash_vote() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n1, _, _) = make_node("x");
        let (n2, _, _) = make_node("y");
        // Vote is for n2 but cert claims n1.
        let v = signed_vote(&a, 0, n2.hash, &sk_a);
        let cert = CommitCertificate {
            node_hash: n1.hash,
            votes: vec![v],
            round: 0,
        };
        let resolver = |_d: &Did| Some(pk_a);
        let res = commit_verified(&mut state, cert, &resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
    }

    // -----------------------------------------------------------------------
    // Coverage completion tests — exercise remaining error branches.
    // -----------------------------------------------------------------------

    // Covers Vote::verify_signature rejecting a non-Ed25519 signature without
    // relying on the legacy Signature::as_bytes() zero sentinel.
    #[test]
    fn vote_verify_signature_rejects_postquantum_signature() {
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let v = Vote {
            voter: Did::new("did:exo:alice").unwrap(),
            round: 0,
            node_hash: Hash256::ZERO,
            signature: Signature::PostQuantum(vec![1u8; 64]),
        };
        assert!(!v.verify_signature(&pk_a));
    }

    // Covers Proposal::verify_signature line 170: empty-signature rejection.
    #[test]
    fn proposal_verify_signature_rejects_empty() {
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let p = Proposal {
            proposer: Did::new("did:exo:alice").unwrap(),
            round: 0,
            node_hash: Hash256::ZERO,
        };
        assert!(!p.verify_signature(&pk_a, &Signature::empty()));
    }

    // Covers Proposal::verify_signature rejecting a non-Ed25519 signature without
    // relying on the legacy Signature::as_bytes() zero sentinel.
    #[test]
    fn proposal_verify_signature_rejects_postquantum_signature() {
        let (pk_a, _sk_a) = crypto::generate_keypair();
        let p = Proposal {
            proposer: Did::new("did:exo:alice").unwrap(),
            round: 0,
            node_hash: Hash256::ZERO,
        };
        let sig = Signature::PostQuantum(vec![1u8; 64]);
        assert!(!p.verify_signature(&pk_a, &sig));
    }

    // Covers Proposal::verify_signature pass-through to crypto::verify with a
    // wrong key (neither empty nor zero sentinel path) — asserts rejection.
    #[test]
    fn proposal_verify_signature_rejects_wrong_key() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let (pk_b, _sk_b) = crypto::generate_keypair();
        let p = Proposal {
            proposer: Did::new("did:exo:alice").unwrap(),
            round: 0,
            node_hash: Hash256::ZERO,
        };
        let payload = p.signing_payload().unwrap();
        let sig = crypto::sign(&payload, &sk_a);
        // Signed by A, verified against B -> must fail.
        assert!(!p.verify_signature(&pk_b, &sig));
        // Sanity: verifies under the right key.
        assert!(p.verify_signature(&pk_a, &sig));
    }

    // Covers check_commit line 317: quorum==0 short-circuit when validator set is empty.
    #[test]
    fn check_commit_returns_none_when_validator_set_empty() {
        let config = ConsensusConfig::new(BTreeSet::new(), 1000);
        let mut state = ConsensusState::new(config);
        // Plant a "vote" for a hash so pending is non-empty; quorum==0
        // must still short-circuit to None (no commit is ever possible
        // with zero validators).
        let h = Hash256::ZERO;
        state
            .pending
            .entry(0)
            .or_default()
            .entry(h)
            .or_default()
            .push(Vote {
                voter: Did::new("did:exo:ghost").unwrap(),
                round: 0,
                node_hash: h,
                signature: Signature::from_bytes([1u8; 64]),
            });
        assert!(check_commit(&state, &h).is_none());
    }

    // Covers check_commit line 329: pending map has the round but not the node_hash.
    #[test]
    fn check_commit_returns_none_for_unknown_hash_in_existing_round() {
        let validators = make_validators(4);
        let config = ConsensusConfig::new(validators.clone(), 1000);
        let mut state = ConsensusState::new(config);
        let (_dag, node) = setup_dag_with_node();

        let v: Vec<Did> = validators.iter().cloned().collect();
        // Populate pending for round 0 under `node.hash`.
        propose(&mut state, &node, &v[0]).unwrap();

        // Query a hash that has no pending entry -> inner get() is None,
        // falls through to the end-of-function None.
        let phantom = Hash256::from_bytes([0xAAu8; 32]);
        assert!(check_commit(&state, &phantom).is_none());
        // Sanity: the real hash is also not committable (no votes yet)
        // but reaches the inner branch.
        assert!(check_commit(&state, &node.hash).is_none());
    }

    // Covers propose_verified line 375: proposer not in validator set.
    #[test]
    fn propose_verified_rejects_non_validator() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let outsider = Did::new("did:exo:outsider").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        // Sign a well-formed proposal by the outsider — membership must
        // be rejected *before* signature verification is even attempted.
        let shape = Proposal {
            proposer: outsider.clone(),
            round: 0,
            node_hash: n.hash,
        };
        let sig = crypto::sign(&shape.signing_payload().unwrap(), &sk_a);
        let resolver = |_d: &Did| Some(pk_a);
        let res = propose_verified(&mut state, &n, &outsider, &sig, &resolver);
        assert!(matches!(res, Err(DagError::NotAValidator(_))));
        // State must remain empty.
        assert!(state.pending.is_empty());
    }

    // Covers propose_verified line 385: resolver returns None for the proposer.
    #[test]
    fn propose_verified_rejects_when_resolver_returns_none() {
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let sig = Signature::from_bytes([1u8; 64]);
        let null_resolver = |_d: &Did| None;
        let res = propose_verified(&mut state, &n, &a, &sig, &null_resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
        assert!(state.pending.is_empty());
    }

    // Covers vote_verified line 418: voter not in validator set.
    #[test]
    fn vote_verified_rejects_non_validator() {
        let (pk_a, sk_out) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let outsider = Did::new("did:exo:outsider").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let v = signed_vote(&outsider, 0, n.hash, &sk_out);
        let resolver = |_d: &Did| Some(pk_a);
        let res = vote_verified(&mut state, v, &resolver);
        assert!(matches!(res, Err(DagError::NotAValidator(_))));
        assert!(state.pending.get(&0).is_none_or(|m| m.is_empty()));
    }

    // Covers vote_verified lines 437-440: duplicate vote by same voter in same round.
    #[test]
    fn vote_verified_rejects_duplicate_vote_same_round() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n1, _, _) = make_node("x");
        let (n2, _, _) = make_node("y");
        let resolver = |_d: &Did| Some(pk_a);
        // First vote succeeds.
        let v1 = signed_vote(&a, 0, n1.hash, &sk_a);
        assert!(vote_verified(&mut state, v1, &resolver).is_ok());
        // Second signed vote in the same round — even for a different
        // node — must be rejected as a duplicate.
        let v2 = signed_vote(&a, 0, n2.hash, &sk_a);
        let res = vote_verified(&mut state, v2, &resolver);
        assert!(matches!(res, Err(DagError::DuplicateVote { .. })));
        // Only the first vote is recorded.
        let voters = state.voted_in_round.get(&0).expect("round tracked");
        assert_eq!(voters.len(), 1);
    }

    // Covers commit_verified line 478: a vote in the cert is not from a validator.
    #[test]
    fn commit_verified_rejects_vote_from_non_validator() {
        let (pk_a, sk_a) = crypto::generate_keypair();
        let (_, sk_out) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let outsider = Did::new("did:exo:outsider").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let good = signed_vote(&a, 0, n.hash, &sk_a);
        let bad = signed_vote(&outsider, 0, n.hash, &sk_out);
        let cert = CommitCertificate {
            node_hash: n.hash,
            votes: vec![good, bad],
            round: 0,
        };
        let resolver = |_d: &Did| Some(pk_a);
        let res = commit_verified(&mut state, cert, &resolver);
        assert!(matches!(res, Err(DagError::NotAValidator(_))));
        // Nothing was committed.
        assert!(state.committed.is_empty());
        assert!(state.certificates.is_empty());
    }

    // Covers commit_verified line 481: resolver returns None for a voter in the cert.
    #[test]
    fn commit_verified_rejects_when_resolver_returns_none_for_voter() {
        let (_, sk_a) = crypto::generate_keypair();
        let a = Did::new("did:exo:alice").unwrap();
        let mut vs = BTreeSet::new();
        vs.insert(a.clone());
        let mut state = ConsensusState::new(ConsensusConfig::new(vs, 1000));
        let (n, _, _) = make_node("x");
        let v = signed_vote(&a, 0, n.hash, &sk_a);
        let cert = CommitCertificate {
            node_hash: n.hash,
            votes: vec![v],
            round: 0,
        };
        let null_resolver = |_d: &Did| None;
        let res = commit_verified(&mut state, cert, &null_resolver);
        assert!(matches!(res, Err(DagError::InvalidSignature(_))));
        assert!(state.committed.is_empty());
    }
}
