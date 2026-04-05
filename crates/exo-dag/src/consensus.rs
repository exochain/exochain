//! DAG-BFT consensus -- Byzantine fault tolerant commitment over the DAG.
//!
//! Tolerates f < n/3 Byzantine validators. Nodes are finalized when a
//! commit certificate gathers >2/3 validator votes.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::types::{Did, Hash256, Signature};
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
pub fn commit(state: &mut ConsensusState, cert: CommitCertificate) {
    let hash = cert.node_hash;
    state.committed.push(hash);
    state.certificates.insert(hash, cert);
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
mod tests {
    use super::*;
    use crate::dag::{Dag, HybridClock, append};

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
        let mut clock = HybridClock::new();
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
        let mut clock = HybridClock::new();
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
        let mut clock = HybridClock::new();
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
        let mut clock = HybridClock::new();
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
        let mut clock = HybridClock::new();
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
}
