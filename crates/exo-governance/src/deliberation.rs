//! Deliberation process — structured decision-making with quorum-backed closure.

use exo_core::{Did, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::GovernanceError,
    quorum::{Approval, IndependenceAttestation, QuorumPolicy, QuorumResult, Role, compute_quorum},
};

/// A participant's stance on a deliberation proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Position {
    For,
    Against,
    Abstain,
}

/// A signed vote cast by a participant in a deliberation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter_did: Did,
    pub position: Position,
    pub reasoning_hash: [u8; 32],
    pub signature: Signature,
}

/// Lifecycle state of a deliberation: Open, Closed, or Cancelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliberationStatus {
    Open,
    Closed,
    Cancelled,
}

/// A structured governance deliberation over a hashed proposal with tracked votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deliberation {
    pub id: Uuid,
    pub proposal_hash: [u8; 32],
    pub participants: Vec<Did>,
    pub votes: Vec<Vote>,
    pub status: DeliberationStatus,
    pub created: Timestamp,
}

/// Outcome of closing a deliberation: approved, rejected, or quorum not met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliberationResult {
    Approved {
        votes_for: usize,
        votes_against: usize,
        abstentions: usize,
    },
    Rejected {
        votes_for: usize,
        votes_against: usize,
        abstentions: usize,
    },
    NoQuorum {
        reason: String,
    },
}

/// Open a new deliberation for the given proposal bytes and participant list.
#[must_use]
pub fn open_deliberation(proposal: &[u8], participants: &[Did]) -> Deliberation {
    Deliberation {
        id: Uuid::new_v4(),
        proposal_hash: *blake3::hash(proposal).as_bytes(),
        participants: participants.to_vec(),
        votes: Vec::new(),
        status: DeliberationStatus::Open,
        created: Timestamp::now_utc(),
    }
}

/// Record a vote in an open deliberation, rejecting duplicates and closed sessions.
pub fn cast_vote(delib: &mut Deliberation, vote: Vote) -> Result<(), GovernanceError> {
    if delib.status != DeliberationStatus::Open {
        return Err(GovernanceError::DeliberationNotOpen);
    }
    if delib.votes.iter().any(|v| v.voter_did == vote.voter_did) {
        return Err(GovernanceError::DuplicateVote(vote.voter_did.to_string()));
    }
    delib.votes.push(vote);
    Ok(())
}

/// Close a deliberation, tally votes, and return the result based on quorum policy.
pub fn close(delib: &mut Deliberation, quorum_policy: &QuorumPolicy) -> DeliberationResult {
    delib.status = DeliberationStatus::Closed;
    let votes_for = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::For)
        .count();
    let votes_against = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::Against)
        .count();
    let abstentions = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::Abstain)
        .count();

    let approvals: Vec<Approval> = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::For)
        .map(|v| Approval {
            approver_did: v.voter_did.clone(),
            role: Role::Contributor,
            timestamp: delib.created,
            signature: v.signature.clone(),
            independence_attestation: Some(IndependenceAttestation {
                attester_did: v.voter_did.clone(),
                no_common_control: true,
                no_coordination: true,
                identity_verified: true,
                signature: v.signature.clone(),
            }),
        })
        .collect();

    match compute_quorum(&approvals, quorum_policy) {
        QuorumResult::Met { .. } => {
            if votes_for > votes_against {
                DeliberationResult::Approved {
                    votes_for,
                    votes_against,
                    abstentions,
                }
            } else {
                DeliberationResult::Rejected {
                    votes_for,
                    votes_against,
                    abstentions,
                }
            }
        }
        QuorumResult::NotMet { reason } => DeliberationResult::NoQuorum { reason },
        QuorumResult::Contested { challenge } => DeliberationResult::NoQuorum {
            reason: format!("contested: {challenge}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use exo_core::crypto;

    use super::*;

    fn test_sig() -> Signature {
        let (_, sk) = crypto::generate_keypair();
        crypto::sign(b"vote", &sk)
    }
    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("ok")
    }
    fn vote(name: &str, pos: Position) -> Vote {
        Vote {
            voter_did: did(name),
            position: pos,
            reasoning_hash: [0u8; 32],
            signature: test_sig(),
        }
    }
    fn policy(min: usize) -> QuorumPolicy {
        QuorumPolicy {
            min_approvals: min,
            min_independent: min,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        }
    }

    #[test]
    fn open_creates_open_status() {
        let d = open_deliberation(b"proposal", &[did("alice"), did("bob")]);
        assert_eq!(d.status, DeliberationStatus::Open);
        assert_eq!(d.participants.len(), 2);
        assert!(d.votes.is_empty());
    }
    #[test]
    fn cast_vote_succeeds() {
        let mut d = open_deliberation(b"p", &[did("alice")]);
        assert!(cast_vote(&mut d, vote("alice", Position::For)).is_ok());
        assert_eq!(d.votes.len(), 1);
    }
    #[test]
    fn duplicate_vote_rejected() {
        let mut d = open_deliberation(b"p", &[did("alice")]);
        cast_vote(&mut d, vote("alice", Position::For)).unwrap();
        assert!(matches!(
            cast_vote(&mut d, vote("alice", Position::Against)).unwrap_err(),
            GovernanceError::DuplicateVote(_)
        ));
    }
    #[test]
    fn vote_on_closed_rejected() {
        let mut d = open_deliberation(b"p", &[did("alice")]);
        d.status = DeliberationStatus::Closed;
        assert!(matches!(
            cast_vote(&mut d, vote("alice", Position::For)).unwrap_err(),
            GovernanceError::DeliberationNotOpen
        ));
    }
    #[test]
    fn close_approved() {
        let mut d = open_deliberation(b"p", &[did("a"), did("b"), did("c")]);
        cast_vote(&mut d, vote("a", Position::For)).unwrap();
        cast_vote(&mut d, vote("b", Position::For)).unwrap();
        cast_vote(&mut d, vote("c", Position::Against)).unwrap();
        assert!(matches!(
            close(&mut d, &policy(2)),
            DeliberationResult::Approved {
                votes_for: 2,
                votes_against: 1,
                abstentions: 0
            }
        ));
    }
    #[test]
    fn close_rejected() {
        let mut d = open_deliberation(b"p", &[did("a"), did("b"), did("c")]);
        cast_vote(&mut d, vote("a", Position::For)).unwrap();
        cast_vote(&mut d, vote("b", Position::Against)).unwrap();
        cast_vote(&mut d, vote("c", Position::Against)).unwrap();
        assert!(matches!(
            close(&mut d, &policy(1)),
            DeliberationResult::Rejected { .. }
        ));
    }
    #[test]
    fn close_no_quorum() {
        let mut d = open_deliberation(b"p", &[did("a")]);
        cast_vote(&mut d, vote("a", Position::For)).unwrap();
        assert!(matches!(
            close(&mut d, &policy(3)),
            DeliberationResult::NoQuorum { .. }
        ));
    }
    #[test]
    fn abstentions_counted() {
        let mut d = open_deliberation(b"p", &[did("a"), did("b"), did("c")]);
        cast_vote(&mut d, vote("a", Position::For)).unwrap();
        cast_vote(&mut d, vote("b", Position::For)).unwrap();
        cast_vote(&mut d, vote("c", Position::Abstain)).unwrap();
        assert!(matches!(
            close(&mut d, &policy(2)),
            DeliberationResult::Approved {
                votes_for: 2,
                votes_against: 0,
                abstentions: 1
            }
        ));
    }
    #[test]
    fn cancelled_rejects_votes() {
        let mut d = open_deliberation(b"p", &[did("a")]);
        d.status = DeliberationStatus::Cancelled;
        assert!(cast_vote(&mut d, vote("a", Position::For)).is_err());
    }
    #[test]
    fn proposal_hash_deterministic() {
        let d1 = open_deliberation(b"same", &[]);
        let d2 = open_deliberation(b"same", &[]);
        assert_eq!(d1.proposal_hash, d2.proposal_hash);
        assert_ne!(
            d1.proposal_hash,
            open_deliberation(b"diff", &[]).proposal_hash
        );
    }
}
