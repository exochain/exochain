//! Wire protocol — CBOR-encoded messages exchanged between exochain nodes.
//!
//! All messages are deterministically serialized via CBOR (ciborium) to honour
//! the constitutional determinism contract. Messages fall into three layers:
//!
//! 1. **Discovery** — peer exchange for bootstrapping
//! 2. **DAG sync** — request/response for missing DAG nodes
//! 3. **Consensus** — BFT proposal, vote, and commit certificate broadcast
//! 4. **Governance** — governance event broadcast

#![allow(clippy::large_enum_variant)]

use exo_core::types::{Did, Hash256, Signature, Timestamp};
use exo_dag::{
    consensus::{CommitCertificate, Proposal, Vote},
    dag::DagNode,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Wire message envelope
// ---------------------------------------------------------------------------

/// Top-level wire message exchanged between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    // -- Discovery layer --
    /// Exchange peer information for bootstrapping.
    PeerExchange(PeerExchangeMsg),

    // -- DAG sync layer (request/response) --
    /// Request DAG nodes that the sender is missing.
    DagSyncRequest(DagSyncRequestMsg),
    /// Response with requested DAG nodes.
    DagSyncResponse(DagSyncResponseMsg),

    // -- Consensus layer (gossipsub broadcast) --
    /// A BFT proposal to commit a DAG node.
    ConsensusProposal(ConsensusProposalMsg),
    /// A BFT vote on a proposal.
    ConsensusVote(ConsensusVoteMsg),
    /// A commit certificate proving >2/3 validator agreement.
    ConsensusCommit(ConsensusCommitMsg),

    // -- Governance layer (gossipsub broadcast) --
    /// A governance event (decision created, vote cast, etc.).
    GovernanceEvent(GovernanceEventMsg),

    // -- State sync layer (request/response) --
    /// Request a state snapshot from a peer.
    StateSnapshotRequest(StateSnapshotRequestMsg),
    /// A chunk of the state snapshot.
    StateSnapshotChunk(StateSnapshotChunkMsg),
}

// ---------------------------------------------------------------------------
// Discovery messages
// ---------------------------------------------------------------------------

/// Peer information shared during discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePeerInfo {
    pub did: Did,
    pub addresses: Vec<String>,
    pub public_key_hash: Hash256,
    pub last_seen: Timestamp,
}

/// Exchange peer lists for bootstrapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchangeMsg {
    pub sender: Did,
    pub peers: Vec<WirePeerInfo>,
}

// ---------------------------------------------------------------------------
// DAG sync messages (request/response)
// ---------------------------------------------------------------------------

/// Request missing DAG nodes by providing local tip hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagSyncRequestMsg {
    pub sender: Did,
    /// The sender's current tip hashes so the responder knows what to send.
    pub tip_hashes: Vec<Hash256>,
    /// Maximum number of nodes to return.
    pub max_nodes: u32,
}

/// Response with DAG nodes the requester is missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagSyncResponseMsg {
    pub sender: Did,
    /// DAG nodes in topological order (parents before children).
    pub nodes: Vec<DagNode>,
    /// Whether there are more nodes available (pagination).
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// Consensus messages (gossipsub broadcast)
// ---------------------------------------------------------------------------

/// BFT proposal broadcast to all validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposalMsg {
    pub proposal: Proposal,
    /// The full DAG node being proposed (so validators can verify it).
    pub node: DagNode,
    /// Signature over the proposal by the proposer.
    pub signature: Signature,
}

/// BFT vote broadcast to all validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVoteMsg {
    pub vote: Vote,
}

/// Commit certificate broadcast to all nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusCommitMsg {
    pub certificate: CommitCertificate,
}

// ---------------------------------------------------------------------------
// Governance messages (gossipsub broadcast)
// ---------------------------------------------------------------------------

/// A governance event broadcast to the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEventMsg {
    pub sender: Did,
    pub event_type: GovernanceEventType,
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
    pub signature: Signature,
}

/// Types of governance events broadcast over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceEventType {
    /// A new governance decision was created.
    DecisionCreated,
    /// A vote was cast on a decision.
    VoteCast,
    /// A decision was finalized.
    DecisionFinalized,
    /// Authority was delegated.
    AuthorityDelegated,
    /// Consent was granted or revoked.
    ConsentChanged,
    /// A user/agent was enrolled.
    EntityEnrolled,
    /// An audit entry was appended.
    AuditEntry,
    /// Validator set change — add or remove a validator.
    ValidatorSetChange,
}

/// A request to change the validator set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "unaudited-infrastructure-holons"), allow(dead_code))]
pub enum ValidatorChange {
    /// Promote a node to validator status.
    AddValidator { did: Did },
    /// Remove a node from the validator set.
    RemoveValidator { did: Did },
}

// ---------------------------------------------------------------------------
// State sync messages (request/response)
// ---------------------------------------------------------------------------

/// Request a state snapshot for initial sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshotRequestMsg {
    pub sender: Did,
    /// Start syncing from this committed height.
    pub from_height: u64,
    /// Maximum number of nodes per chunk.
    pub chunk_size: u32,
}

/// A chunk of the state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshotChunkMsg {
    pub sender: Did,
    /// The starting height of this chunk.
    pub from_height: u64,
    /// Committed DAG nodes in height order.
    pub nodes: Vec<DagNode>,
    /// The committed height this chunk reaches.
    pub to_height: u64,
    /// Whether there are more chunks.
    pub has_more: bool,
}

// ---------------------------------------------------------------------------
// CBOR serialization
// ---------------------------------------------------------------------------

/// Encode a wire message to CBOR bytes (deterministic).
pub fn encode(msg: &WireMessage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf).map_err(|e| format!("CBOR encode: {e}"))?;
    Ok(buf)
}

/// Decode a wire message from CBOR bytes.
pub fn decode(bytes: &[u8]) -> Result<WireMessage, String> {
    ciborium::from_reader(bytes).map_err(|e| format!("CBOR decode: {e}"))
}

// ---------------------------------------------------------------------------
// Gossipsub topic names
// ---------------------------------------------------------------------------

/// Topic names for gossipsub pub/sub channels.
pub mod topics {
    /// Consensus messages (proposals, votes, commits).
    pub const CONSENSUS: &str = "exochain/consensus/v1";
    /// Governance events (decisions, votes, delegations).
    pub const GOVERNANCE: &str = "exochain/governance/v1";
    /// Peer exchange messages.
    pub const PEER_EXCHANGE: &str = "exochain/peers/v1";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use exo_core::types::{Did, Hash256, Signature, Timestamp};

    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-node").unwrap()
    }

    #[test]
    fn roundtrip_peer_exchange() {
        let msg = WireMessage::PeerExchange(PeerExchangeMsg {
            sender: test_did(),
            peers: vec![WirePeerInfo {
                did: test_did(),
                addresses: vec!["/ip4/127.0.0.1/tcp/4001".into()],
                public_key_hash: Hash256::ZERO,
                last_seen: Timestamp::ZERO,
            }],
        });
        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();
        match decoded {
            WireMessage::PeerExchange(pe) => {
                assert_eq!(pe.peers.len(), 1);
                assert_eq!(pe.peers[0].addresses[0], "/ip4/127.0.0.1/tcp/4001");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_dag_sync_request() {
        let msg = WireMessage::DagSyncRequest(DagSyncRequestMsg {
            sender: test_did(),
            tip_hashes: vec![Hash256::ZERO],
            max_nodes: 100,
        });
        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();
        match decoded {
            WireMessage::DagSyncRequest(req) => {
                assert_eq!(req.tip_hashes.len(), 1);
                assert_eq!(req.max_nodes, 100);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_governance_event() {
        let msg = WireMessage::GovernanceEvent(GovernanceEventMsg {
            sender: test_did(),
            event_type: GovernanceEventType::DecisionCreated,
            payload: b"test payload".to_vec(),
            timestamp: Timestamp::new(1000, 1),
            signature: Signature::from_bytes([1u8; 64]),
        });
        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();
        match decoded {
            WireMessage::GovernanceEvent(ge) => {
                assert_eq!(ge.payload, b"test payload");
                assert!(matches!(
                    ge.event_type,
                    GovernanceEventType::DecisionCreated
                ));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_consensus_vote() {
        let msg = WireMessage::ConsensusVote(ConsensusVoteMsg {
            vote: Vote {
                voter: test_did(),
                round: 5,
                node_hash: Hash256::ZERO,
                signature: Signature::from_bytes([2u8; 64]),
            },
        });
        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();
        match decoded {
            WireMessage::ConsensusVote(cv) => {
                assert_eq!(cv.vote.round, 5);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_state_snapshot_request() {
        let msg = WireMessage::StateSnapshotRequest(StateSnapshotRequestMsg {
            sender: test_did(),
            from_height: 42,
            chunk_size: 50,
        });
        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();
        match decoded {
            WireMessage::StateSnapshotRequest(req) => {
                assert_eq!(req.from_height, 42);
                assert_eq!(req.chunk_size, 50);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deterministic_encoding() {
        let msg = WireMessage::PeerExchange(PeerExchangeMsg {
            sender: test_did(),
            peers: vec![],
        });
        let bytes1 = encode(&msg).unwrap();
        let bytes2 = encode(&msg).unwrap();
        assert_eq!(bytes1, bytes2, "CBOR encoding must be deterministic");
    }
}
