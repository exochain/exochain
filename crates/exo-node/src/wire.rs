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

use std::{fmt, marker::PhantomData};

use exo_core::types::{Did, Hash256, Signature, Timestamp};
use exo_dag::{
    consensus::{CommitCertificate, Proposal, Vote},
    dag::DagNode,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

pub const MAX_WIRE_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PEER_EXCHANGE_PEERS: usize = 256;
const MAX_PEER_ADDRESSES: usize = 16;
const MAX_PEER_ADDRESS_BYTES: usize = 512;
const MAX_DAG_SYNC_TIP_HASHES: usize = 128;
const MAX_DAG_NODES_PER_MESSAGE: usize = 500;
const MAX_DAG_NODE_PARENTS: usize = 1024;
const MAX_WIRE_GOVERNANCE_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_COMMIT_CERTIFICATE_VOTES: usize = 1024;
const MAX_POST_QUANTUM_SIGNATURE_BYTES: usize = 3_309;

struct BoundedVecVisitor<T, const MAX: usize> {
    label: &'static str,
    _marker: PhantomData<fn() -> T>,
}

impl<T, const MAX: usize> BoundedVecVisitor<T, MAX> {
    const fn new(label: &'static str) -> Self {
        Self {
            label,
            _marker: PhantomData,
        }
    }
}

impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} containing at most {} elements",
            self.label, MAX
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element()? {
            if values.len() >= MAX {
                return Err(de::Error::custom(format!(
                    "{} exceeds {} element limit",
                    self.label, MAX
                )));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(
    deserializer: D,
    label: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>::new(label))
}

struct BoundedBytesVisitor<const MAX: usize> {
    label: &'static str,
}

impl<const MAX: usize> BoundedBytesVisitor<MAX> {
    const fn new(label: &'static str) -> Self {
        Self { label }
    }

    fn validate_len<E: de::Error>(&self, len: usize) -> Result<(), E> {
        if len > MAX {
            return Err(de::Error::custom(format!(
                "{} exceeds {} byte limit",
                self.label, MAX
            )));
        }
        Ok(())
    }
}

impl<'de, const MAX: usize> Visitor<'de> for BoundedBytesVisitor<MAX> {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} of at most {} bytes", self.label, MAX)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.validate_len(value.len())?;
        Ok(value.to_vec())
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.validate_len(value.len())?;
        Ok(value)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element()? {
            if values.len() >= MAX {
                return Err(de::Error::custom(format!(
                    "{} exceeds {} byte limit",
                    self.label, MAX
                )));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_bounded_bytes<'de, D, const MAX: usize>(
    deserializer: D,
    label: &'static str,
) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_byte_buf(BoundedBytesVisitor::<MAX>::new(label))
}

fn deserialize_ed25519_signature_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_bounded_bytes::<D, 64>(deserializer, "Ed25519 signature bytes")?;
    if bytes.len() != 64 {
        return Err(de::Error::invalid_length(
            bytes.len(),
            &"64 bytes for Ed25519",
        ));
    }
    Ok(bytes)
}

fn deserialize_post_quantum_signature_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_POST_QUANTUM_SIGNATURE_BYTES>(
        deserializer,
        "post-quantum signature bytes",
    )
}

#[derive(Deserialize)]
enum WireSignatureProxy {
    Ed25519(#[serde(deserialize_with = "deserialize_ed25519_signature_bytes")] Vec<u8>),
    PostQuantum(#[serde(deserialize_with = "deserialize_post_quantum_signature_bytes")] Vec<u8>),
    Hybrid {
        #[serde(deserialize_with = "deserialize_ed25519_signature_bytes")]
        classical: Vec<u8>,
        #[serde(deserialize_with = "deserialize_post_quantum_signature_bytes")]
        pq: Vec<u8>,
    },
    Empty,
}

fn deserialize_bounded_signature<'de, D>(deserializer: D) -> Result<Signature, D::Error>
where
    D: Deserializer<'de>,
{
    match WireSignatureProxy::deserialize(deserializer)? {
        WireSignatureProxy::Ed25519(bytes) => {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes);
            Ok(Signature::Ed25519(sig))
        }
        WireSignatureProxy::PostQuantum(bytes) => Ok(Signature::PostQuantum(bytes)),
        WireSignatureProxy::Hybrid { classical, pq } => {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&classical);
            Ok(Signature::Hybrid { classical: sig, pq })
        }
        WireSignatureProxy::Empty => Ok(Signature::Empty),
    }
}

fn deserialize_peer_exchange_peers<'de, D>(deserializer: D) -> Result<Vec<WirePeerInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, WirePeerInfo, MAX_PEER_EXCHANGE_PEERS>(
        deserializer,
        "peer exchange peers",
    )
}

struct PeerAddressVisitor;

impl<'de> Visitor<'de> for PeerAddressVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "peer addresses containing at most {} strings of at most {} bytes",
            MAX_PEER_ADDRESSES, MAX_PEER_ADDRESS_BYTES
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<String>()? {
            if values.len() >= MAX_PEER_ADDRESSES {
                return Err(de::Error::custom(format!(
                    "peer addresses exceeds {MAX_PEER_ADDRESSES} element limit"
                )));
            }
            if value.len() > MAX_PEER_ADDRESS_BYTES {
                return Err(de::Error::custom(format!(
                    "peer address exceeds {MAX_PEER_ADDRESS_BYTES} byte limit"
                )));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_peer_addresses<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(PeerAddressVisitor)
}

fn deserialize_dag_sync_tip_hashes<'de, D>(deserializer: D) -> Result<Vec<Hash256>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Hash256, MAX_DAG_SYNC_TIP_HASHES>(
        deserializer,
        "DAG sync tip hashes",
    )
}

fn deserialize_governance_payload<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_bytes::<D, MAX_WIRE_GOVERNANCE_PAYLOAD_BYTES>(
        deserializer,
        "governance payload",
    )
}

fn deserialize_dag_node_parents<'de, D>(deserializer: D) -> Result<Vec<Hash256>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, Hash256, MAX_DAG_NODE_PARENTS>(deserializer, "DAG node parents")
}

#[derive(Deserialize)]
struct WireDagNodeSerde {
    hash: Hash256,
    #[serde(deserialize_with = "deserialize_dag_node_parents")]
    parents: Vec<Hash256>,
    payload_hash: Hash256,
    creator_did: Did,
    timestamp: Timestamp,
    #[serde(deserialize_with = "deserialize_bounded_signature")]
    signature: Signature,
}

impl From<WireDagNodeSerde> for DagNode {
    fn from(node: WireDagNodeSerde) -> Self {
        Self {
            hash: node.hash,
            parents: node.parents,
            payload_hash: node.payload_hash,
            creator_did: node.creator_did,
            timestamp: node.timestamp,
            signature: node.signature,
        }
    }
}

fn deserialize_dag_node<'de, D>(deserializer: D) -> Result<DagNode, D::Error>
where
    D: Deserializer<'de>,
{
    WireDagNodeSerde::deserialize(deserializer).map(Into::into)
}

fn deserialize_dag_nodes<'de, D>(deserializer: D) -> Result<Vec<DagNode>, D::Error>
where
    D: Deserializer<'de>,
{
    let nodes = deserialize_bounded_vec::<D, WireDagNodeSerde, MAX_DAG_NODES_PER_MESSAGE>(
        deserializer,
        "DAG nodes",
    )?;
    Ok(nodes.into_iter().map(Into::into).collect())
}

#[derive(Deserialize)]
struct WireVoteSerde {
    voter: Did,
    round: u64,
    node_hash: Hash256,
    #[serde(deserialize_with = "deserialize_bounded_signature")]
    signature: Signature,
}

impl From<WireVoteSerde> for Vote {
    fn from(vote: WireVoteSerde) -> Self {
        Self {
            voter: vote.voter,
            round: vote.round,
            node_hash: vote.node_hash,
            signature: vote.signature,
        }
    }
}

fn deserialize_vote<'de, D>(deserializer: D) -> Result<Vote, D::Error>
where
    D: Deserializer<'de>,
{
    WireVoteSerde::deserialize(deserializer).map(Into::into)
}

fn deserialize_commit_certificate_votes<'de, D>(deserializer: D) -> Result<Vec<Vote>, D::Error>
where
    D: Deserializer<'de>,
{
    let votes = deserialize_bounded_vec::<D, WireVoteSerde, MAX_COMMIT_CERTIFICATE_VOTES>(
        deserializer,
        "commit certificate votes",
    )?;
    Ok(votes.into_iter().map(Into::into).collect())
}

#[derive(Deserialize)]
struct WireCommitCertificateSerde {
    node_hash: Hash256,
    #[serde(deserialize_with = "deserialize_commit_certificate_votes")]
    votes: Vec<Vote>,
    round: u64,
}

impl From<WireCommitCertificateSerde> for CommitCertificate {
    fn from(certificate: WireCommitCertificateSerde) -> Self {
        Self {
            node_hash: certificate.node_hash,
            votes: certificate.votes,
            round: certificate.round,
        }
    }
}

fn deserialize_commit_certificate<'de, D>(deserializer: D) -> Result<CommitCertificate, D::Error>
where
    D: Deserializer<'de>,
{
    WireCommitCertificateSerde::deserialize(deserializer).map(Into::into)
}

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
    #[serde(deserialize_with = "deserialize_peer_addresses")]
    pub addresses: Vec<String>,
    pub public_key_hash: Hash256,
    pub last_seen: Timestamp,
}

/// Exchange peer lists for bootstrapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchangeMsg {
    pub sender: Did,
    #[serde(deserialize_with = "deserialize_peer_exchange_peers")]
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
    #[serde(deserialize_with = "deserialize_dag_sync_tip_hashes")]
    pub tip_hashes: Vec<Hash256>,
    /// Maximum number of nodes to return.
    pub max_nodes: u32,
}

/// Response with DAG nodes the requester is missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagSyncResponseMsg {
    pub sender: Did,
    /// DAG nodes in topological order (parents before children).
    #[serde(deserialize_with = "deserialize_dag_nodes")]
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
    #[serde(deserialize_with = "deserialize_dag_node")]
    pub node: DagNode,
    /// Signature over the proposal by the proposer.
    #[serde(deserialize_with = "deserialize_bounded_signature")]
    pub signature: Signature,
}

/// BFT vote broadcast to all validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVoteMsg {
    #[serde(deserialize_with = "deserialize_vote")]
    pub vote: Vote,
}

/// Commit certificate broadcast to all nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusCommitMsg {
    #[serde(deserialize_with = "deserialize_commit_certificate")]
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
    #[serde(deserialize_with = "deserialize_governance_payload")]
    pub payload: Vec<u8>,
    pub timestamp: Timestamp,
    #[serde(deserialize_with = "deserialize_bounded_signature")]
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
    #[serde(deserialize_with = "deserialize_dag_nodes")]
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
    ensure_wire_message_size(buf.len())?;
    Ok(buf)
}

/// Decode a wire message from CBOR bytes.
pub fn decode(bytes: &[u8]) -> Result<WireMessage, String> {
    ensure_wire_message_size(bytes.len())?;
    ciborium::from_reader(bytes).map_err(|e| format!("CBOR decode: {e}"))
}

fn ensure_wire_message_size(size: usize) -> Result<(), String> {
    if size > MAX_WIRE_MESSAGE_BYTES {
        return Err(format!(
            "wire message exceeds {MAX_WIRE_MESSAGE_BYTES} byte limit: {size} bytes"
        ));
    }
    Ok(())
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

    const EXPECTED_MAX_PEER_EXCHANGE_PEERS: usize = 256;
    const EXPECTED_MAX_PEER_ADDRESSES: usize = 16;
    const EXPECTED_MAX_PEER_ADDRESS_BYTES: usize = 512;
    const EXPECTED_MAX_DAG_SYNC_TIP_HASHES: usize = 128;
    const EXPECTED_MAX_DAG_NODES_PER_MESSAGE: usize = 500;
    const EXPECTED_MAX_DAG_NODE_PARENTS: usize = 1024;
    const EXPECTED_MAX_WIRE_GOVERNANCE_PAYLOAD_BYTES: usize = 64 * 1024;
    const EXPECTED_MAX_COMMIT_CERTIFICATE_VOTES: usize = 1024;
    const EXPECTED_MAX_POST_QUANTUM_SIGNATURE_BYTES: usize = 3_309;

    fn test_did() -> Did {
        Did::new("did:exo:test-node").unwrap()
    }

    fn test_hash(label: &[u8]) -> Hash256 {
        Hash256::digest(label)
    }

    fn test_vote(index: usize) -> Vote {
        Vote {
            voter: Did::new(&format!("did:exo:voter-{index}")).unwrap(),
            round: 1,
            node_hash: test_hash(b"node"),
            signature: Signature::empty(),
        }
    }

    fn test_node(parents: Vec<Hash256>) -> DagNode {
        DagNode {
            hash: test_hash(b"dag-node"),
            parents,
            payload_hash: test_hash(b"payload"),
            creator_did: test_did(),
            timestamp: Timestamp::new(1_000, 0),
            signature: Signature::empty(),
        }
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
    fn roundtrip_consensus_proposal_preserves_node_and_hybrid_signature() {
        let node_hash = test_hash(b"proposal-node");
        let msg = WireMessage::ConsensusProposal(ConsensusProposalMsg {
            proposal: Proposal {
                proposer: test_did(),
                round: 9,
                node_hash,
            },
            node: test_node(vec![test_hash(b"parent-1"), test_hash(b"parent-2")]),
            signature: Signature::Hybrid {
                classical: [4u8; 64],
                pq: vec![5u8; 96],
            },
        });

        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();

        match decoded {
            WireMessage::ConsensusProposal(proposal) => {
                assert_eq!(proposal.proposal.round, 9);
                assert_eq!(proposal.proposal.node_hash, node_hash);
                assert_eq!(proposal.node.parents.len(), 2);
                match proposal.signature {
                    Signature::Hybrid { classical, pq } => {
                        assert_eq!(classical, [4u8; 64]);
                        assert_eq!(pq, vec![5u8; 96]);
                    }
                    other => panic!("expected hybrid signature, got {other:?}"),
                }
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_consensus_commit_preserves_certificate_votes() {
        let node_hash = test_hash(b"committed-node");
        let msg = WireMessage::ConsensusCommit(ConsensusCommitMsg {
            certificate: CommitCertificate {
                node_hash,
                votes: vec![test_vote(1), test_vote(2), test_vote(3)],
                round: 11,
            },
        });

        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();

        match decoded {
            WireMessage::ConsensusCommit(commit) => {
                assert_eq!(commit.certificate.node_hash, node_hash);
                assert_eq!(commit.certificate.votes.len(), 3);
                assert_eq!(commit.certificate.round, 11);
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
    fn roundtrip_state_snapshot_chunk_preserves_post_quantum_node_signature() {
        let mut node = test_node(vec![]);
        node.signature = Signature::PostQuantum(vec![7u8; 128]);
        let msg = WireMessage::StateSnapshotChunk(StateSnapshotChunkMsg {
            sender: test_did(),
            from_height: 12,
            nodes: vec![node],
            to_height: 12,
            has_more: true,
        });

        let bytes = encode(&msg).unwrap();
        let decoded = decode(&bytes).unwrap();

        match decoded {
            WireMessage::StateSnapshotChunk(chunk) => {
                assert_eq!(chunk.from_height, 12);
                assert_eq!(chunk.to_height, 12);
                assert!(chunk.has_more);
                match &chunk.nodes[0].signature {
                    Signature::PostQuantum(pq) => assert_eq!(pq, &vec![7u8; 128]),
                    other => panic!("expected post-quantum signature, got {other:?}"),
                }
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

    #[test]
    fn decode_rejects_oversized_wire_message_before_cbor() {
        let oversized = vec![0u8; MAX_WIRE_MESSAGE_BYTES + 1];

        let err = decode(&oversized).expect_err("oversized inbound frame must fail");

        assert!(err.contains(&format!(
            "wire message exceeds {MAX_WIRE_MESSAGE_BYTES} byte limit"
        )));
    }

    #[test]
    fn encode_rejects_oversized_wire_message() {
        let msg = WireMessage::GovernanceEvent(GovernanceEventMsg {
            sender: test_did(),
            event_type: GovernanceEventType::AuditEntry,
            payload: vec![0xA5; MAX_WIRE_MESSAGE_BYTES + 1],
            timestamp: Timestamp::new(1000, 1),
            signature: Signature::from_bytes([3u8; 64]),
        });

        let result = encode(&msg);
        assert!(result.is_err());
        let err = result.unwrap_err();

        assert!(err.contains(&format!(
            "wire message exceeds {MAX_WIRE_MESSAGE_BYTES} byte limit"
        )));
    }

    #[test]
    fn decode_rejects_peer_exchange_with_too_many_peers() {
        let peers = (0..=EXPECTED_MAX_PEER_EXCHANGE_PEERS)
            .map(|idx| WirePeerInfo {
                did: Did::new(&format!("did:exo:peer-{idx}")).unwrap(),
                addresses: Vec::new(),
                public_key_hash: test_hash(format!("peer-key-{idx}").as_bytes()),
                last_seen: Timestamp::new(1_000, 0),
            })
            .collect();
        let msg = WireMessage::PeerExchange(PeerExchangeMsg {
            sender: test_did(),
            peers,
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("oversized peer exchange must fail");

        assert!(err.contains("peer exchange peers"));
    }

    #[test]
    fn decode_rejects_peer_with_too_many_addresses() {
        let addresses = (0..=EXPECTED_MAX_PEER_ADDRESSES)
            .map(|idx| format!("/ip4/127.0.0.1/tcp/{}", 4_000 + idx))
            .collect();
        let msg = WireMessage::PeerExchange(PeerExchangeMsg {
            sender: test_did(),
            peers: vec![WirePeerInfo {
                did: test_did(),
                addresses,
                public_key_hash: test_hash(b"peer-key"),
                last_seen: Timestamp::new(1_000, 0),
            }],
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("peer with too many addresses must fail");

        assert!(err.contains("peer addresses"));
    }

    #[test]
    fn decode_rejects_peer_address_over_byte_limit() {
        let oversized_address = "a".repeat(EXPECTED_MAX_PEER_ADDRESS_BYTES + 1);
        let msg = WireMessage::PeerExchange(PeerExchangeMsg {
            sender: test_did(),
            peers: vec![WirePeerInfo {
                did: test_did(),
                addresses: vec![oversized_address],
                public_key_hash: test_hash(b"peer-key"),
                last_seen: Timestamp::new(1_000, 0),
            }],
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("peer with oversized address must fail");

        assert!(err.contains("peer address"));
    }

    #[test]
    fn decode_rejects_dag_sync_request_with_too_many_tip_hashes() {
        let tip_hashes = (0..=EXPECTED_MAX_DAG_SYNC_TIP_HASHES)
            .map(|idx| test_hash(format!("tip-{idx}").as_bytes()))
            .collect();
        let msg = WireMessage::DagSyncRequest(DagSyncRequestMsg {
            sender: test_did(),
            tip_hashes,
            max_nodes: 10,
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("oversized tip hash request must fail");

        assert!(err.contains("DAG sync tip hashes"));
    }

    #[test]
    fn decode_rejects_dag_sync_response_with_too_many_nodes() {
        let nodes = (0..=EXPECTED_MAX_DAG_NODES_PER_MESSAGE)
            .map(|idx| {
                let mut node = test_node(vec![]);
                node.hash = test_hash(format!("node-{idx}").as_bytes());
                node
            })
            .collect();
        let msg = WireMessage::DagSyncResponse(DagSyncResponseMsg {
            sender: test_did(),
            nodes,
            has_more: false,
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("DAG sync response with too many nodes must fail");

        assert!(err.contains("DAG nodes"));
    }

    #[test]
    fn decode_rejects_dag_node_with_too_many_parents() {
        let parents = (0..=EXPECTED_MAX_DAG_NODE_PARENTS)
            .map(|idx| test_hash(format!("parent-{idx}").as_bytes()))
            .collect();
        let msg = WireMessage::DagSyncResponse(DagSyncResponseMsg {
            sender: test_did(),
            nodes: vec![test_node(parents)],
            has_more: false,
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("DAG node with too many parents must fail");

        assert!(err.contains("DAG node parents"));
    }

    #[test]
    fn decode_rejects_governance_event_with_oversized_payload() {
        let msg = WireMessage::GovernanceEvent(GovernanceEventMsg {
            sender: test_did(),
            event_type: GovernanceEventType::AuditEntry,
            payload: vec![0xA5; EXPECTED_MAX_WIRE_GOVERNANCE_PAYLOAD_BYTES + 1],
            timestamp: Timestamp::new(1000, 1),
            signature: Signature::from_bytes([3u8; 64]),
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("oversized governance payload must fail");

        assert!(err.contains("governance payload"));
    }

    #[test]
    fn decode_rejects_commit_certificate_with_too_many_votes() {
        let votes = (0..=EXPECTED_MAX_COMMIT_CERTIFICATE_VOTES)
            .map(test_vote)
            .collect();
        let msg = WireMessage::ConsensusCommit(ConsensusCommitMsg {
            certificate: CommitCertificate {
                node_hash: test_hash(b"node"),
                votes,
                round: 1,
            },
        });
        let bytes = encode(&msg).unwrap();

        let err = decode(&bytes).expect_err("oversized commit certificate must fail");

        assert!(err.contains("commit certificate votes"));
    }

    #[test]
    fn deserialize_rejects_short_ed25519_signature_from_untrusted_envelope() {
        let msg = WireMessage::GovernanceEvent(GovernanceEventMsg {
            sender: test_did(),
            event_type: GovernanceEventType::AuditEntry,
            payload: b"audit".to_vec(),
            timestamp: Timestamp::new(1000, 1),
            signature: Signature::from_bytes([3u8; 64]),
        });
        let mut value = serde_json::to_value(&msg).unwrap();
        value["GovernanceEvent"]["signature"] = serde_json::json!({ "Ed25519": [1, 2, 3] });

        let err = serde_json::from_value::<WireMessage>(value)
            .expect_err("short Ed25519 signatures must fail during deserialization");

        assert!(err.to_string().contains("64 bytes"));
    }

    #[test]
    fn deserialize_rejects_oversized_post_quantum_signature_from_untrusted_envelope() {
        let mut node = test_node(vec![]);
        node.signature = Signature::PostQuantum(vec![7u8; 128]);
        let msg = WireMessage::StateSnapshotChunk(StateSnapshotChunkMsg {
            sender: test_did(),
            from_height: 12,
            nodes: vec![node],
            to_height: 12,
            has_more: false,
        });
        let mut value = serde_json::to_value(&msg).unwrap();
        value["StateSnapshotChunk"]["nodes"][0]["signature"] = serde_json::json!({
            "PostQuantum": vec![9u8; EXPECTED_MAX_POST_QUANTUM_SIGNATURE_BYTES + 1],
        });

        let err = serde_json::from_value::<WireMessage>(value)
            .expect_err("oversized post-quantum signatures must fail during deserialization");

        assert!(err.to_string().contains("post-quantum signature bytes"));
    }
}
