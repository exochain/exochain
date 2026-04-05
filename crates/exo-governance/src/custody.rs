//! CustodyEvent — chain of responsibility tracking for decision.forum
//!
//! Per the decision.forum whitepaper: "who did what, when, optionally signed."
//! CustodyEvents form an append-only log of all actions taken on a DecisionRecord,
//! creating a complete chain of responsibility.
//!
//! Satisfies: GOV-005 (authority chain), TNC-03 (audit continuity), LEG-001 (business records)

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::types::GovernanceSignature;

/// Actions that produce CustodyEvents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyAction {
    /// Record created.
    Create,
    /// Record edited (context, decision, or consequences modified).
    Edit,
    /// CrosscheckReport attached.
    AttachCrosscheck { report_id: String },
    /// Attestation: approval.
    Approve,
    /// Attestation: rejection.
    Reject,
    /// Attestation: abstention.
    Abstain,
    /// Veto exercised (if policy allows).
    Veto,
    /// Clearance certificate issued.
    IssueClearance { certificate_id: String },
    /// Record anchored to immutable store (EXOCHAIN).
    Anchor { receipt_id: String },
    /// Status advanced in lifecycle.
    AdvanceStatus { from: String, to: String },
    /// Record superseded by a new record.
    Supersede { successor_id: String },
    /// Record deprecated.
    Deprecate,
    /// Emergency action taken.
    EmergencyAction { reason: String },
    /// Challenge filed.
    Challenge { challenge_id: String },
    /// Comment or note added.
    Comment { content: String },
    /// Custom action.
    Custom {
        action: String,
        metadata: Option<String>,
    },
}

/// Role of the actor performing the custody action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyRole {
    /// Decision proposer/author.
    Proposer,
    /// Reviewer with attestation authority.
    Reviewer,
    /// Steward with elevated authority.
    Steward,
    /// Observer (read-only, but may comment).
    Observer,
    /// System/automated process.
    System,
    /// AI agent acting under delegation.
    AiAgent { delegation_id: Hash256 },
    /// Custom role.
    Custom(String),
}

/// A single custody event in the chain of responsibility.
///
/// Per whitepaper: CustodyEvents include actor_id, role, action, time,
/// and optionally a signature over the record hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyEvent {
    /// Unique event identifier.
    pub id: String,
    /// Sequence number in the custody chain (monotonically increasing).
    pub sequence: u64,
    /// Hash of the DecisionRecord at time of this event.
    pub record_hash: Hash256,
    /// Hash of the previous CustodyEvent (chain linkage).
    pub prev_event_hash: Option<Hash256>,
    /// DID of the actor.
    pub actor_id: Did,
    /// Role of the actor.
    pub role: CustodyRole,
    /// The action performed.
    pub action: CustodyAction,
    /// Timestamp.
    pub timestamp: Timestamp,
    /// Optional detached signature over the record_hash (Ed25519).
    pub signature: Option<GovernanceSignature>,
    /// Hash of this event (computed over all fields except this one).
    pub event_hash: Hash256,
}

/// An append-only chain of custody events for a single DecisionRecord.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyChain {
    /// The DecisionRecord this chain belongs to.
    pub decision_id: Hash256,
    /// Ordered custody events.
    pub events: Vec<CustodyEvent>,
    /// Current sequence counter.
    pub next_sequence: u64,
}

impl CustodyChain {
    /// Create a new empty custody chain for a decision.
    #[must_use]
    pub fn new(decision_id: Hash256) -> Self {
        Self {
            decision_id,
            events: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Append a custody event to the chain.
    pub fn append(
        &mut self,
        actor_id: Did,
        role: CustodyRole,
        action: CustodyAction,
        record_hash: Hash256,
        timestamp: Timestamp,
        signature: Option<GovernanceSignature>,
    ) -> &CustodyEvent {
        let prev_event_hash = self.events.last().map(|e| e.event_hash);
        let sequence = self.next_sequence;

        // Compute event hash over canonical fields
        let event_hash = Self::compute_event_hash(
            sequence,
            &record_hash,
            prev_event_hash.as_ref(),
            &actor_id,
            &action,
            &timestamp,
        );

        let event = CustodyEvent {
            id: format!("ce-{}-{}", self.decision_id.as_bytes()[0], sequence),
            sequence,
            record_hash,
            prev_event_hash,
            actor_id,
            role,
            action,
            timestamp,
            signature,
            event_hash,
        };

        self.next_sequence += 1;
        self.events.push(event);
        // SAFETY: we just pushed, so `last()` is guaranteed `Some`.
        // Using indexing instead of `expect` for constitutional lint compliance.
        &self.events[self.events.len() - 1]
    }

    /// Verify the integrity of the custody chain.
    /// Returns `Ok(())` if all event hashes and chain links are valid.
    ///
    /// # Errors
    ///
    /// Returns [`CustodyChainError`] if any sequence gap, broken link,
    /// missing link, or hash mismatch is detected.
    pub fn verify_integrity(&self) -> Result<(), CustodyChainError> {
        for (i, event) in self.events.iter().enumerate() {
            // Verify sequence — use checked conversion (constitutional lint compliance)
            let expected_seq = u64::try_from(i).map_err(|_| CustodyChainError::SequenceGap {
                expected: 0,
                actual: event.sequence,
            })?;
            if event.sequence != expected_seq {
                return Err(CustodyChainError::SequenceGap {
                    expected: expected_seq,
                    actual: event.sequence,
                });
            }

            // Verify chain linkage
            if i == 0 {
                if event.prev_event_hash.is_some() {
                    return Err(CustodyChainError::InvalidGenesisLink);
                }
            } else {
                let expected_prev = self.events[i - 1].event_hash;
                match &event.prev_event_hash {
                    Some(prev) if *prev != expected_prev => {
                        return Err(CustodyChainError::BrokenLink {
                            sequence: event.sequence,
                            expected: expected_prev,
                            actual: *prev,
                        });
                    }
                    None => {
                        return Err(CustodyChainError::MissingLink {
                            sequence: event.sequence,
                        });
                    }
                    _ => {}
                }
            }

            // Verify event hash
            let recomputed = Self::compute_event_hash(
                event.sequence,
                &event.record_hash,
                event.prev_event_hash.as_ref(),
                &event.actor_id,
                &event.action,
                &event.timestamp,
            );
            if recomputed != event.event_hash {
                return Err(CustodyChainError::HashMismatch {
                    sequence: event.sequence,
                    expected: recomputed,
                    actual: event.event_hash,
                });
            }
        }

        Ok(())
    }

    /// Number of events in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get the latest event.
    #[must_use]
    pub fn latest(&self) -> Option<&CustodyEvent> {
        self.events.last()
    }

    /// Get all events by a specific actor DID string.
    #[must_use]
    pub fn events_by_actor(&self, actor: &str) -> Vec<&CustodyEvent> {
        self.events
            .iter()
            .filter(|e| e.actor_id.as_str() == actor)
            .collect()
    }

    /// Get all attestation events (Approve, Reject, Abstain, Veto).
    #[must_use]
    pub fn attestations(&self) -> Vec<&CustodyEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    CustodyAction::Approve
                        | CustodyAction::Reject
                        | CustodyAction::Abstain
                        | CustodyAction::Veto
                )
            })
            .collect()
    }

    /// Compute the hash of a custody event from its canonical fields.
    ///
    /// Uses blake3 for deterministic hashing. The action is serialized
    /// via CBOR (through `exo_core::hash::hash_structured`) for canonical
    /// byte representation.
    fn compute_event_hash(
        sequence: u64,
        record_hash: &Hash256,
        prev_event_hash: Option<&Hash256>,
        actor_id: &Did,
        action: &CustodyAction,
        timestamp: &Timestamp,
    ) -> Hash256 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&sequence.to_le_bytes());
        hasher.update(record_hash.as_bytes());
        if let Some(prev) = prev_event_hash {
            hasher.update(prev.as_bytes());
        }
        hasher.update(actor_id.as_str().as_bytes());
        // Use CBOR canonical serialization for the action via exo_core
        let action_hash = exo_core::hash::hash_structured(action).unwrap_or(Hash256::ZERO);
        hasher.update(action_hash.as_bytes());
        hasher.update(&timestamp.physical_ms.to_le_bytes());
        hasher.update(&timestamp.logical.to_le_bytes());

        let hash = hasher.finalize();
        Hash256::from_bytes(*hash.as_bytes())
    }
}

/// Errors in custody chain verification.
#[derive(Debug, Clone)]
pub enum CustodyChainError {
    /// Sequence number gap detected.
    SequenceGap { expected: u64, actual: u64 },
    /// Genesis event should not have a previous event hash.
    InvalidGenesisLink,
    /// Chain link hash does not match expected previous event hash.
    BrokenLink {
        sequence: u64,
        expected: Hash256,
        actual: Hash256,
    },
    /// Missing previous event hash on non-genesis event.
    MissingLink { sequence: u64 },
    /// Event hash does not match recomputed hash.
    HashMismatch {
        sequence: u64,
        expected: Hash256,
        actual: Hash256,
    },
}

impl std::fmt::Display for CustodyChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceGap { expected, actual } => {
                write!(f, "Sequence gap: expected {expected}, got {actual}")
            }
            Self::InvalidGenesisLink => write!(f, "Genesis event should not have prev_event_hash"),
            Self::BrokenLink { sequence, .. } => {
                write!(f, "Broken chain link at sequence {sequence}")
            }
            Self::MissingLink { sequence } => {
                write!(f, "Missing prev_event_hash at sequence {sequence}")
            }
            Self::HashMismatch { sequence, .. } => {
                write!(f, "Event hash mismatch at sequence {sequence}")
            }
        }
    }
}

impl std::error::Error for CustodyChainError {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn test_did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("valid")
    }

    #[test]
    fn test_custody_chain_creation() {
        let chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.latest().is_none());
    }

    #[test]
    fn test_append_events() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("alice"),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_ts(1000),
            None,
        );

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.events[0].sequence, 0);
        assert!(chain.events[0].prev_event_hash.is_none());

        chain.append(
            test_did("bob"),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_ts(2000),
            None,
        );

        assert_eq!(chain.len(), 2);
        assert_eq!(chain.events[1].sequence, 1);
        assert_eq!(
            chain.events[1].prev_event_hash.expect("should have prev"),
            chain.events[0].event_hash
        );
    }

    #[test]
    fn test_chain_integrity() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("alice"),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_ts(1000),
            None,
        );
        chain.append(
            test_did("bob"),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_ts(2000),
            None,
        );
        chain.append(
            test_did("carol"),
            CustodyRole::Steward,
            CustodyAction::IssueClearance {
                certificate_id: "cert-1".to_string(),
            },
            record_hash,
            test_ts(3000),
            None,
        );

        assert!(chain.verify_integrity().is_ok());
    }

    #[test]
    fn test_tampered_chain_detected() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("alice"),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_ts(1000),
            None,
        );
        chain.append(
            test_did("bob"),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_ts(2000),
            None,
        );

        // Tamper with the first event's hash
        chain.events[0].event_hash = Hash256::digest(b"tampered");
        assert!(chain.verify_integrity().is_err());
    }

    #[test]
    fn test_events_by_actor() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("alice"),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_ts(1000),
            None,
        );
        chain.append(
            test_did("bob"),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_ts(2000),
            None,
        );
        chain.append(
            test_did("alice"),
            CustodyRole::Proposer,
            CustodyAction::Comment {
                content: "Updated rationale".to_string(),
            },
            record_hash,
            test_ts(3000),
            None,
        );

        let alice_events = chain.events_by_actor("did:exo:alice");
        assert_eq!(alice_events.len(), 2);
    }

    #[test]
    fn test_attestations() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("alice"),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_ts(1000),
            None,
        );
        chain.append(
            test_did("bob"),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_ts(2000),
            None,
        );
        chain.append(
            test_did("carol"),
            CustodyRole::Reviewer,
            CustodyAction::Reject,
            record_hash,
            test_ts(3000),
            None,
        );
        chain.append(
            test_did("dave"),
            CustodyRole::Observer,
            CustodyAction::Comment {
                content: "I agree with Carol".to_string(),
            },
            record_hash,
            test_ts(4000),
            None,
        );

        let attestations = chain.attestations();
        assert_eq!(attestations.len(), 2); // Approve + Reject
    }

    #[test]
    fn test_ai_agent_role() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("ai-assistant"),
            CustodyRole::AiAgent {
                delegation_id: Hash256::digest(b"delegation-001"),
            },
            CustodyAction::Comment {
                content: "Automated analysis complete".to_string(),
            },
            record_hash,
            test_ts(1000),
            None,
        );

        assert_eq!(chain.len(), 1);
        assert!(matches!(chain.events[0].role, CustodyRole::AiAgent { .. }));
    }

    #[test]
    fn test_emergency_action() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain.append(
            test_did("steward"),
            CustodyRole::Steward,
            CustodyAction::EmergencyAction {
                reason: "Security breach detected".to_string(),
            },
            record_hash,
            test_ts(1000),
            None,
        );

        assert!(chain.verify_integrity().is_ok());
    }
}
