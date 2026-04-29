//! CustodyEvent — chain of responsibility tracking for decision.forum
//!
//! Per the decision.forum whitepaper: "who did what, when, optionally signed."
//! CustodyEvents form an append-only log of all actions taken on a DecisionRecord,
//! creating a complete chain of responsibility.
//!
//! Satisfies: GOV-005 (authority chain), TNC-03 (audit continuity), LEG-001 (business records)

use exo_core::{Did, Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::types::GovernanceSignature;

const CUSTODY_EVENT_HASH_DOMAIN: &str = "exo.governance.custody_event.v1";
const CUSTODY_EVENT_HASH_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize)]
struct CustodyEventHashPayload {
    domain: &'static str,
    schema_version: u16,
    sequence: u64,
    record_hash: Hash256,
    prev_event_hash: Option<Hash256>,
    actor_id: Did,
    action: CustodyAction,
    timestamp: Timestamp,
}

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
    ) -> Result<&CustodyEvent, CustodyChainError> {
        let prev_event_hash = self.events.last().map(|e| e.event_hash);
        let sequence = self.next_sequence;

        // Compute event hash over canonical fields.
        let event_hash = Self::compute_event_hash(
            sequence,
            &record_hash,
            prev_event_hash.as_ref(),
            &actor_id,
            &action,
            &timestamp,
        )?;

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
        Ok(&self.events[self.events.len() - 1])
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
            )?;
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
    fn compute_event_hash(
        sequence: u64,
        record_hash: &Hash256,
        prev_event_hash: Option<&Hash256>,
        actor_id: &Did,
        action: &CustodyAction,
        timestamp: &Timestamp,
    ) -> Result<Hash256, CustodyChainError> {
        hash_structured(&custody_event_hash_payload(
            sequence,
            record_hash,
            prev_event_hash,
            actor_id,
            action,
            timestamp,
        ))
        .map_err(|e| CustodyChainError::HashEncodingFailed {
            reason: format!("custody event canonical CBOR hash failed: {e}"),
        })
    }
}

fn custody_event_hash_payload(
    sequence: u64,
    record_hash: &Hash256,
    prev_event_hash: Option<&Hash256>,
    actor_id: &Did,
    action: &CustodyAction,
    timestamp: &Timestamp,
) -> CustodyEventHashPayload {
    CustodyEventHashPayload {
        domain: CUSTODY_EVENT_HASH_DOMAIN,
        schema_version: CUSTODY_EVENT_HASH_SCHEMA_VERSION,
        sequence,
        record_hash: *record_hash,
        prev_event_hash: prev_event_hash.copied(),
        actor_id: actor_id.clone(),
        action: action.clone(),
        timestamp: *timestamp,
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
    /// Canonical CBOR event hash encoding failed.
    HashEncodingFailed { reason: String },
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
            Self::HashEncodingFailed { reason } => {
                write!(f, "Custody event hash encoding failed: {reason}")
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

    fn production_source() -> &'static str {
        let source = include_str!("custody.rs");
        let end = source
            .find("#[cfg(test)]")
            .expect("tests marker must exist");
        &source[..end]
    }

    #[test]
    fn custody_event_hash_payload_is_domain_separated_cbor() {
        let record_hash = Hash256::digest(b"record-v1");
        let prev_event_hash = Some(Hash256::digest(b"prev-event"));
        let actor = test_did("alice");
        let action = CustodyAction::AdvanceStatus {
            from: "draft".into(),
            to: "review".into(),
        };
        let timestamp = test_ts(1000);

        let payload = custody_event_hash_payload(
            7,
            &record_hash,
            prev_event_hash.as_ref(),
            &actor,
            &action,
            &timestamp,
        );

        assert_eq!(payload.domain, CUSTODY_EVENT_HASH_DOMAIN);
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.sequence, 7);
        assert_eq!(payload.record_hash, record_hash);
        assert_eq!(payload.prev_event_hash, prev_event_hash);
        assert_eq!(payload.actor_id, actor);
        assert_eq!(payload.action, action);
        assert_eq!(payload.timestamp, timestamp);
    }

    #[test]
    fn custody_event_hash_rejects_legacy_raw_concat_hash() {
        let record_hash = Hash256::digest(b"record-v1");
        let prev_event_hash = Some(Hash256::digest(b"prev-event"));
        let actor = test_did("alice");
        let action = CustodyAction::Approve;
        let timestamp = test_ts(1000);

        let mut hasher = blake3::Hasher::new();
        hasher.update(&7u64.to_le_bytes());
        hasher.update(record_hash.as_bytes());
        hasher.update(prev_event_hash.as_ref().expect("prev").as_bytes());
        hasher.update(actor.as_str().as_bytes());
        let action_hash = exo_core::hash::hash_structured(&action).expect("action hash");
        hasher.update(action_hash.as_bytes());
        hasher.update(&timestamp.physical_ms.to_le_bytes());
        hasher.update(&timestamp.logical.to_le_bytes());
        let legacy = Hash256::from_bytes(*hasher.finalize().as_bytes());

        let canonical = CustodyChain::compute_event_hash(
            7,
            &record_hash,
            prev_event_hash.as_ref(),
            &actor,
            &action,
            &timestamp,
        )
        .expect("canonical custody hash");

        assert_ne!(canonical, legacy);
    }

    #[test]
    fn custody_production_source_has_no_raw_hash_loop_or_zero_fallback() {
        let production = production_source();
        assert!(
            !production.contains("blake3::Hasher"),
            "custody event hashes must use domain-separated canonical CBOR"
        );
        assert!(
            !production.contains("unwrap_or(Hash256::ZERO)"),
            "custody event hashing must fail closed instead of using a zero hash"
        );
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

        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.events[0].sequence, 0);
        assert!(chain.events[0].prev_event_hash.is_none());

        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");

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

        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("carol"),
                CustodyRole::Steward,
                CustodyAction::IssueClearance {
                    certificate_id: "cert-1".to_string(),
                },
                record_hash,
                test_ts(3000),
                None,
            )
            .expect("append custody event");

        assert!(chain.verify_integrity().is_ok());
    }

    #[test]
    fn test_tampered_chain_detected() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");

        // Tamper with the first event's hash
        chain.events[0].event_hash = Hash256::digest(b"tampered");
        assert!(chain.verify_integrity().is_err());
    }

    #[test]
    fn test_events_by_actor() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Comment {
                    content: "Updated rationale".to_string(),
                },
                record_hash,
                test_ts(3000),
                None,
            )
            .expect("append custody event");

        let alice_events = chain.events_by_actor("did:exo:alice");
        assert_eq!(alice_events.len(), 2);
    }

    #[test]
    fn test_attestations() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("carol"),
                CustodyRole::Reviewer,
                CustodyAction::Reject,
                record_hash,
                test_ts(3000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("dave"),
                CustodyRole::Observer,
                CustodyAction::Comment {
                    content: "I agree with Carol".to_string(),
                },
                record_hash,
                test_ts(4000),
                None,
            )
            .expect("append custody event");

        let attestations = chain.attestations();
        assert_eq!(attestations.len(), 2); // Approve + Reject
    }

    #[test]
    fn test_ai_agent_role() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain
            .append(
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
            )
            .expect("append custody event");

        assert_eq!(chain.len(), 1);
        assert!(matches!(chain.events[0].role, CustodyRole::AiAgent { .. }));
    }

    #[test]
    fn test_emergency_action() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-1"));
        let record_hash = Hash256::digest(b"record-v1");

        chain
            .append(
                test_did("steward"),
                CustodyRole::Steward,
                CustodyAction::EmergencyAction {
                    reason: "Security breach detected".to_string(),
                },
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");

        assert!(chain.verify_integrity().is_ok());
    }

    fn test_signature() -> GovernanceSignature {
        use exo_core::Signature;

        use crate::types::SignerType;
        GovernanceSignature {
            signer: test_did("signer"),
            signer_type: SignerType::Human,
            signature: Signature::from_bytes([7u8; 64]),
            key_version: 1,
            timestamp: test_ts(1000),
        }
    }

    // Covers: latest() returning Some(&event) and is_empty() returning false after append.
    #[test]
    fn test_latest_and_is_empty_after_append() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-latest"));
        let record_hash = Hash256::digest(b"record-v1");
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        assert!(!chain.is_empty());
        let latest = chain.latest().expect("non-empty");
        assert_eq!(latest.sequence, 0);
        assert_eq!(latest.actor_id, test_did("alice"));
    }

    // Covers: Some(GovernanceSignature) path on append storing the signature on the event.
    #[test]
    fn test_append_with_signature() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-sig"));
        let record_hash = Hash256::digest(b"record-v1");
        let sig = test_signature();
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                Some(sig.clone()),
            )
            .expect("append custody event");
        let stored = chain.events[0]
            .signature
            .as_ref()
            .expect("signature present");
        assert_eq!(stored.signer, sig.signer);
        assert_eq!(stored.key_version, sig.key_version);
    }

    // Covers: returned reference from append points to the last-appended event.
    #[test]
    fn test_append_returns_last_event_reference() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-ret"));
        let record_hash = Hash256::digest(b"record-v1");
        let ev = chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        assert_eq!(ev.sequence, 0);
        assert!(ev.prev_event_hash.is_none());
        let id = ev.id.clone();
        assert_eq!(chain.events[0].id, id);
    }

    // Covers: verify_integrity InvalidGenesisLink branch (genesis has prev_event_hash = Some).
    #[test]
    fn test_verify_integrity_invalid_genesis_link() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-ig"));
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                Hash256::digest(b"r"),
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain.events[0].prev_event_hash = Some(Hash256::digest(b"unexpected"));
        let err = chain.verify_integrity().expect_err("must be error");
        assert!(matches!(err, CustodyChainError::InvalidGenesisLink));
    }

    // Covers: verify_integrity BrokenLink branch (non-genesis prev_event_hash mismatches predecessor).
    #[test]
    fn test_verify_integrity_broken_link() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-bl"));
        let record_hash = Hash256::digest(b"r");
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        let bogus = Hash256::digest(b"bogus-prev");
        chain.events[1].prev_event_hash = Some(bogus);
        let err = chain.verify_integrity().expect_err("must be error");
        match err {
            CustodyChainError::BrokenLink {
                sequence, actual, ..
            } => {
                assert_eq!(sequence, 1);
                assert_eq!(actual, bogus);
            }
            other => panic!("expected BrokenLink, got {other:?}"),
        }
    }

    // Covers: verify_integrity MissingLink branch (non-genesis prev_event_hash = None).
    #[test]
    fn test_verify_integrity_missing_link() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-ml"));
        let record_hash = Hash256::digest(b"r");
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                record_hash,
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        chain.events[1].prev_event_hash = None;
        let err = chain.verify_integrity().expect_err("must be error");
        assert!(matches!(
            err,
            CustodyChainError::MissingLink { sequence: 1 }
        ));
    }

    // Covers: verify_integrity SequenceGap branch (event sequence number does not match index).
    #[test]
    fn test_verify_integrity_sequence_gap() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-sg"));
        let record_hash = Hash256::digest(b"r");
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain.events[0].sequence = 99;
        let err = chain.verify_integrity().expect_err("must be error");
        match err {
            CustodyChainError::SequenceGap { expected, actual } => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 99);
            }
            other => panic!("expected SequenceGap, got {other:?}"),
        }
    }

    // Covers: verify_integrity HashMismatch branch asserting the exact variant (not just is_err).
    #[test]
    fn test_verify_integrity_hash_mismatch_variant() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-hm"));
        let record_hash = Hash256::digest(b"r");
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                record_hash,
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        let tampered = Hash256::digest(b"tampered");
        chain.events[0].event_hash = tampered;
        let err = chain.verify_integrity().expect_err("must be error");
        match err {
            CustodyChainError::HashMismatch {
                sequence, actual, ..
            } => {
                assert_eq!(sequence, 0);
                assert_eq!(actual, tampered);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    // Covers: Display impls for every CustodyChainError variant.
    #[test]
    fn test_error_display_all_variants() {
        let h = Hash256::digest(b"x");
        let seq_gap = CustodyChainError::SequenceGap {
            expected: 3,
            actual: 7,
        };
        assert_eq!(format!("{seq_gap}"), "Sequence gap: expected 3, got 7");

        let genesis = CustodyChainError::InvalidGenesisLink;
        assert_eq!(
            format!("{genesis}"),
            "Genesis event should not have prev_event_hash"
        );

        let broken = CustodyChainError::BrokenLink {
            sequence: 4,
            expected: h,
            actual: h,
        };
        assert_eq!(format!("{broken}"), "Broken chain link at sequence 4");

        let missing = CustodyChainError::MissingLink { sequence: 5 };
        assert_eq!(
            format!("{missing}"),
            "Missing prev_event_hash at sequence 5"
        );

        let mismatch = CustodyChainError::HashMismatch {
            sequence: 6,
            expected: h,
            actual: h,
        };
        assert_eq!(format!("{mismatch}"), "Event hash mismatch at sequence 6");
    }

    // Covers: CustodyChainError implements std::error::Error (trait-object usability).
    #[test]
    fn test_error_trait_object() {
        let err: Box<dyn std::error::Error> =
            Box::new(CustodyChainError::MissingLink { sequence: 2 });
        assert!(err.to_string().contains("sequence 2"));
    }

    // Covers: CustodyEvent id uses first byte of decision_id and the sequence number.
    #[test]
    fn test_event_id_format() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x2a;
        let decision_id = Hash256::from_bytes(bytes);
        let mut chain = CustodyChain::new(decision_id);
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                Hash256::digest(b"r"),
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                Hash256::digest(b"r"),
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        assert_eq!(chain.events[0].id, "ce-42-0");
        assert_eq!(chain.events[1].id, "ce-42-1");
    }

    // Covers: next_sequence monotonically increases across appends.
    #[test]
    fn test_next_sequence_monotonic() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-mono"));
        assert_eq!(chain.next_sequence, 0);
        for i in 0..3 {
            chain
                .append(
                    test_did("alice"),
                    CustodyRole::Proposer,
                    CustodyAction::Create,
                    Hash256::digest(b"r"),
                    test_ts(1000 + i),
                    None,
                )
                .expect("append custody event");
        }
        assert_eq!(chain.next_sequence, 3);
        assert_eq!(chain.len(), 3);
    }

    // Covers: events_by_actor filters and returns only matching actor's events (no false positives).
    #[test]
    fn test_events_by_actor_nonmatching_filtered_out() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-filter"));
        chain
            .append(
                test_did("alice"),
                CustodyRole::Proposer,
                CustodyAction::Create,
                Hash256::digest(b"r"),
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        chain
            .append(
                test_did("bob"),
                CustodyRole::Reviewer,
                CustodyAction::Approve,
                Hash256::digest(b"r"),
                test_ts(2000),
                None,
            )
            .expect("append custody event");
        assert!(chain.events_by_actor("did:exo:charlie").is_empty());
        let bobs = chain.events_by_actor("did:exo:bob");
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0].actor_id, test_did("bob"));
    }

    // Covers: attestations() includes Veto and Abstain (all four attestation variants).
    #[test]
    fn test_attestations_include_veto_and_abstain() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-att"));
        let r = Hash256::digest(b"r");
        for (i, action) in [
            CustodyAction::Approve,
            CustodyAction::Reject,
            CustodyAction::Abstain,
            CustodyAction::Veto,
            CustodyAction::Comment {
                content: "noise".to_string(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            chain
                .append(
                    test_did("alice"),
                    CustodyRole::Reviewer,
                    action,
                    r,
                    test_ts(1000 + u64::try_from(i).expect("small")),
                    None,
                )
                .expect("append custody event");
        }
        let atts = chain.attestations();
        assert_eq!(atts.len(), 4);
        assert!(atts.iter().any(|e| matches!(e.action, CustodyAction::Veto)));
        assert!(
            atts.iter()
                .any(|e| matches!(e.action, CustodyAction::Abstain))
        );
    }

    // Covers: verify_integrity succeeds on an empty chain (no events to validate).
    #[test]
    fn test_verify_integrity_empty_chain() {
        let chain = CustodyChain::new(Hash256::digest(b"decision-empty"));
        assert!(chain.verify_integrity().is_ok());
    }

    // Covers: CustodyChainError implements Clone + Debug (derived trait usage).
    #[test]
    fn test_error_clone_debug() {
        let err = CustodyChainError::SequenceGap {
            expected: 1,
            actual: 2,
        };
        let cloned = err.clone();
        assert!(matches!(
            cloned,
            CustodyChainError::SequenceGap {
                expected: 1,
                actual: 2
            }
        ));
        assert!(format!("{err:?}").contains("SequenceGap"));
    }

    // Covers: serde round-trip for CustodyChain (Serialize + Deserialize derives on all enums/structs).
    #[test]
    fn test_custody_chain_serde_roundtrip() {
        let mut chain = CustodyChain::new(Hash256::digest(b"decision-serde"));
        chain
            .append(
                test_did("alice"),
                CustodyRole::AiAgent {
                    delegation_id: Hash256::digest(b"d"),
                },
                CustodyAction::Custom {
                    action: "sign-off".to_string(),
                    metadata: Some("ok".to_string()),
                },
                Hash256::digest(b"r"),
                test_ts(1000),
                None,
            )
            .expect("append custody event");
        let json = serde_json::to_string(&chain).expect("serialize");
        let decoded: CustodyChain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.events.len(), 1);
        assert!(decoded.verify_integrity().is_ok());
    }
}
