//! Event system for EXOCHAIN.
//!
//! Every significant action produces a signed, timestamped event that can
//! be verified independently.  Events carry a CBOR-encoded payload and are
//! attributed to a DID via an Ed25519 signature.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    types::{CorrelationId, Did, PqPublicKey, PublicKey, Signature, Timestamp},
};

// ---------------------------------------------------------------------------
// EventType
// ---------------------------------------------------------------------------

/// Classification of system events.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// A BCTS transaction changed state.
    TransactionStateChanged,
    /// An identity was resolved.
    IdentityResolved,
    /// Consent was granted.
    ConsentGranted,
    /// Consent was revoked.
    ConsentRevoked,
    /// An invariant was checked.
    InvariantChecked,
    /// An invariant was violated.
    InvariantViolated,
    /// A governance decision was made.
    GovernanceDecision,
    /// An escalation was triggered.
    EscalationTriggered,
    /// A sybil detection alert was raised.
    SybilAlert,
    /// A cryptographic key was rotated.
    KeyRotated,
    /// A new entity was registered.
    EntityRegistered,
    /// An audit log entry.
    AuditEntry,
    /// Custom / extension event.
    Custom(String),
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// A signed, timestamped event in the EXOCHAIN system.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unique identifier for this event.
    pub id: CorrelationId,
    /// HLC timestamp of when the event was created.
    pub timestamp: Timestamp,
    /// Classification of the event.
    pub event_type: EventType,
    /// CBOR-encoded payload (opaque bytes).
    pub payload: Vec<u8>,
    /// DID of the entity that produced the event.
    pub source_did: Did,
    /// Ed25519 signature over the canonical event content.
    pub signature: Signature,
}

impl Event {
    /// Construct the canonical bytes that are signed.
    ///
    /// The signed content is: `id || timestamp || event_type || payload || source_did`
    /// serialized as CBOR.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::SerializationError` if CBOR encoding fails.
    pub fn write_signable_bytes<W: Write>(&self, writer: W) -> crate::Result<()> {
        #[derive(Serialize)]
        struct Signable<'a> {
            id: &'a CorrelationId,
            timestamp: &'a Timestamp,
            event_type: &'a EventType,
            payload: &'a [u8],
            source_did: &'a Did,
        }
        let s = Signable {
            id: &self.id,
            timestamp: &self.timestamp,
            event_type: &self.event_type,
            payload: &self.payload,
            source_did: &self.source_did,
        };
        ciborium::into_writer(&s, writer)?;
        Ok(())
    }

    /// Construct the canonical bytes that are signed.
    ///
    /// The signed content is: `id || timestamp || event_type || payload || source_did`
    /// serialized as CBOR.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::SerializationError` if CBOR encoding fails.
    pub fn signable_bytes(&self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write_signable_bytes(&mut buf)?;
        Ok(buf)
    }
}

/// Verify that an event's signature is valid for the given public key.
#[must_use]
pub fn verify_event(event: &Event, public_key: &PublicKey) -> bool {
    let Ok(bytes) = event.signable_bytes() else {
        return false;
    };
    crypto::verify(&bytes, &event.signature, public_key)
}

/// Verify that an event's post-quantum signature is valid for the given ML-DSA public key.
#[must_use]
pub fn verify_event_pq(event: &Event, public_key: &PqPublicKey) -> bool {
    let Ok(bytes) = event.signable_bytes() else {
        return false;
    };
    crypto::verify_pq(&bytes, &event.signature, public_key)
}

/// Verify that an event's hybrid signature is valid for both public keys.
///
/// Both Ed25519 and ML-DSA components must verify. Use [`verify_event`] only
/// for Ed25519-only events.
#[must_use]
pub fn verify_event_hybrid(
    event: &Event,
    classical_public_key: &PublicKey,
    pq_public_key: &PqPublicKey,
) -> bool {
    let Ok(bytes) = event.signable_bytes() else {
        return false;
    };
    crypto::verify_hybrid(
        &bytes,
        &event.signature,
        classical_public_key,
        pq_public_key,
    )
}

/// Helper: create a signed event.
///
/// # Errors
///
/// Returns `ExoError::SerializationError` if canonical event serialization fails.
pub fn create_signed_event(
    id: CorrelationId,
    timestamp: Timestamp,
    event_type: EventType,
    payload: Vec<u8>,
    source_did: Did,
    secret_key: &crate::types::SecretKey,
) -> crate::Result<Event> {
    // Build a temporary event with a dummy signature to compute signable bytes
    let mut event = Event {
        id,
        timestamp,
        event_type,
        payload,
        source_did,
        signature: Signature::from_bytes([0u8; 64]),
    };
    let bytes = event.signable_bytes()?;
    event.signature = crypto::sign(&bytes, secret_key);
    Ok(event)
}

// ---------------------------------------------------------------------------
// Typed Event Payloads — merged from orphan event.rs per council review
// ---------------------------------------------------------------------------

/// Typed event payload variants for structured governance, identity, and
/// Holon lifecycle events.
///
/// These typed variants provide compile-time enforcement of payload structure,
/// complementing the opaque `payload: Vec<u8>` on [`Event`] for cases that
/// require structured payloads with DAG linkage.
///
/// Per EXOCHAIN Specification v2.2 §3A (Holon lifecycle) and decision.forum governance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventPayload {
    /// Genesis event for a new network.
    Genesis { network_id: String },
    /// A new DID document was created.
    IdentityCreated { did_doc_cid: String },
    // --- decision.forum governance events ---
    /// A new decision record was created.
    DecisionCreated {
        decision_id: crate::Hash256,
        title: String,
        decision_class: String,
        constitution_hash: crate::Hash256,
    },
    /// A decision was advanced to a new status.
    DecisionAdvanced {
        decision_id: crate::Hash256,
        from_status: String,
        to_status: String,
    },
    /// A vote was cast on a decision.
    VoteCast {
        decision_id: crate::Hash256,
        voter: Did,
        choice: String,
    },
    /// Delegation authority was granted.
    DelegationGranted {
        delegation_id: crate::Hash256,
        delegator: Did,
        delegatee: Did,
        expires_at: u64,
    },
    /// Delegation authority was revoked.
    DelegationRevoked {
        delegation_id: crate::Hash256,
        revoked_at: u64,
    },
    /// The constitution was amended.
    ConstitutionAmended {
        from_version: String,
        to_version: String,
        amendment_hash: crate::Hash256,
    },
    /// A challenge was raised against a decision.
    ChallengeRaised {
        challenge_id: crate::Hash256,
        contested_decision_id: crate::Hash256,
        grounds: String,
    },
    /// An emergency action was taken.
    EmergencyActionTaken {
        emergency_id: crate::Hash256,
        decision_id: crate::Hash256,
        ratification_deadline: u64,
    },
    /// A conflict of interest was disclosed.
    ConflictDisclosed {
        decision_id: crate::Hash256,
        discloser: Did,
    },
    // --- Holon lifecycle events (per EXOCHAIN Specification v2.2 §3A) ---
    /// A new Holon was created.
    HolonCreated {
        holon_did: Did,
        sponsor_did: Did,
        genesis_model_cid: crate::Hash256,
    },
    /// A Holon was activated.
    HolonActivated {
        holon_did: Did,
        approver_did: Did,
        approval_level: u32,
    },
    /// A Holon action was proposed.
    HolonActionProposed {
        holon_did: Did,
        action_hash: crate::Hash256,
        reasoning_trace_cid: crate::Hash256,
    },
    /// A Holon action was verified.
    HolonActionVerified {
        holon_did: Did,
        action_hash: crate::Hash256,
        cgr_proof_hash: crate::Hash256,
    },
    /// A Holon action was executed.
    HolonActionExecuted {
        holon_did: Did,
        action_hash: crate::Hash256,
        outcome_hash: crate::Hash256,
    },
    /// A Holon was suspended.
    HolonSuspended {
        holon_did: Did,
        reason: String,
        suspended_by: Did,
    },
    /// A Holon was reinstated after suspension.
    HolonReinstated {
        holon_did: Did,
        reinstated_by: Did,
        remediation_evidence_cid: crate::Hash256,
    },
    /// A Holon was permanently retired.
    HolonSunset {
        holon_did: Did,
        reason: String,
        initiated_by: Did,
    },
    // --- CGR Kernel events ---
    /// A Compact Governance Representation proof was issued.
    CgrProofIssued {
        proof_id: u64,
        invariants_checked: u32,
        registry_hash: crate::Hash256,
    },
    /// Opaque payload — extension point for domain-specific events.
    Opaque(Vec<u8>),
}

/// Compute a canonical event identifier by hashing the CBOR-encoded
/// representation with blake3.
///
/// Any serializable event structure can be identified this way, ensuring
/// that identical logical events produce identical IDs regardless of
/// serialization context.
///
/// # Errors
///
/// Returns `ExoError::SerializationError` if CBOR encoding fails.
pub fn compute_event_id<T: serde::Serialize>(envelope: &T) -> crate::Result<crate::Hash256> {
    crate::hash::hash_structured(envelope)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{self, KeyPair, PqKeyPair},
        types::{CorrelationId, Did, Timestamp},
    };

    macro_rules! correlation_id {
        () => {
            CorrelationId::from_uuid(uuid::Uuid::from_u128(u128::from(line!())))
        };
    }

    fn make_event(kp: &KeyPair) -> Event {
        let did = Did::new("did:exo:test-source").expect("valid");
        create_signed_event(
            correlation_id!(),
            Timestamp::new(1000, 0),
            EventType::AuditEntry,
            b"test payload".to_vec(),
            did,
            kp.secret_key(),
        )
        .expect("sign event")
    }

    fn make_unsigned_event(source_did: Did) -> Event {
        Event {
            id: correlation_id!(),
            timestamp: Timestamp::new(1000, 0),
            event_type: EventType::AuditEntry,
            payload: b"test payload".to_vec(),
            source_did,
            signature: Signature::Empty,
        }
    }

    #[test]
    fn create_and_verify_event() {
        let kp = KeyPair::generate();
        let event = make_event(&kp);
        assert!(verify_event(&event, kp.public_key()));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let event = make_event(&kp1);
        assert!(!verify_event(&event, kp2.public_key()));
    }

    #[test]
    fn verify_fails_tampered_payload() {
        let kp = KeyPair::generate();
        let mut event = make_event(&kp);
        event.payload = b"tampered".to_vec();
        assert!(!verify_event(&event, kp.public_key()));
    }

    #[test]
    fn verify_fails_tampered_timestamp() {
        let kp = KeyPair::generate();
        let mut event = make_event(&kp);
        event.timestamp = Timestamp::new(9999, 99);
        assert!(!verify_event(&event, kp.public_key()));
    }

    #[test]
    fn verify_fails_tampered_event_type() {
        let kp = KeyPair::generate();
        let mut event = make_event(&kp);
        event.event_type = EventType::SybilAlert;
        assert!(!verify_event(&event, kp.public_key()));
    }

    #[test]
    fn verify_event_pq_accepts_valid_post_quantum_signature() {
        let pq = PqKeyPair::generate();
        let did = Did::new("did:exo:pq-source").expect("valid");
        let mut event = make_unsigned_event(did);
        let bytes = event.signable_bytes().expect("serialize signable bytes");
        event.signature = pq.sign(&bytes).expect("sign pq event");

        assert!(verify_event_pq(&event, pq.public_key()));
        assert!(
            !verify_event(&event, &PublicKey::from_bytes([7u8; 32])),
            "classical verifier must not accept a PQ event signature"
        );
    }

    #[test]
    fn verify_event_pq_rejects_wrong_key_and_tamper() {
        let pq = PqKeyPair::generate();
        let wrong_pq = PqKeyPair::generate();
        let did = Did::new("did:exo:pq-source").expect("valid");
        let mut event = make_unsigned_event(did);
        let bytes = event.signable_bytes().expect("serialize signable bytes");
        event.signature = pq.sign(&bytes).expect("sign pq event");

        assert!(!verify_event_pq(&event, wrong_pq.public_key()));

        event.payload = b"tampered".to_vec();
        assert!(!verify_event_pq(&event, pq.public_key()));
    }

    #[test]
    fn verify_event_hybrid_accepts_valid_dual_signature() {
        let classical = KeyPair::generate();
        let (pq_public, pq_secret) = crypto::generate_pq_keypair();
        let did = Did::new("did:exo:hybrid-source").expect("valid");
        let mut event = make_unsigned_event(did);
        let bytes = event.signable_bytes().expect("serialize signable bytes");
        event.signature = crypto::sign_hybrid(&bytes, classical.secret_key(), &pq_secret)
            .expect("sign hybrid event");

        assert!(verify_event_hybrid(
            &event,
            classical.public_key(),
            &pq_public
        ));
        assert!(
            !verify_event(&event, classical.public_key()),
            "classical verifier must not accept a hybrid event signature"
        );
    }

    #[test]
    fn verify_event_hybrid_rejects_wrong_keys_and_tamper() {
        let classical = KeyPair::generate();
        let wrong_classical = KeyPair::generate();
        let (pq_public, pq_secret) = crypto::generate_pq_keypair();
        let (wrong_pq_public, _) = crypto::generate_pq_keypair();
        let did = Did::new("did:exo:hybrid-source").expect("valid");
        let mut event = make_unsigned_event(did);
        let bytes = event.signable_bytes().expect("serialize signable bytes");
        event.signature = crypto::sign_hybrid(&bytes, classical.secret_key(), &pq_secret)
            .expect("sign hybrid event");

        assert!(!verify_event_hybrid(
            &event,
            wrong_classical.public_key(),
            &pq_public
        ));
        assert!(!verify_event_hybrid(
            &event,
            classical.public_key(),
            &wrong_pq_public
        ));

        event.event_type = EventType::SybilAlert;
        assert!(!verify_event_hybrid(
            &event,
            classical.public_key(),
            &pq_public
        ));
    }

    #[test]
    fn event_type_serde_roundtrip() {
        let types = vec![
            EventType::TransactionStateChanged,
            EventType::IdentityResolved,
            EventType::ConsentGranted,
            EventType::ConsentRevoked,
            EventType::InvariantChecked,
            EventType::InvariantViolated,
            EventType::GovernanceDecision,
            EventType::EscalationTriggered,
            EventType::SybilAlert,
            EventType::KeyRotated,
            EventType::EntityRegistered,
            EventType::AuditEntry,
            EventType::Custom("my-event".into()),
        ];
        for t in &types {
            let json = serde_json::to_string(t).expect("ser");
            let t2: EventType = serde_json::from_str(&json).expect("de");
            assert_eq!(t, &t2);
        }
    }

    #[test]
    fn event_serde_roundtrip() {
        let kp = KeyPair::generate();
        let event = make_event(&kp);
        let json = serde_json::to_string(&event).expect("ser");
        let event2: Event = serde_json::from_str(&json).expect("de");
        assert_eq!(event, event2);
        // Signature should still verify after deserialization
        assert!(verify_event(&event2, kp.public_key()));
    }

    #[test]
    fn signable_bytes_deterministic() {
        let kp = KeyPair::generate();
        let event = make_event(&kp);
        let b1 = event.signable_bytes().expect("serialize signable bytes");
        let b2 = event.signable_bytes().expect("serialize signable bytes");
        assert_eq!(b1, b2);
    }

    #[test]
    fn signable_bytes_writer_error_is_returned() {
        struct FailingWriter;

        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("intentional signable writer failure"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let kp = KeyPair::generate();
        let event = make_event(&kp);
        let error = event.write_signable_bytes(FailingWriter).unwrap_err();
        assert!(matches!(error, crate::ExoError::SerializationError { .. }));
    }

    #[test]
    fn event_type_ord() {
        let a = EventType::AuditEntry;
        let b = EventType::SybilAlert;
        // Just verify Ord doesn't panic
        let _ = a.cmp(&b);
    }

    #[test]
    fn event_type_hash() {
        use std::hash::{Hash, Hasher};
        let t = EventType::KeyRotated;
        let mut h = std::hash::DefaultHasher::new();
        t.hash(&mut h);
        let _ = h.finish();
    }

    #[test]
    fn event_with_empty_payload() {
        let kp = KeyPair::generate();
        let did = Did::new("did:exo:empty-payload").expect("valid");
        let event = create_signed_event(
            correlation_id!(),
            Timestamp::new(500, 1),
            EventType::Custom("empty".into()),
            Vec::new(),
            did,
            kp.secret_key(),
        )
        .expect("sign event");
        assert!(verify_event(&event, kp.public_key()));
    }

    #[test]
    fn event_with_large_payload() {
        let kp = KeyPair::generate();
        let did = Did::new("did:exo:large-payload").expect("valid");
        let payload = vec![0xab_u8; 10_000];
        let event = create_signed_event(
            correlation_id!(),
            Timestamp::new(500, 1),
            EventType::AuditEntry,
            payload,
            did,
            kp.secret_key(),
        )
        .expect("sign event");
        assert!(verify_event(&event, kp.public_key()));
    }

    #[test]
    fn event_debug_format() {
        let kp = KeyPair::generate();
        let event = make_event(&kp);
        let dbg = format!("{event:?}");
        assert!(dbg.contains("Event"));
    }

    // -----------------------------------------------------------------------
    // EventPayload tests (merged from orphan event.rs)
    // -----------------------------------------------------------------------

    #[test]
    fn event_payload_serde_roundtrip() {
        let payloads = vec![
            EventPayload::Genesis {
                network_id: "exochain-mainnet".into(),
            },
            EventPayload::IdentityCreated {
                did_doc_cid: "bafy...".into(),
            },
            EventPayload::DecisionCreated {
                decision_id: crate::Hash256::digest(b"decision-1"),
                title: "Governance Reform".into(),
                decision_class: "Constitutional".into(),
                constitution_hash: crate::Hash256::digest(b"constitution"),
            },
            EventPayload::VoteCast {
                decision_id: crate::Hash256::digest(b"decision-1"),
                voter: Did::new("did:exo:voter").expect("valid"),
                choice: "approve".into(),
            },
            EventPayload::HolonCreated {
                holon_did: Did::new("did:exo:holon-1").expect("valid"),
                sponsor_did: Did::new("did:exo:sponsor").expect("valid"),
                genesis_model_cid: crate::Hash256::digest(b"model"),
            },
            EventPayload::CgrProofIssued {
                proof_id: 42,
                invariants_checked: 8,
                registry_hash: crate::Hash256::digest(b"registry"),
            },
            EventPayload::Opaque(vec![1, 2, 3]),
        ];
        for payload in &payloads {
            let json = serde_json::to_string(payload).expect("serialize");
            let deserialized: EventPayload = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(payload, &deserialized);
        }
    }

    #[test]
    fn compute_event_id_deterministic() {
        let payload = EventPayload::Genesis {
            network_id: "test-net".into(),
        };
        let id1 = compute_event_id(&payload).expect("compute");
        let id2 = compute_event_id(&payload).expect("compute");
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_event_id_different_payloads() {
        let p1 = EventPayload::Genesis {
            network_id: "net-a".into(),
        };
        let p2 = EventPayload::Genesis {
            network_id: "net-b".into(),
        };
        let id1 = compute_event_id(&p1).expect("compute");
        let id2 = compute_event_id(&p2).expect("compute");
        assert_ne!(id1, id2);
    }

    #[test]
    fn event_payload_all_governance_variants() {
        // Ensure all governance variants can be created and serialized
        let variants: Vec<EventPayload> = vec![
            EventPayload::DecisionAdvanced {
                decision_id: crate::Hash256::ZERO,
                from_status: "Draft".into(),
                to_status: "Submitted".into(),
            },
            EventPayload::DelegationGranted {
                delegation_id: crate::Hash256::ZERO,
                delegator: Did::new("did:exo:alice").expect("valid"),
                delegatee: Did::new("did:exo:bob").expect("valid"),
                expires_at: 1_000_000,
            },
            EventPayload::DelegationRevoked {
                delegation_id: crate::Hash256::ZERO,
                revoked_at: 2_000_000,
            },
            EventPayload::ConstitutionAmended {
                from_version: "1.0.0".into(),
                to_version: "1.1.0".into(),
                amendment_hash: crate::Hash256::ZERO,
            },
            EventPayload::ChallengeRaised {
                challenge_id: crate::Hash256::ZERO,
                contested_decision_id: crate::Hash256::ZERO,
                grounds: "Procedural violation".into(),
            },
            EventPayload::EmergencyActionTaken {
                emergency_id: crate::Hash256::ZERO,
                decision_id: crate::Hash256::ZERO,
                ratification_deadline: 86400,
            },
            EventPayload::ConflictDisclosed {
                decision_id: crate::Hash256::ZERO,
                discloser: Did::new("did:exo:discloser").expect("valid"),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("ser");
            let _: EventPayload = serde_json::from_str(&json).expect("de");
        }
    }

    #[test]
    fn event_payload_all_holon_variants() {
        let holon = Did::new("did:exo:holon").expect("valid");
        let actor = Did::new("did:exo:actor").expect("valid");
        let variants: Vec<EventPayload> = vec![
            EventPayload::HolonActivated {
                holon_did: holon.clone(),
                approver_did: actor.clone(),
                approval_level: 3,
            },
            EventPayload::HolonActionProposed {
                holon_did: holon.clone(),
                action_hash: crate::Hash256::ZERO,
                reasoning_trace_cid: crate::Hash256::ZERO,
            },
            EventPayload::HolonActionVerified {
                holon_did: holon.clone(),
                action_hash: crate::Hash256::ZERO,
                cgr_proof_hash: crate::Hash256::ZERO,
            },
            EventPayload::HolonActionExecuted {
                holon_did: holon.clone(),
                action_hash: crate::Hash256::ZERO,
                outcome_hash: crate::Hash256::ZERO,
            },
            EventPayload::HolonSuspended {
                holon_did: holon.clone(),
                reason: "anomaly detected".into(),
                suspended_by: actor.clone(),
            },
            EventPayload::HolonReinstated {
                holon_did: holon.clone(),
                reinstated_by: actor.clone(),
                remediation_evidence_cid: crate::Hash256::ZERO,
            },
            EventPayload::HolonSunset {
                holon_did: holon,
                reason: "end of lifecycle".into(),
                initiated_by: actor,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("ser");
            let _: EventPayload = serde_json::from_str(&json).expect("de");
        }
    }
}
