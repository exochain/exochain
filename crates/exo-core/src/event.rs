//! Ledger event types for the append-only DAG event system.
//!
//! Defines [`EventEnvelope`], [`EventPayload`], and [`LedgerEvent`] along with
//! the canonical [`compute_event_id`] hash function.

use crate::crypto::{hash_bytes, Blake3Hash};
use crate::hlc::HybridLogicalClock;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

/// Determine DID type later (string for now to avoid circular dep with exo-identity).
pub type Did = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Parent event_ids establishing DAG causality.
    pub parents: Vec<Blake3Hash>,

    /// Hybrid Logical Clock for causality ordering.
    pub logical_time: HybridLogicalClock,

    /// DID of the event author.
    pub author: Did,

    /// Key version used for signing.
    pub key_version: u64,

    /// Polymorphic payload.
    pub payload: EventPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventPayload {
    Genesis {
        network_id: String,
    },
    IdentityCreated {
        did_doc_cid: String,
    },
    // --- decision.forum governance events ---
    DecisionCreated {
        decision_id: Blake3Hash,
        title: String,
        decision_class: String,
        constitution_hash: Blake3Hash,
    },
    DecisionAdvanced {
        decision_id: Blake3Hash,
        from_status: String,
        to_status: String,
    },
    VoteCast {
        decision_id: Blake3Hash,
        voter: Did,
        choice: String,
    },
    DelegationGranted {
        delegation_id: Blake3Hash,
        delegator: Did,
        delegatee: Did,
        expires_at: u64,
    },
    DelegationRevoked {
        delegation_id: Blake3Hash,
        revoked_at: u64,
    },
    ConstitutionAmended {
        from_version: String,
        to_version: String,
        amendment_hash: Blake3Hash,
    },
    ChallengeRaised {
        challenge_id: Blake3Hash,
        contested_decision_id: Blake3Hash,
        grounds: String,
    },
    EmergencyActionTaken {
        emergency_id: Blake3Hash,
        decision_id: Blake3Hash,
        ratification_deadline: u64,
    },
    ConflictDisclosed {
        decision_id: Blake3Hash,
        discloser: Did,
    },
    // --- Holon lifecycle events (per EXOCHAIN Specification v2.2 §3A) ---
    HolonCreated {
        holon_did: Did,
        sponsor_did: Did,
        genesis_model_cid: Blake3Hash,
    },
    HolonActivated {
        holon_did: Did,
        approver_did: Did,
        approval_level: u32,
    },
    HolonActionProposed {
        holon_did: Did,
        action_hash: Blake3Hash,
        reasoning_trace_cid: Blake3Hash,
    },
    HolonActionVerified {
        holon_did: Did,
        action_hash: Blake3Hash,
        cgr_proof_hash: Blake3Hash,
    },
    HolonActionExecuted {
        holon_did: Did,
        action_hash: Blake3Hash,
        outcome_hash: Blake3Hash,
    },
    HolonSuspended {
        holon_did: Did,
        reason: String,
        suspended_by: Did,
    },
    HolonReinstated {
        holon_did: Did,
        reinstated_by: Did,
        remediation_evidence_cid: Blake3Hash,
    },
    HolonSunset {
        holon_did: Did,
        reason: String,
        initiated_by: Did,
    },
    // --- CGR Kernel events ---
    CgrProofIssued {
        proof_id: u64,
        invariants_checked: u32,
        registry_hash: Blake3Hash,
    },
    // Generic extension point
    Opaque(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub envelope: EventEnvelope,
    pub event_id: Blake3Hash,
    pub signature: Signature,
}

/// Compute canonical event ID.
pub fn compute_event_id(envelope: &EventEnvelope) -> Result<Blake3Hash, serde_cbor::Error> {
    // Canonical CBOR encoding
    let canonical_bytes = serde_cbor::to_vec(envelope)?;
    Ok(hash_bytes(&canonical_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::compute_signature;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_event_creation() {
        let envelope = EventEnvelope {
            parents: vec![],
            logical_time: HybridLogicalClock {
                physical_ms: 1000,
                logical: 0,
            },
            author: "did:exo:test".to_string(),
            key_version: 1,
            payload: EventPayload::Opaque(vec![1, 2, 3]),
        };

        let event_id = compute_event_id(&envelope).unwrap();

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let sig = compute_signature(&signing_key, &event_id);

        let event = LedgerEvent {
            envelope,
            event_id,
            signature: sig,
        };

        // Assert event_id is not empty
        assert_ne!(event.event_id.0, [0u8; 32]);
    }
}
