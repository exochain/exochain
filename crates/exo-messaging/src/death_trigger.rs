//! Death trigger — afterlife message release state machine.
//!
//! Manages the lifecycle of death verification claims and the
//! conditional release of afterlife messages.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, PublicKey, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::MessagingError;

const DEATH_CONFIRMATION_SIGNING_DOMAIN: &str = "exo.messaging.death-trigger.confirmation.v1";

/// Status of a death verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeathVerificationStatus {
    /// Claim initiated, awaiting trustee confirmations.
    Pending,
    /// Sufficient trustees confirmed — death verified.
    Verified,
    /// Claim rejected or expired.
    Rejected,
}

/// A single trustee confirmation of a death claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeConfirmation {
    pub trustee_did: Did,
    pub public_key: PublicKey,
    pub signature: Signature,
    pub confirmed_at: Timestamp,
}

/// Caller-supplied metadata for initiating a death verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeathVerificationCreationMetadata {
    pub created_at: Timestamp,
}

impl DeathVerificationCreationMetadata {
    /// Validate caller-supplied creation metadata.
    pub fn new(created_at: Timestamp) -> Result<Self, MessagingError> {
        if created_at == Timestamp::ZERO {
            return Err(MessagingError::InvalidDeathVerification(
                "created_at must be caller-supplied and non-zero".to_owned(),
            ));
        }
        Ok(Self { created_at })
    }
}

/// Caller-supplied metadata for a trustee confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeathConfirmationMetadata {
    pub confirmed_at: Timestamp,
}

impl DeathConfirmationMetadata {
    /// Validate caller-supplied confirmation metadata.
    pub fn new(confirmed_at: Timestamp) -> Result<Self, MessagingError> {
        if confirmed_at == Timestamp::ZERO {
            return Err(MessagingError::InvalidDeathVerification(
                "confirmed_at must be caller-supplied and non-zero".to_owned(),
            ));
        }
        Ok(Self { confirmed_at })
    }
}

/// Caller-supplied metadata for rejecting a death verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeathRejectionMetadata {
    pub rejected_at: Timestamp,
}

impl DeathRejectionMetadata {
    /// Validate caller-supplied rejection metadata.
    pub fn new(rejected_at: Timestamp) -> Result<Self, MessagingError> {
        if rejected_at == Timestamp::ZERO {
            return Err(MessagingError::InvalidDeathVerification(
                "rejected_at must be caller-supplied and non-zero".to_owned(),
            ));
        }
        Ok(Self { rejected_at })
    }
}

/// A death verification request tracking trustee consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeathVerification {
    /// The DID of the person whose death is being claimed.
    pub subject_did: Did,
    /// The trustee who initiated the death claim.
    pub initiated_by: Did,
    /// Number of trustee confirmations required (default: 3 for 3-of-4 PACE).
    pub required_confirmations: u8,
    /// Authorized trustee public keys, sorted by DID for deterministic signing payloads.
    pub authorized_trustees: BTreeMap<Did, PublicKey>,
    /// Caller-supplied claim nonce binding signatures to this verification instance.
    pub claim_nonce: Vec<u8>,
    /// Collected trustee confirmations.
    pub confirmations: Vec<TrusteeConfirmation>,
    /// Current verification status.
    pub status: DeathVerificationStatus,
    /// When the claim was initiated.
    pub created: Timestamp,
    /// When the claim was resolved (verified or rejected).
    pub resolved_at: Option<Timestamp>,
}

#[derive(Serialize)]
struct AuthorizedTrusteeSigningEntry<'a> {
    did: &'a str,
    public_key: &'a [u8; 32],
}

#[derive(Serialize)]
struct ConfirmationSigningPayload<'a> {
    domain: &'static str,
    subject_did: &'a str,
    initiated_by: &'a str,
    required_confirmations: u8,
    claim_nonce: &'a [u8],
    trustee_did: &'a str,
    authorized_trustees: Vec<AuthorizedTrusteeSigningEntry<'a>>,
}

/// Canonical CBOR payload signed for the initiator's first confirmation.
///
/// The payload binds the subject, initiator, threshold, authorized trustee set,
/// caller-supplied claim nonce, and confirming trustee DID. The signature itself
/// and HLC timestamps are excluded so callers can sign before the state exists.
pub fn initial_confirmation_signing_payload(
    subject_did: &Did,
    initiated_by: &Did,
    required_confirmations: u8,
    authorized_trustees: &BTreeMap<Did, PublicKey>,
    claim_nonce: &[u8],
) -> Result<Vec<u8>, MessagingError> {
    confirmation_signing_payload_for(
        subject_did,
        initiated_by,
        required_confirmations,
        authorized_trustees,
        claim_nonce,
        initiated_by,
    )
}

fn confirmation_signing_payload_for(
    subject_did: &Did,
    initiated_by: &Did,
    required_confirmations: u8,
    authorized_trustees: &BTreeMap<Did, PublicKey>,
    claim_nonce: &[u8],
    trustee_did: &Did,
) -> Result<Vec<u8>, MessagingError> {
    let trustee_entries = authorized_trustees
        .iter()
        .map(|(did, public_key)| AuthorizedTrusteeSigningEntry {
            did: did.as_str(),
            public_key: public_key.as_bytes(),
        })
        .collect();
    let payload = ConfirmationSigningPayload {
        domain: DEATH_CONFIRMATION_SIGNING_DOMAIN,
        subject_did: subject_did.as_str(),
        initiated_by: initiated_by.as_str(),
        required_confirmations,
        claim_nonce,
        trustee_did: trustee_did.as_str(),
        authorized_trustees: trustee_entries,
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded)
        .map_err(|e| MessagingError::DeathConfirmationPayloadEncoding(e.to_string()))?;
    Ok(encoded)
}

impl DeathVerification {
    /// Create a new death verification request.
    pub fn new(
        subject_did: Did,
        initiated_by: Did,
        required_confirmations: u8,
        authorized_trustees: BTreeMap<Did, PublicKey>,
        claim_nonce: Vec<u8>,
        initiator_signature: Signature,
        metadata: DeathVerificationCreationMetadata,
    ) -> Result<Self, MessagingError> {
        validate_death_verification_request(
            &initiated_by,
            required_confirmations,
            &authorized_trustees,
            &claim_nonce,
        )?;
        let initiator_public_key = *authorized_trustees
            .get(&initiated_by)
            .ok_or_else(|| MessagingError::UnauthorizedTrustee(initiated_by.as_str().to_owned()))?;
        let signing_payload = initial_confirmation_signing_payload(
            &subject_did,
            &initiated_by,
            required_confirmations,
            &authorized_trustees,
            &claim_nonce,
        )?;
        if !exo_core::crypto::verify(
            &signing_payload,
            &initiator_signature,
            &initiator_public_key,
        ) {
            return Err(MessagingError::SignatureVerificationFailed);
        }

        let now = metadata.created_at;
        let status = if required_confirmations == 1 {
            DeathVerificationStatus::Verified
        } else {
            DeathVerificationStatus::Pending
        };
        let resolved_at = if status == DeathVerificationStatus::Verified {
            Some(now)
        } else {
            None
        };

        Ok(Self {
            subject_did,
            initiated_by: initiated_by.clone(),
            required_confirmations,
            authorized_trustees,
            claim_nonce,
            confirmations: vec![TrusteeConfirmation {
                trustee_did: initiated_by,
                public_key: initiator_public_key,
                signature: initiator_signature,
                confirmed_at: now,
            }],
            status,
            created: now,
            resolved_at,
        })
    }

    /// Canonical CBOR payload a trustee signs to confirm this death claim.
    pub fn confirmation_signing_payload(
        &self,
        trustee_did: &Did,
    ) -> Result<Vec<u8>, MessagingError> {
        confirmation_signing_payload_for(
            &self.subject_did,
            &self.initiated_by,
            self.required_confirmations,
            &self.authorized_trustees,
            &self.claim_nonce,
            trustee_did,
        )
    }

    /// Add a trustee confirmation. Returns `true` if the threshold is now met.
    pub fn confirm(
        &mut self,
        trustee_did: Did,
        trustee_public_key: PublicKey,
        signature: Signature,
        metadata: DeathConfirmationMetadata,
    ) -> Result<bool, MessagingError> {
        if self.status != DeathVerificationStatus::Pending {
            return Err(MessagingError::DeathTriggerAlreadyResolved);
        }
        let expected_public_key = *self
            .authorized_trustees
            .get(&trustee_did)
            .ok_or_else(|| MessagingError::UnauthorizedTrustee(trustee_did.as_str().to_owned()))?;

        // Check for duplicate
        let existing: BTreeSet<String> = self
            .confirmations
            .iter()
            .map(|c| c.trustee_did.as_str().to_owned())
            .collect();
        if existing.contains(trustee_did.as_str()) {
            return Err(MessagingError::DuplicateConfirmation(
                trustee_did.as_str().to_owned(),
            ));
        }
        if expected_public_key != trustee_public_key {
            return Err(MessagingError::SignatureVerificationFailed);
        }
        let signing_payload = self.confirmation_signing_payload(&trustee_did)?;
        if !exo_core::crypto::verify(&signing_payload, &signature, &expected_public_key) {
            return Err(MessagingError::SignatureVerificationFailed);
        }

        let now = metadata.confirmed_at;

        self.confirmations.push(TrusteeConfirmation {
            trustee_did,
            public_key: expected_public_key,
            signature,
            confirmed_at: now,
        });

        // Check if threshold is met. `required_confirmations` is a
        // u8 (max 255); widening to usize is lossless.
        if self.confirmations.len() >= usize::from(self.required_confirmations) {
            self.status = DeathVerificationStatus::Verified;
            self.resolved_at = Some(now);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Reject the death claim.
    pub fn reject(&mut self, metadata: DeathRejectionMetadata) -> Result<(), MessagingError> {
        if self.status != DeathVerificationStatus::Pending {
            return Err(MessagingError::DeathTriggerAlreadyResolved);
        }
        self.status = DeathVerificationStatus::Rejected;
        self.resolved_at = Some(metadata.rejected_at);
        Ok(())
    }

    /// Check if the verification is complete and afterlife messages should be released.
    #[must_use]
    pub fn should_release(&self) -> bool {
        self.status == DeathVerificationStatus::Verified
    }

    /// Number of confirmations still needed.
    #[must_use]
    pub fn confirmations_remaining(&self) -> u8 {
        // Confirmations count is bounded by required_confirmations
        // (a u8) in the normal path; saturating at u8::MAX is the
        // correct behavior if somehow it grows past 255.
        let current = u8::try_from(self.confirmations.len()).unwrap_or(u8::MAX);
        self.required_confirmations.saturating_sub(current)
    }
}

fn validate_death_verification_request(
    initiated_by: &Did,
    required_confirmations: u8,
    authorized_trustees: &BTreeMap<Did, PublicKey>,
    claim_nonce: &[u8],
) -> Result<(), MessagingError> {
    if required_confirmations == 0 {
        return Err(MessagingError::InvalidDeathVerification(
            "required_confirmations must be at least 1".to_owned(),
        ));
    }
    if authorized_trustees.is_empty() {
        return Err(MessagingError::InvalidDeathVerification(
            "authorized_trustees must not be empty".to_owned(),
        ));
    }
    if usize::from(required_confirmations) > authorized_trustees.len() {
        return Err(MessagingError::InsufficientConfirmations {
            need: required_confirmations,
            got: u8::try_from(authorized_trustees.len()).unwrap_or(u8::MAX),
        });
    }
    if claim_nonce.is_empty() {
        return Err(MessagingError::InvalidDeathVerification(
            "claim_nonce must not be empty".to_owned(),
        ));
    }
    if !authorized_trustees.contains_key(initiated_by) {
        return Err(MessagingError::UnauthorizedTrustee(
            initiated_by.as_str().to_owned(),
        ));
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::{
        PublicKey, Signature,
        crypto::{KeyPair, sign},
    };

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).unwrap()
    }

    fn keypair(seed: u8) -> KeyPair {
        KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }

    fn timestamp(physical_ms: u64) -> Timestamp {
        Timestamp::new(physical_ms, 0)
    }

    fn creation_metadata(physical_ms: u64) -> DeathVerificationCreationMetadata {
        DeathVerificationCreationMetadata::new(timestamp(physical_ms)).unwrap()
    }

    fn confirmation_metadata(physical_ms: u64) -> DeathConfirmationMetadata {
        DeathConfirmationMetadata::new(timestamp(physical_ms)).unwrap()
    }

    fn rejection_metadata(physical_ms: u64) -> DeathRejectionMetadata {
        DeathRejectionMetadata::new(timestamp(physical_ms)).unwrap()
    }

    fn authorized_trustees(entries: &[(&Did, &KeyPair)]) -> BTreeMap<Did, PublicKey> {
        entries
            .iter()
            .map(|(trustee_did, keypair)| ((*trustee_did).clone(), *keypair.public_key()))
            .collect()
    }

    fn initial_signature(
        subject: &Did,
        initiated_by: &Did,
        required_confirmations: u8,
        authorized_trustees: &BTreeMap<Did, PublicKey>,
        claim_nonce: &[u8],
        keypair: &KeyPair,
    ) -> Signature {
        let payload = initial_confirmation_signing_payload(
            subject,
            initiated_by,
            required_confirmations,
            authorized_trustees,
            claim_nonce,
        )
        .unwrap();
        sign(&payload, keypair.secret_key())
    }

    fn signed_verification(
        subject: &Did,
        initiated_by: &Did,
        required_confirmations: u8,
        authorized_trustees: BTreeMap<Did, PublicKey>,
        claim_nonce: Vec<u8>,
        keypair: &KeyPair,
    ) -> DeathVerification {
        let signature = initial_signature(
            subject,
            initiated_by,
            required_confirmations,
            &authorized_trustees,
            &claim_nonce,
            keypair,
        );
        DeathVerification::new(
            subject.clone(),
            initiated_by.clone(),
            required_confirmations,
            authorized_trustees,
            claim_nonce,
            signature,
            creation_metadata(1_000),
        )
        .unwrap()
    }

    fn confirmation_signature(
        verification: &DeathVerification,
        trustee_did: &Did,
        keypair: &KeyPair,
    ) -> Signature {
        let payload = verification
            .confirmation_signing_payload(trustee_did)
            .unwrap();
        sign(&payload, keypair.secret_key())
    }

    #[test]
    fn initiator_confirmation_requires_valid_signature() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let nonce = b"r6-claim-1".to_vec();

        let result = DeathVerification::new(
            subject.clone(),
            bob.clone(),
            2,
            authorized.clone(),
            nonce.clone(),
            Signature::Empty,
            creation_metadata(1_001),
        );
        assert!(matches!(
            result,
            Err(MessagingError::SignatureVerificationFailed)
        ));

        let signature = initial_signature(&subject, &bob, 2, &authorized, &nonce, &bob_key);
        let dv = DeathVerification::new(
            subject,
            bob.clone(),
            2,
            authorized,
            nonce,
            signature,
            creation_metadata(1_002),
        )
        .unwrap();
        assert_eq!(dv.confirmations.len(), 1);
        assert_eq!(dv.confirmations[0].trustee_did, did("bob"));
        assert_eq!(dv.confirmations[0].public_key, *bob_key.public_key());
        assert_eq!(dv.status, DeathVerificationStatus::Pending);
        assert_eq!(dv.confirmations_remaining(), 1);
    }

    #[test]
    fn unknown_trustee_confirmation_rejected() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let mallory = did("mallory");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let mallory_key = keypair(9);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-2".to_vec(),
            &bob_key,
        );

        let result = dv.confirm(
            mallory.clone(),
            *mallory_key.public_key(),
            Signature::Empty,
            confirmation_metadata(2_000),
        );
        assert!(matches!(
            result,
            Err(MessagingError::UnauthorizedTrustee(trustee)) if trustee == mallory.as_str()
        ));
    }

    #[test]
    fn wrong_key_confirmation_rejected() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let wrong_key = keypair(9);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-3".to_vec(),
            &bob_key,
        );
        let signature = confirmation_signature(&dv, &carol, &wrong_key);

        let result = dv.confirm(
            carol,
            *wrong_key.public_key(),
            signature,
            confirmation_metadata(2_001),
        );
        assert!(matches!(
            result,
            Err(MessagingError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn replayed_confirmation_for_different_claim_nonce_rejected() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let dv_a = signed_verification(
            &subject,
            &bob,
            2,
            authorized.clone(),
            b"r6-claim-a".to_vec(),
            &bob_key,
        );
        let mut dv_b = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-b".to_vec(),
            &bob_key,
        );
        let replayed_signature = confirmation_signature(&dv_a, &carol, &carol_key);

        let result = dv_b.confirm(
            carol,
            *carol_key.public_key(),
            replayed_signature,
            confirmation_metadata(2_002),
        );
        assert!(matches!(
            result,
            Err(MessagingError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn tampered_verification_state_rejects_previous_signature() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-4".to_vec(),
            &bob_key,
        );
        let signature = confirmation_signature(&dv, &carol, &carol_key);
        dv.subject_did = did("mallory");

        let result = dv.confirm(
            carol,
            *carol_key.public_key(),
            signature,
            confirmation_metadata(2_003),
        );
        assert!(matches!(
            result,
            Err(MessagingError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn threshold_met_triggers_verified() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let dave = did("dave");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let dave_key = keypair(3);
        let authorized =
            authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key), (&dave, &dave_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            3,
            authorized,
            b"r6-claim-5".to_vec(),
            &bob_key,
        );

        let carol_signature = confirmation_signature(&dv, &carol, &carol_key);
        let met = dv
            .confirm(
                carol.clone(),
                *carol_key.public_key(),
                carol_signature,
                confirmation_metadata(2_004),
            )
            .unwrap();
        assert!(!met);
        assert_eq!(dv.confirmations_remaining(), 1);

        let dave_signature = confirmation_signature(&dv, &dave, &dave_key);
        let met = dv
            .confirm(
                dave,
                *dave_key.public_key(),
                dave_signature,
                confirmation_metadata(2_005),
            )
            .unwrap();
        assert!(met);
        assert_eq!(dv.status, DeathVerificationStatus::Verified);
        assert!(dv.should_release());
        assert!(dv.resolved_at.is_some());
    }

    #[test]
    fn duplicate_confirmation_rejected() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let dave = did("dave");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let dave_key = keypair(3);
        let authorized =
            authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key), (&dave, &dave_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            3,
            authorized,
            b"r6-claim-6".to_vec(),
            &bob_key,
        );
        let signature = confirmation_signature(&dv, &carol, &carol_key);
        dv.confirm(
            carol.clone(),
            *carol_key.public_key(),
            signature.clone(),
            confirmation_metadata(2_006),
        )
        .unwrap();

        let result = dv.confirm(
            carol.clone(),
            *carol_key.public_key(),
            signature,
            confirmation_metadata(2_007),
        );
        assert!(matches!(
            result,
            Err(MessagingError::DuplicateConfirmation(trustee)) if trustee == carol.as_str()
        ));
    }

    #[test]
    fn cannot_confirm_after_resolved() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let dave = did("dave");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let dave_key = keypair(3);
        let authorized =
            authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key), (&dave, &dave_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-7".to_vec(),
            &bob_key,
        );
        let carol_signature = confirmation_signature(&dv, &carol, &carol_key);
        dv.confirm(
            carol,
            *carol_key.public_key(),
            carol_signature,
            confirmation_metadata(2_008),
        )
        .unwrap();

        let dave_signature = confirmation_signature(&dv, &dave, &dave_key);
        let result = dv.confirm(
            dave,
            *dave_key.public_key(),
            dave_signature,
            confirmation_metadata(2_009),
        );
        assert!(matches!(
            result,
            Err(MessagingError::DeathTriggerAlreadyResolved)
        ));
    }

    #[test]
    fn reject_prevents_further_confirmations() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-8".to_vec(),
            &bob_key,
        );
        dv.reject(rejection_metadata(3_000)).unwrap();
        assert_eq!(dv.status, DeathVerificationStatus::Rejected);
        assert!(!dv.should_release());

        let carol_signature = confirmation_signature(&dv, &carol, &carol_key);
        let result = dv.confirm(
            carol,
            *carol_key.public_key(),
            carol_signature,
            confirmation_metadata(2_010),
        );
        assert!(matches!(
            result,
            Err(MessagingError::DeathTriggerAlreadyResolved)
        ));
    }

    #[test]
    fn full_pace_4_trustee_flow() {
        let subject = did("subject");
        let primary = did("primary");
        let alternate = did("alternate");
        let contingency = did("contingency");
        let observer = did("observer");
        let primary_key = keypair(1);
        let alternate_key = keypair(2);
        let contingency_key = keypair(3);
        let observer_key = keypair(4);
        let authorized = authorized_trustees(&[
            (&primary, &primary_key),
            (&alternate, &alternate_key),
            (&contingency, &contingency_key),
            (&observer, &observer_key),
        ]);
        let mut dv = signed_verification(
            &subject,
            &primary,
            3,
            authorized,
            b"r6-claim-9".to_vec(),
            &primary_key,
        );
        assert_eq!(dv.confirmations_remaining(), 2);

        let alternate_signature = confirmation_signature(&dv, &alternate, &alternate_key);
        dv.confirm(
            alternate,
            *alternate_key.public_key(),
            alternate_signature,
            confirmation_metadata(2_011),
        )
        .unwrap();
        assert_eq!(dv.confirmations_remaining(), 1);

        let contingency_signature = confirmation_signature(&dv, &contingency, &contingency_key);
        let verified = dv
            .confirm(
                contingency,
                *contingency_key.public_key(),
                contingency_signature,
                confirmation_metadata(2_012),
            )
            .unwrap();
        assert!(verified);
        assert!(dv.should_release());
        assert_eq!(dv.confirmations_remaining(), 0);
    }

    #[test]
    fn creation_metadata_rejects_zero_created_at() {
        let result = DeathVerificationCreationMetadata::new(Timestamp::ZERO);

        assert!(
            matches!(result, Err(MessagingError::InvalidDeathVerification(reason)) if reason.contains("created_at"))
        );
    }

    #[test]
    fn creation_preserves_caller_supplied_timestamps() {
        let subject = did("alice");
        let bob = did("bob");
        let bob_key = keypair(1);
        let authorized = authorized_trustees(&[(&bob, &bob_key)]);
        let nonce = b"r6-claim-single".to_vec();
        let signature = initial_signature(&subject, &bob, 1, &authorized, &nonce, &bob_key);
        let metadata = creation_metadata(7_001);

        let dv = DeathVerification::new(subject, bob, 1, authorized, nonce, signature, metadata)
            .unwrap();

        assert_eq!(dv.created, timestamp(7_001));
        assert_eq!(dv.confirmations[0].confirmed_at, timestamp(7_001));
        assert_eq!(dv.resolved_at, Some(timestamp(7_001)));
    }

    #[test]
    fn confirmation_metadata_rejects_zero_confirmed_at() {
        let result = DeathConfirmationMetadata::new(Timestamp::ZERO);

        assert!(
            matches!(result, Err(MessagingError::InvalidDeathVerification(reason)) if reason.contains("confirmed_at"))
        );
    }

    #[test]
    fn confirm_preserves_caller_supplied_timestamp() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-confirm-time".to_vec(),
            &bob_key,
        );
        let signature = confirmation_signature(&dv, &carol, &carol_key);

        let verified = dv
            .confirm(
                carol,
                *carol_key.public_key(),
                signature,
                confirmation_metadata(7_002),
            )
            .unwrap();

        assert!(verified);
        assert_eq!(dv.confirmations[1].confirmed_at, timestamp(7_002));
        assert_eq!(dv.resolved_at, Some(timestamp(7_002)));
    }

    #[test]
    fn rejection_metadata_rejects_zero_rejected_at() {
        let result = DeathRejectionMetadata::new(Timestamp::ZERO);

        assert!(
            matches!(result, Err(MessagingError::InvalidDeathVerification(reason)) if reason.contains("rejected_at"))
        );
    }

    #[test]
    fn reject_preserves_caller_supplied_timestamp() {
        let subject = did("alice");
        let bob = did("bob");
        let carol = did("carol");
        let bob_key = keypair(1);
        let carol_key = keypair(2);
        let authorized = authorized_trustees(&[(&bob, &bob_key), (&carol, &carol_key)]);
        let mut dv = signed_verification(
            &subject,
            &bob,
            2,
            authorized,
            b"r6-claim-reject-time".to_vec(),
            &bob_key,
        );

        dv.reject(rejection_metadata(7_003)).unwrap();

        assert_eq!(dv.status, DeathVerificationStatus::Rejected);
        assert_eq!(dv.resolved_at, Some(timestamp(7_003)));
    }

    #[test]
    fn death_trigger_path_does_not_fabricate_hlc_metadata() {
        let source = include_str!("death_trigger.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .unwrap();
        let forbidden_clock = ["HybridClock", "::new()"].concat();

        assert!(
            !production.contains(&forbidden_clock),
            "death-trigger production path must not fabricate HLC timestamps"
        );
    }
}
