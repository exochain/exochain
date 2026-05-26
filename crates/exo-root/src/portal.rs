//! Server-side root genesis portal relay policy.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Hash256, SecretKey, Signature, crypto, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{GenesisCeremonyConfig, PairwiseEncryptedPayload, Result, RootError};

const MAX_PORTAL_PAYLOAD_BYTES: usize = 64 * 1024;

/// Ceremony phase associated with a portal envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CeremonyPhase {
    /// DKG round one broadcast.
    Round1,
    /// Roster-wide round one set attestation.
    Round1SetAttestation,
    /// DKG round two pairwise exchange.
    Round2,
    /// Final DKG confirmation.
    Finalize,
    /// Root artifact signing.
    RootSigning,
}

/// Bounded payload type carried by a portal envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CeremonyPayloadKind {
    /// DKG round one public package.
    Round1Package,
    /// Signed statement binding the full round one set.
    Round1SetAttestation,
    /// Recipient-bound encrypted DKG round two package.
    Round2EncryptedPackage,
    /// Rejected DKG round two raw package.
    Round2PlaintextPackage,
    /// Final key confirmation package.
    FinalKeyConfirmation,
    /// Root signing nonce commitment.
    RootSigningCommitment,
    /// Root signing share.
    RootSignatureShare,
}

/// Signed, bounded, untrusted relay envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyEnvelope {
    /// Ceremony identifier.
    pub ceremony_id: String,
    /// Ceremony phase.
    pub phase: CeremonyPhase,
    /// Payload type.
    pub payload_kind: CeremonyPayloadKind,
    /// Rostered sender DID.
    pub sender_did: Did,
    /// Optional rostered recipient DID.
    pub recipient_did: Option<Did>,
    /// Monotonic sender sequence.
    pub sequence: u64,
    /// Bounded opaque payload.
    pub payload_bytes: Vec<u8>,
    /// Canonical payload hash.
    pub payload_hash: Hash256,
    /// Ed25519 signature by the sender.
    pub signature: Signature,
}

/// Inputs that are signed into a portal relay envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyEnvelopeDraft {
    /// Ceremony identifier.
    pub ceremony_id: String,
    /// Ceremony phase.
    pub phase: CeremonyPhase,
    /// Payload type.
    pub payload_kind: CeremonyPayloadKind,
    /// Rostered sender DID.
    pub sender_did: Did,
    /// Optional rostered recipient DID.
    pub recipient_did: Option<Did>,
    /// Monotonic sender sequence.
    pub sequence: u64,
    /// Bounded opaque payload.
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PortalEnvelopeKey {
    sender_did: Did,
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    sequence: u64,
    recipient_did: Option<Did>,
}

/// In-memory portal store used by the server relay and tests.
#[derive(Debug, Clone)]
pub struct PortalStore {
    config: GenesisCeremonyConfig,
    envelopes: BTreeMap<PortalEnvelopeKey, CeremonyEnvelope>,
    seen_sequences: BTreeSet<(Did, u64)>,
}

#[derive(Serialize)]
struct PayloadHashEnvelope<'a> {
    domain: &'static str,
    payload_kind: CeremonyPayloadKind,
    payload_bytes: &'a [u8],
}

#[derive(Serialize)]
struct EnvelopeSigningPayload<'a> {
    domain: &'static str,
    ceremony_id: &'a str,
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    sender_did: &'a Did,
    recipient_did: &'a Option<Did>,
    sequence: u64,
    payload_hash: Hash256,
}

fn payload_hash(kind: CeremonyPayloadKind, payload_bytes: &[u8]) -> Result<Hash256> {
    hash_structured(&PayloadHashEnvelope {
        domain: "EXOCHAIN_ROOT_PORTAL_PAYLOAD_V1",
        payload_kind: kind,
        payload_bytes,
    })
    .map_err(canonical_encoding_error)
}

fn signing_payload(envelope: &CeremonyEnvelope) -> Result<Vec<u8>> {
    let payload = EnvelopeSigningPayload {
        domain: "EXOCHAIN_ROOT_PORTAL_ENVELOPE_V1",
        ceremony_id: &envelope.ceremony_id,
        phase: envelope.phase,
        payload_kind: envelope.payload_kind,
        sender_did: &envelope.sender_did,
        recipient_did: &envelope.recipient_did,
        sequence: envelope.sequence,
        payload_hash: envelope.payload_hash,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&payload, &mut bytes).map_err(canonical_encoding_error)?;
    Ok(bytes)
}

fn canonical_encoding_error(error: impl core::fmt::Display) -> RootError {
    RootError::CanonicalEncoding {
        detail: error.to_string(),
    }
}

impl CeremonyEnvelope {
    /// Create and sign a portal relay envelope.
    pub fn sign(draft: CeremonyEnvelopeDraft, signing_secret: &SecretKey) -> Result<Self> {
        let mut envelope = Self {
            ceremony_id: draft.ceremony_id,
            phase: draft.phase,
            payload_kind: draft.payload_kind,
            sender_did: draft.sender_did,
            recipient_did: draft.recipient_did,
            sequence: draft.sequence,
            payload_hash: payload_hash(draft.payload_kind, draft.payload_bytes.as_slice())?,
            payload_bytes: draft.payload_bytes,
            signature: Signature::Empty,
        };
        let payload = signing_payload(&envelope)?;
        envelope.signature = crypto::sign(payload.as_slice(), signing_secret);
        Ok(envelope)
    }
}

impl PortalStore {
    /// Construct an empty portal store for a ceremony.
    #[must_use]
    pub fn new(config: GenesisCeremonyConfig) -> Self {
        Self {
            config,
            envelopes: BTreeMap::new(),
            seen_sequences: BTreeSet::new(),
        }
    }

    /// Number of accepted relay envelopes.
    #[must_use]
    pub fn envelope_count(&self) -> usize {
        self.envelopes.len()
    }

    /// Return accepted envelopes matching all of the supplied filters; a `None`
    /// filter matches any value. Envelopes are relay data — already signed and
    /// (for round two) encrypted — so returning them to rostered participants is
    /// the read half of the relay, used to collect round-one packages, pull
    /// recipient-bound round-two packages, and gather signing commitments/shares.
    #[must_use]
    pub fn query(
        &self,
        phase: Option<CeremonyPhase>,
        payload_kind: Option<CeremonyPayloadKind>,
        recipient_did: Option<&Did>,
    ) -> Vec<CeremonyEnvelope> {
        self.envelopes
            .values()
            .filter(|envelope| phase.is_none_or(|value| envelope.phase == value))
            .filter(|envelope| payload_kind.is_none_or(|value| envelope.payload_kind == value))
            .filter(|envelope| {
                recipient_did.is_none_or(|value| envelope.recipient_did.as_ref() == Some(value))
            })
            .cloned()
            .collect()
    }

    /// Submit a signed envelope to the relay.
    pub fn submit(&mut self, envelope: CeremonyEnvelope) -> Result<Hash256> {
        self.validate_envelope(&envelope)?;
        let sequence_key = (envelope.sender_did.clone(), envelope.sequence);
        if self.seen_sequences.contains(&sequence_key) {
            return Err(RootError::PortalRejected {
                reason: "sender sequence replay".to_owned(),
            });
        }
        let key = PortalEnvelopeKey {
            sender_did: envelope.sender_did.clone(),
            phase: envelope.phase,
            payload_kind: envelope.payload_kind,
            sequence: envelope.sequence,
            recipient_did: envelope.recipient_did.clone(),
        };
        let envelope_id = hash_structured(&key_parts(&key)).map_err(canonical_encoding_error)?;
        self.seen_sequences.insert(sequence_key);
        self.envelopes.insert(key, envelope);
        Ok(envelope_id)
    }

    fn validate_envelope(&self, envelope: &CeremonyEnvelope) -> Result<()> {
        self.config.validate()?;
        if envelope.ceremony_id != self.config.ceremony_id {
            return Err(RootError::PortalRejected {
                reason: "ceremony_id mismatch".to_owned(),
            });
        }
        if envelope.payload_bytes.len() > MAX_PORTAL_PAYLOAD_BYTES {
            return Err(RootError::PortalRejected {
                reason: "payload exceeds portal limit".to_owned(),
            });
        }
        if envelope.payload_hash
            != payload_hash(envelope.payload_kind, envelope.payload_bytes.as_slice())?
        {
            return Err(RootError::PortalRejected {
                reason: "payload hash mismatch".to_owned(),
            });
        }
        self.validate_phase_policy(envelope)?;

        let sender = self
            .config
            .certifier_by_did(&envelope.sender_did)
            .ok_or_else(|| RootError::PortalRejected {
                reason: "sender is not rostered".to_owned(),
            })?;
        if let Some(recipient) = &envelope.recipient_did {
            if self.config.certifier_by_did(recipient).is_none() {
                return Err(RootError::PortalRejected {
                    reason: "recipient is not rostered".to_owned(),
                });
            }
            if recipient == &envelope.sender_did {
                return Err(RootError::PortalRejected {
                    reason: "sender cannot target itself".to_owned(),
                });
            }
        }

        let payload = signing_payload(envelope)?;
        if !crypto::verify(
            payload.as_slice(),
            &envelope.signature,
            &sender.signing_public_key,
        ) {
            return Err(RootError::SignatureRejected {
                reason: "certifier envelope signature rejected".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_phase_policy(&self, envelope: &CeremonyEnvelope) -> Result<()> {
        match (envelope.phase, envelope.payload_kind) {
            (CeremonyPhase::Round1, CeremonyPayloadKind::Round1Package)
            | (CeremonyPhase::Round1SetAttestation, CeremonyPayloadKind::Round1SetAttestation)
            | (CeremonyPhase::Finalize, CeremonyPayloadKind::FinalKeyConfirmation)
            | (CeremonyPhase::RootSigning, CeremonyPayloadKind::RootSigningCommitment)
            | (CeremonyPhase::RootSigning, CeremonyPayloadKind::RootSignatureShare) => {
                if envelope.recipient_did.is_some() {
                    return Err(RootError::PortalRejected {
                        reason: "broadcast payload must not set recipient".to_owned(),
                    });
                }
                Ok(())
            }
            (CeremonyPhase::Round2, CeremonyPayloadKind::Round2EncryptedPackage) => {
                if envelope.recipient_did.is_none() {
                    return Err(RootError::PortalRejected {
                        reason: "round-two encrypted package requires recipient".to_owned(),
                    });
                }
                validate_encrypted_round2_payload(envelope.payload_bytes.as_slice())?;
                Ok(())
            }
            (_, CeremonyPayloadKind::Round2PlaintextPackage) => Err(RootError::PortalRejected {
                reason: "round-two raw package is rejected".to_owned(),
            }),
            _ => Err(RootError::PortalRejected {
                reason: "payload kind is not valid for phase".to_owned(),
            }),
        }
    }
}

fn validate_encrypted_round2_payload(payload_bytes: &[u8]) -> Result<()> {
    let encrypted: PairwiseEncryptedPayload =
        ciborium::from_reader(payload_bytes).map_err(|error| RootError::PortalRejected {
            reason: format!("round-two encrypted package is malformed: {error}"),
        })?;
    if encrypted.ciphertext.is_empty() {
        return Err(RootError::PortalRejected {
            reason: "round-two encrypted package ciphertext must not be empty".to_owned(),
        });
    }
    Ok(())
}

#[derive(Serialize)]
struct PortalEnvelopeKeyParts<'a> {
    sender_did: &'a Did,
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    sequence: u64,
    recipient_did: &'a Option<Did>,
}

fn key_parts(key: &PortalEnvelopeKey) -> PortalEnvelopeKeyParts<'_> {
    PortalEnvelopeKeyParts {
        sender_did: &key.sender_did,
        phase: key.phase,
        payload_kind: key.payload_kind,
        sequence: key.sequence,
        recipient_did: &key.recipient_did,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_core::{Timestamp, crypto::KeyPair};

    use super::*;
    use crate::{CertifierContact, PairwiseEncryptedPayload};

    fn certifier(index: u16) -> (CertifierContact, exo_core::SecretKey) {
        let seed = [u8::try_from(index).expect("index fits"); 32];
        let keypair = KeyPair::from_secret_bytes(seed).expect("keypair");
        let transport_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed));
        (
            CertifierContact {
                did: Did::new(&format!("did:exo:portal-query-{index:02}")).expect("did"),
                frost_identifier: index,
                signing_public_key: *keypair.public_key(),
                transport_public_key: *transport_public.as_bytes(),
            },
            keypair.secret_key().clone(),
        )
    }

    fn config_with_secrets() -> (GenesisCeremonyConfig, Vec<SecretKey>) {
        let mut certifiers = Vec::new();
        let mut secrets = Vec::new();
        for index in 1..=crate::ROOT_GENESIS_SIGNERS {
            let (contact, secret) = certifier(index);
            certifiers.push(contact);
            secrets.push(secret);
        }
        (
            GenesisCeremonyConfig {
                ceremony_id: "portal-query".into(),
                network_id: "exochain-test".into(),
                repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".into(),
                constitution_hash: Hash256::digest(b"constitution"),
                threshold: crate::ROOT_GENESIS_THRESHOLD,
                max_signers: crate::ROOT_GENESIS_SIGNERS,
                created_at: Timestamp::new(1, 0),
                certifiers,
            },
            secrets,
        )
    }

    fn encrypted_payload_bytes() -> Vec<u8> {
        let payload = PairwiseEncryptedPayload {
            nonce: [9u8; 24],
            ciphertext: b"ciphertext".to_vec(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes).expect("encode");
        bytes
    }

    #[test]
    fn canonical_error_conversion_is_diagnostic() {
        let error = canonical_encoding_error("portal encoding failed");
        assert!(error.to_string().contains("portal encoding failed"));
    }

    #[test]
    fn query_filters_by_phase_kind_and_recipient() {
        let (config, secrets) = config_with_secrets();
        let mut store = PortalStore::new(config.clone());

        // A round-one broadcast from certifier 1.
        store
            .submit(
                CeremonyEnvelope::sign(
                    CeremonyEnvelopeDraft {
                        ceremony_id: config.ceremony_id.clone(),
                        phase: CeremonyPhase::Round1,
                        payload_kind: CeremonyPayloadKind::Round1Package,
                        sender_did: config.certifiers[0].did.clone(),
                        recipient_did: None,
                        sequence: 0,
                        payload_bytes: b"round1".to_vec(),
                    },
                    &secrets[0],
                )
                .expect("round1 envelope"),
            )
            .expect("submit round1");

        // A round-two package from certifier 1 addressed to certifier 2.
        store
            .submit(
                CeremonyEnvelope::sign(
                    CeremonyEnvelopeDraft {
                        ceremony_id: config.ceremony_id.clone(),
                        phase: CeremonyPhase::Round2,
                        payload_kind: CeremonyPayloadKind::Round2EncryptedPackage,
                        sender_did: config.certifiers[0].did.clone(),
                        recipient_did: Some(config.certifiers[1].did.clone()),
                        sequence: 1,
                        payload_bytes: encrypted_payload_bytes(),
                    },
                    &secrets[0],
                )
                .expect("round2 envelope"),
            )
            .expect("submit round2");

        // No filters → both envelopes.
        assert_eq!(store.query(None, None, None).len(), 2);
        // Phase filter (match + non-match).
        assert_eq!(
            store.query(Some(CeremonyPhase::Round1), None, None).len(),
            1
        );
        assert_eq!(
            store.query(Some(CeremonyPhase::Finalize), None, None).len(),
            0
        );
        // Payload-kind filter.
        assert_eq!(
            store
                .query(
                    None,
                    Some(CeremonyPayloadKind::Round2EncryptedPackage),
                    None
                )
                .len(),
            1
        );
        // Recipient filter (match + non-match).
        assert_eq!(
            store
                .query(
                    Some(CeremonyPhase::Round2),
                    None,
                    Some(&config.certifiers[1].did)
                )
                .len(),
            1
        );
        assert_eq!(
            store
                .query(None, None, Some(&config.certifiers[2].did))
                .len(),
            0
        );
    }
}
