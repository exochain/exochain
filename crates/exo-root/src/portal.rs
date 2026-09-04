//! Server-side root genesis portal relay policy.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Hash256, SecretKey, Signature, crypto, hash::hash_structured};
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};

use crate::{
    GenesisCeremonyConfig, PairwiseEncryptedPayload, Result, RootError,
    dkg::{
        RootParticipantDkgOutput, RootPublicKeyPackage, deserialize_frost, frost_identifier,
        validate_public_key_package,
    },
};

const MAX_PORTAL_PAYLOAD_BYTES: usize = 64 * 1024;
pub const FINAL_KEY_CONFIRMATION_DOMAIN: &str = "EXOCHAIN_ROOT_FINAL_KEY_CONFIRMATION_V1";
pub const FINAL_KEY_CONFIRMATION_SCHEMA_VERSION: u16 = 1;

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

/// Ratified final DKG key confirmation payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalKeyConfirmation {
    /// Domain separator; must equal [`crate::FINAL_KEY_CONFIRMATION_DOMAIN`].
    pub domain: String,
    /// Schema version; must equal [`crate::FINAL_KEY_CONFIRMATION_SCHEMA_VERSION`].
    pub schema_version: u16,
    /// Ceremony identifier.
    pub ceremony_id: String,
    /// Confirming certifier DID.
    pub certifier_did: Did,
    /// Confirming certifier FROST identifier.
    pub frost_identifier: u16,
    /// Canonical hash of the ceremony config.
    pub config_hash: Hash256,
    /// Canonical hash of the completed DKG relay transcript.
    pub dkg_transcript_hash: Hash256,
    /// Public key package independently derived by the certifier.
    pub public_key_package: RootPublicKeyPackage,
    /// Canonical hash of the full public key package.
    pub root_public_key_package_hash: Hash256,
    /// Hash of `public_key_package.root_public_key`.
    pub root_public_key_hash: Hash256,
    /// Hash of this certifier's verifying share in the public key package.
    pub certifier_verifying_share_hash: Hash256,
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
    final_key_confirmations: BTreeMap<Did, FinalKeyConfirmation>,
    /// Signers who have already submitted a root signature share this session.
    /// Enforces one share per signer (single-use of the signer's nonces).
    signature_share_senders: BTreeSet<Did>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct TranscriptEnvelopeRecord {
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    sender_did: Did,
    recipient_did: Option<Did>,
    sequence: u64,
    envelope_id: Hash256,
    envelope_hash: Hash256,
}

#[derive(Serialize)]
struct DkgTranscriptPayload<'a> {
    domain: &'static str,
    config_hash: Hash256,
    envelopes: &'a [TranscriptEnvelopeRecord],
}

#[derive(Serialize)]
struct FinalTranscriptPayload<'a> {
    domain: &'static str,
    config_hash: Hash256,
    dkg_transcript_hash: Hash256,
    final_key_confirmations: &'a [TranscriptEnvelopeRecord],
}

fn payload_hash(kind: CeremonyPayloadKind, payload_bytes: &[u8]) -> Result<Hash256> {
    hash_structured(&PayloadHashEnvelope {
        domain: "EXOCHAIN_ROOT_PORTAL_PAYLOAD_V1",
        payload_kind: kind,
        payload_bytes,
    })
    .map_err(canonical_encoding_error)
}

/// Canonical hash of a root genesis ceremony config.
pub fn ceremony_config_hash(config: &GenesisCeremonyConfig) -> Result<Hash256> {
    hash_structured(config).map_err(canonical_encoding_error)
}

/// Encode a ratified final key confirmation as portal payload bytes.
pub fn encode_final_key_confirmation_payload(
    confirmation: &FinalKeyConfirmation,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(confirmation, &mut bytes).map_err(canonical_encoding_error)?;
    Ok(bytes)
}

fn decode_final_key_confirmation_payload(bytes: &[u8]) -> Result<FinalKeyConfirmation> {
    ciborium::from_reader(bytes).map_err(|error| RootError::PortalRejected {
        reason: format!("final key confirmation payload failed schema validation: {error}"),
    })
}

fn certifier_verifying_share_hash(
    public_key_package: &RootPublicKeyPackage,
    frost_identifier_value: u16,
    missing_error: RootError,
) -> Result<Hash256> {
    let verifying_share = public_key_package
        .verifying_shares
        .get(&frost_identifier_value)
        .ok_or(missing_error)?;
    Ok(Hash256::digest(verifying_share.as_slice()))
}

/// Build the ratified final key confirmation payload for one finalized
/// certifier. This emits only public confirmation material; the secret FROST key
/// package is parsed locally to bind the certifier identifier but is never copied
/// into the payload.
pub fn build_final_key_confirmation(
    config: &GenesisCeremonyConfig,
    dkg_output: &RootParticipantDkgOutput,
    dkg_transcript_hash: Hash256,
) -> Result<FinalKeyConfirmation> {
    config.validate()?;
    validate_public_key_package(config, &dkg_output.public_key_package)?;
    let frost_identifier_value = dkg_output.key_package.frost_identifier;
    let certifier = config
        .certifier_by_identifier(frost_identifier_value)
        .ok_or_else(|| RootError::InvalidConfig {
            reason: format!(
                "final key confirmation certifier {frost_identifier_value} is not rostered"
            ),
        })?;
    let parsed_key_package: frost::keys::KeyPackage =
        deserialize_frost(dkg_output.key_package.key_package.as_slice())?;
    if *parsed_key_package.identifier() != frost_identifier(frost_identifier_value)? {
        return Err(RootError::Frost {
            detail: "final key confirmation key package identifier mismatch".to_owned(),
        });
    }
    let certifier_verifying_share_hash = certifier_verifying_share_hash(
        &dkg_output.public_key_package,
        frost_identifier_value,
        RootError::BundleRejected {
            reason: format!(
                "public key package missing verifying share for certifier {frost_identifier_value}"
            ),
        },
    )?;
    Ok(FinalKeyConfirmation {
        domain: FINAL_KEY_CONFIRMATION_DOMAIN.to_owned(),
        schema_version: FINAL_KEY_CONFIRMATION_SCHEMA_VERSION,
        ceremony_id: config.ceremony_id.clone(),
        certifier_did: certifier.did.clone(),
        frost_identifier: frost_identifier_value,
        config_hash: ceremony_config_hash(config)?,
        dkg_transcript_hash,
        public_key_package: dkg_output.public_key_package.clone(),
        root_public_key_package_hash: hash_structured(&dkg_output.public_key_package)
            .map_err(canonical_encoding_error)?,
        root_public_key_hash: Hash256::digest(
            dkg_output.public_key_package.root_public_key.as_slice(),
        ),
        certifier_verifying_share_hash,
    })
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
            final_key_confirmations: BTreeMap::new(),
            signature_share_senders: BTreeSet::new(),
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
        let final_key_confirmation =
            if envelope.payload_kind == CeremonyPayloadKind::FinalKeyConfirmation {
                Some(self.validate_final_key_confirmation(&envelope)?)
            } else {
                None
            };
        let sequence_key = (envelope.sender_did.clone(), envelope.sequence);
        if self.seen_sequences.contains(&sequence_key) {
            return Err(RootError::PortalRejected {
                reason: "sender sequence replay".to_owned(),
            });
        }
        // One root signature share per signer per session: a second share from the
        // same signer is rejected, enforcing single-use of that signer's nonces.
        if envelope.payload_kind == CeremonyPayloadKind::RootSignatureShare
            && self.signature_share_senders.contains(&envelope.sender_did)
        {
            return Err(RootError::PortalRejected {
                reason: "signer has already submitted a signature share this session".to_owned(),
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
        if envelope.payload_kind == CeremonyPayloadKind::RootSignatureShare {
            self.signature_share_senders
                .insert(envelope.sender_did.clone());
        }
        if let Some(confirmation) = final_key_confirmation {
            self.final_key_confirmations
                .insert(envelope.sender_did.clone(), confirmation);
        }
        self.envelopes.insert(key, envelope);
        Ok(envelope_id)
    }

    /// Canonical hash over the complete accepted DKG relay transcript.
    pub fn dkg_transcript_hash(&self) -> Result<Hash256> {
        let records = self.dkg_transcript_records()?;
        self.ensure_dkg_transcript_complete(records.as_slice())?;
        let payload = DkgTranscriptPayload {
            domain: "EXOCHAIN_ROOT_DKG_TRANSCRIPT_V1",
            config_hash: ceremony_config_hash(&self.config)?,
            envelopes: records.as_slice(),
        };
        hash_structured(&payload).map_err(canonical_encoding_error)
    }

    /// Canonical final ceremony transcript hash, including all accepted final
    /// key confirmation envelopes. This is the transcript hash root artifacts
    /// must bind before root signing begins.
    pub fn final_transcript_hash(&self) -> Result<Hash256> {
        self.ensure_final_key_confirmations_complete()?;
        let records = self.final_key_confirmation_records()?;
        let payload = FinalTranscriptPayload {
            domain: "EXOCHAIN_ROOT_FINAL_TRANSCRIPT_V1",
            config_hash: ceremony_config_hash(&self.config)?,
            dkg_transcript_hash: self.dkg_transcript_hash()?,
            final_key_confirmations: records.as_slice(),
        };
        hash_structured(&payload).map_err(canonical_encoding_error)
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
        // Every accepted payload kind is schema-validated by decoding it to its
        // concrete type before storage — the portal never stores opaque bytes for
        // a security-sensitive kind. Kinds without a ratified, decodable schema
        // (round-one set attestation) are disabled.
        let bytes = envelope.payload_bytes.as_slice();
        match (envelope.phase, envelope.payload_kind) {
            (CeremonyPhase::Round1, CeremonyPayloadKind::Round1Package) => {
                reject_recipient(envelope)?;
                self.reject_dkg_mutation_after_final_confirmation()?;
                self.reject_duplicate_broadcast_sender(
                    envelope,
                    CeremonyPhase::Round1,
                    CeremonyPayloadKind::Round1Package,
                    "round-one package already submitted by sender",
                )?;
                reject_unless_decodable::<frost::keys::dkg::round1::Package>(
                    bytes,
                    "round-one package",
                )
            }
            (CeremonyPhase::RootSigning, CeremonyPayloadKind::RootSigningCommitment) => {
                reject_recipient(envelope)?;
                self.ensure_final_key_confirmations_complete()?;
                self.reject_duplicate_broadcast_sender(
                    envelope,
                    CeremonyPhase::RootSigning,
                    CeremonyPayloadKind::RootSigningCommitment,
                    "root signing commitment already submitted by sender",
                )?;
                reject_unless_decodable::<frost::round1::SigningCommitments>(
                    bytes,
                    "root signing commitment",
                )
            }
            (CeremonyPhase::RootSigning, CeremonyPayloadKind::RootSignatureShare) => {
                reject_recipient(envelope)?;
                self.ensure_final_key_confirmations_complete()?;
                reject_unless_decodable::<frost::round2::SignatureShare>(
                    bytes,
                    "root signature share",
                )
            }
            (CeremonyPhase::Round2, CeremonyPayloadKind::Round2EncryptedPackage) => {
                if envelope.recipient_did.is_none() {
                    return Err(RootError::PortalRejected {
                        reason: "round-two encrypted package requires recipient".to_owned(),
                    });
                }
                self.reject_dkg_mutation_after_final_confirmation()?;
                self.reject_duplicate_pairwise_sender_recipient(
                    envelope,
                    CeremonyPhase::Round2,
                    CeremonyPayloadKind::Round2EncryptedPackage,
                    "round-two encrypted package already submitted for sender and recipient",
                )?;
                validate_encrypted_round2_payload(bytes)
            }
            (CeremonyPhase::Round1SetAttestation, CeremonyPayloadKind::Round1SetAttestation) => {
                Err(RootError::PortalRejected {
                    reason: "round-one set attestation is disabled pending a ratified, \
                             portal-validated payload schema"
                        .to_owned(),
                })
            }
            (CeremonyPhase::Finalize, CeremonyPayloadKind::FinalKeyConfirmation) => {
                reject_recipient(envelope)?;
                self.validate_final_key_confirmation(envelope).map(|_| ())
            }
            (_, CeremonyPayloadKind::Round2PlaintextPackage) => Err(RootError::PortalRejected {
                reason: "round-two raw package is rejected".to_owned(),
            }),
            _ => Err(RootError::PortalRejected {
                reason: "payload kind is not valid for phase".to_owned(),
            }),
        }
    }

    fn reject_dkg_mutation_after_final_confirmation(&self) -> Result<()> {
        if !self.final_key_confirmations.is_empty() {
            return Err(RootError::PortalRejected {
                reason: "dkg transcript is frozen after final key confirmation".to_owned(),
            });
        }
        Ok(())
    }

    fn reject_duplicate_broadcast_sender(
        &self,
        envelope: &CeremonyEnvelope,
        phase: CeremonyPhase,
        payload_kind: CeremonyPayloadKind,
        reason: &str,
    ) -> Result<()> {
        if self.envelopes.values().any(|accepted| {
            accepted.sender_did == envelope.sender_did
                && accepted.phase == phase
                && accepted.payload_kind == payload_kind
                && accepted.recipient_did.is_none()
                && accepted.sequence != envelope.sequence
        }) {
            return Err(RootError::PortalRejected {
                reason: reason.to_owned(),
            });
        }
        Ok(())
    }

    fn reject_duplicate_pairwise_sender_recipient(
        &self,
        envelope: &CeremonyEnvelope,
        phase: CeremonyPhase,
        payload_kind: CeremonyPayloadKind,
        reason: &str,
    ) -> Result<()> {
        if self.envelopes.values().any(|accepted| {
            accepted.sender_did == envelope.sender_did
                && accepted.recipient_did == envelope.recipient_did
                && accepted.phase == phase
                && accepted.payload_kind == payload_kind
                && accepted.sequence != envelope.sequence
        }) {
            return Err(RootError::PortalRejected {
                reason: reason.to_owned(),
            });
        }
        Ok(())
    }

    fn validate_final_key_confirmation(
        &self,
        envelope: &CeremonyEnvelope,
    ) -> Result<FinalKeyConfirmation> {
        if self
            .final_key_confirmations
            .contains_key(&envelope.sender_did)
        {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation already submitted by sender".to_owned(),
            });
        }
        let confirmation =
            decode_final_key_confirmation_payload(envelope.payload_bytes.as_slice())?;
        self.validate_final_key_confirmation_semantics(envelope, &confirmation)?;
        for accepted in self.final_key_confirmations.values() {
            if accepted.config_hash != confirmation.config_hash {
                return Err(RootError::PortalRejected {
                    reason: "final key confirmation config hash disagrees with accepted set"
                        .to_owned(),
                });
            }
            if accepted.dkg_transcript_hash != confirmation.dkg_transcript_hash {
                return Err(RootError::PortalRejected {
                    reason:
                        "final key confirmation DKG transcript hash disagrees with accepted set"
                            .to_owned(),
                });
            }
            if accepted.public_key_package != confirmation.public_key_package {
                return Err(RootError::PortalRejected {
                    reason: "final key confirmation public key package disagrees with accepted set"
                        .to_owned(),
                });
            }
            if accepted.root_public_key_package_hash != confirmation.root_public_key_package_hash {
                return Err(RootError::PortalRejected {
                    reason:
                        "final key confirmation public key package hash disagrees with accepted set"
                            .to_owned(),
                });
            }
            if accepted.root_public_key_hash != confirmation.root_public_key_hash {
                return Err(RootError::PortalRejected {
                    reason: "final key confirmation root key hash disagrees with accepted set"
                        .to_owned(),
                });
            }
        }
        Ok(confirmation)
    }

    fn validate_final_key_confirmation_semantics(
        &self,
        envelope: &CeremonyEnvelope,
        confirmation: &FinalKeyConfirmation,
    ) -> Result<()> {
        if confirmation.domain != FINAL_KEY_CONFIRMATION_DOMAIN {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation domain mismatch".to_owned(),
            });
        }
        if confirmation.schema_version != FINAL_KEY_CONFIRMATION_SCHEMA_VERSION {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation schema version mismatch".to_owned(),
            });
        }
        if confirmation.ceremony_id != self.config.ceremony_id {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation ceremony_id mismatch".to_owned(),
            });
        }
        if confirmation.certifier_did != envelope.sender_did {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation certifier_did must match envelope sender"
                    .to_owned(),
            });
        }
        let certifier = self
            .config
            .certifier_by_did(&confirmation.certifier_did)
            .ok_or_else(|| RootError::PortalRejected {
                reason: "final key confirmation certifier is not rostered".to_owned(),
            })?;
        if certifier.frost_identifier != confirmation.frost_identifier {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation DID and FROST identifier mismatch".to_owned(),
            });
        }
        let expected_config_hash = ceremony_config_hash(&self.config)?;
        if confirmation.config_hash != expected_config_hash {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation config hash mismatch".to_owned(),
            });
        }
        let expected_dkg_transcript_hash = self.dkg_transcript_hash()?;
        if confirmation.dkg_transcript_hash != expected_dkg_transcript_hash {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation DKG transcript hash mismatch".to_owned(),
            });
        }
        validate_public_key_package(&self.config, &confirmation.public_key_package)?;
        let expected_package_hash =
            hash_structured(&confirmation.public_key_package).map_err(canonical_encoding_error)?;
        if confirmation.root_public_key_package_hash != expected_package_hash {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation public key package hash mismatch".to_owned(),
            });
        }
        let expected_root_public_key_hash =
            Hash256::digest(confirmation.public_key_package.root_public_key.as_slice());
        if confirmation.root_public_key_hash != expected_root_public_key_hash {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation root public key hash mismatch".to_owned(),
            });
        }
        let certifier_verifying_share_hash = certifier_verifying_share_hash(
            &confirmation.public_key_package,
            confirmation.frost_identifier,
            RootError::PortalRejected {
                reason: "final key confirmation verifying share is missing".to_owned(),
            },
        )?;
        if confirmation.certifier_verifying_share_hash != certifier_verifying_share_hash {
            return Err(RootError::PortalRejected {
                reason: "final key confirmation verifying share hash mismatch".to_owned(),
            });
        }
        Ok(())
    }

    fn dkg_transcript_records(&self) -> Result<Vec<TranscriptEnvelopeRecord>> {
        let mut records = Vec::new();
        for (key, envelope) in &self.envelopes {
            if matches!(
                (envelope.phase, envelope.payload_kind),
                (CeremonyPhase::Round1, CeremonyPayloadKind::Round1Package)
                    | (
                        CeremonyPhase::Round2,
                        CeremonyPayloadKind::Round2EncryptedPackage
                    )
            ) {
                records.push(transcript_record(key, envelope)?);
            }
        }
        records.sort();
        Ok(records)
    }

    fn final_key_confirmation_records(&self) -> Result<Vec<TranscriptEnvelopeRecord>> {
        let mut records = Vec::new();
        for (key, envelope) in &self.envelopes {
            if envelope.phase == CeremonyPhase::Finalize
                && envelope.payload_kind == CeremonyPayloadKind::FinalKeyConfirmation
            {
                records.push(transcript_record(key, envelope)?);
            }
        }
        records.sort();
        Ok(records)
    }

    fn ensure_dkg_transcript_complete(&self, records: &[TranscriptEnvelopeRecord]) -> Result<()> {
        let expected_certifiers: BTreeSet<Did> = self
            .config
            .certifiers
            .iter()
            .map(|certifier| certifier.did.clone())
            .collect();
        let mut round1_senders = BTreeSet::new();
        let mut round2_pairs = BTreeSet::new();
        for record in records {
            match (record.phase, record.payload_kind) {
                (CeremonyPhase::Round1, CeremonyPayloadKind::Round1Package) => {
                    if record.recipient_did.is_some() {
                        return Err(RootError::PortalRejected {
                            reason: "dkg transcript round-one record has a recipient".to_owned(),
                        });
                    }
                    if !round1_senders.insert(record.sender_did.clone()) {
                        return Err(RootError::PortalRejected {
                            reason: "dkg transcript contains duplicate round-one sender".to_owned(),
                        });
                    }
                }
                (CeremonyPhase::Round2, CeremonyPayloadKind::Round2EncryptedPackage) => {
                    let recipient =
                        record
                            .recipient_did
                            .clone()
                            .ok_or_else(|| RootError::PortalRejected {
                                reason: "dkg transcript round-two record missing recipient"
                                    .to_owned(),
                            })?;
                    if !round2_pairs.insert((record.sender_did.clone(), recipient)) {
                        return Err(RootError::PortalRejected {
                            reason:
                                "dkg transcript contains duplicate round-two sender-recipient pair"
                                    .to_owned(),
                        });
                    }
                }
                _ => {
                    return Err(RootError::PortalRejected {
                        reason: "dkg transcript contains non-DKG envelope".to_owned(),
                    });
                }
            }
        }
        if round1_senders != expected_certifiers {
            return Err(RootError::PortalRejected {
                reason: "dkg transcript requires one round-one package from every certifier"
                    .to_owned(),
            });
        }
        let expected_round2 = usize::from(self.config.max_signers)
            * usize::from(self.config.max_signers.saturating_sub(1));
        if round2_pairs.len() != expected_round2 {
            return Err(RootError::PortalRejected {
                reason: "dkg transcript requires every ordered round-two sender-recipient package"
                    .to_owned(),
            });
        }
        for sender in &expected_certifiers {
            for recipient in &expected_certifiers {
                if sender == recipient {
                    continue;
                }
                if !round2_pairs.contains(&(sender.clone(), recipient.clone())) {
                    return Err(RootError::PortalRejected {
                        reason: "dkg transcript missing round-two sender-recipient package"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn ensure_final_key_confirmations_complete(&self) -> Result<()> {
        if self.final_key_confirmations.len() != usize::from(self.config.max_signers) {
            return Err(RootError::PortalRejected {
                reason: "root signing requires final key confirmations from all certifiers"
                    .to_owned(),
            });
        }
        for certifier in &self.config.certifiers {
            if !self.final_key_confirmations.contains_key(&certifier.did) {
                return Err(RootError::PortalRejected {
                    reason: "root signing missing a certifier final key confirmation".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Reject a broadcast payload that carries a recipient.
fn reject_recipient(envelope: &CeremonyEnvelope) -> Result<()> {
    if envelope.recipient_did.is_some() {
        return Err(RootError::PortalRejected {
            reason: "broadcast payload must not set recipient".to_owned(),
        });
    }
    Ok(())
}

/// Schema-validate a payload by decoding it to its concrete type `T`; a decode
/// failure is a portal rejection (bad request), never silent storage.
fn reject_unless_decodable<T: serde::de::DeserializeOwned>(bytes: &[u8], kind: &str) -> Result<()> {
    ciborium::from_reader::<T, _>(bytes)
        .map(|_decoded| ())
        .map_err(|error| RootError::PortalRejected {
            reason: format!("{kind} payload failed schema validation: {error}"),
        })
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

fn transcript_record(
    key: &PortalEnvelopeKey,
    envelope: &CeremonyEnvelope,
) -> Result<TranscriptEnvelopeRecord> {
    Ok(TranscriptEnvelopeRecord {
        phase: envelope.phase,
        payload_kind: envelope.payload_kind,
        sender_did: envelope.sender_did.clone(),
        recipient_did: envelope.recipient_did.clone(),
        sequence: envelope.sequence,
        envelope_id: hash_structured(&key_parts(key)).map_err(canonical_encoding_error)?,
        envelope_hash: hash_structured(envelope).map_err(canonical_encoding_error)?,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_core::{Timestamp, crypto::KeyPair};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{CertifierContact, PairwiseEncryptedPayload};

    fn round1_package_bytes(config: &GenesisCeremonyConfig, frost_identifier: u16) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(u64::from(frost_identifier));
        let mut output = crate::dkg_round1(config, frost_identifier, &mut rng).expect("round one");
        std::mem::take(&mut output.round1_package)
    }

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
                signing_set: (1..=7).collect(),
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

    fn encrypted_payload_with(ciphertext: impl Into<Vec<u8>>) -> Vec<u8> {
        let payload = PairwiseEncryptedPayload {
            nonce: [9u8; 24],
            ciphertext: ciphertext.into(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes).expect("encode");
        bytes
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_envelope(
        config: &GenesisCeremonyConfig,
        secrets: &[SecretKey],
        sender_identifier: u16,
        phase: CeremonyPhase,
        payload_kind: CeremonyPayloadKind,
        recipient_identifier: Option<u16>,
        sequence: u64,
        payload_bytes: Vec<u8>,
    ) -> CeremonyEnvelope {
        let sender_index = usize::from(sender_identifier - 1);
        let recipient_did = recipient_identifier
            .map(|identifier| config.certifiers[usize::from(identifier - 1)].did.clone());
        CeremonyEnvelope::sign(
            CeremonyEnvelopeDraft {
                ceremony_id: config.ceremony_id.clone(),
                phase,
                payload_kind,
                sender_did: config.certifiers[sender_index].did.clone(),
                recipient_did,
                sequence,
                payload_bytes,
            },
            &secrets[sender_index],
        )
        .expect("signed envelope")
    }

    fn participant_output(
        dkg: &mut crate::RootDkgOutput,
        identifier: u16,
    ) -> crate::RootParticipantDkgOutput {
        crate::RootParticipantDkgOutput {
            key_package: dkg
                .key_packages
                .remove(&identifier)
                .expect("participant key package"),
            public_key_package: dkg.public_key_package.clone(),
        }
    }

    fn submit_complete_dkg_transcript(
        store: &mut PortalStore,
        config: &GenesisCeremonyConfig,
        secrets: &[SecretKey],
    ) -> Hash256 {
        for certifier in &config.certifiers {
            store
                .submit(sign_envelope(
                    config,
                    secrets,
                    certifier.frost_identifier,
                    CeremonyPhase::Round1,
                    CeremonyPayloadKind::Round1Package,
                    None,
                    10,
                    round1_package_bytes(config, certifier.frost_identifier),
                ))
                .expect("round one submit");
        }
        for sender in &config.certifiers {
            for recipient in &config.certifiers {
                if sender.frost_identifier == recipient.frost_identifier {
                    continue;
                }
                store
                    .submit(sign_envelope(
                        config,
                        secrets,
                        sender.frost_identifier,
                        CeremonyPhase::Round2,
                        CeremonyPayloadKind::Round2EncryptedPackage,
                        Some(recipient.frost_identifier),
                        1_000
                            + u64::from(sender.frost_identifier) * 100
                            + u64::from(recipient.frost_identifier),
                        encrypted_payload_with(format!(
                            "round2-{}-{}",
                            sender.frost_identifier, recipient.frost_identifier
                        )),
                    ))
                    .expect("round two submit");
            }
        }
        store.dkg_transcript_hash().expect("dkg transcript hash")
    }

    fn final_key_confirmation(
        config: &GenesisCeremonyConfig,
        dkg: &mut crate::RootDkgOutput,
        identifier: u16,
        dkg_transcript_hash: Hash256,
    ) -> FinalKeyConfirmation {
        build_final_key_confirmation(
            config,
            &participant_output(dkg, identifier),
            dkg_transcript_hash,
        )
        .expect("final key confirmation")
    }

    fn final_key_confirmation_envelope(
        config: &GenesisCeremonyConfig,
        secrets: &[SecretKey],
        identifier: u16,
        confirmation: &FinalKeyConfirmation,
    ) -> CeremonyEnvelope {
        sign_envelope(
            config,
            secrets,
            identifier,
            CeremonyPhase::Finalize,
            CeremonyPayloadKind::FinalKeyConfirmation,
            None,
            5_000 + u64::from(identifier),
            encode_final_key_confirmation_payload(confirmation).expect("confirmation payload"),
        )
    }

    fn transcript_record_for(
        config: &GenesisCeremonyConfig,
        phase: CeremonyPhase,
        payload_kind: CeremonyPayloadKind,
        sender_identifier: u16,
        recipient_identifier: Option<u16>,
        sequence: u64,
    ) -> TranscriptEnvelopeRecord {
        let sender_did = if sender_identifier == 0 {
            Did::new("did:exo:transcript-outside").expect("outside did")
        } else {
            config.certifiers[usize::from(sender_identifier - 1)]
                .did
                .clone()
        };
        let recipient_did = recipient_identifier.map(|identifier| {
            if identifier == 0 {
                Did::new("did:exo:transcript-outside-recipient").expect("outside recipient")
            } else {
                config.certifiers[usize::from(identifier - 1)].did.clone()
            }
        });
        let material = format!("{phase:?}:{payload_kind:?}:{sender_identifier}:{sequence}");
        TranscriptEnvelopeRecord {
            phase,
            payload_kind,
            sender_did,
            recipient_did,
            sequence,
            envelope_id: Hash256::digest(material.as_bytes()),
            envelope_hash: Hash256::digest(format!("hash:{material}").as_bytes()),
        }
    }

    fn complete_transcript_records(
        config: &GenesisCeremonyConfig,
    ) -> Vec<TranscriptEnvelopeRecord> {
        let mut records = Vec::new();
        for certifier in &config.certifiers {
            records.push(transcript_record_for(
                config,
                CeremonyPhase::Round1,
                CeremonyPayloadKind::Round1Package,
                certifier.frost_identifier,
                None,
                10,
            ));
        }
        for sender in &config.certifiers {
            for recipient in &config.certifiers {
                if sender.frost_identifier == recipient.frost_identifier {
                    continue;
                }
                records.push(transcript_record_for(
                    config,
                    CeremonyPhase::Round2,
                    CeremonyPayloadKind::Round2EncryptedPackage,
                    sender.frost_identifier,
                    Some(recipient.frost_identifier),
                    1_000
                        + u64::from(sender.frost_identifier) * 100
                        + u64::from(recipient.frost_identifier),
                ));
            }
        }
        records
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
                        payload_bytes: round1_package_bytes(&config, 1),
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

    #[test]
    fn final_key_confirmation_builder_rejects_misbound_key_material() {
        let (config, _) = config_with_secrets();
        let mut rng = StdRng::seed_from_u64(7_001);
        let mut dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let dkg_transcript_hash = Hash256::digest(b"dkg transcript");

        let mut unrostered = participant_output(&mut dkg, 1);
        unrostered.key_package.frost_identifier = 99;
        assert!(
            build_final_key_confirmation(&config, &unrostered, dkg_transcript_hash).is_err(),
            "builder must reject a certifier id outside the ratified roster"
        );

        let mut mismatched = participant_output(&mut dkg, 2);
        mismatched.key_package.frost_identifier = 1;
        assert!(
            build_final_key_confirmation(&config, &mismatched, dkg_transcript_hash).is_err(),
            "builder must bind the public confirmation to the certifier key package"
        );

        let mut missing_share = participant_output(&mut dkg, 3);
        missing_share.public_key_package.verifying_shares.remove(&3);
        assert!(
            build_final_key_confirmation(&config, &missing_share, dkg_transcript_hash).is_err(),
            "builder must reject public key package metadata that omits a rostered share"
        );
        let missing_share_error = certifier_verifying_share_hash(
            &missing_share.public_key_package,
            3,
            RootError::PortalRejected {
                reason: "unit missing share".to_owned(),
            },
        )
        .expect_err("missing share helper must fail closed");
        assert!(
            missing_share_error
                .to_string()
                .contains("unit missing share")
        );
    }

    #[test]
    fn duplicate_dkg_replacements_are_rejected() {
        let (config, secrets) = config_with_secrets();
        let mut store = PortalStore::new(config.clone());
        store
            .submit(sign_envelope(
                &config,
                &secrets,
                1,
                CeremonyPhase::Round1,
                CeremonyPayloadKind::Round1Package,
                None,
                1,
                round1_package_bytes(&config, 1),
            ))
            .expect("first round-one");
        assert!(
            store
                .submit(sign_envelope(
                    &config,
                    &secrets,
                    1,
                    CeremonyPhase::Round1,
                    CeremonyPayloadKind::Round1Package,
                    None,
                    2,
                    round1_package_bytes(&config, 1),
                ))
                .is_err(),
            "a sender cannot replace a broadcast DKG package after acceptance"
        );

        store
            .submit(sign_envelope(
                &config,
                &secrets,
                1,
                CeremonyPhase::Round2,
                CeremonyPayloadKind::Round2EncryptedPackage,
                Some(2),
                101,
                encrypted_payload_with(b"one"),
            ))
            .expect("first round-two");
        assert!(
            store
                .submit(sign_envelope(
                    &config,
                    &secrets,
                    1,
                    CeremonyPhase::Round2,
                    CeremonyPayloadKind::Round2EncryptedPackage,
                    Some(2),
                    102,
                    encrypted_payload_with(b"two"),
                ))
                .is_err(),
            "a sender cannot replace a pairwise DKG package after acceptance"
        );
    }

    #[test]
    fn final_key_confirmation_semantics_reject_every_bound_field() {
        let (config, secrets) = config_with_secrets();
        let mut rng = StdRng::seed_from_u64(7_002);
        let mut dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut store = PortalStore::new(config.clone());
        let dkg_transcript_hash = submit_complete_dkg_transcript(&mut store, &config, &secrets);
        let valid = final_key_confirmation(&config, &mut dkg, 1, dkg_transcript_hash);
        let envelope = final_key_confirmation_envelope(&config, &secrets, 1, &valid);

        let mut bad = valid.clone();
        bad.domain = "wrong-domain".to_owned();
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.schema_version = FINAL_KEY_CONFIRMATION_SCHEMA_VERSION + 1;
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.ceremony_id = "wrong-ceremony".to_owned();
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad_envelope = envelope.clone();
        bad_envelope.sender_did = Did::new("did:exo:not-rostered").expect("outside did");
        let mut bad = valid.clone();
        bad.certifier_did = bad_envelope.sender_did.clone();
        assert!(
            store
                .validate_final_key_confirmation_semantics(&bad_envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.frost_identifier = 2;
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.config_hash = Hash256::digest(b"wrong config hash");
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.dkg_transcript_hash = Hash256::digest(b"wrong dkg transcript");
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.root_public_key_package_hash = Hash256::digest(b"wrong public package");
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid.clone();
        bad.root_public_key_hash = Hash256::digest(b"wrong root key");
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );

        let mut bad = valid;
        bad.certifier_verifying_share_hash = Hash256::digest(b"wrong verifying share");
        assert!(
            store
                .validate_final_key_confirmation_semantics(&envelope, &bad)
                .is_err()
        );
    }

    #[test]
    fn final_key_confirmation_rejects_accepted_set_drift() {
        let (config, secrets) = config_with_secrets();
        let mut rng = StdRng::seed_from_u64(7_003);
        let mut dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut store = PortalStore::new(config.clone());
        let dkg_transcript_hash = submit_complete_dkg_transcript(&mut store, &config, &secrets);
        let valid_one = final_key_confirmation(&config, &mut dkg, 1, dkg_transcript_hash);
        let valid_two = final_key_confirmation(&config, &mut dkg, 2, dkg_transcript_hash);
        let envelope_two = final_key_confirmation_envelope(&config, &secrets, 2, &valid_two);
        let transcript_store = store.clone();

        for mutation in 0..5 {
            let mut store = transcript_store.clone();
            let mut accepted = valid_one.clone();
            if mutation == 0 {
                accepted.config_hash = Hash256::digest(b"accepted config drift");
            } else if mutation == 1 {
                accepted.dkg_transcript_hash = Hash256::digest(b"accepted transcript drift");
            } else if mutation == 2 {
                accepted.public_key_package.root_public_key = b"accepted package drift".to_vec();
            } else if mutation == 3 {
                accepted.root_public_key_package_hash =
                    Hash256::digest(b"accepted package hash drift");
            } else {
                accepted.root_public_key_hash = Hash256::digest(b"accepted root drift");
            }
            store
                .final_key_confirmations
                .insert(valid_one.certifier_did.clone(), accepted);
            assert!(
                store
                    .validate_final_key_confirmation(&envelope_two)
                    .is_err(),
                "accepted-set drift case {mutation} must be rejected"
            );
        }
    }

    #[test]
    fn dkg_transcript_completion_reports_malformed_shapes() {
        let (config, _) = config_with_secrets();
        let store = PortalStore::new(config.clone());
        let complete = complete_transcript_records(&config);

        let mut round1_with_recipient = complete.clone();
        round1_with_recipient[0].recipient_did = Some(config.certifiers[1].did.clone());
        assert!(
            store
                .ensure_dkg_transcript_complete(&round1_with_recipient)
                .is_err()
        );

        let mut duplicate_round1 = complete.clone();
        duplicate_round1[1].sender_did = duplicate_round1[0].sender_did.clone();
        assert!(
            store
                .ensure_dkg_transcript_complete(&duplicate_round1)
                .is_err()
        );

        let round2_start = usize::from(config.max_signers);
        let mut round2_missing_recipient = complete.clone();
        round2_missing_recipient[round2_start].recipient_did = None;
        assert!(
            store
                .ensure_dkg_transcript_complete(&round2_missing_recipient)
                .is_err()
        );

        let mut duplicate_round2 = complete.clone();
        duplicate_round2[round2_start + 1].sender_did =
            duplicate_round2[round2_start].sender_did.clone();
        duplicate_round2[round2_start + 1].recipient_did =
            duplicate_round2[round2_start].recipient_did.clone();
        assert!(
            store
                .ensure_dkg_transcript_complete(&duplicate_round2)
                .is_err()
        );

        let mut non_dkg = complete.clone();
        non_dkg[0].phase = CeremonyPhase::Finalize;
        assert!(store.ensure_dkg_transcript_complete(&non_dkg).is_err());

        let mut missing_round1 = complete.clone();
        missing_round1.remove(0);
        assert!(
            store
                .ensure_dkg_transcript_complete(&missing_round1)
                .is_err()
        );

        let round1_only = complete[..round2_start].to_vec();
        assert!(store.ensure_dkg_transcript_complete(&round1_only).is_err());

        let mut missing_specific_pair = complete;
        let removed = missing_specific_pair.remove(round2_start);
        assert_eq!(removed.sender_did, config.certifiers[0].did);
        missing_specific_pair.push(transcript_record_for(
            &config,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            0,
            Some(2),
            9_999,
        ));
        assert!(
            store
                .ensure_dkg_transcript_complete(&missing_specific_pair)
                .is_err()
        );
    }

    #[test]
    fn root_signing_completion_rejects_missing_rostered_confirmation() {
        let (config, _) = config_with_secrets();
        let mut store = PortalStore::new(config.clone());
        for certifier in &config.certifiers[1..] {
            let confirmation = FinalKeyConfirmation {
                domain: FINAL_KEY_CONFIRMATION_DOMAIN.to_owned(),
                schema_version: FINAL_KEY_CONFIRMATION_SCHEMA_VERSION,
                ceremony_id: config.ceremony_id.clone(),
                certifier_did: certifier.did.clone(),
                frost_identifier: certifier.frost_identifier,
                config_hash: Hash256::digest(b"config"),
                dkg_transcript_hash: Hash256::digest(b"dkg"),
                public_key_package: RootPublicKeyPackage {
                    public_key_package: Vec::new(),
                    root_public_key: Vec::new(),
                    verifying_shares: BTreeMap::new(),
                },
                root_public_key_package_hash: Hash256::digest(b"package"),
                root_public_key_hash: Hash256::digest(b"root"),
                certifier_verifying_share_hash: Hash256::digest(b"share"),
            };
            store
                .final_key_confirmations
                .insert(certifier.did.clone(), confirmation);
        }
        let outside = Did::new("did:exo:outside-confirmation").expect("outside did");
        let mut outside_confirmation = store
            .final_key_confirmations
            .values()
            .next()
            .expect("seed confirmation")
            .clone();
        outside_confirmation.certifier_did = outside.clone();
        store
            .final_key_confirmations
            .insert(outside, outside_confirmation);
        assert!(store.ensure_final_key_confirmations_complete().is_err());
    }

    #[test]
    fn encrypted_round2_payload_validation_rejects_bad_shapes() {
        assert!(validate_encrypted_round2_payload(b"not cbor").is_err());
        assert!(validate_encrypted_round2_payload(&encrypted_payload_with(Vec::new())).is_err());
    }
}
