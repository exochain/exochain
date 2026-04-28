//! Encrypted message envelope — the wire format for VitalLock messages.
//!
//! An `EncryptedEnvelope` contains everything a recipient needs to decrypt
//! and verify a message: the ephemeral public key, ciphertext, sender DID,
//! recipient DID, content type, and Ed25519 signature.

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::MessagingError;

/// Domain tag for encrypted-envelope signatures.
pub const ENVELOPE_SIGNING_DOMAIN: &str = "exo.messaging.envelope.v1";
const ENVELOPE_SIGNING_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct EnvelopeSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    id: &'a str,
    sender_did: &'a Did,
    recipient_did: &'a Did,
    ephemeral_public_key: &'a [u8; 32],
    ciphertext: &'a [u8],
    content_type: u8,
    plaintext_hash: &'a Hash256,
    release_on_death: bool,
    release_delay_hours: u32,
    created: &'a Timestamp,
}

/// The type of content in the encrypted message.
///
/// `#[repr(u8)]` with explicit discriminants so the wire-format byte
/// value is stable and independent of declaration order. See
/// `impl From<ContentType> for u8` below — that's the canonical
/// widening the envelope serializer uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentType {
    /// General text message.
    Text = 0,
    /// Password or credential.
    Password = 1,
    /// Generic secret (API keys, 2FA seeds, etc.).
    Secret = 2,
    /// Message to be delivered after sender's death.
    AfterlifeMessage = 3,
    /// Pre-populated template message.
    Template = 4,
    /// Binary attachment (file).
    Attachment = 5,
}

impl From<ContentType> for u8 {
    fn from(ct: ContentType) -> Self {
        // `ContentType` is `#[repr(u8)]` with explicit discriminants,
        // so this is a well-defined no-op widening — the only place
        // we use `as` and it's canonical for the repr.
        #[allow(clippy::as_conversions)]
        {
            ct as u8
        }
    }
}

/// An encrypted message envelope — the complete wire format.
///
/// The ciphertext is produced by X25519 ECDH + HKDF + XChaCha20-Poly1305.
/// Format: `[24-byte nonce][ciphertext][16-byte Poly1305 tag]`
/// (same layout as `VaultEncryptor` in `exo-identity`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Unique message ID.
    pub id: String,
    /// Sender's DID.
    pub sender_did: Did,
    /// Recipient's DID.
    pub recipient_did: Did,
    /// Ephemeral X25519 public key used for this message's ECDH.
    pub ephemeral_public_key: [u8; 32],
    /// Encrypted payload: `[nonce][ciphertext][tag]`.
    pub ciphertext: Vec<u8>,
    /// Content type classification.
    pub content_type: ContentType,
    /// Ed25519 signature over the canonical envelope bytes (excl. signature field).
    pub signature: Signature,
    /// Blake3 hash of the plaintext (for integrity verification after decrypt).
    pub plaintext_hash: Hash256,
    /// Whether this message should be released after the sender's death.
    pub release_on_death: bool,
    /// Delay in hours after death verification before release (0 = immediate).
    pub release_delay_hours: u32,
    /// Creation timestamp (hybrid logical clock).
    pub created: Timestamp,
}

impl EncryptedEnvelope {
    /// Compute the domain-separated canonical CBOR payload for signing.
    ///
    /// The payload covers every envelope field except the signature itself.
    ///
    /// # Errors
    ///
    /// Returns [`MessagingError::EnvelopeSigningPayloadEncoding`] if the CBOR
    /// encoder rejects the payload.
    pub fn signing_payload(&self) -> Result<Vec<u8>, MessagingError> {
        let payload = EnvelopeSigningPayload {
            domain: ENVELOPE_SIGNING_DOMAIN,
            schema_version: ENVELOPE_SIGNING_SCHEMA_VERSION,
            id: &self.id,
            sender_did: &self.sender_did,
            recipient_did: &self.recipient_did,
            ephemeral_public_key: &self.ephemeral_public_key,
            ciphertext: &self.ciphertext,
            content_type: u8::from(self.content_type),
            plaintext_hash: &self.plaintext_hash,
            release_on_death: self.release_on_death,
            release_delay_hours: self.release_delay_hours,
            created: &self.created,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)
            .map_err(|e| MessagingError::EnvelopeSigningPayloadEncoding(e.to_string()))?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[test]
    fn content_type_serde_round_trip() {
        for ct in [
            ContentType::Text,
            ContentType::Password,
            ContentType::Secret,
            ContentType::AfterlifeMessage,
            ContentType::Template,
            ContentType::Attachment,
        ] {
            let json = serde_json::to_string(&ct).unwrap();
            let recovered: ContentType = serde_json::from_str(&json).unwrap();
            assert_eq!(ct, recovered);
        }
    }

    #[derive(Debug, Deserialize)]
    struct DecodedEnvelopeSigningPayload {
        domain: String,
        schema_version: u16,
        id: String,
        sender_did: Did,
        recipient_did: Did,
        ephemeral_public_key: [u8; 32],
        ciphertext: Vec<u8>,
        content_type: u8,
        plaintext_hash: Hash256,
        release_on_death: bool,
        release_delay_hours: u32,
        created: Timestamp,
    }

    fn sample_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            id: "018f7a96-8ad0-7c4f-8e0f-111111111199".to_string(),
            sender_did: Did::new("did:exo:alice").unwrap(),
            recipient_did: Did::new("did:exo:bob").unwrap(),
            ephemeral_public_key: [7; 32],
            ciphertext: vec![1, 1, 2, 3, 5, 8],
            content_type: ContentType::Secret,
            signature: Signature::empty(),
            plaintext_hash: Hash256::digest(b"plaintext"),
            release_on_death: true,
            release_delay_hours: 72,
            created: Timestamp::new(9_000, 3),
        }
    }

    #[test]
    fn envelope_signing_payload_is_domain_separated_cbor() {
        let envelope = sample_envelope();
        let payload = envelope
            .signing_payload()
            .expect("canonical envelope signing payload");
        let decoded: DecodedEnvelopeSigningPayload =
            ciborium::from_reader(&payload[..]).expect("decode envelope signing payload");

        assert_eq!(decoded.domain, "exo.messaging.envelope.v1");
        assert_eq!(decoded.schema_version, 1);
        assert_eq!(decoded.id, envelope.id);
        assert_eq!(decoded.sender_did, envelope.sender_did);
        assert_eq!(decoded.recipient_did, envelope.recipient_did);
        assert_eq!(decoded.ephemeral_public_key, envelope.ephemeral_public_key);
        assert_eq!(decoded.ciphertext, envelope.ciphertext);
        assert_eq!(decoded.content_type, u8::from(envelope.content_type));
        assert_eq!(decoded.plaintext_hash, envelope.plaintext_hash);
        assert_eq!(decoded.release_on_death, envelope.release_on_death);
        assert_eq!(decoded.release_delay_hours, envelope.release_delay_hours);
        assert_eq!(decoded.created, envelope.created);
    }
}
