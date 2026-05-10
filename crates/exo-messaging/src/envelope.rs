// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Encrypted message envelope — the wire format for VitalLock messages.
//!
//! An `EncryptedEnvelope` contains everything a recipient needs to decrypt
//! and verify a message: the ephemeral public key, ciphertext, sender DID,
//! recipient DID, content type, and Ed25519 signature.

use std::fmt;

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use crate::error::MessagingError;

/// Domain tag for encrypted-envelope signatures.
pub const ENVELOPE_SIGNING_DOMAIN: &str = "exo.messaging.envelope.v1";
const ENVELOPE_SIGNING_SCHEMA_VERSION: u16 = 1;
pub const MAX_ENVELOPE_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;

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
/// `#[repr(u8)]` with explicit discriminants so the wire-format byte value is
/// stable and independent of declaration order. The `From<ContentType> for u8`
/// implementation below repeats those discriminants explicitly so the wire
/// mapping stays obvious without relying on a numeric cast.
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
        match ct {
            ContentType::Text => 0,
            ContentType::Password => 1,
            ContentType::Secret => 2,
            ContentType::AfterlifeMessage => 3,
            ContentType::Template => 4,
            ContentType::Attachment => 5,
        }
    }
}

/// An encrypted message envelope — the complete wire format.
///
/// The ciphertext is produced by X25519 ECDH + HKDF + XChaCha20-Poly1305.
/// Format: `[24-byte nonce][ciphertext][16-byte Poly1305 tag]`
/// (same layout as `VaultEncryptor` in `exo-identity`).
#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(deserialize_with = "deserialize_bounded_ciphertext")]
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

impl fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedEnvelope")
            .field("id", &self.id)
            .field("sender_did", &self.sender_did)
            .field("recipient_did", &self.recipient_did)
            .field("ephemeral_public_key", &"<redacted>")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("content_type", &self.content_type)
            .field("release_on_death", &self.release_on_death)
            .field("release_delay_hours", &self.release_delay_hours)
            .field("created", &self.created)
            .finish()
    }
}

fn deserialize_bounded_ciphertext<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedCiphertextVisitor;

    impl<'de> Visitor<'de> for BoundedCiphertextVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "ciphertext no longer than {MAX_ENVELOPE_CIPHERTEXT_LEN} bytes"
            )
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            validate_ciphertext_len(value.len()).map_err(E::custom)?;
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            validate_ciphertext_len(value.len()).map_err(E::custom)?;
            Ok(value)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if let Some(size_hint) = seq.size_hint() {
                validate_ciphertext_len(size_hint).map_err(de::Error::custom)?;
            }

            let capacity = seq
                .size_hint()
                .unwrap_or(0)
                .min(MAX_ENVELOPE_CIPHERTEXT_LEN);
            let mut ciphertext = Vec::with_capacity(capacity);
            while let Some(byte) = seq.next_element::<u8>()? {
                if ciphertext.len() == MAX_ENVELOPE_CIPHERTEXT_LEN {
                    return Err(de::Error::custom(format!(
                        "ciphertext length exceeds {MAX_ENVELOPE_CIPHERTEXT_LEN} bytes"
                    )));
                }
                ciphertext.push(byte);
            }
            Ok(ciphertext)
        }
    }

    deserializer.deserialize_byte_buf(BoundedCiphertextVisitor)
}

fn validate_ciphertext_len(len: usize) -> Result<(), String> {
    if len > MAX_ENVELOPE_CIPHERTEXT_LEN {
        return Err(format!(
            "ciphertext length {len} exceeds {MAX_ENVELOPE_CIPHERTEXT_LEN} bytes"
        ));
    }
    Ok(())
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

    #[test]
    fn content_type_wire_conversion_uses_explicit_mapping() {
        assert_eq!(u8::from(ContentType::Text), 0);
        assert_eq!(u8::from(ContentType::Password), 1);
        assert_eq!(u8::from(ContentType::Secret), 2);
        assert_eq!(u8::from(ContentType::AfterlifeMessage), 3);
        assert_eq!(u8::from(ContentType::Template), 4);
        assert_eq!(u8::from(ContentType::Attachment), 5);

        let source = include_str!("envelope.rs");
        let conversion_source = source
            .split("fn from(ct: ContentType) -> Self")
            .nth(1)
            .expect("content type conversion exists")
            .split("/// An encrypted message envelope")
            .next()
            .expect("content type conversion ends before envelope struct");
        let forbidden_cast = ["ct", " as ", "u8"].concat();

        assert!(
            !conversion_source.contains("clippy::as_conversions"),
            "content type wire conversion must not suppress checked conversion lints"
        );
        assert!(
            !conversion_source.contains(&forbidden_cast),
            "content type wire conversion must not rely on an unchecked numeric cast"
        );
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

    #[test]
    fn encrypted_envelope_debug_redacts_ciphertext_and_signature() {
        let envelope = sample_envelope();

        let debug = format!("{envelope:?}");

        assert!(debug.contains("EncryptedEnvelope"));
        assert!(debug.contains("ciphertext_len"));
        assert!(!debug.contains("ciphertext: [1, 1, 2, 3, 5, 8]"));
        assert!(!debug.contains("signature:"));
        assert!(!debug.contains("plaintext_hash:"));
    }

    #[test]
    fn encrypted_envelope_deserialization_rejects_oversized_ciphertext() {
        let mut envelope = sample_envelope();
        envelope.ciphertext = vec![0xab; 16 * 1024 * 1024 + 1];
        let mut encoded = Vec::new();
        if let Err(error) = ciborium::into_writer(&envelope, &mut encoded) {
            panic!("encode oversized envelope failed: {error}");
        }

        let decoded: Result<EncryptedEnvelope, _> = ciborium::from_reader(&encoded[..]);

        assert!(
            decoded.is_err(),
            "oversized ciphertext must be rejected during envelope deserialization"
        );
    }
}
