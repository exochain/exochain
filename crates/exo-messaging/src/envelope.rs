//! Encrypted message envelope — the wire format for VitalLock messages.
//!
//! An `EncryptedEnvelope` contains everything a recipient needs to decrypt
//! and verify a message: the ephemeral public key, ciphertext, sender DID,
//! recipient DID, content type, and Ed25519 signature.

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

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
    /// Compute the canonical bytes for signing (everything except the signature field).
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.id.as_bytes());
        buf.extend_from_slice(self.sender_did.as_str().as_bytes());
        buf.extend_from_slice(self.recipient_did.as_str().as_bytes());
        buf.extend_from_slice(&self.ephemeral_public_key);
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&[u8::from(self.content_type)]);
        buf.extend_from_slice(self.plaintext_hash.as_bytes());
        buf.extend_from_slice(&[u8::from(self.release_on_death)]);
        buf.extend_from_slice(&self.release_delay_hours.to_le_bytes());
        buf.extend_from_slice(&self.created.physical_ms.to_le_bytes());
        buf.extend_from_slice(&self.created.logical.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
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
}
