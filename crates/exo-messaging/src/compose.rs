//! Compose & Lock — sender-side message encryption.
//!
//! Generates an ephemeral X25519 keypair, performs ECDH with the recipient's
//! public key, derives a symmetric key via HKDF, encrypts the plaintext with
//! XChaCha20-Poly1305, and signs the envelope with the sender's Ed25519 key.

use exo_core::{Did, Hash256, SecretKey, Timestamp};
use exo_identity::vault::VaultEncryptor;
use uuid::Uuid;

use crate::{
    envelope::{ContentType, EncryptedEnvelope},
    error::MessagingError,
    kex::{self, X25519PublicKey},
};

/// The HKDF context string for message encryption key derivation.
const MESSAGE_KEX_CONTEXT: &[u8] = b"vitallock-message-v1";

/// Caller-supplied provenance metadata for an encrypted envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComposeMetadata {
    /// Unique message ID assigned by the caller's deterministic boundary.
    pub id: Uuid,
    /// Non-zero HLC timestamp assigned by the caller's deterministic boundary.
    pub created: Timestamp,
}

impl ComposeMetadata {
    /// Validate caller-supplied envelope metadata.
    pub fn new(id: Uuid, created: Timestamp) -> Result<Self, MessagingError> {
        if id.is_nil() {
            return Err(MessagingError::InvalidEnvelope(
                "message id must be caller-supplied and non-nil".into(),
            ));
        }
        if created == Timestamp::ZERO {
            return Err(MessagingError::InvalidEnvelope(
                "message timestamp must be caller-supplied and non-zero".into(),
            ));
        }
        Ok(Self { id, created })
    }
}

/// Lock & Send: encrypt a message for a specific recipient.
///
/// # Arguments
///
/// * `plaintext` — The message content to encrypt.
/// * `content_type` — Classification of the message content.
/// * `sender_did` — The sender's DID.
/// * `recipient_did` — The recipient's DID.
/// * `sender_signing_key` — The sender's Ed25519 secret key for signing.
/// * `recipient_x25519_public` — The recipient's X25519 public key.
/// * `metadata` — Caller-supplied non-nil ID and non-zero HLC timestamp.
/// * `release_on_death` — Whether to release after sender's death.
/// * `release_delay_hours` — Hours to wait after death verification.
///
/// # Returns
///
/// An `EncryptedEnvelope` ready for transmission/storage.
#[allow(clippy::too_many_arguments)]
// 8 args is the minimum for a sender→recipient envelope with
// death-trigger semantics: plaintext + content_type + sender DID +
// recipient DID + sender key + recipient pubkey + release_on_death +
// release_delay_hours. Grouping into a struct would add boilerplate
// for every single call site with zero safety benefit — every field
// is semantically required and independently typed.
pub fn lock_and_send(
    plaintext: &[u8],
    content_type: ContentType,
    sender_did: &Did,
    recipient_did: &Did,
    sender_signing_key: &SecretKey,
    recipient_x25519_public: &X25519PublicKey,
    metadata: ComposeMetadata,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<EncryptedEnvelope, MessagingError> {
    // 1. Generate ephemeral X25519 keypair
    let ephemeral = kex::generate_ephemeral();

    // 2. ECDH: derive shared symmetric key
    let shared_key = kex::derive_shared_key(
        &ephemeral.secret,
        recipient_x25519_public,
        MESSAGE_KEX_CONTEXT,
    )?;

    // 3. Encrypt plaintext with XChaCha20-Poly1305
    //    Associated data = recipient DID (binds ciphertext to intended recipient)
    let encryptor = VaultEncryptor::from_key(shared_key);
    let ciphertext = encryptor
        .encrypt(plaintext, recipient_did.as_str().as_bytes())
        .map_err(|e| MessagingError::EncryptionFailed(e.to_string()))?;

    // 4. Hash plaintext for post-decrypt integrity check
    let plaintext_hash = Hash256::digest(plaintext);

    // 5. Build envelope (without signature first)
    let mut envelope = EncryptedEnvelope {
        id: metadata.id.to_string(),
        sender_did: sender_did.clone(),
        recipient_did: recipient_did.clone(),
        ephemeral_public_key: ephemeral.public.0,
        ciphertext,
        content_type,
        signature: exo_core::Signature::empty(),
        plaintext_hash,
        release_on_death,
        release_delay_hours,
        created: metadata.created,
    };

    // 6. Sign the envelope
    let signable = envelope.signing_payload()?;
    let signature = exo_core::crypto::sign(&signable, sender_signing_key);
    envelope.signature = signature;

    Ok(envelope)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::{Timestamp, crypto::generate_keypair};
    use uuid::Uuid;

    use super::*;

    fn metadata() -> ComposeMetadata {
        ComposeMetadata::new(
            Uuid::parse_str("018f7a96-8ad0-7c4f-8e0f-111111111111").unwrap(),
            Timestamp::new(7_000, 2),
        )
        .expect("valid compose metadata")
    }

    #[test]
    fn lock_and_send_produces_valid_envelope() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let recipient_kp = kex::X25519KeyPair::generate();
        let metadata = metadata();

        let envelope = lock_and_send(
            b"my secret password: hunter2",
            ContentType::Password,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata,
            false,
            0,
        )
        .expect("lock_and_send");

        assert_eq!(
            envelope.id,
            "018f7a96-8ad0-7c4f-8e0f-111111111111".to_string()
        );
        assert_eq!(envelope.created, Timestamp::new(7_000, 2));
        assert_eq!(envelope.sender_did, sender_did);
        assert_eq!(envelope.recipient_did, recipient_did);
        assert_eq!(envelope.content_type, ContentType::Password);
        assert!(!envelope.ciphertext.is_empty());
        assert!(!envelope.release_on_death);
        assert_ne!(envelope.signature, exo_core::Signature::empty());
    }

    #[test]
    fn afterlife_message_flags() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let recipient_kp = kex::X25519KeyPair::generate();
        let metadata = metadata();

        let envelope = lock_and_send(
            b"Read this after I'm gone",
            ContentType::AfterlifeMessage,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata,
            true,
            72,
        )
        .expect("lock_and_send");

        assert!(envelope.release_on_death);
        assert_eq!(envelope.release_delay_hours, 72);
        assert_eq!(envelope.content_type, ContentType::AfterlifeMessage);
    }

    #[test]
    fn compose_metadata_rejects_nil_message_id() {
        let result = ComposeMetadata::new(Uuid::nil(), Timestamp::new(7_000, 2));

        assert!(
            matches!(result, Err(MessagingError::InvalidEnvelope(reason)) if reason.contains("message id"))
        );
    }

    #[test]
    fn compose_metadata_rejects_zero_timestamp() {
        let result = ComposeMetadata::new(
            Uuid::parse_str("018f7a96-8ad0-7c4f-8e0f-222222222222").unwrap(),
            Timestamp::ZERO,
        );

        assert!(
            matches!(result, Err(MessagingError::InvalidEnvelope(reason)) if reason.contains("timestamp"))
        );
    }

    #[test]
    fn compose_path_does_not_fabricate_envelope_metadata() {
        let source = include_str!("compose.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("production section");

        assert!(
            !production.contains("Uuid::new_v4"),
            "compose production path must not fabricate message IDs"
        );
        let forbidden_clock = ["HybridClock", "::new()"].concat();
        assert!(
            !production.contains(&forbidden_clock),
            "compose production path must not fabricate HLC timestamps"
        );
    }
}
