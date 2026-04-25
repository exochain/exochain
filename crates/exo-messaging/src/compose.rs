//! Compose & Lock — sender-side message encryption.
//!
//! Generates an ephemeral X25519 keypair, performs ECDH with the recipient's
//! public key, derives a symmetric key via HKDF, encrypts the plaintext with
//! XChaCha20-Poly1305, and signs the envelope with the sender's Ed25519 key.

use exo_core::{Did, Hash256, SecretKey, hlc::HybridClock};
use exo_identity::vault::VaultEncryptor;
use uuid::Uuid;

use crate::{
    envelope::{ContentType, EncryptedEnvelope},
    error::MessagingError,
    kex::{self, X25519PublicKey},
};

/// The HKDF context string for message encryption key derivation.
const MESSAGE_KEX_CONTEXT: &[u8] = b"vitallock-message-v1";

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

    // 5. Generate message ID and timestamp
    let id = Uuid::new_v4().to_string();
    let mut clock = HybridClock::new();
    let created = clock.now();

    // 6. Build envelope (without signature first)
    let mut envelope = EncryptedEnvelope {
        id,
        sender_did: sender_did.clone(),
        recipient_did: recipient_did.clone(),
        ephemeral_public_key: ephemeral.public.0,
        ciphertext,
        content_type,
        signature: exo_core::Signature::empty(),
        plaintext_hash,
        release_on_death,
        release_delay_hours,
        created,
    };

    // 7. Sign the envelope
    let signable = envelope.signable_bytes();
    let signature = exo_core::crypto::sign(&signable, sender_signing_key);
    envelope.signature = signature;

    Ok(envelope)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::crypto::generate_keypair;

    use super::*;

    #[test]
    fn lock_and_send_produces_valid_envelope() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let recipient_kp = kex::X25519KeyPair::generate();

        let envelope = lock_and_send(
            b"my secret password: hunter2",
            ContentType::Password,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            false,
            0,
        )
        .expect("lock_and_send");

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

        let envelope = lock_and_send(
            b"Read this after I'm gone",
            ContentType::AfterlifeMessage,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            true,
            72,
        )
        .expect("lock_and_send");

        assert!(envelope.release_on_death);
        assert_eq!(envelope.release_delay_hours, 72);
        assert_eq!(envelope.content_type, ContentType::AfterlifeMessage);
    }
}
