//! Open & Verify — recipient-side message decryption.
//!
//! Derives the shared secret from the ephemeral public key + recipient's
//! X25519 secret key, decrypts the ciphertext, verifies the sender's
//! Ed25519 signature, and checks the plaintext integrity hash.

use exo_core::{Hash256, PublicKey, crypto};
use exo_identity::vault::VaultEncryptor;

use crate::{
    envelope::EncryptedEnvelope,
    error::MessagingError,
    kex::{self, X25519PublicKey, X25519SecretKey},
};

/// The HKDF context string — must match `compose::MESSAGE_KEX_CONTEXT`.
const MESSAGE_KEX_CONTEXT: &[u8] = b"vitallock-message-v1";

/// Unlock a received message: decrypt and verify.
///
/// # Arguments
///
/// * `envelope` — The encrypted message envelope.
/// * `recipient_x25519_secret` — The recipient's X25519 secret key.
/// * `sender_ed25519_public` — The sender's Ed25519 public key (for signature verification).
///
/// # Returns
///
/// The decrypted plaintext bytes.
pub fn unlock(
    envelope: &EncryptedEnvelope,
    recipient_x25519_secret: &X25519SecretKey,
    sender_ed25519_public: &PublicKey,
) -> Result<Vec<u8>, MessagingError> {
    // 1. Verify the sender's signature
    let signable = envelope.signing_payload()?;
    if !crypto::verify(&signable, &envelope.signature, sender_ed25519_public) {
        return Err(MessagingError::SignatureVerificationFailed);
    }

    // 2. ECDH: derive shared symmetric key from ephemeral public + our secret
    let ephemeral_pub = X25519PublicKey::from_bytes(envelope.ephemeral_public_key);
    let shared_key =
        kex::derive_shared_key(recipient_x25519_secret, &ephemeral_pub, MESSAGE_KEX_CONTEXT)?;

    // 3. Decrypt with XChaCha20-Poly1305
    //    Associated data = recipient DID (must match what was used during encryption)
    let encryptor = VaultEncryptor::from_key(shared_key);
    let plaintext = encryptor
        .decrypt(
            &envelope.ciphertext,
            envelope.recipient_did.as_str().as_bytes(),
        )
        .map_err(|_| MessagingError::DecryptionFailed)?;

    // 4. Verify plaintext integrity hash
    let computed_hash = Hash256::digest(&plaintext);
    if computed_hash != envelope.plaintext_hash {
        return Err(MessagingError::InvalidEnvelope(
            "plaintext hash mismatch".into(),
        ));
    }

    Ok(plaintext)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::{Did, Timestamp, crypto::generate_keypair};
    use uuid::Uuid;

    use super::*;
    use crate::{
        compose::{ComposeMetadata, lock_and_send},
        envelope::{ContentType, EncryptedEnvelope},
        kex::X25519KeyPair,
    };

    fn metadata(suffix: u128) -> ComposeMetadata {
        ComposeMetadata::new(Uuid::from_u128(suffix), Timestamp::new(8_000, 0))
            .expect("valid compose metadata")
    }

    fn legacy_signable_bytes(envelope: &EncryptedEnvelope) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(envelope.id.as_bytes());
        buf.extend_from_slice(envelope.sender_did.as_str().as_bytes());
        buf.extend_from_slice(envelope.recipient_did.as_str().as_bytes());
        buf.extend_from_slice(&envelope.ephemeral_public_key);
        buf.extend_from_slice(&envelope.ciphertext);
        buf.extend_from_slice(&[u8::from(envelope.content_type)]);
        buf.extend_from_slice(envelope.plaintext_hash.as_bytes());
        buf.extend_from_slice(&[u8::from(envelope.release_on_death)]);
        buf.extend_from_slice(&envelope.release_delay_hours.to_le_bytes());
        buf.extend_from_slice(&envelope.created.physical_ms.to_le_bytes());
        buf.extend_from_slice(&envelope.created.logical.to_le_bytes());
        buf
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = X25519KeyPair::generate();

        let plaintext = b"super secret password: correcthorsebatterystaple";

        let envelope = lock_and_send(
            plaintext,
            ContentType::Password,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1101),
            false,
            0,
        )
        .expect("lock_and_send");

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = X25519KeyPair::generate();
        let wrong_kp = X25519KeyPair::generate();

        let envelope = lock_and_send(
            b"secret",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1102),
            false,
            0,
        )
        .expect("lock_and_send");

        let result = unlock(&envelope, &wrong_kp.secret, &sender_pk);
        assert!(result.is_err(), "wrong key should fail decryption");
    }

    #[test]
    fn wrong_sender_signature_fails() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let (wrong_pk, _) = generate_keypair(); // different sender's public key
        let recipient_kp = X25519KeyPair::generate();

        let envelope = lock_and_send(
            b"secret",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1103),
            false,
            0,
        )
        .expect("lock_and_send");

        let result = unlock(&envelope, &recipient_kp.secret, &wrong_pk);
        assert!(
            matches!(result, Err(MessagingError::SignatureVerificationFailed)),
            "wrong sender key should fail signature verification"
        );
    }

    #[test]
    fn unlock_rejects_legacy_byte_concat_signature() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = X25519KeyPair::generate();

        let mut envelope = lock_and_send(
            b"secret",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1121),
            false,
            0,
        )
        .expect("lock_and_send");

        envelope.signature = exo_core::crypto::sign(&legacy_signable_bytes(&envelope), &sender_sk);

        let result = unlock(&envelope, &recipient_kp.secret, &sender_pk);
        assert!(
            matches!(result, Err(MessagingError::SignatureVerificationFailed)),
            "legacy byte-concat signatures must not verify"
        );
    }

    #[test]
    fn afterlife_message_round_trip() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:family").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = X25519KeyPair::generate();

        let plaintext = b"I love you all. The safe combination is 42-17-93.";

        let envelope = lock_and_send(
            plaintext,
            ContentType::AfterlifeMessage,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1104),
            true,
            72,
        )
        .expect("lock_and_send");

        assert!(envelope.release_on_death);
        assert_eq!(envelope.release_delay_hours, 72);

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_message_round_trip() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = X25519KeyPair::generate();

        let envelope = lock_and_send(
            b"",
            ContentType::Text,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1105),
            false,
            0,
        )
        .expect("lock_and_send");

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_message_round_trip() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = X25519KeyPair::generate();

        let plaintext = vec![0xab_u8; 100_000]; // 100 KB

        let envelope = lock_and_send(
            &plaintext,
            ContentType::Attachment,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1106),
            false,
            0,
        )
        .expect("lock_and_send");

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");
        assert_eq!(decrypted, plaintext);
    }
}
