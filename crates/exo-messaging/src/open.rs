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
    let signable = envelope.signable_bytes();
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
    use exo_core::{Did, crypto::generate_keypair};

    use super::*;
    use crate::{compose::lock_and_send, envelope::ContentType, kex::X25519KeyPair};

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
            false,
            0,
        )
        .expect("lock_and_send");

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");
        assert_eq!(decrypted, plaintext);
    }
}
