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

//! Open & Verify — recipient-side message decryption.
//!
//! Derives the shared secret from the ephemeral public key + recipient's
//! X25519 secret key, decrypts the ciphertext, and verifies the sender's
//! Ed25519 signature over the encrypted envelope.

use exo_core::{PublicKey, crypto};
use exo_identity::vault::VaultEncryptor;

use crate::{
    envelope::{
        EncryptedEnvelope, KDF_VERSION_LEGACY_UNSALTED, KDF_VERSION_TRANSCRIPT_SALTED,
        explicit_kdf_version,
    },
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
    let ephemeral_pub = X25519PublicKey::from_bytes(envelope.ephemeral_public_key)?;
    let explicit_kdf_version = explicit_kdf_version(envelope)?;

    match explicit_kdf_version {
        Some(KDF_VERSION_TRANSCRIPT_SALTED) => {
            let shared_key = kex::derive_shared_key(
                recipient_x25519_secret,
                &ephemeral_pub,
                MESSAGE_KEX_CONTEXT,
            )?;
            decrypt_with_key(envelope, shared_key)
        }
        Some(KDF_VERSION_LEGACY_UNSALTED) => {
            let shared_key = kex::derive_shared_key_legacy_unsalted(
                recipient_x25519_secret,
                &ephemeral_pub,
                MESSAGE_KEX_CONTEXT,
            )?;
            decrypt_with_key(envelope, shared_key)
        }
        None => unlock_unversioned_envelope(envelope, recipient_x25519_secret, &ephemeral_pub),
        Some(_) => Err(MessagingError::InvalidEnvelope(
            "unsupported envelope KDF version".to_owned(),
        )),
    }
}

fn unlock_unversioned_envelope(
    envelope: &EncryptedEnvelope,
    recipient_x25519_secret: &X25519SecretKey,
    ephemeral_pub: &X25519PublicKey,
) -> Result<Vec<u8>, MessagingError> {
    let legacy_key = kex::derive_shared_key_legacy_unsalted(
        recipient_x25519_secret,
        ephemeral_pub,
        MESSAGE_KEX_CONTEXT,
    )?;
    match decrypt_with_key(envelope, legacy_key) {
        Ok(plaintext) => Ok(plaintext),
        Err(MessagingError::DecryptionFailed) => {
            let salted_key = kex::derive_shared_key(
                recipient_x25519_secret,
                ephemeral_pub,
                MESSAGE_KEX_CONTEXT,
            )?;
            decrypt_with_key(envelope, salted_key)
        }
        Err(error) => Err(error),
    }
}

fn decrypt_with_key(
    envelope: &EncryptedEnvelope,
    shared_key: [u8; 32],
) -> Result<Vec<u8>, MessagingError> {
    let encryptor = VaultEncryptor::from_key(shared_key);
    encryptor
        .decrypt(
            &envelope.ciphertext,
            envelope.recipient_did.as_str().as_bytes(),
        )
        .map_err(|_| MessagingError::DecryptionFailed)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::{Did, Signature, Timestamp, crypto::generate_keypair};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use uuid::Uuid;
    use x25519_dalek::{PublicKey as DalekX25519PublicKey, StaticSecret};

    use super::*;
    use crate::{
        compose::{ComposeMetadata, lock_and_send_with_ephemeral},
        envelope::{ContentType, EncryptedEnvelope},
        kex::X25519KeyPair,
    };

    fn metadata(suffix: u128) -> ComposeMetadata {
        ComposeMetadata::new(Uuid::from_u128(suffix), Timestamp::new(8_000, 0))
            .expect("valid compose metadata")
    }

    fn x25519_keypair(seed: u8) -> X25519KeyPair {
        X25519KeyPair::from_secret_bytes([seed; 32]).expect("valid deterministic X25519 keypair")
    }

    fn legacy_unsalted_shared_key(
        ephemeral_secret_seed: u8,
        recipient_public: &X25519PublicKey,
    ) -> [u8; 32] {
        let secret = StaticSecret::from([ephemeral_secret_seed; 32]);
        let public = DalekX25519PublicKey::from(*recipient_public.as_bytes());
        let shared_secret = secret.diffie_hellman(&public);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(MESSAGE_KEX_CONTEXT, &mut okm)
            .expect("legacy HKDF expands");
        okm
    }

    fn legacy_signable_bytes(envelope: &EncryptedEnvelope) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(envelope.id.as_bytes());
        buf.extend_from_slice(envelope.sender_did.as_str().as_bytes());
        buf.extend_from_slice(envelope.recipient_did.as_str().as_bytes());
        buf.extend_from_slice(&envelope.ephemeral_public_key);
        buf.extend_from_slice(&envelope.ciphertext);
        buf.extend_from_slice(&[u8::from(envelope.content_type)]);
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
        let recipient_kp = x25519_keypair(0x41);
        let ephemeral_kp = x25519_keypair(0x51);

        let plaintext = b"super secret password: correcthorsebatterystaple";

        let envelope = lock_and_send_with_ephemeral(
            plaintext,
            ContentType::Password,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1101),
            false,
            0,
        )
        .expect("lock_and_send");

        assert_eq!(envelope.kdf_version, Some(KDF_VERSION_TRANSCRIPT_SALTED));

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unlock_accepts_legacy_unsalted_unversioned_envelope() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x48);
        let ephemeral_kp = x25519_keypair(0x58);
        let plaintext = b"legacy encrypted message";

        let legacy_key = legacy_unsalted_shared_key(0x58, &recipient_kp.public);
        let encryptor = VaultEncryptor::from_key(legacy_key);
        let ciphertext = encryptor
            .encrypt_with_nonce(plaintext, recipient_did.as_str().as_bytes(), &[0x7c_u8; 24])
            .expect("legacy encrypt");

        let mut envelope = EncryptedEnvelope {
            id: "018f7a96-8ad0-7c4f-8e0f-111111111131".to_owned(),
            sender_did,
            recipient_did,
            ephemeral_public_key: *ephemeral_kp.public.as_bytes(),
            kdf_version: None,
            ciphertext,
            content_type: ContentType::Secret,
            signature: Signature::empty(),
            release_on_death: false,
            release_delay_hours: 0,
            created: Timestamp::new(8_000, 0),
        };
        envelope.signature =
            exo_core::crypto::sign(&envelope.signing_payload().unwrap(), &sender_sk);

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unlock_accepts_unversioned_transcript_salted_transition_envelope() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x49);
        let ephemeral_kp = x25519_keypair(0x59);
        let plaintext = b"transition encrypted message";

        let mut envelope = lock_and_send_with_ephemeral(
            plaintext,
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1132),
            false,
            0,
        )
        .expect("lock_and_send");
        envelope.kdf_version = None;
        envelope.signature =
            exo_core::crypto::sign(&envelope.signing_payload().unwrap(), &sender_sk);

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unlock_rejects_explicit_kdf_version_tampering() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x4a);
        let ephemeral_kp = x25519_keypair(0x5a);

        let mut envelope = lock_and_send_with_ephemeral(
            b"kdf tamper",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1133),
            false,
            0,
        )
        .expect("lock_and_send");
        envelope.kdf_version = Some(KDF_VERSION_LEGACY_UNSALTED);

        let result = unlock(&envelope, &recipient_kp.secret, &sender_pk);

        assert!(matches!(
            result,
            Err(MessagingError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn unlock_rejects_unknown_explicit_kdf_version() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x4b);
        let ephemeral_kp = x25519_keypair(0x5b);

        let mut envelope = lock_and_send_with_ephemeral(
            b"kdf unknown",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1134),
            false,
            0,
        )
        .expect("lock_and_send");
        envelope.kdf_version = Some(99);

        let result = unlock(&envelope, &recipient_kp.secret, &sender_pk);

        assert!(
            matches!(result, Err(MessagingError::InvalidEnvelope(reason)) if reason.contains("unsupported envelope KDF version 99"))
        );
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x42);
        let wrong_kp = x25519_keypair(0x52);
        let ephemeral_kp = x25519_keypair(0x62);

        let envelope = lock_and_send_with_ephemeral(
            b"secret",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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
        let recipient_kp = x25519_keypair(0x43);
        let ephemeral_kp = x25519_keypair(0x53);

        let envelope = lock_and_send_with_ephemeral(
            b"secret",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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
        let recipient_kp = x25519_keypair(0x44);
        let ephemeral_kp = x25519_keypair(0x54);

        let mut envelope = lock_and_send_with_ephemeral(
            b"secret",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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
        let recipient_kp = x25519_keypair(0x45);
        let ephemeral_kp = x25519_keypair(0x55);

        let plaintext = b"I love you all. The safe combination is 42-17-93.";

        let envelope = lock_and_send_with_ephemeral(
            plaintext,
            ContentType::AfterlifeMessage,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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
        let recipient_kp = x25519_keypair(0x46);
        let ephemeral_kp = x25519_keypair(0x56);

        let envelope = lock_and_send_with_ephemeral(
            b"",
            ContentType::Text,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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
        let recipient_kp = x25519_keypair(0x47);
        let ephemeral_kp = x25519_keypair(0x57);

        let plaintext = vec![0xab_u8; 100_000]; // 100 KB

        let envelope = lock_and_send_with_ephemeral(
            &plaintext,
            ContentType::Attachment,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(0x018f_7a96_8ad0_7c4f_8e0f_1111_1111_1106),
            false,
            0,
        )
        .expect("lock_and_send");

        let decrypted = unlock(&envelope, &recipient_kp.secret, &sender_pk).expect("unlock");
        assert_eq!(decrypted, plaintext);
    }
}
