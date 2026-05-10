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

//! Compose & Lock — sender-side message encryption.
//!
//! Requires caller-supplied ephemeral X25519 key material, performs ECDH with
//! the recipient's public key, derives a symmetric key via HKDF, encrypts the
//! plaintext with XChaCha20-Poly1305, and signs the envelope with the sender's
//! Ed25519 key.

use exo_core::{Did, Hash256, PublicKey, SecretKey, Signature, Timestamp};
use exo_identity::vault::{VAULT_NONCE_SIZE, VaultEncryptor};
use uuid::Uuid;

use crate::{
    envelope::{ContentType, EncryptedEnvelope},
    error::MessagingError,
    kex::{self, X25519KeyPair, X25519PublicKey},
};

/// The HKDF context string for message encryption key derivation.
const MESSAGE_KEX_CONTEXT: &[u8] = b"vitallock-message-v1";
const MESSAGE_VAULT_NONCE_DOMAIN: &[u8] = b"exo.messaging.vault-nonce.v1";

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

/// Legacy Lock & Send entrypoint.
///
/// This fails closed because EXOCHAIN message composition must not fabricate
/// X25519 key material internally. Use [`lock_and_send_with_ephemeral`] with a
/// caller-supplied one-time X25519 keypair.
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
/// A fail-closed error directing callers to the explicit ephemeral-key API.
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
    let _ = (
        plaintext,
        content_type,
        sender_did,
        recipient_did,
        sender_signing_key,
        recipient_x25519_public,
        metadata,
        release_on_death,
        release_delay_hours,
    );
    Err(caller_supplied_ephemeral_required())
}

/// Lock & Send with caller-supplied X25519 ephemeral key material.
#[allow(clippy::too_many_arguments)]
pub fn lock_and_send_with_ephemeral(
    plaintext: &[u8],
    content_type: ContentType,
    sender_did: &Did,
    recipient_did: &Did,
    sender_signing_key: &SecretKey,
    recipient_x25519_public: &X25519PublicKey,
    ephemeral_x25519_keypair: &X25519KeyPair,
    metadata: ComposeMetadata,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<EncryptedEnvelope, MessagingError> {
    let envelope = prepare_envelope_for_signing_with_ephemeral(
        plaintext,
        content_type,
        sender_did,
        recipient_did,
        recipient_x25519_public,
        ephemeral_x25519_keypair,
        metadata,
        release_on_death,
        release_delay_hours,
    )?;
    sign_prepared_envelope(envelope, sender_signing_key)
}

/// Legacy unsigned-envelope entrypoint.
///
/// This fails closed because EXOCHAIN message composition must not fabricate
/// X25519 key material internally. Use
/// [`prepare_envelope_for_signing_with_ephemeral`] with a caller-supplied
/// one-time X25519 keypair.
#[allow(clippy::too_many_arguments)]
pub fn prepare_envelope_for_signing(
    plaintext: &[u8],
    content_type: ContentType,
    sender_did: &Did,
    recipient_did: &Did,
    recipient_x25519_public: &X25519PublicKey,
    metadata: ComposeMetadata,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<EncryptedEnvelope, MessagingError> {
    let _ = (
        plaintext,
        content_type,
        sender_did,
        recipient_did,
        recipient_x25519_public,
        metadata,
        release_on_death,
        release_delay_hours,
    );
    Err(caller_supplied_ephemeral_required())
}

/// Encrypt a message with caller-supplied X25519 ephemeral key material and
/// return the unsigned envelope whose signing payload can be signed externally.
#[allow(clippy::too_many_arguments)]
pub fn prepare_envelope_for_signing_with_ephemeral(
    plaintext: &[u8],
    content_type: ContentType,
    sender_did: &Did,
    recipient_did: &Did,
    recipient_x25519_public: &X25519PublicKey,
    ephemeral_x25519_keypair: &X25519KeyPair,
    metadata: ComposeMetadata,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<EncryptedEnvelope, MessagingError> {
    // 1. ECDH: derive shared symmetric key using caller-supplied ephemeral key.
    let shared_key = kex::derive_shared_key(
        &ephemeral_x25519_keypair.secret,
        recipient_x25519_public,
        MESSAGE_KEX_CONTEXT,
    )?;

    let plaintext_hash = Hash256::digest(plaintext);
    let nonce = derive_vault_nonce(
        &metadata,
        content_type,
        sender_did,
        recipient_did,
        ephemeral_x25519_keypair.public.as_bytes(),
        &plaintext_hash,
        release_on_death,
        release_delay_hours,
    )?;

    // 3. Encrypt plaintext with XChaCha20-Poly1305
    //    Associated data = recipient DID (binds ciphertext to intended recipient)
    let encryptor = VaultEncryptor::from_key(shared_key);
    let ciphertext = encryptor
        .encrypt_with_nonce(plaintext, recipient_did.as_str().as_bytes(), &nonce)
        .map_err(|e| MessagingError::EncryptionFailed(e.to_string()))?;

    // 4. Hash plaintext for post-decrypt integrity check
    // 5. Build envelope (without signature first)
    let envelope = EncryptedEnvelope {
        id: metadata.id.to_string(),
        sender_did: sender_did.clone(),
        recipient_did: recipient_did.clone(),
        ephemeral_public_key: *ephemeral_x25519_keypair.public.as_bytes(),
        ciphertext,
        content_type,
        signature: exo_core::Signature::empty(),
        plaintext_hash,
        release_on_death,
        release_delay_hours,
        created: metadata.created,
    };

    Ok(envelope)
}

fn caller_supplied_ephemeral_required() -> MessagingError {
    MessagingError::KeyExchangeFailed(
        "message composition requires caller-supplied ephemeral X25519 keypair".to_owned(),
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_vault_nonce(
    metadata: &ComposeMetadata,
    content_type: ContentType,
    sender_did: &Did,
    recipient_did: &Did,
    ephemeral_public_key: &[u8; 32],
    plaintext_hash: &Hash256,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<[u8; VAULT_NONCE_SIZE], MessagingError> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(MESSAGE_VAULT_NONCE_DOMAIN);
    append_len_prefixed(&mut transcript, "id", metadata.id.as_bytes())?;
    transcript.extend_from_slice(&metadata.created.physical_ms.to_le_bytes());
    transcript.extend_from_slice(&metadata.created.logical.to_le_bytes());
    append_len_prefixed(
        &mut transcript,
        "sender_did",
        sender_did.as_str().as_bytes(),
    )?;
    append_len_prefixed(
        &mut transcript,
        "recipient_did",
        recipient_did.as_str().as_bytes(),
    )?;
    transcript.extend_from_slice(ephemeral_public_key);
    transcript.extend_from_slice(plaintext_hash.as_bytes());
    transcript.push(u8::from(content_type));
    transcript.push(u8::from(release_on_death));
    transcript.extend_from_slice(&release_delay_hours.to_le_bytes());

    let digest = Hash256::digest(&transcript);
    let mut nonce = [0u8; VAULT_NONCE_SIZE];
    nonce.copy_from_slice(&digest.as_bytes()[..VAULT_NONCE_SIZE]);
    Ok(nonce)
}

fn append_len_prefixed(
    transcript: &mut Vec<u8>,
    label: &'static str,
    value: &[u8],
) -> Result<(), MessagingError> {
    transcript.extend_from_slice(label.as_bytes());
    let len = u64::try_from(value.len())
        .map_err(|_| MessagingError::InvalidEnvelope(format!("{label} length exceeds u64::MAX")))?;
    transcript.extend_from_slice(&len.to_le_bytes());
    transcript.extend_from_slice(value);
    Ok(())
}

/// Sign a prepared envelope with an in-process Ed25519 secret key.
pub fn sign_prepared_envelope(
    mut envelope: EncryptedEnvelope,
    sender_signing_key: &SecretKey,
) -> Result<EncryptedEnvelope, MessagingError> {
    let signable = envelope.signing_payload()?;
    let signature = exo_core::crypto::sign(&signable, sender_signing_key);
    envelope.signature = signature;

    Ok(envelope)
}

/// Attach and verify a caller-produced Ed25519 signature to a prepared envelope.
pub fn attach_verified_signature(
    mut envelope: EncryptedEnvelope,
    signature: Signature,
    sender_public_key: &PublicKey,
) -> Result<EncryptedEnvelope, MessagingError> {
    if signature.is_empty() {
        return Err(MessagingError::SignatureVerificationFailed);
    }

    let signable = envelope.signing_payload()?;
    if !exo_core::crypto::verify(&signable, &signature, sender_public_key) {
        return Err(MessagingError::SignatureVerificationFailed);
    }
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

    fn x25519_keypair(seed: u8) -> kex::X25519KeyPair {
        kex::X25519KeyPair::from_secret_bytes([seed; 32])
            .expect("valid deterministic X25519 keypair")
    }

    #[test]
    fn lock_and_send_produces_valid_envelope() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x21);
        let ephemeral_kp = x25519_keypair(0x31);
        let metadata = metadata();

        let envelope = lock_and_send_with_ephemeral(
            b"my secret password: hunter2",
            ContentType::Password,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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
    fn prepare_envelope_for_signing_returns_canonical_payload_without_signature() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let recipient_kp = x25519_keypair(0x22);
        let ephemeral_kp = x25519_keypair(0x32);

        let envelope = prepare_envelope_for_signing_with_ephemeral(
            b"external signer",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(),
            false,
            0,
        )
        .expect("prepare envelope");

        assert_eq!(envelope.signature, exo_core::Signature::empty());
        assert!(
            !envelope
                .signing_payload()
                .expect("signing payload")
                .is_empty(),
            "prepared envelopes must expose canonical bytes for external signing"
        );
    }

    #[test]
    fn attach_verified_signature_accepts_external_signature() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (sender_pk, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x23);
        let ephemeral_kp = x25519_keypair(0x33);

        let envelope = prepare_envelope_for_signing_with_ephemeral(
            b"external signer",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(),
            false,
            0,
        )
        .expect("prepare envelope");
        let signature = exo_core::crypto::sign(
            &envelope.signing_payload().expect("signing payload"),
            &sender_sk,
        );

        let signed =
            attach_verified_signature(envelope, signature, &sender_pk).expect("attach signature");

        assert_ne!(signed.signature, exo_core::Signature::empty());
    }

    #[test]
    fn attach_verified_signature_rejects_wrong_sender_key() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let (wrong_pk, _) = generate_keypair();
        let recipient_kp = x25519_keypair(0x24);
        let ephemeral_kp = x25519_keypair(0x34);

        let envelope = prepare_envelope_for_signing_with_ephemeral(
            b"external signer",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &recipient_kp.public,
            &ephemeral_kp,
            metadata(),
            false,
            0,
        )
        .expect("prepare envelope");
        let signature = exo_core::crypto::sign(
            &envelope.signing_payload().expect("signing payload"),
            &sender_sk,
        );

        let result = attach_verified_signature(envelope, signature, &wrong_pk);

        assert!(matches!(
            result,
            Err(MessagingError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn afterlife_message_flags() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let (_, sender_sk) = generate_keypair();
        let recipient_kp = x25519_keypair(0x25);
        let ephemeral_kp = x25519_keypair(0x35);
        let metadata = metadata();

        let envelope = lock_and_send_with_ephemeral(
            b"Read this after I'm gone",
            ContentType::AfterlifeMessage,
            &sender_did,
            &recipient_did,
            &sender_sk,
            &recipient_kp.public,
            &ephemeral_kp,
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

    #[test]
    fn compose_path_supplies_explicit_vault_nonce() {
        let source = include_str!("compose.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("production section");

        assert!(
            production.contains("encrypt_with_nonce"),
            "compose must pass an explicit deterministic nonce into vault encryption"
        );
        assert!(
            !production.contains(".encrypt("),
            "compose must not call the implicit vault encryption entrypoint"
        );
    }

    #[test]
    fn prepare_envelope_for_signing_requires_caller_supplied_ephemeral_key() {
        let sender_did = Did::new("did:exo:alice").unwrap();
        let recipient_did = Did::new("did:exo:bob").unwrap();
        let recipient_kp = x25519_keypair(0x26);

        let result = prepare_envelope_for_signing(
            b"external signer",
            ContentType::Secret,
            &sender_did,
            &recipient_did,
            &recipient_kp.public,
            metadata(),
            false,
            0,
        );

        assert!(
            matches!(result, Err(MessagingError::KeyExchangeFailed(reason)) if reason.contains("caller-supplied ephemeral")),
            "message composition must fail closed unless the caller supplies the ephemeral X25519 keypair"
        );
    }

    #[test]
    fn compose_path_requires_caller_supplied_ephemeral_key() {
        let source = include_str!("compose.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("production section");

        assert!(
            production.contains("prepare_envelope_for_signing_with_ephemeral"),
            "compose must expose an explicit ephemeral-key entrypoint"
        );
        for pattern in ["generate_ephemeral", "X25519KeyPair::generate"] {
            assert!(
                !production.contains(pattern),
                "compose production path must not fabricate X25519 ephemeral key material via {pattern}"
            );
        }
    }
}
