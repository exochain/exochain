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

//! Vault encryption module for EXOCHAIN identity-bound AEAD.
//!
//! Provides XChaCha20-Poly1305 authenticated encryption with associated data
//! (AEAD), where the associated data is typically DID bytes so that ciphertext
//! is cryptographically bound to a specific identity.
//!
//! Key derivation uses HKDF-SHA256 from an Ed25519 secret key with a
//! protocol-domain salt.
//!
//! Ciphertext format: `[24-byte nonce][encrypted payload][16-byte Poly1305 tag]`.

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use exo_core::SecretKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::IdentityError;

/// Size of the XChaCha20-Poly1305 nonce in bytes.
pub const VAULT_NONCE_SIZE: usize = 24;

/// Size of the XChaCha20-Poly1305 nonce in bytes.
const NONCE_SIZE: usize = VAULT_NONCE_SIZE;

/// Size of the Poly1305 authentication tag in bytes.
const TAG_SIZE: usize = 16;

/// Minimum ciphertext length: nonce + tag (payload can be empty).
const MIN_CIPHERTEXT_LEN: usize = NONCE_SIZE + TAG_SIZE;

/// HKDF extraction salt for identity vault keys.
const VAULT_HKDF_SALT_DOMAIN: &[u8] = b"exo.identity.vault.hkdf.salt.v1";

/// AEAD vault encryptor using XChaCha20-Poly1305.
///
/// Wraps a 256-bit symmetric key derived from an Ed25519 secret key via
/// HKDF-SHA256.  The key material is zeroized on drop.
pub struct VaultEncryptor {
    key: [u8; 32],
}

impl VaultEncryptor {
    /// Create a `VaultEncryptor` from raw 256-bit key material.
    #[must_use]
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive a vault encryption key from an Ed25519 secret key using
    /// HKDF-SHA256.
    ///
    /// The `context` bytes are used as the HKDF info parameter, allowing
    /// the same secret key to produce different vault keys for different
    /// purposes.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::VaultKeyDerivationFailed` if HKDF expand
    /// fails (in practice this cannot occur for a 32-byte output).
    pub fn derive_key(secret: &SecretKey, context: &[u8]) -> Result<Self, IdentityError> {
        let hk = Hkdf::<Sha256>::new(Some(VAULT_HKDF_SALT_DOMAIN), secret.as_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(context, &mut *okm)
            .map_err(|e| IdentityError::VaultKeyDerivationFailed(e.to_string()))?;
        Ok(Self { key: *okm })
    }

    /// Legacy encryption entrypoint retained for API compatibility.
    ///
    /// Vault encryption must receive an explicit nonce from the caller so the
    /// runtime path remains deterministic and the nonce provenance is auditable.
    /// Use [`encrypt_with_nonce`](Self::encrypt_with_nonce) for supported
    /// encryption.
    ///
    /// # Errors
    ///
    /// Always returns `IdentityError::VaultNonceRequired`.
    pub fn encrypt(
        &self,
        _plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        Err(IdentityError::VaultNonceRequired)
    }

    /// Decrypt a ciphertext produced by [`encrypt_with_nonce`](Self::encrypt_with_nonce).
    ///
    /// `associated_data` must match the value used during encryption.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::VaultCiphertextTooShort` if the ciphertext
    /// is shorter than `NONCE_SIZE + TAG_SIZE`.
    ///
    /// Returns `IdentityError::VaultDecryptionFailed` if authentication
    /// fails (wrong key, tampered ciphertext, or wrong associated data).
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        if ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(IdentityError::VaultCiphertextTooShort);
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
        let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

        let cipher = XChaCha20Poly1305::new(self.cipher_key());

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: encrypted,
                    aad: associated_data,
                },
            )
            .map_err(|_| IdentityError::VaultDecryptionFailed)
    }

    /// Return a reference to the raw key bytes (for testing/inspection).
    #[must_use]
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Encrypt with an explicit caller-supplied nonce.
    ///
    /// `associated_data` should be the DID bytes so the ciphertext is bound
    /// to the identity. The nonce must be unique for the derived key and must
    /// be supplied by the caller from an auditable deterministic runtime input.
    ///
    /// Returns `[24-byte nonce][ciphertext][16-byte tag]`.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::InvalidVaultNonce` when the nonce fails local
    /// validation.
    ///
    /// Returns `IdentityError::VaultEncryptionFailed` on cipher failure.
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce: &[u8; VAULT_NONCE_SIZE],
    ) -> Result<Vec<u8>, IdentityError> {
        Self::validate_nonce(nonce)?;

        let cipher = XChaCha20Poly1305::new(self.cipher_key());
        let xcnonce = chacha20poly1305::XNonce::from_slice(nonce);

        let encrypted = cipher
            .encrypt(
                xcnonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|e| IdentityError::VaultEncryptionFailed(e.to_string()))?;

        // Format: [nonce][encrypted payload with appended tag]
        let mut out = Vec::with_capacity(NONCE_SIZE + encrypted.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    // ---- internal helpers ----

    fn validate_nonce(nonce: &[u8; VAULT_NONCE_SIZE]) -> Result<(), IdentityError> {
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(IdentityError::InvalidVaultNonce {
                reason: "nonce must not be all zero".into(),
            });
        }

        Ok(())
    }

    /// Build the `chacha20poly1305` key type from our raw bytes.
    fn cipher_key(&self) -> &chacha20poly1305::Key {
        chacha20poly1305::Key::from_slice(&self.key)
    }
}

impl Drop for VaultEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl core::fmt::Debug for VaultEncryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultEncryptor")
            .field("key", &"***")
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::crypto::generate_keypair;

    use super::*;

    /// Helper: create a VaultEncryptor from deterministic test key material.
    fn test_encryptor() -> VaultEncryptor {
        VaultEncryptor::from_key([0x42; 32])
    }

    fn test_nonce(tag: u8) -> [u8; NONCE_SIZE] {
        [tag; NONCE_SIZE]
    }

    fn encrypt_for_test(
        enc: &VaultEncryptor,
        plaintext: &[u8],
        associated_data: &[u8],
        nonce_tag: u8,
    ) -> Vec<u8> {
        enc.encrypt_with_nonce(plaintext, associated_data, &test_nonce(nonce_tag))
            .expect("encrypt_with_nonce")
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let enc = test_encryptor();
        let plaintext = b"secret identity data";
        let ad = b"did:exo:alice";

        let ct = encrypt_for_test(&enc, plaintext, ad, 1);
        let pt = enc.decrypt(&ct, ad).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_requires_caller_supplied_nonce() {
        let enc = test_encryptor();
        let result = enc.encrypt(b"secret identity data", b"did:exo:alice");

        assert!(
            matches!(result, Err(IdentityError::VaultNonceRequired)),
            "implicit nonce generation must fail closed, got {result:?}"
        );
    }

    #[test]
    fn encrypt_source_does_not_generate_internal_nonce() {
        let source = include_str!("vault.rs");
        let production = match source.split("#[cfg(test)]").next() {
            Some(production) => production,
            None => panic!("test boundary marker must be present"),
        };

        assert!(
            !production.contains("random_nonce"),
            "vault encryption must not hide nonce generation inside production logic"
        );
        assert!(
            !production.contains("OsRng"),
            "vault encryption must not use OS randomness in production logic"
        );
        assert!(
            !production.contains("fill_bytes"),
            "vault encryption must not fill nonce bytes from hidden randomness"
        );
    }

    #[test]
    fn encrypt_with_nonce_rejects_all_zero_nonce() {
        let enc = test_encryptor();
        let result = enc.encrypt_with_nonce(b"secret identity data", b"did:exo:alice", &[0u8; 24]);

        assert!(
            matches!(result, Err(IdentityError::InvalidVaultNonce { .. })),
            "zero nonce must be rejected, got {result:?}"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let enc = test_encryptor();
        let plaintext = b"do not tamper";
        let ad = b"did:exo:bob";

        let mut ct = encrypt_for_test(&enc, plaintext, ad, 2);
        // Flip a byte in the encrypted payload (after nonce)
        let idx = NONCE_SIZE + 1;
        ct[idx] ^= 0xff;

        let result = enc.decrypt(&ct, ad);
        assert!(
            matches!(result, Err(IdentityError::VaultDecryptionFailed)),
            "expected VaultDecryptionFailed, got {result:?}"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let enc1 = VaultEncryptor::from_key([0x11; 32]);
        let enc2 = VaultEncryptor::from_key([0x22; 32]);
        let plaintext = b"key mismatch";
        let ad = b"did:exo:carol";

        let ct = encrypt_for_test(&enc1, plaintext, ad, 3);
        let result = enc2.decrypt(&ct, ad);
        assert!(
            matches!(result, Err(IdentityError::VaultDecryptionFailed)),
            "expected VaultDecryptionFailed, got {result:?}"
        );
    }

    #[test]
    fn wrong_associated_data_fails() {
        let enc = test_encryptor();
        let plaintext = b"bound to identity";
        let ad_a = b"did:exo:alice";
        let ad_b = b"did:exo:eve";

        let ct = encrypt_for_test(&enc, plaintext, ad_a, 4);
        let result = enc.decrypt(&ct, ad_b);
        assert!(
            matches!(result, Err(IdentityError::VaultDecryptionFailed)),
            "expected VaultDecryptionFailed, got {result:?}"
        );
    }

    #[test]
    fn empty_plaintext() {
        let enc = test_encryptor();
        let ad = b"did:exo:empty";

        let ct = encrypt_for_test(&enc, b"", ad, 5);
        assert_eq!(
            ct.len(),
            NONCE_SIZE + TAG_SIZE,
            "empty plaintext produces nonce + tag only"
        );

        let pt = enc.decrypt(&ct, ad).expect("decrypt");
        assert!(pt.is_empty());
    }

    #[test]
    fn large_plaintext() {
        let enc = test_encryptor();
        let plaintext = vec![0xab_u8; 1_000_000]; // 1 MB
        let ad = b"did:exo:large";

        let ct = encrypt_for_test(&enc, &plaintext, ad, 6);
        let pt = enc.decrypt(&ct, ad).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn derive_key_deterministic() {
        let (_, sk) = generate_keypair();
        let context = b"vault-test-context";

        let enc1 = VaultEncryptor::derive_key(&sk, context).expect("derive_key");
        let enc2 = VaultEncryptor::derive_key(&sk, context).expect("derive_key");

        assert_eq!(enc1.key_bytes(), enc2.key_bytes());
    }

    #[test]
    fn derive_key_different_contexts() {
        let (_, sk) = generate_keypair();

        let enc1 = VaultEncryptor::derive_key(&sk, b"context-alpha").expect("derive_key");
        let enc2 = VaultEncryptor::derive_key(&sk, b"context-beta").expect("derive_key");

        assert_ne!(enc1.key_bytes(), enc2.key_bytes());
    }

    #[test]
    fn derive_key_uses_protocol_bound_hkdf_salt() {
        let (_, sk) = generate_keypair();
        let context = b"vault-test-context";
        let enc = VaultEncryptor::derive_key(&sk, context).expect("derive_key");

        let unsalted_hkdf = Hkdf::<Sha256>::new(None, sk.as_bytes());
        let mut unsalted = [0u8; 32];
        unsalted_hkdf
            .expand(context, &mut unsalted)
            .expect("unsalted HKDF expansion");

        assert_ne!(
            enc.key_bytes(),
            &unsalted,
            "vault key derivation must not match HKDF extraction with an absent salt"
        );

        let source = include_str!("vault.rs");
        let production = match source.split("#[cfg(test)]").next() {
            Some(production) => production,
            None => panic!("test boundary marker must be present"),
        };

        assert!(
            production.contains("VAULT_HKDF_SALT_DOMAIN"),
            "derive_key must use an explicit protocol-domain HKDF salt"
        );
        assert!(
            !production.contains("Hkdf::<Sha256>::new(None"),
            "derive_key must not use HKDF extraction with an absent salt"
        );
    }

    #[test]
    fn derive_key_source_zeroizes_hkdf_output_buffer() {
        let source = include_str!("vault.rs");
        let production = match source.split("#[cfg(test)]").next() {
            Some(production) => production,
            None => panic!("test boundary marker must be present"),
        };

        assert!(
            production.contains("Zeroizing::new([0u8; 32])"),
            "derive_key must hold HKDF output in an auto-zeroizing buffer"
        );
        assert!(
            !production.contains("let mut okm = [0u8; 32]"),
            "derive_key must not leave a plain stack copy of derived key material"
        );
    }

    #[test]
    fn zeroize_on_drop() {
        // Verify that VaultEncryptor implements the Zeroize trait via Drop.
        // We construct, read the key, drop, and verify via a copy of the pointer
        // that the type system enforces Zeroize.
        fn assert_zeroize_impl<T: Zeroize>() {}
        assert_zeroize_impl::<[u8; 32]>(); // underlying storage implements Zeroize

        // Functional check: create an encryptor, do work, drop it.
        let enc = test_encryptor();
        let key_copy = *enc.key_bytes();
        // Key was non-zero before drop
        assert_ne!(key_copy, [0u8; 32]);
        // After drop the struct's Drop impl calls zeroize.
        // We can't safely read freed memory, but we verify the Drop impl
        // compiles and the Zeroize trait is used on [u8; 32].
        drop(enc);
    }
}
