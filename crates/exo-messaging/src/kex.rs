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

//! X25519 Diffie-Hellman key exchange for E2E encrypted messaging.
//!
//! Requires caller-supplied X25519 key material and derives shared secrets via
//! ECDH. The shared secret is then expanded via HKDF-SHA256 into a 256-bit
//! symmetric key suitable for XChaCha20-Poly1305.

use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::MessagingError;

const X25519_HKDF_SALT_DOMAIN: &[u8] = b"exo.messaging.x25519.hkdf.salt.v1";

/// An X25519 public key (32 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, MessagingError> {
        validate_x25519_public_key(&bytes)?;
        Ok(Self(bytes))
    }

    fn from_trusted_bytes(bytes: [u8; 32]) -> Self {
        debug_assert!(validate_x25519_public_key(&bytes).is_ok());
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, MessagingError> {
        let bytes = hex::decode(hex)
            .map_err(|e| MessagingError::KeyExchangeFailed(format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(MessagingError::KeyExchangeFailed(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }

    /// Encode as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for X25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for X25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(de::Error::custom)
    }
}

impl core::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "X25519PublicKey({})", self.to_hex())
    }
}

/// An X25519 secret key (32 bytes). Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct X25519SecretKey([u8; 32]);

impl X25519SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, MessagingError> {
        let bytes = zeroize::Zeroizing::new(bytes);
        validate_x25519_secret_key(&bytes)?;
        Ok(Self(*bytes))
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, MessagingError> {
        let bytes = zeroize::Zeroizing::new(
            hex::decode(hex)
                .map_err(|e| MessagingError::KeyExchangeFailed(format!("invalid hex: {e}")))?,
        );
        if bytes.len() != 32 {
            return Err(MessagingError::KeyExchangeFailed(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = zeroize::Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(bytes.as_slice());
        Self::from_bytes(*arr)
    }

    /// Derive the public key corresponding to this secret key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        let secret = StaticSecret::from(self.0);
        let public = PublicKey::from(&secret);
        X25519PublicKey::from_trusted_bytes(public.to_bytes())
    }

    fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.0)
    }
}

impl core::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X25519SecretKey")
            .field("key", &"***")
            .finish()
    }
}

/// An X25519 keypair for Diffie-Hellman key exchange.
#[derive(Debug)]
pub struct X25519KeyPair {
    pub public: X25519PublicKey,
    pub secret: X25519SecretKey,
}

impl X25519KeyPair {
    /// Fail closed for legacy callers that previously relied on internal RNG.
    ///
    /// EXOCHAIN runtime adapters must receive X25519 key material from an
    /// explicit caller-controlled key-management boundary.
    pub fn generate() -> Result<Self, MessagingError> {
        Err(MessagingError::KeyExchangeFailed(
            "X25519 keypair generation requires caller-supplied key material".to_owned(),
        ))
    }

    /// Reconstruct from raw secret bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, MessagingError> {
        let secret = X25519SecretKey::from_bytes(bytes)?;
        let public = secret.public_key();
        validate_x25519_public_key(public.as_bytes())?;
        Ok(Self { public, secret })
    }
}

/// Perform X25519 ECDH and derive a 256-bit symmetric key via HKDF-SHA256.
///
/// The `context` parameter binds the derived key to a specific purpose
/// (e.g., `b"vitallock-message-v1"`).
pub fn derive_shared_key(
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
    context: &[u8],
) -> Result<[u8; 32], MessagingError> {
    let (shared_secret, our_public) = x25519_shared_secret(our_secret, their_public)?;
    let salt = hkdf_salt(&our_public, their_public);

    // HKDF-SHA256: extract from shared secret with a deterministic transcript
    // salt, then expand with caller-supplied context.
    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .map_err(|e| MessagingError::KeyExchangeFailed(e.to_string()))?;
    Ok(okm)
}

/// Derive the pre-versioned legacy symmetric key via unsalted HKDF-SHA256.
///
/// This is retained only so unversioned envelopes created before the transcript
/// salt was introduced can still be opened. New envelopes must use
/// [`derive_shared_key`], which binds the HKDF extract step to both X25519
/// public keys.
pub fn derive_shared_key_legacy_unsalted(
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
    context: &[u8],
) -> Result<[u8; 32], MessagingError> {
    let (shared_secret, _) = x25519_shared_secret(our_secret, their_public)?;
    let hk = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .map_err(|e| MessagingError::KeyExchangeFailed(e.to_string()))?;
    Ok(okm)
}

fn x25519_shared_secret(
    our_secret: &X25519SecretKey,
    their_public: &X25519PublicKey,
) -> Result<([u8; 32], X25519PublicKey), MessagingError> {
    let secret = our_secret.static_secret();
    let public = PublicKey::from(*their_public.as_bytes());
    let shared_secret = secret.diffie_hellman(&public);
    if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(MessagingError::KeyExchangeFailed(
            "invalid X25519 public key: low-order shared secret".to_owned(),
        ));
    }
    let our_public = X25519PublicKey::from_trusted_bytes(PublicKey::from(&secret).to_bytes());
    Ok((*shared_secret.as_bytes(), our_public))
}

fn hkdf_salt(our_public: &X25519PublicKey, their_public: &X25519PublicKey) -> [u8; 32] {
    let (first, second) = if our_public.as_bytes() <= their_public.as_bytes() {
        (our_public.as_bytes(), their_public.as_bytes())
    } else {
        (their_public.as_bytes(), our_public.as_bytes())
    };

    let mut hasher = Sha256::new();
    hasher.update(X25519_HKDF_SALT_DOMAIN);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

fn validate_x25519_public_key(bytes: &[u8; 32]) -> Result<(), MessagingError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(MessagingError::KeyExchangeFailed(
            "invalid X25519 public key: all-zero value".to_owned(),
        ));
    }

    let validation_secret = StaticSecret::from([0x5a; 32]);
    let validation_public = PublicKey::from(*bytes);
    let validation_shared = validation_secret.diffie_hellman(&validation_public);
    if validation_shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(MessagingError::KeyExchangeFailed(
            "invalid X25519 public key: low-order point".to_owned(),
        ));
    }

    Ok(())
}

fn validate_x25519_secret_key(bytes: &[u8; 32]) -> Result<(), MessagingError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(MessagingError::KeyExchangeFailed(
            "invalid X25519 secret key: all-zero value".to_owned(),
        ));
    }

    Ok(())
}

/// Fail closed for legacy callers that previously generated an ephemeral
/// X25519 keypair inside the messaging crate.
pub fn generate_ephemeral() -> Result<X25519KeyPair, MessagingError> {
    Err(MessagingError::KeyExchangeFailed(
        "ephemeral X25519 key generation requires caller-supplied key material".to_owned(),
    ))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> X25519KeyPair {
        X25519KeyPair::from_secret_bytes([seed; 32]).expect("valid deterministic X25519 keypair")
    }

    #[test]
    fn keypair_generation_fails_closed_without_caller_material() {
        let result = X25519KeyPair::generate();

        assert!(
            matches!(result, Err(MessagingError::KeyExchangeFailed(reason)) if reason.contains("caller-supplied key material")),
            "legacy X25519 key generation must fail closed"
        );
    }

    #[test]
    fn x25519_keypair_source_does_not_generate_internal_entropy() {
        let source = include_str!("kex.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .expect("production section");

        for pattern in ["random_from_rng", "OsRng", "fill_bytes", "rand::"] {
            assert!(
                !production.contains(pattern),
                "X25519 key exchange must require caller-supplied key material instead of internal entropy via {pattern}"
            );
        }
    }

    #[test]
    fn ecdh_shared_secret_agreement() {
        let alice = keypair(0xA1);
        let bob = keypair(0xB2);
        let context = b"test-context";

        let alice_key =
            derive_shared_key(&alice.secret, &bob.public, context).expect("alice derive");
        let bob_key = derive_shared_key(&bob.secret, &alice.public, context).expect("bob derive");

        assert_eq!(alice_key, bob_key, "shared keys must match");
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let alice = keypair(0xA3);
        let bob = keypair(0xB4);

        let key1 = derive_shared_key(&alice.secret, &bob.public, b"context-a").expect("derive");
        let key2 = derive_shared_key(&alice.secret, &bob.public, b"context-b").expect("derive");

        assert_ne!(key1, key2, "different contexts must produce different keys");
    }

    #[test]
    fn from_secret_bytes_deterministic() {
        let secret = X25519SecretKey::from_bytes([7u8; 32]).expect("valid secret");
        let kp1 = X25519KeyPair::from_secret_bytes([7u8; 32]).expect("valid keypair");
        let kp2 = X25519KeyPair {
            public: secret.public_key(),
            secret,
        };

        assert_eq!(
            kp1.public.as_bytes(),
            kp2.public.as_bytes(),
            "same secret → same public"
        );
    }

    #[test]
    fn hex_round_trip() {
        let kp = keypair(0xC5);
        let hex = kp.public.to_hex();
        let recovered = X25519PublicKey::from_hex(&hex).expect("from_hex");
        assert_eq!(kp.public, recovered);
    }

    #[test]
    fn x25519_secret_key_rejects_all_zero_hex() {
        let zero_hex = "00".repeat(32);

        let result = X25519SecretKey::from_hex(&zero_hex);

        assert!(
            matches!(result, Err(MessagingError::KeyExchangeFailed(reason)) if reason.contains("all-zero")),
            "all-zero X25519 secret keys must be rejected"
        );
    }

    #[test]
    fn x25519_public_key_rejects_all_zero_hex() {
        let zero_hex = "00".repeat(32);

        let result = X25519PublicKey::from_hex(&zero_hex);

        assert!(
            matches!(result, Err(MessagingError::KeyExchangeFailed(reason)) if reason.contains("invalid X25519 public key")),
            "all-zero X25519 public keys must be rejected"
        );
    }

    #[test]
    fn x25519_public_key_deserialization_rejects_all_zero_bytes() {
        let zero_bytes = format!("[{}]", vec!["0"; 32].join(","));

        let result: Result<X25519PublicKey, _> = serde_json::from_str(&zero_bytes);

        assert!(
            result.is_err(),
            "serde deserialization must validate X25519 public keys"
        );
    }

    #[test]
    fn x25519_public_key_source_does_not_expose_inner_bytes() {
        let source = include_str!("kex.rs");

        assert!(
            !source.contains(&["pub struct X25519PublicKey", "(pub"].concat()),
            "X25519 public key bytes must not be exposed through a public tuple field"
        );
    }

    #[test]
    fn x25519_secret_key_source_does_not_expose_inner_bytes_or_plain_hex() {
        let source = include_str!("kex.rs");
        let secret_impl = source
            .split("impl X25519SecretKey {")
            .nth(1)
            .and_then(|rest| {
                rest.split("impl core::fmt::Debug for X25519SecretKey")
                    .next()
            })
            .expect("secret-key impl block must be present");
        assert!(
            !source.contains(&["pub struct X25519SecretKey", "(pub"].concat()),
            "X25519 secret key bytes must not be exposed through a public tuple field"
        );
        assert!(
            !secret_impl.contains(&["pub fn to_", "hex(&self) -> String"].concat()),
            "X25519 secret keys must not expose a plain String hex encoder"
        );
        assert!(
            !source.contains(&["our_secret", ".0"].concat()),
            "internal key exchange must use the bounded secret-key accessor"
        );
    }

    #[test]
    fn x25519_secret_key_decoding_zeroizes_rust_owned_buffers() {
        let source = include_str!("kex.rs");
        let secret_impl = source
            .split("impl X25519SecretKey {")
            .nth(1)
            .and_then(|rest| {
                rest.split("impl core::fmt::Debug for X25519SecretKey")
                    .next()
            })
            .expect("secret-key impl block must be present");
        let from_bytes = secret_impl
            .split("pub fn from_bytes(bytes: [u8; 32])")
            .nth(1)
            .and_then(|rest| rest.split("/// Create from hex string.").next())
            .expect("X25519SecretKey::from_bytes must be present");
        assert!(
            from_bytes.contains("zeroize::Zeroizing::new(bytes)"),
            "X25519SecretKey::from_bytes must zeroize its source stack buffer"
        );

        let from_hex = secret_impl
            .split("pub fn from_hex(hex: &str)")
            .nth(1)
            .and_then(|rest| rest.split("/// Derive the public key corresponding").next())
            .expect("X25519SecretKey::from_hex must be present");
        assert!(
            from_hex.matches("zeroize::Zeroizing::new").count() >= 2,
            "X25519SecretKey::from_hex must zeroize both decoded Vec and stack array buffers"
        );
    }

    #[test]
    fn derive_shared_key_uses_protocol_bound_hkdf_salt() {
        let source = include_str!("kex.rs");
        let derive_shared_key = source
            .split("pub fn derive_shared_key(")
            .nth(1)
            .and_then(|section| section.split("/// Derive the pre-versioned legacy").next())
            .expect("current derive_shared_key must be present");

        assert!(
            derive_shared_key.contains("hkdf_salt(&our_public, their_public)")
                && derive_shared_key.contains("Hkdf::<Sha256>::new(Some(&salt), &shared_secret)")
                && !derive_shared_key.contains("Hkdf::<Sha256>::new(None"),
            "current X25519 shared-secret HKDF extraction must use a protocol-bound salt"
        );
    }

    #[test]
    fn legacy_unsalted_kdf_is_quarantined_for_unversioned_compatibility() {
        let source = include_str!("kex.rs");
        let legacy = source
            .split("pub fn derive_shared_key_legacy_unsalted(")
            .nth(1)
            .and_then(|section| section.split("fn x25519_shared_secret").next())
            .expect("legacy compatibility derive must be present");

        assert!(
            legacy.contains("Hkdf::<Sha256>::new(None, &shared_secret)"),
            "legacy unsalted HKDF must be isolated to the explicitly named compatibility helper"
        );
    }
}
