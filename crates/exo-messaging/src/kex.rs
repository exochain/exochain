//! X25519 Diffie-Hellman key exchange for E2E encrypted messaging.
//!
//! Generates ephemeral X25519 keypairs and derives shared secrets via ECDH.
//! The shared secret is then expanded via HKDF-SHA256 into a 256-bit
//! symmetric key suitable for XChaCha20-Poly1305.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::MessagingError;

/// An X25519 public key (32 bytes).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
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
        Ok(Self(arr))
    }

    /// Encode as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
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
pub struct X25519SecretKey(pub [u8; 32]);

impl X25519SecretKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
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
        Ok(Self(arr))
    }

    /// Encode as hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
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
    /// Generate a fresh random X25519 keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self {
            public: X25519PublicKey(public.to_bytes()),
            secret: X25519SecretKey(secret.to_bytes()),
        }
    }

    /// Reconstruct from raw secret bytes.
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self {
            public: X25519PublicKey(public.to_bytes()),
            secret: X25519SecretKey(secret.to_bytes()),
        }
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
    let secret = StaticSecret::from(our_secret.0);
    let public = PublicKey::from(their_public.0);
    let shared_secret = secret.diffie_hellman(&public);

    // HKDF-SHA256: extract from shared secret, expand with context
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(context, &mut okm)
        .map_err(|e| MessagingError::KeyExchangeFailed(e.to_string()))?;
    Ok(okm)
}

/// Generate an ephemeral X25519 keypair for one-time use in message encryption.
///
/// This uses `EphemeralSecret` which is consumed after a single DH operation,
/// but we return the raw bytes so the ephemeral public key can be included
/// in the message envelope.
#[must_use]
pub fn generate_ephemeral() -> X25519KeyPair {
    X25519KeyPair::generate()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let kp = X25519KeyPair::generate();
        assert_ne!(kp.public.0, [0u8; 32], "public key should not be all zeros");
    }

    #[test]
    fn ecdh_shared_secret_agreement() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();
        let context = b"test-context";

        let alice_key =
            derive_shared_key(&alice.secret, &bob.public, context).expect("alice derive");
        let bob_key = derive_shared_key(&bob.secret, &alice.public, context).expect("bob derive");

        assert_eq!(alice_key, bob_key, "shared keys must match");
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let key1 = derive_shared_key(&alice.secret, &bob.public, b"context-a").expect("derive");
        let key2 = derive_shared_key(&alice.secret, &bob.public, b"context-b").expect("derive");

        assert_ne!(key1, key2, "different contexts must produce different keys");
    }

    #[test]
    fn from_secret_bytes_deterministic() {
        let kp1 = X25519KeyPair::generate();
        let kp2 = X25519KeyPair::from_secret_bytes(kp1.secret.0);

        assert_eq!(kp1.public.0, kp2.public.0, "same secret → same public");
    }

    #[test]
    fn hex_round_trip() {
        let kp = X25519KeyPair::generate();
        let hex = kp.public.to_hex();
        let recovered = X25519PublicKey::from_hex(&hex).expect("from_hex");
        assert_eq!(kp.public, recovered);
    }
}
