//! Cryptographic primitives for EXOCHAIN.
//!
//! All cryptographic operations use Ed25519 via the `ed25519-dalek` crate.
//! Secret keys are zeroized on drop to prevent residual key material in
//! memory.

use ed25519_dalek::{Signer, Verifier};
use zeroize::Zeroize;

use crate::{
    error::Result,
    types::{PublicKey, SecretKey, Signature},
};

/// An Ed25519 key pair.  The secret key is zeroized when this struct is
/// dropped.
pub struct KeyPair {
    pub public: PublicKey,
    secret: SecretKey,
}

impl KeyPair {
    /// Generate a fresh random key pair.
    #[must_use]
    pub fn generate() -> Self {
        let (public, secret) = generate_keypair();
        Self { public, secret }
    }

    /// Reconstruct a key pair from raw secret-key bytes.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::CryptoError` if the bytes are not a valid Ed25519
    /// secret key.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            public: PublicKey::from_bytes(verifying_key.to_bytes()),
            secret: SecretKey::from_bytes(bytes),
        })
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        sign(message, &self.secret)
    }

    /// Verify a signature against this key pair's public key.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        verify(message, signature, &self.public)
    }

    /// Return a reference to the public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Return a reference to the secret key.
    #[must_use]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.secret.0.zeroize();
    }
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .field("secret", &"***")
            .finish()
    }
}

/// Generate a fresh Ed25519 key pair.
#[must_use]
pub fn generate_keypair() -> (PublicKey, SecretKey) {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (
        PublicKey::from_bytes(verifying_key.to_bytes()),
        SecretKey::from_bytes(signing_key.to_bytes()),
    )
}

/// Sign `message` with the given secret key (Ed25519).
#[must_use]
pub fn sign(message: &[u8], secret: &SecretKey) -> Signature {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret.as_bytes());
    let sig = signing_key.sign(message);
    Signature::Ed25519(sig.to_bytes())
}

/// Verify a signature against a public key.
///
/// For Ed25519 and Hybrid signatures, verifies the classical Ed25519 component.
/// Empty signatures always return `false`.
///
/// # SECURITY NOTE — Post-Quantum Gap (T-17 / M4, tracked in threat_matrix.md)
///
/// `Signature::PostQuantum` and the PQ component of `Signature::Hybrid` are
/// **not yet verified** — ML-DSA (NIST FIPS 204) implementation is planned.
///
/// - `PostQuantum(_)` is rejected outright (returns `false`).
/// - `Hybrid { classical, pq }` only verifies Ed25519; the PQ component is
///   ignored, so hybrid signatures do NOT provide AND-security until M4 ships.
///
/// Current chains use `Ed25519` exclusively.  Records with 50-year retention
/// requirements are vulnerable to harvest-now-decrypt-later until M4 is
/// implemented and audited.
#[must_use]
pub fn verify(message: &[u8], signature: &Signature, public: &PublicKey) -> bool {
    let sig_bytes = match signature {
        Signature::Ed25519(b) => b,
        Signature::Hybrid { classical, .. } => classical, // PQ component not yet verified — T-17
        Signature::PostQuantum(_) => return false,        // PQ verifier not yet implemented — T-17
        Signature::Empty => return false,
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(public.as_bytes()) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(sig_bytes) else {
        return false;
    };
    verifying_key.verify(message, &sig).is_ok()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_pair() {
        let (pk, sk) = generate_keypair();
        // Sign and verify
        let msg = b"test message";
        let sig = sign(msg, &sk);
        assert!(verify(msg, &sig, &pk));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair();
        let msg = b"hello exochain";
        let sig = sign(msg, &sk);
        assert!(verify(msg, &sig, &pk));
    }

    #[test]
    fn verify_fails_wrong_message() {
        let (pk, sk) = generate_keypair();
        let sig = sign(b"original", &sk);
        assert!(!verify(b"tampered", &sig, &pk));
    }

    #[test]
    fn verify_fails_wrong_key() {
        let (_pk1, sk1) = generate_keypair();
        let (pk2, _sk2) = generate_keypair();
        let sig = sign(b"msg", &sk1);
        assert!(!verify(b"msg", &sig, &pk2));
    }

    #[test]
    fn verify_fails_corrupt_signature() {
        let (pk, sk) = generate_keypair();
        let sig = sign(b"msg", &sk);
        // Corrupt the Ed25519 bytes
        let corrupted = match sig {
            Signature::Ed25519(mut b) => {
                b[0] ^= 0xff;
                Signature::Ed25519(b)
            }
            _ => panic!("expected Ed25519"),
        };
        assert!(!verify(b"msg", &corrupted, &pk));
    }

    #[test]
    fn verify_rejects_empty_signature() {
        let (pk, _) = generate_keypair();
        assert!(!verify(b"msg", &Signature::Empty, &pk));
    }

    #[test]
    fn verify_rejects_pq_signature() {
        let (pk, _) = generate_keypair();
        assert!(!verify(b"msg", &Signature::PostQuantum(vec![1, 2, 3]), &pk));
    }

    #[test]
    fn verify_fails_invalid_public_key() {
        let (_, sk) = generate_keypair();
        let sig = sign(b"msg", &sk);
        // All-zero public key is invalid for Ed25519
        let bad_pk = PublicKey::from_bytes([0u8; 32]);
        assert!(!verify(b"msg", &sig, &bad_pk));
    }

    #[test]
    fn keypair_generate_and_use() {
        let kp = KeyPair::generate();
        let msg = b"keypair test";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn keypair_from_secret_bytes() {
        let (_, sk) = generate_keypair();
        let kp = KeyPair::from_secret_bytes(*sk.as_bytes()).expect("valid");
        let msg = b"from bytes";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn keypair_public_key_accessor() {
        let kp = KeyPair::generate();
        let pk = kp.public_key();
        assert_eq!(*pk, kp.public);
    }

    #[test]
    fn keypair_secret_key_accessor() {
        let kp = KeyPair::generate();
        let sk = kp.secret_key();
        // Verify we can sign with the extracted secret
        let sig = sign(b"test", sk);
        assert!(verify(b"test", &sig, kp.public_key()));
    }

    #[test]
    fn keypair_debug_redacts_secret() {
        let kp = KeyPair::generate();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("***"));
        assert!(dbg.contains("KeyPair"));
    }

    #[test]
    fn keypair_deterministic_from_same_bytes() {
        let (_, sk) = generate_keypair();
        let bytes = *sk.as_bytes();
        let kp1 = KeyPair::from_secret_bytes(bytes).expect("ok");
        let kp2 = KeyPair::from_secret_bytes(bytes).expect("ok");
        assert_eq!(kp1.public, kp2.public);
    }

    #[test]
    fn signature_deterministic() {
        let (_, sk) = generate_keypair();
        let msg = b"determinism test";
        let sig1 = sign(msg, &sk);
        let sig2 = sign(msg, &sk);
        // Ed25519 with the same key and message produces the same signature
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn empty_message_sign_verify() {
        let (pk, sk) = generate_keypair();
        let sig = sign(b"", &sk);
        assert!(verify(b"", &sig, &pk));
    }

    #[test]
    fn large_message_sign_verify() {
        let (pk, sk) = generate_keypair();
        let msg = vec![0xab_u8; 10_000];
        let sig = sign(&msg, &sk);
        assert!(verify(&msg, &sig, &pk));
    }
}
