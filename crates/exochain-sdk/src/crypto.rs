//! Cryptographic primitives — hash, sign, verify.
//!
//! This module provides ergonomic wrappers around [`exo_core::crypto`] for the
//! three operations every SDK user needs: hashing bytes, signing a message,
//! and verifying a signature. The underlying primitives are **BLAKE3** for
//! hashing and **Ed25519** for classical signatures.
//!
//! ## Why use this module
//!
//! - You want to hash and sign without pulling in the full `exo-core` crate
//!   or sorting out the right primitive to use.
//! - You want deterministic, reproducible hex digests for logging and test
//!   vectors.
//! - You want re-exports of the foundational types ([`Did`], [`PublicKey`],
//!   [`SecretKey`], [`Signature`], [`Hash256`], [`Timestamp`]) from a single
//!   place.
//!
//! ## Quick start
//!
//! ```
//! use exochain_sdk::crypto::{generate_keypair, hash, hash_hex, sign, verify};
//!
//! // Hash bytes.
//! let digest = hash(b"hello");
//! assert_eq!(digest.len(), 32);
//! assert_eq!(hash_hex(b"hello").len(), 64);
//!
//! // Sign and verify.
//! let (pk, sk) = generate_keypair();
//! let sig = sign(b"payload", &sk);
//! assert!(verify(b"payload", &sig, &pk));
//! ```

pub use exo_core::{
    Did, Hash256, PublicKey, SecretKey, Signature, Timestamp,
    crypto::{generate_keypair, sign, verify},
};

/// Compute the BLAKE3 hash of `data`, returning the raw 32-byte digest.
///
/// BLAKE3 is collision-resistant, deterministic, and the same hash used for
/// DID derivation, bailment IDs, and decision IDs across the Rust SDK.
///
/// # Examples
///
/// ```
/// use exochain_sdk::crypto::hash;
///
/// let a = hash(b"hello");
/// let b = hash(b"hello");
/// assert_eq!(a, b); // deterministic
/// assert_ne!(a, hash(b"world"));
/// ```
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute the BLAKE3 hash of `data`, returning it as a 64-character lowercase
/// hex string.
///
/// Use this when you want a human-readable, copy-pasteable digest — for
/// example when logging a fingerprint or embedding a hash in JSON.
///
/// # Examples
///
/// ```
/// use exochain_sdk::crypto::hash_hex;
///
/// let hex = hash_hex(b"hello");
/// assert_eq!(hex.len(), 64);
/// assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
/// ```
#[must_use]
pub fn hash_hex(data: &[u8]) -> String {
    let digest = blake3::hash(data);
    let bytes = digest.as_bytes();
    let mut s = String::with_capacity(64);
    for byte in bytes {
        // Lowercase hex — deterministic and stable across platforms.
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = hash(b"hello");
        let b = hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_different_inputs_different_outputs() {
        let a = hash(b"hello");
        let b = hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_hex_is_64_chars_lowercase_hex() {
        let h = hash_hex(b"hello");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn hash_hex_matches_raw_hash() {
        let raw = hash(b"hello");
        let hex = hash_hex(b"hello");
        let mut expected = String::new();
        for b in &raw {
            expected.push_str(&format!("{b:02x}"));
        }
        assert_eq!(hex, expected);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair();
        let msg = b"SDK test message";
        let sig = sign(msg, &sk);
        assert!(verify(msg, &sig, &pk));
    }

    #[test]
    fn sign_verify_rejects_wrong_key() {
        let (_pk1, sk1) = generate_keypair();
        let (pk2, _sk2) = generate_keypair();
        let sig = sign(b"msg", &sk1);
        assert!(!verify(b"msg", &sig, &pk2));
    }

    #[test]
    fn sign_verify_rejects_tampered_message() {
        let (pk, sk) = generate_keypair();
        let sig = sign(b"original", &sk);
        assert!(!verify(b"tampered", &sig, &pk));
    }

    #[test]
    fn reexports_are_accessible() {
        // Basic smoke test that the re-exports compile and are usable.
        let _h: Hash256 = Hash256::digest(b"x");
        let _ts: Timestamp = Timestamp::ZERO;
        let _did = Did::new("did:exo:sdk-reexport-test").expect("valid");
    }
}
