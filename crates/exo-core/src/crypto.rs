//! Cryptographic primitives for EXOCHAIN.
//!
//! # Algorithm support
//!
//! | Variant        | Algorithm                       | Status      |
//! |----------------|---------------------------------|-------------|
//! | Ed25519        | Ed25519 / ed25519-dalek         | Production  |
//! | PostQuantum    | ML-DSA-65 (NIST FIPS 204)       | Production  |
//! | Hybrid         | Ed25519 + ML-DSA-65 (strict AND)| Production  |
//!
//! # Hybrid verification
//!
//! [`verify_hybrid`] requires **both** the Ed25519 and ML-DSA-65 components
//! to pass.  Both components are always evaluated — no short-circuit — so
//! the timing of a rejection does not reveal which component failed.
//!
//! # Security note — `verify()` and Hybrid signatures
//!
//! [`verify`] returns `false` for `Hybrid` signatures because it cannot
//! verify the PQ component without a [`PqPublicKey`].  Use [`verify_hybrid`]
//! for Hybrid signatures.  This closes the silent Ed25519-only downgrade that
//! existed in the stub implementation.
//!
//! # Post-quantum implementation
//!
//! ML-DSA is implemented via the `ml-dsa` crate (RustCrypto, pure Rust,
//! WASM-compatible). Version 0.1.0-rc.7 patches RUSTSEC-2025-0144 — a
//! timing side-channel in the `decompose` function during signing, fixed via
//! constant-time Barrett reduction in rc.3+.
//!
//! `PqSecretKey` stores the 32-byte ML-DSA seed (`ξ` in FIPS 204 §5.1).
//! `PqPublicKey` stores the 1952-byte encoded ML-DSA-65 verifying key.

use ed25519_dalek::{Signer, Verifier};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use zeroize::Zeroize;

use crate::{
    error::{ExoError, Result},
    types::{PqPublicKey, PqSecretKey, PublicKey, SecretKey, Signature},
};

// ---------------------------------------------------------------------------
// Classical Ed25519 — KeyPair
// ---------------------------------------------------------------------------

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

    /// Sign a message (Ed25519).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        sign(message, &self.secret)
    }

    /// Verify an Ed25519 signature against this key pair's public key.
    ///
    /// For Hybrid signatures use [`verify_hybrid`] instead.
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

// ---------------------------------------------------------------------------
// Post-quantum ML-DSA-65 — PqKeyPair
// ---------------------------------------------------------------------------

/// An ML-DSA-65 key pair.
///
/// The 32-byte seed (`PqSecretKey`) is zeroized on drop.  Signing is
/// deterministic: the same seed + message always produces the same signature.
pub struct PqKeyPair {
    pub public: PqPublicKey,
    secret: PqSecretKey,
}

impl PqKeyPair {
    /// Generate a fresh random ML-DSA-65 key pair.
    #[must_use]
    pub fn generate() -> Self {
        let (public, secret) = generate_pq_keypair();
        Self { public, secret }
    }

    /// Sign a message (ML-DSA-65, deterministic).
    ///
    /// # Errors
    ///
    /// Returns `ExoError::CryptoError` if the stored seed bytes are malformed.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        sign_pq(message, &self.secret)
    }

    /// Verify a `PostQuantum` signature against this key pair's public key.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        verify_pq(message, signature, &self.public)
    }

    /// Return a reference to the PQ public key.
    #[must_use]
    pub fn public_key(&self) -> &PqPublicKey {
        &self.public
    }
}

impl core::fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqKeyPair")
            .field("public", &self.public)
            .field("secret", &"***")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Classical Ed25519 — free functions
// ---------------------------------------------------------------------------

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

/// Verify an Ed25519 signature against a public key.
///
/// - `Ed25519` — verifies the Ed25519 component.
/// - `Hybrid` — **always returns `false`**.  Use [`verify_hybrid`] instead;
///   this function cannot check the PQ component without a [`PqPublicKey`].
///   This closes the silent Ed25519-only downgrade that existed in the stub.
/// - `PostQuantum` — returns `false`.  Use [`verify_pq`] instead.
/// - `Empty` — always returns `false`.
#[must_use]
pub fn verify(message: &[u8], signature: &Signature, public: &PublicKey) -> bool {
    let sig_bytes = match signature {
        Signature::Ed25519(b) => b,
        // Cannot fully verify Hybrid without the PQ component — return false
        // rather than silently accepting with only the Ed25519 half.
        Signature::Hybrid { .. } => return false,
        Signature::PostQuantum(_) => return false,
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

// ---------------------------------------------------------------------------
// Post-quantum ML-DSA-65 — free functions
// ---------------------------------------------------------------------------

/// Generate a fresh ML-DSA-65 key pair.
///
/// Returns `(PqPublicKey, PqSecretKey)`.
///
/// - `PqSecretKey` stores the 32-byte seed `ξ` (FIPS 204 §5.1).  All ML-DSA
///   security levels use a 32-byte seed.
/// - `PqPublicKey` stores the 1952-byte encoded ML-DSA-65 verifying key.
#[must_use]
pub fn generate_pq_keypair() -> (PqPublicKey, PqSecretKey) {
    // Generate entropy via rand 0.8 (rand_core 0.6) — no conflict with
    // ml-dsa's rand_core 0.10, because we fill a plain byte array and then
    // hand it to ml-dsa's seed-based constructor.
    let mut seed_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed_bytes);

    let seed: ml_dsa::Seed = seed_bytes.into();
    let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();
    let vk_encoded: EncodedVerifyingKey<MlDsa65> = vk.encode();
    let vk_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&vk_encoded).to_vec();

    (
        PqPublicKey::from_bytes(vk_bytes),
        PqSecretKey::from_bytes(seed_bytes.to_vec()),
    )
}

/// Sign `message` with an ML-DSA-65 secret key (deterministic, empty context).
///
/// Returns `Signature::PostQuantum` containing the raw encoded ML-DSA-65
/// signature bytes (3293 bytes for ML-DSA-65).
///
/// Signing is deterministic: the same seed and message always produce the
/// same signature, satisfying the `DeterministicFinality` invariant.
///
/// # Errors
///
/// Returns `ExoError::CryptoError` if `secret` bytes are not exactly 32 bytes
/// (the ML-DSA seed size) or if ML-DSA signing fails internally.
pub fn sign_pq(message: &[u8], secret: &PqSecretKey) -> Result<Signature> {
    let seed_arr: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| ExoError::CryptoError {
            reason: format!(
                "ML-DSA seed must be 32 bytes, got {}",
                secret.as_bytes().len()
            ),
        })?;
    let seed: ml_dsa::Seed = seed_arr.into();
    let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
    let pq_sig = sk
        .sign_deterministic(message, &[])
        .map_err(|e| ExoError::CryptoError {
            reason: format!("ML-DSA-65 sign failed: {e}"),
        })?;
    let sig_encoded: EncodedSignature<MlDsa65> = pq_sig.encode();
    Ok(Signature::PostQuantum(
        AsRef::<[u8]>::as_ref(&sig_encoded).to_vec(),
    ))
}

/// Verify a `PostQuantum` signature with an ML-DSA-65 public key.
///
/// Returns `false` for any `Signature` variant other than `PostQuantum`.
#[must_use]
pub fn verify_pq(message: &[u8], signature: &Signature, public: &PqPublicKey) -> bool {
    let Signature::PostQuantum(sig_bytes) = signature else {
        return false;
    };
    let Ok(encoded_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(public.as_bytes()) else {
        return false;
    };
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded_vk);
    let Ok(ml_sig) = ml_dsa::Signature::<MlDsa65>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    vk.verify_with_context(message, &[], &ml_sig)
}

// ---------------------------------------------------------------------------
// Hybrid Ed25519 + ML-DSA-65 — free functions
// ---------------------------------------------------------------------------

/// Sign `message` with both Ed25519 and ML-DSA-65 (strict dual-sign).
///
/// Returns `Signature::Hybrid` containing both components.  Both must pass
/// during verification via [`verify_hybrid`].  This is a cryptographic
/// instantiation of the `DualControl` constitutional invariant.
///
/// # Errors
///
/// Returns `ExoError::CryptoError` if the PQ signing key bytes are invalid.
pub fn sign_hybrid(
    message: &[u8],
    classical_secret: &SecretKey,
    pq_secret: &PqSecretKey,
) -> Result<Signature> {
    let Signature::Ed25519(classical) = sign(message, classical_secret) else {
        // sign() always returns Ed25519 — this branch is unreachable.
        return Err(ExoError::CryptoError {
            reason: "unexpected non-Ed25519 variant from sign()".into(),
        });
    };
    let Signature::PostQuantum(pq) = sign_pq(message, pq_secret)? else {
        return Err(ExoError::CryptoError {
            reason: "unexpected non-PostQuantum variant from sign_pq()".into(),
        });
    };
    Ok(Signature::Hybrid { classical, pq })
}

/// Verify a `Hybrid` signature.
///
/// **Both** the Ed25519 and ML-DSA-65 components must pass.  Both are always
/// evaluated — no short-circuit — so the timing of a `false` result does not
/// reveal which component failed.
///
/// Returns `false` for any `Signature` variant other than `Hybrid`.
#[must_use]
pub fn verify_hybrid(
    message: &[u8],
    signature: &Signature,
    classical_public: &PublicKey,
    pq_public: &PqPublicKey,
) -> bool {
    let Signature::Hybrid { classical, pq } = signature else {
        return false;
    };

    // Evaluate both before combining — no short-circuit — to prevent timing
    // leakage of which component failed.
    let classical_ok = verify_ed25519_bytes(message, classical, classical_public);
    let pq_ok = verify_pq(message, &Signature::PostQuantum(pq.clone()), pq_public);

    // Strict AND: both must pass.
    classical_ok & pq_ok
}

/// Internal helper: verify raw Ed25519 signature bytes against a public key.
fn verify_ed25519_bytes(message: &[u8], sig_bytes: &[u8; 64], public: &PublicKey) -> bool {
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

    // -----------------------------------------------------------------------
    // Ed25519 — classical tests, all unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn generate_keypair_produces_valid_pair() {
        let (pk, sk) = generate_keypair();
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
    fn verify_rejects_pq_signature_via_classical_path() {
        // verify() cannot verify PostQuantum — use verify_pq() instead.
        let (pk, _) = generate_keypair();
        assert!(!verify(b"msg", &Signature::PostQuantum(vec![1, 2, 3]), &pk));
    }

    #[test]
    fn verify_rejects_hybrid_via_classical_path() {
        // Regression: previously verify() silently accepted Hybrid with only
        // the Ed25519 component valid. Now it must return false.
        let (pk, sk) = generate_keypair();
        let classical = match sign(b"msg", &sk) {
            Signature::Ed25519(b) => b,
            _ => panic!("expected Ed25519"),
        };
        let hybrid = Signature::Hybrid {
            classical,
            pq: vec![0u8; 32],
        };
        assert!(
            !verify(b"msg", &hybrid, &pk),
            "verify() must not silently downgrade Hybrid to Ed25519-only"
        );
    }

    #[test]
    fn verify_fails_invalid_public_key() {
        let (_, sk) = generate_keypair();
        let sig = sign(b"msg", &sk);
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

    // -----------------------------------------------------------------------
    // ML-DSA-65 (PostQuantum) — new tests
    // -----------------------------------------------------------------------

    #[test]
    fn pq_generate_keypair_produces_valid_sizes() {
        let (pk, sk) = generate_pq_keypair();
        // ML-DSA-65: verifying key = 1952 bytes, seed = 32 bytes
        assert_eq!(
            pk.as_bytes().len(),
            1952,
            "PQ public key should be 1952 bytes"
        );
        assert_eq!(
            sk.as_bytes().len(),
            32,
            "PQ secret key (seed) should be 32 bytes"
        );
    }

    #[test]
    fn pq_sign_verify_roundtrip() {
        let (pk, sk) = generate_pq_keypair();
        let msg = b"hello post-quantum exochain";
        let sig = sign_pq(msg, &sk).expect("sign_pq should succeed");
        assert!(
            verify_pq(msg, &sig, &pk),
            "verify_pq should accept a valid PostQuantum signature"
        );
    }

    #[test]
    fn pq_verify_fails_wrong_message() {
        let (pk, sk) = generate_pq_keypair();
        let sig = sign_pq(b"original", &sk).expect("sign_pq");
        assert!(!verify_pq(b"tampered", &sig, &pk));
    }

    #[test]
    fn pq_verify_fails_wrong_key() {
        let (_pk1, sk1) = generate_pq_keypair();
        let (pk2, _sk2) = generate_pq_keypair();
        let sig = sign_pq(b"msg", &sk1).expect("sign_pq");
        assert!(!verify_pq(b"msg", &sig, &pk2));
    }

    #[test]
    fn pq_verify_fails_corrupt_signature() {
        let (pk, sk) = generate_pq_keypair();
        let sig = sign_pq(b"msg", &sk).expect("sign_pq");
        let corrupted = match sig {
            Signature::PostQuantum(mut b) => {
                b[0] ^= 0xff;
                Signature::PostQuantum(b)
            }
            _ => panic!("expected PostQuantum"),
        };
        assert!(!verify_pq(b"msg", &corrupted, &pk));
    }

    #[test]
    fn pq_verify_rejects_wrong_variant() {
        let (pk, _) = generate_pq_keypair();
        assert!(!verify_pq(b"msg", &Signature::Empty, &pk));
        // Ed25519 signature presented to PQ verifier must be rejected
        let (_, classical_sk) = generate_keypair();
        let ed_sig = sign(b"msg", &classical_sk);
        assert!(!verify_pq(b"msg", &ed_sig, &pk));
    }

    #[test]
    fn pq_signature_has_correct_byte_length() {
        let (_, sk) = generate_pq_keypair();
        let sig = sign_pq(b"msg", &sk).expect("sign_pq");
        let Signature::PostQuantum(bytes) = sig else {
            panic!("expected PostQuantum variant");
        };
        // ML-DSA-65 signature is 3309 bytes (FIPS 204 §Table 1)
        assert_eq!(
            bytes.len(),
            3309,
            "ML-DSA-65 signature should be 3309 bytes"
        );
    }

    #[test]
    fn pq_sign_is_deterministic() {
        let (_, sk) = generate_pq_keypair();
        let msg = b"determinism";
        let sig1 = sign_pq(msg, &sk).expect("sign_pq");
        let sig2 = sign_pq(msg, &sk).expect("sign_pq");
        assert_eq!(
            sig1, sig2,
            "ML-DSA-65 deterministic signing must be reproducible"
        );
    }

    #[test]
    fn pq_keypair_struct_roundtrip() {
        let kp = PqKeyPair::generate();
        let msg = b"pq keypair test";
        let sig = kp.sign(msg).expect("PqKeyPair::sign");
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn pq_keypair_debug_redacts_secret() {
        let kp = PqKeyPair::generate();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("***"));
        assert!(dbg.contains("PqKeyPair"));
    }

    #[test]
    fn pq_invalid_sk_bytes_returns_error() {
        let bad_sk = PqSecretKey::from_bytes(vec![0u8; 8]); // wrong size
        let result = sign_pq(b"msg", &bad_sk);
        assert!(
            result.is_err(),
            "sign_pq with wrong-length seed should fail"
        );
    }

    // -----------------------------------------------------------------------
    // Hybrid Ed25519 + ML-DSA-65 — new tests
    // -----------------------------------------------------------------------

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let msg = b"hybrid dual-sign";
        let sig = sign_hybrid(msg, &classical_sk, &pq_sk).expect("sign_hybrid");
        assert!(
            verify_hybrid(msg, &sig, &classical_pk, &pq_pk),
            "verify_hybrid should accept a valid Hybrid signature"
        );
    }

    #[test]
    fn hybrid_verify_fails_wrong_message() {
        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let sig = sign_hybrid(b"original", &classical_sk, &pq_sk).expect("sign_hybrid");
        assert!(!verify_hybrid(b"tampered", &sig, &classical_pk, &pq_pk));
    }

    #[test]
    fn hybrid_verify_fails_wrong_classical_key() {
        let (_classical_pk1, classical_sk1) = generate_keypair();
        let (classical_pk2, _classical_sk2) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let sig = sign_hybrid(b"msg", &classical_sk1, &pq_sk).expect("sign_hybrid");
        assert!(!verify_hybrid(b"msg", &sig, &classical_pk2, &pq_pk));
    }

    #[test]
    fn hybrid_verify_fails_wrong_pq_key() {
        let (classical_pk, classical_sk) = generate_keypair();
        let (_pq_pk1, pq_sk1) = generate_pq_keypair();
        let (pq_pk2, _pq_sk2) = generate_pq_keypair();
        let sig = sign_hybrid(b"msg", &classical_sk, &pq_sk1).expect("sign_hybrid");
        assert!(!verify_hybrid(b"msg", &sig, &classical_pk, &pq_pk2));
    }

    #[test]
    fn hybrid_verify_fails_stripped_pq_component() {
        // Regression: previously verify() silently accepted Hybrid with only
        // the Ed25519 component valid (silent downgrade). This test confirms
        // verify_hybrid rejects a tampered PQ component — closing the gap
        // documented in EXOCHAIN-REM-005.
        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let sig = sign_hybrid(b"msg", &classical_sk, &pq_sk).expect("sign_hybrid");
        let tampered = match sig {
            Signature::Hybrid { classical, mut pq } => {
                pq[0] ^= 0xff;
                Signature::Hybrid { classical, pq }
            }
            _ => panic!("expected Hybrid"),
        };
        assert!(
            !verify_hybrid(b"msg", &tampered, &classical_pk, &pq_pk),
            "tampered PQ component must cause rejection (ExistentialSafeguard)"
        );
    }

    #[test]
    fn hybrid_verify_fails_stripped_classical_component() {
        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let sig = sign_hybrid(b"msg", &classical_sk, &pq_sk).expect("sign_hybrid");
        let tampered = match sig {
            Signature::Hybrid { mut classical, pq } => {
                classical[0] ^= 0xff;
                Signature::Hybrid { classical, pq }
            }
            _ => panic!("expected Hybrid"),
        };
        assert!(
            !verify_hybrid(b"msg", &tampered, &classical_pk, &pq_pk),
            "tampered Ed25519 component must cause rejection (DualControl)"
        );
    }

    #[test]
    fn hybrid_verify_rejects_wrong_variant() {
        let (classical_pk, _) = generate_keypair();
        let (pq_pk, _) = generate_pq_keypair();
        assert!(!verify_hybrid(
            b"msg",
            &Signature::Empty,
            &classical_pk,
            &pq_pk
        ));
        assert!(!verify_hybrid(
            b"msg",
            &Signature::PostQuantum(vec![0u8; 32]),
            &classical_pk,
            &pq_pk
        ));
    }
}
