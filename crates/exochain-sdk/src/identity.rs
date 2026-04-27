//! Decentralized identity — DIDs backed by Ed25519 keypairs.
//!
//! [`Identity`] is the SDK's ergonomic handle to a DID with its associated
//! Ed25519 keypair. The DID is derived deterministically from the public key
//! so that two identities generated with different entropy always produce
//! different DIDs, while an identity re-constructed from the same key bytes
//! always yields the same DID.
//!
//! ## When to reach for this module
//!
//! - Every actor in EXOCHAIN — human, AI agent, service, organization — needs
//!   an [`Identity`]. The identity's DID is the principal that appears in
//!   bailments, decisions, authority chains, and kernel adjudications.
//! - Signatures produced by [`Identity::sign`] feed straight into the kernel
//!   as proof of provenance.
//!
//! ## Quick start
//!
//! ```
//! use exochain_sdk::identity::Identity;
//!
//! let alice = Identity::generate("alice");
//! let sig = alice.sign(b"hello");
//! assert!(alice.verify(b"hello", &sig));
//! ```

use exo_core::{
    Did, PublicKey, SecretKey, Signature, Timestamp,
    crypto::{generate_keypair, sign as core_sign, verify as core_verify},
};
use exo_identity::did::DidDocument;

use crate::error::{ExoError, ExoResult};

const KEYPAIR_PROOF_MESSAGE: &[u8] = b"exo.sdk.identity.keypair.v1";

/// A DID paired with its Ed25519 keypair and a human-readable label.
///
/// Local identities are created either with [`Identity::generate`] (fresh
/// random keypair) or [`Identity::from_keypair`] (reuse an existing keypair,
/// e.g. loaded from a keystore). The local SDK DID is derived from the public
/// key as:
///
/// ```text
/// did:exo: + first 16 hex chars of BLAKE3(public_key_bytes)
/// ```
///
/// Use [`Identity::from_resolved_keypair`] when the canonical DID has already
/// been resolved from the fabric and must not be re-derived locally.
///
/// The `Debug` implementation deliberately redacts the secret key so identities
/// can be logged without leaking private material.
///
/// # Examples
///
/// ```
/// use exochain_sdk::identity::Identity;
///
/// let alice = Identity::generate("alice");
/// assert!(alice.did().as_str().starts_with("did:exo:"));
/// assert_eq!(alice.label(), "alice");
///
/// // Debug never leaks the secret key.
/// let debug = format!("{alice:?}");
/// assert!(debug.contains("***"));
/// ```
pub struct Identity {
    did: Did,
    public: PublicKey,
    secret: SecretKey,
    label: String,
}

impl Identity {
    /// Generate a fresh identity with a random Ed25519 keypair and a DID
    /// derived from the public key.
    ///
    /// The `label` is stored alongside the identity for developer convenience
    /// and is never cryptographically bound to the DID — renaming an identity
    /// does not change its DID.
    ///
    /// Use this when you need a brand-new principal. Use
    /// [`Identity::from_keypair`] when loading a previously generated keypair
    /// from storage.
    ///
    /// This method is infallible in practice: the method-specific portion of
    /// the DID is always 16 lowercase hex characters, which satisfies DID
    /// validation. In the unreachable case of validation failure, the DID
    /// falls back to `did:exo:sdk-fallback`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::identity::Identity;
    ///
    /// let id = Identity::generate("agent");
    /// assert!(id.did().as_str().starts_with("did:exo:"));
    /// assert_eq!(id.did().as_str().len(), "did:exo:".len() + 16);
    /// ```
    ///
    /// Two fresh identities have different DIDs:
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let a = Identity::generate("a");
    /// let b = Identity::generate("b");
    /// assert_ne!(a.did(), b.did());
    /// ```
    #[must_use]
    pub fn generate(label: &str) -> Self {
        let (public, secret) = generate_keypair();
        let did = derive_did(&public).unwrap_or_else(|_| fallback_did());
        Self {
            did,
            public,
            secret,
            label: label.to_owned(),
        }
    }

    /// Build an [`Identity`] from an existing Ed25519 keypair and label.
    ///
    /// The DID is derived from the public key in the same way as
    /// [`Identity::generate`]. Reconstructing an identity from the same
    /// keypair always produces the same DID.
    ///
    /// Use this to load a persisted identity, or to rehydrate the identity
    /// belonging to another actor when you only know their public material.
    ///
    /// # Errors
    ///
    /// Returns [`ExoError::InvalidDid`] only in the highly unlikely case that
    /// BLAKE3 output somehow failed DID validation — this should be
    /// unreachable in practice.
    ///
    /// # Examples
    ///
    /// Build an identity from a freshly generated keypair using the
    /// underlying core crypto primitives.
    ///
    /// ```
    /// use exochain_sdk::identity::Identity;
    /// use exo_core::crypto::generate_keypair;
    ///
    /// let (public, secret) = generate_keypair();
    /// let alice = Identity::from_keypair("alice", public, secret)?;
    /// assert!(alice.did().as_str().starts_with("did:exo:"));
    /// assert_eq!(alice.label(), "alice");
    /// # Ok::<(), exochain_sdk::error::ExoError>(())
    /// ```
    pub fn from_keypair(label: &str, public: PublicKey, secret: SecretKey) -> ExoResult<Self> {
        let did = derive_did(&public)?;
        Self::from_resolved_keypair(label, did, public, secret)
    }

    /// Build an [`Identity`] from an existing Ed25519 keypair and a DID that
    /// was resolved from the canonical fabric.
    ///
    /// Unlike [`Identity::from_keypair`], this method preserves the supplied
    /// DID instead of re-deriving a local SDK DID from the public key. It is
    /// intended for cross-language or gateway-backed flows where the fabric
    /// has already resolved the DID document and associated public key.
    ///
    /// # Errors
    ///
    /// Returns [`ExoError::Identity`] when the supplied secret key does not
    /// match the supplied public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use exo_core::{Did, crypto::generate_keypair};
    /// use exochain_sdk::identity::Identity;
    ///
    /// let (public, secret) = generate_keypair();
    /// let did = Did::new("did:exo:fabric-resolved")?;
    /// let identity = Identity::from_resolved_keypair("alice", did.clone(), public, secret)?;
    /// assert_eq!(identity.did(), &did);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_resolved_keypair(
        label: &str,
        did: Did,
        public: PublicKey,
        secret: SecretKey,
    ) -> ExoResult<Self> {
        verify_keypair_match(&public, &secret)?;
        Ok(Self {
            did,
            public,
            secret,
            label: label.to_owned(),
        })
    }

    /// Return the DID for this identity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let id = Identity::generate("alice");
    /// assert!(id.did().as_str().starts_with("did:exo:"));
    /// ```
    #[must_use]
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// Return the Ed25519 public key.
    ///
    /// Public keys are safe to share and can be handed to counterparties so
    /// they can verify signatures this identity produces.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let id = Identity::generate("alice");
    /// let pk = id.public_key();
    /// assert_eq!(pk.as_bytes().len(), 32);
    /// ```
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Return the human-readable label.
    ///
    /// Labels are developer affordances and have no cryptographic meaning.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let id = Identity::generate("alice");
    /// assert_eq!(id.label(), "alice");
    /// ```
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Sign `message` with this identity's secret key (Ed25519).
    ///
    /// The returned [`Signature`] is suitable for feeding into
    /// [`Identity::verify`] or into the kernel's provenance field.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let id = Identity::generate("signer");
    /// let sig = id.sign(b"hello");
    /// assert!(id.verify(b"hello", &sig));
    /// ```
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        core_sign(message, &self.secret)
    }

    /// Verify `signature` over `message` against this identity's public key.
    ///
    /// Returns `true` only if the signature was produced by the matching
    /// secret key over exactly these message bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let id = Identity::generate("signer");
    /// let sig = id.sign(b"hello");
    /// assert!(id.verify(b"hello", &sig));
    /// assert!(!id.verify(b"tampered", &sig));
    /// ```
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        core_verify(message, signature, &self.public)
    }

    /// Build a minimal [`DidDocument`] describing this identity.
    ///
    /// The resulting document contains the identity's single Ed25519 public
    /// key, with empty authentication/verification-method/service-endpoint
    /// lists and `created == updated == Timestamp::ZERO`. Callers can augment
    /// the document after construction if they need richer DID metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::identity::Identity;
    /// let id = Identity::generate("alice");
    /// let doc = id.did_document();
    /// assert_eq!(&doc.id, id.did());
    /// assert_eq!(doc.public_keys.len(), 1);
    /// assert!(!doc.revoked);
    /// ```
    #[must_use]
    pub fn did_document(&self) -> DidDocument {
        DidDocument {
            id: self.did.clone(),
            public_keys: vec![self.public],
            authentication: Vec::new(),
            verification_methods: Vec::new(),
            hybrid_verification_methods: Vec::new(),
            service_endpoints: Vec::new(),
            created: Timestamp::ZERO,
            updated: Timestamp::ZERO,
            revoked: false,
        }
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("did", &self.did)
            .field("label", &self.label)
            .field("public", &self.public)
            .field("secret", &"***")
            .finish()
    }
}

/// Derive `did:exo:<first 16 hex chars of BLAKE3(public_key_bytes)>`.
fn derive_did(public: &PublicKey) -> ExoResult<Did> {
    let digest = blake3::hash(public.as_bytes());
    let bytes = digest.as_bytes();
    let mut hex = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        hex.push_str(&format!("{byte:02x}"));
    }
    let did_str = format!("did:exo:{hex}");
    Did::new(&did_str).map_err(|e| ExoError::InvalidDid(e.to_string()))
}

fn verify_keypair_match(public: &PublicKey, secret: &SecretKey) -> ExoResult<()> {
    let signature = core_sign(KEYPAIR_PROOF_MESSAGE, secret);
    if core_verify(KEYPAIR_PROOF_MESSAGE, &signature, public) {
        Ok(())
    } else {
        Err(ExoError::Identity(
            "secret key does not match public key".to_owned(),
        ))
    }
}

/// Fallback DID for the unreachable case where hex-derived DIDs fail
/// validation.  Never observed in practice; present only so that
/// [`Identity::generate`] remains infallible.
#[allow(clippy::expect_used)] // static DID "did:exo:sdk-fallback" is unconditionally valid
fn fallback_did() -> Did {
    Did::new("did:exo:sdk-fallback").expect("did:exo:sdk-fallback is a well-formed DID")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::error::ExoError;

    #[test]
    fn generate_produces_valid_did() {
        let id = Identity::generate("alice");
        assert!(id.did().as_str().starts_with("did:exo:"));
        // 16 hex chars after the prefix.
        assert_eq!(id.did().as_str().len(), "did:exo:".len() + 16);
    }

    #[test]
    fn generate_stores_label() {
        let id = Identity::generate("alice");
        assert_eq!(id.label(), "alice");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = Identity::generate("signer");
        let sig = id.sign(b"hello");
        assert!(id.verify(b"hello", &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let id = Identity::generate("signer");
        let sig = id.sign(b"original");
        assert!(!id.verify(b"tampered", &sig));
    }

    #[test]
    fn different_identities_produce_different_dids() {
        let a = Identity::generate("a");
        let b = Identity::generate("b");
        // Random keypairs should never collide in practice; the check is on
        // the DID (derived from the public key) not the label.
        assert_ne!(a.did(), b.did());
    }

    #[test]
    fn from_keypair_derives_same_did_as_generate() {
        let id = Identity::generate("first");
        let rebuilt = Identity::from_keypair(
            "rebuilt",
            *id.public_key(),
            SecretKey::from_bytes(*id.secret.as_bytes()),
        )
        .expect("ok");
        assert_eq!(id.did(), rebuilt.did());
        assert_eq!(rebuilt.label(), "rebuilt");
    }

    #[test]
    fn from_resolved_keypair_preserves_fabric_resolved_did() {
        let id = Identity::generate("local");
        let fabric_did = Did::new("did:exo:fabric-resolved").unwrap();

        let rebuilt = Identity::from_resolved_keypair(
            "fabric",
            fabric_did.clone(),
            *id.public_key(),
            SecretKey::from_bytes(*id.secret.as_bytes()),
        )
        .expect("resolved identity");

        assert_eq!(rebuilt.did(), &fabric_did);
        assert_ne!(rebuilt.did(), id.did());
        assert_eq!(rebuilt.label(), "fabric");
        let sig = rebuilt.sign(b"resolved fabric DID");
        assert!(rebuilt.verify(b"resolved fabric DID", &sig));
    }

    #[test]
    fn from_resolved_keypair_rejects_mismatched_public_and_secret_keys() {
        let public_source = Identity::generate("public");
        let secret_source = Identity::generate("secret");
        let fabric_did = Did::new("did:exo:fabric-mismatch").unwrap();

        let err = Identity::from_resolved_keypair(
            "fabric",
            fabric_did,
            *public_source.public_key(),
            SecretKey::from_bytes(*secret_source.secret.as_bytes()),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ExoError::Identity(msg) if msg.contains("does not match public key")
        ));
    }

    #[test]
    fn did_document_contains_identity_fields() {
        let id = Identity::generate("doc");
        let doc = id.did_document();
        assert_eq!(&doc.id, id.did());
        assert_eq!(doc.public_keys.len(), 1);
        assert_eq!(&doc.public_keys[0], id.public_key());
        assert!(!doc.revoked);
        assert!(doc.authentication.is_empty());
        assert!(doc.verification_methods.is_empty());
        assert!(doc.hybrid_verification_methods.is_empty());
        assert!(doc.service_endpoints.is_empty());
    }

    #[test]
    fn debug_redacts_secret() {
        let id = Identity::generate("secret-test");
        let dbg = format!("{id:?}");
        assert!(dbg.contains("***"));
        assert!(dbg.contains("Identity"));
    }

    #[test]
    fn public_key_accessor() {
        let id = Identity::generate("pk");
        // PublicKey implements Copy; the accessor returns a reference we can
        // compare against itself via dereference.
        let pk = *id.public_key();
        assert_eq!(&pk, id.public_key());
    }
}
