//! Decentralized Identity (DID) document management.
//!
//! ## Hybrid verification methods
//!
//! `HybridVerificationMethod` binds an Ed25519 classical key and an
//! ML-DSA-65 post-quantum key to a single DID fragment.  Verification
//! requires **both** components to pass (strict AND, identical to
//! `crypto::verify_hybrid`), providing a cryptographic instantiation of
//! the `DualControl` constitutional invariant.

use std::collections::BTreeMap;

use exo_core::{Did, PqPublicKey, PublicKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;

/// Authentication method associated with a DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationMethod {
    pub id: String,
    pub method_type: String,
    pub public_key: PublicKey,
}

/// A service endpoint advertised by a DID subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub service_type: String,
    pub endpoint: String,
}

/// A W3C DID Core verification method.
///
/// Represents a cryptographic public key associated with a DID, supporting
/// key versioning, lifecycle management (active/revoked), and multibase-encoded
/// public key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Unique identifier, typically `did:exo:<id>#key-<version>`.
    pub id: String,
    /// Key type, e.g. `"Ed25519VerificationKey2020"`.
    pub key_type: String,
    /// DID of the entity that controls this key.
    pub controller: Did,
    /// Multibase-encoded public key (prefix `z` for base58btc).
    pub public_key_multibase: String,
    /// Key version (monotonically increasing per DID).
    pub version: u64,
    /// Whether this key is currently active.
    pub active: bool,
    /// Timestamp (physical_ms) from which this key is valid.
    pub valid_from: u64,
    /// Timestamp (physical_ms) at which this key was revoked, if any.
    pub revoked_at: Option<u64>,
}

/// A hybrid Ed25519 + ML-DSA-65 verification method bound to a DID.
///
/// Verification requires **both** the classical Ed25519 and post-quantum
/// ML-DSA-65 components to pass (`crypto::verify_hybrid`).  This is the
/// cryptographic instantiation of the `DualControl` constitutional invariant
/// and closes the silent Ed25519-only downgrade documented in EXOCHAIN-REM-005.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridVerificationMethod {
    /// Unique fragment identifier, typically `did:exo:<id>#hybrid-key-<version>`.
    pub id: String,
    /// Always `"HybridKeyEd25519MlDsa652020"` for this variant.
    pub key_type: String,
    /// DID of the entity that controls this key pair.
    pub controller: Did,
    /// Ed25519 verifying key (32 bytes, multibase `z`-prefixed base58btc).
    pub classical_public_key_multibase: String,
    /// ML-DSA-65 verifying key (1952 bytes, multibase `z`-prefixed base58btc).
    pub pq_public_key_multibase: String,
    /// ML-DSA-65 verifying key, stored as raw bytes for efficient verification.
    pub pq_public_key: PqPublicKey,
    /// Ed25519 verifying key, stored as raw bytes for efficient verification.
    pub classical_public_key: PublicKey,
    /// Key version (monotonically increasing per DID).
    pub version: u64,
    /// Whether this key pair is currently active.
    pub active: bool,
    /// Timestamp (physical_ms) from which this key pair is valid.
    pub valid_from: u64,
    /// Timestamp (physical_ms) at which this key pair was revoked, if any.
    pub revoked_at: Option<u64>,
}

impl HybridVerificationMethod {
    /// Verify a `Signature::Hybrid` against this method's key bundle.
    ///
    /// Delegates to `crypto::verify_hybrid`, which requires **both** the
    /// Ed25519 and ML-DSA-65 components to pass with no short-circuit.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if !self.active {
            return false;
        }
        crypto::verify_hybrid(
            message,
            signature,
            &self.classical_public_key,
            &self.pq_public_key,
        )
    }
}

/// Proof that a DID holder authorized a revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationProof {
    pub did: Did,
    pub signature: Signature,
}

/// A DID document describing a decentralized identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: Did,
    pub public_keys: Vec<PublicKey>,
    pub authentication: Vec<AuthenticationMethod>,
    /// W3C DID Core verification methods with lifecycle management.
    #[serde(default)]
    pub verification_methods: Vec<VerificationMethod>,
    /// Hybrid Ed25519 + ML-DSA-65 verification methods.
    #[serde(default)]
    pub hybrid_verification_methods: Vec<HybridVerificationMethod>,
    pub service_endpoints: Vec<ServiceEndpoint>,
    pub created: Timestamp,
    pub updated: Timestamp,
    pub revoked: bool,
}

/// In-memory DID registry using a `BTreeMap` for deterministic ordering.
#[derive(Debug, Default)]
pub struct DidRegistry {
    documents: BTreeMap<String, DidDocument>,
}

impl DidRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn resolve(&self, did: &Did) -> Option<&DidDocument> {
        self.documents.get(did.as_str()).filter(|doc| !doc.revoked)
    }

    pub fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError> {
        if self.documents.contains_key(doc.id.as_str()) {
            return Err(IdentityError::DuplicateDid(doc.id));
        }
        self.documents.insert(doc.id.as_str().to_owned(), doc);
        Ok(())
    }

    pub fn revoke(&mut self, did: &Did, proof: &RevocationProof) -> Result<(), IdentityError> {
        let doc = self
            .documents
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        let msg = did.as_str().as_bytes();
        let valid = doc
            .public_keys
            .iter()
            .any(|pk| crypto::verify(msg, &proof.signature, pk));

        if !valid {
            return Err(IdentityError::InvalidRevocationProof(did.clone()));
        }

        doc.revoked = true;
        Ok(())
    }

    pub fn rotate_key(
        &mut self,
        did: &Did,
        new_key: &PublicKey,
        proof: &Signature,
    ) -> Result<(), IdentityError> {
        let doc = self
            .documents
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        if doc.revoked {
            return Err(IdentityError::DidRevoked(did.clone()));
        }

        let msg = new_key.as_bytes();
        let valid = doc
            .public_keys
            .iter()
            .any(|pk| crypto::verify(msg, proof, pk));

        if !valid {
            return Err(IdentityError::InvalidSignature);
        }

        doc.public_keys.push(*new_key);
        doc.updated = Timestamp::new(doc.updated.physical_ms + 1, 0);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Return all registered DID strings in deterministic (sorted) order.
    #[must_use]
    pub fn list_dids(&self) -> Vec<&str> {
        self.documents.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    // bs58 is available as a dependency of this crate
    use bs58;
    use exo_core::crypto::{generate_keypair, sign};

    use super::*;

    fn make_did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("valid did")
    }

    fn make_doc(did: Did, pk: PublicKey) -> DidDocument {
        DidDocument {
            id: did,
            public_keys: vec![pk],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::new(1000, 0),
            updated: Timestamp::new(1000, 0),
            revoked: false,
        }
    }

    #[test]
    fn register_and_resolve() {
        let (pk, _sk) = generate_keypair();
        let did = make_did("alice");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.id, did);
    }

    #[test]
    fn duplicate_registration_fails() {
        let (pk, _sk) = generate_keypair();
        let did = make_did("bob");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc.clone()).unwrap();
        let err = reg.register(doc).unwrap_err();
        assert!(matches!(err, IdentityError::DuplicateDid(_)));
    }

    #[test]
    fn resolve_unknown_did_returns_none() {
        let reg = DidRegistry::new();
        assert!(reg.is_empty());
        let did = make_did("nonexistent");
        assert!(reg.resolve(&did).is_none());
    }

    #[test]
    fn revoke_did() {
        let (pk, sk) = generate_keypair();
        let did = make_did("charlie");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();

        let proof = RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk),
        };
        reg.revoke(&did, &proof).unwrap();
        assert!(reg.resolve(&did).is_none());
    }

    #[test]
    fn revoke_unknown_did_fails() {
        let (_pk, sk) = generate_keypair();
        let did = make_did("unknown");
        let proof = RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk),
        };

        let mut reg = DidRegistry::new();
        let err = reg.revoke(&did, &proof).unwrap_err();
        assert!(matches!(err, IdentityError::DidNotFound(_)));
    }

    #[test]
    fn revoke_with_invalid_proof_fails() {
        let (pk, _sk) = generate_keypair();
        let did = make_did("dave");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();

        let (_pk2, sk2) = generate_keypair();
        let proof = RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk2),
        };
        let err = reg.revoke(&did, &proof).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidRevocationProof(_)));
    }

    #[test]
    fn rotate_key_success() {
        let (pk, sk) = generate_keypair();
        let did = make_did("eve");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _new_sk) = generate_keypair();
        let proof = sign(new_pk.as_bytes(), &sk);
        reg.rotate_key(&did, &new_pk, &proof).unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.public_keys.len(), 2);
        assert!(resolved.updated.physical_ms > 1000);
    }

    #[test]
    fn rotate_key_unknown_did_fails() {
        let (_pk, sk) = generate_keypair();
        let did = make_did("unknown2");
        let (new_pk, _) = generate_keypair();
        let proof = sign(new_pk.as_bytes(), &sk);

        let mut reg = DidRegistry::new();
        let err = reg.rotate_key(&did, &new_pk, &proof).unwrap_err();
        assert!(matches!(err, IdentityError::DidNotFound(_)));
    }

    #[test]
    fn rotate_key_revoked_did_fails() {
        let (pk, sk) = generate_keypair();
        let did = make_did("frank");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();

        let revocation = RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk),
        };
        reg.revoke(&did, &revocation).unwrap();

        let (new_pk, _) = generate_keypair();
        let proof = sign(new_pk.as_bytes(), &sk);
        let err = reg.rotate_key(&did, &new_pk, &proof).unwrap_err();
        assert!(matches!(err, IdentityError::DidRevoked(_)));
    }

    #[test]
    fn rotate_key_invalid_signature_fails() {
        let (pk, _sk) = generate_keypair();
        let did = make_did("grace");
        let doc = make_doc(did.clone(), pk);

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _) = generate_keypair();
        let (_other_pk, other_sk) = generate_keypair();
        let bad_proof = sign(new_pk.as_bytes(), &other_sk);
        let err = reg.rotate_key(&did, &new_pk, &bad_proof).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidSignature));
    }

    #[test]
    fn authentication_method_and_service_endpoint() {
        let (pk, _sk) = generate_keypair();
        let did = make_did("heidi");
        let doc = DidDocument {
            id: did.clone(),
            public_keys: vec![pk],
            authentication: vec![AuthenticationMethod {
                id: "auth-1".into(),
                method_type: "Ed25519VerificationKey2020".into(),
                public_key: pk,
            }],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![ServiceEndpoint {
                id: "svc-1".into(),
                service_type: "ExochainMessaging".into(),
                endpoint: "https://example.com/msg".into(),
            }],
            created: Timestamp::new(1000, 0),
            updated: Timestamp::new(1000, 0),
            revoked: false,
        };

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();
        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.authentication.len(), 1);
        assert_eq!(resolved.authentication[0].id, "auth-1");
        assert_eq!(resolved.service_endpoints.len(), 1);
        assert_eq!(
            resolved.service_endpoints[0].endpoint,
            "https://example.com/msg"
        );
    }

    #[test]
    fn list_dids_returns_sorted_ids() {
        let (pk1, _) = generate_keypair();
        let (pk2, _) = generate_keypair();
        let mut reg = DidRegistry::new();
        reg.register(make_doc(make_did("charlie"), pk1)).unwrap();
        reg.register(make_doc(make_did("alice"), pk2)).unwrap();
        let dids = reg.list_dids();
        // BTreeMap iteration is sorted, so alice comes before charlie.
        assert_eq!(dids, vec!["did:exo:alice", "did:exo:charlie"]);
    }

    // -----------------------------------------------------------------------
    // HybridVerificationMethod tests
    // -----------------------------------------------------------------------

    fn make_hybrid_method(
        did: &Did,
        pk: PublicKey,
        pq_pk: PqPublicKey,
    ) -> HybridVerificationMethod {
        let classical_mb = format!("z{}", bs58::encode(pk.as_bytes()).into_string());
        let pq_mb = format!("z{}", bs58::encode(pq_pk.as_bytes()).into_string());
        HybridVerificationMethod {
            id: format!("{}#hybrid-key-1", did.as_str()),
            key_type: "HybridKeyEd25519MlDsa652020".into(),
            controller: did.clone(),
            classical_public_key_multibase: classical_mb,
            pq_public_key_multibase: pq_mb,
            pq_public_key: pq_pk,
            classical_public_key: pk,
            version: 1,
            active: true,
            valid_from: 1000,
            revoked_at: None,
        }
    }

    #[test]
    fn hybrid_method_verify_roundtrip() {
        use exo_core::crypto::{generate_pq_keypair, sign_hybrid};

        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let did = make_did("hybrid-alice");

        let method = make_hybrid_method(&did, classical_pk, pq_pk);
        let message = b"hybrid DID verification";
        let sig = sign_hybrid(message, &classical_sk, &pq_sk).expect("sign_hybrid");
        assert!(
            method.verify(message, &sig),
            "HybridVerificationMethod::verify must accept valid Hybrid signature"
        );
    }

    #[test]
    fn hybrid_method_verify_fails_wrong_message() {
        use exo_core::crypto::{generate_pq_keypair, sign_hybrid};

        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let did = make_did("hybrid-bob");
        let method = make_hybrid_method(&did, classical_pk, pq_pk);
        let sig = sign_hybrid(b"original", &classical_sk, &pq_sk).expect("sign_hybrid");
        assert!(!method.verify(b"tampered", &sig));
    }

    #[test]
    fn hybrid_method_verify_fails_wrong_key() {
        use exo_core::crypto::{generate_pq_keypair, sign_hybrid};

        let (_pk1, sk1) = generate_keypair();
        let (pk2, _sk2) = generate_keypair();
        let (_pq1, pq_sk1) = generate_pq_keypair();
        let (pq2, _pq_sk2) = generate_pq_keypair();
        let did = make_did("hybrid-carol");
        // Method uses pk2/pq2 but signature was made with sk1/pq_sk1
        let method = make_hybrid_method(&did, pk2, pq2);
        let sig = sign_hybrid(b"msg", &sk1, &pq_sk1).expect("sign_hybrid");
        assert!(!method.verify(b"msg", &sig));
    }

    #[test]
    fn hybrid_method_inactive_always_fails() {
        use exo_core::crypto::{generate_pq_keypair, sign_hybrid};

        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let did = make_did("hybrid-dave");
        let mut method = make_hybrid_method(&did, classical_pk, pq_pk);
        method.active = false;
        let sig = sign_hybrid(b"msg", &classical_sk, &pq_sk).expect("sign_hybrid");
        assert!(
            !method.verify(b"msg", &sig),
            "inactive hybrid method must always reject verification"
        );
    }

    #[test]
    fn hybrid_method_rejects_non_hybrid_signature() {
        use exo_core::crypto::generate_pq_keypair;

        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, _pq_sk) = generate_pq_keypair();
        let did = make_did("hybrid-eve");
        let method = make_hybrid_method(&did, classical_pk, pq_pk);
        // Present a classical Ed25519 signature to a hybrid verifier
        let ed_sig = exo_core::crypto::sign(b"msg", &classical_sk);
        assert!(
            !method.verify(b"msg", &ed_sig),
            "hybrid method must reject plain Ed25519 signature (no downgrade)"
        );
    }

    #[test]
    fn did_document_with_hybrid_method_roundtrip() {
        use exo_core::crypto::{generate_pq_keypair, sign_hybrid};

        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        let did = make_did("hybrid-frank");
        let hybrid_method = make_hybrid_method(&did, classical_pk, pq_pk);

        let doc = DidDocument {
            id: did.clone(),
            public_keys: vec![classical_pk],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![hybrid_method],
            service_endpoints: vec![],
            created: Timestamp::new(1000, 0),
            updated: Timestamp::new(1000, 0),
            revoked: false,
        };

        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.hybrid_verification_methods.len(), 1);

        let method = &resolved.hybrid_verification_methods[0];
        let msg = b"hybrid DID doc test";
        let sig = sign_hybrid(msg, &classical_sk, &pq_sk).expect("sign_hybrid");
        assert!(method.verify(msg, &sig));
    }
}
