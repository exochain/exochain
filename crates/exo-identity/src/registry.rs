use crate::did::{DidDocument, RevocationProof};
use crate::error::IdentityError;
use exo_core::{Did, PublicKey, Signature, Timestamp, crypto};
use std::collections::BTreeMap;

/// A decentralized identifier registry trait.
pub trait DidRegistry {
    /// Register a new DID document.
    fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError>;

    /// Resolve a DID to its document.
    fn resolve(&self, did: &Did) -> Option<&DidDocument>;

    /// Revoke a DID after verifying the proof.
    fn revoke(&mut self, did: &Did, proof: &RevocationProof) -> Result<(), IdentityError>;

    /// Rotate the key for a DID after verifying the proof.
    fn rotate_key(
        &mut self,
        did: &Did,
        new_key: &PublicKey,
        proof: &Signature,
    ) -> Result<(), IdentityError>;
}

/// A local, in-memory implementation of the `DidRegistry` trait.
#[derive(Debug, Default)]
pub struct LocalDidRegistry {
    documents: BTreeMap<String, DidDocument>,
}

impl LocalDidRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    #[must_use]
    pub fn list_dids(&self) -> Vec<&str> {
        self.documents.keys().map(String::as_str).collect()
    }
}

impl DidRegistry for LocalDidRegistry {
    fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError> {
        if self.documents.contains_key(doc.id.as_str()) {
            return Err(IdentityError::DuplicateDid(doc.id));
        }
        self.documents.insert(doc.id.as_str().to_owned(), doc);
        Ok(())
    }

    fn resolve(&self, did: &Did) -> Option<&DidDocument> {
        self.documents.get(did.as_str()).filter(|doc| !doc.revoked)
    }

    fn revoke(&mut self, did: &Did, proof: &RevocationProof) -> Result<(), IdentityError> {
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

    fn rotate_key(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::DidDocument;
    use exo_core::crypto::{generate_keypair, sign};

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
    fn test_register_and_resolve() {
        let (pk, _) = generate_keypair();
        let did = make_did("alice");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();
        assert_eq!(reg.len(), 1);

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.id, did);
    }

    #[test]
    fn test_revoke_did() {
        let (pk, sk) = generate_keypair();
        let did = make_did("bob");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let proof = RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk),
        };
        reg.revoke(&did, &proof).unwrap();

        assert!(reg.resolve(&did).is_none());
    }

    #[test]
    fn test_add_verification_method() {
        // We'll test rotate_key which adds a new public key.
        let (pk, sk) = generate_keypair();
        let did = make_did("charlie");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _) = generate_keypair();
        let proof = sign(new_pk.as_bytes(), &sk);

        reg.rotate_key(&did, &new_pk, &proof).unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.public_keys.len(), 2);
    }

    #[test]
    fn test_resolve_nonexistent() {
        let reg = LocalDidRegistry::new();
        let did = make_did("nobody");

        assert!(reg.resolve(&did).is_none());
    }
}
