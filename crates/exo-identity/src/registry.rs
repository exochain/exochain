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

use std::collections::BTreeMap;

use exo_core::{Did, PublicKey, Signature, Timestamp, crypto};
use serde::Serialize;

use crate::{
    did::{DidDocument, RevocationProof},
    error::IdentityError,
};

const DID_REVOCATION_PROOF_DOMAIN: &str = "exo.identity.did_registry.revocation.v1";
const DID_KEY_ROTATION_PROOF_DOMAIN: &str = "exo.identity.did_registry.key_rotation.v1";
pub const MAX_LOCAL_DID_REGISTRY_DOCUMENTS: usize = 16_384;
const MAX_DID_DOCUMENT_ID_BYTES: usize = 512;
const MAX_DID_DOCUMENT_PUBLIC_KEYS: usize = 16;
const MAX_DID_DOCUMENT_AUTHENTICATION_METHODS: usize = 32;
const MAX_DID_DOCUMENT_VERIFICATION_METHODS: usize = 32;
const MAX_DID_DOCUMENT_HYBRID_VERIFICATION_METHODS: usize = 16;
const MAX_DID_DOCUMENT_SERVICE_ENDPOINTS: usize = 32;
const MAX_DID_DOCUMENT_FIELD_BYTES: usize = 1024;
const MAX_DID_DOCUMENT_PQ_MULTIBASE_BYTES: usize = 4096;
const MAX_DID_DOCUMENT_ENDPOINT_BYTES: usize = 2048;

#[derive(Serialize)]
struct RevocationProofPayload<'a> {
    domain: &'static str,
    did: &'a Did,
}

#[derive(Serialize)]
struct KeyRotationProofPayload<'a> {
    domain: &'static str,
    did: &'a Did,
    new_public_key: &'a [u8; 32],
    updated: Timestamp,
}

/// Build the canonical signable payload for DID revocation proofs.
///
/// The explicit domain prevents raw DID-string signatures from being replayed
/// into revocation, or revocation signatures from being replayed into another
/// DID protocol step.
pub(crate) fn revocation_proof_payload(did: &Did) -> Result<Vec<u8>, IdentityError> {
    let payload = RevocationProofPayload {
        domain: DID_REVOCATION_PROOF_DOMAIN,
        did,
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        IdentityError::RevocationProofPayloadEncoding {
            did: did.clone(),
            reason: e.to_string(),
        }
    })?;
    Ok(encoded)
}

/// Build the canonical signable payload for DID key-rotation proofs.
///
/// The payload binds the signature to key rotation for one DID, one replacement
/// public key, and one caller-supplied HLC timestamp so raw public-key
/// signatures and stale rotation proofs cannot be replayed into this method.
pub fn key_rotation_proof_payload(
    did: &Did,
    new_key: &PublicKey,
    updated: Timestamp,
) -> Result<Vec<u8>, IdentityError> {
    let payload = KeyRotationProofPayload {
        domain: DID_KEY_ROTATION_PROOF_DOMAIN,
        did,
        new_public_key: new_key.as_bytes(),
        updated,
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        IdentityError::KeyRotationProofPayloadEncoding {
            did: did.clone(),
            reason: e.to_string(),
        }
    })?;
    Ok(encoded)
}

/// A decentralized identifier registry trait.
pub trait DidRegistry {
    /// Register a new DID document.
    fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError>;

    /// Resolve a DID to its document.
    fn resolve(&self, did: &Did) -> Option<&DidDocument>;

    /// Revoke a DID after verifying the proof.
    fn revoke(&mut self, did: &Did, proof: &RevocationProof) -> Result<(), IdentityError>;

    /// Rotate the key for a DID after verifying the proof.
    ///
    /// `updated` must be supplied by the caller's deterministic execution
    /// context, normally an `exo_core::hlc::HybridClock`, and must advance
    /// past the current document timestamp.
    fn rotate_key(
        &mut self,
        did: &Did,
        new_key: &PublicKey,
        proof: &Signature,
        updated: Timestamp,
    ) -> Result<(), IdentityError>;
}

/// A local, in-memory implementation of the `DidRegistry` trait.
#[derive(Debug)]
pub struct LocalDidRegistry {
    documents: BTreeMap<String, DidDocument>,
    max_documents: usize,
}

impl Default for LocalDidRegistry {
    fn default() -> Self {
        Self {
            documents: BTreeMap::new(),
            max_documents: MAX_LOCAL_DID_REGISTRY_DOCUMENTS,
        }
    }
}

impl LocalDidRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_max_documents(max_documents: usize) -> Self {
        Self {
            documents: BTreeMap::new(),
            max_documents,
        }
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

fn ensure_byte_bound(did: &str, field: &str, value: &str, max: usize) -> Result<(), IdentityError> {
    let actual = value.len();
    if actual > max {
        return Err(IdentityError::DidDocumentFieldTooLarge {
            did: did.to_owned(),
            field: field.to_owned(),
            max,
            actual,
        });
    }
    Ok(())
}

fn ensure_len_bound(
    did: &str,
    field: &str,
    actual: usize,
    max: usize,
) -> Result<(), IdentityError> {
    if actual > max {
        return Err(IdentityError::DidDocumentFieldTooLarge {
            did: did.to_owned(),
            field: field.to_owned(),
            max,
            actual,
        });
    }
    Ok(())
}

fn validate_registered_did_document(doc: &DidDocument) -> Result<(), IdentityError> {
    let did = doc.id.as_str();
    Did::new(did).map_err(|e| IdentityError::InvalidDidDocumentField {
        did: did.to_owned(),
        field: "id".to_owned(),
        reason: e.to_string(),
    })?;
    ensure_byte_bound(did, "id", did, MAX_DID_DOCUMENT_ID_BYTES)?;
    ensure_len_bound(
        did,
        "public_keys",
        doc.public_keys.len(),
        MAX_DID_DOCUMENT_PUBLIC_KEYS,
    )?;
    ensure_len_bound(
        did,
        "authentication",
        doc.authentication.len(),
        MAX_DID_DOCUMENT_AUTHENTICATION_METHODS,
    )?;
    ensure_len_bound(
        did,
        "verification_methods",
        doc.verification_methods.len(),
        MAX_DID_DOCUMENT_VERIFICATION_METHODS,
    )?;
    ensure_len_bound(
        did,
        "hybrid_verification_methods",
        doc.hybrid_verification_methods.len(),
        MAX_DID_DOCUMENT_HYBRID_VERIFICATION_METHODS,
    )?;
    ensure_len_bound(
        did,
        "service_endpoints",
        doc.service_endpoints.len(),
        MAX_DID_DOCUMENT_SERVICE_ENDPOINTS,
    )?;

    for method in &doc.authentication {
        ensure_byte_bound(
            did,
            "authentication.id",
            &method.id,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "authentication.method_type",
            &method.method_type,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
    }
    for method in &doc.verification_methods {
        ensure_byte_bound(
            did,
            "verification_methods.id",
            &method.id,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "verification_methods.key_type",
            &method.key_type,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "verification_methods.controller",
            method.controller.as_str(),
            MAX_DID_DOCUMENT_ID_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "verification_methods.public_key_multibase",
            &method.public_key_multibase,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
    }
    for method in &doc.hybrid_verification_methods {
        ensure_byte_bound(
            did,
            "hybrid_verification_methods.id",
            &method.id,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "hybrid_verification_methods.key_type",
            &method.key_type,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "hybrid_verification_methods.controller",
            method.controller.as_str(),
            MAX_DID_DOCUMENT_ID_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "hybrid_verification_methods.classical_public_key_multibase",
            &method.classical_public_key_multibase,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "hybrid_verification_methods.pq_public_key_multibase",
            &method.pq_public_key_multibase,
            MAX_DID_DOCUMENT_PQ_MULTIBASE_BYTES,
        )?;
    }
    for endpoint in &doc.service_endpoints {
        ensure_byte_bound(
            did,
            "service_endpoints.id",
            &endpoint.id,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "service_endpoints.service_type",
            &endpoint.service_type,
            MAX_DID_DOCUMENT_FIELD_BYTES,
        )?;
        ensure_byte_bound(
            did,
            "service_endpoints.endpoint",
            &endpoint.endpoint,
            MAX_DID_DOCUMENT_ENDPOINT_BYTES,
        )?;
    }

    Ok(())
}

impl DidRegistry for LocalDidRegistry {
    fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError> {
        if self.documents.contains_key(doc.id.as_str()) {
            return Err(IdentityError::DuplicateDid(doc.id));
        }
        validate_registered_did_document(&doc)?;
        if self.documents.len() >= self.max_documents {
            return Err(IdentityError::RegistryCapacityExceeded {
                max_documents: self.max_documents,
                attempted_documents: self.documents.len().saturating_add(1),
            });
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

        let msg = revocation_proof_payload(did)?;
        let valid = doc
            .public_keys
            .iter()
            .any(|pk| crypto::verify(&msg, &proof.signature, pk));

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
        updated: Timestamp,
    ) -> Result<(), IdentityError> {
        let doc = self
            .documents
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        if doc.revoked {
            return Err(IdentityError::DidRevoked(did.clone()));
        }

        let msg = key_rotation_proof_payload(did, new_key, updated)?;
        let valid = doc
            .public_keys
            .iter()
            .any(|pk| crypto::verify(&msg, proof, pk));

        if !valid {
            return Err(IdentityError::InvalidSignature);
        }

        if updated <= doc.updated {
            return Err(IdentityError::NonMonotonicTimestamp {
                did: did.clone(),
                current: doc.updated,
                proposed: updated,
            });
        }

        doc.public_keys.clear();
        doc.public_keys.push(*new_key);
        doc.updated = updated;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use exo_core::{
        SecretKey,
        crypto::{generate_keypair, sign},
    };

    use super::*;
    use crate::did::DidDocument;

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

    fn make_doc_with_label(label: &str, pk: PublicKey) -> DidDocument {
        make_doc(make_did(label), pk)
    }

    fn rotation_signature(
        did: &Did,
        new_key: &PublicKey,
        updated: Timestamp,
        secret_key: &SecretKey,
    ) -> Signature {
        let payload = key_rotation_proof_payload(did, new_key, updated).unwrap();
        sign(&payload, secret_key)
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
    fn register_rejects_documents_after_default_registry_capacity() {
        let (pk, _) = generate_keypair();
        let mut reg = LocalDidRegistry::new();

        for i in 0..MAX_LOCAL_DID_REGISTRY_DOCUMENTS {
            reg.register(make_doc_with_label(&format!("capacity-{i:05}"), pk))
                .unwrap();
        }

        let err = reg
            .register(make_doc_with_label("capacity-overflow", pk))
            .expect_err("registry must reject documents after the fixed capacity");

        assert!(
            err.to_string().contains("capacity"),
            "capacity error should carry diagnostic context: {err}"
        );
        assert_eq!(reg.len(), MAX_LOCAL_DID_REGISTRY_DOCUMENTS);
    }

    #[test]
    fn register_rejects_did_document_with_unbounded_public_keys() {
        let (pk, _) = generate_keypair();
        let mut doc = make_doc_with_label("too-many-keys", pk);
        doc.public_keys = vec![pk; 17];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("oversized DID document vectors must be rejected");

        assert!(
            err.to_string().contains("public_keys"),
            "field-specific bound error should identify public_keys: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_revalidates_deserialized_did_document_id() {
        let (pk, _) = generate_keypair();
        let mut value =
            serde_json::to_value(make_doc_with_label("deserialized-invalid-did", pk)).unwrap();
        value["id"] = serde_json::json!("not-a-did");
        let doc: DidDocument = serde_json::from_value(value).unwrap();

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("registry must reject deserialized DIDs that bypass Did::new");

        assert!(
            err.to_string().contains("id"),
            "invalid DID error should identify the id field: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_revoke_did() {
        let (pk, sk) = generate_keypair();
        let did = make_did("bob");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let payload = revocation_proof_payload(&did).unwrap();
        let proof = RevocationProof {
            did: did.clone(),
            signature: sign(&payload, &sk),
        };
        reg.revoke(&did, &proof).unwrap();

        assert!(reg.resolve(&did).is_none());
    }

    #[test]
    fn revoke_requires_domain_separated_payload_not_raw_did() {
        let (pk, sk) = generate_keypair();
        let did = make_did("domain-revoke");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let raw_proof = RevocationProof {
            did: did.clone(),
            signature: sign(did.as_str().as_bytes(), &sk),
        };
        let err = reg.revoke(&did, &raw_proof).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidRevocationProof(_)));
        assert!(reg.resolve(&did).is_some());

        let payload = revocation_proof_payload(&did).unwrap();
        let proof = RevocationProof {
            did: did.clone(),
            signature: sign(&payload, &sk),
        };
        reg.revoke(&did, &proof).unwrap();

        assert!(reg.resolve(&did).is_none());
    }

    #[test]
    fn test_rotate_key_replaces_public_key() {
        // We'll test rotate_key which replaces the active public key.
        let (pk, sk) = generate_keypair();
        let did = make_did("charlie");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _) = generate_keypair();
        let proof = rotation_signature(&did, &new_pk, Timestamp::new(1001, 0), &sk);

        reg.rotate_key(&did, &new_pk, &proof, Timestamp::new(1001, 0))
            .unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.public_keys, vec![new_pk]);
        assert_eq!(resolved.updated, Timestamp::new(1001, 0));
    }

    #[test]
    fn rotate_key_replaces_active_public_key_and_rejects_rotated_key_for_next_rotation() {
        let (pk, sk) = generate_keypair();
        let did = make_did("rotated-key-pruned");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, new_sk) = generate_keypair();
        let proof = rotation_signature(&did, &new_pk, Timestamp::new(1001, 0), &sk);
        reg.rotate_key(&did, &new_pk, &proof, Timestamp::new(1001, 0))
            .unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(
            resolved.public_keys,
            vec![new_pk],
            "rotation must leave only the new active public key"
        );

        let (third_pk, _) = generate_keypair();
        let rotated_out_proof = rotation_signature(&did, &third_pk, Timestamp::new(1002, 0), &sk);
        let err = reg
            .rotate_key(&did, &third_pk, &rotated_out_proof, Timestamp::new(1002, 0))
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidSignature));

        let active_proof = rotation_signature(&did, &third_pk, Timestamp::new(1002, 0), &new_sk);
        reg.rotate_key(&did, &third_pk, &active_proof, Timestamp::new(1002, 0))
            .unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.public_keys, vec![third_pk]);
        assert_eq!(resolved.updated, Timestamp::new(1002, 0));
    }

    #[test]
    fn rotate_key_requires_domain_separated_payload_not_raw_new_key() {
        let (pk, sk) = generate_keypair();
        let did = make_did("domain-rotate");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _) = generate_keypair();
        let raw_proof = sign(new_pk.as_bytes(), &sk);
        let updated = Timestamp::new(1001, 0);

        let err = reg
            .rotate_key(&did, &new_pk, &raw_proof, updated)
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidSignature));
        assert_eq!(reg.resolve(&did).unwrap().public_keys, vec![pk]);

        let proof = rotation_signature(&did, &new_pk, updated, &sk);
        reg.rotate_key(&did, &new_pk, &proof, updated).unwrap();

        assert_eq!(reg.resolve(&did).unwrap().public_keys, vec![new_pk]);
    }

    #[test]
    fn rotate_key_rejects_replayed_payload_for_different_timestamp() {
        let (pk, sk) = generate_keypair();
        let did = make_did("timestamp-bound-rotate");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _) = generate_keypair();
        let signed_updated = Timestamp::new(1001, 0);
        let replayed_updated = Timestamp::new(1002, 0);
        let proof = rotation_signature(&did, &new_pk, signed_updated, &sk);

        let err = reg
            .rotate_key(&did, &new_pk, &proof, replayed_updated)
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidSignature));
        assert_eq!(reg.resolve(&did).unwrap().public_keys, vec![pk]);
    }

    #[test]
    fn rotate_key_rejects_non_advancing_updated_timestamp() {
        let (pk, sk) = generate_keypair();
        let did = make_did("dora");
        let doc = make_doc(did.clone(), pk);

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let (new_pk, _) = generate_keypair();
        let proof = rotation_signature(&did, &new_pk, Timestamp::new(1000, 0), &sk);
        let err = reg
            .rotate_key(&did, &new_pk, &proof, Timestamp::new(1000, 0))
            .unwrap_err();

        assert!(matches!(err, IdentityError::NonMonotonicTimestamp { .. }));
        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.public_keys, vec![pk]);
        assert_eq!(resolved.updated, Timestamp::new(1000, 0));
    }

    #[test]
    fn rotate_key_does_not_fabricate_timestamp_from_existing_document() {
        let source = std::fs::read_to_string("src/registry.rs").expect("read registry source");
        let forbidden = ["physical_ms", " + ", "1"].concat();
        assert!(
            !source.contains(&forbidden),
            "DID key rotation must use a caller-supplied HLC timestamp"
        );
    }

    #[test]
    fn test_resolve_nonexistent() {
        let reg = LocalDidRegistry::new();
        let did = make_did("nobody");

        assert!(reg.resolve(&did).is_none());
    }
}
