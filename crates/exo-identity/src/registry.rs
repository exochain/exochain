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

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, PublicKey, Signature, Timestamp, crypto};
use serde::Serialize;

use crate::{
    did::{DidDocument, DidRegistrationProof, RevocationProof, did_from_public_key},
    did_verification::validate_verification_method_document_binding,
    error::IdentityError,
};

const DID_REGISTRATION_PROOF_DOMAIN: &str = "exo.identity.did_registry.registration.v1";
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
const DID_DOCUMENT_ED25519_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

#[derive(Serialize)]
struct RegistrationProofPayload<'a> {
    domain: &'static str,
    document: &'a DidDocument,
    signing_public_key: &'a [u8; 32],
}

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

/// Build the canonical signable payload for first-time DID registration proofs.
///
/// The payload binds the signature to a full DID document and to one declared
/// Ed25519 key so a key-control proof cannot be replayed across documents,
/// routes, or later key-management operations.
pub fn did_registration_proof_payload(
    doc: &DidDocument,
    public_key: &PublicKey,
) -> Result<Vec<u8>, IdentityError> {
    let payload = RegistrationProofPayload {
        domain: DID_REGISTRATION_PROOF_DOMAIN,
        document: doc,
        signing_public_key: public_key.as_bytes(),
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        IdentityError::RegistrationProofPayloadEncoding {
            did: doc.id.clone(),
            reason: e.to_string(),
        }
    })?;
    Ok(encoded)
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

/// Verify proof-of-possession for first-time DID document registration.
///
/// The signer must be one of the public keys declared by the document. The
/// signature covers the full document and the signing key under a dedicated
/// domain separator, preventing first-writer claims that do not prove control of
/// document key material.
pub fn verify_did_registration_proof(
    doc: &DidDocument,
    proof: &DidRegistrationProof,
) -> Result<(), IdentityError> {
    validate_registered_did_document(doc)?;

    let derived_did = did_from_public_key(&proof.public_key).map_err(|e| {
        IdentityError::InvalidRegistrationProof {
            did: doc.id.clone(),
            reason: format!("proof public key cannot derive a canonical EXOCHAIN DID: {e}"),
        }
    })?;
    if derived_did != doc.id {
        return Err(IdentityError::InvalidRegistrationProof {
            did: doc.id.clone(),
            reason: format!(
                "DID subject must equal canonical DID derived from proof public key: expected {}",
                derived_did
            ),
        });
    }

    if !doc.public_keys.iter().any(|key| key == &proof.public_key) {
        return Err(IdentityError::InvalidRegistrationProof {
            did: doc.id.clone(),
            reason: "proof public key is not declared in the DID document".to_owned(),
        });
    }

    let msg = did_registration_proof_payload(doc, &proof.public_key)?;
    if crypto::verify(&msg, &proof.signature, &proof.public_key) {
        Ok(())
    } else {
        Err(IdentityError::InvalidRegistrationProof {
            did: doc.id.clone(),
            reason: "signature does not verify for the declared DID document key".to_owned(),
        })
    }
}

/// A decentralized identifier registry trait.
pub trait DidRegistry {
    /// Register a new DID document.
    fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError>;

    /// Register a new DID document after proof-of-possession verification.
    fn register_with_proof(
        &mut self,
        doc: DidDocument,
        proof: &DidRegistrationProof,
    ) -> Result<(), IdentityError> {
        verify_did_registration_proof(&doc, proof)?;
        self.register(doc)
    }

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

fn invalid_did_document_field(did: &str, field: &str, reason: impl Into<String>) -> IdentityError {
    IdentityError::InvalidDidDocumentField {
        did: did.to_owned(),
        field: field.to_owned(),
        reason: reason.into(),
    }
}

fn ensure_verification_method_key_material(
    did: &str,
    field: &str,
    method_id: &str,
    public_key_multibase: &str,
) -> Result<(), IdentityError> {
    let encoded = public_key_multibase.strip_prefix('z').ok_or_else(|| {
        invalid_did_document_field(
            did,
            field,
            format!(
                "verification method '{method_id}' uses unsupported multibase prefix; expected z base58btc"
            ),
        )
    })?;
    let key = bs58::decode(encoded).into_vec().map_err(|e| {
        invalid_did_document_field(
            did,
            field,
            format!("verification method '{method_id}' public key is not valid base58btc: {e}"),
        )
    })?;
    if key.len() != 32 {
        return Err(invalid_did_document_field(
            did,
            field,
            format!(
                "verification method '{method_id}' public key must be 32 bytes, got {}",
                key.len()
            ),
        ));
    }
    Ok(())
}

fn ensure_verification_method_lifecycle(
    did: &str,
    field: &str,
    method_id: &str,
    active: bool,
    revoked_at: Option<u64>,
) -> Result<(), IdentityError> {
    match (active, revoked_at) {
        (true, Some(_)) => Err(invalid_did_document_field(
            did,
            field,
            format!("active verification method '{method_id}' must not set revoked_at"),
        )),
        (false, None) => Err(invalid_did_document_field(
            did,
            field,
            format!("inactive verification method '{method_id}' must set revoked_at"),
        )),
        _ => Ok(()),
    }
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
    let mut verification_method_ids = BTreeSet::new();
    let verification_method_id_prefix = format!("{did}#");
    for method in &doc.verification_methods {
        if !verification_method_ids.insert(method.id.as_str()) {
            return Err(invalid_did_document_field(
                did,
                "verification_methods.id",
                format!("duplicate verification method id '{}'", method.id),
            ));
        }
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
        if !method.id.starts_with(&verification_method_id_prefix)
            || method.id.len() <= verification_method_id_prefix.len()
        {
            return Err(invalid_did_document_field(
                did,
                "verification_methods.id",
                format!(
                    "verification method id '{}' must be scoped to DID subject '{}'",
                    method.id, did
                ),
            ));
        }
        if method.controller != doc.id {
            return Err(invalid_did_document_field(
                did,
                "verification_methods.controller",
                format!(
                    "verification method '{}' controller '{}' must equal DID subject '{}'",
                    method.id, method.controller, did
                ),
            ));
        }
        if method.key_type != DID_DOCUMENT_ED25519_VERIFICATION_KEY_TYPE {
            return Err(invalid_did_document_field(
                did,
                "verification_methods.key_type",
                format!(
                    "verification method '{}' key_type '{}' is unsupported; expected '{}'",
                    method.id, method.key_type, DID_DOCUMENT_ED25519_VERIFICATION_KEY_TYPE
                ),
            ));
        }
        ensure_verification_method_key_material(
            did,
            "verification_methods.public_key_multibase",
            &method.id,
            &method.public_key_multibase,
        )?;
        ensure_verification_method_lifecycle(
            did,
            "verification_methods.revoked_at",
            &method.id,
            method.active,
            method.revoked_at,
        )?;
        if method.active {
            validate_verification_method_document_binding(doc, method).map_err(|e| {
                IdentityError::InvalidDidDocumentField {
                    did: did.to_owned(),
                    field: "verification_methods".to_owned(),
                    reason: e.to_string(),
                }
            })?;
        }
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
        if !method.key_material_matches_multibase() {
            return Err(invalid_did_document_field(
                did,
                "hybrid_verification_methods",
                format!(
                    "hybrid verification method '{}' raw key material must match multibase encodings",
                    method.id
                ),
            ));
        }
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
        PqPublicKey, SecretKey,
        crypto::{generate_keypair, generate_pq_keypair, sign},
    };

    use super::*;
    use crate::did::{DidDocument, HybridVerificationMethod, VerificationMethod};

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

    fn verification_method(did: &Did, pk: PublicKey, version: u64) -> VerificationMethod {
        VerificationMethod {
            id: format!("{did}#key-{version}"),
            key_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.clone(),
            public_key_multibase: format!("z{}", bs58::encode(pk.as_bytes()).into_string()),
            version,
            active: true,
            valid_from: 1000,
            revoked_at: None,
        }
    }

    fn hybrid_verification_method(
        did: &Did,
        classical_pk: PublicKey,
        pq_pk: PqPublicKey,
        version: u64,
    ) -> HybridVerificationMethod {
        HybridVerificationMethod {
            id: format!("{did}#hybrid-key-{version}"),
            key_type: "HybridKeyEd25519MlDsa652020".to_owned(),
            controller: did.clone(),
            classical_public_key_multibase: format!(
                "z{}",
                bs58::encode(classical_pk.as_bytes()).into_string()
            ),
            pq_public_key_multibase: format!("z{}", bs58::encode(pq_pk.as_bytes()).into_string()),
            pq_public_key: pq_pk,
            classical_public_key: classical_pk,
            version,
            active: true,
            valid_from: 1000,
            revoked_at: None,
        }
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

    fn registration_proof(
        doc: &DidDocument,
        public_key: PublicKey,
        secret_key: &SecretKey,
    ) -> DidRegistrationProof {
        let payload = did_registration_proof_payload(doc, &public_key).unwrap();
        DidRegistrationProof {
            public_key,
            signature: sign(&payload, secret_key),
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
    fn register_accepts_bound_active_verification_method() {
        let (pk, _) = generate_keypair();
        let did = make_did("bound-verification-method");
        let mut doc = make_doc(did.clone(), pk);
        doc.verification_methods = vec![verification_method(&did, pk, 1)];

        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.verification_methods.len(), 1);
        assert_eq!(resolved.verification_methods[0].controller, did);
    }

    #[test]
    fn register_rejects_active_verification_method_with_mismatched_controller() {
        let (pk, _) = generate_keypair();
        let did = make_did("method-controller");
        let mut doc = make_doc(did.clone(), pk);
        let mut method = verification_method(&did, pk, 1);
        method.controller = make_did("different-controller");
        doc.verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("active verification methods must be controlled by the DID subject");

        assert!(
            err.to_string().contains("controller"),
            "error should identify the controller binding: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_active_verification_method_with_non_subject_method_id() {
        let (pk, _) = generate_keypair();
        let did = make_did("method-id");
        let mut doc = make_doc(did.clone(), pk);
        let mut method = verification_method(&did, pk, 1);
        method.id = format!("{}#key-1", make_did("different-subject"));
        doc.verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("verification method IDs must be DID-subject scoped");

        assert!(
            err.to_string().contains("id"),
            "error should identify the method id binding: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_duplicate_verification_method_ids() {
        let (pk, _) = generate_keypair();
        let did = make_did("duplicate-method-id");
        let mut doc = make_doc(did.clone(), pk);
        let mut first = verification_method(&did, pk, 1);
        let mut second = verification_method(&did, pk, 2);
        second.id.clone_from(&first.id);
        first.active = false;
        first.revoked_at = Some(1001);
        doc.verification_methods = vec![first, second];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("duplicate verification method IDs must be rejected");

        assert!(
            err.to_string().contains("duplicate"),
            "error should identify duplicate method ids: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_unsupported_verification_method_key_type() {
        let (pk, _) = generate_keypair();
        let did = make_did("unsupported-method-type");
        let mut doc = make_doc(did.clone(), pk);
        let mut method = verification_method(&did, pk, 1);
        method.key_type = "JsonWebKey2020".to_owned();
        doc.verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("unsupported verification method key types must be rejected");

        assert!(
            err.to_string().contains("key_type"),
            "error should identify the unsupported key type: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_active_verification_method_with_wrong_length_public_key() {
        let (pk, _) = generate_keypair();
        let did = make_did("wrong-method-key-length");
        let mut doc = make_doc(did.clone(), pk);
        let mut method = verification_method(&did, pk, 1);
        method.public_key_multibase = format!("z{}", bs58::encode([1_u8, 2, 3]).into_string());
        doc.verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("active verification method keys must decode to Ed25519 length");

        assert!(
            err.to_string().contains("32 bytes"),
            "error should identify the key length: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_active_verification_method_with_revoked_at() {
        let (pk, _) = generate_keypair();
        let did = make_did("active-with-revoked-at");
        let mut doc = make_doc(did.clone(), pk);
        let mut method = verification_method(&did, pk, 1);
        method.revoked_at = Some(1001);
        doc.verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("active verification methods must not carry revocation timestamps");

        assert!(
            err.to_string().contains("revoked_at"),
            "error should identify active revoked_at inconsistency: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_inactive_verification_method_without_revoked_at() {
        let (pk, _) = generate_keypair();
        let did = make_did("inactive-without-revoked-at");
        let mut doc = make_doc(did.clone(), pk);
        let mut method = verification_method(&did, pk, 1);
        method.active = false;
        doc.verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("inactive verification methods must carry revocation timestamps");

        assert!(
            err.to_string().contains("revoked_at"),
            "error should identify inactive revoked_at inconsistency: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_rejects_hybrid_method_with_mismatched_multibase_key_material() {
        let (document_pk, _) = generate_keypair();
        let (classical_pk, _) = generate_keypair();
        let (declared_classical_pk, _) = generate_keypair();
        let (pq_pk, _) = generate_pq_keypair();
        let (declared_pq_pk, _) = generate_pq_keypair();
        let did = make_did("hybrid-mismatched-key-material");
        let mut doc = make_doc(did.clone(), document_pk);
        let mut method = hybrid_verification_method(&did, classical_pk, pq_pk, 1);
        method.classical_public_key_multibase = format!(
            "z{}",
            bs58::encode(declared_classical_pk.as_bytes()).into_string()
        );
        method.pq_public_key_multibase =
            format!("z{}", bs58::encode(declared_pq_pk.as_bytes()).into_string());
        doc.hybrid_verification_methods = vec![method];

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register(doc)
            .expect_err("hybrid methods must bind raw keys to advertised multibase keys");

        assert!(
            err.to_string().contains("hybrid_verification_methods"),
            "error should identify hybrid method key binding failure: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_with_proof_accepts_document_signed_by_declared_key() {
        let (pk, sk) = generate_keypair();
        let did = did_from_public_key(&pk).expect("canonical DID");
        let doc = make_doc(did.clone(), pk);
        let proof = registration_proof(&doc, pk, &sk);

        let mut reg = LocalDidRegistry::new();
        reg.register_with_proof(doc, &proof).unwrap();

        let resolved = reg.resolve(&did).unwrap();
        assert_eq!(resolved.id, did);
        assert_eq!(resolved.public_keys, vec![pk]);
    }

    #[test]
    fn register_with_proof_rejects_non_self_certifying_did() {
        let (attacker_pk, attacker_sk) = generate_keypair();
        let victim_did = make_did("unclaimed-victim");
        let doc = make_doc(victim_did, attacker_pk);
        let proof = registration_proof(&doc, attacker_pk, &attacker_sk);

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register_with_proof(doc, &proof)
            .expect_err("registration proof must bind the DID subject to the proof key");

        assert!(matches!(
            err,
            IdentityError::InvalidRegistrationProof { .. }
        ));
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_with_proof_rejects_key_not_declared_by_document() {
        let (document_pk, _) = generate_keypair();
        let (attacker_pk, attacker_sk) = generate_keypair();
        let doc = make_doc_with_label("proof-unlisted-key", document_pk);
        let proof = registration_proof(&doc, attacker_pk, &attacker_sk);

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register_with_proof(doc, &proof)
            .expect_err("registration proof must be bound to a document key");

        assert!(matches!(
            err,
            IdentityError::InvalidRegistrationProof { .. }
        ));
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_with_proof_rejects_active_method_not_bound_to_declared_key() {
        let (document_pk, document_sk) = generate_keypair();
        let (method_pk, _) = generate_keypair();
        let did = did_from_public_key(&document_pk).expect("canonical DID");
        let mut doc = make_doc(did, document_pk);
        doc.verification_methods
            .push(verification_method(&doc.id, method_pk, 1));
        let proof = registration_proof(&doc, document_pk, &document_sk);

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register_with_proof(doc, &proof)
            .expect_err("active verification methods must be bound to declared document keys");

        assert!(
            err.to_string().contains("verification_methods"),
            "error should identify verification method binding failure: {err}"
        );
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn register_with_proof_rejects_raw_did_signature_replay() {
        let (pk, sk) = generate_keypair();
        let doc = make_doc_with_label("proof-domain-separated", pk);
        let proof = DidRegistrationProof {
            public_key: pk,
            signature: sign(doc.id.as_str().as_bytes(), &sk),
        };

        let mut reg = LocalDidRegistry::new();
        let err = reg
            .register_with_proof(doc, &proof)
            .expect_err("registration must require the domain-separated document payload");

        assert!(matches!(
            err,
            IdentityError::InvalidRegistrationProof { .. }
        ));
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
