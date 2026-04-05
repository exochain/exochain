//! DID-based signature verification and key rotation.
//!
//! Bridges the gap between key management (`key_management`) and DID documents
//! (`did`) by providing:
//! - [`KeyVault`] trait for abstracting TEE/HSM key storage
//! - [`verify_did_signature`] for verifying signatures against DID document
//!   verification methods with multibase key decoding
//! - [`rotate_verification_key`] for proper lifecycle management of verification
//!   methods (deactivate old, add new with version increment)

use exo_core::{Did, PublicKey, crypto};

use crate::did::{DidDocument, VerificationMethod};

/// Errors specific to DID verification operations.
#[derive(Debug, thiserror::Error)]
pub enum DidVerificationError {
    /// Verification method not found by key ID.
    #[error("verification method not found: {0}")]
    MethodNotFound(String),

    /// Key has been revoked or deactivated.
    #[error("verification method revoked: {0}")]
    MethodRevoked(String),

    /// Cryptographic operation failed (e.g., invalid multibase encoding,
    /// wrong key length, unsupported multibase prefix).
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,
}

/// Abstract key vault interface for secure key storage.
///
/// In production, implementations would interface with a TEE (Trusted
/// Execution Environment) or HSM (Hardware Security Module). For testing,
/// an in-memory implementation suffices.
pub trait KeyVault {
    /// Retrieve a public key for a DID at a specific version.
    fn get_public_key(&self, did: &Did, version: u64) -> Result<PublicKey, DidVerificationError>;

    /// Store a public key for a DID at a specific version.
    fn store_public_key(
        &mut self,
        did: &Did,
        key: PublicKey,
        version: u64,
    ) -> Result<(), DidVerificationError>;
}

/// Verify a signature against a DID document's verification methods.
///
/// Resolves the verification method by `key_id` (e.g., `"did:exo:123#key-1"`),
/// checks that the key is active, decodes the multibase base58btc public key,
/// and verifies the signature over the provided message.
///
/// # Errors
///
/// Returns [`DidVerificationError::MethodNotFound`] if the key ID doesn't
/// match any verification method.
/// Returns [`DidVerificationError::MethodRevoked`] if the key is inactive.
/// Returns [`DidVerificationError::InvalidSignature`] if verification fails.
pub fn verify_did_signature(
    doc: &DidDocument,
    key_id: &str,
    message: &[u8],
    signature: &exo_core::Signature,
) -> Result<(), DidVerificationError> {
    let method = doc
        .verification_methods
        .iter()
        .find(|m| m.id == key_id)
        .ok_or_else(|| DidVerificationError::MethodNotFound(key_id.to_string()))?;

    if !method.active {
        return Err(DidVerificationError::MethodRevoked(key_id.to_string()));
    }

    // Decode multibase base58btc public key (prefix 'z')
    let pub_key_bytes = if method.public_key_multibase.starts_with('z') {
        bs58::decode(&method.public_key_multibase[1..])
            .into_vec()
            .map_err(|e| DidVerificationError::CryptoError(format!("base58 decode: {e}")))?
    } else {
        return Err(DidVerificationError::CryptoError(
            "unsupported multibase prefix (expected 'z' for base58btc)".to_string(),
        ));
    };

    let pub_key_array: [u8; 32] = pub_key_bytes.try_into().map_err(|_| {
        DidVerificationError::CryptoError("public key must be 32 bytes".to_string())
    })?;

    let public_key = PublicKey::from_bytes(pub_key_array);

    if crypto::verify(message, signature, &public_key) {
        Ok(())
    } else {
        Err(DidVerificationError::InvalidSignature)
    }
}

/// Rotate a verification key in a DID document.
///
/// Deactivates the old verification method identified by `old_key_id`,
/// creates a new verification method with an incremented version, and
/// appends it to the document's verification methods.
///
/// # Arguments
///
/// * `doc` — The DID document to mutate.
/// * `old_key_id` — ID of the verification method to deactivate.
/// * `new_public_key` — Raw 32-byte Ed25519 public key for the new method.
/// * `controller` — DID that controls the new key.
/// * `current_time_ms` — Current wall-clock time in milliseconds (for lifecycle tracking).
///
/// # Returns
///
/// The newly created [`VerificationMethod`].
pub fn rotate_verification_key(
    doc: &mut DidDocument,
    old_key_id: &str,
    new_public_key: &[u8; 32],
    controller: &Did,
    current_time_ms: u64,
) -> Result<VerificationMethod, DidVerificationError> {
    // Find the old method
    let old_method_idx = doc
        .verification_methods
        .iter()
        .position(|m| m.id == old_key_id)
        .ok_or_else(|| DidVerificationError::MethodNotFound(old_key_id.to_string()))?;

    // Deactivate old key
    let old_version = doc.verification_methods[old_method_idx].version;
    doc.verification_methods[old_method_idx].active = false;
    doc.verification_methods[old_method_idx].revoked_at = Some(current_time_ms);

    // Create new method with incremented version
    let new_version = old_version + 1;
    let new_id = format!("{}#key-{}", doc.id, new_version);
    let multibase = format!("z{}", bs58::encode(new_public_key).into_string());

    let new_method = VerificationMethod {
        id: new_id,
        key_type: "Ed25519VerificationKey2020".to_string(),
        controller: controller.clone(),
        public_key_multibase: multibase,
        version: new_version,
        active: true,
        valid_from: current_time_ms,
        revoked_at: None,
    };

    doc.verification_methods.push(new_method.clone());
    doc.updated = exo_core::Timestamp::new(current_time_ms, 0);

    Ok(new_method)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::{
        Timestamp,
        crypto::{generate_keypair, sign},
    };

    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-verification").expect("valid")
    }

    fn make_doc_with_verification(did: Did, pk: PublicKey) -> DidDocument {
        let multibase = format!("z{}", bs58::encode(pk.as_bytes()).into_string());
        DidDocument {
            id: did.clone(),
            public_keys: vec![pk],
            authentication: vec![],
            verification_methods: vec![VerificationMethod {
                id: format!("{}#key-1", did),
                key_type: "Ed25519VerificationKey2020".to_string(),
                controller: did,
                public_key_multibase: multibase,
                version: 1,
                active: true,
                valid_from: 1000,
                revoked_at: None,
            }],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::new(1000, 0),
            updated: Timestamp::new(1000, 0),
            revoked: false,
        }
    }

    #[test]
    fn verify_valid_signature() {
        let (pk, sk) = generate_keypair();
        let did = test_did();
        let doc = make_doc_with_verification(did.clone(), pk);

        let message = b"hello world";
        let signature = sign(message, &sk);

        let key_id = format!("{}#key-1", did);
        assert!(verify_did_signature(&doc, &key_id, message, &signature).is_ok());
    }

    #[test]
    fn verify_wrong_signature_fails() {
        let (pk, _sk) = generate_keypair();
        let (_pk2, sk2) = generate_keypair();
        let did = test_did();
        let doc = make_doc_with_verification(did.clone(), pk);

        let message = b"hello world";
        let wrong_sig = sign(message, &sk2);

        let key_id = format!("{}#key-1", did);
        let err = verify_did_signature(&doc, &key_id, message, &wrong_sig).unwrap_err();
        assert!(matches!(err, DidVerificationError::InvalidSignature));
    }

    #[test]
    fn verify_unknown_key_id_fails() {
        let (pk, sk) = generate_keypair();
        let did = test_did();
        let doc = make_doc_with_verification(did, pk);

        let message = b"test";
        let signature = sign(message, &sk);

        let err =
            verify_did_signature(&doc, "nonexistent#key-99", message, &signature).unwrap_err();
        assert!(matches!(err, DidVerificationError::MethodNotFound(_)));
    }

    #[test]
    fn verify_revoked_key_fails() {
        let (pk, sk) = generate_keypair();
        let did = test_did();
        let mut doc = make_doc_with_verification(did.clone(), pk);

        // Revoke the key
        doc.verification_methods[0].active = false;

        let message = b"test";
        let signature = sign(message, &sk);

        let key_id = format!("{}#key-1", did);
        let err = verify_did_signature(&doc, &key_id, message, &signature).unwrap_err();
        assert!(matches!(err, DidVerificationError::MethodRevoked(_)));
    }

    #[test]
    fn verify_bad_multibase_prefix_fails() {
        let (pk, sk) = generate_keypair();
        let did = test_did();
        let mut doc = make_doc_with_verification(did.clone(), pk);

        // Set unsupported multibase prefix
        doc.verification_methods[0].public_key_multibase =
            format!("m{}", bs58::encode(pk.as_bytes()).into_string());

        let message = b"test";
        let signature = sign(message, &sk);

        let key_id = format!("{}#key-1", did);
        let err = verify_did_signature(&doc, &key_id, message, &signature).unwrap_err();
        assert!(matches!(err, DidVerificationError::CryptoError(_)));
    }

    #[test]
    fn rotate_key_success() {
        let (pk, _sk) = generate_keypair();
        let did = test_did();
        let mut doc = make_doc_with_verification(did.clone(), pk);

        let (new_pk, _new_sk) = generate_keypair();
        let new_method = rotate_verification_key(
            &mut doc,
            &format!("{}#key-1", did),
            new_pk.as_bytes(),
            &did,
            2000,
        )
        .expect("rotation should succeed");

        // Old key deactivated
        assert!(!doc.verification_methods[0].active);
        assert_eq!(doc.verification_methods[0].revoked_at, Some(2000));

        // New key active
        assert_eq!(new_method.version, 2);
        assert!(new_method.active);
        assert_eq!(doc.verification_methods.len(), 2);
        assert_eq!(doc.updated.physical_ms, 2000);
    }

    #[test]
    fn rotate_unknown_key_fails() {
        let (pk, _sk) = generate_keypair();
        let did = test_did();
        let mut doc = make_doc_with_verification(did.clone(), pk);

        let (new_pk, _) = generate_keypair();
        let err = rotate_verification_key(
            &mut doc,
            "nonexistent#key-99",
            new_pk.as_bytes(),
            &did,
            2000,
        )
        .unwrap_err();
        assert!(matches!(err, DidVerificationError::MethodNotFound(_)));
    }

    #[test]
    fn verify_after_rotation() {
        let (pk, _sk) = generate_keypair();
        let did = test_did();
        let mut doc = make_doc_with_verification(did.clone(), pk);

        let (new_pk, new_sk) = generate_keypair();
        let new_method = rotate_verification_key(
            &mut doc,
            &format!("{}#key-1", did),
            new_pk.as_bytes(),
            &did,
            2000,
        )
        .expect("rotation");

        // Verify with new key works
        let message = b"post-rotation message";
        let signature = sign(message, &new_sk);
        assert!(verify_did_signature(&doc, &new_method.id, message, &signature).is_ok());

        // Verify with old key fails (revoked)
        let old_key_id = format!("{}#key-1", did);
        let err = verify_did_signature(&doc, &old_key_id, message, &signature).unwrap_err();
        assert!(matches!(err, DidVerificationError::MethodRevoked(_)));
    }
}
