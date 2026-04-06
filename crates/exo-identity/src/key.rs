//! Key management types and DID-based signature operations.
//!
//! Defines [`KeyError`], the [`KeyVault`] trait for secure key storage, and
//! helpers for DID signature verification and key rotation.

use crate::did::{Did, DidDocument, VerificationMethod};
use ed25519_dalek::{Signature, VerifyingKey};
use exo_core::{verify_signature, Blake3Hash};
use thiserror::Error;

/// Errors arising from key operations such as lookup, revocation checks, and signature verification.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Key revoked: {0}")]
    Revoked(String),
    #[error("Key expired: {0}")]
    Expired(String),
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Crypto Error")]
    CryptoError,
}

/// Abstract Key Vault Interface for storing and retrieving keys securely.
/// In production, this would interface with a TEE or HSM.
pub trait KeyVault {
    /// Retrieve a verifying key for the given DID at a specific version.
    fn get_key(&self, did: &Did, version: u64) -> Result<VerifyingKey, KeyError>;
    /// Store a verifying key for the given DID at a specific version.
    fn store_key(&mut self, did: &Did, key: VerifyingKey, version: u64) -> Result<(), KeyError>;
}

/// Verifies a signature against a DID Document's verification methods.
pub fn verify_did_signature(
    doc: &DidDocument,
    key_id: &str, // e.g. "did:exo:123#key-1"
    message_hash: &Blake3Hash,
    signature: &Signature,
) -> Result<(), KeyError> {
    let method = doc
        .verification_methods
        .iter()
        .find(|m| m.id == key_id)
        .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;

    if !method.active {
        return Err(KeyError::Revoked(key_id.to_string()));
    }

    // In a real implementation, we would check valid_from/revoked_at against current block time.
    // Here we assume strict check against 'active' flag which should be maintained by state.

    // Decode public key from multibase (assuming base58 for now as per spec default)
    // Multibase prefix 'z' for base58btc.
    let pub_key_bytes = if method.public_key_multibase.starts_with('z') {
        bs58::decode(&method.public_key_multibase[1..])
            .into_vec()
            .map_err(|_| KeyError::CryptoError)?
    } else {
        return Err(KeyError::CryptoError); // Unsupported format
    };

    let pub_key_array: [u8; 32] = pub_key_bytes
        .try_into()
        .map_err(|_| KeyError::CryptoError)?;

    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_array).map_err(|_| KeyError::CryptoError)?;

    verify_signature(&verifying_key, message_hash, signature)
        .map_err(|_| KeyError::InvalidSignature)
}

/// Rotates a key in the DID Document.
/// Returns the new verification method to be appended.
pub fn rotate_key(
    doc: &mut DidDocument,
    old_key_id: &str,
    new_public_key: &[u8; 32],
    controller: &Did,
    current_time: u64,
) -> Result<VerificationMethod, KeyError> {
    // 1. Find/Validate old key
    let old_method_idx = doc
        .verification_methods
        .iter()
        .position(|m| m.id == old_key_id)
        .ok_or_else(|| KeyError::NotFound(old_key_id.to_string()))?;

    // 2. Revoke old key (or set inactive)
    let old_method = &mut doc.verification_methods[old_method_idx];
    old_method.active = false;
    old_method.revoked_at = Some(current_time);

    // 3. Create new method
    let new_version = old_method.version + 1;
    let new_id = format!("{}#key-{}", doc.id, new_version);
    let multibase = format!("z{}", bs58::encode(new_public_key).into_string());

    let new_method = VerificationMethod {
        id: new_id.clone(),
        key_type: "Ed25519VerificationKey2020".to_string(),
        controller: controller.clone(),
        public_key_multibase: multibase,
        version: new_version,
        active: true,
        valid_from: current_time,
        revoked_at: None,
    };

    doc.updated = current_time;
    doc.verification_methods.push(new_method.clone());

    Ok(new_method)
}
