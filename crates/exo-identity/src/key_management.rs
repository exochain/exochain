//! Key lifecycle management for EXOCHAIN identities.
//!
//! Supports two key flavours:
//! - **Ed25519** — classical signing keys (see [`KeyStore`])
//! - **Hybrid** — Ed25519 + ML-DSA-65 keypairs for post-quantum hardened
//!   identities (see [`HybridKeyStore`])

use std::collections::BTreeMap;

use exo_core::{
    Did, PqPublicKey, PqSecretKey, PublicKey, SecretKey, Timestamp,
    crypto::{generate_keypair, generate_pq_keypair},
};
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;

/// Lifecycle status of a key record in the key store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    Rotated,
    Revoked,
    Expired,
}

/// A versioned key record tracking an Ed25519 public key and its lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub public_key: PublicKey,
    pub status: KeyStatus,
    pub created: Timestamp,
    pub rotated_to: Option<PublicKey>,
    pub revocation_reason: Option<String>,
}

/// In-memory key store mapping DIDs to ordered lists of Ed25519 key records.
#[derive(Debug, Default)]
pub struct KeyStore {
    records: BTreeMap<String, Vec<KeyRecord>>,
    clock: u64,
}

impl KeyStore {
    /// Create an empty key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate and store a new Ed25519 key pair for the given DID.
    pub fn create_key(&mut self, did: &Did) -> Result<(PublicKey, SecretKey), IdentityError> {
        let (pk, sk) = generate_keypair();
        self.clock += 1;

        let record = KeyRecord {
            public_key: pk,
            status: KeyStatus::Active,
            created: Timestamp::new(self.clock, 0),
            rotated_to: None,
            revocation_reason: None,
        };

        self.records
            .entry(did.as_str().to_owned())
            .or_default()
            .push(record);

        Ok((pk, sk))
    }

    /// Rotate a key by marking the old key as rotated and generating a new active key.
    pub fn rotate_key(
        &mut self,
        did: &Did,
        old: &PublicKey,
    ) -> Result<(PublicKey, SecretKey), IdentityError> {
        let records = self
            .records
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        let old_record = records
            .iter_mut()
            .find(|r| r.public_key == *old)
            .ok_or_else(|| IdentityError::KeyNotFound(did.clone()))?;

        match old_record.status {
            KeyStatus::Active => {}
            KeyStatus::Rotated => return Err(IdentityError::KeyAlreadyRotated),
            KeyStatus::Revoked | KeyStatus::Expired => {
                return Err(IdentityError::KeyAlreadyRevoked);
            }
        }

        let (new_pk, new_sk) = generate_keypair();
        self.clock += 1;

        old_record.status = KeyStatus::Rotated;
        old_record.rotated_to = Some(new_pk);

        let new_record = KeyRecord {
            public_key: new_pk,
            status: KeyStatus::Active,
            created: Timestamp::new(self.clock, 0),
            rotated_to: None,
            revocation_reason: None,
        };
        records.push(new_record);

        Ok((new_pk, new_sk))
    }

    /// Revoke a key, recording the reason for revocation.
    pub fn revoke_key(
        &mut self,
        did: &Did,
        key: &PublicKey,
        reason: &str,
    ) -> Result<(), IdentityError> {
        let records = self
            .records
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        let record = records
            .iter_mut()
            .find(|r| r.public_key == *key)
            .ok_or_else(|| IdentityError::KeyNotFound(did.clone()))?;

        if record.status == KeyStatus::Revoked {
            return Err(IdentityError::KeyAlreadyRevoked);
        }

        record.status = KeyStatus::Revoked;
        record.revocation_reason = Some(reason.to_owned());
        Ok(())
    }

    /// Return all key records for the given DID, or `None` if the DID is unknown.
    #[must_use]
    pub fn get_keys(&self, did: &Did) -> Option<&[KeyRecord]> {
        self.records.get(did.as_str()).map(Vec::as_slice)
    }

    /// Return the most recent active public key for the given DID, if any.
    #[must_use]
    pub fn active_key(&self, did: &Did) -> Option<&PublicKey> {
        self.records.get(did.as_str()).and_then(|records| {
            records
                .iter()
                .rev()
                .find(|r| r.status == KeyStatus::Active)
                .map(|r| &r.public_key)
        })
    }
}

// ---------------------------------------------------------------------------
// Hybrid key storage — Ed25519 + ML-DSA-65 keypairs
// ---------------------------------------------------------------------------

/// A hybrid key pair bundle: classical Ed25519 + post-quantum ML-DSA-65.
///
/// The two public keys are stored together so verifiers can construct a
/// `Signature::Hybrid` check in one step.  Secret keys are returned only
/// at creation/rotation time and must be zeroized by the caller when done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKeys {
    /// Ed25519 verifying key.
    pub classical: PublicKey,
    /// ML-DSA-65 verifying key (1952 bytes).
    pub post_quantum: PqPublicKey,
}

/// A secret key bundle returned at key creation/rotation time.
///
/// The caller **must** zeroize both fields after use.  Neither field is
/// stored in `HybridKeyStore`.
pub struct HybridSecretKeys {
    /// Ed25519 signing key (32-byte scalar).
    pub classical: SecretKey,
    /// ML-DSA-65 seed (32 bytes, `ξ` in FIPS 204 §5.1).
    pub post_quantum: PqSecretKey,
}

impl core::fmt::Debug for HybridSecretKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridSecretKeys")
            .field("classical", &"***")
            .field("post_quantum", &"***")
            .finish()
    }
}

/// Lifecycle status for a hybrid key record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridKeyStatus {
    Active,
    Rotated,
    Revoked,
}

/// A single versioned hybrid key record stored by `HybridKeyStore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKeyRecord {
    /// The public key bundle (classical + PQ).
    pub public_keys: HybridPublicKeys,
    /// Current lifecycle status.
    pub status: HybridKeyStatus,
    /// When this record was created (monotonic store clock).
    pub created: Timestamp,
    /// The classical public key this record was rotated to, if any.
    pub rotated_to: Option<PublicKey>,
    /// Human-readable reason for revocation, if revoked.
    pub revocation_reason: Option<String>,
}

/// Key store for hybrid Ed25519 + ML-DSA-65 identity keys.
///
/// Each DID maps to an ordered list of `HybridKeyRecord`s.  The most-recent
/// `Active` record is the current key.  Uses `BTreeMap` for deterministic
/// iteration order.
#[derive(Debug, Default)]
pub struct HybridKeyStore {
    records: BTreeMap<String, Vec<HybridKeyRecord>>,
    clock: u64,
}

impl HybridKeyStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate and store a fresh hybrid key pair for `did`.
    ///
    /// Returns the secret keys; the caller is responsible for zeroizing them.
    pub fn create_key(&mut self, did: &Did) -> Result<HybridSecretKeys, IdentityError> {
        let (classical_pk, classical_sk) = generate_keypair();
        let (pq_pk, pq_sk) = generate_pq_keypair();
        self.clock += 1;

        let record = HybridKeyRecord {
            public_keys: HybridPublicKeys {
                classical: classical_pk,
                post_quantum: pq_pk,
            },
            status: HybridKeyStatus::Active,
            created: Timestamp::new(self.clock, 0),
            rotated_to: None,
            revocation_reason: None,
        };

        self.records
            .entry(did.as_str().to_owned())
            .or_default()
            .push(record);

        Ok(HybridSecretKeys {
            classical: classical_sk,
            post_quantum: pq_sk,
        })
    }

    /// Rotate the hybrid key for `did`, identified by its classical component.
    ///
    /// The old record is marked `Rotated` and a new one is appended.
    /// Returns the new secret keys.
    pub fn rotate_key(
        &mut self,
        did: &Did,
        old_classical: &PublicKey,
    ) -> Result<HybridSecretKeys, IdentityError> {
        let records = self
            .records
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        let old_record = records
            .iter_mut()
            .find(|r| &r.public_keys.classical == old_classical)
            .ok_or_else(|| IdentityError::KeyNotFound(did.clone()))?;

        match old_record.status {
            HybridKeyStatus::Active => {}
            HybridKeyStatus::Rotated => return Err(IdentityError::KeyAlreadyRotated),
            HybridKeyStatus::Revoked => return Err(IdentityError::KeyAlreadyRevoked),
        }

        let (new_classical_pk, new_classical_sk) = generate_keypair();
        let (new_pq_pk, new_pq_sk) = generate_pq_keypair();
        self.clock += 1;

        old_record.status = HybridKeyStatus::Rotated;
        old_record.rotated_to = Some(new_classical_pk);

        let new_record = HybridKeyRecord {
            public_keys: HybridPublicKeys {
                classical: new_classical_pk,
                post_quantum: new_pq_pk,
            },
            status: HybridKeyStatus::Active,
            created: Timestamp::new(self.clock, 0),
            rotated_to: None,
            revocation_reason: None,
        };
        records.push(new_record);

        Ok(HybridSecretKeys {
            classical: new_classical_sk,
            post_quantum: new_pq_sk,
        })
    }

    /// Revoke the hybrid key identified by its classical component.
    pub fn revoke_key(
        &mut self,
        did: &Did,
        classical: &PublicKey,
        reason: &str,
    ) -> Result<(), IdentityError> {
        let records = self
            .records
            .get_mut(did.as_str())
            .ok_or_else(|| IdentityError::DidNotFound(did.clone()))?;

        let record = records
            .iter_mut()
            .find(|r| &r.public_keys.classical == classical)
            .ok_or_else(|| IdentityError::KeyNotFound(did.clone()))?;

        if record.status == HybridKeyStatus::Revoked {
            return Err(IdentityError::KeyAlreadyRevoked);
        }

        record.status = HybridKeyStatus::Revoked;
        record.revocation_reason = Some(reason.to_owned());
        Ok(())
    }

    /// Return all records for `did`, or `None` if unknown.
    #[must_use]
    pub fn get_keys(&self, did: &Did) -> Option<&[HybridKeyRecord]> {
        self.records.get(did.as_str()).map(Vec::as_slice)
    }

    /// Return the public key bundle for the most-recent active key.
    #[must_use]
    pub fn active_keys(&self, did: &Did) -> Option<&HybridPublicKeys> {
        self.records.get(did.as_str()).and_then(|records| {
            records
                .iter()
                .rev()
                .find(|r| r.status == HybridKeyStatus::Active)
                .map(|r| &r.public_keys)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("valid did")
    }

    #[test]
    fn create_key_stores_record() {
        let did = make_did("test1");
        let mut store = KeyStore::new();
        let (pk, _sk) = store.create_key(&did).unwrap();

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].status, KeyStatus::Active);
        assert_eq!(keys[0].public_key, pk);
    }

    #[test]
    fn active_key_returns_latest() {
        let did = make_did("test2");
        let mut store = KeyStore::new();
        let (pk1, _sk1) = store.create_key(&did).unwrap();
        assert_eq!(store.active_key(&did), Some(&pk1));
    }

    #[test]
    fn rotate_key_marks_old_and_creates_new() {
        let did = make_did("test3");
        let mut store = KeyStore::new();
        let (pk1, _sk1) = store.create_key(&did).unwrap();
        let (pk2, _sk2) = store.rotate_key(&did, &pk1).unwrap();

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].status, KeyStatus::Rotated);
        assert_eq!(keys[0].rotated_to.as_ref(), Some(&pk2));
        assert_eq!(keys[1].status, KeyStatus::Active);
        assert_eq!(keys[1].public_key, pk2);
        assert_eq!(store.active_key(&did), Some(&pk2));
    }

    #[test]
    fn rotate_unknown_did_fails() {
        let did = make_did("unknown");
        let (pk, _) = generate_keypair();
        let mut store = KeyStore::new();
        assert!(matches!(
            store.rotate_key(&did, &pk).unwrap_err(),
            IdentityError::DidNotFound(_)
        ));
    }

    #[test]
    fn rotate_unknown_key_fails() {
        let did = make_did("test4");
        let mut store = KeyStore::new();
        store.create_key(&did).unwrap();
        let (other_pk, _) = generate_keypair();
        assert!(matches!(
            store.rotate_key(&did, &other_pk).unwrap_err(),
            IdentityError::KeyNotFound(_)
        ));
    }

    #[test]
    fn rotate_already_rotated_fails() {
        let did = make_did("test5");
        let mut store = KeyStore::new();
        let (pk1, _) = store.create_key(&did).unwrap();
        store.rotate_key(&did, &pk1).unwrap();
        assert!(matches!(
            store.rotate_key(&did, &pk1).unwrap_err(),
            IdentityError::KeyAlreadyRotated
        ));
    }

    #[test]
    fn rotate_revoked_key_fails() {
        let did = make_did("test5b");
        let mut store = KeyStore::new();
        let (pk1, _) = store.create_key(&did).unwrap();
        store.revoke_key(&did, &pk1, "compromised").unwrap();
        assert!(matches!(
            store.rotate_key(&did, &pk1).unwrap_err(),
            IdentityError::KeyAlreadyRevoked
        ));
    }

    #[test]
    fn revoke_key_success() {
        let did = make_did("test6");
        let mut store = KeyStore::new();
        let (pk, _) = store.create_key(&did).unwrap();
        store.revoke_key(&did, &pk, "compromised").unwrap();

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys[0].status, KeyStatus::Revoked);
        assert_eq!(keys[0].revocation_reason.as_deref(), Some("compromised"));
        assert!(store.active_key(&did).is_none());
    }

    #[test]
    fn revoke_unknown_did_fails() {
        let did = make_did("unknown2");
        let (pk, _) = generate_keypair();
        let mut store = KeyStore::new();
        assert!(matches!(
            store.revoke_key(&did, &pk, "reason").unwrap_err(),
            IdentityError::DidNotFound(_)
        ));
    }

    #[test]
    fn revoke_unknown_key_fails() {
        let did = make_did("test7");
        let mut store = KeyStore::new();
        store.create_key(&did).unwrap();
        let (other_pk, _) = generate_keypair();
        assert!(matches!(
            store.revoke_key(&did, &other_pk, "reason").unwrap_err(),
            IdentityError::KeyNotFound(_)
        ));
    }

    #[test]
    fn revoke_already_revoked_fails() {
        let did = make_did("test8");
        let mut store = KeyStore::new();
        let (pk, _) = store.create_key(&did).unwrap();
        store.revoke_key(&did, &pk, "first").unwrap();
        assert!(matches!(
            store.revoke_key(&did, &pk, "second").unwrap_err(),
            IdentityError::KeyAlreadyRevoked
        ));
    }

    #[test]
    fn get_keys_unknown_did() {
        let store = KeyStore::new();
        let did = make_did("unknown3");
        assert!(store.get_keys(&did).is_none());
    }

    #[test]
    fn active_key_unknown_did() {
        let store = KeyStore::new();
        let did = make_did("unknown4");
        assert!(store.active_key(&did).is_none());
    }

    #[test]
    fn multiple_keys_per_did() {
        let did = make_did("multi");
        let mut store = KeyStore::new();
        let (pk1, _) = store.create_key(&did).unwrap();
        let (pk2, _) = store.create_key(&did).unwrap();

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].public_key, pk1);
        assert_eq!(keys[1].public_key, pk2);
    }

    #[test]
    fn clock_increments_deterministically() {
        let did = make_did("clock");
        let mut store = KeyStore::new();
        store.create_key(&did).unwrap();
        store.create_key(&did).unwrap();

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys[0].created, Timestamp::new(1, 0));
        assert_eq!(keys[1].created, Timestamp::new(2, 0));
    }

    // -----------------------------------------------------------------------
    // HybridKeyStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn hybrid_create_key_stores_record() {
        let did = make_did("hybrid1");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].status, HybridKeyStatus::Active);
        // PQ public key must be 1952 bytes (ML-DSA-65)
        assert_eq!(keys[0].public_keys.post_quantum.as_bytes().len(), 1952);
    }

    #[test]
    fn hybrid_active_keys_returns_latest() {
        let did = make_did("hybrid2");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");

        let active = store.active_keys(&did).expect("active_keys");
        assert_eq!(active.post_quantum.as_bytes().len(), 1952);
    }

    #[test]
    fn hybrid_rotate_key_marks_old_and_creates_new() {
        let did = make_did("hybrid3");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");

        let old_classical = store.get_keys(&did).unwrap()[0].public_keys.classical;
        store.rotate_key(&did, &old_classical).expect("rotate_key");

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].status, HybridKeyStatus::Rotated);
        assert_eq!(
            keys[0].rotated_to.as_ref(),
            Some(&keys[1].public_keys.classical)
        );
        assert_eq!(keys[1].status, HybridKeyStatus::Active);
        assert!(store.active_keys(&did).is_some());
    }

    #[test]
    fn hybrid_rotate_unknown_did_fails() {
        let did = make_did("hybrid_unknown");
        let (pk, _) = generate_keypair();
        let mut store = HybridKeyStore::new();
        assert!(matches!(
            store.rotate_key(&did, &pk).unwrap_err(),
            IdentityError::DidNotFound(_)
        ));
    }

    #[test]
    fn hybrid_rotate_unknown_key_fails() {
        let did = make_did("hybrid4");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");
        let (other_pk, _) = generate_keypair();
        assert!(matches!(
            store.rotate_key(&did, &other_pk).unwrap_err(),
            IdentityError::KeyNotFound(_)
        ));
    }

    #[test]
    fn hybrid_rotate_already_rotated_fails() {
        let did = make_did("hybrid5");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");
        let old_classical = store.get_keys(&did).unwrap()[0].public_keys.classical;
        store
            .rotate_key(&did, &old_classical)
            .expect("first rotate");
        assert!(matches!(
            store.rotate_key(&did, &old_classical).unwrap_err(),
            IdentityError::KeyAlreadyRotated
        ));
    }

    #[test]
    fn hybrid_revoke_key_success() {
        let did = make_did("hybrid6");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");
        let classical = store.get_keys(&did).unwrap()[0].public_keys.classical;
        store
            .revoke_key(&did, &classical, "compromised")
            .expect("revoke_key");

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys[0].status, HybridKeyStatus::Revoked);
        assert_eq!(keys[0].revocation_reason.as_deref(), Some("compromised"));
        assert!(store.active_keys(&did).is_none());
    }

    #[test]
    fn hybrid_revoke_already_revoked_fails() {
        let did = make_did("hybrid7");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");
        let classical = store.get_keys(&did).unwrap()[0].public_keys.classical;
        store
            .revoke_key(&did, &classical, "first")
            .expect("first revoke");
        assert!(matches!(
            store.revoke_key(&did, &classical, "second").unwrap_err(),
            IdentityError::KeyAlreadyRevoked
        ));
    }

    #[test]
    fn hybrid_active_keys_unknown_did() {
        let store = HybridKeyStore::new();
        assert!(store.active_keys(&make_did("nobody")).is_none());
    }

    #[test]
    fn hybrid_rotate_revoked_key_fails() {
        let did = make_did("hybrid8");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");
        let classical = store.get_keys(&did).unwrap()[0].public_keys.classical;
        store.revoke_key(&did, &classical, "gone").expect("revoke");
        assert!(matches!(
            store.rotate_key(&did, &classical).unwrap_err(),
            IdentityError::KeyAlreadyRevoked
        ));
    }

    #[test]
    fn hybrid_clock_increments_per_operation() {
        let did = make_did("hybridclock");
        let mut store = HybridKeyStore::new();
        store.create_key(&did).expect("create_key");
        let classical = store.get_keys(&did).unwrap()[0].public_keys.classical;
        store.rotate_key(&did, &classical).expect("rotate");

        let keys = store.get_keys(&did).unwrap();
        assert_eq!(keys[0].created, Timestamp::new(1, 0));
        assert_eq!(keys[1].created, Timestamp::new(2, 0));
    }
}
