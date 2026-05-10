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

//! Node identity — Ed25519 keypair + DID, persisted in the data directory.
//!
//! On first run, generates a fresh Ed25519 keypair, derives a DID from the
//! public key (`did:exo:<base58(blake3(pubkey))>`), and stores the secret
//! key in `identity.key`. Subsequent runs reload from disk.

#![allow(clippy::same_item_push)]

use std::{io::Write, path::Path};

use exo_core::{
    crypto::KeyPair,
    types::{Did, PublicKey},
};
use zeroize::Zeroize;

/// A node's persistent identity.
pub struct NodeIdentity {
    pub did: Did,
    /// The node's public key — used for identity verification and governance.
    pub public_key: PublicKey,
    keypair: KeyPair,
}

impl NodeIdentity {
    /// Returns a reference to this node's public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key.0
    }
}

impl NodeIdentity {
    /// Sign a message using this node's secret key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> exo_core::types::Signature {
        self.keypair.sign(message)
    }

    /// Returns the Ed25519 public key.
    #[must_use]
    #[allow(dead_code)] // Accessor for delegation/attestation flows
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// Derive the EXOCHAIN DID bound to a raw Ed25519 public key.
///
/// The node DID format is `did:exo:<base58(blake3(pubkey))>`. Validator
/// public-key configuration uses this derivation as a consistency check before
/// a key can be accepted for consensus signature verification.
pub fn did_from_public_key(public_key: &PublicKey) -> anyhow::Result<Did> {
    let hash = blake3::hash(public_key.as_bytes());
    let encoded = bs58_encode(hash.as_bytes());
    Did::new(&format!("did:exo:{encoded}")).map_err(Into::into)
}

/// Load an existing identity from the data directory, or generate a new one.
pub fn load_or_create(data_dir: &Path) -> anyhow::Result<NodeIdentity> {
    let key_path = data_dir.join("identity.key");
    let did_path = data_dir.join("identity.did");

    if key_path.exists() {
        // Reload existing identity.
        let mut secret_bytes = std::fs::read(&key_path)?;
        if secret_bytes.len() != 32 {
            let actual_len = secret_bytes.len();
            secret_bytes.zeroize();
            anyhow::bail!(
                "Corrupt identity key at {} — expected 32 bytes, got {}",
                key_path.display(),
                actual_len
            );
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();
        let keypair_result = KeyPair::from_secret_bytes(buf);
        buf.zeroize();
        let keypair = keypair_result?;

        let did_str = std::fs::read_to_string(&did_path)?;
        let did = Did::new(did_str.trim())?;

        tracing::info!(did = %did, "Loaded existing identity");

        Ok(NodeIdentity {
            did,
            public_key: *keypair.public_key(),
            keypair,
        })
    } else {
        // Generate fresh identity.
        let keypair = KeyPair::generate();
        let public_key = *keypair.public_key();

        let did = did_from_public_key(&public_key)?;

        // Persist secret key (mode 0600).
        write_secret(&key_path, keypair.secret_key().as_bytes())?;
        std::fs::write(&did_path, did.as_str().as_bytes())?;

        tracing::info!(did = %did, "Generated new node identity");

        Ok(NodeIdentity {
            did,
            public_key,
            keypair,
        })
    }
}

/// Minimal base58 encoding (Bitcoin alphabet) — avoids adding `bs58` as a dep
/// since we only need encoding of 32-byte hashes here.
fn bs58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if data.is_empty() {
        return String::new();
    }

    // Count leading zeros.
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to base58 via repeated division.
    let mut num = data.to_vec();
    let mut encoded = Vec::new();

    while !num.is_empty() {
        let mut remainder = 0u32;
        let mut next = Vec::new();
        for &byte in &num {
            let value = (remainder << 8) | u32::from(byte);
            let digit = value / 58;
            remainder = value % 58;
            if !next.is_empty() || digit > 0 {
                let Ok(digit_byte) = u8::try_from(digit) else {
                    return String::new();
                };
                next.push(digit_byte);
            }
        }
        let Ok(alphabet_index) = usize::try_from(remainder) else {
            return String::new();
        };
        encoded.push(ALPHABET[alphabet_index]);
        num = next;
    }

    // Add leading '1's for leading zeros.
    for _ in 0..leading_zeros {
        encoded.push(b'1');
    }

    encoded.reverse();
    encoded.into_iter().map(char::from).collect()
}

/// Write secret key bytes with restrictive permissions.
fn write_secret(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                anyhow::anyhow!("failed to create secret key file {}: {e}", path.display())
            })?;
        file.write_all(data)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                anyhow::anyhow!("failed to create secret key file {}: {e}", path.display())
            })?;
        file.write_all(data)?;
        file.sync_all()?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_creates_identity_files() {
        let dir = tempfile::tempdir().unwrap();
        let identity = load_or_create(dir.path()).unwrap();

        let key_bytes = std::fs::read(dir.path().join("identity.key")).unwrap();
        let did_text = std::fs::read_to_string(dir.path().join("identity.did")).unwrap();

        assert_eq!(key_bytes.len(), 32);
        assert_eq!(did_text.trim(), identity.did.as_str());
        assert_eq!(identity.public_key_bytes().len(), 32);
    }

    #[test]
    fn load_or_create_reloads_existing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create(dir.path()).unwrap();
        let second = load_or_create(dir.path()).unwrap();

        assert_eq!(first.did, second.did);
        assert_eq!(first.public_key_bytes(), second.public_key_bytes());
    }

    #[test]
    fn did_from_public_key_matches_node_identity_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let identity = load_or_create(dir.path()).unwrap();

        assert_eq!(
            did_from_public_key(identity.public_key()).unwrap(),
            identity.did
        );
    }

    #[test]
    fn load_or_create_rejects_corrupt_secret_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("identity.key"), [7u8; 31]).unwrap();
        std::fs::write(dir.path().join("identity.did"), b"did:exo:corrupt").unwrap();

        let err = match load_or_create(dir.path()) {
            Ok(_) => panic!("corrupt secret key must not load"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("Corrupt identity key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn write_secret_rejects_existing_file_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("identity.key");
        std::fs::write(&key_path, [0xA5u8; 32]).unwrap();

        let err = match write_secret(&key_path, &[0x5Au8; 32]) {
            Ok(()) => panic!("write_secret must not overwrite an existing secret path"),
            Err(err) => err,
        };
        let contents = std::fs::read(&key_path).unwrap();

        assert!(
            err.to_string().contains("identity.key"),
            "error should identify the refused secret path: {err}"
        );
        assert_eq!(contents, vec![0xA5u8; 32]);
    }

    #[test]
    fn write_secret_source_creates_file_with_restrictive_mode_before_write() {
        let source = include_str!("identity.rs");
        let write_secret_source = source
            .split("fn write_secret")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();

        assert!(
            !write_secret_source.contains("std::fs::write(path, data)"),
            "secret key must not be written before restrictive permissions are applied"
        );
        assert!(
            write_secret_source.contains(".create_new(true)"),
            "secret key creation must fail if an attacker races in an existing path"
        );
        #[cfg(unix)]
        assert!(
            write_secret_source.contains(".mode(0o600)"),
            "Unix secret key file must be created with mode 0600 before bytes are written"
        );
    }

    #[test]
    fn load_existing_identity_source_zeroizes_secret_read_buffer() {
        let source = include_str!("identity.rs");
        let load_source = source
            .split("pub fn load_or_create")
            .nth(1)
            .unwrap()
            .split("/// Minimal base58 encoding")
            .next()
            .unwrap();

        assert!(
            load_source.contains("secret_bytes.zeroize()"),
            "temporary Vec holding identity.key bytes must be zeroized after copying"
        );
    }

    #[test]
    fn bs58_encode_source_uses_checked_integer_conversions() {
        let source = include_str!("identity.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        let encode_source = production
            .split("fn bs58_encode")
            .nth(1)
            .expect("base58 encoder source exists")
            .split("/// Write secret key bytes with restrictive permissions.")
            .next()
            .expect("base58 encoder source ends before write_secret");

        assert!(
            !encode_source.contains("clippy::as_conversions"),
            "node identity base58 encoding must not suppress checked conversion lints"
        );
        assert!(
            !encode_source.contains("digit as u8"),
            "base58 digit conversion must be checked rather than truncated"
        );
        assert!(
            !encode_source.contains("remainder as usize"),
            "base58 alphabet index conversion must be checked rather than truncated"
        );
        assert!(
            !encode_source.contains("String::from_utf8(encoded).unwrap_or_default()"),
            "base58 encoding must not silently collapse encoding defects to an empty string"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_or_create_writes_secret_key_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let _identity = load_or_create(dir.path()).unwrap();

        let mode = std::fs::metadata(dir.path().join("identity.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
