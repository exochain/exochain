//! Node identity — Ed25519 keypair + DID, persisted in the data directory.
//!
//! On first run, generates a fresh Ed25519 keypair, derives a DID from the
//! public key (`did:exo:<base58(blake3(pubkey))>`), and stores the secret
//! key in `identity.key`. Subsequent runs reload from disk.

#![allow(clippy::same_item_push)]

use std::path::Path;

use exo_core::{
    crypto::KeyPair,
    types::{Did, PublicKey},
};

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

/// Load an existing identity from the data directory, or generate a new one.
pub fn load_or_create(data_dir: &Path) -> anyhow::Result<NodeIdentity> {
    let key_path = data_dir.join("identity.key");
    let did_path = data_dir.join("identity.did");

    if key_path.exists() {
        // Reload existing identity.
        let secret_bytes = std::fs::read(&key_path)?;
        if secret_bytes.len() != 32 {
            anyhow::bail!(
                "Corrupt identity key at {} — expected 32 bytes, got {}",
                key_path.display(),
                secret_bytes.len()
            );
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&secret_bytes);
        let keypair = KeyPair::from_secret_bytes(buf)?;

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

        // DID = did:exo:<base58(blake3(pubkey))>
        let hash = blake3::hash(&public_key.0);
        let encoded = bs58_encode(hash.as_bytes());
        let did_str = format!("did:exo:{encoded}");
        let did = Did::new(&did_str)?;

        // Persist secret key (mode 0600).
        write_secret(&key_path, keypair.secret_key().as_bytes())?;
        std::fs::write(&did_path, did_str.as_bytes())?;

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
                #[allow(clippy::as_conversions)]
                next.push(digit as u8);
            }
        }
        #[allow(clippy::as_conversions)]
        encoded.push(ALPHABET[remainder as usize]);
        num = next;
    }

    // Add leading '1's for leading zeros.
    for _ in 0..leading_zeros {
        encoded.push(b'1');
    }

    encoded.reverse();
    String::from_utf8(encoded).unwrap_or_default()
}

/// Write secret key bytes with restrictive permissions.
fn write_secret(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, data)?;

    // Set 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}
