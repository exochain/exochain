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

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Durable PDP identity and service-signed runtime authority state.

use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::Path,
};

use exo_core::crypto::KeyPair;
use exo_pdp::{PdpSnapshot, PolicyDecisionPoint};

const KEY_FILE: &str = "pdp.key";
const STATE_FILE: &str = "pdp-state.cbor";

fn open_private_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn read_key(path: &Path) -> anyhow::Result<KeyPair> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "PDP key at {} has unsafe mode {:o}; expected owner-only permissions",
                path.display(),
                mode
            );
        }
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut secret_bytes = Vec::new();
    file.read_to_end(&mut secret_bytes)?;
    if secret_bytes.len() != 32 {
        anyhow::bail!(
            "corrupt PDP key at {} — expected 32 bytes, got {}",
            path.display(),
            secret_bytes.len()
        );
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&secret_bytes);
    Ok(KeyPair::from_secret_bytes(buf)?)
}

fn load_or_create_key(path: &Path) -> anyhow::Result<KeyPair> {
    match read_key(path) {
        Ok(key) => Ok(key),
        Err(read_error)
            if read_error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            let keypair = KeyPair::generate();
            match open_private_new(path) {
                Ok(mut file) => {
                    file.write_all(keypair.secret_key().as_bytes())?;
                    file.sync_all()?;
                    Ok(keypair)
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => read_key(path),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error),
    }
}

/// Load a durable PDP from `data_dir`, or create one and persist the key.
pub fn load_or_create(data_dir: &Path) -> anyhow::Result<PolicyDecisionPoint> {
    std::fs::create_dir_all(data_dir)?;
    let key_path = data_dir.join(KEY_FILE);
    let state_path = data_dir.join(STATE_FILE);
    let keypair = load_or_create_key(&key_path)?;

    let mut pdp = PolicyDecisionPoint::new(keypair);
    match std::fs::read(&state_path) {
        Ok(bytes) => {
            let snapshot = PdpSnapshot::from_cbor(&bytes)?;
            pdp.import_snapshot(snapshot)?;
            tracing::info!(path = %state_path.display(), "loaded signed PDP runtime state");
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(pdp)
}

/// Atomically write all signed PDP runtime state to disk.
pub fn save(data_dir: &Path, pdp: &PolicyDecisionPoint) -> anyhow::Result<()> {
    let bytes = pdp.export_snapshot()?.to_cbor()?;
    let tmp = data_dir.join("pdp-state.cbor.tmp");
    let dest = data_dir.join(STATE_FILE);
    let mut file = open_private_new(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, &dest)?;
    File::open(data_dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, Timestamp, crypto::KeyPair};

    use super::*;

    #[test]
    fn restart_preserves_key_revocation_and_consumed_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut pdp = load_or_create(dir.path()).unwrap();
        let principal = Did::new("did:exo:principal").unwrap();
        let principal_key = KeyPair::generate();
        let mandate_hash = Hash256::digest(b"durable-mandate");
        pdp.register_key(principal.clone(), *principal_key.public_key());
        pdp.reserve(mandate_hash, Timestamp::new(1, 0)).unwrap();
        pdp.commit(&mandate_hash).unwrap();
        pdp.revoke_mandate(mandate_hash, Timestamp::new(2, 0), "revoked".into());
        let service_public_key = pdp.service_public_key();
        save(dir.path(), &pdp).unwrap();

        let restored = load_or_create(dir.path()).unwrap();
        assert_eq!(restored.service_public_key(), service_public_key);
        assert_eq!(
            restored.resolve_public(&principal),
            Some(*principal_key.public_key())
        );
        assert!(restored.is_consumed(&mandate_hash));
        assert!(restored.is_mandate_revoked(&mandate_hash));
    }

    #[cfg(unix)]
    #[test]
    fn new_key_and_state_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let pdp = load_or_create(dir.path()).unwrap();
        save(dir.path(), &pdp).unwrap();
        let key_mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let state_mode = std::fs::metadata(dir.path().join(STATE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600);
        assert_eq!(state_mode, 0o600);
    }

    #[test]
    fn existing_key_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEY_FILE);
        let original = [7u8; 32];
        let mut file = open_private_new(&path).unwrap();
        file.write_all(&original).unwrap();
        file.sync_all().unwrap();

        let loaded = load_or_create(dir.path()).unwrap();
        assert_eq!(loaded.service_secret_bytes(), original);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}
