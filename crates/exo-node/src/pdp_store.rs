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

use std::path::Path;

use exo_core::crypto::KeyPair;
use exo_pdp::{PdpSnapshot, PolicyDecisionPoint};
use zeroize::{Zeroize, Zeroizing};

use crate::private_file::{
    PrivateFileReadError, read_private_file, write_private_create_new, write_private_replace,
};

const KEY_FILE: &str = "pdp.key";
const STATE_FILE: &str = "pdp-state.cbor";
const MAX_PDP_SNAPSHOT_BYTES: u64 = 67_108_864;

fn read_key(path: &Path) -> anyhow::Result<KeyPair> {
    let mut secret_bytes = read_private_file(path, 32, "PDP key custody rejected")?;
    if secret_bytes.len() != 32 {
        anyhow::bail!(
            "corrupt PDP key at {} — expected 32 bytes, got {}",
            path.display(),
            secret_bytes.len()
        );
    }
    let mut buf = Zeroizing::new([0u8; 32]);
    buf.copy_from_slice(&secret_bytes);
    secret_bytes.zeroize();
    Ok(KeyPair::from_secret_bytes(std::mem::take(&mut *buf))?)
}

fn load_or_create_key(path: &Path) -> anyhow::Result<KeyPair> {
    match read_key(path) {
        Ok(key) => Ok(key),
        Err(read_error)
            if matches!(
                read_error.downcast_ref(),
                Some(PrivateFileReadError::NotFound { .. })
            ) =>
        {
            let keypair = KeyPair::generate();
            match write_private_create_new(path, keypair.secret_key().as_bytes()) {
                Ok(()) => Ok(keypair),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io_error| {
                            io_error.kind() == std::io::ErrorKind::AlreadyExists
                        }) =>
                {
                    read_key(path)
                }
                Err(error) => Err(error),
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
    match read_snapshot(&state_path) {
        Ok(bytes) => {
            let snapshot = PdpSnapshot::from_cbor(&bytes)?;
            pdp.import_snapshot(snapshot)?;
            tracing::info!(path = %state_path.display(), "loaded signed PDP runtime state");
        }
        Err(PrivateFileReadError::NotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(pdp)
}

fn read_snapshot(path: &Path) -> Result<Zeroizing<Vec<u8>>, PrivateFileReadError> {
    read_private_file(
        path,
        MAX_PDP_SNAPSHOT_BYTES,
        "PDP snapshot custody rejected",
    )
}

/// Atomically write all signed PDP runtime state to disk.
pub fn save(data_dir: &Path, pdp: &PolicyDecisionPoint) -> anyhow::Result<()> {
    let bytes = Zeroizing::new(pdp.export_snapshot()?.to_cbor()?);
    let dest = data_dir.join(STATE_FILE);
    write_private_replace(&dest, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use exo_core::{Did, Hash256, Timestamp, crypto::KeyPair};

    use super::*;

    fn create_sized_private_file(path: &Path, len: u64) {
        write_private_create_new(path, b"x").expect("create private fixture");
        OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open private fixture")
            .set_len(len)
            .expect("size private fixture");
    }

    #[test]
    fn absent_pdp_snapshot_first_start_remains_accepted() {
        let directory = tempfile::tempdir().expect("fixture");
        let pdp = load_or_create(directory.path()).expect("first start");
        assert_ne!(pdp.service_public_key().as_bytes(), &[0_u8; 32]);
        assert!(!directory.path().join(STATE_FILE).exists());
    }

    #[test]
    fn pdp_snapshot_bounds_are_enforced_before_cbor_parse() {
        let directory = tempfile::tempdir().expect("fixture");
        load_or_create(directory.path()).expect("create PDP key");
        let path = directory.path().join(STATE_FILE);
        create_sized_private_file(&path, 67_108_864);
        assert_eq!(
            read_snapshot(&path).expect("exact snapshot limit").len(),
            67_108_864
        );

        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open private fixture")
            .set_len(67_108_865)
            .expect("size oversized fixture");
        let error = match load_or_create(directory.path()) {
            Ok(_) => panic!("oversized snapshot must fail before CBOR parse"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("PDP snapshot custody rejected"));
    }

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
        let expected_public_key = *KeyPair::from_secret_bytes(original).unwrap().public_key();
        write_private_create_new(&path, &original).unwrap();

        let loaded = load_or_create(dir.path()).unwrap();
        assert_eq!(loaded.service_public_key(), expected_public_key);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[test]
    fn stale_pdp_temp_owned_regular_file_recovers_without_weakening_create_new() {
        let directory = tempfile::tempdir().unwrap();
        let pdp = load_or_create(directory.path()).unwrap();
        let stale = directory.path().join("pdp-state.cbor.tmp");
        crate::private_file::write_private_create_new(&stale, b"stale owned temp").unwrap();

        save(directory.path(), &pdp).expect("exact owned stale temp must recover");

        assert!(!stale.exists());
        assert!(directory.path().join(STATE_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_file_pdp_rejects_permissive_snapshot_and_symlink_key_before_decode() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let snapshot_dir = tempfile::tempdir().unwrap();
        let pdp = load_or_create(snapshot_dir.path()).unwrap();
        save(snapshot_dir.path(), &pdp).unwrap();
        let snapshot = snapshot_dir.path().join(STATE_FILE);
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = match load_or_create(snapshot_dir.path()) {
            Ok(_) => panic!("permissive PDP snapshot must fail before CBOR decode"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(STATE_FILE));

        let source = tempfile::tempdir().unwrap();
        let source_pdp = load_or_create(source.path()).unwrap();
        let linked = tempfile::tempdir().unwrap();
        symlink(source.path().join(KEY_FILE), linked.path().join(KEY_FILE)).unwrap();
        let error = match load_or_create(linked.path()) {
            Ok(_) => panic!("symlink PDP key must fail before key decode"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(KEY_FILE));
        drop(source_pdp);
    }
}
