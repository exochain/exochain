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

//! Durable PDP identity + Article 26 evidence pack.

use std::path::Path;

use exo_core::crypto::KeyPair;
use exo_pdp::{EvidencePack, PolicyDecisionPoint};

/// Load a durable PDP from `data_dir`, or create one and persist the key.
pub fn load_or_create(data_dir: &Path) -> anyhow::Result<PolicyDecisionPoint> {
    std::fs::create_dir_all(data_dir)?;
    let key_path = data_dir.join("pdp.key");
    let pack_path = data_dir.join("pdp-evidence.json");

    let keypair = if key_path.exists() {
        let secret_bytes = std::fs::read(&key_path)?;
        if secret_bytes.len() != 32 {
            anyhow::bail!(
                "corrupt PDP key at {} — expected 32 bytes, got {}",
                key_path.display(),
                secret_bytes.len()
            );
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&secret_bytes);
        KeyPair::from_secret_bytes(buf)?
    } else {
        let keypair = KeyPair::generate();
        std::fs::write(&key_path, keypair.secret_key().as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms)?;
        }
        keypair
    };

    let mut pdp = PolicyDecisionPoint::new(keypair);
    if pack_path.exists() {
        let bytes = std::fs::read(&pack_path)?;
        let pack = EvidencePack::from_json(&bytes)?;
        pdp.import_pack(pack)?;
        tracing::info!(path = %pack_path.display(), "loaded PDP evidence pack");
    }
    Ok(pdp)
}

/// Write the current pack to disk (Article 26 retention copy).
pub fn save(data_dir: &Path, pdp: &PolicyDecisionPoint) -> anyhow::Result<()> {
    let pack = pdp.export_pack();
    let bytes = pack.to_json()?;
    let tmp = data_dir.join("pdp-evidence.json.tmp");
    let dest = data_dir.join("pdp-evidence.json");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}
