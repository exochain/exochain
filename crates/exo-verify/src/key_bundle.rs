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

//! Property 3: signer identity.
//!
//! A key bundle is a versioned list of `did:exo` identities with their
//! Ed25519 public keys, roles and validity windows. The verifier takes it as
//! input and resolves every signing key against it. The bundle itself is
//! unsigned in this version: it is the caller's trust root.

use exo_core::{Did, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::VerifyError;

/// Format tag for [`KeyBundle`] version 1.
pub const KEY_BUNDLE_FORMAT_V1: &str = "exo.verify.key_bundle.v1";

/// Role a key may sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// Subject (agent) that signs actions.
    Agent,
    /// Validator that signs receipts and receipt tree heads.
    Validator,
}

impl KeyRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Validator => "validator",
        }
    }
}

/// One identity in a [`KeyBundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundleEntry {
    pub did: Did,
    pub public_key: PublicKey,
    pub roles: Vec<KeyRole>,
    /// First instant the key may sign, inclusive. `None` = no lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<Timestamp>,
    /// Instant the key stops being valid, exclusive. `None` = no upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<Timestamp>,
}

/// Versioned set of known signer identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundle {
    /// Must be [`KEY_BUNDLE_FORMAT_V1`].
    pub format: String,
    /// Monotonic version chosen by the bundle publisher.
    pub version: u64,
    pub keys: Vec<KeyBundleEntry>,
}

impl KeyBundle {
    /// Check the bundle format and that each DID appears once.
    ///
    /// # Errors
    /// Returns [`VerifyError::MalformedBundle`] on an unknown format or a
    /// duplicate DID.
    pub fn validate(&self) -> Result<(), VerifyError> {
        if self.format != KEY_BUNDLE_FORMAT_V1 {
            return Err(VerifyError::MalformedBundle {
                reason: format!("unsupported key bundle format {:?}", self.format),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.keys {
            if !seen.insert(entry.did.as_str()) {
                return Err(VerifyError::MalformedBundle {
                    reason: format!("key bundle lists {} more than once", entry.did),
                });
            }
        }
        Ok(())
    }

    /// Resolve `did` to its public key for `role`, valid at `at`.
    ///
    /// # Errors
    /// [`VerifyError::UnknownSigner`] when the DID is absent,
    /// [`VerifyError::SignerRoleMismatch`] when it lacks `role`, and
    /// [`VerifyError::SignerKeyNotValidAtTime`] outside its validity window.
    pub fn resolve(
        &self,
        did: &Did,
        role: KeyRole,
        at: Option<&Timestamp>,
    ) -> Result<&KeyBundleEntry, VerifyError> {
        let entry = self
            .keys
            .iter()
            .find(|entry| &entry.did == did)
            .ok_or_else(|| VerifyError::UnknownSigner {
                did: did.to_string(),
            })?;
        if !entry.roles.contains(&role) {
            return Err(VerifyError::SignerRoleMismatch {
                did: did.to_string(),
                role: role.label(),
            });
        }
        if let Some(at) = at {
            let before = entry.valid_from.as_ref().is_some_and(|from| at < from);
            let after = entry.valid_until.as_ref().is_some_and(|until| at >= until);
            if before || after {
                return Err(VerifyError::SignerKeyNotValidAtTime {
                    did: did.to_string(),
                });
            }
        }
        Ok(entry)
    }

    /// Resolve `did` and require that it uses exactly `public_key`.
    ///
    /// # Errors
    /// As [`KeyBundle::resolve`], plus [`VerifyError::SignerKeyMismatch`].
    pub fn require_key(
        &self,
        did: &Did,
        public_key: &PublicKey,
        role: KeyRole,
        at: Option<&Timestamp>,
    ) -> Result<(), VerifyError> {
        let entry = self.resolve(did, role, at)?;
        if &entry.public_key != public_key {
            return Err(VerifyError::SignerKeyMismatch {
                did: did.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).unwrap()
    }

    fn bundle() -> KeyBundle {
        KeyBundle {
            format: KEY_BUNDLE_FORMAT_V1.into(),
            version: 1,
            keys: vec![KeyBundleEntry {
                did: did("validator"),
                public_key: PublicKey::from_bytes([1; 32]),
                roles: vec![KeyRole::Validator],
                valid_from: Some(Timestamp::new(100, 0)),
                valid_until: Some(Timestamp::new(200, 0)),
            }],
        }
    }

    #[test]
    fn resolves_known_key_within_window() {
        let b = bundle();
        b.validate().unwrap();
        b.require_key(
            &did("validator"),
            &PublicKey::from_bytes([1; 32]),
            KeyRole::Validator,
            Some(&Timestamp::new(150, 0)),
        )
        .unwrap();
        b.resolve(&did("validator"), KeyRole::Validator, None)
            .unwrap();
    }

    #[test]
    fn distinct_errors_for_each_identity_failure() {
        let b = bundle();
        let at = Timestamp::new(150, 0);
        assert!(matches!(
            b.resolve(&did("nobody"), KeyRole::Validator, Some(&at)),
            Err(VerifyError::UnknownSigner { .. })
        ));
        assert!(matches!(
            b.resolve(&did("validator"), KeyRole::Agent, Some(&at)),
            Err(VerifyError::SignerRoleMismatch { role: "agent", .. })
        ));
        for t in [Timestamp::new(99, 0), Timestamp::new(200, 0)] {
            assert!(matches!(
                b.resolve(&did("validator"), KeyRole::Validator, Some(&t)),
                Err(VerifyError::SignerKeyNotValidAtTime { .. })
            ));
        }
        assert!(matches!(
            b.require_key(
                &did("validator"),
                &PublicKey::from_bytes([2; 32]),
                KeyRole::Validator,
                Some(&at)
            ),
            Err(VerifyError::SignerKeyMismatch { .. })
        ));
    }

    #[test]
    fn rejects_unknown_format_and_duplicates() {
        let mut b = bundle();
        b.format = "other".into();
        assert!(matches!(
            b.validate(),
            Err(VerifyError::MalformedBundle { .. })
        ));
        let mut b = bundle();
        b.keys.push(b.keys[0].clone());
        assert!(matches!(
            b.validate(),
            Err(VerifyError::MalformedBundle { .. })
        ));
    }
}
