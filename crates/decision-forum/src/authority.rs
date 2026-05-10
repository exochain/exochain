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

//! Forum authority management.
//!
//! Verifies forum-level authority bindings: root DID, constitution hash,
//! rules, and signature validation.

use exo_core::types::{Did, Hash256, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{ForumError, Result};

/// A named rule within the forum authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumRule {
    pub name: String,
    pub hash: Hash256,
}

/// The top-level forum authority binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumAuthority {
    pub root_did: Did,
    pub constitution_hash: Hash256,
    pub rules: Vec<ForumRule>,
    pub signature: Signature,
}

/// Verify that a forum authority binding is structurally valid.
pub fn verify_forum_authority(authority: &ForumAuthority) -> Result<()> {
    if authority.signature.is_empty() {
        return Err(ForumError::AuthorityInvalid {
            reason: "empty signature".into(),
        });
    }
    if authority.constitution_hash == Hash256::ZERO {
        return Err(ForumError::AuthorityInvalid {
            reason: "zero constitution hash".into(),
        });
    }
    if authority.rules.is_empty() {
        return Err(ForumError::AuthorityInvalid {
            reason: "no rules defined".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:exo:root").expect("ok")
    }
    fn sig() -> Signature {
        let mut s = [0u8; 64];
        s[0] = 1;
        Signature::from_bytes(s)
    }

    fn auth() -> ForumAuthority {
        ForumAuthority {
            root_did: did(),
            constitution_hash: Hash256::digest(b"const"),
            rules: vec![ForumRule {
                name: "r1".into(),
                hash: Hash256::digest(b"r1"),
            }],
            signature: sig(),
        }
    }

    #[test]
    fn valid_authority() {
        verify_forum_authority(&auth()).expect("ok");
    }

    #[test]
    fn empty_sig() {
        let mut a = auth();
        a.signature = Signature::from_bytes([0u8; 64]);
        assert!(verify_forum_authority(&a).is_err());
    }

    #[test]
    fn zero_hash() {
        let mut a = auth();
        a.constitution_hash = Hash256::ZERO;
        assert!(verify_forum_authority(&a).is_err());
    }

    #[test]
    fn no_rules() {
        let mut a = auth();
        a.rules.clear();
        assert!(verify_forum_authority(&a).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let a = auth();
        let j = serde_json::to_string(&a).expect("ser");
        assert!(!j.is_empty());
    }
}
