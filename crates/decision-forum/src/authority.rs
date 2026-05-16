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
//! rules, and cryptographic signature validation.

use exo_core::{
    crypto,
    hash::hash_structured,
    types::{Did, Hash256, PublicKey, Signature},
};
use serde::{Deserialize, Serialize};

use crate::error::{ForumError, Result};

const FORUM_AUTHORITY_SIGNATURE_DOMAIN: &str = "decision.forum.authority_signature.v1";

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

#[derive(Debug, Clone, Serialize)]
struct ForumAuthoritySignaturePayload<'a> {
    domain: &'static str,
    root_did: &'a Did,
    constitution_hash: &'a Hash256,
    rules: &'a [ForumRule],
}

fn verify_forum_authority_structure(authority: &ForumAuthority) -> Result<()> {
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

/// Canonical message bytes to sign for a forum authority binding.
pub fn forum_authority_signature_message(authority: &ForumAuthority) -> Result<Vec<u8>> {
    let digest = hash_structured(&ForumAuthoritySignaturePayload {
        domain: FORUM_AUTHORITY_SIGNATURE_DOMAIN,
        root_did: &authority.root_did,
        constitution_hash: &authority.constitution_hash,
        rules: &authority.rules,
    })?;
    Ok(digest.as_ref().to_vec())
}

/// Verify a forum authority binding against a trusted root public key.
///
/// The caller must resolve `root_public_key` from a trusted registry for
/// `authority.root_did`; the key must not come from untrusted authority JSON.
pub fn verify_forum_authority_with_key(
    authority: &ForumAuthority,
    root_public_key: &PublicKey,
) -> Result<()> {
    verify_forum_authority_structure(authority)?;
    let message = forum_authority_signature_message(authority)?;
    if !crypto::verify(&message, &authority.signature, root_public_key) {
        return Err(ForumError::AuthorityInvalid {
            reason: "signature is not valid for trusted root public key".into(),
        });
    }
    Ok(())
}

/// Fail-closed legacy verifier.
///
/// Authenticity cannot be established from a `ForumAuthority` object alone
/// because the trusted root public key belongs to the caller's trust boundary,
/// not to the untrusted authority payload.
pub fn verify_forum_authority(_authority: &ForumAuthority) -> Result<()> {
    Err(ForumError::AuthorityInvalid {
        reason: "trusted root public key required for forum authority verification".into(),
    })
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

    fn signed_auth() -> (ForumAuthority, PublicKey) {
        let (public_key, secret_key) = exo_core::crypto::generate_keypair();
        let mut authority = auth();
        authority.signature = Signature::Empty;
        let message =
            forum_authority_signature_message(&authority).expect("canonical authority payload");
        authority.signature = exo_core::crypto::sign(&message, &secret_key);
        (authority, public_key)
    }

    #[test]
    fn valid_authority() {
        let (authority, public_key) = signed_auth();
        verify_forum_authority_with_key(&authority, &public_key).expect("ok");
    }

    #[test]
    fn verify_forum_authority_rejects_unverified_non_empty_signature() {
        let err = verify_forum_authority(&auth()).unwrap_err();
        assert!(
            err.to_string().contains("public key"),
            "ForumAuthority authenticity must not be accepted from a non-empty signature alone"
        );
    }

    #[test]
    fn verify_forum_authority_with_key_rejects_forged_non_empty_signature() {
        let (public_key, _secret_key) = exo_core::crypto::generate_keypair();
        let err = verify_forum_authority_with_key(&auth(), &public_key).unwrap_err();
        assert!(
            err.to_string().contains("signature"),
            "ForumAuthority must verify the signature against a trusted root public key"
        );
    }

    #[test]
    fn forum_authority_signature_binds_rules() {
        let (mut authority, public_key) = signed_auth();
        authority.rules.push(ForumRule {
            name: "r2".into(),
            hash: Hash256::digest(b"r2"),
        });
        assert!(verify_forum_authority_with_key(&authority, &public_key).is_err());
    }

    #[test]
    fn empty_sig() {
        let (mut a, public_key) = signed_auth();
        a.signature = Signature::from_bytes([0u8; 64]);
        assert!(verify_forum_authority_with_key(&a, &public_key).is_err());
    }

    #[test]
    fn zero_hash() {
        let (mut a, public_key) = signed_auth();
        a.constitution_hash = Hash256::ZERO;
        assert!(verify_forum_authority_with_key(&a, &public_key).is_err());
    }

    #[test]
    fn no_rules() {
        let (mut a, public_key) = signed_auth();
        a.rules.clear();
        assert!(verify_forum_authority_with_key(&a, &public_key).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let a = auth();
        let j = serde_json::to_string(&a).expect("ser");
        assert!(!j.is_empty());
    }
}
