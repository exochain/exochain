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

//! CrossCheckResult types + Ed25519 verify (IW-4 / PM-004) — .ai extension point.

use exo_core::{
    Did, Hash256, PublicKey, SecretKey, Signature, crypto,
    hash::hash_structured,
};
use exo_gatekeeper::types::TrustedProvenanceKeys;
use serde::{Deserialize, Serialize};

use crate::error::{IntelwarError, Result};
use crate::log_entry::VoiceKind;

/// Domain separator for CrossCheckResult signing.
pub const CROSSCHECK_DOMAIN: &str = "intelwar.crosscheck.v1";

/// Cross-check verdict from a distinct intelligence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossCheckVerdict {
    Agree,
    Disagree,
    Abstain,
}

impl CrossCheckVerdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agree => "agree",
            Self::Disagree => "disagree",
            Self::Abstain => "abstain",
        }
    }
}

/// Result of a cross-intelligence check against a subject entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCheckResult {
    pub checker_did: Did,
    pub subject_entry_hash: Hash256,
    pub verdict: CrossCheckVerdict,
    pub evidence_hash: Hash256,
    pub voice_kind: VoiceKind,
    pub signature: Vec<u8>,
}

fn voice_label(voice: VoiceKind) -> &'static str {
    match voice {
        VoiceKind::Human => "human",
        VoiceKind::Synthetic => "synthetic",
        VoiceKind::System => "system",
    }
}

/// Canonical signing payload (CBOR-hashed) for a CrossCheckResult without signature.
pub fn crosscheck_signing_hash(result: &CrossCheckResult) -> Result<Hash256> {
    #[derive(Serialize)]
    struct Payload<'a> {
        domain: &'a str,
        checker_did: String,
        subject_entry_hash: &'a Hash256,
        verdict: &'a str,
        evidence_hash: &'a Hash256,
        voice_kind: &'a str,
    }
    let payload = Payload {
        domain: CROSSCHECK_DOMAIN,
        checker_did: result.checker_did.to_string(),
        subject_entry_hash: &result.subject_entry_hash,
        verdict: result.verdict.as_str(),
        evidence_hash: &result.evidence_hash,
        voice_kind: voice_label(result.voice_kind),
    };
    hash_structured(&payload).map_err(|e| IntelwarError::Crosscheck {
        reason: format!("crosscheck signing hash failed: {e}"),
    })
}

/// Sign a CrossCheckResult in place (Ed25519 over the canonical hash bytes).
pub fn sign_crosscheck(result: &mut CrossCheckResult, secret: &SecretKey) -> Result<()> {
    let hash = crosscheck_signing_hash(result)?;
    let sig = crypto::sign(hash.as_bytes(), secret);
    result.signature = sig.to_bytes();
    Ok(())
}

/// Verify one CrossCheckResult signature against a 32-byte Ed25519 public key.
pub fn verify_crosscheck_signature(result: &CrossCheckResult, public_key: &[u8]) -> Result<()> {
    if public_key.len() != 32 {
        return Err(IntelwarError::Crosscheck {
            reason: format!(
                "checker public key must be 32 bytes, got {}",
                public_key.len()
            ),
        });
    }
    if result.signature.len() != 64 {
        return Err(IntelwarError::Crosscheck {
            reason: format!(
                "crosscheck signature must be 64 bytes, got {}",
                result.signature.len()
            ),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&result.signature);
    let hash = crosscheck_signing_hash(result)?;
    let pk = PublicKey::from_bytes({
        let mut a = [0u8; 32];
        a.copy_from_slice(public_key);
        a
    });
    let sig = Signature::from_bytes(sig_arr);
    if !crypto::verify(hash.as_bytes(), &sig, &pk) {
        return Err(IntelwarError::Crosscheck {
            reason: format!(
                "crosscheck signature verification failed for {}",
                result.checker_did
            ),
        });
    }
    Ok(())
}

/// Validate that crosschecks satisfy IW-4 for a subject authored by `author`.
///
/// Signatures are verified against `trusted_checker_keys` (DID → public key bytes).
pub fn crosschecks_satisfy(
    author: &Did,
    subject_hash: &Hash256,
    results: &[CrossCheckResult],
    trusted_checker_keys: &TrustedProvenanceKeys,
) -> Result<()> {
    if results.is_empty() {
        return Err(IntelwarError::Crosscheck {
            reason: "at least one CrossCheckResult is required".into(),
        });
    }
    for (idx, result) in results.iter().enumerate() {
        if &result.checker_did == author {
            return Err(IntelwarError::Crosscheck {
                reason: format!("self-crosscheck denied at index {idx}"),
            });
        }
        if &result.subject_entry_hash != subject_hash {
            return Err(IntelwarError::Crosscheck {
                reason: format!("subject_entry_hash mismatch at index {idx}"),
            });
        }
        let keys = trusted_checker_keys.get(&result.checker_did).ok_or_else(|| {
            IntelwarError::Crosscheck {
                reason: format!(
                    "no trusted public key for checker {} at index {idx}",
                    result.checker_did
                ),
            }
        })?;
        if keys.is_empty() {
            return Err(IntelwarError::Crosscheck {
                reason: format!("empty trusted key list for checker at index {idx}"),
            });
        }
        let mut verified = false;
        let mut last_err: Option<IntelwarError> = None;
        for key in keys {
            match verify_crosscheck_signature(result, key) {
                Ok(()) => {
                    verified = true;
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        if !verified {
            return Err(match last_err {
                Some(e) => e,
                None => IntelwarError::Crosscheck {
                    reason: format!("signature verify failed at index {idx}"),
                },
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, crypto};

    use super::*;

    #[test]
    fn signed_crosscheck_verifies_and_rejects_tamper() {
        let (pk, sk) = crypto::generate_keypair();
        let checker = Did::new("did:exo:checker").unwrap();
        let mut result = CrossCheckResult {
            checker_did: checker.clone(),
            subject_entry_hash: Hash256::digest(b"subject"),
            verdict: CrossCheckVerdict::Agree,
            evidence_hash: Hash256::digest(b"evidence"),
            voice_kind: VoiceKind::Synthetic,
            signature: Vec::new(),
        };
        sign_crosscheck(&mut result, &sk).unwrap();
        verify_crosscheck_signature(&result, pk.as_bytes()).unwrap();

        result.verdict = CrossCheckVerdict::Disagree;
        assert!(verify_crosscheck_signature(&result, pk.as_bytes()).is_err());
    }

    #[test]
    fn crosschecks_satisfy_requires_trusted_key() {
        let (pk, sk) = crypto::generate_keypair();
        let checker = Did::new("did:exo:checker").unwrap();
        let author = Did::new("did:exo:author").unwrap();
        let subject = Hash256::digest(b"subject");
        let mut result = CrossCheckResult {
            checker_did: checker.clone(),
            subject_entry_hash: subject,
            verdict: CrossCheckVerdict::Agree,
            evidence_hash: Hash256::digest(b"evidence"),
            voice_kind: VoiceKind::Human,
            signature: Vec::new(),
        };
        sign_crosscheck(&mut result, &sk).unwrap();

        let mut keys = TrustedProvenanceKeys::default();
        keys.insert(checker, vec![pk.as_bytes().to_vec()]);
        crosschecks_satisfy(&author, &subject, &[result.clone()], &keys).unwrap();

        let empty = TrustedProvenanceKeys::default();
        assert!(crosschecks_satisfy(&author, &subject, &[result], &empty).is_err());
    }
}
