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

//! Terms and conditions management.

use exo_core::types::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{ForumError, Result};

/// A terms-and-conditions document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermsDocument {
    pub id: String,
    pub version: u64,
    pub text_hash: Hash256,
    pub effective_at: Timestamp,
}

/// An acceptance record for terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermsAcceptance {
    pub terms_id: String,
    pub terms_version: u64,
    pub accepted_by: Did,
    pub accepted_at: Timestamp,
    pub signature_hash: Hash256,
}

/// Registry of terms acceptances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TermsRegistry {
    pub acceptances: Vec<TermsAcceptance>,
}

impl TermsRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            acceptances: Vec::new(),
        }
    }

    /// Record an acceptance.
    pub fn accept(&mut self, acceptance: TermsAcceptance) {
        self.acceptances.push(acceptance);
    }

    /// Check if a given DID has accepted a specific terms document version.
    #[must_use]
    pub fn has_accepted(&self, did: &Did, terms_id: &str, version: u64) -> bool {
        self.acceptances
            .iter()
            .any(|a| a.accepted_by == *did && a.terms_id == terms_id && a.terms_version == version)
    }

    /// Require acceptance, returning an error if not found.
    pub fn require_acceptance(&self, did: &Did, terms_id: &str, version: u64) -> Result<()> {
        if self.has_accepted(did, terms_id, version) {
            Ok(())
        } else {
            Err(ForumError::TermsNotAccepted(did.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:exo:alice").expect("ok")
    }
    fn ts() -> Timestamp {
        Timestamp::new(1000, 0)
    }

    #[test]
    fn accept_and_check() {
        let mut reg = TermsRegistry::new();
        reg.accept(TermsAcceptance {
            terms_id: "tos".into(),
            terms_version: 1,
            accepted_by: did(),
            accepted_at: ts(),
            signature_hash: Hash256::digest(b"sig"),
        });
        assert!(reg.has_accepted(&did(), "tos", 1));
        assert!(!reg.has_accepted(&did(), "tos", 2));
    }

    #[test]
    fn require_acceptance_ok() {
        let mut reg = TermsRegistry::new();
        reg.accept(TermsAcceptance {
            terms_id: "tos".into(),
            terms_version: 1,
            accepted_by: did(),
            accepted_at: ts(),
            signature_hash: Hash256::ZERO,
        });
        assert!(reg.require_acceptance(&did(), "tos", 1).is_ok());
    }

    #[test]
    fn require_acceptance_missing() {
        let reg = TermsRegistry::new();
        let err = reg.require_acceptance(&did(), "tos", 1).unwrap_err();
        assert!(matches!(err, ForumError::TermsNotAccepted(_)));
    }

    #[test]
    fn default_empty() {
        let reg = TermsRegistry::default();
        assert!(reg.acceptances.is_empty());
    }
}
