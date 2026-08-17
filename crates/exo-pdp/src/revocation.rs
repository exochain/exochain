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

//! Real-time revocation of mandates and delegated capabilities.

use std::collections::BTreeSet;

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{PdpError, Result};

/// A revocation entry. Presence in the set is sufficient to deny.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Revocation {
    pub target: RevocationTarget,
    pub revoked_at: Timestamp,
    pub reason: String,
}

/// What was revoked.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RevocationTarget {
    Mandate(Hash256),
    Agent(Did),
    Delegation(Hash256),
}

/// In-memory revocation set. Lookups are fail-closed on hit.
#[derive(Debug, Default)]
pub struct RevocationSet {
    mandates: BTreeSet<Hash256>,
    agents: BTreeSet<Did>,
    delegations: BTreeSet<Hash256>,
    log: Vec<Revocation>,
}

impl RevocationSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, target: RevocationTarget, now: Timestamp, reason: String) {
        match &target {
            RevocationTarget::Mandate(h) => {
                self.mandates.insert(*h);
            }
            RevocationTarget::Agent(d) => {
                self.agents.insert(d.clone());
            }
            RevocationTarget::Delegation(h) => {
                self.delegations.insert(*h);
            }
        }
        self.log.push(Revocation {
            target,
            revoked_at: now,
            reason,
        });
    }

    #[must_use]
    pub fn is_mandate_revoked(&self, h: &Hash256) -> bool {
        self.mandates.contains(h)
    }

    #[must_use]
    pub fn is_agent_revoked(&self, d: &Did) -> bool {
        self.agents.contains(d)
    }

    #[must_use]
    pub fn is_delegation_revoked(&self, h: &Hash256) -> bool {
        self.delegations.contains(h)
    }

    #[must_use]
    pub fn log(&self) -> &[Revocation] {
        &self.log
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Rebuild the indexes from a signed append-only revocation log.
    pub fn from_log(log: Vec<Revocation>) -> Result<Self> {
        let mut set = Self::new();
        for revocation in log {
            if revocation.revoked_at == Timestamp::ZERO {
                return Err(PdpError::InvalidMandate(
                    "revocation timestamp must be non-zero".into(),
                ));
            }
            set.revoke(revocation.target, revocation.revoked_at, revocation.reason);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_mandate() {
        let mut s = RevocationSet::new();
        let h = Hash256::digest(b"m");
        s.revoke(
            RevocationTarget::Mandate(h),
            Timestamp::new(1, 0),
            "user cancelled".into(),
        );
        assert!(s.is_mandate_revoked(&h));
        assert!(!s.is_empty());
    }

    #[test]
    fn revoke_agent() {
        let mut s = RevocationSet::new();
        let d = Did::new("did:exo:bot").unwrap();
        s.revoke(
            RevocationTarget::Agent(d.clone()),
            Timestamp::new(1, 0),
            "compromised".into(),
        );
        assert!(s.is_agent_revoked(&d));
    }
}
