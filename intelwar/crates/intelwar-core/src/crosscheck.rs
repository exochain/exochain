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

//! CrossCheckResult types (IW-6) — .ai extension point.

use exo_core::{Did, Hash256};
use serde::{Deserialize, Serialize};

use crate::error::{IntelwarError, Result};
use crate::log_entry::VoiceKind;

/// Cross-check verdict from a distinct intelligence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossCheckVerdict {
    Agree,
    Disagree,
    Abstain,
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

/// Validate that crosschecks satisfy IW-6 for a subject authored by `author`.
pub fn crosschecks_satisfy(
    author: &Did,
    subject_hash: &Hash256,
    results: &[CrossCheckResult],
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
        if result.signature.is_empty() {
            return Err(IntelwarError::Crosscheck {
                reason: format!("empty signature at index {idx}"),
            });
        }
    }
    Ok(())
}
