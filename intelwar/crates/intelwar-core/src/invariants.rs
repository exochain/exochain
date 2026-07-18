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

//! Eight IntelWar invariants — overlays on EXOCHAIN CGR.
//!
//! Spec: `intelwar/docs/INTELWAR_INVARIANTS_v1.md`

use serde::{Deserialize, Serialize};

use crate::error::{IntelwarError, Result};
use crate::log_entry::{EntryKind, LogEntry, VoiceKind};

/// IntelWar invariant identifiers (stable kebab-case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IntelWarInvariant {
    LivingLogIntegrity,
    ConsentBeforeMemory,
    AuthorityBoundAppend,
    MultiIntelligenceTransparent,
    HumanOverrideSacred,
    CrossCheckBeforeCommit,
    DebateBeforeDoctrine,
    ProvenanceCompounding,
}

impl IntelWarInvariant {
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::LivingLogIntegrity => "living-log-integrity",
            Self::ConsentBeforeMemory => "consent-before-memory",
            Self::AuthorityBoundAppend => "authority-bound-append",
            Self::MultiIntelligenceTransparent => "multi-intelligence-transparent",
            Self::HumanOverrideSacred => "human-override-sacred",
            Self::CrossCheckBeforeCommit => "crosscheck-before-commit",
            Self::DebateBeforeDoctrine => "debate-before-doctrine",
            Self::ProvenanceCompounding => "provenance-compounding",
        }
    }

    #[must_use]
    pub fn all() -> [Self; 8] {
        [
            Self::LivingLogIntegrity,
            Self::ConsentBeforeMemory,
            Self::AuthorityBoundAppend,
            Self::MultiIntelligenceTransparent,
            Self::HumanOverrideSacred,
            Self::CrossCheckBeforeCommit,
            Self::DebateBeforeDoctrine,
            Self::ProvenanceCompounding,
        ]
    }
}

/// Context for IntelWar overlay checks after CGR Permitted.
#[derive(Debug, Clone)]
pub struct IntelWarInvariantContext<'a> {
    pub entry: &'a LogEntry,
    pub human_override_preserved: bool,
    pub consent_ok: bool,
    pub authority_ok: bool,
    pub dag_parents_valid: bool,
    pub content_hash_valid: bool,
    pub receipt_will_chain: bool,
    pub crosscheck_satisfied: bool,
    pub debate_satisfied: bool,
}

/// Enforce all eight IntelWar overlays. Fail closed on first logical group.
pub fn enforce_all(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    check_living_log_integrity(ctx)?;
    check_consent_before_memory(ctx)?;
    check_authority_bound_append(ctx)?;
    check_multi_intelligence_transparent(ctx)?;
    check_human_override_sacred(ctx)?;
    check_crosscheck_before_commit(ctx)?;
    check_debate_before_doctrine(ctx)?;
    check_provenance_compounding(ctx)?;
    Ok(())
}

fn deny(invariant: IntelWarInvariant, description: impl Into<String>) -> IntelwarError {
    IntelwarError::IntelwarInvariant {
        invariant: invariant.id().into(),
        description: description.into(),
    }
}

fn check_living_log_integrity(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.content_hash_valid {
        return Err(deny(
            IntelWarInvariant::LivingLogIntegrity,
            "content_hash does not match canonical CBOR body",
        ));
    }
    if !ctx.dag_parents_valid {
        return Err(deny(
            IntelWarInvariant::LivingLogIntegrity,
            "parent_hashes are not valid for append (missing parent or illegal empty parents)",
        ));
    }
    Ok(())
}

fn check_consent_before_memory(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.consent_ok {
        return Err(deny(
            IntelWarInvariant::ConsentBeforeMemory,
            "active bailment consent covering log:append is required",
        ));
    }
    if ctx.entry.consent_scope.trim().is_empty() {
        return Err(deny(
            IntelWarInvariant::ConsentBeforeMemory,
            "consent_scope must be non-empty on LogEntry",
        ));
    }
    Ok(())
}

fn check_authority_bound_append(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.authority_ok {
        return Err(deny(
            IntelWarInvariant::AuthorityBoundAppend,
            "verified authority chain terminating at actor with log:append is required",
        ));
    }
    Ok(())
}

fn check_multi_intelligence_transparent(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    match ctx.entry.voice_kind {
        VoiceKind::Human => {
            if ctx.entry.independence.is_none() || ctx.entry.review_order.is_none() {
                return Err(deny(
                    IntelWarInvariant::MultiIntelligenceTransparent,
                    "human voice requires independence and review_order",
                ));
            }
        }
        VoiceKind::Synthetic => {
            if ctx.entry.agent_attestation.is_none() {
                return Err(deny(
                    IntelWarInvariant::MultiIntelligenceTransparent,
                    "synthetic voice requires agent_attestation",
                ));
            }
        }
        VoiceKind::System => {}
    }
    Ok(())
}

fn check_human_override_sacred(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.human_override_preserved {
        return Err(deny(
            IntelWarInvariant::HumanOverrideSacred,
            "human_override_preserved must remain true",
        ));
    }
    Ok(())
}

fn check_crosscheck_before_commit(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if ctx.entry.requires_crosscheck && !ctx.crosscheck_satisfied {
        return Err(deny(
            IntelWarInvariant::CrossCheckBeforeCommit,
            "requires_crosscheck=true but no valid distinct-intelligence CrossCheckResult",
        ));
    }
    Ok(())
}

fn check_debate_before_doctrine(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    let needs_debate = matches!(
        ctx.entry.entry_kind,
        EntryKind::Doctrine | EntryKind::ConstitutionalAmendment
    );
    if needs_debate && !ctx.debate_satisfied {
        return Err(deny(
            IntelWarInvariant::DebateBeforeDoctrine,
            "Doctrine/ConstitutionalAmendment requires approved DebateSession reference",
        ));
    }
    Ok(())
}

fn check_provenance_compounding(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.receipt_will_chain {
        return Err(deny(
            IntelWarInvariant::ProvenanceCompounding,
            "append must mint a chaining LivingLogReceipt",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariant_ids_are_stable_kebab() {
        let ids: Vec<_> = IntelWarInvariant::all().iter().map(|i| i.id()).collect();
        assert_eq!(
            ids,
            vec![
                "living-log-integrity",
                "consent-before-memory",
                "authority-bound-append",
                "multi-intelligence-transparent",
                "human-override-sacred",
                "crosscheck-before-commit",
                "debate-before-doctrine",
                "provenance-compounding",
            ]
        );
    }
}
