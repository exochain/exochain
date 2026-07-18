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
//! Spec: `intelwar/docs/INTELWAR_INVARIANTS_v1.md` (adopted dec9ddc8).

use serde::{Deserialize, Serialize};

use crate::error::{IntelwarError, Result};
use crate::log_entry::{EntryKind, LogEntry, VoiceKind};

/// IntelWar invariant identifiers (stable kebab-case wire ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IntelWarInvariant {
    /// IW-1
    ConsentRequired,
    /// IW-2
    ProvenanceVerifiable,
    /// IW-3
    MultiIntelligenceTransparent,
    /// IW-4
    EvidenceDisciplined,
    /// IW-5
    HumanOverridePriority,
    /// IW-6
    FailClosedEnforcement,
    /// IW-7
    StrategicUtility,
    /// IW-8
    LogIntegrity,
}

impl IntelWarInvariant {
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::ConsentRequired => "consent-required",
            Self::ProvenanceVerifiable => "provenance-verifiable",
            Self::MultiIntelligenceTransparent => "multi-intelligence-transparent",
            Self::EvidenceDisciplined => "evidence-disciplined",
            Self::HumanOverridePriority => "human-override-priority",
            Self::FailClosedEnforcement => "fail-closed-enforcement",
            Self::StrategicUtility => "strategic-utility",
            Self::LogIntegrity => "log-integrity",
        }
    }

    #[must_use]
    pub fn all() -> [Self; 8] {
        [
            Self::ConsentRequired,
            Self::ProvenanceVerifiable,
            Self::MultiIntelligenceTransparent,
            Self::EvidenceDisciplined,
            Self::HumanOverridePriority,
            Self::FailClosedEnforcement,
            Self::StrategicUtility,
            Self::LogIntegrity,
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

/// Enforce all eight IntelWar overlays. Fail closed (IW-6).
pub fn enforce_all(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    check_consent_required(ctx)?;
    check_provenance_verifiable(ctx)?;
    check_multi_intelligence_transparent(ctx)?;
    check_evidence_disciplined(ctx)?;
    check_human_override_priority(ctx)?;
    check_fail_closed_enforcement(ctx)?;
    check_strategic_utility(ctx)?;
    check_log_integrity(ctx)?;
    Ok(())
}

fn deny(invariant: IntelWarInvariant, description: impl Into<String>) -> IntelwarError {
    IntelwarError::IntelwarInvariant {
        invariant: invariant.id().into(),
        description: description.into(),
    }
}

fn check_consent_required(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.consent_ok {
        return Err(deny(
            IntelWarInvariant::ConsentRequired,
            "active bailment consent covering log:append is required before Log append",
        ));
    }
    if ctx.entry.consent_scope.trim().is_empty() {
        return Err(deny(
            IntelWarInvariant::ConsentRequired,
            "consent_scope must be non-empty on LogEntry",
        ));
    }
    Ok(())
}

fn check_provenance_verifiable(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.content_hash_valid {
        return Err(deny(
            IntelWarInvariant::ProvenanceVerifiable,
            "content_hash does not match canonical CBOR body",
        ));
    }
    if !ctx.receipt_will_chain {
        return Err(deny(
            IntelWarInvariant::ProvenanceVerifiable,
            "append must mint a chaining LivingLogReceipt (previous entry / receipt pointer)",
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
                    "human voice requires independence and review_order disclosure",
                ));
            }
        }
        VoiceKind::Synthetic => {
            if ctx.entry.agent_attestation.is_none() {
                return Err(deny(
                    IntelWarInvariant::MultiIntelligenceTransparent,
                    "synthetic voice requires agent_attestation (AVC or equivalent)",
                ));
            }
        }
        VoiceKind::System => {}
    }
    Ok(())
}

fn check_evidence_disciplined(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    // Bare assertion: empty payload + empty summary already fails StrategicUtility;
    // permanent-record kinds need evidence linkage (crosscheck and/or debate).
    if ctx.entry.requires_crosscheck && !ctx.crosscheck_satisfied {
        return Err(deny(
            IntelWarInvariant::EvidenceDisciplined,
            "requires_crosscheck=true but no valid distinct-intelligence CrossCheckResult",
        ));
    }
    let needs_debate = matches!(
        ctx.entry.entry_kind,
        EntryKind::Doctrine | EntryKind::ConstitutionalAmendment
    );
    if needs_debate && !ctx.debate_satisfied {
        return Err(deny(
            IntelWarInvariant::EvidenceDisciplined,
            "Doctrine/ConstitutionalAmendment requires approved DebateSession evidence link",
        ));
    }
    if matches!(
        ctx.entry.entry_kind,
        EntryKind::Analysis | EntryKind::Observation | EntryKind::DebateNote
    ) && ctx.entry.payload.is_empty()
        && ctx.entry.summary.trim().len() < 8
    {
        return Err(deny(
            IntelWarInvariant::EvidenceDisciplined,
            "bare assertion inadmissible: provide payload evidence or a substantive summary",
        ));
    }
    Ok(())
}

fn check_human_override_priority(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.human_override_preserved {
        return Err(deny(
            IntelWarInvariant::HumanOverridePriority,
            "human_override_preserved must remain true; machine paths must not disable override",
        ));
    }
    Ok(())
}

fn check_fail_closed_enforcement(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.authority_ok {
        return Err(deny(
            IntelWarInvariant::FailClosedEnforcement,
            "unauthorized authority path — action rejected with no privileged bypass",
        ));
    }
    if !ctx.consent_ok {
        return Err(deny(
            IntelWarInvariant::FailClosedEnforcement,
            "missing consent — action rejected with no privileged bypass",
        ));
    }
    Ok(())
}

fn check_strategic_utility(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if ctx.entry.summary.trim().is_empty() {
        return Err(deny(
            IntelWarInvariant::StrategicUtility,
            "Log contributions must carry a non-empty summary of strategic utility",
        ));
    }
    Ok(())
}

fn check_log_integrity(ctx: &IntelWarInvariantContext<'_>) -> Result<()> {
    if !ctx.content_hash_valid {
        return Err(deny(
            IntelWarInvariant::LogIntegrity,
            "content_hash does not match canonical CBOR body",
        ));
    }
    if !ctx.dag_parents_valid {
        return Err(deny(
            IntelWarInvariant::LogIntegrity,
            "parent_hashes are not valid for append (missing parent or illegal empty parents)",
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
                "consent-required",
                "provenance-verifiable",
                "multi-intelligence-transparent",
                "evidence-disciplined",
                "human-override-priority",
                "fail-closed-enforcement",
                "strategic-utility",
                "log-integrity",
            ]
        );
    }
}
