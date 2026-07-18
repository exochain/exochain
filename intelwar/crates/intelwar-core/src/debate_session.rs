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

//! DebateSession ↔ decision-forum DecisionObject (IW-4 EvidenceDisciplined, PM-003).
//!
//! Doctrine / ConstitutionalAmendment Living Log appends must bind to a real
//! [`DecisionObject`] in an approved BCTS terminal state. Bare
//! [`DebateSession`] claims without a DecisionObject fail closed on those
//! entry kinds. Strategic/Constitutional classes also require the forum
//! human gate with externally verified human voter DIDs.

use std::collections::BTreeSet;

use decision_forum::{
    decision_object::{DecisionClass, DecisionObject},
    human_gate::{
        HumanGatePolicy, enforce_human_gate_with_verified_humans, requires_human_approval,
    },
};
use exo_core::{Did, bcts::BctsState};
use serde::{Deserialize, Serialize};

use crate::error::{IntelwarError, Result};

/// Terminal states accepted for doctrine / amendment append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebateTerminalState {
    Approved,
    Recorded,
    Closed,
}

/// Lightweight Living Log reference to a decision-forum DecisionObject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebateSession {
    /// Decision-forum decision id (UUID string).
    pub decision_id: String,
    pub state: DebateTerminalState,
    pub summary: String,
}

/// Return true when debate is in an accepted terminal state.
#[must_use]
pub fn debate_is_approved(session: &DebateSession) -> bool {
    matches!(
        session.state,
        DebateTerminalState::Approved
            | DebateTerminalState::Recorded
            | DebateTerminalState::Closed
    )
}

/// Map BCTS states that authorize doctrine evidence onto DebateTerminalState.
pub fn terminal_state_from_bcts(state: BctsState) -> Result<DebateTerminalState> {
    match state {
        BctsState::Approved | BctsState::Executed => Ok(DebateTerminalState::Approved),
        BctsState::Recorded => Ok(DebateTerminalState::Recorded),
        BctsState::Closed => Ok(DebateTerminalState::Closed),
        other => Err(IntelwarError::Debate {
            reason: format!(
                "decision BCTS state {other} is not an approved terminal for Living Log doctrine evidence"
            ),
        }),
    }
}

/// Derive a DebateSession from a decision-forum DecisionObject (fail closed).
pub fn debate_session_from_decision(decision: &DecisionObject) -> Result<DebateSession> {
    let state = terminal_state_from_bcts(decision.state)?;
    if decision.title.trim().is_empty() {
        return Err(IntelwarError::Debate {
            reason: "decision title must be non-empty".into(),
        });
    }
    Ok(DebateSession {
        decision_id: decision.id.to_string(),
        state,
        summary: decision.title.clone(),
    })
}

/// Ensure a claimed session matches the DecisionObject source of truth.
pub fn verify_debate_against_decision(
    session: &DebateSession,
    decision: &DecisionObject,
) -> Result<()> {
    let derived = debate_session_from_decision(decision)?;
    if session.decision_id != derived.decision_id {
        return Err(IntelwarError::Debate {
            reason: format!(
                "debate decision_id {} does not match DecisionObject {}",
                session.decision_id, derived.decision_id
            ),
        });
    }
    if session.state != derived.state {
        return Err(IntelwarError::Debate {
            reason: format!(
                "debate state {:?} does not match DecisionObject BCTS-derived {:?}",
                session.state, derived.state
            ),
        });
    }
    Ok(())
}

/// Validate a debate reference for Doctrine / ConstitutionalAmendment.
///
/// Prefer [`require_decision_forum_debate`] when a DecisionObject is available.
pub fn require_approved_debate(session: Option<&DebateSession>) -> Result<()> {
    let Some(session) = session else {
        return Err(IntelwarError::Debate {
            reason: "missing DebateSession reference".into(),
        });
    };
    if session.decision_id.trim().is_empty() {
        return Err(IntelwarError::Debate {
            reason: "debate decision_id must be non-empty".into(),
        });
    }
    if !debate_is_approved(session) {
        return Err(IntelwarError::Debate {
            reason: format!(
                "debate {} is not in an approved terminal state",
                session.decision_id
            ),
        });
    }
    Ok(())
}

/// Verify DecisionObject evidence for doctrine / amendment (PM-003).
///
/// - Decision must be in Approved / Executed / Recorded / Closed.
/// - Optional claimed [`DebateSession`] must match the DecisionObject.
/// - Strategic / Constitutional classes require human-gate with verified humans.
/// - ConstitutionalAmendment entries require `DecisionClass::Constitutional`.
pub fn require_decision_forum_debate(
    decision: &DecisionObject,
    claimed: Option<&DebateSession>,
    verified_human_voters: &BTreeSet<Did>,
    require_constitutional_class: bool,
) -> Result<DebateSession> {
    if require_constitutional_class && decision.class != DecisionClass::Constitutional {
        return Err(IntelwarError::Debate {
            reason: format!(
                "ConstitutionalAmendment requires DecisionClass::Constitutional, got {}",
                decision.class.quorum_policy_key()
            ),
        });
    }

    let session = debate_session_from_decision(decision)?;
    if let Some(claimed) = claimed {
        verify_debate_against_decision(claimed, decision)?;
    }
    require_approved_debate(Some(&session))?;

    let policy = HumanGatePolicy::default();
    if requires_human_approval(&policy, decision.class) {
        enforce_human_gate_with_verified_humans(&policy, decision, verified_human_voters).map_err(
            |e| IntelwarError::Debate {
                reason: format!("decision-forum human gate failed: {e}"),
            },
        )?;
    }

    Ok(session)
}

#[cfg(test)]
mod tests {
    use decision_forum::decision_object::{DecisionClass, DecisionObject, DecisionObjectInput};
    use exo_core::{Hash256, Timestamp, bcts::BctsState};
    use uuid::Uuid;

    use super::*;

    fn draft_decision() -> DecisionObject {
        DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(7),
            title: "Draft doctrine debate".into(),
            class: DecisionClass::Strategic,
            constitutional_hash: Hash256::digest(b"iw-const"),
            created_at: Timestamp::new(1_000, 0),
        })
        .expect("decision")
    }

    #[test]
    fn draft_decision_is_not_doctrine_evidence() {
        let d = draft_decision();
        let err = debate_session_from_decision(&d).expect_err("draft must fail");
        assert!(err.to_string().contains("not an approved terminal"));
    }

    #[test]
    fn terminal_mapping_covers_approved_family() {
        assert_eq!(
            terminal_state_from_bcts(BctsState::Approved).unwrap(),
            DebateTerminalState::Approved
        );
        assert_eq!(
            terminal_state_from_bcts(BctsState::Executed).unwrap(),
            DebateTerminalState::Approved
        );
        assert_eq!(
            terminal_state_from_bcts(BctsState::Recorded).unwrap(),
            DebateTerminalState::Recorded
        );
        assert_eq!(
            terminal_state_from_bcts(BctsState::Closed).unwrap(),
            DebateTerminalState::Closed
        );
    }
}
