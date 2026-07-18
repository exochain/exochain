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

//! DebateSession references (IW-4 EvidenceDisciplined) — decision-forum extension point.

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

/// Lightweight reference to a decision-forum DecisionObject.
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

/// Validate a debate reference for Doctrine / ConstitutionalAmendment.
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
