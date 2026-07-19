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

//! # intelwar-core
//!
//! Living Log adapter for IntelWar on EXOCHAIN v0.2.3.
//!
//! Append path: consent → authority → CGR Kernel → IntelWar overlays →
//! provenance receipt → `exo_dag::append`.
//!
//! Normative docs:
//! - `intelwar/INTELWAR_CONSTITUTION.md`
//! - `intelwar/docs/INTELWAR_INVARIANTS_v1.md`
//! - `intelwar/docs/LIVING_LOG_DATA_MODEL.md`

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod append_flow;
pub mod bridge;
pub mod consent_flow;
pub mod crosscheck;
pub mod debate_session;
pub mod error;
pub mod invariants;
pub mod log_entry;

pub use append_flow::{
    AppendReceipt, AppendRequest, INTELWAR_CONSTITUTION_BYTES, append_log_entry,
    default_invariant_id_lists, development_decision_body, intelwar_kernel, judicial_role,
    signed_authority_link,
};
pub use bridge::{
    BridgeAppendRequest, BridgeAppendResponse, BridgeConsentWire, bridge_append, load_log_mirror,
};
pub use consent_flow::{LOG_APPEND_PERMISSION, consent_allows_log_append};
pub use crosscheck::{
    CROSSCHECK_DOMAIN, CrossCheckResult, CrossCheckVerdict, crosscheck_signing_hash,
    crosschecks_satisfy, sign_crosscheck, verify_crosscheck_signature,
};
pub use debate_session::{
    DebateSession, DebateTerminalState, debate_session_from_decision, require_approved_debate,
    require_decision_forum_debate, terminal_state_from_bcts, verify_debate_against_decision,
};
pub use error::{IntelwarError, Result};
pub use invariants::{IntelWarInvariant, IntelWarInvariantContext, enforce_all};
pub use log_entry::{
    AgentAttestation, ENTRY_DOMAIN, EntryKind, IndependenceClaim, LivingLogReceipt, LogEntry,
    LogEntryBody, RECEIPT_DOMAIN, ReviewOrder, VoiceKind,
};
