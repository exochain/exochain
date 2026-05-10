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

//! Escalation error types.

use thiserror::Error;

/// Errors that can occur during escalation case management.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EscalationError {
    #[error("case not found: {0}")]
    CaseNotFound(String),

    #[error("invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("incomplete case: {reason}")]
    IncompleteCase { reason: String },

    #[error("invalid signal: {0}")]
    InvalidSignal(String),

    #[error("invalid provenance: {reason}")]
    InvalidProvenance { reason: String },

    #[error("invalid signature from {signer}: {reason}")]
    InvalidSignature { signer: String, reason: String },

    #[error("serialization failed for {context}: {reason}")]
    SerializationFailed { context: String, reason: String },

    #[error("column not found: {0}")]
    ColumnNotFound(String),
}
