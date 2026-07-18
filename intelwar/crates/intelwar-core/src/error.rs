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

//! Typed errors for the IntelWar Living Log adapter.

use thiserror::Error;

/// Errors produced by IntelWar core Living Log operations.
#[derive(Debug, Error)]
pub enum IntelwarError {
    #[error("canonical CBOR serialization failed: {reason}")]
    Serialization { reason: String },

    #[error("content hash mismatch: expected {expected}, computed {computed}")]
    ContentHashMismatch { expected: String, computed: String },

    #[error("CGR kernel denied append: {summary}")]
    KernelDenied { summary: String },

    #[error("IntelWar invariant violated: {invariant}: {description}")]
    IntelwarInvariant {
        invariant: String,
        description: String,
    },

    #[error("consent gate failed: {reason}")]
    Consent { reason: String },

    #[error("authority check failed: {reason}")]
    Authority { reason: String },

    #[error("crosscheck required but missing or invalid: {reason}")]
    Crosscheck { reason: String },

    #[error("debate session required but missing or not approved: {reason}")]
    Debate { reason: String },

    #[error("DAG append failed: {reason}")]
    Dag { reason: String },

    #[error("provenance construction failed: {reason}")]
    Provenance { reason: String },

    #[error("validation error: {reason}")]
    Validation { reason: String },

    #[error("EXOCHAIN core error: {0}")]
    Core(#[from] exo_core::ExoError),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, IntelwarError>;
