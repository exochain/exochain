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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Round limit exceeded")]
    RoundLimitExceeded,

    #[error("Commitment mismatch for model {model_id}")]
    CommitmentMismatch { model_id: String },

    #[error("Model {model_id} not found in panel")]
    ModelNotFound { model_id: String },

    #[error("LLM Provider error: {0}")]
    ProviderError(String),

    #[error("Invalid panel configuration: {0}")]
    InvalidPanel(String),

    #[error("State error: {0}")]
    StateError(String),

    #[error("Hash serialization failed for {context}: {source}")]
    HashSerialization {
        context: &'static str,
        source: exo_core::error::ExoError,
    },
}

pub type Result<T> = std::result::Result<T, ConsensusError>;
