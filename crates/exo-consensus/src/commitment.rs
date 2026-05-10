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

use exo_core::{hash::hash_structured, types::Hash256};
use serde::Serialize;

use crate::{
    error::{ConsensusError, Result},
    round::ModelDeliberationResponse,
};

/// Cryptographically commits to a position before revealing it.
/// Uses BLAKE3 under the hood.
pub fn commit(position_text: &str) -> Hash256 {
    Hash256::digest(position_text.as_bytes())
}

/// Verifies that a revealed position matches its prior commitment.
pub fn verify_commitment(position_text: &str, commitment: &Hash256) -> bool {
    commit(position_text) == *commitment
}

/// Cryptographically commits to the structured response evidence before reveal.
pub fn commit_response(response: &ModelDeliberationResponse) -> Result<Hash256> {
    #[derive(Serialize)]
    struct CommitmentPayload<'a> {
        domain: &'static str,
        schema_version: &'static str,
        position_text: &'a str,
        key_claims: &'a [String],
        confidence_bps: u64,
    }

    let payload = CommitmentPayload {
        domain: "exo.consensus.model_response.commitment.v1",
        schema_version: "1",
        position_text: &response.position_text,
        key_claims: &response.key_claims,
        confidence_bps: response.confidence_bps,
    };

    hash_structured(&payload).map_err(|source| ConsensusError::HashSerialization {
        context: "structured consensus model response commitment",
        source,
    })
}

/// Verifies that revealed structured response evidence matches its commitment.
pub fn verify_response_commitment(
    response: &ModelDeliberationResponse,
    commitment: &Hash256,
) -> Result<bool> {
    Ok(commit_response(response)? == *commitment)
}
