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

use serde::{Deserialize, Serialize};

use crate::{round::ModelPosition, scoring::canonical_claim_set};

/// A minority report from a dissenting model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinorityReport {
    pub model_id: String,
    pub round: u32,
    pub dissenting_position: String,
    pub reasons: Vec<String>,
    pub divergence_score_bps: u64,
}

pub fn is_minority_report(
    position: &ModelPosition,
    consensus_claims: &[String],
    threshold_bps: u64,
) -> bool {
    let consensus_claims = canonical_claim_set(consensus_claims);
    if consensus_claims.is_empty() {
        return false;
    }

    let position_claims = canonical_claim_set(&position.key_claims);
    let present = consensus_claims
        .iter()
        .filter(|claim| position_claims.contains(claim))
        .count();

    let overlap_bps = overlap_bps_from_counts(present, consensus_claims.len());

    overlap_bps < threshold_bps
}

fn overlap_bps_from_counts(present: usize, total: usize) -> u64 {
    if total == 0 {
        return 0;
    }

    let numerator = u128::try_from(present)
        .unwrap_or(u128::MAX)
        .saturating_mul(10_000);
    let denominator = u128::try_from(total).unwrap_or(u128::MAX);
    let bps = numerator / denominator;
    u64::try_from(bps.min(10_000)).unwrap_or(10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_bps_from_counts_handles_pathological_lengths_without_overflow() {
        assert_eq!(overlap_bps_from_counts(2, 4), 5_000);
        assert_eq!(overlap_bps_from_counts(usize::MAX, usize::MAX), 10_000);
        assert_eq!(overlap_bps_from_counts(usize::MAX, 1), 10_000);
    }
}
