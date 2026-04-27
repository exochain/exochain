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

    let overlap_bps = (u64::try_from(present).unwrap_or(0) * 10000)
        / u64::try_from(consensus_claims.len()).unwrap_or(1);

    overlap_bps < threshold_bps
}
