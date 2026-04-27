use serde::{Deserialize, Serialize};

use crate::round::ModelPosition;

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
    _consensus_claims: &[String],
    threshold_bps: u64,
) -> bool {
    // A simplistic implementation: if convergence is poor, trigger report.
    // Real implementation would calculate overlap of position claims vs consensus claims.
    // For test purposes, let's say if the mock text implies low overlap, return true.
    // Since we don't have full LLM synthesis here, let's just use the threshold.
    // For now we'll mock this by checking if the confidence_bps is below threshold
    // or if divergence is somehow known. Let's return false by default unless
    // specifically triggered. Wait, let's calculate divergence based on key claims.

    // Divergence score: how many consensus claims are MISSING from the model's claims.
    // If consensus has 0 claims, no divergence.
    if _consensus_claims.is_empty() {
        return false;
    }

    let mut missing = 0;
    for c in _consensus_claims {
        if !position.key_claims.contains(c) {
            missing += 1;
        }
    }

    let overlap_bps = (u64::try_from(_consensus_claims.len() - missing).unwrap_or(0) * 10000)
        / u64::try_from(_consensus_claims.len()).unwrap_or(1);

    // Dissenting if overlap is less than threshold
    overlap_bps < threshold_bps
}
