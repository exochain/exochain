use std::collections::BTreeMap;

use exo_core::types::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};

/// A single position submitted by a model in a round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPosition {
    pub model_id: String,
    pub round: u32,
    pub position_hash: Hash256,
    pub position_text: String,
    pub key_claims: Vec<String>,
    pub confidence_bps: u64,
    pub submitted_at: Timestamp,
    pub revealed_at: Option<Timestamp>,
}

/// A complete round of deliberation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliberationRound {
    pub round_number: u32,
    pub question: String,
    pub positions: BTreeMap<String, ModelPosition>,
    pub synthesis: Option<String>,
    pub convergence_score_bps: u64,
    pub devil_advocate_challenge: Option<String>,
    pub round_hash: Hash256,
}

impl DeliberationRound {
    /// Hashes the round deterministically.
    pub fn compute_hash(&self) -> Hash256 {
        hash_round(self)
    }
}

pub fn hash_round(round: &DeliberationRound) -> Hash256 {
    #[derive(Serialize)]
    struct HashInput<'a> {
        pub round_number: u32,
        pub question: &'a str,
        pub positions: &'a BTreeMap<String, ModelPosition>,
        pub synthesis: &'a Option<String>,
        pub convergence_score_bps: u64,
        pub devil_advocate_challenge: &'a Option<String>,
    }

    let input = HashInput {
        round_number: round.round_number,
        question: &round.question,
        positions: &round.positions,
        synthesis: &round.synthesis,
        convergence_score_bps: round.convergence_score_bps,
        devil_advocate_challenge: &round.devil_advocate_challenge,
    };

    // In production we'd use `hash_structured` from `exo_core::hash`. For now JSON:
    let json = serde_json::to_string(&input).unwrap_or_default();
    Hash256::digest(json.as_bytes())
}
