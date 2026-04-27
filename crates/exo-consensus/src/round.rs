use std::collections::BTreeMap;

use exo_core::{
    hash::hash_structured,
    types::{Hash256, Timestamp},
};
use serde::{Deserialize, Serialize};

use crate::error::{ConsensusError, Result};

/// Structured deterministic response from one panel model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelDeliberationResponse {
    pub position_text: String,
    pub key_claims: Vec<String>,
    pub confidence_bps: u64,
}

/// Structured deterministic devil's advocate review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevilAdvocateReview {
    pub review_text: String,
    pub serious_objection: bool,
    pub reasons: Vec<String>,
}

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
    pub devil_advocate_review: Option<DevilAdvocateReview>,
    pub round_hash: Hash256,
}

impl DeliberationRound {
    /// Hashes the round deterministically.
    pub fn compute_hash(&self) -> Result<Hash256> {
        hash_round(self)
    }
}

pub fn hash_round(round: &DeliberationRound) -> Result<Hash256> {
    #[derive(Serialize)]
    struct HashInput<'a> {
        pub domain: &'static str,
        pub schema_version: &'static str,
        pub round_number: u32,
        pub question: &'a str,
        pub positions: &'a BTreeMap<String, ModelPosition>,
        pub synthesis: &'a Option<String>,
        pub convergence_score_bps: u64,
        pub devil_advocate_review: &'a Option<DevilAdvocateReview>,
    }

    let input = HashInput {
        domain: "exo.consensus.deliberation_round.v1",
        schema_version: "1",
        round_number: round.round_number,
        question: &round.question,
        positions: &round.positions,
        synthesis: &round.synthesis,
        convergence_score_bps: round.convergence_score_bps,
        devil_advocate_review: &round.devil_advocate_review,
    };

    hash_structured(&input).map_err(|source| ConsensusError::HashSerialization {
        context: "deliberation round",
        source,
    })
}
