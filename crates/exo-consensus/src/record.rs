use exo_core::{
    hash::hash_structured,
    types::{Hash256, Timestamp},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ConsensusError, Result},
    report::MinorityReport,
    round::DeliberationRound,
};

/// The final result of a deliberation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliberationResult {
    pub session_id: String,
    pub question: String,
    pub rounds: Vec<DeliberationRound>,
    pub final_consensus: String,
    pub minority_reports: Vec<MinorityReport>,
    pub panel_confidence_index_bps: u64,
    pub rounds_to_convergence: u32,
    pub devil_advocate_summary: Option<String>,
    pub deliberation_hash: Hash256,
    pub completed_at: Timestamp,
}

impl DeliberationResult {
    pub fn compute_hash(&self) -> Result<Hash256> {
        hash_result(self)
    }
}

pub fn hash_result(result: &DeliberationResult) -> Result<Hash256> {
    #[derive(Serialize)]
    struct HashInput<'a> {
        pub domain: &'static str,
        pub schema_version: &'static str,
        pub session_id: &'a str,
        pub question: &'a str,
        pub rounds: &'a [DeliberationRound],
        pub final_consensus: &'a str,
        pub minority_reports: &'a [MinorityReport],
        pub panel_confidence_index_bps: u64,
        pub rounds_to_convergence: u32,
        pub devil_advocate_summary: &'a Option<String>,
        pub completed_at: Timestamp,
    }

    let input = HashInput {
        domain: "exo.consensus.deliberation_result.v1",
        schema_version: "1",
        session_id: &result.session_id,
        question: &result.question,
        rounds: &result.rounds,
        final_consensus: &result.final_consensus,
        minority_reports: &result.minority_reports,
        panel_confidence_index_bps: result.panel_confidence_index_bps,
        rounds_to_convergence: result.rounds_to_convergence,
        devil_advocate_summary: &result.devil_advocate_summary,
        completed_at: result.completed_at,
    };

    hash_structured(&input).map_err(|source| ConsensusError::HashSerialization {
        context: "deliberation result",
        source,
    })
}
