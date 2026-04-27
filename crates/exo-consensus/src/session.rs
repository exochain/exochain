use std::collections::BTreeMap;

use exo_core::types::{Hash256, Timestamp};

use crate::{
    advocate::is_serious_challenge,
    commitment::{commit, verify_commitment},
    error::{ConsensusError, Result},
    panel::{ModelRole, Panel},
    record::DeliberationResult,
    report::{MinorityReport, is_minority_report},
    round::{DeliberationRound, ModelPosition},
    scoring::{PanelConfidenceInputs, calculate_convergence, calculate_panel_confidence},
};

#[derive(Debug, Clone)]
pub struct DeterministicResponseProvider {
    responses: BTreeMap<String, String>,
}

impl DeterministicResponseProvider {
    pub fn new(responses: BTreeMap<String, String>) -> Self {
        Self { responses }
    }

    fn response_for(&self, model_id: &str) -> Result<String> {
        self.responses.get(model_id).cloned().ok_or_else(|| {
            ConsensusError::ProviderError(format!(
                "missing deterministic response for model {model_id}"
            ))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundExecutionTiming {
    pub submitted_at: Timestamp,
    pub revealed_at: Timestamp,
}

impl RoundExecutionTiming {
    fn validate(&self) -> Result<()> {
        if self.submitted_at == Timestamp::ZERO {
            return Err(ConsensusError::StateError(
                "round submitted_at must be caller-supplied non-zero HLC".into(),
            ));
        }
        if self.revealed_at < self.submitted_at {
            return Err(ConsensusError::StateError(
                "round revealed_at must not precede submitted_at".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizationTiming {
    pub completed_at: Timestamp,
}

impl FinalizationTiming {
    fn validate(&self) -> Result<()> {
        if self.completed_at == Timestamp::ZERO {
            return Err(ConsensusError::StateError(
                "finalization completed_at must be caller-supplied non-zero HLC".into(),
            ));
        }
        Ok(())
    }
}

pub struct DeliberationSession {
    pub session_id: String,
    pub panel: Panel,
    pub question: String,
    pub current_round: u32,
    pub rounds: Vec<DeliberationRound>,
    pub response_provider: DeterministicResponseProvider,
}

impl DeliberationSession {
    pub fn new(
        session_id: String,
        panel: Panel,
        question: String,
        response_provider: DeterministicResponseProvider,
    ) -> Self {
        Self {
            session_id,
            panel,
            question,
            current_round: 1,
            rounds: Vec::new(),
            response_provider,
        }
    }

    pub fn execute_round(&mut self, timing: RoundExecutionTiming) -> Result<DeliberationRound> {
        if self.current_round > self.panel.max_rounds {
            return Err(ConsensusError::RoundLimitExceeded);
        }
        timing.validate()?;

        let mut positions = BTreeMap::new();
        let mut raw_texts = Vec::new();

        // 1. Commitment Phase
        let mut commitments = BTreeMap::new();
        for model in &self.panel.models {
            if model.role == ModelRole::Panelist {
                let text = self.response_provider.response_for(&model.model_id)?;
                let position_hash = commit(&text);
                commitments.insert(model.model_id.clone(), (text, position_hash));
            }
        }

        // 2. Reveal & Verify Phase
        for (model_id, (text, position_hash)) in commitments {
            if !verify_commitment(&text, &position_hash) {
                return Err(ConsensusError::CommitmentMismatch { model_id });
            }

            let key_claims: Vec<String> = text
                .split([',', '\n', ';'])
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();

            raw_texts.push(text.clone());

            let pos = ModelPosition {
                model_id: model_id.clone(),
                round: self.current_round,
                position_hash,
                position_text: text,
                key_claims,
                confidence_bps: 8000,
                submitted_at: timing.submitted_at,
                revealed_at: Some(timing.revealed_at),
            };

            positions.insert(model_id, pos);
        }

        // 3. Synthesis
        let synthesis_text = format!("Synthesized consensus from {} models.", positions.len());

        // 4. Scoring
        let texts: Vec<&str> = raw_texts.iter().map(|s| s.as_str()).collect();
        let convergence_score_bps = calculate_convergence(&texts);

        // 5. Devil's Advocate (only if converging well or on final round)
        let mut devil_advocate_challenge = None;
        if convergence_score_bps >= self.panel.convergence_threshold_bps
            || self.current_round == self.panel.max_rounds
        {
            if let Some(da_id) = &self.panel.devil_advocate_model {
                let challenge = self.response_provider.response_for(da_id)?;
                devil_advocate_challenge = Some(challenge);
            }
        }

        let mut round = DeliberationRound {
            round_number: self.current_round,
            question: self.question.clone(),
            positions,
            synthesis: Some(synthesis_text),
            convergence_score_bps,
            devil_advocate_challenge,
            round_hash: Hash256::ZERO,
        };

        round.round_hash = round.compute_hash()?;

        self.rounds.push(round.clone());
        self.current_round += 1;

        Ok(round)
    }

    pub fn is_converged(&self) -> bool {
        if let Some(last) = self.rounds.last() {
            return last.convergence_score_bps >= self.panel.convergence_threshold_bps;
        }
        false
    }

    pub fn finalize(&self, timing: FinalizationTiming) -> Result<DeliberationResult> {
        timing.validate()?;

        if self.rounds.is_empty() {
            return Err(ConsensusError::StateError(
                "Cannot finalize without any rounds".into(),
            ));
        }

        let Some(last_round) = self.rounds.last() else {
            return Err(ConsensusError::StateError(
                "Rounds exist but last() failed".into(),
            ));
        };
        let mut minority_reports = Vec::new();

        // Determine consensus claims to check for minority reports
        let mut consensus_claims = Vec::new();
        for pos in last_round.positions.values() {
            consensus_claims.extend(pos.key_claims.clone());
        }
        // Very rough naive deduplication
        consensus_claims.sort();
        consensus_claims.dedup();

        for pos in last_round.positions.values() {
            if is_minority_report(pos, &consensus_claims, self.panel.convergence_threshold_bps) {
                minority_reports.push(MinorityReport {
                    model_id: pos.model_id.clone(),
                    round: pos.round,
                    dissenting_position: pos.position_text.clone(),
                    reasons: vec!["Diverged from consensus key claims".into()],
                    divergence_score_bps: 10000 - last_round.convergence_score_bps, // proxy
                });
            }
        }

        let mut da_summary = None;
        let mut serious_objection = false;
        if let Some(challenge) = &last_round.devil_advocate_challenge {
            da_summary = Some(challenge.clone());
            serious_objection = is_serious_challenge(challenge);
        }

        let panelists_count = u32::try_from(
            self.panel
                .models
                .iter()
                .filter(|m| m.role == ModelRole::Panelist)
                .count(),
        )
        .unwrap_or(0);

        let inputs = PanelConfidenceInputs {
            models_agreeing: panelists_count
                .saturating_sub(u32::try_from(minority_reports.len()).unwrap_or(0)),
            total_models: panelists_count,
            rounds_to_convergence: u32::try_from(self.rounds.len()).unwrap_or(0),
            max_rounds: self.panel.max_rounds,
            devil_found_serious_objection: serious_objection,
            minority_reports_count: u32::try_from(minority_reports.len()).unwrap_or(0),
        };

        let pci = calculate_panel_confidence(&inputs);

        let mut result = DeliberationResult {
            session_id: self.session_id.clone(),
            question: self.question.clone(),
            rounds: self.rounds.clone(),
            final_consensus: last_round.synthesis.clone().unwrap_or_default(),
            minority_reports,
            panel_confidence_index_bps: pci,
            rounds_to_convergence: u32::try_from(self.rounds.len()).unwrap_or(0),
            devil_advocate_summary: da_summary,
            deliberation_hash: Hash256::ZERO,
            completed_at: timing.completed_at,
        };

        result.deliberation_hash = result.compute_hash()?;

        Ok(result)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use decision_forum::decision_object::DecisionClass;

    use super::*;

    fn routine_responses(response: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("claude-3-haiku".to_string(), response.to_string()),
            ("gpt-4o-mini".to_string(), response.to_string()),
            ("gemini-1.5-flash".to_string(), response.to_string()),
        ])
    }

    fn timing(round: u64) -> RoundExecutionTiming {
        RoundExecutionTiming {
            submitted_at: Timestamp::new(round * 10, 0),
            revealed_at: Timestamp::new(round * 10, 1),
        }
    }

    fn finalization_timing() -> FinalizationTiming {
        FinalizationTiming {
            completed_at: Timestamp::new(1000, 0),
        }
    }

    // Covers line 45: execute_round returns RoundLimitExceeded when current_round > max_rounds.
    #[test]
    fn execute_round_returns_round_limit_exceeded_when_current_round_exceeds_max() {
        let panel = Panel::default_panel(DecisionClass::Routine); // max_rounds = 1
        let provider = DeterministicResponseProvider::new(routine_responses("A, B"));
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        // First round succeeds; second should be rejected because current_round (2) > max_rounds (1).
        let first = session.execute_round(timing(1)).expect("first round ok");
        assert_eq!(first.round_number, 1);
        assert_eq!(session.current_round, 2);
        let err = session
            .execute_round(timing(2))
            .expect_err("must exceed limit");
        assert!(matches!(err, ConsensusError::RoundLimitExceeded));
        // The failed call must not push a round or advance the counter.
        assert_eq!(session.rounds.len(), 1);
        assert_eq!(session.current_round, 2);
    }

    // Covers lines 130-131: is_converged returns false when last round's score is below threshold.
    #[test]
    fn is_converged_false_when_last_round_below_threshold() {
        // Operational panel: threshold 7500, 3 panelists. Distinct responses => convergence 0.
        let panel = Panel::default_panel(DecisionClass::Operational);
        let mut responses = BTreeMap::new();
        responses.insert("claude-3-5-sonnet".into(), "alpha".into());
        responses.insert("gpt-4o".into(), "beta".into());
        responses.insert("gemini-1.5-pro".into(), "gamma".into());
        let provider = DeterministicResponseProvider::new(responses);
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        let round = session.execute_round(timing(1)).unwrap();
        // Zero overlap across three distinct claims => 0 bps, clearly below the 7500 threshold.
        assert_eq!(round.convergence_score_bps, 0);
        assert!(!session.is_converged());
    }

    // Covers is_converged false branch when no rounds have been executed yet.
    #[test]
    fn is_converged_false_when_no_rounds() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let provider = DeterministicResponseProvider::new(BTreeMap::new());
        let session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        assert!(!session.is_converged());
    }

    // Covers lines 136-138: finalize returns StateError when no rounds have been executed.
    #[test]
    fn finalize_errors_with_state_error_when_rounds_empty() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let provider = DeterministicResponseProvider::new(BTreeMap::new());
        let session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        let err = session
            .finalize(finalization_timing())
            .expect_err("must fail when empty");
        match err {
            ConsensusError::StateError(msg) => {
                assert!(
                    msg.contains("Cannot finalize without any rounds"),
                    "unexpected state error message: {msg}"
                );
            }
            other => panic!("expected StateError, got {other:?}"),
        }
    }

    // Covers line 100 true branch: devil's advocate runs on final round even when convergence is low.
    #[test]
    fn devil_advocate_runs_on_final_round_even_without_convergence() {
        // Operational panel: max_rounds = 2, threshold 7500, DA = "gpt-4o".
        let panel = Panel::default_panel(DecisionClass::Operational);
        let mut responses = BTreeMap::new();
        // Distinct responses so convergence < threshold in both rounds.
        responses.insert("claude-3-5-sonnet".into(), "alpha".into());
        responses.insert("gpt-4o".into(), "beta".into());
        responses.insert("gemini-1.5-pro".into(), "gamma".into());
        let provider = DeterministicResponseProvider::new(responses);
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);

        // Round 1: not final, convergence below threshold -> DA does NOT run.
        let r1 = session.execute_round(timing(1)).unwrap();
        assert!(r1.convergence_score_bps < 7500);
        assert!(
            r1.devil_advocate_challenge.is_none(),
            "DA should not run when neither converged nor on the final round"
        );

        // Round 2: final round, still below threshold -> DA MUST run via the line-100 clause.
        let r2 = session.execute_round(timing(2)).unwrap();
        assert_eq!(r2.round_number, 2);
        assert!(r2.convergence_score_bps < 7500);
        assert!(
            r2.devil_advocate_challenge.is_some(),
            "DA must trigger on the final round even without convergence"
        );

        // And finalize must surface that DA summary on the result.
        let result = session.finalize(finalization_timing()).unwrap();
        assert!(result.devil_advocate_summary.is_some());
    }

    // Covers the DA-skipped branch when the panel has no devil_advocate_model configured.
    #[test]
    fn devil_advocate_skipped_when_panel_has_no_da_model_even_on_converged_final_round() {
        // Routine panel: max_rounds = 1 (final), devil_advocate_model = None.
        let panel = Panel::default_panel(DecisionClass::Routine);
        assert!(panel.devil_advocate_model.is_none());
        let provider = DeterministicResponseProvider::new(routine_responses("same claim"));
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        let round = session.execute_round(timing(1)).unwrap();
        // Convergence is 10000 (all identical) and we are at the final round,
        // but devil_advocate_model is None => the inner `if let Some(..)` is false.
        assert_eq!(round.convergence_score_bps, 10000);
        assert!(round.devil_advocate_challenge.is_none());
    }
}
