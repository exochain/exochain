use std::collections::BTreeMap;

use exo_core::types::{Hash256, Timestamp};

use crate::{
    commitment::{commit_response, verify_response_commitment},
    error::{ConsensusError, Result},
    panel::{ModelRole, Panel},
    record::DeliberationResult,
    report::{MinorityReport, is_minority_report},
    round::{DeliberationRound, DevilAdvocateReview, ModelDeliberationResponse, ModelPosition},
    scoring::{
        PanelConfidenceInputs, calculate_convergence, calculate_panel_confidence,
        canonical_claim_set, consensus_claims_at_threshold,
    },
};

#[derive(Debug, Clone)]
pub struct DeterministicResponseProvider {
    positions: BTreeMap<String, ModelDeliberationResponse>,
    devil_advocate_reviews: BTreeMap<String, DevilAdvocateReview>,
}

impl DeterministicResponseProvider {
    pub fn new(
        positions: BTreeMap<String, ModelDeliberationResponse>,
        devil_advocate_reviews: BTreeMap<String, DevilAdvocateReview>,
    ) -> Self {
        Self {
            positions,
            devil_advocate_reviews,
        }
    }

    pub fn with_positions(positions: BTreeMap<String, ModelDeliberationResponse>) -> Self {
        Self::new(positions, BTreeMap::new())
    }

    fn position_for(&self, model_id: &str) -> Result<ModelDeliberationResponse> {
        self.positions.get(model_id).cloned().ok_or_else(|| {
            ConsensusError::ProviderError(format!(
                "missing structured deterministic response for model {model_id}"
            ))
        })
    }

    fn devil_advocate_review_for(&self, model_id: &str) -> Result<DevilAdvocateReview> {
        self.devil_advocate_reviews
            .get(model_id)
            .cloned()
            .ok_or_else(|| {
                ConsensusError::ProviderError(format!(
                    "missing structured devil's advocate review for model {model_id}"
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

        // 1. Commitment Phase
        let mut commitments = BTreeMap::new();
        for model in &self.panel.models {
            if model.role == ModelRole::Panelist {
                let response = self.response_provider.position_for(&model.model_id)?;
                let response = validate_model_response(&model.model_id, response)?;
                let position_hash = commit_response(&response)?;
                commitments.insert(model.model_id.clone(), (response, position_hash));
            }
        }

        // 2. Reveal & Verify Phase
        for (model_id, (response, position_hash)) in commitments {
            if !verify_response_commitment(&response, &position_hash)? {
                return Err(ConsensusError::CommitmentMismatch { model_id });
            }

            let pos = ModelPosition {
                model_id: model_id.clone(),
                round: self.current_round,
                position_hash,
                position_text: response.position_text,
                key_claims: response.key_claims,
                confidence_bps: response.confidence_bps,
                submitted_at: timing.submitted_at,
                revealed_at: Some(timing.revealed_at),
            };

            positions.insert(model_id, pos);
        }

        // 3. Scoring
        let claim_sets = position_claim_sets(&positions);
        let convergence_score_bps = calculate_convergence(&claim_sets);
        let consensus_claims =
            consensus_claims_at_threshold(&claim_sets, self.panel.convergence_threshold_bps);

        // 4. Synthesis
        let synthesis_text = consensus_summary(&consensus_claims);

        // 5. Devil's Advocate (only if converging well or on final round)
        let mut devil_advocate_review = None;
        if convergence_score_bps >= self.panel.convergence_threshold_bps
            || self.current_round == self.panel.max_rounds
        {
            if let Some(da_id) = &self.panel.devil_advocate_model {
                let review = self.response_provider.devil_advocate_review_for(da_id)?;
                devil_advocate_review = Some(validate_devil_advocate_review(da_id, review)?);
            }
        }

        let mut round = DeliberationRound {
            round_number: self.current_round,
            question: self.question.clone(),
            positions,
            synthesis: Some(synthesis_text),
            convergence_score_bps,
            devil_advocate_review,
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

        let claim_sets = position_claim_sets(&last_round.positions);
        let consensus_claims =
            consensus_claims_at_threshold(&claim_sets, self.panel.convergence_threshold_bps);

        for pos in last_round.positions.values() {
            if is_minority_report(pos, &consensus_claims, self.panel.convergence_threshold_bps) {
                let missing_claims = missing_consensus_claims(pos, &consensus_claims);
                minority_reports.push(MinorityReport {
                    model_id: pos.model_id.clone(),
                    round: pos.round,
                    dissenting_position: pos.position_text.clone(),
                    reasons: vec![format!(
                        "Missing structured consensus claims: {}",
                        missing_claims.join(", ")
                    )],
                    divergence_score_bps: 10000 - last_round.convergence_score_bps,
                });
            }
        }

        let mut da_summary = None;
        let mut serious_objection = false;
        if let Some(review) = &last_round.devil_advocate_review {
            da_summary = Some(review.review_text.clone());
            serious_objection = review.serious_objection;
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

fn validate_model_response(
    model_id: &str,
    response: ModelDeliberationResponse,
) -> Result<ModelDeliberationResponse> {
    let position_text = response.position_text.trim().to_string();
    if position_text.is_empty() {
        return Err(ConsensusError::ProviderError(format!(
            "structured deterministic response for model {model_id} has empty position_text"
        )));
    }
    if response.confidence_bps > 10000 {
        return Err(ConsensusError::ProviderError(format!(
            "structured deterministic response for model {model_id} has confidence_bps above 10000"
        )));
    }
    let key_claims = canonical_claim_set(&response.key_claims);
    if key_claims.is_empty() {
        return Err(ConsensusError::ProviderError(format!(
            "structured deterministic response for model {model_id} must include explicit key_claims"
        )));
    }

    Ok(ModelDeliberationResponse {
        position_text,
        key_claims,
        confidence_bps: response.confidence_bps,
    })
}

fn validate_devil_advocate_review(
    model_id: &str,
    review: DevilAdvocateReview,
) -> Result<DevilAdvocateReview> {
    let review_text = review.review_text.trim().to_string();
    if review_text.is_empty() {
        return Err(ConsensusError::ProviderError(format!(
            "structured devil's advocate review for model {model_id} has empty review_text"
        )));
    }

    let reasons = canonical_claim_set(&review.reasons);
    if review.serious_objection && reasons.is_empty() {
        return Err(ConsensusError::ProviderError(format!(
            "structured devil's advocate review for model {model_id} marks serious_objection without reasons"
        )));
    }

    Ok(DevilAdvocateReview {
        review_text,
        serious_objection: review.serious_objection,
        reasons,
    })
}

fn position_claim_sets(positions: &BTreeMap<String, ModelPosition>) -> Vec<Vec<String>> {
    positions
        .values()
        .map(|position| position.key_claims.clone())
        .collect()
}

fn consensus_summary(consensus_claims: &[String]) -> String {
    if consensus_claims.is_empty() {
        "No structured consensus claims met threshold.".to_string()
    } else {
        format!(
            "Structured consensus claims: {}.",
            consensus_claims.join("; ")
        )
    }
}

fn missing_consensus_claims(position: &ModelPosition, consensus_claims: &[String]) -> Vec<String> {
    let position_claims = canonical_claim_set(&position.key_claims);
    consensus_claims
        .iter()
        .filter(|claim| !position_claims.contains(claim))
        .cloned()
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use decision_forum::decision_object::DecisionClass;

    use super::*;

    fn response(text: &str, claims: &[&str]) -> ModelDeliberationResponse {
        ModelDeliberationResponse {
            position_text: text.to_string(),
            key_claims: claims.iter().map(|claim| (*claim).to_string()).collect(),
            confidence_bps: 8000,
        }
    }

    fn routine_responses(
        response_text: &str,
        claims: &[&str],
    ) -> BTreeMap<String, ModelDeliberationResponse> {
        BTreeMap::from([
            (
                "claude-3-haiku".to_string(),
                response(response_text, claims),
            ),
            ("gpt-4o-mini".to_string(), response(response_text, claims)),
            (
                "gemini-1.5-flash".to_string(),
                response(response_text, claims),
            ),
        ])
    }

    fn neutral_review() -> DevilAdvocateReview {
        DevilAdvocateReview {
            review_text: "No threshold objection found.".to_string(),
            serious_objection: false,
            reasons: Vec::new(),
        }
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
        let provider =
            DeterministicResponseProvider::with_positions(routine_responses("A, B", &["a", "b"]));
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
        responses.insert(
            "claude-3-5-sonnet".into(),
            response("alpha position", &["alpha"]),
        );
        responses.insert("gpt-4o".into(), response("beta position", &["beta"]));
        responses.insert(
            "gemini-1.5-pro".into(),
            response("gamma position", &["gamma"]),
        );
        let provider = DeterministicResponseProvider::with_positions(responses);
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
        let provider = DeterministicResponseProvider::with_positions(BTreeMap::new());
        let session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        assert!(!session.is_converged());
    }

    // Covers lines 136-138: finalize returns StateError when no rounds have been executed.
    #[test]
    fn finalize_errors_with_state_error_when_rounds_empty() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let provider = DeterministicResponseProvider::with_positions(BTreeMap::new());
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

    #[test]
    fn execute_round_rejects_text_only_response_without_structured_claims() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let provider = DeterministicResponseProvider::with_positions(routine_responses(
            "raw text has commas, but no structured claims",
            &[],
        ));
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);

        let err = session
            .execute_round(timing(1))
            .expect_err("text-only model response must fail closed");

        match err {
            ConsensusError::ProviderError(message) => {
                assert!(message.contains("explicit key_claims"));
            }
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    #[test]
    fn execute_round_rejects_out_of_range_model_confidence() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let mut responses = routine_responses("claim text", &["claim"]);
        let mut invalid = response("claim text", &["claim"]);
        invalid.confidence_bps = 10001;
        responses.insert("gpt-4o-mini".to_string(), invalid);
        let provider = DeterministicResponseProvider::with_positions(responses);
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);

        let err = session
            .execute_round(timing(1))
            .expect_err("confidence above 10000 bps must fail closed");

        match err {
            ConsensusError::ProviderError(message) => {
                assert!(message.contains("confidence_bps above 10000"));
            }
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    // Covers line 100 true branch: devil's advocate runs on final round even when convergence is low.
    #[test]
    fn devil_advocate_runs_on_final_round_even_without_convergence() {
        // Operational panel: max_rounds = 2, threshold 7500, DA = "gpt-4o".
        let panel = Panel::default_panel(DecisionClass::Operational);
        let mut responses = BTreeMap::new();
        // Distinct responses so convergence < threshold in both rounds.
        responses.insert(
            "claude-3-5-sonnet".into(),
            response("alpha position", &["alpha"]),
        );
        responses.insert("gpt-4o".into(), response("beta position", &["beta"]));
        responses.insert(
            "gemini-1.5-pro".into(),
            response("gamma position", &["gamma"]),
        );
        let provider = DeterministicResponseProvider::new(
            responses,
            BTreeMap::from([("gpt-4o".to_string(), neutral_review())]),
        );
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);

        // Round 1: not final, convergence below threshold -> DA does NOT run.
        let r1 = session.execute_round(timing(1)).unwrap();
        assert!(r1.convergence_score_bps < 7500);
        assert!(
            r1.devil_advocate_review.is_none(),
            "DA should not run when neither converged nor on the final round"
        );

        // Round 2: final round, still below threshold -> DA MUST run via the line-100 clause.
        let r2 = session.execute_round(timing(2)).unwrap();
        assert_eq!(r2.round_number, 2);
        assert!(r2.convergence_score_bps < 7500);
        assert!(
            r2.devil_advocate_review.is_some(),
            "DA must trigger on the final round even without convergence"
        );

        // And finalize must surface that DA summary on the result.
        let result = session.finalize(finalization_timing()).unwrap();
        assert!(result.devil_advocate_summary.is_some());
    }

    #[test]
    fn devil_advocate_keyword_text_is_not_binding_without_serious_flag() {
        let panel = Panel::default_panel(DecisionClass::Operational);
        let positions = BTreeMap::from([
            (
                "claude-3-5-sonnet".to_string(),
                response("shared position", &["shared claim"]),
            ),
            (
                "gpt-4o".to_string(),
                response("shared position", &["shared claim"]),
            ),
            (
                "gemini-1.5-pro".to_string(),
                response("shared position", &["shared claim"]),
            ),
        ]);
        let reviews = BTreeMap::from([(
            "gpt-4o".to_string(),
            DevilAdvocateReview {
                review_text: "The prose says serious and fatal but the structured flag is false."
                    .to_string(),
                serious_objection: false,
                reasons: Vec::new(),
            },
        )]);
        let provider = DeterministicResponseProvider::new(positions, reviews);
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);

        session.execute_round(timing(1)).unwrap();
        let result = session.finalize(finalization_timing()).unwrap();

        assert_eq!(result.panel_confidence_index_bps, 10000);
        assert_eq!(
            result.devil_advocate_summary.as_deref(),
            Some("The prose says serious and fatal but the structured flag is false.")
        );
    }

    #[test]
    fn devil_advocate_serious_objection_requires_reasons_and_penalizes_panel_confidence() {
        let panel = Panel::default_panel(DecisionClass::Operational);
        let positions = BTreeMap::from([
            (
                "claude-3-5-sonnet".to_string(),
                response("shared position", &["shared claim"]),
            ),
            (
                "gpt-4o".to_string(),
                response("shared position", &["shared claim"]),
            ),
            (
                "gemini-1.5-pro".to_string(),
                response("shared position", &["shared claim"]),
            ),
        ]);
        let reviews = BTreeMap::from([(
            "gpt-4o".to_string(),
            DevilAdvocateReview {
                review_text: "Structured objection accepted.".to_string(),
                serious_objection: true,
                reasons: vec!["missing safety bound".to_string()],
            },
        )]);
        let provider = DeterministicResponseProvider::new(positions, reviews);
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);

        session.execute_round(timing(1)).unwrap();
        let result = session.finalize(finalization_timing()).unwrap();

        assert_eq!(result.panel_confidence_index_bps, 8000);

        let invalid_positions = BTreeMap::from([
            (
                "claude-3-5-sonnet".to_string(),
                response("shared position", &["shared claim"]),
            ),
            (
                "gpt-4o".to_string(),
                response("shared position", &["shared claim"]),
            ),
            (
                "gemini-1.5-pro".to_string(),
                response("shared position", &["shared claim"]),
            ),
        ]);
        let invalid_reviews = BTreeMap::from([(
            "gpt-4o".to_string(),
            DevilAdvocateReview {
                review_text: "Structured objection lacks reasons.".to_string(),
                serious_objection: true,
                reasons: Vec::new(),
            },
        )]);
        let provider = DeterministicResponseProvider::new(invalid_positions, invalid_reviews);
        let mut session = DeliberationSession::new(
            "s2".into(),
            Panel::default_panel(DecisionClass::Operational),
            "Q?".into(),
            provider,
        );
        let err = session
            .execute_round(timing(1))
            .expect_err("serious objection without reasons must fail closed");
        match err {
            ConsensusError::ProviderError(message) => {
                assert!(message.contains("marks serious_objection without reasons"));
            }
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    // Covers the DA-skipped branch when the panel has no devil_advocate_model configured.
    #[test]
    fn devil_advocate_skipped_when_panel_has_no_da_model_even_on_converged_final_round() {
        // Routine panel: max_rounds = 1 (final), devil_advocate_model = None.
        let panel = Panel::default_panel(DecisionClass::Routine);
        assert!(panel.devil_advocate_model.is_none());
        let provider = DeterministicResponseProvider::with_positions(routine_responses(
            "same claim",
            &["same claim"],
        ));
        let mut session = DeliberationSession::new("s".into(), panel, "Q?".into(), provider);
        let round = session.execute_round(timing(1)).unwrap();
        // Convergence is 10000 (all identical) and we are at the final round,
        // but devil_advocate_model is None => the inner `if let Some(..)` is false.
        assert_eq!(round.convergence_score_bps, 10000);
        assert!(round.devil_advocate_review.is_none());
    }
}
