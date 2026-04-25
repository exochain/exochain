use std::collections::BTreeMap;

use exo_core::types::{Hash256, Timestamp};

use crate::{
    advocate::{generate_advocate_prompt, is_serious_challenge},
    commitment::{commit, verify_commitment},
    error::{ConsensusError, Result},
    mock_client::MockLlmClient,
    panel::{ModelRole, Panel},
    record::DeliberationResult,
    report::{MinorityReport, is_minority_report},
    round::{DeliberationRound, ModelPosition},
    scoring::{PanelConfidenceInputs, calculate_convergence, calculate_panel_confidence},
};

pub struct DeliberationSession {
    pub session_id: String,
    pub panel: Panel,
    pub question: String,
    pub current_round: u32,
    pub rounds: Vec<DeliberationRound>,
    pub llm_client: MockLlmClient, // Just using mock client for now to fulfill deterministic API
}

impl DeliberationSession {
    pub fn new(
        session_id: String,
        panel: Panel,
        question: String,
        llm_client: MockLlmClient,
    ) -> Self {
        Self {
            session_id,
            panel,
            question,
            current_round: 1,
            rounds: Vec::new(),
            llm_client,
        }
    }

    pub fn execute_round(&mut self) -> Result<DeliberationRound> {
        if self.current_round > self.panel.max_rounds {
            return Err(ConsensusError::RoundLimitExceeded);
        }

        let mut positions = BTreeMap::new();
        let mut raw_texts = Vec::new();

        // 1. Commitment Phase
        let mut commitments = BTreeMap::new();
        for model in &self.panel.models {
            if model.role == ModelRole::Panelist {
                let prompt = format!("Round {}: {}", self.current_round, self.question);
                let text = self.llm_client.call(&model.model_id, &prompt);
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
                submitted_at: Timestamp::now_utc(),
                revealed_at: Some(Timestamp::now_utc()),
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
                let da_prompt = generate_advocate_prompt(&self.question, &synthesis_text);
                let challenge = self.llm_client.call(da_id, &da_prompt);
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

        round.round_hash = round.compute_hash();

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

    pub fn finalize(&self) -> Result<DeliberationResult> {
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
            completed_at: Timestamp::now_utc(),
        };

        result.deliberation_hash = result.compute_hash();

        Ok(result)
    }
}
