pub mod advocate;
pub mod commitment;
pub mod error;
pub mod panel;
pub mod record;
pub mod report;
pub mod round;
pub mod scoring;
pub mod session;

pub use commitment::{commit, commit_response, verify_commitment, verify_response_commitment};
pub use error::{ConsensusError, Result};
pub use panel::{ModelProvider, ModelRole, Panel, PanelModel};
pub use record::DeliberationResult;
pub use report::MinorityReport;
pub use round::{DeliberationRound, DevilAdvocateReview, ModelDeliberationResponse, ModelPosition};
pub use scoring::{
    PanelConfidenceInputs, calculate_convergence, calculate_panel_confidence, canonical_claim_set,
    consensus_claims_at_threshold,
};
pub use session::{
    DeliberationSession, DeterministicResponseProvider, FinalizationTiming, RoundExecutionTiming,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use decision_forum::decision_object::DecisionClass;
    use exo_core::types::Timestamp;
    use serde::Serialize;

    use super::*;

    fn round_timing(round: u64) -> RoundExecutionTiming {
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

    fn response(text: &str, claims: &[&str]) -> ModelDeliberationResponse {
        ModelDeliberationResponse {
            position_text: text.to_string(),
            key_claims: claims.iter().map(|claim| (*claim).to_string()).collect(),
            confidence_bps: 8000,
        }
    }

    fn routine_response_provider(
        response_text: &str,
        claims: &[&str],
    ) -> DeterministicResponseProvider {
        DeterministicResponseProvider::with_positions(routine_panel_responses(
            response_text,
            claims,
        ))
    }

    fn operational_response_provider(
        response_text: &str,
        claims: &[&str],
    ) -> DeterministicResponseProvider {
        DeterministicResponseProvider::new(
            BTreeMap::from([
                (
                    "claude-3-5-sonnet".to_string(),
                    response(response_text, claims),
                ),
                ("gpt-4o".to_string(), response(response_text, claims)),
                (
                    "gemini-1.5-pro".to_string(),
                    response(response_text, claims),
                ),
            ]),
            BTreeMap::from([("gpt-4o".to_string(), neutral_review())]),
        )
    }

    fn neutral_review() -> DevilAdvocateReview {
        DevilAdvocateReview {
            review_text: "No threshold objection found.".to_string(),
            serious_objection: false,
            reasons: Vec::new(),
        }
    }

    // 1. test_convergence_identical_positions
    #[test]
    fn test_convergence_identical_positions() {
        let pos = vec![
            vec![
                "claim1".to_string(),
                "claim2".to_string(),
                "claim3".to_string(),
            ],
            vec![
                "claim1".to_string(),
                "claim2".to_string(),
                "claim3".to_string(),
            ],
        ];
        let score = calculate_convergence(&pos);
        assert_eq!(score, 10000);
    }

    // 2. test_convergence_zero_overlap
    #[test]
    fn test_convergence_zero_overlap() {
        let pos = vec![
            vec!["claim1".to_string(), "claim2".to_string()],
            vec!["claim3".to_string(), "claim4".to_string()],
        ];
        let score = calculate_convergence(&pos);
        assert_eq!(score, 0);
    }

    // 3. test_convergence_partial_overlap
    #[test]
    fn test_convergence_partial_overlap() {
        // "claim1" is shared, "claim2", "claim3", "claim4", "claim5" are not. Total unique: 5.
        // Shared: 1. Wait, let's just make it simple:
        let pos = vec![
            vec!["A".to_string(), "B".to_string()],
            vec!["A".to_string(), "C".to_string()],
        ];
        let score = calculate_convergence(&pos);
        // Unique claims: a, b, c (3). Shared: a (1).
        // Score = 1/3 * 10000 = 3333.
        // Let's adjust expected based on logic.
        assert_eq!(score, 3333);

        // For exactly 50%: "A, B", "A, B, C, D" => Wait.
        let pos2 = vec![
            vec!["A".to_string(), "B".to_string()],
            vec![
                "A".to_string(),
                "B".to_string(),
                "C".to_string(),
                "D".to_string(),
            ],
        ];
        let score2 = calculate_convergence(&pos2);
        // unique: a, b, c, d (4). Shared: a, b (2).
        // 2/4 = 5000
        assert_eq!(score2, 5000);
    }

    // 4. test_panel_confidence_unanimous_fast
    #[test]
    fn test_panel_confidence_unanimous_fast() {
        let inputs = PanelConfidenceInputs {
            models_agreeing: 3,
            total_models: 3,
            rounds_to_convergence: 1,
            max_rounds: 3,
            devil_found_serious_objection: false,
            minority_reports_count: 0,
        };
        let pci = calculate_panel_confidence(&inputs);
        // agreement = 5000
        // speed = ((3 - 1 + 1) / 3) * 3000 = 3/3 * 3000 = 3000
        // advocate = 2000
        // total = 10000
        assert_eq!(pci, 10000);
    }

    // 5. test_panel_confidence_split_slow
    #[test]
    fn test_panel_confidence_split_slow() {
        let inputs = PanelConfidenceInputs {
            models_agreeing: 2,
            total_models: 3,
            rounds_to_convergence: 3,
            max_rounds: 3,
            devil_found_serious_objection: false,
            minority_reports_count: 1,
        };
        let pci = calculate_panel_confidence(&inputs);
        // agreement = (2/3) * 5000 = 3333
        // speed = ((3 - 3 + 1) / 3) * 3000 = 1/3 * 3000 = 1000
        // advocate = 2000
        // total = 6333
        assert_eq!(pci, 6333);
    }

    // 6. test_panel_confidence_devil_found_issue
    #[test]
    fn test_panel_confidence_devil_found_issue() {
        let inputs = PanelConfidenceInputs {
            models_agreeing: 3,
            total_models: 3,
            rounds_to_convergence: 1,
            max_rounds: 3,
            devil_found_serious_objection: true,
            minority_reports_count: 0,
        };
        let pci = calculate_panel_confidence(&inputs);
        // advocate = 0
        assert_eq!(pci, 8000); // 5000 + 3000 + 0
    }

    // 7. test_minority_report_triggered
    #[test]
    fn test_minority_report_triggered() {
        let pos = ModelPosition {
            model_id: "m1".into(),
            round: 1,
            position_hash: exo_core::types::Hash256::ZERO,
            position_text: "claim3".into(),
            key_claims: vec!["claim3".into()],
            confidence_bps: 8000,
            submitted_at: Timestamp::new(1, 0),
            revealed_at: None,
        };
        let consensus_claims = vec!["claim1".into(), "claim2".into()];
        // overlap is 0/2. threshold is 5000.
        let triggered = report::is_minority_report(&pos, &consensus_claims, 5000);
        assert!(triggered);
    }

    // 8. test_minority_report_not_triggered
    #[test]
    fn test_minority_report_not_triggered() {
        let pos = ModelPosition {
            model_id: "m1".into(),
            round: 1,
            position_hash: exo_core::types::Hash256::ZERO,
            position_text: "claim1, claim2".into(),
            key_claims: vec!["claim1".into(), "claim2".into()],
            confidence_bps: 8000,
            submitted_at: Timestamp::new(1, 0),
            revealed_at: None,
        };
        let consensus_claims = vec!["claim1".into(), "claim2".into()];
        let triggered = report::is_minority_report(&pos, &consensus_claims, 5000);
        assert!(!triggered);
    }

    // 9. test_round_hash_deterministic
    #[test]
    fn test_round_hash_deterministic() {
        let round = DeliberationRound {
            round_number: 1,
            question: "Q".into(),
            positions: BTreeMap::new(),
            synthesis: None,
            convergence_score_bps: 10000,
            devil_advocate_review: None,
            round_hash: exo_core::types::Hash256::ZERO,
        };
        let h1 = round.compute_hash().expect("round hash");
        let h2 = round.compute_hash().expect("round hash");
        assert_eq!(h1, h2);
    }

    #[test]
    fn structured_response_commitment_binds_claims_and_confidence() {
        let original = response("same prose", &["claim-a", "claim-b"]);
        let same = response("same prose", &["claim-a", "claim-b"]);
        let changed_claims = response("same prose", &["claim-a", "claim-c"]);
        let mut changed_confidence = response("same prose", &["claim-a", "claim-b"]);
        changed_confidence.confidence_bps = 7000;

        let original_hash = commit_response(&original).expect("structured response hash");

        assert_eq!(
            original_hash,
            commit_response(&same).expect("same structured response hash")
        );
        assert_ne!(
            original_hash,
            commit_response(&changed_claims).expect("changed claims hash")
        );
        assert_ne!(
            original_hash,
            commit_response(&changed_confidence).expect("changed confidence hash")
        );
        assert!(
            verify_response_commitment(&original, &original_hash)
                .expect("verify structured commitment")
        );
        assert!(
            !verify_response_commitment(&changed_claims, &original_hash)
                .expect("reject changed structured claims")
        );
    }

    // 10. test_result_hash_deterministic
    #[test]
    fn test_result_hash_deterministic() {
        let result = DeliberationResult {
            session_id: "s1".into(),
            question: "Q".into(),
            rounds: vec![],
            final_consensus: "C".into(),
            minority_reports: vec![],
            panel_confidence_index_bps: 8000,
            rounds_to_convergence: 1,
            devil_advocate_summary: None,
            deliberation_hash: exo_core::types::Hash256::ZERO,
            completed_at: Timestamp::new(1, 0),
        };
        let h1 = result.compute_hash().expect("result hash");
        let h2 = result.compute_hash().expect("result hash");
        assert_eq!(h1, h2);
    }

    // 11. test_result_hash_changes
    #[test]
    fn test_result_hash_changes() {
        let mut result = DeliberationResult {
            session_id: "s1".into(),
            question: "Q".into(),
            rounds: vec![],
            final_consensus: "C".into(),
            minority_reports: vec![],
            panel_confidence_index_bps: 8000,
            rounds_to_convergence: 1,
            devil_advocate_summary: None,
            deliberation_hash: exo_core::types::Hash256::ZERO,
            completed_at: Timestamp::new(1, 0),
        };
        let h1 = result.compute_hash().expect("result hash");
        result.rounds_to_convergence = 2;
        let h2 = result.compute_hash().expect("result hash");
        assert_ne!(h1, h2);
    }

    // 12. test_deterministic_session_single_round
    #[test]
    fn test_deterministic_session_single_round() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let provider = routine_response_provider("A, B, C", &["a", "b", "c"]);

        let mut session =
            DeliberationSession::new("test".into(), panel, "What is X?".into(), provider);
        let round = session.execute_round(round_timing(1)).unwrap();
        assert_eq!(round.round_number, 1);
        assert_eq!(round.positions.len(), 3);

        let result = session.finalize(finalization_timing()).unwrap();
        assert_eq!(result.rounds.len(), 1);
    }

    // 13. test_deterministic_session_converges
    #[test]
    fn test_deterministic_session_converges() {
        let panel = Panel::default_panel(DecisionClass::Operational);
        let provider = operational_response_provider("identical claim", &["identical claim"]);

        let mut session =
            DeliberationSession::new("test".into(), panel, "What is X?".into(), provider);
        let round = session.execute_round(round_timing(1)).unwrap();

        // Since all give "identical claim", convergence should be 10000
        assert_eq!(round.convergence_score_bps, 10000);
        assert!(session.is_converged());

        let result = session.finalize(finalization_timing()).unwrap();
        assert_eq!(result.rounds_to_convergence, 1);
    }

    // 14. test_default_panel_by_class
    #[test]
    fn test_default_panel_by_class() {
        let p_routine = Panel::default_panel(DecisionClass::Routine);
        assert_eq!(p_routine.max_rounds, 1);
        assert!(p_routine.devil_advocate_model.is_none());

        let p_const = Panel::default_panel(DecisionClass::Constitutional);
        assert_eq!(p_const.max_rounds, 4);
        assert!(p_const.devil_advocate_model.is_some());
        assert_eq!(p_const.models.len(), 5);
    }

    #[test]
    fn session_uses_caller_supplied_hlc_inputs() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let responses = routine_panel_responses("A, B, C", &["a", "b", "c"]);
        let provider = DeterministicResponseProvider::with_positions(responses);
        let submitted_at = Timestamp::new(42_000, 7);
        let revealed_at = Timestamp::new(42_000, 8);
        let completed_at = Timestamp::new(42_001, 0);
        let mut session =
            DeliberationSession::new("test".into(), panel, "What is X?".into(), provider);

        let round = session
            .execute_round(RoundExecutionTiming {
                submitted_at,
                revealed_at,
            })
            .expect("round executes with caller-supplied timing");
        for position in round.positions.values() {
            assert_eq!(position.submitted_at, submitted_at);
            assert_eq!(position.revealed_at, Some(revealed_at));
        }

        let result = session
            .finalize(FinalizationTiming { completed_at })
            .expect("finalizes with caller-supplied timing");
        assert_eq!(result.completed_at, completed_at);
    }

    #[test]
    fn missing_deterministic_response_is_rejected_without_placeholder_text() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let mut responses = routine_panel_responses("A, B, C", &["a", "b", "c"]);
        responses.remove("gpt-4o-mini");
        let provider = DeterministicResponseProvider::with_positions(responses);
        let mut session =
            DeliberationSession::new("test".into(), panel, "What is X?".into(), provider);

        let err = session
            .execute_round(RoundExecutionTiming {
                submitted_at: Timestamp::new(50_000, 0),
                revealed_at: Timestamp::new(50_000, 1),
            })
            .expect_err("missing model response must fail closed");

        match err {
            ConsensusError::ProviderError(message) => {
                assert!(message.contains("gpt-4o-mini"));
                assert!(!message.contains("Mocked response"));
            }
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    #[test]
    fn round_hash_is_canonical_cbor_with_domain_tag() {
        let round = sample_round();
        #[derive(Serialize)]
        struct ExpectedRoundHashPayload<'a> {
            domain: &'static str,
            schema_version: &'static str,
            round_number: u32,
            question: &'a str,
            positions: &'a BTreeMap<String, ModelPosition>,
            synthesis: &'a Option<String>,
            convergence_score_bps: u64,
            devil_advocate_review: &'a Option<DevilAdvocateReview>,
        }
        let expected = exo_core::hash::hash_structured(&ExpectedRoundHashPayload {
            domain: "exo.consensus.deliberation_round.v1",
            schema_version: "1",
            round_number: round.round_number,
            question: &round.question,
            positions: &round.positions,
            synthesis: &round.synthesis,
            convergence_score_bps: round.convergence_score_bps,
            devil_advocate_review: &round.devil_advocate_review,
        })
        .expect("expected CBOR hash");

        assert_eq!(round.compute_hash().expect("round hash"), expected);
    }

    #[test]
    fn result_hash_is_canonical_cbor_with_domain_tag_and_completion_time() {
        let result = sample_result(Timestamp::new(100_100, 0));
        #[derive(Serialize)]
        struct ExpectedResultHashPayload<'a> {
            domain: &'static str,
            schema_version: &'static str,
            session_id: &'a str,
            question: &'a str,
            rounds: &'a [DeliberationRound],
            final_consensus: &'a str,
            minority_reports: &'a [MinorityReport],
            panel_confidence_index_bps: u64,
            rounds_to_convergence: u32,
            devil_advocate_summary: &'a Option<String>,
            completed_at: Timestamp,
        }
        let expected = exo_core::hash::hash_structured(&ExpectedResultHashPayload {
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
        })
        .expect("expected CBOR hash");

        assert_eq!(result.compute_hash().expect("result hash"), expected);

        let changed_completion_time = sample_result(Timestamp::new(100_101, 0));
        assert_ne!(
            result.compute_hash().expect("original hash"),
            changed_completion_time
                .compute_hash()
                .expect("changed hash")
        );
    }

    #[test]
    fn production_session_source_has_no_system_time_or_mock_boundary() {
        let source = production_source("src/session.rs");
        assert!(
            !source.contains("Timestamp::now_utc()"),
            "production session code must not synthesize wall-clock timestamps"
        );
        assert!(
            !source.contains("MockLlmClient") && !source.contains("llm_client"),
            "production session boundary must not be wired through a mock LLM client"
        );
    }

    #[test]
    fn production_session_source_has_no_raw_text_consensus_heuristics() {
        let source = production_source("src/session.rs");
        assert!(
            !source.contains(".split([',', '\\n', ';'])"),
            "production session code must not derive structured claims by splitting raw prose"
        );
        assert!(
            !source.contains("is_serious_challenge"),
            "production session code must not derive serious objections from keyword heuristics"
        );
    }

    #[test]
    fn production_hashing_source_has_no_json_or_silent_default_fallback() {
        for file in ["src/round.rs", "src/record.rs"] {
            let source = production_source(file);
            assert!(
                !source.contains("serde_json::to_string"),
                "{file} must hash canonical CBOR, not JSON"
            );
            assert!(
                !source.contains("unwrap_or_default"),
                "{file} must not hide hash serialization failures"
            );
        }
    }

    fn routine_panel_responses(
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

    fn sample_round() -> DeliberationRound {
        let mut positions = BTreeMap::new();
        let position_text = "A, B, C".to_string();
        positions.insert(
            "claude-3-haiku".to_string(),
            ModelPosition {
                model_id: "claude-3-haiku".to_string(),
                round: 1,
                position_hash: commit_response(&ModelDeliberationResponse {
                    position_text: position_text.clone(),
                    key_claims: vec!["a".to_string(), "b".to_string(), "c".to_string()],
                    confidence_bps: 8000,
                })
                .expect("structured commitment"),
                position_text,
                key_claims: vec!["a".to_string(), "b".to_string(), "c".to_string()],
                confidence_bps: 8000,
                submitted_at: Timestamp::new(100_000, 0),
                revealed_at: Some(Timestamp::new(100_000, 1)),
            },
        );
        DeliberationRound {
            round_number: 1,
            question: "What is X?".to_string(),
            positions,
            synthesis: Some("Structured consensus claims: a; b; c.".to_string()),
            convergence_score_bps: 10000,
            devil_advocate_review: None,
            round_hash: exo_core::types::Hash256::ZERO,
        }
    }

    fn sample_result(completed_at: Timestamp) -> DeliberationResult {
        DeliberationResult {
            session_id: "test".to_string(),
            question: "What is X?".to_string(),
            rounds: vec![sample_round()],
            final_consensus: "Structured consensus claims: a; b; c.".to_string(),
            minority_reports: Vec::new(),
            panel_confidence_index_bps: 10000,
            rounds_to_convergence: 1,
            devil_advocate_summary: None,
            deliberation_hash: exo_core::types::Hash256::ZERO,
            completed_at,
        }
    }

    fn production_source(path: &str) -> String {
        let full_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        let source = std::fs::read_to_string(&full_path).unwrap_or_else(|e| {
            panic!(
                "failed to read production source {}: {e}",
                full_path.display()
            )
        });
        source
            .split("#[cfg(test)]")
            .next()
            .expect("source split must have production section")
            .to_string()
    }
}
