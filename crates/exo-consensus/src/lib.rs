pub mod advocate;
pub mod commitment;
pub mod error;
pub mod mock_client;
pub mod panel;
pub mod record;
pub mod report;
pub mod round;
pub mod scoring;
pub mod session;

pub use commitment::{commit, verify_commitment};
pub use error::{ConsensusError, Result};
pub use mock_client::MockLlmClient;
pub use panel::{ModelProvider, ModelRole, Panel, PanelModel};
pub use record::DeliberationResult;
pub use report::MinorityReport;
pub use round::{DeliberationRound, ModelPosition};
pub use scoring::{PanelConfidenceInputs, calculate_convergence, calculate_panel_confidence};
pub use session::DeliberationSession;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use decision_forum::decision_object::DecisionClass;
    use exo_core::types::Timestamp;

    use super::*;

    // Helper functions for tests
    fn make_mock_client() -> MockLlmClient {
        MockLlmClient::new()
    }

    // 1. test_convergence_identical_positions
    #[test]
    fn test_convergence_identical_positions() {
        let pos = vec!["claim1, claim2, claim3", "claim1, claim2, claim3"];
        let score = calculate_convergence(&pos);
        assert_eq!(score, 10000);
    }

    // 2. test_convergence_zero_overlap
    #[test]
    fn test_convergence_zero_overlap() {
        let pos = vec!["claim1, claim2", "claim3, claim4"];
        let score = calculate_convergence(&pos);
        assert_eq!(score, 0);
    }

    // 3. test_convergence_partial_overlap
    #[test]
    fn test_convergence_partial_overlap() {
        // "claim1" is shared, "claim2", "claim3", "claim4", "claim5" are not. Total unique: 5.
        // Shared: 1. Wait, let's just make it simple:
        let pos = vec!["A, B", "A, C"];
        let score = calculate_convergence(&pos);
        // Unique claims: a, b, c (3). Shared: a (1).
        // Score = 1/3 * 10000 = 3333.
        // Let's adjust expected based on logic.
        assert_eq!(score, 3333);

        // For exactly 50%: "A, B", "A, B, C, D" => Wait.
        let pos2 = vec!["A, B", "A, B, C, D"];
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
            submitted_at: Timestamp::now_utc(),
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
            submitted_at: Timestamp::now_utc(),
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
            devil_advocate_challenge: None,
            round_hash: exo_core::types::Hash256::ZERO,
        };
        let h1 = round.compute_hash();
        let h2 = round.compute_hash();
        assert_eq!(h1, h2);
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
            completed_at: Timestamp::now_utc(),
        };
        let h1 = result.compute_hash();
        let h2 = result.compute_hash();
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
            completed_at: Timestamp::now_utc(),
        };
        let h1 = result.compute_hash();
        result.rounds_to_convergence = 2;
        let h2 = result.compute_hash();
        assert_ne!(h1, h2);
    }

    // 12. test_mock_session_single_round
    #[test]
    fn test_mock_session_single_round() {
        let panel = Panel::default_panel(DecisionClass::Routine);
        let mut client = make_mock_client();
        client.default_response = "A, B, C".into();

        let mut session =
            DeliberationSession::new("test".into(), panel, "What is X?".into(), client);
        let round = session.execute_round().unwrap();
        assert_eq!(round.round_number, 1);
        assert_eq!(round.positions.len(), 3);

        let result = session.finalize().unwrap();
        assert_eq!(result.rounds.len(), 1);
    }

    // 13. test_mock_session_converges
    #[test]
    fn test_mock_session_converges() {
        let panel = Panel::default_panel(DecisionClass::Operational);
        let mut client = make_mock_client();
        client.default_response = "identical claim".into();

        let mut session =
            DeliberationSession::new("test".into(), panel, "What is X?".into(), client);
        let round = session.execute_round().unwrap();

        // Since all give "identical claim", convergence should be 10000
        assert_eq!(round.convergence_score_bps, 10000);
        assert!(session.is_converged());

        let result = session.finalize().unwrap();
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
}
