//! Completeness checking — ensures all required stages completed, evidence collected, sign-offs obtained.

use crate::escalation::{CaseStatus, EscalationCase, EscalationPath, SybilStage};

/// Outcome of a completeness check on an escalation case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletenessResult {
    Complete,
    Incomplete { missing: Vec<String> },
}

/// Check whether an escalation case has completed all required stages.
#[must_use]
pub fn check_completeness(case: &EscalationCase) -> CompletenessResult {
    let mut missing = Vec::new();

    // Check evidence
    if case.evidence.is_empty() {
        missing.push("no evidence collected".to_string());
    }

    // Path-specific completeness requirements
    match case.path {
        EscalationPath::SybilAdjudication => {
            let required = [
                SybilStage::Detection,
                SybilStage::Triage,
                SybilStage::Quarantine,
                SybilStage::EvidentaryReview,
                SybilStage::ClearanceDowngrade,
                SybilStage::Reinstatement,
                SybilStage::AuditLog,
            ];
            for stage in &required {
                let stage_name = stage.to_string();
                if !case.stages_completed.contains(&stage_name) {
                    missing.push(format!("missing stage: {stage_name}"));
                }
            }
        }
        EscalationPath::Standard => {
            if !case.stages_completed.contains(&"intake".to_string()) {
                missing.push("missing stage: intake".into());
            }
        }
        EscalationPath::Emergency => {
            if !case
                .stages_completed
                .contains(&"emergency_activated".to_string())
            {
                missing.push("missing stage: emergency_activated".into());
            }
        }
        EscalationPath::Constitutional => {
            if !case
                .stages_completed
                .contains(&"constitutional_review".to_string())
            {
                missing.push("missing stage: constitutional_review".into());
            }
        }
    }

    // Resolved/Closed cases should have assignee
    if (case.status == CaseStatus::Resolved || case.status == CaseStatus::Closed)
        && case.assignee.is_none()
    {
        missing.push("resolved case has no assignee".to_string());
    }

    if missing.is_empty() {
        CompletenessResult::Complete
    } else {
        CompletenessResult::Incomplete { missing }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::Timestamp;
    use uuid::Uuid;

    use super::*;
    use crate::{detector::*, escalation::*};

    fn signal(confidence: u8) -> DetectionSignal {
        DetectionSignal {
            source: "test".into(),
            signal_type: SignalType::SybilSuspicion,
            confidence,
            evidence_hash: [1u8; 32],
            timestamp: Timestamp::new(1000, 0),
        }
    }
    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }
    fn case_input(id_marker: u8, confidence: u8, path: EscalationPath) -> EscalationCaseInput {
        EscalationCaseInput {
            id: uuid(id_marker),
            created: Timestamp::new(2000, 0),
            signal: signal(confidence),
            path,
        }
    }

    #[test]
    fn standard_case_complete() {
        let c = escalate(case_input(1, 50, EscalationPath::Standard)).unwrap();
        assert_eq!(check_completeness(&c), CompletenessResult::Complete);
    }

    #[test]
    fn sybil_case_incomplete_initially() {
        let c = escalate(case_input(2, 75, EscalationPath::SybilAdjudication)).unwrap();
        match check_completeness(&c) {
            CompletenessResult::Incomplete { missing } => {
                assert!(missing.iter().any(|m| m.contains("Triage")));
                assert!(missing.iter().any(|m| m.contains("AuditLog")));
            }
            _ => panic!("expected incomplete"),
        }
    }

    #[test]
    fn sybil_case_complete_after_all_stages() {
        let mut c = escalate(case_input(3, 75, EscalationPath::SybilAdjudication)).unwrap();
        c.assignee = Some(exo_core::Did::new("did:exo:reviewer").expect("ok"));
        for stage in [
            SybilStage::Triage,
            SybilStage::Quarantine,
            SybilStage::EvidentaryReview,
            SybilStage::ClearanceDowngrade,
            SybilStage::Reinstatement,
            SybilStage::AuditLog,
        ] {
            advance_sybil_stage(&mut c, stage).unwrap();
        }
        assert_eq!(check_completeness(&c), CompletenessResult::Complete);
    }

    #[test]
    fn resolved_without_assignee_incomplete() {
        let mut c = escalate(case_input(4, 50, EscalationPath::Standard)).unwrap();
        c.status = CaseStatus::Resolved;
        match check_completeness(&c) {
            CompletenessResult::Incomplete { missing } => {
                assert!(missing.iter().any(|m| m.contains("no assignee")));
            }
            _ => panic!("expected incomplete"),
        }
    }

    #[test]
    fn emergency_case_complete() {
        let c = escalate(case_input(5, 95, EscalationPath::Emergency)).unwrap();
        assert_eq!(check_completeness(&c), CompletenessResult::Complete);
    }

    #[test]
    fn constitutional_case_complete() {
        let c = escalate(case_input(6, 60, EscalationPath::Constitutional)).unwrap();
        assert_eq!(check_completeness(&c), CompletenessResult::Complete);
    }

    #[test]
    fn no_evidence_incomplete() {
        let mut c = escalate(case_input(7, 50, EscalationPath::Standard)).unwrap();
        c.evidence.clear();
        match check_completeness(&c) {
            CompletenessResult::Incomplete { missing } => {
                assert!(missing.iter().any(|m| m.contains("no evidence")));
            }
            _ => panic!("expected incomplete"),
        }
    }
}
