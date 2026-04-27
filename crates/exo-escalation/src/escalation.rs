//! Escalation pathways including Sybil adjudication (CR-001 section 8.6).

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{detector::DetectionSignal, error::EscalationError};

/// Pathway through which a detected threat is escalated for resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationPath {
    Standard,
    SybilAdjudication,
    Emergency,
    Constitutional,
}

/// Stages of the Sybil adjudication path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SybilStage {
    Detection,
    Triage,
    Quarantine,
    EvidentaryReview,
    ClearanceDowngrade,
    Reinstatement,
    AuditLog,
}

/// Lifecycle status of an escalation case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseStatus {
    Open,
    InProgress,
    PendingReview,
    Resolved,
    Closed,
}

/// Priority ranking of an escalation case, derived from signal confidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CasePriority {
    Low,
    Medium,
    High,
    Critical,
}

/// A tracked escalation case linking detection signals to resolution stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationCase {
    pub id: Uuid,
    pub path: EscalationPath,
    pub status: CaseStatus,
    pub priority: CasePriority,
    pub stages_completed: Vec<String>,
    pub evidence: Vec<[u8; 32]>,
    pub assignee: Option<Did>,
    pub created: Timestamp,
}

/// Deterministic input for opening an escalation case.
///
/// The case id and creation timestamp are supplied by the caller from the
/// surrounding HLC/provenance context. Escalation case creation never reads
/// randomness or wall-clock time internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationCaseInput {
    pub id: Uuid,
    pub created: Timestamp,
    pub signal: DetectionSignal,
    pub path: EscalationPath,
}

/// Escalate a detection signal along a specific path.
///
/// # Errors
/// Returns an error when caller-supplied provenance fields are placeholders or
/// the detection signal is outside its documented bounds.
pub fn escalate(input: EscalationCaseInput) -> Result<EscalationCase, EscalationError> {
    if input.id == Uuid::nil() {
        return Err(EscalationError::InvalidProvenance {
            reason: "escalation case id must be caller-supplied and non-nil".into(),
        });
    }
    if input.signal.source.trim().is_empty() {
        return Err(EscalationError::InvalidSignal(
            "detection signal source must not be empty".into(),
        ));
    }
    if input.signal.confidence > 100 {
        return Err(EscalationError::InvalidSignal(
            "detection signal confidence must be between 0 and 100".into(),
        ));
    }
    if input.signal.evidence_hash == [0u8; 32] {
        return Err(EscalationError::InvalidProvenance {
            reason: "escalation case requires a non-zero evidence hash".into(),
        });
    }

    let priority = match input.signal.confidence {
        0..=30 => CasePriority::Low,
        31..=60 => CasePriority::Medium,
        61..=85 => CasePriority::High,
        _ => CasePriority::Critical,
    };

    let initial_stage = match &input.path {
        EscalationPath::SybilAdjudication => SybilStage::Detection.to_string(),
        EscalationPath::Emergency => "emergency_activated".to_string(),
        EscalationPath::Constitutional => "constitutional_review".to_string(),
        EscalationPath::Standard => "intake".to_string(),
    };

    Ok(EscalationCase {
        id: input.id,
        path: input.path,
        status: CaseStatus::Open,
        priority,
        stages_completed: vec![initial_stage],
        evidence: vec![input.signal.evidence_hash],
        assignee: None,
        created: input.created,
    })
}

/// Advance a Sybil adjudication case to the next stage.
pub fn advance_sybil_stage(
    case: &mut EscalationCase,
    stage: SybilStage,
) -> Result<(), EscalationError> {
    if case.path != EscalationPath::SybilAdjudication {
        return Err(EscalationError::InvalidStateTransition {
            from: format!("{:?}", case.path),
            to: format!("{stage:?}"),
        });
    }
    case.stages_completed.push(stage.to_string());
    if stage == SybilStage::AuditLog {
        case.status = CaseStatus::Resolved;
    } else {
        case.status = CaseStatus::InProgress;
    }
    Ok(())
}

/// Reinstate a Sybil adjudication case with explicit clearance evidence.
///
/// A non-zero `clearance_evidence` hash is REQUIRED — CR-001 §8.6 mandates
/// that reinstatement without evidence is rejected to prevent automatic or
/// evidence-free restoration of contested actors.
///
/// On success, the evidence hash is appended to `case.evidence` and the case
/// advances to `SybilStage::Reinstatement`.
pub fn reinstate(
    case: &mut EscalationCase,
    clearance_evidence: [u8; 32],
) -> Result<(), EscalationError> {
    if case.path != EscalationPath::SybilAdjudication {
        return Err(EscalationError::InvalidStateTransition {
            from: format!("{:?}", case.path),
            to: "Reinstatement".into(),
        });
    }
    if clearance_evidence == [0u8; 32] {
        return Err(EscalationError::IncompleteCase {
            reason: "reinstatement requires explicit clearance evidence (non-zero hash)".into(),
        });
    }
    case.evidence.push(clearance_evidence);
    advance_sybil_stage(case, SybilStage::Reinstatement)
}

impl std::fmt::Display for SybilStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::detector::*;

    fn signal(confidence: u8, st: SignalType) -> DetectionSignal {
        DetectionSignal {
            source: "test".into(),
            signal_type: st,
            confidence,
            evidence_hash: [1u8; 32],
            timestamp: Timestamp::new(1000, 0),
        }
    }
    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }
    fn case_input(
        id_marker: u8,
        confidence: u8,
        st: SignalType,
        path: EscalationPath,
    ) -> EscalationCaseInput {
        EscalationCaseInput {
            id: uuid(id_marker),
            created: Timestamp::new(2000, 0),
            signal: signal(confidence, st),
            path,
        }
    }

    #[test]
    fn escalate_standard() {
        let c = escalate(case_input(
            1,
            40,
            SignalType::AnomalousPattern,
            EscalationPath::Standard,
        ))
        .unwrap();
        assert_eq!(c.path, EscalationPath::Standard);
        assert_eq!(c.status, CaseStatus::Open);
        assert_eq!(c.priority, CasePriority::Medium);
        assert!(c.stages_completed.contains(&"intake".to_string()));
        assert_eq!(c.evidence, vec![[1u8; 32]]);
        assert_eq!(c.id, uuid(1));
        assert_eq!(c.created, Timestamp::new(2000, 0));
    }

    #[test]
    fn escalate_is_deterministic_for_same_input() {
        let input = case_input(
            2,
            40,
            SignalType::AnomalousPattern,
            EscalationPath::Standard,
        );
        let first = escalate(input.clone()).unwrap();
        let second = escalate(input).unwrap();

        assert_eq!(first.id, second.id);
        assert_eq!(first.created, second.created);
        assert_eq!(first.stages_completed, second.stages_completed);
        assert_eq!(first.evidence, second.evidence);
    }

    #[test]
    fn escalate_rejects_placeholder_provenance() {
        let mut input = case_input(
            3,
            40,
            SignalType::AnomalousPattern,
            EscalationPath::Standard,
        );
        input.id = Uuid::nil();
        assert!(escalate(input.clone()).is_err());

        input.id = uuid(3);
        input.signal.evidence_hash = [0u8; 32];
        assert!(escalate(input).is_err());
    }

    #[test]
    fn escalate_sybil() {
        let c = escalate(case_input(
            4,
            75,
            SignalType::SybilSuspicion,
            EscalationPath::SybilAdjudication,
        ))
        .unwrap();
        assert_eq!(c.path, EscalationPath::SybilAdjudication);
        assert_eq!(c.priority, CasePriority::High);
        assert!(c.stages_completed.contains(&"Detection".to_string()));
    }
    #[test]
    fn escalate_emergency() {
        let c = escalate(case_input(
            5,
            95,
            SignalType::EmergencyCondition,
            EscalationPath::Emergency,
        ))
        .unwrap();
        assert_eq!(c.priority, CasePriority::Critical);
    }
    #[test]
    fn escalate_constitutional() {
        let c = escalate(case_input(
            6,
            60,
            SignalType::ConsentViolation,
            EscalationPath::Constitutional,
        ))
        .unwrap();
        assert!(
            c.stages_completed
                .contains(&"constitutional_review".to_string())
        );
    }
    #[test]
    fn priority_from_confidence() {
        assert_eq!(
            escalate(case_input(
                7,
                20,
                SignalType::AnomalousPattern,
                EscalationPath::Standard
            ))
            .unwrap()
            .priority,
            CasePriority::Low
        );
        assert_eq!(
            escalate(case_input(
                8,
                50,
                SignalType::AnomalousPattern,
                EscalationPath::Standard
            ))
            .unwrap()
            .priority,
            CasePriority::Medium
        );
        assert_eq!(
            escalate(case_input(
                9,
                70,
                SignalType::AnomalousPattern,
                EscalationPath::Standard
            ))
            .unwrap()
            .priority,
            CasePriority::High
        );
        assert_eq!(
            escalate(case_input(
                10,
                90,
                SignalType::AnomalousPattern,
                EscalationPath::Standard
            ))
            .unwrap()
            .priority,
            CasePriority::Critical
        );
    }
    #[test]
    fn advance_sybil_stages() {
        let mut c = escalate(case_input(
            11,
            75,
            SignalType::SybilSuspicion,
            EscalationPath::SybilAdjudication,
        ))
        .unwrap();
        assert!(advance_sybil_stage(&mut c, SybilStage::Triage).is_ok());
        assert_eq!(c.status, CaseStatus::InProgress);
        assert!(advance_sybil_stage(&mut c, SybilStage::Quarantine).is_ok());
        assert!(advance_sybil_stage(&mut c, SybilStage::EvidentaryReview).is_ok());
        assert!(advance_sybil_stage(&mut c, SybilStage::ClearanceDowngrade).is_ok());
        assert!(advance_sybil_stage(&mut c, SybilStage::Reinstatement).is_ok());
        assert!(advance_sybil_stage(&mut c, SybilStage::AuditLog).is_ok());
        assert_eq!(c.status, CaseStatus::Resolved);
        assert_eq!(c.stages_completed.len(), 7); // Detection + 6 stages
    }
    #[test]
    fn advance_non_sybil_fails() {
        let mut c = escalate(case_input(
            12,
            50,
            SignalType::AnomalousPattern,
            EscalationPath::Standard,
        ))
        .unwrap();
        assert!(advance_sybil_stage(&mut c, SybilStage::Triage).is_err());
    }

    // ── reinstate() tests ──────────────────────────────────────────────────────

    fn sybil_case_at_clearance_downgrade() -> EscalationCase {
        let mut c = escalate(case_input(
            13,
            80,
            SignalType::SybilSuspicion,
            EscalationPath::SybilAdjudication,
        ))
        .unwrap();
        for stage in [
            SybilStage::Triage,
            SybilStage::Quarantine,
            SybilStage::EvidentaryReview,
            SybilStage::ClearanceDowngrade,
        ] {
            advance_sybil_stage(&mut c, stage).unwrap();
        }
        c
    }

    #[test]
    fn reinstate_requires_nonzero_evidence() {
        let mut c = sybil_case_at_clearance_downgrade();
        assert!(reinstate(&mut c, [0u8; 32]).is_err());
    }

    #[test]
    fn reinstate_with_valid_evidence_succeeds() {
        let mut c = sybil_case_at_clearance_downgrade();
        let evidence = [0xCEu8; 32];
        assert!(reinstate(&mut c, evidence).is_ok());
        assert!(c.stages_completed.contains(&"Reinstatement".to_string()));
        assert!(c.evidence.contains(&evidence));
    }

    #[test]
    fn reinstate_fails_on_non_sybil_path() {
        let mut c = escalate(case_input(
            14,
            50,
            SignalType::AnomalousPattern,
            EscalationPath::Standard,
        ))
        .unwrap();
        assert!(reinstate(&mut c, [0xAAu8; 32]).is_err());
    }
    #[test]
    fn sybil_stage_display() {
        assert_eq!(SybilStage::Detection.to_string(), "Detection");
        assert_eq!(SybilStage::AuditLog.to_string(), "AuditLog");
    }
}
