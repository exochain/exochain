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

/// Escalate a detection signal along a specific path.
#[must_use]
pub fn escalate(signal: &DetectionSignal, path: &EscalationPath) -> EscalationCase {
    let priority = match signal.confidence {
        0..=30 => CasePriority::Low,
        31..=60 => CasePriority::Medium,
        61..=85 => CasePriority::High,
        _ => CasePriority::Critical,
    };

    let initial_stage = match path {
        EscalationPath::SybilAdjudication => SybilStage::Detection.to_string(),
        EscalationPath::Emergency => "emergency_activated".to_string(),
        EscalationPath::Constitutional => "constitutional_review".to_string(),
        EscalationPath::Standard => "intake".to_string(),
    };

    EscalationCase {
        id: Uuid::new_v4(),
        path: path.clone(),
        status: CaseStatus::Open,
        priority,
        stages_completed: vec![initial_stage],
        evidence: vec![signal.evidence_hash],
        assignee: None,
        created: Timestamp::now_utc(),
    }
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

    #[test]
    fn escalate_standard() {
        let s = signal(40, SignalType::AnomalousPattern);
        let c = escalate(&s, &EscalationPath::Standard);
        assert_eq!(c.path, EscalationPath::Standard);
        assert_eq!(c.status, CaseStatus::Open);
        assert_eq!(c.priority, CasePriority::Medium);
        assert!(c.stages_completed.contains(&"intake".to_string()));
        assert_eq!(c.evidence, vec![[1u8; 32]]);
    }
    #[test]
    fn escalate_sybil() {
        let s = signal(75, SignalType::SybilSuspicion);
        let c = escalate(&s, &EscalationPath::SybilAdjudication);
        assert_eq!(c.path, EscalationPath::SybilAdjudication);
        assert_eq!(c.priority, CasePriority::High);
        assert!(c.stages_completed.contains(&"Detection".to_string()));
    }
    #[test]
    fn escalate_emergency() {
        let s = signal(95, SignalType::EmergencyCondition);
        let c = escalate(&s, &EscalationPath::Emergency);
        assert_eq!(c.priority, CasePriority::Critical);
    }
    #[test]
    fn escalate_constitutional() {
        let s = signal(60, SignalType::ConsentViolation);
        let c = escalate(&s, &EscalationPath::Constitutional);
        assert!(
            c.stages_completed
                .contains(&"constitutional_review".to_string())
        );
    }
    #[test]
    fn priority_from_confidence() {
        assert_eq!(
            escalate(
                &signal(20, SignalType::AnomalousPattern),
                &EscalationPath::Standard
            )
            .priority,
            CasePriority::Low
        );
        assert_eq!(
            escalate(
                &signal(50, SignalType::AnomalousPattern),
                &EscalationPath::Standard
            )
            .priority,
            CasePriority::Medium
        );
        assert_eq!(
            escalate(
                &signal(70, SignalType::AnomalousPattern),
                &EscalationPath::Standard
            )
            .priority,
            CasePriority::High
        );
        assert_eq!(
            escalate(
                &signal(90, SignalType::AnomalousPattern),
                &EscalationPath::Standard
            )
            .priority,
            CasePriority::Critical
        );
    }
    #[test]
    fn advance_sybil_stages() {
        let s = signal(75, SignalType::SybilSuspicion);
        let mut c = escalate(&s, &EscalationPath::SybilAdjudication);
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
        let s = signal(50, SignalType::AnomalousPattern);
        let mut c = escalate(&s, &EscalationPath::Standard);
        assert!(advance_sybil_stage(&mut c, SybilStage::Triage).is_err());
    }

    // ── reinstate() tests ──────────────────────────────────────────────────────

    fn sybil_case_at_clearance_downgrade() -> EscalationCase {
        let s = signal(80, SignalType::SybilSuspicion);
        let mut c = escalate(&s, &EscalationPath::SybilAdjudication);
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
        let s = signal(50, SignalType::AnomalousPattern);
        let mut c = escalate(&s, &EscalationPath::Standard);
        assert!(reinstate(&mut c, [0xAAu8; 32]).is_err());
    }
    #[test]
    fn sybil_stage_display() {
        assert_eq!(SybilStage::Detection.to_string(), "Detection");
        assert_eq!(SybilStage::AuditLog.to_string(), "AuditLog");
    }
}
