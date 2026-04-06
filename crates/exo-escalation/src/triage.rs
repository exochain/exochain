//! Triage engine.

use exo_core::Timestamp;
use serde::{Deserialize, Serialize};

use crate::detector::{Severity, ThreatAssessment};

/// Degree of human oversight required for a triaged threat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageLevel {
    Automatic,
    Supervised,
    ManualRequired,
    EmergencyHuman,
}

/// Concrete action the triage engine can prescribe for a threat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageAction {
    Log,
    Alert,
    Quarantine,
    Suspend,
    Escalate,
    Shutdown,
}

/// Named reference to an escalation pathway used by triage decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPathSpec {
    pub name: String,
}

/// Output of the triage engine: oversight level, actions, timeout, and optional escalation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageDecision {
    pub level: TriageLevel,
    pub actions: Vec<TriageAction>,
    pub timeout: Timestamp,
    pub escalation_path: Option<EscalationPathSpec>,
}

/// Triage based on severity: Low->Automatic, Medium->Supervised, High->ManualRequired, Critical->EmergencyHuman
#[must_use]
pub fn triage(assessment: &ThreatAssessment) -> TriageDecision {
    match assessment.overall_severity {
        Severity::Low => TriageDecision {
            level: TriageLevel::Automatic,
            actions: vec![TriageAction::Log],
            timeout: Timestamp::new(3_600_000, 0), // 1 hour
            escalation_path: None,
        },
        Severity::Medium => TriageDecision {
            level: TriageLevel::Supervised,
            actions: vec![TriageAction::Log, TriageAction::Alert],
            timeout: Timestamp::new(1_800_000, 0), // 30 min
            escalation_path: Some(EscalationPathSpec {
                name: "standard".into(),
            }),
        },
        Severity::High => TriageDecision {
            level: TriageLevel::ManualRequired,
            actions: vec![TriageAction::Alert, TriageAction::Quarantine],
            timeout: Timestamp::new(900_000, 0), // 15 min
            escalation_path: Some(EscalationPathSpec {
                name: "sybil_adjudication".into(),
            }),
        },
        Severity::Critical => TriageDecision {
            level: TriageLevel::EmergencyHuman,
            actions: vec![
                TriageAction::Suspend,
                TriageAction::Escalate,
                TriageAction::Shutdown,
            ],
            timeout: Timestamp::new(300_000, 0), // 5 min
            escalation_path: Some(EscalationPathSpec {
                name: "emergency".into(),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::*;

    fn assessment(severity: Severity) -> ThreatAssessment {
        ThreatAssessment {
            overall_severity: severity,
            recommended_action: RecommendedAction::Monitor,
            signals: vec![],
        }
    }

    #[test]
    fn low_automatic() {
        let d = triage(&assessment(Severity::Low));
        assert_eq!(d.level, TriageLevel::Automatic);
        assert!(d.actions.contains(&TriageAction::Log));
        assert!(d.escalation_path.is_none());
    }
    #[test]
    fn medium_supervised() {
        let d = triage(&assessment(Severity::Medium));
        assert_eq!(d.level, TriageLevel::Supervised);
        assert!(d.actions.contains(&TriageAction::Alert));
        assert!(d.escalation_path.is_some());
    }
    #[test]
    fn high_manual() {
        let d = triage(&assessment(Severity::High));
        assert_eq!(d.level, TriageLevel::ManualRequired);
        assert!(d.actions.contains(&TriageAction::Quarantine));
    }
    #[test]
    fn critical_emergency() {
        let d = triage(&assessment(Severity::Critical));
        assert_eq!(d.level, TriageLevel::EmergencyHuman);
        assert!(d.actions.contains(&TriageAction::Shutdown));
        assert!(d.actions.contains(&TriageAction::Escalate));
    }
    #[test]
    fn all_levels_constructible() {
        for l in [
            TriageLevel::Automatic,
            TriageLevel::Supervised,
            TriageLevel::ManualRequired,
            TriageLevel::EmergencyHuman,
        ] {
            assert_eq!(l, l.clone());
        }
    }
}
