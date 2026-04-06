//! Anomaly/threat detection.

use exo_core::Timestamp;
use serde::{Deserialize, Serialize};

/// Classification of anomaly or threat signals detected in governance events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalType {
    SybilSuspicion,
    UnauthorizedAccess,
    ConsentViolation,
    InvariantBreach,
    AnomalousPattern,
    EmergencyCondition,
}

/// confidence is u8 0-100, NOT float — deterministic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub source: String,
    pub signal_type: SignalType,
    pub confidence: u8,
    pub evidence_hash: [u8; 32],
    pub timestamp: Timestamp,
}

/// Severity level assigned to a threat assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Action recommended by the threat evaluation engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    Monitor,
    Investigate,
    Quarantine,
    EmergencyShutdown,
}

/// Aggregated threat assessment produced by evaluating one or more detection signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub overall_severity: Severity,
    pub recommended_action: RecommendedAction,
    pub signals: Vec<DetectionSignal>,
}

/// Evaluate a set of detection signals into a threat assessment.
#[must_use]
pub fn evaluate_signals(signals: &[DetectionSignal]) -> ThreatAssessment {
    if signals.is_empty() {
        return ThreatAssessment {
            overall_severity: Severity::Low,
            recommended_action: RecommendedAction::Monitor,
            signals: vec![],
        };
    }

    // Find max confidence and check for emergency signals
    let max_confidence = signals.iter().map(|s| s.confidence).max().unwrap_or(0);
    let has_emergency = signals
        .iter()
        .any(|s| s.signal_type == SignalType::EmergencyCondition);
    let has_sybil = signals
        .iter()
        .any(|s| s.signal_type == SignalType::SybilSuspicion);
    let signal_count = signals.len();

    let (severity, action) = if has_emergency || max_confidence >= 90 {
        (Severity::Critical, RecommendedAction::EmergencyShutdown)
    } else if has_sybil && max_confidence >= 70 || max_confidence >= 80 {
        (Severity::High, RecommendedAction::Quarantine)
    } else if signal_count >= 3 || max_confidence >= 50 {
        (Severity::Medium, RecommendedAction::Investigate)
    } else {
        (Severity::Low, RecommendedAction::Monitor)
    };

    ThreatAssessment {
        overall_severity: severity,
        recommended_action: action,
        signals: signals.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(st: SignalType, confidence: u8) -> DetectionSignal {
        DetectionSignal {
            source: "test".into(),
            signal_type: st,
            confidence,
            evidence_hash: [0u8; 32],
            timestamp: Timestamp::new(1000, 0),
        }
    }

    #[test]
    fn empty_signals_low() {
        let a = evaluate_signals(&[]);
        assert_eq!(a.overall_severity, Severity::Low);
        assert_eq!(a.recommended_action, RecommendedAction::Monitor);
    }
    #[test]
    fn low_confidence_low_severity() {
        let a = evaluate_signals(&[signal(SignalType::AnomalousPattern, 20)]);
        assert_eq!(a.overall_severity, Severity::Low);
    }
    #[test]
    fn medium_confidence_investigate() {
        let a = evaluate_signals(&[signal(SignalType::AnomalousPattern, 55)]);
        assert_eq!(a.overall_severity, Severity::Medium);
        assert_eq!(a.recommended_action, RecommendedAction::Investigate);
    }
    #[test]
    fn high_confidence_quarantine() {
        let a = evaluate_signals(&[signal(SignalType::UnauthorizedAccess, 85)]);
        assert_eq!(a.overall_severity, Severity::High);
        assert_eq!(a.recommended_action, RecommendedAction::Quarantine);
    }
    #[test]
    fn emergency_is_critical() {
        let a = evaluate_signals(&[signal(SignalType::EmergencyCondition, 50)]);
        assert_eq!(a.overall_severity, Severity::Critical);
        assert_eq!(a.recommended_action, RecommendedAction::EmergencyShutdown);
    }
    #[test]
    fn sybil_high_confidence_quarantine() {
        let a = evaluate_signals(&[signal(SignalType::SybilSuspicion, 75)]);
        assert_eq!(a.overall_severity, Severity::High);
        assert_eq!(a.recommended_action, RecommendedAction::Quarantine);
    }
    #[test]
    fn multiple_low_signals_escalate() {
        let a = evaluate_signals(&[
            signal(SignalType::AnomalousPattern, 30),
            signal(SignalType::AnomalousPattern, 35),
            signal(SignalType::ConsentViolation, 40),
        ]);
        assert_eq!(a.overall_severity, Severity::Medium);
    }
    #[test]
    fn very_high_confidence_critical() {
        let a = evaluate_signals(&[signal(SignalType::InvariantBreach, 95)]);
        assert_eq!(a.overall_severity, Severity::Critical);
    }
    #[test]
    fn signals_preserved_in_assessment() {
        let sigs = vec![signal(SignalType::AnomalousPattern, 20)];
        let a = evaluate_signals(&sigs);
        assert_eq!(a.signals.len(), 1);
    }
    #[test]
    fn all_signal_types() {
        for st in [
            SignalType::SybilSuspicion,
            SignalType::UnauthorizedAccess,
            SignalType::ConsentViolation,
            SignalType::InvariantBreach,
            SignalType::AnomalousPattern,
            SignalType::EmergencyCondition,
        ] {
            let s = signal(st, 50);
            assert_eq!(s.confidence, 50);
        }
    }
}
