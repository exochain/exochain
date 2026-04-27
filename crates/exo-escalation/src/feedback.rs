//! Feedback loop — learn from resolved cases.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A policy improvement recommendation derived from resolved-case feedback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecommendation {
    pub description: String,
    pub source_case_count: usize,
    pub confidence: u8,
}

/// Record of a resolved case outcome and any lessons learned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub case_id: Uuid,
    pub outcome: FeedbackOutcome,
    pub lessons_learned: String,
    pub policy_recommendations: Vec<String>,
}

/// Classification of a resolved case's detection accuracy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedbackOutcome {
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
    Inconclusive,
}

/// Feedback log.
#[derive(Debug, Clone, Default)]
pub struct FeedbackLog {
    pub entries: Vec<FeedbackEntry>,
}

/// Record a feedback entry.
pub fn record_feedback(log: &mut FeedbackLog, entry: FeedbackEntry) {
    log.entries.push(entry);
}

/// Analyze feedback entries and produce policy recommendations.
#[must_use]
pub fn apply_learnings(feedbacks: &[FeedbackEntry]) -> Vec<PolicyRecommendation> {
    if feedbacks.is_empty() {
        return vec![];
    }

    let mut recommendations = Vec::new();

    // Count false positives
    let false_positives = feedbacks
        .iter()
        .filter(|f| f.outcome == FeedbackOutcome::FalsePositive)
        .count();
    let total = feedbacks.len();

    if false_positives > 0 {
        let fp_rate = (false_positives * 100) / total;
        if fp_rate >= 30 {
            recommendations.push(PolicyRecommendation {
                description: "High false positive rate — consider raising confidence thresholds"
                    .into(),
                source_case_count: false_positives,
                confidence: 80,
            });
        }
    }

    // Count false negatives
    let false_negatives = feedbacks
        .iter()
        .filter(|f| f.outcome == FeedbackOutcome::FalseNegative)
        .count();
    if false_negatives > 0 {
        recommendations.push(PolicyRecommendation {
            description: "False negatives detected — consider lowering detection thresholds".into(),
            source_case_count: false_negatives,
            confidence: 70,
        });
    }

    // Aggregate unique recommendations from entries
    let mut seen = std::collections::BTreeSet::new();
    for entry in feedbacks {
        for rec in &entry.policy_recommendations {
            if seen.insert(rec.clone()) {
                recommendations.push(PolicyRecommendation {
                    description: rec.clone(),
                    source_case_count: 1,
                    confidence: 50,
                });
            }
        }
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn entry(outcome: FeedbackOutcome, recs: &[&str]) -> FeedbackEntry {
        FeedbackEntry {
            case_id: uuid(1),
            outcome,
            lessons_learned: "lesson".into(),
            policy_recommendations: recs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn empty_feedbacks_no_recs() {
        assert!(apply_learnings(&[]).is_empty());
    }
    #[test]
    fn record_and_retrieve() {
        let mut log = FeedbackLog::default();
        record_feedback(&mut log, entry(FeedbackOutcome::TruePositive, &[]));
        assert_eq!(log.entries.len(), 1);
    }
    #[test]
    fn high_false_positive_rate_flagged() {
        let entries = vec![
            entry(FeedbackOutcome::FalsePositive, &[]),
            entry(FeedbackOutcome::FalsePositive, &[]),
            entry(FeedbackOutcome::TruePositive, &[]),
        ];
        let recs = apply_learnings(&entries);
        assert!(
            recs.iter()
                .any(|r| r.description.contains("false positive rate"))
        );
    }
    #[test]
    fn false_negatives_flagged() {
        let entries = vec![entry(FeedbackOutcome::FalseNegative, &[])];
        let recs = apply_learnings(&entries);
        assert!(
            recs.iter()
                .any(|r| r.description.contains("False negatives"))
        );
    }
    #[test]
    fn custom_recs_aggregated() {
        let entries = vec![
            entry(FeedbackOutcome::TruePositive, &["add timing check"]),
            entry(
                FeedbackOutcome::TruePositive,
                &["add timing check", "review thresholds"],
            ),
        ];
        let recs = apply_learnings(&entries);
        assert!(recs.iter().any(|r| r.description == "add timing check"));
        assert!(recs.iter().any(|r| r.description == "review thresholds"));
        // "add timing check" should only appear once
        assert_eq!(
            recs.iter()
                .filter(|r| r.description == "add timing check")
                .count(),
            1
        );
    }
    #[test]
    fn all_outcomes() {
        for o in [
            FeedbackOutcome::TruePositive,
            FeedbackOutcome::FalsePositive,
            FeedbackOutcome::TrueNegative,
            FeedbackOutcome::FalseNegative,
            FeedbackOutcome::Inconclusive,
        ] {
            assert_eq!(o, o.clone());
        }
    }
}
