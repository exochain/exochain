use livesafe::ai_help_topics::HelpAiSessionOutcome;
use livesafe::ai_help_usage_summary::{
    HelpUsageSessionRecord, HelpUsageSummary, TopicUsageCount, summarize_help_usage,
};
use std::collections::BTreeMap;

fn session(
    id: &str,
    created_at: i64,
    outcome: HelpAiSessionOutcome,
    topic_ids: &[&str],
    question: &str,
    generated_feedback_count: u32,
) -> HelpUsageSessionRecord {
    HelpUsageSessionRecord {
        session_id: id.into(),
        created_at,
        outcome,
        cited_topic_ids: topic_ids
            .iter()
            .map(|topic_id| (*topic_id).into())
            .collect(),
        normalized_question: question.into(),
        generated_feedback_count,
    }
}

#[test]
fn usage_summary_filters_to_seven_days_and_aggregates_outcomes_topics_and_feedback() {
    let now = 1_717_200_000_000i64;
    let summary = summarize_help_usage(
        &[
            session(
                "session:recent-1",
                now - 60_000,
                HelpAiSessionOutcome::Answered,
                &["emergency-card"],
                "how do i print my card",
                0,
            ),
            session(
                "session:recent-2",
                now - 120_000,
                HelpAiSessionOutcome::ConfusionDetected,
                &["pace-contacts", "emergency-card"],
                "how do i invite my pace contact",
                2,
            ),
            session(
                "session:expired",
                now - (7 * 24 * 60 * 60 * 1_000) - 1,
                HelpAiSessionOutcome::Unanswered,
                &["trust-state"],
                "what does verified mean",
                1,
            ),
        ],
        now,
    );

    assert_eq!(
        summary,
        HelpUsageSummary {
            window_started_at: now - (7 * 24 * 60 * 60 * 1_000) + 1,
            window_ended_at: now,
            total_sessions: 2,
            generated_feedback_count: 2,
            outcome_counts: BTreeMap::from([
                (HelpAiSessionOutcome::Answered, 1),
                (HelpAiSessionOutcome::ConfusionDetected, 1),
            ]),
            topic_counts: vec![
                TopicUsageCount {
                    topic_id: "emergency-card".into(),
                    count: 2,
                },
                TopicUsageCount {
                    topic_id: "pace-contacts".into(),
                    count: 1,
                },
            ],
            top_questions: vec![
                ("how do i invite my pace contact".into(), 1),
                ("how do i print my card".into(), 1),
            ],
            unresolved_topics: vec!["emergency-card".into(), "pace-contacts".into()],
        }
    );
}

#[test]
fn usage_summary_normalizes_question_keys_and_orders_ties_deterministically() {
    let now = 1_717_200_000_000i64;
    let summary = summarize_help_usage(
        &[
            session(
                "session:1",
                now - 5_000,
                HelpAiSessionOutcome::BugIndicated,
                &["marketplace-templates"],
                "How do I use Marketplace templates?",
                1,
            ),
            session(
                "session:2",
                now - 4_000,
                HelpAiSessionOutcome::BugIndicated,
                &["marketplace-templates"],
                " how do i use marketplace templates ",
                1,
            ),
            session(
                "session:3",
                now - 3_000,
                HelpAiSessionOutcome::PrivacySafetyRisk,
                &["trust-state"],
                "What trust state is shown?",
                1,
            ),
        ],
        now,
    );

    assert_eq!(summary.total_sessions, 3);
    assert_eq!(summary.generated_feedback_count, 3);
    assert_eq!(
        summary.top_questions,
        vec![
            ("how do i use marketplace templates".into(), 2),
            ("what trust state is shown".into(), 1),
        ]
    );
    assert_eq!(
        summary.topic_counts,
        vec![
            TopicUsageCount {
                topic_id: "marketplace-templates".into(),
                count: 2,
            },
            TopicUsageCount {
                topic_id: "trust-state".into(),
                count: 1,
            },
        ]
    );
    assert_eq!(
        summary.unresolved_topics,
        vec![
            "marketplace-templates".to_string(),
            "trust-state".to_string(),
        ]
    );
}

#[test]
fn usage_summary_saturates_timestamp_and_feedback_overflow() {
    let timestamp_floor = summarize_help_usage(&[], i64::MIN);
    assert_eq!(timestamp_floor.window_started_at, i64::MIN + 1);
    assert_eq!(timestamp_floor.window_ended_at, i64::MIN);

    let summary = summarize_help_usage(
        &[
            session(
                "session:max-feedback",
                0,
                HelpAiSessionOutcome::Unanswered,
                &["trust-state"],
                "What does trust state mean?",
                u32::MAX,
            ),
            session(
                "session:one-more-feedback",
                1,
                HelpAiSessionOutcome::ConfusionDetected,
                &["trust-state"],
                "What does trust state mean?",
                1,
            ),
        ],
        1,
    );

    assert_eq!(summary.generated_feedback_count, u32::MAX);
    assert_eq!(summary.total_sessions, 2);
    assert_eq!(
        summary.outcome_counts,
        BTreeMap::from([
            (HelpAiSessionOutcome::Unanswered, 1),
            (HelpAiSessionOutcome::ConfusionDetected, 1),
        ])
    );
    assert_eq!(
        summary.topic_counts,
        vec![TopicUsageCount {
            topic_id: "trust-state".into(),
            count: 2,
        }]
    );
    assert_eq!(
        summary.top_questions,
        vec![("what does trust state mean".into(), 2)]
    );
    assert_eq!(summary.unresolved_topics, vec!["trust-state".to_string()]);
}
