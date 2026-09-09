use livesafe::ai_help_topics::HelpAiSessionOutcome;
use livesafe::ai_help_unanswered_topic::{
    HelpTopicUnansweredCounterRecord, HelpTopicUnansweredSummary, TopicUnansweredCount,
    summarize_unanswered_topics,
};

fn record(
    session_id: &str,
    created_at: i64,
    outcome: HelpAiSessionOutcome,
    topic_ids: &[&str],
) -> HelpTopicUnansweredCounterRecord {
    HelpTopicUnansweredCounterRecord {
        session_id: session_id.into(),
        created_at,
        outcome,
        cited_topic_ids: topic_ids
            .iter()
            .map(|topic_id| (*topic_id).into())
            .collect(),
    }
}

#[test]
fn unanswered_topic_summary_filters_to_seven_days_and_counts_only_unresolved_outcomes() {
    let now = 1_717_200_000_000i64;

    let summary = summarize_unanswered_topics(
        &[
            record(
                "session:unanswered",
                now - 60_000,
                HelpAiSessionOutcome::Unanswered,
                &["trust-state", "emergency-card"],
            ),
            record(
                "session:confusion",
                now - 30_000,
                HelpAiSessionOutcome::ConfusionDetected,
                &["trust-state"],
            ),
            record(
                "session:answered",
                now - 15_000,
                HelpAiSessionOutcome::Answered,
                &["trust-state"],
            ),
            record(
                "session:bug",
                now - 10_000,
                HelpAiSessionOutcome::BugIndicated,
                &["pace-contacts"],
            ),
            record(
                "session:expired",
                now - (7 * 24 * 60 * 60 * 1_000) - 1,
                HelpAiSessionOutcome::Unanswered,
                &["legacy-charter"],
            ),
        ],
        now,
    );

    assert_eq!(
        summary,
        HelpTopicUnansweredSummary {
            window_started_at: now - (7 * 24 * 60 * 60 * 1_000) + 1,
            window_ended_at: now,
            topic_counts: vec![
                TopicUnansweredCount {
                    topic_id: "trust-state".into(),
                    unanswered_count: 1,
                    confusion_count: 1,
                    total_count: 2,
                },
                TopicUnansweredCount {
                    topic_id: "emergency-card".into(),
                    unanswered_count: 1,
                    confusion_count: 0,
                    total_count: 1,
                },
            ],
        }
    );
}

#[test]
fn unanswered_topic_summary_orders_ties_by_topic_and_deduplicates_session_topic_pairs() {
    let now = 1_717_200_000_000i64;

    let summary = summarize_unanswered_topics(
        &[
            record(
                "session:one",
                now - 20_000,
                HelpAiSessionOutcome::ConfusionDetected,
                &["zeta-topic", "alpha-topic", "alpha-topic"],
            ),
            record(
                "session:two",
                now - 10_000,
                HelpAiSessionOutcome::Unanswered,
                &["zeta-topic"],
            ),
            record(
                "session:future",
                now + 1,
                HelpAiSessionOutcome::Unanswered,
                &["future-topic"],
            ),
        ],
        now,
    );

    assert_eq!(
        summary.topic_counts,
        vec![
            TopicUnansweredCount {
                topic_id: "zeta-topic".into(),
                unanswered_count: 1,
                confusion_count: 1,
                total_count: 2,
            },
            TopicUnansweredCount {
                topic_id: "alpha-topic".into(),
                unanswered_count: 0,
                confusion_count: 1,
                total_count: 1,
            },
        ]
    );
}

#[test]
fn unanswered_topic_summary_saturates_timestamp_overflow() {
    let summary = summarize_unanswered_topics(&[], i64::MIN);

    assert_eq!(summary.window_started_at, i64::MIN + 1);
    assert_eq!(summary.window_ended_at, i64::MIN);
    assert!(summary.topic_counts.is_empty());
}
