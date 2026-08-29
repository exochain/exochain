use livesafe::ai_help_session_transcript::{
    HelpMessageRole, HelpSessionMessageRecord, HelpSessionRecord, HelpSessionSummaryView,
    HelpSessionTranscriptView, default_help_session_expires_at, find_help_session_transcript,
    list_recent_help_sessions,
};
use livesafe::ai_help_topics::HelpAiSessionOutcome;

fn session(
    id: &str,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    outcome: HelpAiSessionOutcome,
    question_summary: &str,
    topic_ids: &[&str],
) -> HelpSessionRecord {
    HelpSessionRecord {
        session_id: id.into(),
        created_at,
        updated_at,
        expires_at,
        outcome,
        question_summary: question_summary.into(),
        route: Some("/help".into()),
        surface_id: Some("ai-help-panel".into()),
        cited_topic_ids: topic_ids
            .iter()
            .map(|topic_id| (*topic_id).into())
            .collect(),
        generated_feedback_count: 0,
    }
}

fn message(
    session_id: &str,
    role: HelpMessageRole,
    timestamp: i64,
    text: &str,
) -> HelpSessionMessageRecord {
    HelpSessionMessageRecord {
        session_id: session_id.into(),
        role,
        timestamp,
        text: text.into(),
    }
}

#[test]
fn transcript_lookup_enforces_ttl_and_orders_messages_deterministically() {
    let now = 1_717_200_000_000i64;
    let transcript = find_help_session_transcript(
        &[
            session(
                "session:active",
                now - 100_000,
                now - 10_000,
                now + 1_000,
                HelpAiSessionOutcome::Answered,
                "how do i print my card",
                &["emergency-card"],
            ),
            session(
                "session:expired",
                now - 700_000_000,
                now - 699_000_000,
                now - 1,
                HelpAiSessionOutcome::Unanswered,
                "what does verified mean",
                &["trust-state"],
            ),
        ],
        &[
            message(
                "session:active",
                HelpMessageRole::Assistant,
                now - 50_000,
                "Second response",
            ),
            message(
                "session:active",
                HelpMessageRole::User,
                now - 60_000,
                "First question",
            ),
            message(
                "session:active",
                HelpMessageRole::Assistant,
                now + 10_000,
                "Should not appear after expiry",
            ),
            message(
                "session:expired",
                HelpMessageRole::User,
                now - 100_000,
                "Expired session should not be returned",
            ),
        ],
        "session:active",
        now,
    );

    assert_eq!(
        transcript,
        Some(HelpSessionTranscriptView {
            session: HelpSessionSummaryView {
                session_id: "session:active".into(),
                created_at: now - 100_000,
                updated_at: now - 10_000,
                expires_at: now + 1_000,
                outcome: HelpAiSessionOutcome::Answered,
                question_summary: "how do i print my card".into(),
                route: Some("/help".into()),
                surface_id: Some("ai-help-panel".into()),
                cited_topic_ids: vec!["emergency-card".into()],
                generated_feedback_count: 0,
            },
            messages: vec![
                message(
                    "session:active",
                    HelpMessageRole::User,
                    now - 60_000,
                    "First question",
                ),
                message(
                    "session:active",
                    HelpMessageRole::Assistant,
                    now - 50_000,
                    "Second response",
                ),
            ],
        })
    );

    assert_eq!(
        find_help_session_transcript(&[], &[], "session:expired", now),
        None
    );
}

#[test]
fn recent_session_index_filters_expired_entries_and_orders_ties_consistently() {
    let now = 1_717_200_000_000i64;
    let recent = list_recent_help_sessions(
        &[
            session(
                "session:beta",
                now - 40_000,
                now - 5_000,
                now + 10_000,
                HelpAiSessionOutcome::BugIndicated,
                "beta question",
                &["marketplace-templates"],
            ),
            session(
                "session:alpha",
                now - 50_000,
                now - 5_000,
                now + 10_000,
                HelpAiSessionOutcome::ConfusionDetected,
                "alpha question",
                &["pace-contacts"],
            ),
            session(
                "session:expired",
                now - 60_000,
                now - 6_000,
                now - 1,
                HelpAiSessionOutcome::Unanswered,
                "expired question",
                &["trust-state"],
            ),
        ],
        now,
        10,
    );

    assert_eq!(
        recent,
        vec![
            HelpSessionSummaryView {
                session_id: "session:beta".into(),
                created_at: now - 40_000,
                updated_at: now - 5_000,
                expires_at: now + 10_000,
                outcome: HelpAiSessionOutcome::BugIndicated,
                question_summary: "beta question".into(),
                route: Some("/help".into()),
                surface_id: Some("ai-help-panel".into()),
                cited_topic_ids: vec!["marketplace-templates".into()],
                generated_feedback_count: 0,
            },
            HelpSessionSummaryView {
                session_id: "session:alpha".into(),
                created_at: now - 50_000,
                updated_at: now - 5_000,
                expires_at: now + 10_000,
                outcome: HelpAiSessionOutcome::ConfusionDetected,
                question_summary: "alpha question".into(),
                route: Some("/help".into()),
                surface_id: Some("ai-help-panel".into()),
                cited_topic_ids: vec!["pace-contacts".into()],
                generated_feedback_count: 0,
            },
        ]
    );
}

#[test]
fn default_session_expiry_saturates_on_timestamp_overflow() {
    assert_eq!(default_help_session_expires_at(i64::MAX), i64::MAX);
    assert_eq!(default_help_session_expires_at(0), 7 * 24 * 60 * 60 * 1_000);
}
