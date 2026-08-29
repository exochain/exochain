use crate::ai_help_topics::HelpAiSessionOutcome;
use std::collections::BTreeMap;

const SEVEN_DAY_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpUsageSessionRecord {
    pub session_id: String,
    pub created_at: i64,
    pub outcome: HelpAiSessionOutcome,
    pub cited_topic_ids: Vec<String>,
    pub normalized_question: String,
    pub generated_feedback_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicUsageCount {
    pub topic_id: String,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpUsageSummary {
    pub window_started_at: i64,
    pub window_ended_at: i64,
    pub total_sessions: usize,
    pub generated_feedback_count: u32,
    pub outcome_counts: BTreeMap<HelpAiSessionOutcome, u32>,
    pub topic_counts: Vec<TopicUsageCount>,
    pub top_questions: Vec<(String, u32)>,
    pub unresolved_topics: Vec<String>,
}

pub fn summarize_help_usage(sessions: &[HelpUsageSessionRecord], now: i64) -> HelpUsageSummary {
    let window_started_at = seven_day_window_start(now);
    let mut outcome_counts = BTreeMap::<HelpAiSessionOutcome, u32>::new();
    let mut topic_counts = BTreeMap::<String, u32>::new();
    let mut question_counts = BTreeMap::<String, u32>::new();
    let mut generated_feedback_count = 0u32;
    let mut total_sessions = 0usize;

    for session in sessions {
        if session.created_at < window_started_at || session.created_at > now {
            continue;
        }

        total_sessions = total_sessions.saturating_add(1);
        generated_feedback_count =
            generated_feedback_count.saturating_add(session.generated_feedback_count);
        let outcome_count = outcome_counts.entry(session.outcome).or_default();
        *outcome_count = saturating_count_add(*outcome_count, 1);

        let normalized_question = normalize_question(&session.normalized_question);
        if !normalized_question.is_empty() {
            let question_count = question_counts.entry(normalized_question).or_default();
            *question_count = saturating_count_add(*question_count, 1);
        }

        for topic_id in &session.cited_topic_ids {
            let topic_count = topic_counts.entry(topic_id.clone()).or_default();
            *topic_count = saturating_count_add(*topic_count, 1);
        }
    }

    let mut topic_counts = topic_counts
        .into_iter()
        .map(|(topic_id, count)| TopicUsageCount { topic_id, count })
        .collect::<Vec<_>>();
    topic_counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.topic_id.cmp(&right.topic_id))
    });

    let mut top_questions = question_counts.into_iter().collect::<Vec<_>>();
    top_questions.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let unresolved_topics = topic_counts
        .iter()
        .filter(|topic| {
            topic_counts_for_outcomes(
                sessions,
                now,
                &topic.topic_id,
                &[
                    HelpAiSessionOutcome::Unanswered,
                    HelpAiSessionOutcome::ConfusionDetected,
                    HelpAiSessionOutcome::BugIndicated,
                    HelpAiSessionOutcome::PrivacySafetyRisk,
                ],
            ) > 0
        })
        .map(|topic| topic.topic_id.clone())
        .collect();

    HelpUsageSummary {
        window_started_at,
        window_ended_at: now,
        total_sessions,
        generated_feedback_count,
        outcome_counts,
        topic_counts,
        top_questions,
        unresolved_topics,
    }
}

fn topic_counts_for_outcomes(
    sessions: &[HelpUsageSessionRecord],
    now: i64,
    topic_id: &str,
    outcomes: &[HelpAiSessionOutcome],
) -> u32 {
    let window_started_at = seven_day_window_start(now);
    let count = sessions
        .iter()
        .filter(|session| session.created_at >= window_started_at && session.created_at <= now)
        .filter(|session| outcomes.contains(&session.outcome))
        .filter(|session| {
            session
                .cited_topic_ids
                .iter()
                .any(|entry| entry == topic_id)
        })
        .count();
    summary_count(count)
}

fn seven_day_window_start(now: i64) -> i64 {
    now.saturating_sub(SEVEN_DAY_WINDOW_MS).saturating_add(1)
}

fn summary_count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn saturating_count_add(left: u32, right: u32) -> u32 {
    left.saturating_add(right)
}

fn normalize_question(input: &str) -> String {
    input
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn map_counter_overflow_saturates_at_u32_max() {
        assert_eq!(super::saturating_count_add(u32::MAX, 1), u32::MAX);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn collection_count_overflow_saturates_at_u32_max() {
        let first_unrepresentable =
            usize::try_from(u64::from(u32::MAX) + 1).expect("64-bit usize represents u32::MAX + 1");

        assert_eq!(super::summary_count(first_unrepresentable), u32::MAX);
    }
}
