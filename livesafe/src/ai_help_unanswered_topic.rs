use crate::ai_help_topics::HelpAiSessionOutcome;
use std::collections::{BTreeMap, BTreeSet};

const SEVEN_DAY_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpTopicUnansweredCounterRecord {
    pub session_id: String,
    pub created_at: i64,
    pub outcome: HelpAiSessionOutcome,
    pub cited_topic_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicUnansweredCount {
    pub topic_id: String,
    pub unanswered_count: u32,
    pub confusion_count: u32,
    pub total_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpTopicUnansweredSummary {
    pub window_started_at: i64,
    pub window_ended_at: i64,
    pub topic_counts: Vec<TopicUnansweredCount>,
}

pub fn summarize_unanswered_topics(
    sessions: &[HelpTopicUnansweredCounterRecord],
    now: i64,
) -> HelpTopicUnansweredSummary {
    let window_started_at = now.saturating_sub(SEVEN_DAY_WINDOW_MS).saturating_add(1);
    let mut topic_counts = BTreeMap::<String, (u32, u32)>::new();

    for session in sessions {
        if session.created_at < window_started_at || session.created_at > now {
            continue;
        }

        let (unanswered_delta, confusion_delta) = match session.outcome {
            HelpAiSessionOutcome::Unanswered => (1, 0),
            HelpAiSessionOutcome::ConfusionDetected => (0, 1),
            _ => continue,
        };

        let unique_topics = session
            .cited_topic_ids
            .iter()
            .filter(|topic_id| !topic_id.trim().is_empty())
            .cloned()
            .collect::<BTreeSet<_>>();

        for topic_id in unique_topics {
            let counts = topic_counts.entry(topic_id).or_insert((0, 0));
            counts.0 = saturating_count_add(counts.0, unanswered_delta);
            counts.1 = saturating_count_add(counts.1, confusion_delta);
        }
    }

    let mut topic_counts = topic_counts
        .into_iter()
        .map(
            |(topic_id, (unanswered_count, confusion_count))| TopicUnansweredCount {
                topic_id,
                unanswered_count,
                confusion_count,
                total_count: saturating_count_add(unanswered_count, confusion_count),
            },
        )
        .collect::<Vec<_>>();

    topic_counts.sort_by(|left, right| {
        right
            .total_count
            .cmp(&left.total_count)
            .then_with(|| right.unanswered_count.cmp(&left.unanswered_count))
            .then_with(|| right.confusion_count.cmp(&left.confusion_count))
            .then_with(|| left.topic_id.cmp(&right.topic_id))
    });

    HelpTopicUnansweredSummary {
        window_started_at,
        window_ended_at: now,
        topic_counts,
    }
}

fn saturating_count_add(left: u32, right: u32) -> u32 {
    left.saturating_add(right)
}

#[cfg(test)]
mod tests {
    #[test]
    fn unanswered_display_count_overflow_saturates_at_u32_max() {
        assert_eq!(super::saturating_count_add(u32::MAX, 1), u32::MAX);
    }
}
