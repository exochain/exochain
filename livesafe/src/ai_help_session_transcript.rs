use crate::ai_help_topics::HelpAiSessionOutcome;

pub const DEFAULT_HELP_SESSION_TTL_HOURS: i64 = 168;
const MS_PER_HOUR: i64 = 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HelpMessageRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpSessionRecord {
    pub session_id: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub outcome: HelpAiSessionOutcome,
    pub question_summary: String,
    pub route: Option<String>,
    pub surface_id: Option<String>,
    pub cited_topic_ids: Vec<String>,
    pub generated_feedback_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpSessionMessageRecord {
    pub session_id: String,
    pub role: HelpMessageRole,
    pub text: String,
    pub timestamp: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpSessionSummaryView {
    pub session_id: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub outcome: HelpAiSessionOutcome,
    pub question_summary: String,
    pub route: Option<String>,
    pub surface_id: Option<String>,
    pub cited_topic_ids: Vec<String>,
    pub generated_feedback_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpSessionTranscriptView {
    pub session: HelpSessionSummaryView,
    pub messages: Vec<HelpSessionMessageRecord>,
}

pub fn default_help_session_expires_at(created_at: i64) -> i64 {
    created_at.saturating_add(DEFAULT_HELP_SESSION_TTL_HOURS * MS_PER_HOUR)
}

pub fn find_help_session_transcript(
    sessions: &[HelpSessionRecord],
    messages: &[HelpSessionMessageRecord],
    session_id: &str,
    now: i64,
) -> Option<HelpSessionTranscriptView> {
    let session = sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .filter(|session| is_active(session, now))?;

    let mut session_messages = messages
        .iter()
        .filter(|message| message.session_id == session.session_id)
        .filter(|message| message.timestamp >= session.created_at)
        .filter(|message| message.timestamp <= session.expires_at)
        .cloned()
        .collect::<Vec<_>>();
    session_messages.sort_by(|left, right| {
        left.timestamp
            .cmp(&right.timestamp)
            .then_with(|| left.role.cmp(&right.role))
            .then_with(|| left.text.cmp(&right.text))
    });

    Some(HelpSessionTranscriptView {
        session: summary_view(session),
        messages: session_messages,
    })
}

pub fn list_recent_help_sessions(
    sessions: &[HelpSessionRecord],
    now: i64,
    limit: usize,
) -> Vec<HelpSessionSummaryView> {
    let mut active_sessions = sessions
        .iter()
        .filter(|session| is_active(session, now))
        .map(summary_view)
        .collect::<Vec<_>>();
    active_sessions.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| right.created_at.cmp(&left.created_at))
            .then_with(|| left.session_id.cmp(&right.session_id))
    });
    active_sessions.truncate(limit);
    active_sessions
}

fn is_active(session: &HelpSessionRecord, now: i64) -> bool {
    session.created_at <= now && session.expires_at >= now
}

fn summary_view(session: &HelpSessionRecord) -> HelpSessionSummaryView {
    HelpSessionSummaryView {
        session_id: session.session_id.clone(),
        created_at: session.created_at,
        updated_at: session.updated_at,
        expires_at: session.expires_at,
        outcome: session.outcome,
        question_summary: session.question_summary.clone(),
        route: session.route.clone(),
        surface_id: session.surface_id.clone(),
        cited_topic_ids: session.cited_topic_ids.clone(),
        generated_feedback_count: session.generated_feedback_count,
    }
}
