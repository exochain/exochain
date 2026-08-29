use crate::ai_help_topics::HelpAiSessionOutcome;
use std::collections::{BTreeMap, BTreeSet};

const MAX_TITLE_LEN: usize = 200;
const MAX_BODY_LEN: usize = 5_000;
const INTERNAL_UPVOTE_VOTERS_KEY: &str = "_systemUpvoteVoters";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeedbackTargetType {
    OnboardingStep,
    PaceContact,
    IceCard,
    QrActivation,
    ResponderView,
    EmergencyProfile,
    MedicalJacket,
    GenotypicalImport,
    ConsentControl,
    VaultRecord,
    AmbientSignal,
    MarketplaceTemplate,
    EntitlementPlan,
    FrontlineEligibility,
    TrustState,
    UiComponent,
    General,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeedbackStatus {
    New,
    Backlog,
    Planning,
    Development,
    Testing,
    Validation,
    Deployed,
    Held,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeedbackPriority {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeedbackCategory {
    Bug,
    FeatureRequest,
    DocumentationGap,
    DataQuality,
    UiUx,
    Performance,
    EntitlementBilling,
    PrivacySafety,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackRating {
    Correct,
    Incorrect,
    Ambiguous,
    Helpful,
    NotHelpful,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackActivityAction {
    Created,
    StatusChanged,
    Commented,
    Rejected,
    Accepted,
    Upvoted,
    HoldSet,
    HoldReleased,
    AgentDispatched,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataValue {
    Bool(bool),
    Number(i64),
    Text(String),
    List(Vec<MetadataValue>),
    Map(BTreeMap<String, MetadataValue>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackItem {
    pub id: String,
    pub target_type: FeedbackTargetType,
    pub target_id: String,
    pub target_label: String,
    pub status: FeedbackStatus,
    pub hold_tag: Option<String>,
    pub priority: FeedbackPriority,
    pub category: FeedbackCategory,
    pub sprint_tag: Option<String>,
    pub title: String,
    pub body: String,
    pub rating: Option<FeedbackRating>,
    pub upvotes: u32,
    pub author: String,
    pub metadata: BTreeMap<String, MetadataValue>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_dispatch_at: Option<i64>,
}

impl FeedbackItem {
    pub fn release_hold(self, input: ReleaseHoldInput) -> Result<HoldReleaseResult, String> {
        if self.status != FeedbackStatus::Held {
            return Err("Only held feedback items can be released.".into());
        }

        if input.restored_status == FeedbackStatus::Held {
            return Err("Held feedback items must release into an active workflow status.".into());
        }

        let mut updated_item = self;
        updated_item.status = input.restored_status;
        updated_item.hold_tag = None;
        updated_item.updated_at = input.changed_at;

        Ok(HoldReleaseResult {
            updated_item: updated_item.clone(),
            activity: FeedbackActivity {
                id: format!("activity:{}:{}", updated_item.id, input.changed_at),
                feedback_id: updated_item.id.clone(),
                action: FeedbackActivityAction::HoldReleased,
                from_status: Some(FeedbackStatus::Held),
                to_status: Some(input.restored_status),
                note: input.note,
                author: input.author,
                created_at: input.changed_at,
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackActivity {
    pub id: String,
    pub feedback_id: String,
    pub action: FeedbackActivityAction,
    pub from_status: Option<FeedbackStatus>,
    pub to_status: Option<FeedbackStatus>,
    pub note: Option<String>,
    pub author: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackDecision {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub required_evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackDispatchPayload {
    pub feedback_id: String,
    pub previous_status: FeedbackStatus,
    pub new_status: FeedbackStatus,
    pub note: Option<String>,
    pub author: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentDispatchDecision {
    NotTriggered,
    RateLimited,
    Triggered(FeedbackDispatchPayload),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDispatchConfig {
    pub enabled: bool,
    pub trigger_statuses: Vec<FeedbackStatus>,
    pub dispatch_cooldown_ms: i64,
}

impl AgentDispatchConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            trigger_statuses: vec![FeedbackStatus::Development],
            dispatch_cooldown_ms: 3_600_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusChangeInput {
    pub new_status: FeedbackStatus,
    pub author: String,
    pub note: Option<String>,
    pub changed_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusTransitionResult {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub updated_item: FeedbackItem,
    pub activity: FeedbackActivity,
    pub dispatch: AgentDispatchDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseHoldInput {
    pub restored_status: FeedbackStatus,
    pub author: String,
    pub note: Option<String>,
    pub changed_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldReleaseResult {
    pub updated_item: FeedbackItem,
    pub activity: FeedbackActivity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpvoteInput {
    pub voter: String,
    pub voted_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpvoteResult {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub updated_item: FeedbackItem,
    pub activity: Option<FeedbackActivity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelpSessionReport {
    pub session_id: String,
    pub outcome: HelpAiSessionOutcome,
    pub context_topic_id: Option<String>,
    pub normalized_question: String,
    pub question_excerpt: String,
    pub cited_topic_ids: Vec<String>,
    pub route: Option<String>,
    pub surface_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DailySummaryTotals {
    pub total_sessions: u32,
    pub generated_feedback_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MandatedReporterConfig {
    pub unanswered_threshold: u32,
    pub current_topic_failures: u32,
    pub daily_summary_date: Option<String>,
    pub daily_summary_totals: Option<DailySummaryTotals>,
}

impl Default for MandatedReporterConfig {
    fn default() -> Self {
        Self {
            unanswered_threshold: 3,
            current_topic_failures: 0,
            daily_summary_date: None,
            daily_summary_totals: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MandatedReportResult {
    pub generated_item: Option<FeedbackItem>,
    pub updated_item: Option<FeedbackItem>,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SystemFeedbackDraft {
    id: String,
    category: FeedbackCategory,
    priority: FeedbackPriority,
    target_id: String,
    target_label: String,
    title: String,
    body: String,
    metadata: BTreeMap<String, MetadataValue>,
}

pub fn validate_feedback_item(item: &FeedbackItem) -> FeedbackDecision {
    let mut reasons = BTreeSet::new();
    let mut required_evidence = BTreeSet::new();

    if item.id.trim().is_empty()
        || item.target_id.trim().is_empty()
        || item.target_label.trim().is_empty()
    {
        reasons.insert(
            "Feedback items require non-empty synthetic identifiers and target labels.".into(),
        );
        required_evidence.insert("Synthetic feedback id, target id, and target label.".into());
    }

    if item.title.trim().is_empty() || item.title.chars().count() > MAX_TITLE_LEN {
        reasons.insert("Feedback titles must be present and at most 200 characters.".into());
        required_evidence.insert("Bounded short title for every feedback item.".into());
    }

    if item.body.trim().is_empty() || item.body.chars().count() > MAX_BODY_LEN {
        reasons.insert("Feedback bodies must be present and at most 5000 characters.".into());
        required_evidence.insert("Bounded markdown body for every feedback item.".into());
    }

    if metadata_contains_unsafe_content(&item.metadata) {
        reasons.insert("Feedback metadata must reject raw sensitive fields, raw QR payloads, payment secrets, eligibility documents, and unsafe screenshots.".into());
        required_evidence.insert("Redacted metadata and screenshot references only.".into());
    }

    if item.status == FeedbackStatus::Held && empty_option(&item.hold_tag) {
        reasons.insert("Held feedback items require a hold reason.".into());
        required_evidence.insert("Hold reason for any parked feedback item.".into());
    }

    FeedbackDecision {
        allowed: reasons.is_empty(),
        reasons: reasons.into_iter().collect(),
        required_evidence: required_evidence.into_iter().collect(),
    }
}

pub fn evaluate_status_transition(
    item: FeedbackItem,
    input: StatusChangeInput,
    dispatch_config: AgentDispatchConfig,
) -> StatusTransitionResult {
    let mut reasons = BTreeSet::new();

    if input.new_status == FeedbackStatus::Held && empty_option(&input.note) {
        reasons.insert("Held feedback items require a hold reason.".into());
    } else if input.new_status != FeedbackStatus::Held
        && !is_allowed_status_transition(item.status, input.new_status)
    {
        reasons.insert(status_transition_reason(item.status, input.new_status));
    }

    if !reasons.is_empty() {
        return StatusTransitionResult {
            allowed: false,
            reasons: reasons.into_iter().collect(),
            updated_item: item.clone(),
            activity: invalid_activity(&item, &input),
            dispatch: AgentDispatchDecision::NotTriggered,
        };
    }

    let mut updated_item = item.clone();
    updated_item.status = input.new_status;
    updated_item.updated_at = input.changed_at;
    updated_item.hold_tag = if input.new_status == FeedbackStatus::Held {
        input.note.clone()
    } else {
        None
    };

    let dispatch = maybe_dispatch(&item, &mut updated_item, &input, &dispatch_config);
    let action = match (item.status, input.new_status) {
        (FeedbackStatus::Validation, FeedbackStatus::Deployed) => FeedbackActivityAction::Accepted,
        (FeedbackStatus::Validation, FeedbackStatus::Development) => {
            FeedbackActivityAction::Rejected
        }
        (_, FeedbackStatus::Held) => FeedbackActivityAction::HoldSet,
        _ => FeedbackActivityAction::StatusChanged,
    };

    StatusTransitionResult {
        allowed: true,
        reasons: Vec::new(),
        updated_item: updated_item.clone(),
        activity: FeedbackActivity {
            id: format!("activity:{}:{}", updated_item.id, input.changed_at),
            feedback_id: updated_item.id.clone(),
            action,
            from_status: Some(item.status),
            to_status: Some(input.new_status),
            note: input.note,
            author: input.author,
            created_at: input.changed_at,
        },
        dispatch,
    }
}

pub fn register_upvote(item: FeedbackItem, input: UpvoteInput) -> UpvoteResult {
    if input.voter.trim().is_empty() {
        return UpvoteResult {
            allowed: false,
            reasons: vec!["Feedback upvotes require a voter identifier.".into()],
            updated_item: item,
            activity: None,
        };
    }

    let mut updated_item = item.clone();
    let mut voters = load_upvote_voters(&updated_item.metadata);
    if !voters.insert(input.voter.clone()) {
        return UpvoteResult {
            allowed: true,
            reasons: Vec::new(),
            updated_item,
            activity: None,
        };
    }

    let Some(upvotes) = updated_item.upvotes.checked_add(1) else {
        return UpvoteResult {
            allowed: false,
            reasons: vec!["Feedback upvote count is exhausted.".into()],
            updated_item,
            activity: None,
        };
    };

    updated_item.upvotes = upvotes;
    updated_item.updated_at = input.voted_at;
    updated_item.metadata.insert(
        INTERNAL_UPVOTE_VOTERS_KEY.into(),
        MetadataValue::List(voters.into_iter().map(MetadataValue::Text).collect()),
    );

    UpvoteResult {
        allowed: true,
        reasons: Vec::new(),
        updated_item: updated_item.clone(),
        activity: Some(FeedbackActivity {
            id: format!("activity:{}:{}", updated_item.id, input.voted_at),
            feedback_id: updated_item.id.clone(),
            action: FeedbackActivityAction::Upvoted,
            from_status: Some(updated_item.status),
            to_status: Some(updated_item.status),
            note: None,
            author: input.voter,
            created_at: input.voted_at,
        }),
    }
}

pub fn evaluate_mandated_report(
    report: HelpSessionReport,
    open_items: &[FeedbackItem],
    config: MandatedReporterConfig,
) -> MandatedReportResult {
    match report.outcome {
        HelpAiSessionOutcome::BugIndicated => {
            let target_id = format!(
                "help-ai:bug:{}",
                report.context_topic_id.as_deref().unwrap_or("general")
            );
            if let Some(existing) = find_open_item(open_items, &target_id) {
                let mut updated = existing.clone();
                updated.updated_at = updated.updated_at.max(current_marker_time(&report));
                return MandatedReportResult {
                    generated_item: None,
                    updated_item: Some(updated),
                    comment: Some(format!(
                        "Mandated reporter linked help session {} to this open bug item.",
                        report.session_id
                    )),
                };
            }

            MandatedReportResult {
                generated_item: Some(system_feedback_item(SystemFeedbackDraft {
                    id: "feedback:mandated-bug".into(),
                    category: FeedbackCategory::Bug,
                    priority: FeedbackPriority::High,
                    target_id,
                    target_label: report
                        .context_topic_id
                        .as_deref()
                        .map(|topic| format!("AI help bug: {topic}"))
                        .unwrap_or_else(|| "AI help bug: general".into()),
                    title: "AI help bug report".into(),
                    body: format!(
                        "AI help marked this session as a bug indication. Review session reference {}.",
                        report.session_id
                    ),
                    metadata: mandated_metadata(&report),
                })),
                updated_item: None,
                comment: None,
            }
        }
        HelpAiSessionOutcome::PrivacySafetyRisk => MandatedReportResult {
            generated_item: Some(system_feedback_item(SystemFeedbackDraft {
                id: "feedback:privacy-safety".into(),
                category: FeedbackCategory::PrivacySafety,
                priority: FeedbackPriority::Critical,
                target_id: format!(
                    "help-ai:privacy:{}",
                    report.context_topic_id.as_deref().unwrap_or("general")
                ),
                target_label: "AI help privacy/safety risk".into(),
                title: "Privacy or safety risk detected".into(),
                body: privacy_risk_body(&report),
                metadata: mandated_metadata(&report),
            })),
            updated_item: None,
            comment: None,
        },
        HelpAiSessionOutcome::Unanswered | HelpAiSessionOutcome::ConfusionDetected => {
            let failure_count = config.current_topic_failures.saturating_add(1);
            if failure_count < config.unanswered_threshold {
                return MandatedReportResult {
                    generated_item: None,
                    updated_item: None,
                    comment: None,
                };
            }

            let category = if report.outcome == HelpAiSessionOutcome::Unanswered {
                FeedbackCategory::DocumentationGap
            } else {
                FeedbackCategory::UiUx
            };

            MandatedReportResult {
                generated_item: Some(system_feedback_item(SystemFeedbackDraft {
                    id: "feedback:help-gap".into(),
                    category,
                    priority: FeedbackPriority::Medium,
                    target_id: format!(
                        "help-ai:gap:{}",
                        report.context_topic_id.as_deref().unwrap_or("general")
                    ),
                    target_label: "AI help documentation gap".into(),
                    title: "Repeated unanswered or confusion sessions".into(),
                    body: format!(
                        "Help sessions reached the configured threshold for topic {}. Review session reference {} and cited topics.",
                        report.context_topic_id.as_deref().unwrap_or("general"),
                        report.session_id
                    ),
                    metadata: mandated_metadata(&report),
                })),
                updated_item: None,
                comment: None,
            }
        }
        _ => MandatedReportResult {
            generated_item: None,
            updated_item: None,
            comment: None,
        },
    }
}

fn system_feedback_item(draft: SystemFeedbackDraft) -> FeedbackItem {
    FeedbackItem {
        id: draft.id,
        target_type: FeedbackTargetType::General,
        target_id: draft.target_id,
        target_label: draft.target_label,
        status: FeedbackStatus::New,
        hold_tag: None,
        priority: draft.priority,
        category: draft.category,
        sprint_tag: None,
        title: draft.title,
        body: draft.body,
        rating: None,
        upvotes: 0,
        author: "system:mandated-reporter".into(),
        metadata: draft.metadata,
        created_at: 0,
        updated_at: 0,
        last_dispatch_at: None,
    }
}

fn mandated_metadata(report: &HelpSessionReport) -> BTreeMap<String, MetadataValue> {
    let mut metadata = BTreeMap::from([
        ("isSynthetic".into(), MetadataValue::Bool(true)),
        (
            "helpSessionRef".into(),
            MetadataValue::Text(report.session_id.clone()),
        ),
        (
            "normalizedQuestion".into(),
            MetadataValue::Text(report.normalized_question.clone()),
        ),
        (
            "citedTopicIds".into(),
            MetadataValue::List(
                report
                    .cited_topic_ids
                    .iter()
                    .cloned()
                    .map(MetadataValue::Text)
                    .collect(),
            ),
        ),
    ]);

    if let Some(route) = &report.route {
        metadata.insert("route".into(), MetadataValue::Text(route.clone()));
    }
    if let Some(surface_id) = &report.surface_id {
        metadata.insert("surfaceId".into(), MetadataValue::Text(surface_id.clone()));
    }
    if let Some(context_topic_id) = &report.context_topic_id {
        metadata.insert(
            "contextTopicId".into(),
            MetadataValue::Text(context_topic_id.clone()),
        );
    }

    metadata
}

fn find_open_item<'a>(items: &'a [FeedbackItem], target_id: &str) -> Option<&'a FeedbackItem> {
    items.iter().find(|item| {
        item.target_id == target_id
            && item.status != FeedbackStatus::Deployed
            && item.status != FeedbackStatus::Held
    })
}

fn current_marker_time(report: &HelpSessionReport) -> i64 {
    i64::try_from(report.session_id.len()).unwrap_or(0)
}

fn maybe_dispatch(
    previous_item: &FeedbackItem,
    updated_item: &mut FeedbackItem,
    input: &StatusChangeInput,
    config: &AgentDispatchConfig,
) -> AgentDispatchDecision {
    if !config.enabled || !config.trigger_statuses.contains(&input.new_status) {
        return AgentDispatchDecision::NotTriggered;
    }

    if let Some(last_dispatch_at) = previous_item.last_dispatch_at
        && input.changed_at.saturating_sub(last_dispatch_at) < config.dispatch_cooldown_ms
    {
        return AgentDispatchDecision::RateLimited;
    }

    updated_item.last_dispatch_at = Some(input.changed_at);
    AgentDispatchDecision::Triggered(FeedbackDispatchPayload {
        feedback_id: updated_item.id.clone(),
        previous_status: previous_item.status,
        new_status: input.new_status,
        note: sanitize_note(input.note.as_deref()),
        author: input.author.clone(),
    })
}

fn sanitize_note(note: Option<&str>) -> Option<String> {
    let note = note?;
    Some(redact_sensitive_text(note).trim().to_string())
}

fn privacy_risk_body(report: &HelpSessionReport) -> String {
    let excerpt = if contains_sensitive_question_text(&report.question_excerpt) {
        "redacted".to_string()
    } else {
        redact_sensitive_text(&report.question_excerpt)
    };

    format!(
        "A help session was flagged as privacy or safety risk. Source text {}. Review session reference {} and cited topics.",
        excerpt, report.session_id
    )
}

fn redact_sensitive_text(value: &str) -> String {
    let mut redacted = value.to_string();
    for marker in ["ssn=", "social security", "payment"] {
        if let Some(index) = redacted.to_ascii_lowercase().find(marker) {
            redacted.replace_range(index..redacted.len(), "[redacted-sensitive-note]");
            return redacted;
        }
    }

    if let Some((start, end)) = find_ssn_like_span(&redacted) {
        redacted.replace_range(start..end, "[redacted-sensitive-note]");
    }

    redacted
}

fn find_ssn_like_span(value: &str) -> Option<(usize, usize)> {
    let bytes = value.as_bytes();
    for (index, window) in bytes.windows(11).enumerate() {
        if window[3] == b'-'
            && window[6] == b'-'
            && window[0..3].iter().all(u8::is_ascii_digit)
            && window[4..6].iter().all(u8::is_ascii_digit)
            && window[7..11].iter().all(u8::is_ascii_digit)
        {
            return Some((index, index + 11));
        }
    }

    None
}

fn contains_ssn_like_pattern(value: &str) -> bool {
    find_ssn_like_span(value).is_some()
}

fn contains_sensitive_question_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("medical")
        || lower.contains("genetic")
        || lower.contains("contact")
        || lower.contains("payment")
        || lower.contains("eligibility")
        || contains_ssn_like_pattern(value)
}

fn invalid_activity(item: &FeedbackItem, input: &StatusChangeInput) -> FeedbackActivity {
    FeedbackActivity {
        id: format!("activity:{}:invalid", item.id),
        feedback_id: item.id.clone(),
        action: FeedbackActivityAction::StatusChanged,
        from_status: Some(item.status),
        to_status: Some(input.new_status),
        note: input.note.clone(),
        author: input.author.clone(),
        created_at: input.changed_at,
    }
}

fn is_allowed_status_transition(from: FeedbackStatus, to: FeedbackStatus) -> bool {
    matches!(
        (from, to),
        (FeedbackStatus::New, FeedbackStatus::Backlog)
            | (FeedbackStatus::Backlog, FeedbackStatus::Planning)
            | (FeedbackStatus::Planning, FeedbackStatus::Development)
            | (FeedbackStatus::Development, FeedbackStatus::Testing)
            | (FeedbackStatus::Testing, FeedbackStatus::Validation)
            | (FeedbackStatus::Validation, FeedbackStatus::Development)
            | (FeedbackStatus::Validation, FeedbackStatus::Deployed)
    )
}

fn status_transition_reason(from: FeedbackStatus, to: FeedbackStatus) -> String {
    if to == FeedbackStatus::Deployed {
        "Feedback items may move to DEPLOYED only from VALIDATION.".into()
    } else {
        format!("Unsupported feedback status transition from {from:?} to {to:?}.")
    }
}

fn metadata_contains_unsafe_content(metadata: &BTreeMap<String, MetadataValue>) -> bool {
    metadata
        .iter()
        .any(|(key, value)| metadata_entry_is_unsafe(key, value))
}

fn metadata_entry_is_unsafe(key: &str, value: &MetadataValue) -> bool {
    let normalized_key = key.to_ascii_lowercase();
    if normalized_key.contains("rawqr")
        || normalized_key.contains("medicalrecord")
        || normalized_key.contains("genetic")
        || normalized_key.contains("payment")
        || normalized_key.contains("eligibilitydocument")
        || normalized_key.contains("unsafe")
    {
        return true;
    }

    match value {
        MetadataValue::Text(text) => {
            let normalized_text = text.to_ascii_lowercase();
            normalized_text.contains("otpauth://")
                || normalized_text.contains("raw medical")
                || normalized_text.contains("private key")
        }
        MetadataValue::List(entries) => entries
            .iter()
            .any(|entry| metadata_entry_is_unsafe(key, entry)),
        MetadataValue::Map(entries) => entries
            .iter()
            .any(|(nested_key, nested_value)| metadata_entry_is_unsafe(nested_key, nested_value)),
        MetadataValue::Bool(_) | MetadataValue::Number(_) => false,
    }
}

fn load_upvote_voters(metadata: &BTreeMap<String, MetadataValue>) -> BTreeSet<String> {
    match metadata.get(INTERNAL_UPVOTE_VOTERS_KEY) {
        Some(MetadataValue::List(entries)) => entries
            .iter()
            .filter_map(|entry| match entry {
                MetadataValue::Text(value) => Some(value.clone()),
                _ => None,
            })
            .collect(),
        _ => BTreeSet::new(),
    }
}

fn empty_option(value: &Option<String>) -> bool {
    value
        .as_ref()
        .map(|current| current.trim().is_empty())
        .unwrap_or(true)
}
