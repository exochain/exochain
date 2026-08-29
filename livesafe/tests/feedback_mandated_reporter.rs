use livesafe::ai_help_topics::HelpAiSessionOutcome;
use livesafe::feedback_mandated_reporter::{
    AgentDispatchConfig, AgentDispatchDecision, FeedbackActivityAction, FeedbackCategory,
    FeedbackDispatchPayload, FeedbackItem, FeedbackPriority, FeedbackRating, FeedbackStatus,
    FeedbackTargetType, HelpSessionReport, MandatedReporterConfig, MetadataValue, ReleaseHoldInput,
    StatusChangeInput, UpvoteInput, evaluate_mandated_report, evaluate_status_transition,
    register_upvote, validate_feedback_item,
};
use std::collections::BTreeMap;

fn safe_metadata() -> BTreeMap<String, MetadataValue> {
    BTreeMap::from([
        (
            "route".into(),
            MetadataValue::Text("/onboarding/card".into()),
        ),
        (
            "surfaceId".into(),
            MetadataValue::Text("ice-card-generator".into()),
        ),
        ("isSynthetic".into(), MetadataValue::Bool(true)),
        (
            "codeHints".into(),
            MetadataValue::Map(BTreeMap::from([(
                "filePaths".into(),
                MetadataValue::List(vec![MetadataValue::Text("src/ice_card_packet.rs".into())]),
            )])),
        ),
    ])
}

fn feedback_item(status: FeedbackStatus) -> FeedbackItem {
    FeedbackItem {
        id: "feedback:synthetic-001".into(),
        target_type: FeedbackTargetType::IceCard,
        target_id: "ice-card:generator".into(),
        target_label: "ICE card generator".into(),
        status,
        hold_tag: None,
        priority: FeedbackPriority::Medium,
        category: FeedbackCategory::UiUx,
        sprint_tag: None,
        title: "Card setup copy is unclear".into(),
        body: "The setup prompt needs a clearer next action for QR activation.".into(),
        rating: Some(FeedbackRating::Ambiguous),
        upvotes: 0,
        author: "user:synthetic-author".into(),
        metadata: safe_metadata(),
        created_at: 1_717_000_000_000,
        updated_at: 1_717_000_000_000,
        last_dispatch_at: None,
    }
}

#[test]
fn feedback_validation_rejects_sensitive_metadata_and_overlong_title() {
    let mut item = feedback_item(FeedbackStatus::New);
    item.title = "x".repeat(201);
    item.metadata.insert(
        "rawQrPayload".into(),
        MetadataValue::Text("otpauth://private".into()),
    );
    item.metadata.insert(
        "medicalRecord".into(),
        MetadataValue::Text("contains raw payload".into()),
    );

    let decision = validate_feedback_item(&item);

    assert!(!decision.allowed);
    assert!(
        decision
            .reasons
            .contains(&"Feedback titles must be present and at most 200 characters.".into())
    );
    assert!(
        decision
            .reasons
            .contains(&"Feedback metadata must reject raw sensitive fields, raw QR payloads, payment secrets, eligibility documents, and unsafe screenshots.".into())
    );
}

#[test]
fn status_transition_creates_activity_and_validation_paths() {
    let validation_item = feedback_item(FeedbackStatus::Validation);
    let deployed = evaluate_status_transition(
        validation_item.clone(),
        StatusChangeInput {
            new_status: FeedbackStatus::Deployed,
            author: "reviewer:synthetic".into(),
            note: Some("Acceptance passed.".into()),
            changed_at: 1_717_000_100_000,
        },
        AgentDispatchConfig::disabled(),
    );

    assert!(deployed.allowed, "{deployed:?}");
    assert_eq!(deployed.updated_item.status, FeedbackStatus::Deployed);
    assert_eq!(deployed.activity.action, FeedbackActivityAction::Accepted);
    assert_eq!(
        deployed.activity.from_status,
        Some(FeedbackStatus::Validation)
    );
    assert_eq!(deployed.activity.to_status, Some(FeedbackStatus::Deployed));
    assert_eq!(deployed.dispatch, AgentDispatchDecision::NotTriggered);

    let invalid = evaluate_status_transition(
        feedback_item(FeedbackStatus::New),
        StatusChangeInput {
            new_status: FeedbackStatus::Deployed,
            author: "reviewer:synthetic".into(),
            note: Some("Skipping workflow.".into()),
            changed_at: 1_717_000_200_000,
        },
        AgentDispatchConfig::disabled(),
    );

    assert!(!invalid.allowed);
    assert!(
        invalid
            .reasons
            .contains(&"Feedback items may move to DEPLOYED only from VALIDATION.".into())
    );
}

#[test]
fn hold_release_and_upvotes_are_deduplicated() {
    let held = evaluate_status_transition(
        feedback_item(FeedbackStatus::Backlog),
        StatusChangeInput {
            new_status: FeedbackStatus::Held,
            author: "triage:synthetic".into(),
            note: Some("Needs owner copy approval.".into()),
            changed_at: 1_717_000_300_000,
        },
        AgentDispatchConfig::disabled(),
    );

    assert!(held.allowed, "{held:?}");
    assert_eq!(
        held.updated_item.hold_tag.as_deref(),
        Some("Needs owner copy approval.")
    );
    assert_eq!(held.activity.action, FeedbackActivityAction::HoldSet);

    let released = held
        .updated_item
        .release_hold(ReleaseHoldInput {
            restored_status: FeedbackStatus::Backlog,
            author: "triage:synthetic".into(),
            note: Some("Owner approved non-sensitive copy.".into()),
            changed_at: 1_717_000_400_000,
        })
        .expect("held item should release cleanly");

    assert_eq!(released.updated_item.status, FeedbackStatus::Backlog);
    assert_eq!(released.updated_item.hold_tag, None);
    assert_eq!(
        released.activity.action,
        FeedbackActivityAction::HoldReleased
    );

    let first_vote = register_upvote(
        feedback_item(FeedbackStatus::Backlog),
        UpvoteInput {
            voter: "user:synthetic-voter".into(),
            voted_at: 1_717_000_500_000,
        },
    );
    assert!(first_vote.allowed, "{first_vote:?}");
    assert_eq!(first_vote.updated_item.upvotes, 1);
    assert_eq!(
        first_vote
            .activity
            .expect("first upvote should record activity")
            .action,
        FeedbackActivityAction::Upvoted
    );

    let duplicate_vote = register_upvote(
        first_vote.updated_item,
        UpvoteInput {
            voter: "user:synthetic-voter".into(),
            voted_at: 1_717_000_600_000,
        },
    );
    assert!(duplicate_vote.allowed, "{duplicate_vote:?}");
    assert_eq!(duplicate_vote.updated_item.upvotes, 1);
    assert!(duplicate_vote.activity.is_none());
}

#[test]
fn mandated_reporter_deduplicates_bug_items_and_redacts_privacy_risk_text() {
    let open_bug = FeedbackItem {
        id: "feedback:open-bug".into(),
        target_type: FeedbackTargetType::General,
        target_id: "help-ai:bug:card-setup".into(),
        target_label: "AI help bug: card-setup".into(),
        status: FeedbackStatus::Development,
        hold_tag: None,
        priority: FeedbackPriority::High,
        category: FeedbackCategory::Bug,
        sprint_tag: None,
        title: "AI help bug for card setup".into(),
        body: "Existing open bug item.".into(),
        rating: None,
        upvotes: 0,
        author: "system:mandated-reporter".into(),
        metadata: BTreeMap::new(),
        created_at: 1_717_000_000_000,
        updated_at: 1_717_000_000_000,
        last_dispatch_at: None,
    };

    let bug_result = evaluate_mandated_report(
        HelpSessionReport {
            session_id: "help-session-001".into(),
            outcome: HelpAiSessionOutcome::BugIndicated,
            context_topic_id: Some("card-setup".into()),
            normalized_question: "qr activation fails".into(),
            question_excerpt: "The generator crashed after QR activation.".into(),
            cited_topic_ids: vec!["emergency-card".into()],
            route: Some("/onboarding/card".into()),
            surface_id: Some("ice-card-generator".into()),
        },
        std::slice::from_ref(&open_bug),
        MandatedReporterConfig::default(),
    );

    assert!(bug_result.generated_item.is_none());
    let bug_update = bug_result.updated_item.expect("open bug should be updated");
    assert_eq!(bug_update.id, open_bug.id);
    assert!(bug_result.comment.is_some());
    assert!(
        bug_result
            .comment
            .as_deref()
            .unwrap_or_default()
            .contains("help-session-001")
    );

    let privacy_result = evaluate_mandated_report(
        HelpSessionReport {
            session_id: "help-session-002".into(),
            outcome: HelpAiSessionOutcome::PrivacySafetyRisk,
            context_topic_id: Some("medical-jacket".into()),
            normalized_question: "medical jacket privacy".into(),
            question_excerpt: "My SSN is 123-45-6789 and my emergency contact is Jane Doe.".into(),
            cited_topic_ids: vec!["medical-jacket".into()],
            route: Some("/jacket".into()),
            surface_id: Some("medical-jacket".into()),
        },
        &[],
        MandatedReporterConfig::default(),
    );

    let created = privacy_result
        .generated_item
        .expect("privacy risk should create feedback");
    assert_eq!(created.priority, FeedbackPriority::Critical);
    assert_eq!(created.category, FeedbackCategory::PrivacySafety);
    assert!(!created.body.contains("123-45-6789"));
    assert!(!created.body.contains("Jane Doe"));
    assert!(created.body.contains("redacted"));
}

#[test]
fn unanswered_threshold_creates_doc_gap_and_dispatch_stays_rate_limited_and_redacted() {
    let threshold_result = evaluate_mandated_report(
        HelpSessionReport {
            session_id: "help-session-003".into(),
            outcome: HelpAiSessionOutcome::Unanswered,
            context_topic_id: Some("trust-state".into()),
            normalized_question: "what does adapter missing mean".into(),
            question_excerpt: "What does adapter missing mean?".into(),
            cited_topic_ids: vec!["trust-state".into()],
            route: Some("/trust".into()),
            surface_id: Some("trust-state-banner".into()),
        },
        &[],
        MandatedReporterConfig {
            unanswered_threshold: 3,
            current_topic_failures: 2,
            daily_summary_date: None,
            daily_summary_totals: None,
        },
    );

    let doc_item = threshold_result
        .generated_item
        .expect("threshold hit should create documentation or UX feedback");
    assert_eq!(doc_item.priority, FeedbackPriority::Medium);
    assert!(
        matches!(
            doc_item.category,
            FeedbackCategory::DocumentationGap | FeedbackCategory::UiUx
        ),
        "{doc_item:?}"
    );

    let dispatch_ready = evaluate_status_transition(
        feedback_item(FeedbackStatus::Planning),
        StatusChangeInput {
            new_status: FeedbackStatus::Development,
            author: "triage:synthetic".into(),
            note: Some("Build the QR help fix; ssn=123-45-6789".into()),
            changed_at: 1_717_000_700_000,
        },
        AgentDispatchConfig {
            enabled: true,
            trigger_statuses: vec![FeedbackStatus::Development],
            dispatch_cooldown_ms: 3_600_000,
        },
    );

    assert!(dispatch_ready.allowed, "{dispatch_ready:?}");
    assert_eq!(
        dispatch_ready.dispatch,
        AgentDispatchDecision::Triggered(FeedbackDispatchPayload {
            feedback_id: "feedback:synthetic-001".into(),
            previous_status: FeedbackStatus::Planning,
            new_status: FeedbackStatus::Development,
            note: Some("Build the QR help fix; [redacted-sensitive-note]".into()),
            author: "triage:synthetic".into(),
        })
    );

    let mut already_dispatched = feedback_item(FeedbackStatus::Planning);
    already_dispatched.last_dispatch_at = Some(1_717_000_700_000);
    let rate_limited = evaluate_status_transition(
        already_dispatched,
        StatusChangeInput {
            new_status: FeedbackStatus::Development,
            author: "triage:synthetic".into(),
            note: Some("Retry dispatch immediately.".into()),
            changed_at: 1_717_001_000_000,
        },
        AgentDispatchConfig {
            enabled: true,
            trigger_statuses: vec![FeedbackStatus::Development],
            dispatch_cooldown_ms: 3_600_000,
        },
    );

    assert!(rate_limited.allowed, "{rate_limited:?}");
    assert_eq!(rate_limited.dispatch, AgentDispatchDecision::RateLimited);
}

#[test]
fn exhausted_upvote_fails_closed_without_mutation_on_overflow() {
    let mut exhausted = feedback_item(FeedbackStatus::Backlog);
    exhausted.upvotes = u32::MAX;

    let result = register_upvote(
        exhausted.clone(),
        UpvoteInput {
            voter: "user:new-synthetic-voter".into(),
            voted_at: i64::MAX,
        },
    );

    assert!(!result.allowed);
    assert_eq!(
        result.reasons,
        vec!["Feedback upvote count is exhausted.".to_string()]
    );
    assert_eq!(result.updated_item, exhausted);
    assert!(result.activity.is_none());
}

#[test]
fn dispatch_cooldown_saturates_timestamp_overflow() {
    let mut item = feedback_item(FeedbackStatus::Planning);
    item.last_dispatch_at = Some(i64::MAX);

    let result = evaluate_status_transition(
        item,
        StatusChangeInput {
            new_status: FeedbackStatus::Development,
            author: "triage:synthetic".into(),
            note: Some("Clock-regression control.".into()),
            changed_at: i64::MIN,
        },
        AgentDispatchConfig {
            enabled: true,
            trigger_statuses: vec![FeedbackStatus::Development],
            dispatch_cooldown_ms: 1,
        },
    );

    assert!(result.allowed, "{result:?}");
    assert_eq!(result.dispatch, AgentDispatchDecision::RateLimited);
}
