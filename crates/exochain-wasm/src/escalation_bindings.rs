//! Escalation bindings: anomaly detection, triage, Sybil adjudication, kanban

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Evaluate detection signals and produce threat assessment
#[wasm_bindgen]
pub fn wasm_evaluate_signals(signals_json: &str) -> Result<JsValue, JsValue> {
    let signals: Vec<exo_escalation::detector::DetectionSignal> = from_json_str(signals_json)?;
    let assessment = exo_escalation::detector::evaluate_signals(&signals);
    to_js_value(&assessment)
}

/// Escalate a detection signal to create a case
#[wasm_bindgen]
pub fn wasm_escalate(signal_json: &str, path_json: &str) -> Result<JsValue, JsValue> {
    let signal: exo_escalation::detector::DetectionSignal = from_json_str(signal_json)?;
    let path: exo_escalation::escalation::EscalationPath = from_json_str(path_json)?;
    let case = exo_escalation::escalation::escalate(&signal, &path);
    to_js_value(&case)
}

/// Record feedback on an escalation case (learning loop)
#[wasm_bindgen]
pub fn wasm_record_feedback(entries_json: &str, entry_json: &str) -> Result<JsValue, JsValue> {
    let existing_entries: Vec<exo_escalation::feedback::FeedbackEntry> =
        from_json_str(entries_json)?;
    let entry: exo_escalation::feedback::FeedbackEntry = from_json_str(entry_json)?;
    let mut log = exo_escalation::feedback::FeedbackLog::default();
    for e in existing_entries {
        exo_escalation::feedback::record_feedback(&mut log, e);
    }
    exo_escalation::feedback::record_feedback(&mut log, entry);
    // FeedbackLog doesn't derive Serialize, so serialize the entries directly
    to_js_value(&log.entries)
}

/// Apply learnings from feedback to generate policy recommendations
#[wasm_bindgen]
pub fn wasm_apply_learnings(feedbacks_json: &str) -> Result<JsValue, JsValue> {
    let feedbacks: Vec<exo_escalation::feedback::FeedbackEntry> = from_json_str(feedbacks_json)?;
    let recommendations = exo_escalation::feedback::apply_learnings(&feedbacks);
    to_js_value(&recommendations)
}

/// Check completeness of an escalation case
#[wasm_bindgen]
pub fn wasm_check_completeness(case_json: &str) -> Result<JsValue, JsValue> {
    let case: exo_escalation::escalation::EscalationCase = from_json_str(case_json)?;
    let result = exo_escalation::completeness::check_completeness(&case);
    to_js_value(&serde_json::json!({
        "complete": matches!(result, exo_escalation::completeness::CompletenessResult::Complete),
        "details": format!("{result:?}"),
    }))
}

/// Triage a threat assessment to produce a response decision.
///
/// `assessment_json` — JSON `ThreatAssessment` (as returned by `wasm_evaluate_signals`).
/// Returns `{level, actions, timeout_ms, escalation_path}`.
#[wasm_bindgen]
pub fn wasm_triage(assessment_json: &str) -> Result<JsValue, JsValue> {
    let assessment: exo_escalation::detector::ThreatAssessment = from_json_str(assessment_json)?;
    let decision = exo_escalation::triage::triage(&assessment);
    // TriageDecision may not implement Serialize — flatten manually.
    let path = decision
        .escalation_path
        .as_ref()
        .map(|p| p.name.as_str())
        .unwrap_or("");
    to_js_value(&serde_json::json!({
        "level": format!("{:?}", decision.level),
        "actions": decision.actions.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>(),
        "timeout_ms": decision.timeout.physical_ms,
        "escalation_path": path,
    }))
}

/// Sort a flat list of escalation cases by priority (highest first).
///
/// `KanbanBoard` is a runtime-only type and cannot be serialized across
/// the WASM boundary. This binding operates on a flat JSON array of
/// `EscalationCase` objects and returns them sorted by priority.
#[wasm_bindgen]
pub fn wasm_cases_by_priority(cases_json: &str) -> Result<JsValue, JsValue> {
    use exo_escalation::escalation::CasePriority;

    let mut cases: Vec<exo_escalation::escalation::EscalationCase> =
        from_json_str(cases_json)?;
    // Sort descending so highest priority comes first.
    cases.sort_by(|a, b| {
        let ord = |p: &CasePriority| match p {
            CasePriority::Critical => 3u8,
            CasePriority::High => 2,
            CasePriority::Medium => 1,
            CasePriority::Low => 0,
        };
        ord(&b.priority).cmp(&ord(&a.priority))
    });
    to_js_value(&cases)
}

/// Validate the kanban column value (introspection helper).
///
/// Returns `{valid: true}` if `column_json` is a known `KanbanColumn` variant,
/// otherwise `{valid: false, error: "..."}`.
#[wasm_bindgen]
pub fn wasm_validate_kanban_column(column_json: &str) -> Result<JsValue, JsValue> {
    let result: Result<exo_escalation::kanban::KanbanColumn, _> =
        serde_json::from_str(column_json);
    match result {
        Ok(col) => to_js_value(&serde_json::json!({"valid": true, "column": format!("{col:?}")})),
        Err(e) => to_js_value(&serde_json::json!({"valid": false, "error": e.to_string()})),
    }
}
