// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Escalation bindings: anomaly detection, triage, Sybil adjudication, kanban

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

const MAX_WASM_DETECTION_SIGNALS: usize = 1_024;
const MAX_WASM_FEEDBACK_ENTRIES: usize = 4_096;
const MAX_WASM_ESCALATION_CASES: usize = 1_024;

fn triage_level_label(level: &exo_escalation::triage::TriageLevel) -> &'static str {
    match level {
        exo_escalation::triage::TriageLevel::Automatic => "Automatic",
        exo_escalation::triage::TriageLevel::Supervised => "Supervised",
        exo_escalation::triage::TriageLevel::ManualRequired => "ManualRequired",
        exo_escalation::triage::TriageLevel::EmergencyHuman => "EmergencyHuman",
    }
}

fn triage_action_label(action: &exo_escalation::triage::TriageAction) -> &'static str {
    match action {
        exo_escalation::triage::TriageAction::Log => "Log",
        exo_escalation::triage::TriageAction::Alert => "Alert",
        exo_escalation::triage::TriageAction::Quarantine => "Quarantine",
        exo_escalation::triage::TriageAction::Suspend => "Suspend",
        exo_escalation::triage::TriageAction::Escalate => "Escalate",
        exo_escalation::triage::TriageAction::Shutdown => "Shutdown",
    }
}

fn completeness_details(result: &exo_escalation::completeness::CompletenessResult) -> String {
    match result {
        exo_escalation::completeness::CompletenessResult::Complete => "Complete".to_owned(),
        exo_escalation::completeness::CompletenessResult::Incomplete { missing } => {
            if missing.is_empty() {
                "Incomplete".to_owned()
            } else {
                format!("Incomplete: {}", missing.join("; "))
            }
        }
    }
}

/// Evaluate detection signals and produce threat assessment
#[wasm_bindgen]
pub fn wasm_evaluate_signals(signals_json: &str) -> Result<JsValue, JsValue> {
    let signals: Vec<exo_escalation::detector::DetectionSignal> = from_json_bounded_vec(
        signals_json,
        "detection signals",
        MAX_WASM_DETECTION_SIGNALS,
    )?;
    let assessment = exo_escalation::detector::evaluate_signals(&signals);
    to_js_value(&assessment)
}

/// Escalate a detection signal to create a case.
///
/// The input JSON must be an `EscalationCaseInput` so the caller supplies the
/// case id and HLC creation timestamp explicitly.
#[wasm_bindgen]
pub fn wasm_escalate(input_json: &str) -> Result<JsValue, JsValue> {
    let input: exo_escalation::escalation::EscalationCaseInput = from_json_str(input_json)?;
    let case = exo_escalation::escalation::escalate(input)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_js_value(&case)
}

/// Record feedback on an escalation case (learning loop)
#[wasm_bindgen]
pub fn wasm_record_feedback(entries_json: &str, entry_json: &str) -> Result<JsValue, JsValue> {
    let existing_entries: Vec<exo_escalation::feedback::FeedbackEntry> =
        from_json_bounded_vec(entries_json, "feedback entries", MAX_WASM_FEEDBACK_ENTRIES)?;
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
    let feedbacks: Vec<exo_escalation::feedback::FeedbackEntry> = from_json_bounded_vec(
        feedbacks_json,
        "feedback entries",
        MAX_WASM_FEEDBACK_ENTRIES,
    )?;
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
        "details": completeness_details(&result),
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
        "level": triage_level_label(&decision.level),
        "actions": decision.actions.iter().map(triage_action_label).collect::<Vec<_>>(),
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
        from_json_bounded_vec(cases_json, "escalation cases", MAX_WASM_ESCALATION_CASES)?;
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
    let result: Result<exo_escalation::kanban::KanbanColumn, _> = from_json_str(column_json);
    match result {
        Ok(col) => to_js_value(&serde_json::json!({"valid": true, "column": col.to_string()})),
        Err(_) => {
            to_js_value(&serde_json::json!({"valid": false, "error": "invalid kanban column"}))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn triage_export_uses_stable_labels_not_debug_variants() {
        let source = include_str!("escalation_bindings.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        assert!(
            !production.contains("format!(\"{:?}\", decision.level)"),
            "WASM triage level must not depend on Rust Debug output"
        );
        assert!(
            !production.contains("format!(\"{a:?}\")"),
            "WASM triage actions must not depend on Rust Debug output"
        );
        assert!(
            !production.contains("format!(\"{result:?}\")"),
            "WASM completeness details must not depend on Rust Debug output"
        );
    }

    #[test]
    fn triage_labels_preserve_public_contract() {
        assert_eq!(
            super::triage_level_label(&exo_escalation::triage::TriageLevel::EmergencyHuman),
            "EmergencyHuman"
        );
        assert_eq!(
            super::triage_action_label(&exo_escalation::triage::TriageAction::Quarantine),
            "Quarantine"
        );
    }

    #[test]
    fn completeness_details_preserve_stable_status_text() {
        assert_eq!(
            super::completeness_details(
                &exo_escalation::completeness::CompletenessResult::Complete
            ),
            "Complete"
        );
        assert_eq!(
            super::completeness_details(
                &exo_escalation::completeness::CompletenessResult::Incomplete {
                    missing: vec!["missing stage: intake".to_owned()]
                }
            ),
            "Incomplete: missing stage: intake"
        );
    }
}
