//! AI transparency reporting module.
//!
//! Aggregates AI agent actions, delegation events, and MCP enforcement
//! outcomes into a structured [`AiTransparencyReport`] suitable for
//! regulatory submission under EU AI Act Article 13 and GDPR Article 22.
//!
//! # Clearance requirement
//!
//! [`generate_report`] is a sensitive operation — the report reveals which
//! AI agents hold delegated authority. Callers must verify that the
//! requesting actor holds a valid authority chain before calling this
//! function. The function signature accepts a `clearance_verified: bool`
//! flag which must be set only after an [`exo_authority`] chain check.

use exo_authority::DelegateeKind;
use exo_core::{Did, Timestamp};
use exo_gatekeeper::mcp_audit::{McpAuditLog, McpEnforcementOutcome};
use serde::{Deserialize, Serialize};

use crate::error::{LegalError, Result};

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

/// Summary of a single AI agent delegation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDelegationEvent {
    pub delegator: Did,
    pub delegatee: Did,
    /// The model identifier — may be redacted in compliance reports.
    pub model_id: String,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub depth: usize,
}

/// Per-rule MCP enforcement outcome summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOutcomeSummary {
    pub rule: String,
    pub allowed: u64,
    pub blocked: u64,
    pub escalated: u64,
}

/// A structured AI transparency report for a single tenant and time period.
///
/// Satisfies EU AI Act Article 13 (transparency) and provides the record
/// required by GDPR Article 22(4) for automated decision-making with
/// significant effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTransparencyReport {
    pub tenant_id: Did,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    /// Governance regime under which this report was generated.
    /// e.g. "EU-AI-ACT", "NIST-AI-RMF", "CCPA"
    pub legal_jurisdiction: String,
    /// Total number of actions performed by AI agents during the period.
    pub ai_agent_action_count: u64,
    /// AI delegation grants observed in the MCP audit log during the period.
    pub ai_delegation_grants: Vec<AiDelegationEvent>,
    /// Count of AI delegation revocations during the period.
    pub ai_delegation_revocations: u64,
    /// Per-rule breakdown of MCP enforcement outcomes.
    pub mcp_rule_outcomes: Vec<McpOutcomeSummary>,
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

/// Generate an AI transparency report for the given tenant and time period.
/// Parameters for [`generate_report`].
pub struct ReportParams<'a> {
    pub tenant_id: &'a Did,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    pub legal_jurisdiction: &'a str,
    pub mcp_log: &'a McpAuditLog,
    pub ai_delegation_grants: Vec<AiDelegationEvent>,
    pub ai_delegation_revocations: u64,
    /// Must only be `true` after the caller has validated the requesting
    /// actor's authority chain via `exo_authority::chain::verify_chain`.
    pub clearance_verified: bool,
}

/// Generate an AI transparency report for the given tenant and time period.
///
/// # Clearance requirement
///
/// `params.clearance_verified` must be `true` only after the caller has
/// validated the requesting actor's authority chain. Passing `false` returns
/// [`LegalError::InvalidStateTransition`] immediately without generating data.
///
/// # Errors
///
/// - [`LegalError::InvalidStateTransition`] if clearance is not verified.
pub fn generate_report(params: ReportParams<'_>) -> Result<AiTransparencyReport> {
    let ReportParams {
        tenant_id,
        period_start,
        period_end,
        legal_jurisdiction,
        mcp_log,
        ai_delegation_grants,
        ai_delegation_revocations,
        clearance_verified,
    } = params;

    if !clearance_verified {
        return Err(LegalError::InvalidStateTransition {
            reason: "AiTransparencyReport requires verified authority chain clearance; \
                     call exo_authority::chain::verify_chain before generate_report"
                .into(),
        });
    }

    // Count total AI agent actions from MCP audit log within period.
    let ai_agent_action_count = u64::try_from(
        mcp_log
            .records
            .iter()
            .filter(|r| r.timestamp >= period_start && r.timestamp <= period_end)
            .count(),
    )
    .unwrap_or(u64::MAX);

    // Aggregate MCP rule outcomes.
    let mcp_rule_outcomes = aggregate_mcp_outcomes(mcp_log, period_start, period_end);

    Ok(AiTransparencyReport {
        tenant_id: tenant_id.clone(),
        period_start,
        period_end,
        legal_jurisdiction: legal_jurisdiction.to_owned(),
        ai_agent_action_count,
        ai_delegation_grants,
        ai_delegation_revocations,
        mcp_rule_outcomes,
    })
}

/// Build AI delegation events from authority link data.
///
/// Filters links where `delegatee_kind` is [`DelegateeKind::AiAgent`].
#[must_use]
pub fn ai_delegation_event_from_link(
    delegator: Did,
    delegatee: Did,
    delegatee_kind: &DelegateeKind,
    granted_at: Timestamp,
    expires_at: Option<Timestamp>,
    depth: usize,
) -> Option<AiDelegationEvent> {
    match delegatee_kind {
        DelegateeKind::AiAgent { model_id } => Some(AiDelegationEvent {
            delegator,
            delegatee,
            model_id: model_id.clone(),
            granted_at,
            expires_at,
            depth,
        }),
        DelegateeKind::Human | DelegateeKind::Unknown => None,
    }
}

fn aggregate_mcp_outcomes(
    log: &McpAuditLog,
    period_start: Timestamp,
    period_end: Timestamp,
) -> Vec<McpOutcomeSummary> {
    use std::collections::BTreeMap;

    let mut counts: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();

    for record in log
        .records
        .iter()
        .filter(|r| r.timestamp >= period_start && r.timestamp <= period_end)
    {
        let rule_key = format!("{:?}", record.rule);
        let entry = counts.entry(rule_key).or_insert((0, 0, 0));
        match record.outcome {
            McpEnforcementOutcome::Allowed => entry.0 += 1,
            McpEnforcementOutcome::Blocked => entry.1 += 1,
            McpEnforcementOutcome::Escalated => entry.2 += 1,
        }
    }

    counts
        .into_iter()
        .map(|(rule, (allowed, blocked, escalated))| McpOutcomeSummary {
            rule,
            allowed,
            blocked,
            escalated,
        })
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::{Did, Timestamp};
    use exo_gatekeeper::{
        McpRule,
        mcp_audit::{McpAuditLog, McpEnforcementOutcome, append, create_record},
    };
    use uuid::Uuid;

    use super::*;

    fn did(s: &str) -> Did {
        Did::new(&format!("did:exo:{s}")).expect("valid DID")
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn audit_id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn make_log_with_records() -> McpAuditLog {
        let mut log = McpAuditLog::new();
        let r1 = create_record(
            &log,
            audit_id(0xE001),
            ts(10_000),
            McpRule::Mcp001BctsScope,
            did("agent"),
            McpEnforcementOutcome::Allowed,
            None,
        )
        .expect("deterministic MCP audit record");
        append(&mut log, r1).expect("append deterministic MCP audit record");
        let r2 = create_record(
            &log,
            audit_id(0xE002),
            ts(10_001),
            McpRule::Mcp002NoSelfEscalation,
            did("agent"),
            McpEnforcementOutcome::Blocked,
            None,
        )
        .expect("deterministic MCP audit record");
        append(&mut log, r2).expect("append deterministic MCP audit record");
        log
    }

    #[test]
    fn generate_report_requires_clearance() {
        let log = McpAuditLog::new();
        let result = generate_report(ReportParams {
            tenant_id: &did("tenant"),
            period_start: ts(0),
            period_end: ts(9999),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: 0,
            clearance_verified: false,
        });
        assert!(result.is_err());
    }

    #[test]
    fn generate_report_with_clearance_succeeds() {
        let log = make_log_with_records();
        let report = generate_report(ReportParams {
            tenant_id: &did("tenant"),
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: 0,
            clearance_verified: true,
        })
        .expect("report generation should succeed");
        assert_eq!(report.ai_agent_action_count, 2);
        assert_eq!(report.legal_jurisdiction, "EU-AI-ACT");
    }

    #[test]
    fn mcp_outcomes_aggregated_correctly() {
        let log = make_log_with_records();
        let report = generate_report(ReportParams {
            tenant_id: &did("tenant"),
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "NIST-AI-RMF",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: 0,
            clearance_verified: true,
        })
        .expect("ok");
        // One Allowed for Mcp001, one Blocked for Mcp002
        let mcp001 = report
            .mcp_rule_outcomes
            .iter()
            .find(|o| o.rule.contains("Mcp001"))
            .expect("Mcp001 must appear");
        assert_eq!(mcp001.allowed, 1);
        assert_eq!(mcp001.blocked, 0);
        let mcp002 = report
            .mcp_rule_outcomes
            .iter()
            .find(|o| o.rule.contains("Mcp002"))
            .expect("Mcp002 must appear");
        assert_eq!(mcp002.blocked, 1);
    }

    #[test]
    fn ai_delegation_event_from_human_link_returns_none() {
        let result = ai_delegation_event_from_link(
            did("alice"),
            did("bob"),
            &DelegateeKind::Human,
            ts(100),
            None,
            0,
        );
        assert!(result.is_none());
    }

    #[test]
    fn ai_delegation_event_from_ai_link_returns_some() {
        let result = ai_delegation_event_from_link(
            did("alice"),
            did("agent-1"),
            &DelegateeKind::AiAgent {
                model_id: "claude-sonnet-4-6".into(),
            },
            ts(100),
            Some(ts(200)),
            1,
        );
        let event = result.expect("AI link must produce an event");
        assert_eq!(event.model_id, "claude-sonnet-4-6");
        assert_eq!(event.depth, 1);
    }

    #[test]
    fn period_filtering_applies() {
        let mut log = McpAuditLog::new();
        // MCP audit records use caller-supplied HLC timestamps beyond this report window.
        let r = create_record(
            &log,
            audit_id(0xE003),
            ts(500),
            McpRule::Mcp001BctsScope,
            did("agent"),
            McpEnforcementOutcome::Allowed,
            None,
        )
        .expect("deterministic MCP audit record");
        append(&mut log, r).expect("append deterministic MCP audit record");

        // Period that excludes the record (past epoch)
        let report = generate_report(ReportParams {
            tenant_id: &did("tenant"),
            period_start: ts(0),
            period_end: ts(1), // very narrow window in the past
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: 0,
            clearance_verified: true,
        })
        .expect("ok");
        // Record's timestamp from now_utc() will not fall in [0, 1ms]
        assert_eq!(report.ai_agent_action_count, 0);
    }
}
