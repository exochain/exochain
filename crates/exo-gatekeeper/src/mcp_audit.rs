//! MCP rule enforcement audit trail.
//!
//! Records every MCP rule enforcement outcome in a BLAKE3 hash-chained log
//! that is independent of the governance AuditLog. This keeps the judicial
//! branch (exo-gatekeeper) self-contained — no exo-governance dependency —
//! while providing a tamper-evident record of AI boundary enforcement.
//!
//! The rule ID type is [`McpRule`], an enum defined in this crate. Using a
//! typed enum rather than a plain `String` prevents injection of fabricated
//! rule identifiers into the tamper-evident chain.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::GatekeeperError, mcp::McpRule};

// ---------------------------------------------------------------------------
// Enforcement outcome
// ---------------------------------------------------------------------------

/// The outcome of evaluating an MCP rule against an AI actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpEnforcementOutcome {
    /// The rule was satisfied; the action is permitted.
    Allowed,
    /// The rule was violated; the action is blocked.
    Blocked,
    /// The rule triggered escalation to a human authority.
    Escalated,
}

// ---------------------------------------------------------------------------
// MCP audit record
// ---------------------------------------------------------------------------

/// A single enforcement event appended to [`McpAuditLog`].
///
/// `rule` is typed as [`McpRule`] (a registered enum), NOT a free-form
/// `String`. This prevents MCP rule ID injection attacks where a malicious
/// or misconfigured MCP server inserts rule identifiers that pattern-match
/// compliant rules without actually being enforced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuditRecord {
    pub id: Uuid,
    pub timestamp: Timestamp,
    /// The MCP rule that was evaluated. Typed — not a free-form string.
    pub rule: McpRule,
    pub actor: Did,
    pub outcome: McpEnforcementOutcome,
    /// Optional data residency region for cross-border transfer impact
    /// assessments (GDPR Chapter V). `None` is valid for intra-jurisdiction
    /// deployments but must be set for cross-border processing.
    pub data_residency_region: Option<String>,
    /// BLAKE3 hash of the previous record; `[0u8; 32]` for the first entry.
    pub chain_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Hash function
// ---------------------------------------------------------------------------

fn hash_record(r: &McpAuditRecord) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(r.id.as_bytes());
    h.update(&r.timestamp.physical_ms.to_le_bytes());
    h.update(&r.timestamp.logical.to_le_bytes());
    // Rule is hashed via its debug representation for determinism.
    h.update(format!("{:?}", r.rule).as_bytes());
    h.update(r.actor.as_str().as_bytes());
    h.update(format!("{:?}", r.outcome).as_bytes());
    if let Some(region) = &r.data_residency_region {
        h.update(region.as_bytes());
    }
    h.update(&r.chain_hash);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// MCP audit log
// ---------------------------------------------------------------------------

/// Append-only, BLAKE3 hash-chained log of MCP enforcement events.
///
/// Structurally mirrors [`exo_governance::audit::AuditLog`] but is
/// self-contained within exo-gatekeeper to preserve branch separation.
#[derive(Debug, Clone, Default)]
pub struct McpAuditLog {
    pub records: Vec<McpAuditRecord>,
}

impl McpAuditLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hash of the last record; `[0u8; 32]` for an empty log.
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.records.last().map(hash_record).unwrap_or([0u8; 32])
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Append a pre-built record to the log.
///
/// # Errors
/// Returns [`GatekeeperError::McpAuditChainBroken`] if `record.chain_hash`
/// does not match the current log head — indicating either an ordering error
/// or tampering.
pub fn append(log: &mut McpAuditLog, record: McpAuditRecord) -> Result<(), GatekeeperError> {
    if record.chain_hash != log.head_hash() {
        return Err(GatekeeperError::McpAuditChainBroken {
            index: log.records.len(),
        });
    }
    log.records.push(record);
    Ok(())
}

/// Verify the integrity of the entire log chain.
///
/// # Errors
/// Returns [`GatekeeperError::McpAuditChainBroken`] at the first broken link.
pub fn verify_chain(log: &McpAuditLog) -> Result<(), GatekeeperError> {
    let mut prev = [0u8; 32];
    for (i, record) in log.records.iter().enumerate() {
        if record.chain_hash != prev {
            return Err(GatekeeperError::McpAuditChainBroken { index: i });
        }
        prev = hash_record(record);
    }
    Ok(())
}

/// Build a new record linked to the current log head.
#[must_use]
pub fn create_record(
    log: &McpAuditLog,
    rule: McpRule,
    actor: Did,
    outcome: McpEnforcementOutcome,
    data_residency_region: Option<String>,
) -> McpAuditRecord {
    McpAuditRecord {
        id: Uuid::new_v4(),
        timestamp: Timestamp::now_utc(),
        rule,
        actor,
        outcome,
        data_residency_region,
        chain_hash: log.head_hash(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::Did;

    use super::*;
    use crate::mcp::McpRule;

    fn did(s: &str) -> Did {
        Did::new(&format!("did:exo:{s}")).expect("valid DID")
    }

    fn append_ok(log: &mut McpAuditLog, rule: McpRule, outcome: McpEnforcementOutcome) {
        let r = create_record(log, rule, did("agent"), outcome, None);
        append(log, r).expect("append failed");
    }

    #[test]
    fn empty_log_verifies() {
        assert!(verify_chain(&McpAuditLog::new()).is_ok());
    }

    #[test]
    fn single_record_appended() {
        let mut log = McpAuditLog::new();
        append_ok(
            &mut log,
            McpRule::Mcp001BctsScope,
            McpEnforcementOutcome::Allowed,
        );
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
        assert!(verify_chain(&log).is_ok());
    }

    #[test]
    fn chain_of_records_verifies() {
        let mut log = McpAuditLog::new();
        for rule in McpRule::all() {
            append_ok(&mut log, rule, McpEnforcementOutcome::Allowed);
        }
        assert_eq!(log.len(), 6);
        assert!(verify_chain(&log).is_ok());
    }

    #[test]
    fn tamper_detected() {
        let mut log = McpAuditLog::new();
        for rule in McpRule::all() {
            append_ok(&mut log, rule, McpEnforcementOutcome::Allowed);
        }
        log.records[2].chain_hash = [0xffu8; 32];
        assert!(verify_chain(&log).is_err());
    }

    #[test]
    fn wrong_chain_hash_rejected() {
        let mut log = McpAuditLog::new();
        append_ok(
            &mut log,
            McpRule::Mcp001BctsScope,
            McpEnforcementOutcome::Allowed,
        );
        let bad = McpAuditRecord {
            id: Uuid::new_v4(),
            timestamp: Timestamp::new(9000, 0),
            rule: McpRule::Mcp002NoSelfEscalation,
            actor: did("agent"),
            outcome: McpEnforcementOutcome::Blocked,
            data_residency_region: None,
            chain_hash: [0xffu8; 32], // wrong
        };
        assert!(append(&mut log, bad).is_err());
    }

    #[test]
    fn head_hash_changes_on_append() {
        let mut log = McpAuditLog::new();
        let h0 = log.head_hash();
        assert_eq!(h0, [0u8; 32]);
        append_ok(
            &mut log,
            McpRule::Mcp003ProvenanceRequired,
            McpEnforcementOutcome::Allowed,
        );
        assert_ne!(log.head_hash(), h0);
    }

    #[test]
    fn deterministic_hash() {
        let r = McpAuditRecord {
            id: Uuid::nil(),
            timestamp: Timestamp::new(1000, 0),
            rule: McpRule::Mcp001BctsScope,
            actor: did("test"),
            outcome: McpEnforcementOutcome::Allowed,
            data_residency_region: None,
            chain_hash: [0u8; 32],
        };
        assert_eq!(hash_record(&r), hash_record(&r));
    }

    #[test]
    fn data_residency_region_stored() {
        let mut log = McpAuditLog::new();
        let r = create_record(
            &log,
            McpRule::Mcp001BctsScope,
            did("agent"),
            McpEnforcementOutcome::Allowed,
            Some("EU-WEST-1".into()),
        );
        assert_eq!(r.data_residency_region, Some("EU-WEST-1".into()));
        append(&mut log, r).expect("append ok");
        assert!(verify_chain(&log).is_ok());
    }

    #[test]
    fn blocked_outcome_recorded() {
        let mut log = McpAuditLog::new();
        append_ok(
            &mut log,
            McpRule::Mcp002NoSelfEscalation,
            McpEnforcementOutcome::Blocked,
        );
        assert_eq!(log.records[0].outcome, McpEnforcementOutcome::Blocked);
    }
}
