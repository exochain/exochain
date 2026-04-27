//! Heartbeat monitoring — Paperclip concept adapted for ExoChain.
//!
//! Tracks per-agent pulse via HLC timestamps. Timeouts trigger PACE
//! escalation through the ODA command hierarchy.

use std::collections::BTreeMap;

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CatapultError, Result};

/// Domain tag for canonical heartbeat receipt hashes.
pub const HEARTBEAT_HASH_DOMAIN: &str = "exo.catapult.heartbeat_record.v1";
const HEARTBEAT_HASH_SCHEMA_VERSION: &str = "1.0.0";

/// Status of a heartbeat invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HeartbeatStatus {
    Queued,
    Running,
    Completed,
    Failed,
    TimedOut,
}

/// A single heartbeat record from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub id: Uuid,
    pub newco_id: Uuid,
    pub agent_did: Did,
    pub status: HeartbeatStatus,
    pub started: Timestamp,
    pub finished: Option<Timestamp>,
    /// Resource usage counters (token counts, API calls, etc.).
    pub usage: BTreeMap<String, u64>,
    /// Hash of this heartbeat for receipt chaining.
    pub receipt_hash: Hash256,
}

/// Caller-supplied deterministic metadata for creating a heartbeat record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRecordInput {
    pub id: Uuid,
    pub newco_id: Uuid,
    pub agent_did: Did,
    pub status: HeartbeatStatus,
    pub started: Timestamp,
    pub finished: Option<Timestamp>,
    pub usage: BTreeMap<String, u64>,
}

impl HeartbeatRecord {
    /// Create a heartbeat record with a deterministic canonical receipt hash.
    ///
    /// # Errors
    /// Returns [`CatapultError`] when the input contains placeholder metadata
    /// or canonical hashing fails.
    pub fn new(input: HeartbeatRecordInput) -> Result<Self> {
        validate_heartbeat_input(&input)?;
        let receipt_hash = heartbeat_record_receipt_hash(&input)?;
        Ok(Self {
            id: input.id,
            newco_id: input.newco_id,
            agent_did: input.agent_did,
            status: input.status,
            started: input.started,
            finished: input.finished,
            usage: input.usage,
            receipt_hash,
        })
    }

    /// Validate externally supplied or deserialized heartbeat metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] when placeholders are present or the stored
    /// receipt hash does not match the canonical heartbeat payload.
    pub fn validate(&self) -> Result<()> {
        let input = self.input();
        validate_heartbeat_input(&input)?;
        if self.receipt_hash == Hash256::ZERO {
            return Err(CatapultError::InvalidHeartbeat {
                reason: "heartbeat receipt hash must not be zero".into(),
            });
        }
        if !self.verify_receipt_hash()? {
            return Err(CatapultError::InvalidHeartbeat {
                reason: "heartbeat receipt hash does not match canonical payload".into(),
            });
        }
        Ok(())
    }

    /// Verify the stored receipt hash against the canonical payload.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if canonical hashing fails.
    pub fn verify_receipt_hash(&self) -> Result<bool> {
        Ok(heartbeat_record_receipt_hash(&self.input())? == self.receipt_hash)
    }

    fn input(&self) -> HeartbeatRecordInput {
        HeartbeatRecordInput {
            id: self.id,
            newco_id: self.newco_id,
            agent_did: self.agent_did.clone(),
            status: self.status,
            started: self.started,
            finished: self.finished,
            usage: self.usage.clone(),
        }
    }
}

/// An alert generated when an agent misses their heartbeat window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatAlert {
    pub agent_did: Did,
    pub last_seen: Timestamp,
    pub elapsed_ms: u64,
    pub severity: AlertSeverity,
}

/// Severity of a heartbeat alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    /// Agent is late but within tolerance.
    Warning,
    /// Agent has exceeded the timeout — PACE escalation needed.
    Critical,
}

/// Monitors agent heartbeats and generates alerts on timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMonitor {
    /// Last heartbeat timestamp per agent DID.
    last_seen: BTreeMap<Did, Timestamp>,
    /// Full heartbeat history per agent.
    history: BTreeMap<Did, Vec<HeartbeatRecord>>,
    /// Warning threshold in milliseconds.
    warn_ms: u64,
    /// Critical timeout in milliseconds (triggers PACE escalation).
    timeout_ms: u64,
}

impl HeartbeatMonitor {
    /// Default warning threshold: 3 minutes.
    pub const DEFAULT_WARN_MS: u64 = 180_000;
    /// Default critical timeout: 5 minutes.
    pub const DEFAULT_TIMEOUT_MS: u64 = 300_000;

    /// Create a new heartbeat monitor with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_seen: BTreeMap::new(),
            history: BTreeMap::new(),
            warn_ms: Self::DEFAULT_WARN_MS,
            timeout_ms: Self::DEFAULT_TIMEOUT_MS,
        }
    }

    /// Create a monitor with custom thresholds.
    #[must_use]
    pub fn with_thresholds(warn_ms: u64, timeout_ms: u64) -> Self {
        Self {
            last_seen: BTreeMap::new(),
            history: BTreeMap::new(),
            warn_ms,
            timeout_ms,
        }
    }

    /// Record a heartbeat from an agent.
    pub fn record(&mut self, record: HeartbeatRecord) -> Result<()> {
        record.validate()?;
        let did = record.agent_did.clone();
        let ts = record.started;
        self.last_seen.insert(did.clone(), ts);
        self.history.entry(did).or_default().push(record);
        Ok(())
    }

    /// Check all agents for heartbeat health at the given time.
    #[must_use]
    pub fn check_health(&self, now: &Timestamp) -> Vec<HeartbeatAlert> {
        let mut alerts = Vec::new();
        for (did, last) in &self.last_seen {
            let elapsed_ms = now.physical_ms.saturating_sub(last.physical_ms);
            if elapsed_ms >= self.timeout_ms {
                alerts.push(HeartbeatAlert {
                    agent_did: did.clone(),
                    last_seen: *last,
                    elapsed_ms,
                    severity: AlertSeverity::Critical,
                });
            } else if elapsed_ms >= self.warn_ms {
                alerts.push(HeartbeatAlert {
                    agent_did: did.clone(),
                    last_seen: *last,
                    elapsed_ms,
                    severity: AlertSeverity::Warning,
                });
            }
        }
        alerts
    }

    /// Get the last-seen timestamp for an agent.
    #[must_use]
    pub fn last_seen(&self, did: &Did) -> Option<&Timestamp> {
        self.last_seen.get(did)
    }

    /// Get the heartbeat history for an agent.
    #[must_use]
    pub fn history(&self, did: &Did) -> Option<&[HeartbeatRecord]> {
        self.history.get(did).map(|v| v.as_slice())
    }

    /// Number of agents being monitored.
    #[must_use]
    pub fn agent_count(&self) -> usize {
        self.last_seen.len()
    }

    /// Validate a deserialized monitor and all recorded heartbeat history.
    ///
    /// # Errors
    /// Returns [`CatapultError`] when heartbeat history contains placeholders
    /// or a last-seen timestamp disagrees with recorded history.
    pub fn validate(&self) -> Result<()> {
        for (did, history) in &self.history {
            let mut latest = None;
            for record in history {
                if record.agent_did != *did {
                    return Err(CatapultError::InvalidHeartbeat {
                        reason: format!(
                            "heartbeat history key {did} does not match record DID {}",
                            record.agent_did
                        ),
                    });
                }
                record.validate()?;
                latest = Some(latest.map_or(record.started, |current: Timestamp| {
                    current.max(record.started)
                }));
            }
            match (self.last_seen.get(did), latest) {
                (Some(last_seen), Some(latest_started)) if *last_seen == latest_started => {}
                (Some(_), Some(latest_started)) => {
                    return Err(CatapultError::InvalidHeartbeat {
                        reason: format!(
                            "heartbeat last_seen for {did} does not match latest record {latest_started}"
                        ),
                    });
                }
                _ => {
                    return Err(CatapultError::InvalidHeartbeat {
                        reason: format!("heartbeat history for {did} has no matching last_seen"),
                    });
                }
            }
        }

        for did in self.last_seen.keys() {
            if !self.history.contains_key(did) {
                return Err(CatapultError::InvalidHeartbeat {
                    reason: format!("heartbeat last_seen for {did} has no history"),
                });
            }
        }
        Ok(())
    }
}

impl Default for HeartbeatMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the canonical receipt hash for a heartbeat record.
///
/// # Errors
/// Returns [`CatapultError`] if canonical CBOR hashing fails.
pub fn heartbeat_record_receipt_hash(input: &HeartbeatRecordInput) -> Result<Hash256> {
    validate_heartbeat_input(input)?;
    exo_core::hash::hash_structured(&HeartbeatHashPayload::from_input(input)).map_err(|e| {
        CatapultError::InvalidHeartbeat {
            reason: format!("heartbeat canonical hash failed: {e}"),
        }
    })
}

#[derive(Serialize)]
struct HeartbeatHashPayload<'a> {
    domain: &'static str,
    schema_version: &'static str,
    id: Uuid,
    newco_id: Uuid,
    agent_did: &'a Did,
    status: HeartbeatStatus,
    started: Timestamp,
    finished: Option<Timestamp>,
    usage: &'a BTreeMap<String, u64>,
}

impl<'a> HeartbeatHashPayload<'a> {
    fn from_input(input: &'a HeartbeatRecordInput) -> Self {
        Self {
            domain: HEARTBEAT_HASH_DOMAIN,
            schema_version: HEARTBEAT_HASH_SCHEMA_VERSION,
            id: input.id,
            newco_id: input.newco_id,
            agent_did: &input.agent_did,
            status: input.status,
            started: input.started,
            finished: input.finished,
            usage: &input.usage,
        }
    }
}

fn validate_heartbeat_input(input: &HeartbeatRecordInput) -> Result<()> {
    if input.id.is_nil() {
        return Err(CatapultError::InvalidHeartbeat {
            reason: "heartbeat id must be caller-supplied and non-nil".into(),
        });
    }
    if input.newco_id.is_nil() {
        return Err(CatapultError::InvalidHeartbeat {
            reason: "heartbeat newco id must be non-nil".into(),
        });
    }
    if input.started == Timestamp::ZERO {
        return Err(CatapultError::InvalidHeartbeat {
            reason: "heartbeat started timestamp must be caller-supplied HLC".into(),
        });
    }
    if let Some(finished) = input.finished {
        if finished < input.started {
            return Err(CatapultError::InvalidHeartbeat {
                reason: "heartbeat finished timestamp must not precede started timestamp".into(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did(name: &str) -> Did {
        Did::new(&format!("did:exo:test-{name}")).unwrap()
    }

    fn make_heartbeat(did: Did, time_ms: u64) -> HeartbeatRecord {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&time_ms.to_le_bytes());
        HeartbeatRecord::new(HeartbeatRecordInput {
            id: Uuid::from_bytes(bytes),
            newco_id: test_uuid(3),
            agent_did: did,
            status: HeartbeatStatus::Completed,
            started: Timestamp::new(time_ms, 0),
            finished: Some(Timestamp::new(time_ms + 100, 0)),
            usage: BTreeMap::new(),
        })
        .unwrap()
    }

    fn test_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn valid_heartbeat_input(did: Did, time_ms: u64) -> HeartbeatRecordInput {
        HeartbeatRecordInput {
            id: test_uuid(1),
            newco_id: test_uuid(2),
            agent_did: did,
            status: HeartbeatStatus::Completed,
            started: Timestamp::new(time_ms, 0),
            finished: Some(Timestamp::new(time_ms + 100, 0)),
            usage: BTreeMap::new(),
        }
    }

    #[test]
    fn heartbeat_record_new_requires_caller_supplied_provenance() {
        let record = HeartbeatRecord::new(valid_heartbeat_input(test_did("agent1"), 1000)).unwrap();

        assert_ne!(record.id, Uuid::nil());
        assert_ne!(record.newco_id, Uuid::nil());
        assert_ne!(record.started, Timestamp::ZERO);
        assert_ne!(record.receipt_hash, Hash256::ZERO);
        assert!(record.verify_receipt_hash().unwrap());
    }

    #[test]
    fn monitor_rejects_placeholder_or_tampered_heartbeat_records() {
        let mut monitor = HeartbeatMonitor::new();

        let mut record =
            HeartbeatRecord::new(valid_heartbeat_input(test_did("agent1"), 1000)).unwrap();
        record.receipt_hash = Hash256::ZERO;
        assert!(monitor.record(record).is_err());

        let mut record =
            HeartbeatRecord::new(valid_heartbeat_input(test_did("agent1"), 1000)).unwrap();
        record.status = HeartbeatStatus::Failed;
        assert!(!record.verify_receipt_hash().unwrap());
        assert!(monitor.record(record).is_err());
    }

    #[test]
    fn heartbeat_input_validation_rejects_placeholder_and_regressive_time() {
        let mut input = valid_heartbeat_input(test_did("agent1"), 1000);
        input.id = Uuid::nil();
        assert!(HeartbeatRecord::new(input).is_err());

        let mut input = valid_heartbeat_input(test_did("agent1"), 1000);
        input.newco_id = Uuid::nil();
        assert!(HeartbeatRecord::new(input).is_err());

        let mut input = valid_heartbeat_input(test_did("agent1"), 1000);
        input.started = Timestamp::ZERO;
        assert!(HeartbeatRecord::new(input).is_err());

        let mut input = valid_heartbeat_input(test_did("agent1"), 1000);
        input.finished = Some(Timestamp::new(999, 0));
        assert!(HeartbeatRecord::new(input).is_err());
    }

    #[test]
    fn monitor_validate_rejects_deserialized_inconsistencies() {
        let did = test_did("agent1");
        let record = make_heartbeat(did.clone(), 1000);
        let mut monitor = HeartbeatMonitor::new();
        monitor.record(record.clone()).unwrap();
        assert!(monitor.validate().is_ok());

        let mut mismatched_key = HeartbeatMonitor::new();
        let other = test_did("other");
        mismatched_key
            .last_seen
            .insert(other.clone(), record.started);
        mismatched_key.history.insert(other, vec![record.clone()]);
        assert!(mismatched_key.validate().is_err());

        let mut stale_last_seen = monitor.clone();
        stale_last_seen
            .last_seen
            .insert(did.clone(), Timestamp::new(1, 0));
        assert!(stale_last_seen.validate().is_err());

        let mut missing_history = HeartbeatMonitor::new();
        missing_history
            .last_seen
            .insert(did, Timestamp::new(1000, 0));
        assert!(missing_history.validate().is_err());
    }

    #[test]
    fn record_and_last_seen() {
        let mut monitor = HeartbeatMonitor::new();
        let did = test_did("agent1");
        monitor.record(make_heartbeat(did.clone(), 1000)).unwrap();
        assert_eq!(monitor.last_seen(&did).unwrap().physical_ms, 1000);
        assert_eq!(monitor.agent_count(), 1);
    }

    #[test]
    fn no_alerts_when_healthy() {
        let mut monitor = HeartbeatMonitor::new();
        let did = test_did("agent1");
        monitor.record(make_heartbeat(did, 1000)).unwrap();

        let now = Timestamp {
            physical_ms: 1500,
            logical: 0,
        };
        assert!(monitor.check_health(&now).is_empty());
    }

    #[test]
    fn warning_alert() {
        let mut monitor = HeartbeatMonitor::with_thresholds(100, 200);
        let did = test_did("agent1");
        monitor.record(make_heartbeat(did, 1000)).unwrap();

        let now = Timestamp {
            physical_ms: 1150,
            logical: 0,
        };
        let alerts = monitor.check_health(&now);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
    }

    #[test]
    fn critical_alert() {
        let mut monitor = HeartbeatMonitor::with_thresholds(100, 200);
        let did = test_did("agent1");
        monitor.record(make_heartbeat(did, 1000)).unwrap();

        let now = Timestamp {
            physical_ms: 1250,
            logical: 0,
        };
        let alerts = monitor.check_health(&now);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn multiple_agents() {
        let mut monitor = HeartbeatMonitor::with_thresholds(100, 200);
        monitor.record(make_heartbeat(test_did("a"), 1000)).unwrap();
        monitor.record(make_heartbeat(test_did("b"), 900)).unwrap();

        let now = Timestamp {
            physical_ms: 1150,
            logical: 0,
        };
        let alerts = monitor.check_health(&now);
        // Agent "a" is at 150ms (warning), "b" is at 250ms (critical)
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn history_tracking() {
        let mut monitor = HeartbeatMonitor::new();
        let did = test_did("agent1");
        monitor.record(make_heartbeat(did.clone(), 1000)).unwrap();
        monitor.record(make_heartbeat(did.clone(), 2000)).unwrap();
        assert_eq!(monitor.history(&did).unwrap().len(), 2);
    }

    #[test]
    fn status_serde() {
        let statuses = [
            HeartbeatStatus::Queued,
            HeartbeatStatus::Running,
            HeartbeatStatus::Completed,
            HeartbeatStatus::Failed,
            HeartbeatStatus::TimedOut,
        ];
        for s in &statuses {
            let j = serde_json::to_string(s).unwrap();
            let rt: HeartbeatStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, s);
        }
    }
}
