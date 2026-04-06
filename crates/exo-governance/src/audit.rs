//! Governance audit trail — append-only, hash-chained log.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::GovernanceError;

/// A single entry in the hash-chained audit log, linking to the previous entry via `chain_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: Timestamp,
    pub actor: Did,
    pub action: String,
    pub result: String,
    pub evidence_hash: [u8; 32],
    pub chain_hash: [u8; 32],
}

/// Append-only, hash-chained governance audit log for tamper detection.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create a new empty audit log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Return the hash of the most recent entry, or all-zeros if the log is empty.
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.entries.last().map(hash_entry).unwrap_or([0u8; 32])
    }

    /// Return the number of entries in the audit log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Return `true` if the audit log contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn hash_entry(entry: &AuditEntry) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(entry.id.as_bytes());
    h.update(&entry.timestamp.physical_ms.to_le_bytes());
    h.update(&entry.timestamp.logical.to_le_bytes());
    h.update(entry.actor.as_str().as_bytes());
    h.update(entry.action.as_bytes());
    h.update(entry.result.as_bytes());
    h.update(&entry.evidence_hash);
    h.update(&entry.chain_hash);
    *h.finalize().as_bytes()
}

/// Append an entry to the audit log, verifying its chain hash matches the current head.
pub fn append(log: &mut AuditLog, entry: AuditEntry) -> Result<(), GovernanceError> {
    let head = log.head_hash();
    if entry.chain_hash != head {
        return Err(GovernanceError::AuditChainBroken {
            sequence: u64::try_from(log.entries.len()).unwrap_or(u64::MAX),
            expected: Hash256(head),
            actual: Hash256(entry.chain_hash),
        });
    }
    log.entries.push(entry);
    Ok(())
}

/// Verify the integrity of the entire audit chain, returning an error at the first broken link.
pub fn verify_chain(log: &AuditLog) -> Result<(), GovernanceError> {
    let mut prev = [0u8; 32];
    for (i, entry) in log.entries.iter().enumerate() {
        if entry.chain_hash != prev {
            return Err(GovernanceError::AuditChainBroken {
                sequence: u64::try_from(i).unwrap_or(u64::MAX),
                expected: Hash256(prev),
                actual: Hash256(entry.chain_hash),
            });
        }
        prev = hash_entry(entry);
    }
    Ok(())
}

/// Create a new audit entry chained to the current log head, ready for appending.
#[must_use]
pub fn create_entry(
    log: &AuditLog,
    actor: Did,
    action: String,
    result: String,
    evidence_hash: [u8; 32],
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        timestamp: Timestamp::now_utc(),
        actor,
        action,
        result,
        evidence_hash,
        chain_hash: log.head_hash(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).expect("ok")
    }

    fn make_and_append(log: &mut AuditLog, act: &str) {
        let e = create_entry(log, did("auditor"), act.into(), "ok".into(), [0u8; 32]);
        append(log, e).expect("append failed");
    }

    #[test]
    fn empty_log_verifies() {
        assert!(verify_chain(&AuditLog::new()).is_ok());
    }
    #[test]
    fn append_single() {
        let mut log = AuditLog::new();
        make_and_append(&mut log, "a1");
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }
    #[test]
    fn chain_of_entries() {
        let mut log = AuditLog::new();
        for i in 0..5 {
            make_and_append(&mut log, &format!("a{i}"));
        }
        assert_eq!(log.len(), 5);
        assert!(verify_chain(&log).is_ok());
    }
    #[test]
    fn tamper_detected() {
        let mut log = AuditLog::new();
        for i in 0..3 {
            make_and_append(&mut log, &format!("a{i}"));
        }
        log.entries[1].chain_hash = [0xffu8; 32];
        match verify_chain(&log).unwrap_err() {
            GovernanceError::AuditChainBroken { sequence, .. } => assert_eq!(sequence, 1),
            e => panic!("unexpected: {e:?}"),
        }
    }
    #[test]
    fn wrong_chain_hash_rejected() {
        let mut log = AuditLog::new();
        make_and_append(&mut log, "a1");
        let bad = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Timestamp::new(2000, 0),
            actor: did("x"),
            action: "bad".into(),
            result: "bad".into(),
            evidence_hash: [0u8; 32],
            chain_hash: [0xffu8; 32],
        };
        assert!(append(&mut log, bad).is_err());
    }
    #[test]
    fn head_hash_changes() {
        let mut log = AuditLog::new();
        let h0 = log.head_hash();
        assert_eq!(h0, [0u8; 32]);
        make_and_append(&mut log, "a1");
        assert_ne!(log.head_hash(), h0);
    }
    #[test]
    fn deterministic_hash() {
        let e = AuditEntry {
            id: Uuid::nil(),
            timestamp: Timestamp::new(1000, 0),
            actor: did("test"),
            action: "test".into(),
            result: "ok".into(),
            evidence_hash: [0u8; 32],
            chain_hash: [0u8; 32],
        };
        assert_eq!(hash_entry(&e), hash_entry(&e));
    }
}
