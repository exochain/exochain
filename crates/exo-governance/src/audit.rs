//! Governance audit trail — append-only, hash-chained log.

use exo_core::{Did, Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::GovernanceError;

const AUDIT_ENTRY_HASH_DOMAIN: &str = "exo.governance.audit_entry.v1";
const AUDIT_ENTRY_HASH_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize)]
struct AuditEntryHashPayload {
    domain: &'static str,
    schema_version: u16,
    entry_id: Uuid,
    timestamp: Timestamp,
    actor: Did,
    action: String,
    result: String,
    evidence_hash: [u8; 32],
    chain_hash: [u8; 32],
}

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
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::Serialization`] if canonical CBOR hashing of
    /// the latest entry fails.
    pub fn head_hash(&self) -> Result<[u8; 32], GovernanceError> {
        match self.entries.last() {
            Some(entry) => hash_entry(entry),
            None => Ok([0u8; 32]),
        }
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

fn audit_entry_hash_payload(entry: &AuditEntry) -> AuditEntryHashPayload {
    AuditEntryHashPayload {
        domain: AUDIT_ENTRY_HASH_DOMAIN,
        schema_version: AUDIT_ENTRY_HASH_SCHEMA_VERSION,
        entry_id: entry.id,
        timestamp: entry.timestamp,
        actor: entry.actor.clone(),
        action: entry.action.clone(),
        result: entry.result.clone(),
        evidence_hash: entry.evidence_hash,
        chain_hash: entry.chain_hash,
    }
}

fn hash_entry(entry: &AuditEntry) -> Result<[u8; 32], GovernanceError> {
    hash_structured(&audit_entry_hash_payload(entry))
        .map(|hash| *hash.as_bytes())
        .map_err(|e| {
            GovernanceError::Serialization(format!("audit entry canonical CBOR hash failed: {e}"))
        })
}

/// Append an entry to the audit log, verifying its chain hash matches the current head.
pub fn append(log: &mut AuditLog, entry: AuditEntry) -> Result<(), GovernanceError> {
    let head = log.head_hash()?;
    if entry.chain_hash != head {
        let sequence = u64::try_from(log.entries.len()).map_err(|_| {
            GovernanceError::Serialization("audit log length does not fit u64 sequence".into())
        })?;
        return Err(GovernanceError::AuditChainBroken {
            sequence,
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
            let sequence = u64::try_from(i).map_err(|_| {
                GovernanceError::Serialization("audit log index does not fit u64 sequence".into())
            })?;
            return Err(GovernanceError::AuditChainBroken {
                sequence,
                expected: Hash256(prev),
                actual: Hash256(entry.chain_hash),
            });
        }
        prev = hash_entry(entry)?;
    }
    Ok(())
}

/// Create a new audit entry chained to the current log head, ready for appending.
pub fn create_entry(
    log: &AuditLog,
    id: Uuid,
    timestamp: Timestamp,
    actor: Did,
    action: String,
    result: String,
    evidence_hash: [u8; 32],
) -> Result<AuditEntry, GovernanceError> {
    if id.is_nil() {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "audit_entry.id".into(),
            reason: "must be caller-supplied and non-nil".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "audit_entry.timestamp".into(),
            reason: "must be caller-supplied and non-zero".into(),
        });
    }

    Ok(AuditEntry {
        id,
        timestamp,
        actor,
        action,
        result,
        evidence_hash,
        chain_hash: log.head_hash()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).expect("ok")
    }

    fn entry_id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn create_entry_source() -> &'static str {
        let source = include_str!("audit.rs");
        let start = source
            .find("pub fn create_entry(")
            .expect("create_entry source must exist");
        let end = source[start..]
            .find("#[cfg(test)]")
            .expect("tests marker must exist");
        &source[start..start + end]
    }

    fn production_source() -> &'static str {
        let source = include_str!("audit.rs");
        let end = source
            .find("#[cfg(test)]")
            .expect("tests marker must exist");
        &source[..end]
    }

    fn sample_entry() -> AuditEntry {
        AuditEntry {
            id: entry_id(0xD001),
            timestamp: Timestamp::new(1000, 7),
            actor: did("test"),
            action: "test".into(),
            result: "ok".into(),
            evidence_hash: [0x11u8; 32],
            chain_hash: [0x22u8; 32],
        }
    }

    #[test]
    fn audit_entry_hash_payload_is_domain_separated_cbor() {
        let entry = sample_entry();
        let payload = audit_entry_hash_payload(&entry);
        assert_eq!(payload.domain, AUDIT_ENTRY_HASH_DOMAIN);
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.entry_id, entry.id);
        assert_eq!(payload.timestamp, entry.timestamp);
        assert_eq!(payload.actor, entry.actor);
        assert_eq!(payload.action, entry.action);
        assert_eq!(payload.result, entry.result);
        assert_eq!(payload.evidence_hash, entry.evidence_hash);
        assert_eq!(payload.chain_hash, entry.chain_hash);
    }

    #[test]
    fn audit_entry_hash_rejects_legacy_raw_concat_hash() {
        let entry = sample_entry();
        let mut h = blake3::Hasher::new();
        h.update(entry.id.as_bytes());
        h.update(&entry.timestamp.physical_ms.to_le_bytes());
        h.update(&entry.timestamp.logical.to_le_bytes());
        h.update(entry.actor.as_str().as_bytes());
        h.update(entry.action.as_bytes());
        h.update(entry.result.as_bytes());
        h.update(&entry.evidence_hash);
        h.update(&entry.chain_hash);
        let legacy = *h.finalize().as_bytes();

        assert_ne!(hash_entry(&entry).expect("canonical audit hash"), legacy);
    }

    #[test]
    fn audit_production_source_has_no_raw_hash_loop() {
        let production = production_source();
        assert!(
            !production.contains("blake3::Hasher"),
            "governance audit hashes must use domain-separated canonical CBOR"
        );
        assert!(
            !production.contains("unwrap_or([0u8; 32])"),
            "audit hashing must not hide serialization failures behind a zero hash"
        );
    }

    #[test]
    fn create_entry_has_no_internal_entropy_or_wall_clock() {
        let source = create_entry_source();
        assert!(
            !source.contains("Uuid::new_v4"),
            "governance audit entries must not fabricate UUIDs internally"
        );
        let forbidden_timestamp = ["Timestamp::", "now_utc"].concat();
        assert!(
            !source.contains(&forbidden_timestamp),
            "governance audit entries must not read wall-clock time internally"
        );
    }

    fn make_and_append(log: &mut AuditLog, act: &str) {
        let offset = u128::try_from(log.len()).expect("log length fits u128");
        let timestamp_offset = u64::try_from(log.len()).expect("log length fits u64");
        let e = create_entry(
            log,
            entry_id(0xA000 + offset),
            ts(10_000 + timestamp_offset),
            did("auditor"),
            act.into(),
            "ok".into(),
            [0u8; 32],
        )
        .expect("deterministic audit entry");
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
            id: entry_id(0xB001),
            timestamp: ts(2000),
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
        let h0 = log.head_hash().expect("empty head hash");
        assert_eq!(h0, [0u8; 32]);
        make_and_append(&mut log, "a1");
        assert_ne!(log.head_hash().expect("head hash"), h0);
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
        assert_eq!(
            hash_entry(&e).expect("first hash"),
            hash_entry(&e).expect("second hash")
        );
    }

    #[test]
    fn create_entry_preserves_caller_supplied_metadata() {
        let log = AuditLog::new();
        let id = entry_id(0xC001);
        let timestamp = ts(20_000);
        let entry = create_entry(
            &log,
            id,
            timestamp,
            did("auditor"),
            "act".into(),
            "ok".into(),
            [0u8; 32],
        )
        .expect("deterministic audit entry");

        assert_eq!(entry.id, id);
        assert_eq!(entry.timestamp, timestamp);
    }

    #[test]
    fn create_entry_rejects_nil_id() {
        let err = create_entry(
            &AuditLog::new(),
            Uuid::nil(),
            ts(20_001),
            did("auditor"),
            "act".into(),
            "ok".into(),
            [0u8; 32],
        )
        .expect_err("nil audit entry id must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }

    #[test]
    fn create_entry_rejects_zero_timestamp() {
        let err = create_entry(
            &AuditLog::new(),
            entry_id(0xC002),
            Timestamp::ZERO,
            did("auditor"),
            "act".into(),
            "ok".into(),
            [0u8; 32],
        )
        .expect_err("zero audit entry timestamp must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }
}
