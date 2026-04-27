//! Records management — retention policies and disposition lifecycle.

use std::collections::BTreeMap;

use exo_core::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LegalError, Result};

/// Lifecycle state of a legal record under the retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disposition {
    Active,
    RetentionHold,
    PendingDestruction,
    Destroyed,
}

/// Opaque classification label used to match records to retention rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Classification(pub String);

/// A content-addressed legal record with retention metadata and disposition tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub content_hash: Hash256,
    pub classification: Classification,
    pub retention_period_days: u64,
    pub created: Timestamp,
    pub disposition: Disposition,
}

/// Maps classification labels to retention durations (in days).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub rules: BTreeMap<Classification, u64>,
}
impl RetentionPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: BTreeMap::new(),
        }
    }
    pub fn add_rule(&mut self, c: Classification, days: u64) {
        self.rules.insert(c, days);
    }
}

const MS_PER_DAY: u64 = 86_400_000;

/// Marks records whose retention period has elapsed as `PendingDestruction`.
pub fn apply_retention(records: &mut [Record], policy: &RetentionPolicy, now: &Timestamp) {
    for rec in records.iter_mut() {
        if rec.disposition == Disposition::Destroyed
            || rec.disposition == Disposition::RetentionHold
        {
            continue;
        }
        let days = policy
            .rules
            .get(&rec.classification)
            .copied()
            .unwrap_or(rec.retention_period_days);
        let age = now.physical_ms.saturating_sub(rec.created.physical_ms);
        if age >= days.saturating_mul(MS_PER_DAY) {
            rec.disposition = Disposition::PendingDestruction;
        }
    }
}

/// Creates a new active record with a content hash and the given retention period.
pub fn create_record(
    id: Uuid,
    data: &[u8],
    classification: &str,
    retention_days: u64,
    created: Timestamp,
) -> Result<Record> {
    if id.is_nil() {
        return Err(LegalError::InvalidStateTransition {
            reason: "record ID must be caller-supplied and non-nil".into(),
        });
    }
    if classification.trim().is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "record classification must not be empty".into(),
        });
    }
    if retention_days == 0 {
        return Err(LegalError::InvalidStateTransition {
            reason: "record retention period must be nonzero".into(),
        });
    }
    if created == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "record created timestamp must not be Timestamp::ZERO".into(),
        });
    }
    Ok(Record {
        id,
        content_hash: Hash256::digest(data),
        classification: Classification(classification.into()),
        retention_period_days: retention_days,
        created,
        disposition: Disposition::Active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    #[test]
    fn create_uses_caller_supplied_metadata() {
        let record_id = id(0x200);
        let r = create_record(record_id, b"d", "g", 365, ts(1000)).unwrap();
        assert_eq!(r.id, record_id);
        assert_eq!(r.created, ts(1000));
    }

    #[test]
    fn create_rejects_placeholder_metadata() {
        assert!(create_record(Uuid::nil(), b"d", "g", 365, ts(1000)).is_err());
        assert!(create_record(id(0x201), b"d", "g", 365, Timestamp::ZERO).is_err());
        assert!(create_record(id(0x202), b"d", "g", 0, ts(1000)).is_err());
        assert!(create_record(id(0x203), b"d", " ", 365, ts(1000)).is_err());
    }

    #[test]
    fn create_is_active() {
        let r = create_record(id(0x204), b"d", "g", 365, ts(1000)).unwrap();
        assert_eq!(r.disposition, Disposition::Active);
    }
    #[test]
    fn create_hashes() {
        let r = create_record(id(0x205), b"x", "g", 30, ts(1000)).unwrap();
        assert_eq!(r.content_hash, Hash256::digest(b"x"));
    }
    #[test]
    fn policy_default() {
        assert!(RetentionPolicy::default().rules.is_empty());
    }
    #[test]
    fn policy_add() {
        let mut p = RetentionPolicy::new();
        p.add_rule(Classification("l".into()), 100);
        assert_eq!(p.rules.get(&Classification("l".into())), Some(&100));
    }
    #[test]
    fn retention_marks_expired() {
        let mut r = vec![create_record(id(0x206), b"o", "g", 30, ts(1)).unwrap()];
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(31 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::PendingDestruction);
    }
    #[test]
    fn retention_keeps_fresh() {
        let mut r = vec![create_record(id(0x207), b"n", "g", 30, ts(1)).unwrap()];
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(10 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::Active);
    }
    #[test]
    fn retention_skips_hold() {
        let mut r = vec![create_record(id(0x208), b"h", "g", 1, ts(1)).unwrap()];
        r[0].disposition = Disposition::RetentionHold;
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(100 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::RetentionHold);
    }
    #[test]
    fn retention_skips_destroyed() {
        let mut r = vec![create_record(id(0x209), b"g", "g", 1, ts(1)).unwrap()];
        r[0].disposition = Disposition::Destroyed;
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(100 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::Destroyed);
    }
    #[test]
    fn retention_policy_override() {
        let mut r = vec![create_record(id(0x20a), b"d", "legal", 30, ts(1)).unwrap()];
        let mut p = RetentionPolicy::new();
        p.add_rule(Classification("legal".into()), 365);
        apply_retention(&mut r, &p, &Timestamp::new(31 * MS_PER_DAY, 0));
        assert_eq!(r[0].disposition, Disposition::Active);
    }
    #[test]
    fn disposition_serde() {
        for d in [
            Disposition::Active,
            Disposition::RetentionHold,
            Disposition::PendingDestruction,
            Disposition::Destroyed,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let r: Disposition = serde_json::from_str(&j).unwrap();
            assert_eq!(r, d);
        }
    }
    #[test]
    fn boundary() {
        let mut r = vec![create_record(id(0x20b), b"b", "g", 30, ts(1)).unwrap()];
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(30 * MS_PER_DAY + 1, 0),
        );
        assert_eq!(r[0].disposition, Disposition::PendingDestruction);
    }
}
