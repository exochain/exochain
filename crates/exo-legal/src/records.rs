//! Records management — retention policies and disposition lifecycle.

use std::collections::BTreeMap;

use exo_core::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
#[must_use]
pub fn create_record(data: &[u8], classification: &str, retention_days: u64) -> Record {
    Record {
        id: Uuid::new_v4(),
        content_hash: Hash256::digest(data),
        classification: Classification(classification.into()),
        retention_period_days: retention_days,
        created: Timestamp::ZERO,
        disposition: Disposition::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn create_is_active() {
        let r = create_record(b"d", "g", 365);
        assert_eq!(r.disposition, Disposition::Active);
    }
    #[test]
    fn create_hashes() {
        let r = create_record(b"x", "g", 30);
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
        let mut r = vec![create_record(b"o", "g", 30)];
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(31 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::PendingDestruction);
    }
    #[test]
    fn retention_keeps_fresh() {
        let mut r = vec![create_record(b"n", "g", 30)];
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(10 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::Active);
    }
    #[test]
    fn retention_skips_hold() {
        let mut r = vec![create_record(b"h", "g", 1)];
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
        let mut r = vec![create_record(b"g", "g", 1)];
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
        let mut r = vec![create_record(b"d", "legal", 30)];
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
        let mut r = vec![create_record(b"b", "g", 30)];
        apply_retention(
            &mut r,
            &RetentionPolicy::new(),
            &Timestamp::new(30 * MS_PER_DAY, 0),
        );
        assert_eq!(r[0].disposition, Disposition::PendingDestruction);
    }
}
