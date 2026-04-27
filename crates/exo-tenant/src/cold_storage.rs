//! Cold storage lifecycle — tiered storage migration.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, TenantError};

/// Tiered storage classification for data lifecycle migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
    Archive,
}

/// A storage record associating an item with its current tier.
#[derive(Debug, Clone)]
pub struct StorageRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub tier: StorageTier,
}

/// Manages storage tier assignments and enforces migration rules.
#[derive(Debug, Default)]
pub struct StorageManager {
    records: BTreeMap<(Uuid, Uuid), StorageRecord>,
}

impl StorageManager {
    /// Create an empty storage manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Register an item at the specified storage tier for a tenant.
    pub fn register(&mut self, tenant_id: Uuid, id: Uuid, tier: StorageTier) -> Result<()> {
        Self::validate_key(&tenant_id, &id)?;
        let key = (tenant_id, id);
        if self.records.contains_key(&key) {
            return Err(TenantError::StorageRecordAlreadyExists {
                tenant_id,
                item_id: id,
            });
        }
        self.records.insert(
            key,
            StorageRecord {
                id,
                tenant_id,
                tier,
            },
        );
        Ok(())
    }

    /// Migrate an item from one tier to a colder (or equal) tier.
    pub fn migrate(
        &mut self,
        tenant_id: &Uuid,
        id: &Uuid,
        from: StorageTier,
        to: StorageTier,
    ) -> Result<()> {
        Self::validate_key(tenant_id, id)?;
        let record =
            self.records
                .get_mut(&(*tenant_id, *id))
                .ok_or(TenantError::StorageRecordNotFound {
                    tenant_id: *tenant_id,
                    item_id: *id,
                })?;
        if record.tier != from {
            return Err(TenantError::MigrationError {
                reason: format!("expected {from:?}, found {:?}", record.tier),
            });
        }
        // Can only move to colder or same tier (Hot -> Warm -> Cold -> Archive)
        if to < from {
            return Err(TenantError::MigrationError {
                reason: format!("cannot promote from {from:?} to {to:?}"),
            });
        }
        record.tier = to;
        Ok(())
    }

    /// Return the current storage tier for an item, if registered.
    #[must_use]
    pub fn get_tier(&self, tenant_id: &Uuid, id: &Uuid) -> Option<StorageTier> {
        self.records
            .get(&(*tenant_id, *id))
            .map(|record| record.tier)
    }

    /// Count items currently assigned to the given tier.
    #[must_use]
    pub fn count_by_tier(&self, tenant_id: &Uuid, tier: StorageTier) -> usize {
        self.records
            .values()
            .filter(|record| record.tenant_id == *tenant_id && record.tier == tier)
            .count()
    }

    /// Return `true` if there are no storage records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn validate_key(tenant_id: &Uuid, id: &Uuid) -> Result<()> {
        if *tenant_id == Uuid::nil() {
            return Err(TenantError::StorageError {
                reason: "tenant id must not be nil".into(),
            });
        }
        if *id == Uuid::nil() {
            return Err(TenantError::StorageError {
                reason: "item id must not be nil".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    #[test]
    fn register_and_get() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Hot).unwrap();
        assert_eq!(m.get_tier(&tenant_id, &id), Some(StorageTier::Hot));
    }

    #[test]
    fn register_rejects_nil_tenant_id() {
        let mut m = StorageManager::new();
        assert!(m.register(Uuid::nil(), uuid(10), StorageTier::Hot).is_err());
    }

    #[test]
    fn register_rejects_nil_item_id() {
        let mut m = StorageManager::new();
        assert!(m.register(uuid(1), Uuid::nil(), StorageTier::Hot).is_err());
    }

    #[test]
    fn register_rejects_duplicate_tenant_item_key() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Hot).unwrap();
        assert!(m.register(tenant_id, id, StorageTier::Cold).is_err());
    }

    #[test]
    fn migrate_hot_to_warm() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Hot).unwrap();
        m.migrate(&tenant_id, &id, StorageTier::Hot, StorageTier::Warm)
            .unwrap();
        assert_eq!(m.get_tier(&tenant_id, &id), Some(StorageTier::Warm));
    }
    #[test]
    fn migrate_warm_to_cold() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Warm).unwrap();
        m.migrate(&tenant_id, &id, StorageTier::Warm, StorageTier::Cold)
            .unwrap();
    }
    #[test]
    fn migrate_cold_to_archive() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Cold).unwrap();
        m.migrate(&tenant_id, &id, StorageTier::Cold, StorageTier::Archive)
            .unwrap();
    }
    #[test]
    fn cannot_promote() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Cold).unwrap();
        assert!(
            m.migrate(&tenant_id, &id, StorageTier::Cold, StorageTier::Hot)
                .is_err()
        );
    }
    #[test]
    fn wrong_current_tier() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Hot).unwrap();
        assert!(
            m.migrate(&tenant_id, &id, StorageTier::Cold, StorageTier::Archive)
                .is_err()
        );
    }
    #[test]
    fn not_found() {
        let mut m = StorageManager::new();
        assert!(
            m.migrate(&uuid(1), &uuid(10), StorageTier::Hot, StorageTier::Warm)
                .is_err()
        );
    }
    #[test]
    fn count_by_tier() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        m.register(tenant_id, uuid(10), StorageTier::Hot).unwrap();
        m.register(tenant_id, uuid(11), StorageTier::Hot).unwrap();
        m.register(tenant_id, uuid(12), StorageTier::Cold).unwrap();
        assert_eq!(m.count_by_tier(&tenant_id, StorageTier::Hot), 2);
        assert_eq!(m.count_by_tier(&tenant_id, StorageTier::Cold), 1);
    }

    #[test]
    fn same_item_id_is_scoped_by_tenant() {
        let mut m = StorageManager::new();
        let t1 = uuid(1);
        let t2 = uuid(2);
        let id = uuid(10);
        m.register(t1, id, StorageTier::Hot).unwrap();
        m.register(t2, id, StorageTier::Cold).unwrap();
        assert_eq!(m.get_tier(&t1, &id), Some(StorageTier::Hot));
        assert_eq!(m.get_tier(&t2, &id), Some(StorageTier::Cold));
        assert_eq!(m.count_by_tier(&t1, StorageTier::Hot), 1);
        assert_eq!(m.count_by_tier(&t2, StorageTier::Hot), 0);
    }

    #[test]
    fn migrate_wrong_tenant_does_not_touch_other_tenant_record() {
        let mut m = StorageManager::new();
        let t1 = uuid(1);
        let t2 = uuid(2);
        let id = uuid(10);
        m.register(t1, id, StorageTier::Hot).unwrap();
        assert!(
            m.migrate(&t2, &id, StorageTier::Hot, StorageTier::Warm)
                .is_err()
        );
        assert_eq!(m.get_tier(&t1, &id), Some(StorageTier::Hot));
    }
    #[test]
    fn tier_serde() {
        for t in [
            StorageTier::Hot,
            StorageTier::Warm,
            StorageTier::Cold,
            StorageTier::Archive,
        ] {
            let j = serde_json::to_string(&t).unwrap();
            let r: StorageTier = serde_json::from_str(&j).unwrap();
            assert_eq!(r, t);
        }
    }
    #[test]
    fn default() {
        assert!(StorageManager::default().is_empty());
    }
    #[test]
    fn same_tier_ok() {
        let mut m = StorageManager::new();
        let tenant_id = uuid(1);
        let id = uuid(10);
        m.register(tenant_id, id, StorageTier::Warm).unwrap();
        m.migrate(&tenant_id, &id, StorageTier::Warm, StorageTier::Warm)
            .unwrap();
    }
}
