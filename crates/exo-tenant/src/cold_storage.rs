//! Cold storage lifecycle — tiered storage migration.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, TenantError};

/// Tiered storage classification for data lifecycle migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    pub tier: StorageTier,
}

/// Manages storage tier assignments and enforces migration rules.
#[derive(Debug, Default)]
pub struct StorageManager {
    pub records: BTreeMap<Uuid, StorageTier>,
}

impl StorageManager {
    /// Create an empty storage manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Register an item at the specified storage tier.
    pub fn register(&mut self, id: Uuid, tier: StorageTier) {
        self.records.insert(id, tier);
    }

    /// Migrate an item from one tier to a colder (or equal) tier.
    pub fn migrate(&mut self, id: &Uuid, from: StorageTier, to: StorageTier) -> Result<()> {
        let current = self.records.get(id).ok_or(TenantError::StorageError {
            reason: format!("record {id} not found"),
        })?;
        if *current != from {
            return Err(TenantError::MigrationError {
                reason: format!("expected {from:?}, found {current:?}"),
            });
        }
        // Can only move to colder or same tier (Hot -> Warm -> Cold -> Archive)
        if to < from {
            return Err(TenantError::MigrationError {
                reason: format!("cannot promote from {from:?} to {to:?}"),
            });
        }
        self.records.insert(*id, to);
        Ok(())
    }

    /// Return the current storage tier for an item, if registered.
    #[must_use]
    pub fn get_tier(&self, id: &Uuid) -> Option<StorageTier> {
        self.records.get(id).copied()
    }
    /// Count items currently assigned to the given tier.
    #[must_use]
    pub fn count_by_tier(&self, tier: StorageTier) -> usize {
        self.records.values().filter(|t| **t == tier).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn register_and_get() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Hot);
        assert_eq!(m.get_tier(&id), Some(StorageTier::Hot));
    }
    #[test]
    fn migrate_hot_to_warm() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Hot);
        m.migrate(&id, StorageTier::Hot, StorageTier::Warm).unwrap();
        assert_eq!(m.get_tier(&id), Some(StorageTier::Warm));
    }
    #[test]
    fn migrate_warm_to_cold() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Warm);
        m.migrate(&id, StorageTier::Warm, StorageTier::Cold)
            .unwrap();
    }
    #[test]
    fn migrate_cold_to_archive() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Cold);
        m.migrate(&id, StorageTier::Cold, StorageTier::Archive)
            .unwrap();
    }
    #[test]
    fn cannot_promote() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Cold);
        assert!(m.migrate(&id, StorageTier::Cold, StorageTier::Hot).is_err());
    }
    #[test]
    fn wrong_current_tier() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Hot);
        assert!(
            m.migrate(&id, StorageTier::Cold, StorageTier::Archive)
                .is_err()
        );
    }
    #[test]
    fn not_found() {
        let mut m = StorageManager::new();
        assert!(
            m.migrate(&Uuid::nil(), StorageTier::Hot, StorageTier::Warm)
                .is_err()
        );
    }
    #[test]
    fn count_by_tier() {
        let mut m = StorageManager::new();
        m.register(Uuid::new_v4(), StorageTier::Hot);
        m.register(Uuid::new_v4(), StorageTier::Hot);
        m.register(Uuid::new_v4(), StorageTier::Cold);
        assert_eq!(m.count_by_tier(StorageTier::Hot), 2);
        assert_eq!(m.count_by_tier(StorageTier::Cold), 1);
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
        assert!(StorageManager::default().records.is_empty());
    }
    #[test]
    fn same_tier_ok() {
        let mut m = StorageManager::new();
        let id = Uuid::new_v4();
        m.register(id, StorageTier::Warm);
        m.migrate(&id, StorageTier::Warm, StorageTier::Warm)
            .unwrap();
    }
}
