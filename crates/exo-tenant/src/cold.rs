//! Cold storage archival for long-term retention.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Storage tier for data lifecycle management.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageTier {
    /// Hot storage — fast access, PostgreSQL.
    Hot,
    /// Warm storage — reduced access speed, S3 Standard.
    Warm,
    /// Cold storage — infrequent access, S3 Glacier.
    Cold,
    /// Archive — deep archive, 50-year retention.
    DeepArchive,
}

/// Archival policy for a tenant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchivalPolicy {
    pub tenant_id: Uuid,
    pub hot_to_warm_days: u32,
    pub warm_to_cold_days: u32,
    pub cold_to_archive_days: u32,
    pub retention_years: u32,
    pub created_at: DateTime<Utc>,
}

impl ArchivalPolicy {
    /// Create a default 50-year retention policy.
    pub fn default_50_year(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            hot_to_warm_days: 90,
            warm_to_cold_days: 365,
            cold_to_archive_days: 365 * 3,
            retention_years: 50,
            created_at: Utc::now(),
        }
    }

    /// Determine the target tier for data of a given age.
    pub fn tier_for_age_days(&self, age_days: u32) -> StorageTier {
        if age_days >= self.cold_to_archive_days {
            StorageTier::DeepArchive
        } else if age_days >= self.warm_to_cold_days {
            StorageTier::Cold
        } else if age_days >= self.hot_to_warm_days {
            StorageTier::Warm
        } else {
            StorageTier::Hot
        }
    }
}

/// A cold storage reference — pointer to archived data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColdStorageRef {
    pub tenant_id: Uuid,
    pub object_key: String,
    pub tier: StorageTier,
    pub size_bytes: u64,
    pub archived_at: DateTime<Utc>,
    pub content_hash: exo_core::crypto::Blake3Hash,
}

/// Cold storage service (trait for S3/Glacier backends).
pub struct ColdStorage {
    refs: Vec<ColdStorageRef>,
}

impl ColdStorage {
    /// Create an empty cold storage tracker.
    pub fn new() -> Self {
        Self { refs: Vec::new() }
    }

    /// Record an archival operation.
    pub fn record_archival(&mut self, reference: ColdStorageRef) {
        self.refs.push(reference);
    }

    /// Get all archived references for a tenant.
    pub fn for_tenant(&self, tenant_id: Uuid) -> Vec<&ColdStorageRef> {
        self.refs
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Total archived size for a tenant.
    pub fn archived_size(&self, tenant_id: Uuid) -> u64 {
        self.for_tenant(tenant_id)
            .iter()
            .map(|r| r.size_bytes)
            .sum()
    }
}

impl Default for ColdStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archival_policy_tier_assignment() {
        let tenant = Uuid::new_v4();
        let policy = ArchivalPolicy::default_50_year(tenant);

        assert_eq!(policy.tier_for_age_days(30), StorageTier::Hot);
        assert_eq!(policy.tier_for_age_days(100), StorageTier::Warm);
        assert_eq!(policy.tier_for_age_days(400), StorageTier::Cold);
        assert_eq!(policy.tier_for_age_days(2000), StorageTier::DeepArchive);
    }

    #[test]
    fn test_cold_storage_tracking() {
        let mut cold = ColdStorage::new();
        let tenant = Uuid::new_v4();

        cold.record_archival(ColdStorageRef {
            tenant_id: tenant,
            object_key: "events/2024/q1.cbor".into(),
            tier: StorageTier::Cold,
            size_bytes: 1024 * 1024,
            archived_at: Utc::now(),
            content_hash: exo_core::crypto::Blake3Hash([1u8; 32]),
        });

        assert_eq!(cold.for_tenant(tenant).len(), 1);
        assert_eq!(cold.archived_size(tenant), 1024 * 1024);
    }
}
