//! Cold storage archival for long-term retention.

use std::collections::BTreeMap;

use exo_core::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, TenantError};

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
    pub created_at: Timestamp,
}

impl ArchivalPolicy {
    /// Create a default 50-year retention policy.
    pub fn default_50_year(tenant_id: Uuid, created_at: Timestamp) -> Result<Self> {
        if tenant_id == Uuid::nil() {
            return Err(TenantError::InvalidTenant {
                reason: "tenant id must not be nil".into(),
            });
        }
        if created_at == Timestamp::ZERO {
            return Err(TenantError::InvalidTenant {
                reason: "created timestamp must be caller-supplied HLC".into(),
            });
        }
        Ok(Self {
            tenant_id,
            hot_to_warm_days: 90,
            warm_to_cold_days: 365,
            cold_to_archive_days: 365 * 3,
            retention_years: 50,
            created_at,
        })
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
    pub archived_at: Timestamp,
    pub content_hash: Hash256,
}

/// Cold storage service (trait for S3/Glacier backends).
pub struct ColdStorage {
    refs: BTreeMap<(Uuid, String), ColdStorageRef>,
}

impl ColdStorage {
    /// Create an empty cold storage tracker.
    pub fn new() -> Self {
        Self {
            refs: BTreeMap::new(),
        }
    }

    /// Record an archival operation.
    pub fn record_archival(&mut self, reference: ColdStorageRef) -> Result<()> {
        Self::validate_reference(&reference)?;
        let key = (reference.tenant_id, reference.object_key.clone());
        if self.refs.contains_key(&key) {
            return Err(TenantError::ColdStorageReferenceAlreadyExists {
                tenant_id: reference.tenant_id,
                object_key: reference.object_key,
            });
        }
        self.refs.insert(key, reference);
        Ok(())
    }

    /// Get all archived references for a tenant.
    pub fn for_tenant(&self, tenant_id: Uuid) -> Vec<&ColdStorageRef> {
        self.refs
            .values()
            .filter(|reference| reference.tenant_id == tenant_id)
            .collect()
    }

    /// Total archived size for a tenant.
    pub fn archived_size(&self, tenant_id: Uuid) -> u64 {
        self.for_tenant(tenant_id)
            .iter()
            .map(|reference| reference.size_bytes)
            .sum()
    }

    fn validate_reference(reference: &ColdStorageRef) -> Result<()> {
        if reference.tenant_id == Uuid::nil() {
            return Err(TenantError::StorageError {
                reason: "tenant id must not be nil".into(),
            });
        }
        if reference.object_key.trim().is_empty() {
            return Err(TenantError::StorageError {
                reason: "object key must not be empty".into(),
            });
        }
        if reference.size_bytes == 0 {
            return Err(TenantError::StorageError {
                reason: "archived size must be greater than zero".into(),
            });
        }
        if reference.archived_at == Timestamp::ZERO {
            return Err(TenantError::StorageError {
                reason: "archived timestamp must be caller-supplied HLC".into(),
            });
        }
        if reference.content_hash == Hash256::ZERO {
            return Err(TenantError::StorageError {
                reason: "content hash must not be zero".into(),
            });
        }
        Ok(())
    }
}

impl Default for ColdStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use exo_core::{Hash256, Timestamp};

    use super::*;

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    #[test]
    fn test_archival_policy_tier_assignment() {
        let tenant = uuid(1);
        let policy = ArchivalPolicy::default_50_year(tenant, ts(1_700_000_000_000)).unwrap();

        assert_eq!(policy.tier_for_age_days(30), StorageTier::Hot);
        assert_eq!(policy.tier_for_age_days(100), StorageTier::Warm);
        assert_eq!(policy.tier_for_age_days(400), StorageTier::Cold);
        assert_eq!(policy.tier_for_age_days(2000), StorageTier::DeepArchive);
    }

    #[test]
    fn default_50_year_records_supplied_hlc_timestamp() {
        let created_at = ts(1_700_000_000_000);
        let policy = ArchivalPolicy::default_50_year(uuid(1), created_at).unwrap();
        assert_eq!(policy.created_at, created_at);
    }

    #[test]
    fn default_50_year_rejects_nil_tenant() {
        assert!(ArchivalPolicy::default_50_year(Uuid::nil(), ts(1_700_000_000_000)).is_err());
    }

    #[test]
    fn default_50_year_rejects_zero_created_at() {
        assert!(ArchivalPolicy::default_50_year(uuid(1), Timestamp::ZERO).is_err());
    }

    #[test]
    fn test_cold_storage_tracking() {
        let mut cold = ColdStorage::new();
        let tenant = uuid(1);

        cold.record_archival(ColdStorageRef {
            tenant_id: tenant,
            object_key: "events/2024/q1.cbor".into(),
            tier: StorageTier::Cold,
            size_bytes: 1024 * 1024,
            archived_at: ts(1_700_000_000_000),
            content_hash: Hash256::digest(b"events/2024/q1.cbor"),
        })
        .unwrap();

        assert_eq!(cold.for_tenant(tenant).len(), 1);
        assert_eq!(cold.archived_size(tenant), 1024 * 1024);
    }

    #[test]
    fn record_archival_rejects_wrong_placeholder_fields() {
        let mut cold = ColdStorage::new();
        let valid = ColdStorageRef {
            tenant_id: uuid(1),
            object_key: "events/2024/q1.cbor".into(),
            tier: StorageTier::Cold,
            size_bytes: 1024,
            archived_at: ts(1_700_000_000_000),
            content_hash: Hash256::digest(b"events/2024/q1.cbor"),
        };

        let mut nil_tenant = valid.clone();
        nil_tenant.tenant_id = Uuid::nil();
        assert!(cold.record_archival(nil_tenant).is_err());

        let mut empty_key = valid.clone();
        empty_key.object_key.clear();
        assert!(cold.record_archival(empty_key).is_err());

        let mut zero_size = valid.clone();
        zero_size.size_bytes = 0;
        assert!(cold.record_archival(zero_size).is_err());

        let mut zero_timestamp = valid.clone();
        zero_timestamp.archived_at = Timestamp::ZERO;
        assert!(cold.record_archival(zero_timestamp).is_err());

        let mut zero_hash = valid;
        zero_hash.content_hash = Hash256::ZERO;
        assert!(cold.record_archival(zero_hash).is_err());
    }

    #[test]
    fn record_archival_rejects_duplicate_tenant_object_key() {
        let mut cold = ColdStorage::new();
        let reference = ColdStorageRef {
            tenant_id: uuid(1),
            object_key: "events/2024/q1.cbor".into(),
            tier: StorageTier::Cold,
            size_bytes: 1024,
            archived_at: ts(1_700_000_000_000),
            content_hash: Hash256::digest(b"events/2024/q1.cbor"),
        };
        cold.record_archival(reference.clone()).unwrap();
        assert!(cold.record_archival(reference).is_err());
    }
}
