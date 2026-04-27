//! Tenant sharding strategy for horizontal scaling.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, TenantError};

/// Sharding strategy for distributing tenants across storage backends.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShardStrategy {
    /// Hash-based sharding on tenant ID.
    HashBased { total_shards: u32 },
    /// Range-based sharding on tenant creation order.
    RangeBased { shard_size: u32 },
    /// Geographic sharding for data residency compliance.
    Geographic { region: String },
    /// Single shard — all tenants in one database.
    Single,
}

/// Assignment of a tenant to a specific shard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardAssignment {
    pub tenant_id: Uuid,
    pub shard_id: u32,
    pub strategy: ShardStrategy,
    pub connection_pool: String,
}

impl ShardStrategy {
    /// Compute shard ID for a tenant.
    pub fn assign(&self, tenant_id: Uuid) -> Result<u32> {
        if tenant_id == Uuid::nil() {
            return Err(TenantError::ShardError {
                reason: "tenant id must not be nil".into(),
            });
        }
        match self {
            ShardStrategy::HashBased { total_shards } => {
                if *total_shards == 0 {
                    return Err(TenantError::ShardError {
                        reason: "total_shards must be greater than zero".into(),
                    });
                }
                let bytes = tenant_id.as_bytes();
                let hash = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Ok(hash % total_shards)
            }
            ShardStrategy::RangeBased { shard_size } => {
                if *shard_size == 0 {
                    return Err(TenantError::ShardError {
                        reason: "shard_size must be greater than zero".into(),
                    });
                }
                let bytes = tenant_id.as_bytes();
                let keyspace_position =
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Ok(keyspace_position / shard_size)
            }
            ShardStrategy::Geographic { .. } => Ok(0), // Single region shard
            ShardStrategy::Single => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_based_sharding() {
        let strategy = ShardStrategy::HashBased { total_shards: 16 };
        let tenant = Uuid::from_bytes([1u8; 16]);
        let shard = strategy.assign(tenant).unwrap();
        assert!(shard < 16);
    }

    #[test]
    fn hash_based_rejects_zero_total_shards() {
        let strategy = ShardStrategy::HashBased { total_shards: 0 };
        assert!(strategy.assign(Uuid::from_bytes([1u8; 16])).is_err());
    }

    #[test]
    fn test_deterministic_assignment() {
        let strategy = ShardStrategy::HashBased { total_shards: 8 };
        let tenant = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let shard1 = strategy.assign(tenant).unwrap();
        let shard2 = strategy.assign(tenant).unwrap();
        assert_eq!(shard1, shard2);
    }

    #[test]
    fn test_single_shard() {
        let strategy = ShardStrategy::Single;
        let shard = strategy.assign(Uuid::from_bytes([1u8; 16])).unwrap();
        assert_eq!(shard, 0);
    }

    #[test]
    fn range_based_rejects_zero_shard_size() {
        let strategy = ShardStrategy::RangeBased { shard_size: 0 };
        assert!(strategy.assign(Uuid::from_bytes([1u8; 16])).is_err());
    }

    #[test]
    fn range_based_uses_configured_shard_size() {
        let tenant = Uuid::from_bytes([16u8; 16]);
        let smaller_ranges = ShardStrategy::RangeBased { shard_size: 16 };
        let larger_ranges = ShardStrategy::RangeBased { shard_size: 64 };
        assert_ne!(
            smaller_ranges.assign(tenant).unwrap(),
            larger_ranges.assign(tenant).unwrap()
        );
    }
}
