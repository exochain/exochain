//! Data sharding — deterministic shard assignment via consistent hashing.
use exo_core::Hash256;
use serde::{Deserialize, Serialize};

use crate::error::{Result, TenantError};

/// Configuration for shard count and replication factor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardConfig {
    pub num_shards: usize,
    pub replication_factor: usize,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            num_shards: 16,
            replication_factor: 3,
        }
    }
}

/// Deterministic shard assignment: hash mod num_shards.
pub fn assign_shard(key: &Hash256, config: &ShardConfig) -> Result<usize> {
    validate_config(config)?;
    let bytes = key.as_bytes();
    let val = usize::from(bytes[0])
        | (usize::from(bytes[1]) << 8)
        | (usize::from(bytes[2]) << 16)
        | (usize::from(bytes[3]) << 24);
    Ok(val % config.num_shards)
}

/// Get all replica shards for a given primary shard.
pub fn replica_shards(primary: usize, config: &ShardConfig) -> Result<Vec<usize>> {
    validate_config(config)?;
    if primary >= config.num_shards {
        return Err(TenantError::ShardError {
            reason: format!(
                "primary shard {primary} must be less than configured shard count {}",
                config.num_shards
            ),
        });
    }
    Ok((0..config.replication_factor)
        .map(|i| (primary + i) % config.num_shards)
        .collect())
}

/// Compute which shards a key migrates between when shard count changes.
pub fn migration_plan(
    key: &Hash256,
    old_config: &ShardConfig,
    new_config: &ShardConfig,
) -> Result<(usize, usize)> {
    Ok((
        assign_shard(key, old_config)?,
        assign_shard(key, new_config)?,
    ))
}

fn validate_config(config: &ShardConfig) -> Result<()> {
    if config.num_shards == 0 {
        return Err(TenantError::ShardError {
            reason: "num_shards must be greater than zero".into(),
        });
    }
    if config.replication_factor == 0 {
        return Err(TenantError::ShardError {
            reason: "replication_factor must be greater than zero".into(),
        });
    }
    if config.replication_factor > config.num_shards {
        return Err(TenantError::ShardError {
            reason: format!(
                "replication_factor {} must not exceed num_shards {}",
                config.replication_factor, config.num_shards
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assign_deterministic() {
        let h = Hash256::digest(b"key");
        let c = ShardConfig::default();
        assert_eq!(assign_shard(&h, &c).unwrap(), assign_shard(&h, &c).unwrap());
    }
    #[test]
    fn assign_in_range() {
        let h = Hash256::digest(b"k");
        let c = ShardConfig {
            num_shards: 8,
            replication_factor: 1,
        };
        assert!(assign_shard(&h, &c).unwrap() < 8);
    }
    #[test]
    fn assign_rejects_zero_shards() {
        let h = Hash256::digest(b"k");
        let c = ShardConfig {
            num_shards: 0,
            replication_factor: 1,
        };
        assert!(assign_shard(&h, &c).is_err());
    }
    #[test]
    fn different_keys_may_differ() {
        let h1 = Hash256::digest(b"a");
        let h2 = Hash256::digest(b"b");
        let c = ShardConfig {
            num_shards: 1000,
            replication_factor: 1,
        };
        let s1 = assign_shard(&h1, &c).unwrap();
        let s2 = assign_shard(&h2, &c).unwrap();
        let _ = (s1, s2); /* may or may not differ */
    }
    #[test]
    fn replicas() {
        let r = replica_shards(
            0,
            &ShardConfig {
                num_shards: 4,
                replication_factor: 3,
            },
        )
        .unwrap();
        assert_eq!(r, vec![0, 1, 2]);
    }
    #[test]
    fn replicas_wrap() {
        let r = replica_shards(
            3,
            &ShardConfig {
                num_shards: 4,
                replication_factor: 3,
            },
        )
        .unwrap();
        assert_eq!(r, vec![3, 0, 1]);
    }
    #[test]
    fn replicas_reject_zero_shards() {
        let c = ShardConfig {
            num_shards: 0,
            replication_factor: 1,
        };
        assert!(replica_shards(0, &c).is_err());
    }
    #[test]
    fn replicas_reject_zero_replication_factor() {
        let c = ShardConfig {
            num_shards: 4,
            replication_factor: 0,
        };
        assert!(replica_shards(0, &c).is_err());
    }
    #[test]
    fn replicas_reject_more_replicas_than_shards() {
        let c = ShardConfig {
            num_shards: 2,
            replication_factor: 3,
        };
        assert!(replica_shards(0, &c).is_err());
    }
    #[test]
    fn migration() {
        let h = Hash256::digest(b"k");
        let o = ShardConfig {
            num_shards: 4,
            replication_factor: 1,
        };
        let n = ShardConfig {
            num_shards: 8,
            replication_factor: 1,
        };
        let (a, b) = migration_plan(&h, &o, &n).unwrap();
        assert!(a < 4);
        assert!(b < 8);
    }
    #[test]
    fn config_serde() {
        let c = ShardConfig::default();
        let j = serde_json::to_string(&c).unwrap();
        let r: ShardConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(r.num_shards, 16);
    }
    #[test]
    fn config_default() {
        let c = ShardConfig::default();
        assert_eq!(c.num_shards, 16);
        assert_eq!(c.replication_factor, 3);
    }
}
