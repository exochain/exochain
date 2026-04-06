//! Data sharding — deterministic shard assignment via consistent hashing.
use exo_core::Hash256;
use serde::{Deserialize, Serialize};

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
#[must_use]
pub fn assign_shard(key: &Hash256, config: &ShardConfig) -> usize {
    let bytes = key.as_bytes();
    let val = usize::from(bytes[0])
        | (usize::from(bytes[1]) << 8)
        | (usize::from(bytes[2]) << 16)
        | (usize::from(bytes[3]) << 24);
    val % config.num_shards
}

/// Get all replica shards for a given primary shard.
#[must_use]
pub fn replica_shards(primary: usize, config: &ShardConfig) -> Vec<usize> {
    (0..config.replication_factor)
        .map(|i| (primary + i) % config.num_shards)
        .collect()
}

/// Compute which shards a key migrates between when shard count changes.
#[must_use]
pub fn migration_plan(
    key: &Hash256,
    old_config: &ShardConfig,
    new_config: &ShardConfig,
) -> (usize, usize) {
    (assign_shard(key, old_config), assign_shard(key, new_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assign_deterministic() {
        let h = Hash256::digest(b"key");
        let c = ShardConfig::default();
        assert_eq!(assign_shard(&h, &c), assign_shard(&h, &c));
    }
    #[test]
    fn assign_in_range() {
        let h = Hash256::digest(b"k");
        let c = ShardConfig {
            num_shards: 8,
            replication_factor: 1,
        };
        assert!(assign_shard(&h, &c) < 8);
    }
    #[test]
    fn different_keys_may_differ() {
        let h1 = Hash256::digest(b"a");
        let h2 = Hash256::digest(b"b");
        let c = ShardConfig {
            num_shards: 1000,
            replication_factor: 1,
        };
        let s1 = assign_shard(&h1, &c);
        let s2 = assign_shard(&h2, &c);
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
        );
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
        );
        assert_eq!(r, vec![3, 0, 1]);
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
        let (a, b) = migration_plan(&h, &o, &n);
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
