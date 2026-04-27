//! Authority chain caching — LRU-like cache for resolved chains.

use std::collections::BTreeMap;

use exo_core::{Did, Timestamp};

use crate::chain::AuthorityChain;

/// Maximum number of cached entries.
const DEFAULT_MAX_ENTRIES: usize = 10000;

/// Key for the chain cache.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    from: String,
    to: String,
}

/// A cached chain entry with an access timestamp.
#[derive(Debug, Clone)]
struct CacheEntry {
    chain: AuthorityChain,
    last_accessed: Timestamp,
}

/// LRU-like cache for resolved authority chains.
#[derive(Debug)]
pub struct ChainCache {
    entries: BTreeMap<CacheKey, CacheEntry>,
    max_entries: usize,
}

impl ChainCache {
    /// Create a new cache with the default max entries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// Create a cache with a custom capacity.
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
        }
    }

    /// Get a cached chain, updating access time.
    pub fn get(&mut self, from: &Did, to: &Did, now: &Timestamp) -> Option<&AuthorityChain> {
        let key = CacheKey {
            from: from.as_str().to_owned(),
            to: to.as_str().to_owned(),
        };
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_accessed = *now;
            Some(&entry.chain)
        } else {
            None
        }
    }

    /// Insert a chain into the cache.
    pub fn insert(&mut self, from: &Did, to: &Did, chain: AuthorityChain, now: &Timestamp) {
        // Evict if at capacity
        while self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        let key = CacheKey {
            from: from.as_str().to_owned(),
            to: to.as_str().to_owned(),
        };
        self.entries.insert(
            key,
            CacheEntry {
                chain,
                last_accessed: *now,
            },
        );
    }

    /// Invalidate all chains involving a specific DID.
    pub fn invalidate(&mut self, did: &Did) {
        let did_str = did.as_str();
        self.entries
            .retain(|key, _| key.from != did_str && key.to != did_str);
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the cache empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Evict the oldest entry (lowest last_accessed timestamp).
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, v)| v.last_accessed)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

impl Default for ChainCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use exo_core::Signature;

    use super::*;
    use crate::{
        chain::{AuthorityChain, AuthorityLink},
        permission::Permission,
    };

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn make_chain(from: &str, to: &str) -> AuthorityChain {
        AuthorityChain {
            links: vec![AuthorityLink {
                delegator_did: did(from),
                delegate_did: did(to),
                scope: vec![Permission::Read],
                created: ts(1000),
                expires: None,
                signature: Signature::from_bytes([0xA5u8; 64]),
                depth: 0,
                delegatee_kind: crate::chain::DelegateeKind::Human,
            }],
            max_depth: 5,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut cache = ChainCache::new();
        let chain = make_chain("alice", "bob");
        cache.insert(&did("alice"), &did("bob"), chain, &ts(1000));
        let got = cache.get(&did("alice"), &did("bob"), &ts(2000));
        assert!(got.is_some());
        assert_eq!(got.unwrap().depth(), 1);
    }

    #[test]
    fn get_updates_access_time() {
        let mut cache = ChainCache::new();
        cache.insert(
            &did("alice"),
            &did("bob"),
            make_chain("alice", "bob"),
            &ts(1000),
        );
        cache.get(&did("alice"), &did("bob"), &ts(5000));
        // Access updated — won't be evicted first
        cache.insert(&did("x"), &did("y"), make_chain("x", "y"), &ts(2000));
        // Both should still be there
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn get_miss() {
        let mut cache = ChainCache::new();
        assert!(cache.get(&did("alice"), &did("bob"), &ts(1000)).is_none());
    }

    #[test]
    fn invalidate_removes_related() {
        let mut cache = ChainCache::new();
        cache.insert(
            &did("alice"),
            &did("bob"),
            make_chain("alice", "bob"),
            &ts(1000),
        );
        cache.insert(
            &did("alice"),
            &did("charlie"),
            make_chain("alice", "charlie"),
            &ts(1000),
        );
        cache.insert(
            &did("dave"),
            &did("eve"),
            make_chain("dave", "eve"),
            &ts(1000),
        );
        assert_eq!(cache.len(), 3);

        cache.invalidate(&did("alice"));
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&did("dave"), &did("eve"), &ts(2000)).is_some());
    }

    #[test]
    fn invalidate_as_target() {
        let mut cache = ChainCache::new();
        cache.insert(
            &did("alice"),
            &did("bob"),
            make_chain("alice", "bob"),
            &ts(1000),
        );
        cache.invalidate(&did("bob"));
        assert!(cache.is_empty());
    }

    #[test]
    fn eviction_on_capacity() {
        let mut cache = ChainCache::with_capacity(2);
        cache.insert(&did("a"), &did("b"), make_chain("a", "b"), &ts(1000));
        cache.insert(&did("c"), &did("d"), make_chain("c", "d"), &ts(2000));
        assert_eq!(cache.len(), 2);

        // This should evict the oldest (a->b at ts 1000)
        cache.insert(&did("e"), &did("f"), make_chain("e", "f"), &ts(3000));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&did("a"), &did("b"), &ts(4000)).is_none());
        assert!(cache.get(&did("c"), &did("d"), &ts(4000)).is_some());
    }

    #[test]
    fn clear() {
        let mut cache = ChainCache::new();
        cache.insert(&did("a"), &did("b"), make_chain("a", "b"), &ts(1000));
        cache.insert(&did("c"), &did("d"), make_chain("c", "d"), &ts(1000));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn default_is_empty() {
        let cache = ChainCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn invalidate_unknown_did_is_noop() {
        let mut cache = ChainCache::new();
        cache.insert(&did("a"), &did("b"), make_chain("a", "b"), &ts(1000));
        cache.invalidate(&did("unknown"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn eviction_respects_access_time_update() {
        let mut cache = ChainCache::with_capacity(2);
        cache.insert(&did("a"), &did("b"), make_chain("a", "b"), &ts(1000));
        cache.insert(&did("c"), &did("d"), make_chain("c", "d"), &ts(2000));

        // Access a->b, making it newer than c->d
        cache.get(&did("a"), &did("b"), &ts(3000));

        // Insert new entry — should evict c->d (oldest access = ts 2000)
        cache.insert(&did("e"), &did("f"), make_chain("e", "f"), &ts(4000));
        assert!(cache.get(&did("a"), &did("b"), &ts(5000)).is_some());
        assert!(cache.get(&did("c"), &did("d"), &ts(5000)).is_none());
    }
}
