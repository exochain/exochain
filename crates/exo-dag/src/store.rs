// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Persistent storage abstraction for the DAG.

use std::collections::BTreeMap;

use exo_core::types::Hash256;

use crate::{
    dag::DagNode,
    error::{DagError, Result},
};

// ---------------------------------------------------------------------------
// DagStore trait
// ---------------------------------------------------------------------------

/// Abstraction over persistent storage for DAG nodes.
#[async_trait::async_trait]
pub trait DagStore: Send + Sync {
    /// Retrieve a node by hash.
    async fn get(&self, hash: &Hash256) -> Result<Option<DagNode>>;
    /// Store a node.
    async fn put(&mut self, node: DagNode) -> Result<()>;
    /// Check if a node exists.
    async fn contains(&self, hash: &Hash256) -> Result<bool>;
    /// Return the current tip hashes.
    async fn tips(&self) -> Result<Vec<Hash256>>;
    /// Return the number of committed (finalized) nodes.
    async fn committed_height(&self) -> Result<u64>;
    /// Mark a node as committed at the given height.
    async fn mark_committed(&mut self, hash: &Hash256, height: u64) -> Result<()>;
}

// ---------------------------------------------------------------------------
// MemoryStore
// ---------------------------------------------------------------------------

/// In-memory implementation of `DagStore` using `BTreeMap` for determinism.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    nodes: BTreeMap<Hash256, DagNode>,
    children: BTreeMap<Hash256, Vec<Hash256>>,
    committed: BTreeMap<Hash256, u64>,
    max_committed_height: u64,
}

impl MemoryStore {
    /// Create a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    // ------------------------------------------------------------------
    // Sync convenience methods — for benchmarks and non-async contexts.
    // ------------------------------------------------------------------

    /// Sync version of `DagStore::get`.
    pub fn get_sync(&self, hash: &Hash256) -> Result<Option<DagNode>> {
        Ok(self.nodes.get(hash).cloned())
    }

    /// Sync version of `DagStore::put`.
    pub fn put_sync(&mut self, node: DagNode) -> Result<()> {
        let hash = node.hash;
        for parent in &node.parents {
            self.children.entry(*parent).or_default().push(hash);
        }
        self.children.entry(hash).or_default();
        self.nodes.insert(hash, node);
        Ok(())
    }

    /// Sync version of `DagStore::contains`.
    pub fn contains_sync(&self, hash: &Hash256) -> Result<bool> {
        Ok(self.nodes.contains_key(hash))
    }

    /// Sync version of `DagStore::tips`.
    pub fn tips_sync(&self) -> Result<Vec<Hash256>> {
        let mut result: Vec<Hash256> = self
            .nodes
            .keys()
            .filter(|h| self.children.get(*h).is_none_or(std::vec::Vec::is_empty))
            .copied()
            .collect();
        result.sort();
        Ok(result)
    }

    /// Sync version of `DagStore::committed_height`.
    pub fn committed_height_sync(&self) -> Result<u64> {
        Ok(self.max_committed_height)
    }

    /// Sync version of `DagStore::mark_committed`.
    pub fn mark_committed_sync(&mut self, hash: &Hash256, height: u64) -> Result<()> {
        if !self.nodes.contains_key(hash) {
            return Err(DagError::NodeNotFound(*hash));
        }
        self.committed.insert(*hash, height);
        if height > self.max_committed_height {
            self.max_committed_height = height;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DagStore for MemoryStore {
    async fn get(&self, hash: &Hash256) -> Result<Option<DagNode>> {
        self.get_sync(hash)
    }

    async fn put(&mut self, node: DagNode) -> Result<()> {
        self.put_sync(node)
    }

    async fn contains(&self, hash: &Hash256) -> Result<bool> {
        self.contains_sync(hash)
    }

    async fn tips(&self) -> Result<Vec<Hash256>> {
        self.tips_sync()
    }

    async fn committed_height(&self) -> Result<u64> {
        self.committed_height_sync()
    }

    async fn mark_committed(&mut self, hash: &Hash256, height: u64) -> Result<()> {
        self.mark_committed_sync(hash, height)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::types::{Did, Signature};

    use super::*;
    use crate::dag::{Dag, DeterministicDagClock, append};

    type SignFn = Box<dyn Fn(&[u8]) -> Signature>;

    fn make_sign_fn() -> SignFn {
        Box::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn make_test_node() -> DagNode {
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();
        append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap()
    }

    #[tokio::test]
    async fn new_store_is_empty() {
        let store = MemoryStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.committed_height().await.unwrap(), 0);
        assert!(store.tips().await.unwrap().is_empty());
    }

    #[test]
    fn default_store() {
        let store = MemoryStore::default();
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn put_and_get() {
        let mut store = MemoryStore::new();
        let node = make_test_node();

        store.put(node.clone()).await.unwrap();

        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        let retrieved = store.get(&node.hash).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, node.hash);
    }

    #[tokio::test]
    async fn get_nonexistent() {
        let store = MemoryStore::new();
        let result = store.get(&Hash256::ZERO).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn contains() {
        let mut store = MemoryStore::new();
        let node = make_test_node();

        assert!(!store.contains(&node.hash).await.unwrap());
        store.put(node.clone()).await.unwrap();
        assert!(store.contains(&node.hash).await.unwrap());
    }

    #[tokio::test]
    async fn tips_single_node() {
        let mut store = MemoryStore::new();
        let node = make_test_node();
        store.put(node.clone()).await.unwrap();
        let t = store.tips().await.unwrap();
        assert_eq!(t, vec![node.hash]);
    }

    #[tokio::test]
    async fn tips_with_children() {
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let child = append(
            &mut dag,
            &[genesis.hash],
            b"child",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let mut store = MemoryStore::new();
        store.put(genesis).await.unwrap();
        store.put(child.clone()).await.unwrap();

        let t = store.tips().await.unwrap();
        assert_eq!(t, vec![child.hash]);
    }

    #[tokio::test]
    async fn committed_height_tracking() {
        let mut store = MemoryStore::new();
        let node = make_test_node();
        store.put(node.clone()).await.unwrap();

        assert_eq!(store.committed_height().await.unwrap(), 0);

        store.mark_committed(&node.hash, 1).await.unwrap();
        assert_eq!(store.committed_height().await.unwrap(), 1);

        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:test2").expect("valid");
        let sign_fn = make_sign_fn();
        let node2 = append(&mut dag, &[], b"other", &creator, &*sign_fn, &mut clock).unwrap();
        store.put(node2.clone()).await.unwrap();
        store.mark_committed(&node2.hash, 5).await.unwrap();
        assert_eq!(store.committed_height().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn mark_committed_nonexistent_fails() {
        let mut store = MemoryStore::new();
        let err = store.mark_committed(&Hash256::ZERO, 1).await.unwrap_err();
        assert!(matches!(err, DagError::NodeNotFound(_)));
    }

    #[tokio::test]
    async fn multiple_tips() {
        let mut dag = Dag::new();
        let mut clock = DeterministicDagClock::new();
        let creator = Did::new("did:exo:test").expect("valid");
        let sign_fn = make_sign_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let c1 = append(
            &mut dag,
            &[genesis.hash],
            b"c1",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        let c2 = append(
            &mut dag,
            &[genesis.hash],
            b"c2",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let mut store = MemoryStore::new();
        store.put(genesis).await.unwrap();
        store.put(c1.clone()).await.unwrap();
        store.put(c2.clone()).await.unwrap();

        let t = store.tips().await.unwrap();
        assert_eq!(t.len(), 2);
        assert!(t.contains(&c1.hash));
        assert!(t.contains(&c2.hash));
    }
}
