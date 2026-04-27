//! Append-only directed acyclic graph.
//!
//! Guarantees: append-only (no deletion, no mutation), deterministic ordering.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use exo_core::types::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{DagError, Result};

// ---------------------------------------------------------------------------
// HybridClock — monotonic logical clock for deterministic timestamps
// ---------------------------------------------------------------------------

/// Hybrid Logical Clock for deterministic, monotonic timestamps.
#[derive(Debug, Clone)]
pub struct HybridClock {
    latest: Timestamp,
}

impl HybridClock {
    /// Create a new clock starting at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            latest: Timestamp::ZERO,
        }
    }

    /// Create a clock with a specific starting time.
    #[must_use]
    pub fn with_time(millis: u64) -> Self {
        Self {
            latest: Timestamp::new(millis, 0),
        }
    }

    /// Tick the clock, returning a new monotonically increasing timestamp.
    pub fn tick(&mut self) -> Timestamp {
        self.latest = Timestamp::new(self.latest.physical_ms, self.latest.logical + 1);
        self.latest
    }

    /// Advance the clock to at least the given time, then tick.
    pub fn advance(&mut self, millis: u64) -> Timestamp {
        if millis > self.latest.physical_ms {
            self.latest = Timestamp::new(millis, 0);
        }
        self.tick()
    }
}

impl Default for HybridClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DagNode
// ---------------------------------------------------------------------------

/// A node in the append-only DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagNode {
    /// Blake3 hash of (sorted parents || payload_hash || creator_did || timestamp).
    pub hash: Hash256,
    /// Parent node hashes, sorted for determinism.
    pub parents: Vec<Hash256>,
    /// Hash of the payload data.
    pub payload_hash: Hash256,
    /// DID of the creator.
    pub creator_did: Did,
    /// Deterministic timestamp from hybrid clock.
    pub timestamp: Timestamp,
    /// Signature over the node hash.
    pub signature: Signature,
}

/// Compute the canonical hash of a DAG node from its fields.
#[must_use]
pub fn compute_node_hash(
    parents: &[Hash256],
    payload_hash: &Hash256,
    creator_did: &Did,
    timestamp: &Timestamp,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    for p in parents {
        hasher.update(p.as_bytes());
    }
    hasher.update(payload_hash.as_bytes());
    hasher.update(creator_did.as_str().as_bytes());
    hasher.update(&timestamp.physical_ms.to_le_bytes());
    hasher.update(&timestamp.logical.to_le_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Dag
// ---------------------------------------------------------------------------

/// The append-only directed acyclic graph.
#[derive(Debug, Clone, Default)]
pub struct Dag {
    /// All nodes indexed by their hash.
    nodes: BTreeMap<Hash256, DagNode>,
    /// For each node, the set of children (nodes that list it as a parent).
    children: BTreeMap<Hash256, BTreeSet<Hash256>>,
}

impl Dag {
    /// Create a new empty DAG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nodes in the DAG.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the DAG is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Append a new node to the DAG.
///
/// Genesis node (empty parents) is only allowed when the DAG is empty.
pub fn append(
    dag: &mut Dag,
    parents: &[Hash256],
    payload: &[u8],
    creator: &Did,
    sign_fn: &dyn Fn(&[u8]) -> Signature,
    clock: &mut HybridClock,
) -> Result<DagNode> {
    // Genesis node can have empty parents only when DAG is empty
    if parents.is_empty() && !dag.is_empty() {
        return Err(DagError::EmptyParents);
    }

    // Verify all parents exist
    for p in parents {
        if !dag.nodes.contains_key(p) {
            return Err(DagError::ParentNotFound(*p));
        }
    }

    // Sort parents for determinism
    let mut sorted_parents = parents.to_vec();
    sorted_parents.sort();
    sorted_parents.dedup();

    let payload_hash = Hash256::digest(payload);
    let timestamp = clock.tick();
    let hash = compute_node_hash(&sorted_parents, &payload_hash, creator, &timestamp);

    // Check for duplicate
    if dag.nodes.contains_key(&hash) {
        return Err(DagError::NodeAlreadyExists(hash));
    }

    let signature = sign_fn(hash.as_bytes());

    let node = DagNode {
        hash,
        parents: sorted_parents.clone(),
        payload_hash,
        creator_did: creator.clone(),
        timestamp,
        signature,
    };

    // Update children index
    for p in &sorted_parents {
        dag.children.entry(*p).or_default().insert(hash);
    }
    dag.children.entry(hash).or_default();

    dag.nodes.insert(hash, node.clone());
    Ok(node)
}

/// Get a node by hash.
#[must_use]
pub fn get<'a>(dag: &'a Dag, hash: &Hash256) -> Option<&'a DagNode> {
    dag.nodes.get(hash)
}

/// Return all ancestors of the given node in topological order (parents before children).
pub fn ancestors(dag: &Dag, hash: &Hash256) -> Vec<Hash256> {
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    if let Some(node) = dag.nodes.get(hash) {
        for p in &node.parents {
            if visited.insert(*p) {
                queue.push_back(*p);
            }
        }
    }

    while let Some(current) = queue.pop_front() {
        if let Some(node) = dag.nodes.get(&current) {
            for p in &node.parents {
                if visited.insert(*p) {
                    queue.push_back(*p);
                }
            }
        }
    }

    let hashes: Vec<Hash256> = visited.into_iter().collect();
    topological_sort(dag, &hashes)
}

/// Topological sort of a set of node hashes.
fn topological_sort(dag: &Dag, hashes: &[Hash256]) -> Vec<Hash256> {
    let hash_set: BTreeSet<Hash256> = hashes.iter().copied().collect();
    let mut in_degree: BTreeMap<Hash256, usize> = BTreeMap::new();
    let mut adj: BTreeMap<Hash256, Vec<Hash256>> = BTreeMap::new();

    for h in &hash_set {
        in_degree.entry(*h).or_insert(0);
        adj.entry(*h).or_default();
    }

    // Build edges: parent -> child (within the subset)
    for h in &hash_set {
        if let Some(node) = dag.nodes.get(h) {
            for p in &node.parents {
                if hash_set.contains(p) {
                    adj.entry(*p).or_default().push(*h);
                    *in_degree.entry(*h).or_insert(0) += 1;
                }
            }
        }
    }

    let mut queue: VecDeque<Hash256> = VecDeque::new();
    let mut roots: Vec<Hash256> = in_degree
        .iter()
        .filter(|&(_, &d)| d == 0)
        .map(|(h, _)| *h)
        .collect();
    roots.sort();
    queue.extend(roots);

    let mut result = Vec::new();
    while let Some(current) = queue.pop_front() {
        result.push(current);
        let neighbors = adj.get(&current).cloned().unwrap_or_default();
        let mut next_batch = Vec::new();
        for neighbor in neighbors {
            if let Some(deg) = in_degree.get_mut(&neighbor) {
                *deg = deg.saturating_sub(1);
                if *deg == 0 {
                    next_batch.push(neighbor);
                }
            }
        }
        next_batch.sort();
        queue.extend(next_batch);
    }

    result
}

/// Return the tip nodes -- nodes with no children.
pub fn tips(dag: &Dag) -> Vec<Hash256> {
    let mut result: Vec<Hash256> = dag
        .nodes
        .keys()
        .filter(|h| {
            dag.children
                .get(*h)
                .is_none_or(std::collections::BTreeSet::is_empty)
        })
        .copied()
        .collect();
    result.sort();
    result
}

/// Verify a node: check hash, parent existence, and signature.
pub fn verify_node(
    dag: &Dag,
    node: &DagNode,
    verify_fn: &dyn Fn(&[u8], &Signature) -> bool,
) -> Result<()> {
    // Verify parents are sorted and deduplicated
    let mut sorted = node.parents.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != node.parents {
        return Err(DagError::InvalidSignature(node.hash));
    }

    // Verify hash
    let expected_hash = compute_node_hash(
        &node.parents,
        &node.payload_hash,
        &node.creator_did,
        &node.timestamp,
    );
    if expected_hash != node.hash {
        return Err(DagError::InvalidSignature(node.hash));
    }

    // Verify all parents exist (unless genesis)
    for p in &node.parents {
        if !dag.nodes.contains_key(p) {
            return Err(DagError::ParentNotFound(*p));
        }
    }

    // Verify signature
    if !verify_fn(node.hash.as_bytes(), &node.signature) {
        return Err(DagError::InvalidSignature(node.hash));
    }

    // Check for cycles: node's hash must not appear in its own ancestors
    if !node.parents.is_empty() {
        let ancs = ancestors(dag, &node.hash);
        if ancs.contains(&node.hash) {
            return Err(DagError::CycleDetected(node.hash));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    type SignFn = Box<dyn Fn(&[u8]) -> Signature>;
    type VerifyFn = Box<dyn Fn(&[u8], &Signature) -> bool>;

    fn test_did(name: &str) -> Did {
        Did::new(name).expect("valid DID")
    }

    fn make_sign_fn() -> SignFn {
        Box::new(|data: &[u8]| {
            // Deterministic "signature" for testing: blake3 hash padded to 64 bytes
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    fn make_verify_fn() -> VerifyFn {
        Box::new(|data: &[u8], sig: &Signature| {
            let h = blake3::hash(data);
            sig.as_bytes()[..32] == *h.as_bytes()
        })
    }

    #[test]
    fn genesis_node() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let node = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        assert_eq!(dag.len(), 1);
        assert!(!dag.is_empty());
        assert!(node.parents.is_empty());
        assert_eq!(node.creator_did, creator);
    }

    #[test]
    fn append_with_parents() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
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

        assert_eq!(dag.len(), 2);
        assert_eq!(child.parents, vec![genesis.hash]);
    }

    #[test]
    fn empty_parents_non_genesis_rejected() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let _genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        let err = append(&mut dag, &[], b"orphan", &creator, &*sign_fn, &mut clock).unwrap_err();
        assert!(matches!(err, DagError::EmptyParents));
    }

    #[test]
    fn orphan_parent_rejected() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let fake_parent = Hash256::digest(b"nonexistent");
        let err = append(
            &mut dag,
            &[fake_parent],
            b"orphan",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap_err();
        assert!(matches!(err, DagError::ParentNotFound(_)));
    }

    #[test]
    fn parents_sorted_and_deduped() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let g1 = append(&mut dag, &[], b"g1", &creator, &*sign_fn, &mut clock).unwrap();
        let child = append(
            &mut dag,
            &[g1.hash, g1.hash],
            b"child",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        assert_eq!(child.parents.len(), 1);
    }

    #[test]
    fn get_node() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        assert!(get(&dag, &genesis.hash).is_some());
        assert!(get(&dag, &Hash256::ZERO).is_none());
    }

    #[test]
    fn tips_computation() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let g = append(&mut dag, &[], b"g", &creator, &*sign_fn, &mut clock).unwrap();
        assert_eq!(tips(&dag), vec![g.hash]);

        let c1 = append(&mut dag, &[g.hash], b"c1", &creator, &*sign_fn, &mut clock).unwrap();
        let c2 = append(&mut dag, &[g.hash], b"c2", &creator, &*sign_fn, &mut clock).unwrap();

        let t = tips(&dag);
        assert_eq!(t.len(), 2);
        assert!(t.contains(&c1.hash));
        assert!(t.contains(&c2.hash));

        // Merge c1 and c2
        let _merge = append(
            &mut dag,
            &[c1.hash, c2.hash],
            b"merge",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();
        assert_eq!(tips(&dag).len(), 1);
    }

    #[test]
    fn ancestors_topological() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let g = append(&mut dag, &[], b"g", &creator, &*sign_fn, &mut clock).unwrap();
        let c1 = append(&mut dag, &[g.hash], b"c1", &creator, &*sign_fn, &mut clock).unwrap();
        let c2 = append(&mut dag, &[c1.hash], b"c2", &creator, &*sign_fn, &mut clock).unwrap();

        let ancs = ancestors(&dag, &c2.hash);
        assert_eq!(ancs.len(), 2);
        let g_pos = ancs.iter().position(|h| *h == g.hash).unwrap();
        let c1_pos = ancs.iter().position(|h| *h == c1.hash).unwrap();
        assert!(g_pos < c1_pos);
    }

    #[test]
    fn ancestors_empty_for_genesis() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let g = append(&mut dag, &[], b"g", &creator, &*sign_fn, &mut clock).unwrap();
        assert!(ancestors(&dag, &g.hash).is_empty());
    }

    #[test]
    fn ancestors_nonexistent_node() {
        let dag = Dag::new();
        assert!(ancestors(&dag, &Hash256::ZERO).is_empty());
    }

    #[test]
    fn verify_node_valid() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();
        let verify_fn = make_verify_fn();

        let genesis = append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        assert!(verify_node(&dag, &genesis, &*verify_fn).is_ok());
    }

    #[test]
    fn verify_node_bad_signature() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let mut genesis =
            append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        genesis.signature = Signature::from_bytes([0u8; 64]);

        let verify_fn: VerifyFn = Box::new(|_data: &[u8], _sig: &Signature| false);

        let err = verify_node(&dag, &genesis, &*verify_fn).unwrap_err();
        assert!(matches!(err, DagError::InvalidSignature(_)));
    }

    #[test]
    fn verify_node_bad_hash() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();
        let verify_fn = make_verify_fn();

        let mut genesis =
            append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).unwrap();
        genesis.hash = Hash256::ZERO;

        let err = verify_node(&dag, &genesis, &*verify_fn).unwrap_err();
        assert!(matches!(err, DagError::InvalidSignature(_)));
    }

    #[test]
    fn verify_node_unsorted_parents() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();
        let verify_fn = make_verify_fn();

        let g1 = append(&mut dag, &[], b"g1", &creator, &*sign_fn, &mut clock).unwrap();
        let c = append(&mut dag, &[g1.hash], b"c", &creator, &*sign_fn, &mut clock).unwrap();

        let mut tampered = c.clone();
        tampered.parents = vec![g1.hash, Hash256::ZERO];

        let result = verify_node(&dag, &tampered, &*verify_fn);
        assert!(result.is_err());
    }

    #[test]
    fn diamond_dag() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did("did:exo:alice");
        let sign_fn = make_sign_fn();

        let g = append(&mut dag, &[], b"g", &creator, &*sign_fn, &mut clock).unwrap();
        let a = append(&mut dag, &[g.hash], b"a", &creator, &*sign_fn, &mut clock).unwrap();
        let b = append(&mut dag, &[g.hash], b"b", &creator, &*sign_fn, &mut clock).unwrap();
        let merge = append(
            &mut dag,
            &[a.hash, b.hash],
            b"merge",
            &creator,
            &*sign_fn,
            &mut clock,
        )
        .unwrap();

        let ancs = ancestors(&dag, &merge.hash);
        assert_eq!(ancs.len(), 3);
        assert!(ancs.contains(&g.hash));
        assert!(ancs.contains(&a.hash));
        assert!(ancs.contains(&b.hash));
    }

    #[test]
    fn hybrid_clock_monotonic() {
        let mut clock = HybridClock::new();
        let t1 = clock.tick();
        let t2 = clock.tick();
        let t3 = clock.tick();
        assert!(t1 < t2);
        assert!(t2 < t3);
    }

    #[test]
    fn hybrid_clock_advance() {
        let mut clock = HybridClock::with_time(100);
        let t1 = clock.advance(200);
        assert_eq!(t1.physical_ms, 200);
        assert_eq!(t1.logical, 1);

        // Advancing to earlier time should not go backwards
        let t2 = clock.advance(50);
        assert!(t1 < t2);
    }

    #[test]
    fn hybrid_clock_default() {
        let clock = HybridClock::default();
        assert_eq!(clock.latest, Timestamp::ZERO);
    }

    #[test]
    fn deterministic_hash() {
        let parents = vec![Hash256::digest(b"p1")];
        let payload = Hash256::digest(b"payload");
        let creator = test_did("did:exo:test");
        let ts = Timestamp::new(1000, 1);

        let h1 = compute_node_hash(&parents, &payload, &creator, &ts);
        let h2 = compute_node_hash(&parents, &payload, &creator, &ts);
        assert_eq!(h1, h2);
    }

    #[test]
    fn tips_empty_dag() {
        let dag = Dag::new();
        assert!(tips(&dag).is_empty());
    }

    #[test]
    fn multiple_creators() {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let alice = test_did("did:exo:alice");
        let bob = test_did("did:exo:bob");
        let sign_fn = make_sign_fn();

        let g = append(&mut dag, &[], b"g", &alice, &*sign_fn, &mut clock).unwrap();
        let c = append(&mut dag, &[g.hash], b"c", &bob, &*sign_fn, &mut clock).unwrap();

        assert_eq!(c.creator_did, bob);
        assert_eq!(g.creator_did, alice);
    }
}
