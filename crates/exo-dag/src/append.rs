//! Validated persistent-store DAG append with Byzantine clock defense.
//!
//! Extends the in-memory [`dag::append`](crate::dag::append) with:
//! - Wall-clock skew enforcement (±500ms tolerance)
//! - HLC causality validation (node timestamp must strictly exceed all parents)
//! - Stored-node integrity verification (hash recomputation)
//!
//! These checks implement the normative HLC check (EXOCHAIN Specification v2.2): event > parent,
//! preventing Byzantine clock manipulation in the trust fabric.

use exo_core::types::Hash256;

use crate::{
    dag::compute_node_hash,
    error::{DagError, Result},
    store::DagStore,
};

/// Maximum allowed clock skew between nodes (500ms).
///
/// Nodes claiming timestamps more than this far ahead of the wall clock
/// are rejected as potential Byzantine clock manipulation.
const MAX_CLOCK_SKEW_MS: u64 = 500;

/// Validate and append a DAG node to persistent storage.
///
/// Performs three checks beyond basic structure:
/// 1. **Wall-clock skew**: reject nodes with timestamps too far in the future
/// 2. **HLC causality**: node timestamp must strictly exceed all parent timestamps
/// 3. **Parent existence**: all parents must exist in the store
///
/// This is the normative append path for persistent deployments (EXOCHAIN Specification v2.2).
/// The in-memory [`dag::append`](crate::dag::append) handles local construction;
/// this function handles validation for nodes received from external sources.
pub async fn validated_append(store: &mut impl DagStore, node: crate::dag::DagNode) -> Result<()> {
    // 1. Wall-clock skew check: reject future-dated nodes
    if node.timestamp.physical_ms > 0 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        if node.timestamp.physical_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(DagError::StoreError(format!(
                "clock skew: node timestamp {} exceeds wall clock {} + {}ms tolerance",
                node.timestamp.physical_ms, now_ms, MAX_CLOCK_SKEW_MS
            )));
        }
    }

    // 2. Parent existence & HLC causality
    for parent_hash in &node.parents {
        let parent = store
            .get(parent_hash)
            .await?
            .ok_or(DagError::ParentNotFound(*parent_hash))?;

        // Normative HLC Check: node timestamp must strictly exceed parent
        if node.timestamp <= parent.timestamp {
            return Err(DagError::StoreError(format!(
                "causality violation: node timestamp {:?} <= parent timestamp {:?}",
                node.timestamp, parent.timestamp
            )));
        }
    }

    // 3. Persist
    store.put(node).await
}

/// Verify integrity of a stored node: check that its hash is correctly
/// computed and all parents exist in the store.
///
/// Returns `Ok(true)` if the node passes all integrity checks,
/// `Ok(false)` if any check fails (hash mismatch or missing parent),
/// and `Err` if the node itself is not found.
pub async fn verify_stored_integrity(store: &impl DagStore, hash: &Hash256) -> Result<bool> {
    let node = match store.get(hash).await? {
        Some(n) => n,
        None => return Err(DagError::NodeNotFound(*hash)),
    };

    // Check all parents exist
    for parent in &node.parents {
        if !store.contains(parent).await? {
            return Ok(false);
        }
    }

    // Recompute hash and compare
    let recomputed = compute_node_hash(
        &node.parents,
        &node.payload_hash,
        &node.creator_did,
        &node.timestamp,
    );

    Ok(recomputed == node.hash)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::types::{Did, Signature, Timestamp};

    use super::*;
    use crate::{
        dag::{Dag, DagNode, HybridClock, append},
        store::MemoryStore,
    };

    fn test_did() -> Did {
        Did::new("did:exo:test").expect("valid")
    }

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
        let mut clock = HybridClock::new();
        let creator = test_did();
        let sign_fn = make_sign_fn();
        append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).expect("genesis")
    }

    fn make_child_node(parent: &DagNode) -> DagNode {
        let mut dag = Dag::new();
        let mut clock = HybridClock::new();
        let creator = test_did();
        let sign_fn = make_sign_fn();

        // Insert parent first so we can create a child
        let _g =
            append(&mut dag, &[], b"genesis", &creator, &*sign_fn, &mut clock).expect("genesis");

        // Build child manually with proper parent reference
        let payload_hash = Hash256::digest(b"child-payload");
        let timestamp = Timestamp::new(
            parent.timestamp.physical_ms + 1,
            parent.timestamp.logical + 1,
        );
        let hash = compute_node_hash(&[parent.hash], &payload_hash, &creator, &timestamp);
        let signature = (*sign_fn)(hash.as_bytes());

        DagNode {
            hash,
            parents: vec![parent.hash],
            payload_hash,
            creator_did: creator,
            timestamp,
            signature,
        }
    }

    #[tokio::test]
    async fn validated_append_success() {
        let mut store = MemoryStore::new();
        let genesis = make_test_node();
        store.put(genesis.clone()).await.expect("put genesis");

        let child = make_child_node(&genesis);
        validated_append(&mut store, child.clone())
            .await
            .expect("validated append");

        assert!(store.contains(&child.hash).await.expect("contains"));
    }

    #[tokio::test]
    async fn validated_append_missing_parent() {
        let mut store = MemoryStore::new();
        // Don't put the parent in the store
        let genesis = make_test_node();
        let child = make_child_node(&genesis);

        let err = validated_append(&mut store, child).await.unwrap_err();
        assert!(matches!(err, DagError::ParentNotFound(_)));
    }

    #[tokio::test]
    async fn validated_append_causality_violation() {
        let mut store = MemoryStore::new();
        let genesis = make_test_node();
        store.put(genesis.clone()).await.expect("put genesis");

        // Create a child with timestamp <= parent (causality violation)
        let creator = test_did();
        let payload_hash = Hash256::digest(b"bad-child");
        let timestamp = Timestamp::new(0, 0); // Before genesis
        let hash = compute_node_hash(&[genesis.hash], &payload_hash, &creator, &timestamp);
        let sign_fn = make_sign_fn();
        let signature = (*sign_fn)(hash.as_bytes());

        let bad_child = DagNode {
            hash,
            parents: vec![genesis.hash],
            payload_hash,
            creator_did: creator,
            timestamp,
            signature,
        };

        let err = validated_append(&mut store, bad_child).await.unwrap_err();
        assert!(
            matches!(err, DagError::StoreError(ref msg) if msg.contains("causality")),
            "expected causality violation, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn verify_stored_integrity_valid() {
        let mut store = MemoryStore::new();
        let node = make_test_node();
        store.put(node.clone()).await.expect("put");

        assert!(
            verify_stored_integrity(&store, &node.hash)
                .await
                .expect("verify")
        );
    }

    #[tokio::test]
    async fn verify_stored_integrity_tampered_hash() {
        let mut store = MemoryStore::new();
        let mut node = make_test_node();
        let original_hash = node.hash;
        // Tamper: modify payload hash but keep the original node hash
        node.payload_hash = Hash256::digest(b"tampered");
        // Re-insert with original hash (simulating store corruption)
        node.hash = original_hash;
        store.put(node).await.expect("put");

        // Integrity check should detect the hash mismatch
        assert!(
            !verify_stored_integrity(&store, &original_hash)
                .await
                .expect("verify")
        );
    }

    #[tokio::test]
    async fn verify_stored_integrity_not_found() {
        let store = MemoryStore::new();
        let err = verify_stored_integrity(&store, &Hash256::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(err, DagError::NodeNotFound(_)));
    }

    #[tokio::test]
    async fn genesis_node_validated_append() {
        let mut store = MemoryStore::new();
        let genesis = make_test_node();
        // Genesis has no parents — should pass validation
        validated_append(&mut store, genesis.clone())
            .await
            .expect("genesis append");
        assert!(store.contains(&genesis.hash).await.expect("contains"));
    }
}
