//! Merkle Mountain Range -- append-only accumulator.
//!
//! An MMR is a collection of perfect binary Merkle trees (peaks) that grows
//! by appending leaves. The root is the "bag of peaks" hash.

use exo_core::types::Hash256;
use serde::{Deserialize, Serialize};

use crate::error::{DagError, Result};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mmr:node:");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn hash_leaf(data: &Hash256) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mmr:leaf:");
    hasher.update(data.as_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn bag_peaks(peaks: &[Hash256]) -> Hash256 {
    if peaks.is_empty() {
        return Hash256::digest(b"mmr:empty");
    }
    if peaks.len() == 1 {
        return peaks[0];
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mmr:peaks:");
    for peak in peaks {
        hasher.update(peak.as_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn peak_leaf_counts(leaf_count: usize) -> Vec<usize> {
    let mut remaining = leaf_count;
    let mut counts = Vec::new();

    while remaining > 0 {
        let mut peak_leaf_count = 1usize;
        while peak_leaf_count <= remaining / 2 {
            peak_leaf_count *= 2;
        }
        counts.push(peak_leaf_count);
        remaining -= peak_leaf_count;
    }

    counts
}

// ---------------------------------------------------------------------------
// MmrProof
// ---------------------------------------------------------------------------

/// A proof that a leaf at a given position is included in the MMR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    /// Sibling hashes along the path from leaf to its peak.
    pub siblings: Vec<Hash256>,
    /// Index of the peak this leaf belongs to.
    pub peak_index: usize,
    /// All peak hashes (needed for root reconstruction).
    pub peaks: Vec<Hash256>,
    /// Number of leaves in the MMR when the proof was generated.
    pub leaf_count: usize,
}

// ---------------------------------------------------------------------------
// Peak — a perfect binary tree within the MMR
// ---------------------------------------------------------------------------

/// A peak is a complete binary tree.
#[derive(Debug, Clone)]
struct Peak {
    /// The root hash of this peak.
    hash: Hash256,
    /// The height (0 = single leaf, 1 = two leaves, etc.).
    height: u32,
    /// Number of leaves in this peak: 2^height.
    leaf_count: usize,
    /// Internal storage: all nodes in a complete binary tree layout.
    /// Index 0 = root. For node at index i: left child = 2*i+1, right = 2*i+2.
    /// Leaves start at index (leaf_count - 1).
    nodes: Vec<Hash256>,
}

impl Peak {
    /// Create a peak from a single leaf.
    fn from_leaf(leaf_hash: Hash256) -> Self {
        Self {
            hash: leaf_hash,
            height: 0,
            leaf_count: 1,
            nodes: vec![leaf_hash],
        }
    }

    /// Merge two peaks of equal height into one.
    fn merge(left: &Peak, right: &Peak) -> Self {
        let new_hash = hash_pair(&left.hash, &right.hash);
        let new_height = left.height + 1;
        let new_leaf_count = left.leaf_count + right.leaf_count;

        // Build combined tree array in level-order
        let total_nodes = 2 * new_leaf_count - 1;
        let mut nodes = vec![Hash256::ZERO; total_nodes];
        nodes[0] = new_hash;

        // Copy left subtree into positions 1, 3, 4, 7, 8, 9, 10, ...
        // Copy right subtree into positions 2, 5, 6, 11, 12, 13, 14, ...
        Self::copy_subtree(&mut nodes, 1, &left.nodes, 0);
        Self::copy_subtree(&mut nodes, 2, &right.nodes, 0);

        Self {
            hash: new_hash,
            height: new_height,
            leaf_count: new_leaf_count,
            nodes,
        }
    }

    fn copy_subtree(dst: &mut [Hash256], dst_idx: usize, src: &[Hash256], src_idx: usize) {
        if src_idx >= src.len() || dst_idx >= dst.len() {
            return;
        }
        dst[dst_idx] = src[src_idx];
        // Copy children
        let src_left = 2 * src_idx + 1;
        let src_right = 2 * src_idx + 2;
        let dst_left = 2 * dst_idx + 1;
        let dst_right = 2 * dst_idx + 2;
        Self::copy_subtree(dst, dst_left, src, src_left);
        Self::copy_subtree(dst, dst_right, src, src_right);
    }

    /// Get the sibling path from a local leaf index to the root.
    fn proof_path(&self, local_leaf_idx: usize) -> Vec<Hash256> {
        if self.leaf_count <= 1 {
            return Vec::new();
        }

        let mut siblings = Vec::new();
        // The leaf is at tree-array index: (leaf_count - 1) + local_leaf_idx
        let mut node_idx = (self.leaf_count - 1) + local_leaf_idx;

        while node_idx > 0 {
            let parent = (node_idx - 1) / 2;
            let sibling = if node_idx % 2 == 1 {
                // We're left child, sibling is right
                node_idx + 1
            } else {
                // We're right child, sibling is left
                node_idx - 1
            };
            if sibling < self.nodes.len() {
                siblings.push(self.nodes[sibling]);
            }
            node_idx = parent;
        }

        siblings
    }
}

// ---------------------------------------------------------------------------
// MerkleMountainRange
// ---------------------------------------------------------------------------

/// A Merkle Mountain Range (append-only accumulator).
#[derive(Debug, Clone, Default)]
pub struct MerkleMountainRange {
    /// Original leaf data hashes in insertion order.
    leaves: Vec<Hash256>,
    /// Current peaks, ordered by decreasing height (leftmost is tallest).
    peaks: Vec<Peak>,
}

impl MerkleMountainRange {
    /// Create a new empty MMR.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the MMR is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

/// Append a leaf. Returns the leaf's 0-indexed position.
pub fn append(mmr: &mut MerkleMountainRange, leaf: Hash256) -> usize {
    let leaf_pos = mmr.leaves.len();
    mmr.leaves.push(leaf);

    let leaf_hash = hash_leaf(&leaf);
    let mut new_peak = Peak::from_leaf(leaf_hash);

    // Merge with any trailing peaks of the same height
    loop {
        match mmr.peaks.last() {
            Some(last) if last.height == new_peak.height => {
                // Safety: last() just confirmed the vec is non-empty, so pop() always yields Some.
                if let Some(left) = mmr.peaks.pop() {
                    new_peak = Peak::merge(&left, &new_peak);
                }
            }
            _ => break,
        }
    }

    mmr.peaks.push(new_peak);
    leaf_pos
}

/// Compute the root hash (bag of peaks).
pub fn root(mmr: &MerkleMountainRange) -> Hash256 {
    let peak_hashes: Vec<Hash256> = mmr.peaks.iter().map(|p| p.hash).collect();
    bag_peaks(&peak_hashes)
}

/// Generate a proof for a leaf at the given position.
pub fn prove(mmr: &MerkleMountainRange, position: usize) -> Result<MmrProof> {
    let peak_hashes: Vec<Hash256> = mmr.peaks.iter().map(|p| p.hash).collect();

    if position >= mmr.leaves.len() {
        return Err(DagError::MmrPositionOutOfBounds {
            position,
            leaf_count: mmr.leaves.len(),
        });
    }

    // Find which peak contains this leaf
    let mut leaf_offset = 0;
    let mut peak_idx = 0;
    for (i, peak) in mmr.peaks.iter().enumerate() {
        if position < leaf_offset + peak.leaf_count {
            peak_idx = i;
            break;
        }
        leaf_offset += peak.leaf_count;
    }

    let local_leaf_idx = position - leaf_offset;
    let siblings = mmr.peaks[peak_idx].proof_path(local_leaf_idx);

    Ok(MmrProof {
        siblings,
        peak_index: peak_idx,
        peaks: peak_hashes,
        leaf_count: mmr.leaves.len(),
    })
}

/// Verify an MMR proof.
pub fn verify_proof(mmr_root: &Hash256, leaf: &Hash256, position: usize, proof: &MmrProof) -> bool {
    if proof.leaf_count == 0 || position >= proof.leaf_count {
        return false;
    }
    if proof.peaks.is_empty() {
        return false;
    }

    let peak_leaf_counts = peak_leaf_counts(proof.leaf_count);
    if proof.peaks.len() != peak_leaf_counts.len() || proof.peak_index >= proof.peaks.len() {
        return false;
    }

    let mut current = hash_leaf(leaf);
    let peak_leaf_count = peak_leaf_counts[proof.peak_index];
    let expected_depth = match usize::try_from(peak_leaf_count.trailing_zeros()) {
        Ok(depth) => depth,
        Err(_) => return false,
    };
    if proof.siblings.len() != expected_depth {
        return false;
    }

    let peak_offset: usize = peak_leaf_counts[..proof.peak_index].iter().sum();
    if position < peak_offset || position >= peak_offset + peak_leaf_count {
        return false;
    }
    let local_idx = position - peak_offset;

    // Walk from leaf to peak root
    let mut node_idx = (peak_leaf_count - 1) + local_idx;
    for sibling in &proof.siblings {
        if node_idx % 2 == 1 {
            // We're left child
            current = hash_pair(&current, sibling);
        } else {
            // We're right child
            current = hash_pair(sibling, &current);
        }
        node_idx = (node_idx - 1) / 2;
    }

    if current != proof.peaks[proof.peak_index] {
        return false;
    }

    bag_peaks(&proof.peaks) == *mmr_root
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_mmr() {
        let mmr = MerkleMountainRange::new();
        assert!(mmr.is_empty());
        assert_eq!(mmr.len(), 0);
        let r = root(&mmr);
        assert_eq!(r, Hash256::digest(b"mmr:empty"));
    }

    #[test]
    fn single_leaf() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash256::digest(b"leaf0");
        let pos = append(&mut mmr, leaf);
        assert_eq!(pos, 0);
        assert_eq!(mmr.len(), 1);
        assert!(!mmr.is_empty());
        assert_eq!(mmr.peaks.len(), 1);
        assert_eq!(mmr.peaks[0].height, 0);
    }

    #[test]
    fn two_leaves_merge() {
        let mut mmr = MerkleMountainRange::new();
        append(&mut mmr, Hash256::digest(b"leaf0"));
        append(&mut mmr, Hash256::digest(b"leaf1"));
        assert_eq!(mmr.len(), 2);
        assert_eq!(mmr.peaks.len(), 1);
        assert_eq!(mmr.peaks[0].height, 1);
    }

    #[test]
    fn three_leaves_two_peaks() {
        let mut mmr = MerkleMountainRange::new();
        for i in 0..3u8 {
            append(&mut mmr, Hash256::digest(&[i]));
        }
        assert_eq!(mmr.peaks.len(), 2);
    }

    #[test]
    fn four_leaves_one_peak() {
        let mut mmr = MerkleMountainRange::new();
        for i in 0..4u8 {
            append(&mut mmr, Hash256::digest(&[i]));
        }
        assert_eq!(mmr.peaks.len(), 1);
        assert_eq!(mmr.peaks[0].height, 2);
    }

    #[test]
    fn seven_leaves_three_peaks() {
        let mut mmr = MerkleMountainRange::new();
        for i in 0..7u8 {
            append(&mut mmr, Hash256::digest(&[i]));
        }
        assert_eq!(mmr.peaks.len(), 3);
    }

    #[test]
    fn root_deterministic() {
        let mut mmr1 = MerkleMountainRange::new();
        let mut mmr2 = MerkleMountainRange::new();
        for i in 0..5u8 {
            append(&mut mmr1, Hash256::digest(&[i]));
            append(&mut mmr2, Hash256::digest(&[i]));
        }
        assert_eq!(root(&mmr1), root(&mmr2));
    }

    #[test]
    fn root_changes_on_append() {
        let mut mmr = MerkleMountainRange::new();
        append(&mut mmr, Hash256::digest(b"a"));
        let r1 = root(&mmr);
        append(&mut mmr, Hash256::digest(b"b"));
        let r2 = root(&mmr);
        assert_ne!(r1, r2);
    }

    #[test]
    fn prove_and_verify_single() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash256::digest(b"leaf0");
        append(&mut mmr, leaf);
        let r = root(&mmr);
        let proof = prove(&mmr, 0).unwrap();
        assert!(verify_proof(&r, &leaf, 0, &proof));
    }

    #[test]
    fn prove_and_verify_two() {
        let mut mmr = MerkleMountainRange::new();
        let l0 = Hash256::digest(b"l0");
        let l1 = Hash256::digest(b"l1");
        append(&mut mmr, l0);
        append(&mut mmr, l1);
        let r = root(&mmr);

        let p0 = prove(&mmr, 0).unwrap();
        assert!(verify_proof(&r, &l0, 0, &p0));

        let p1 = prove(&mmr, 1).unwrap();
        assert!(verify_proof(&r, &l1, 1, &p1));
    }

    #[test]
    fn prove_and_verify_four() {
        let mut mmr = MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..4u8).map(|i| Hash256::digest(&[i])).collect();
        for leaf in &leaves {
            append(&mut mmr, *leaf);
        }
        let r = root(&mmr);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = prove(&mmr, i).unwrap();
            assert!(verify_proof(&r, leaf, i, &proof), "Failed at pos {i}");
        }
    }

    #[test]
    fn prove_and_verify_multiple() {
        let mut mmr = MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..8u8).map(|i| Hash256::digest(&[i])).collect();
        for leaf in &leaves {
            append(&mut mmr, *leaf);
        }
        let r = root(&mmr);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = prove(&mmr, i).unwrap();
            assert!(verify_proof(&r, leaf, i, &proof), "Failed at pos {i}");
        }
    }

    #[test]
    fn prove_and_verify_odd_count() {
        for count in [3u8, 5, 6, 7, 9, 10, 11, 13, 15] {
            let mut mmr = MerkleMountainRange::new();
            let leaves: Vec<Hash256> = (0..count).map(|i| Hash256::digest(&[i])).collect();
            for leaf in &leaves {
                append(&mut mmr, *leaf);
            }
            let r = root(&mmr);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = prove(&mmr, i).unwrap();
                assert!(
                    verify_proof(&r, leaf, i, &proof),
                    "Failed at pos {i} with {count} leaves"
                );
            }
        }
    }

    #[test]
    fn proof_fails_wrong_leaf() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash256::digest(b"real");
        append(&mut mmr, leaf);
        let r = root(&mmr);
        let proof = prove(&mmr, 0).unwrap();
        let wrong = Hash256::digest(b"wrong");
        assert!(!verify_proof(&r, &wrong, 0, &proof));
    }

    #[test]
    fn proof_fails_wrong_root() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash256::digest(b"leaf");
        append(&mut mmr, leaf);
        let proof = prove(&mmr, 0).unwrap();
        assert!(!verify_proof(&Hash256::ZERO, &leaf, 0, &proof));
    }

    #[test]
    fn proof_out_of_bounds() {
        let mut mmr = MerkleMountainRange::new();
        append(&mut mmr, Hash256::digest(b"leaf"));
        let err = prove(&mmr, 999).unwrap_err();
        assert!(matches!(
            err,
            DagError::MmrPositionOutOfBounds {
                position: 999,
                leaf_count: 1
            }
        ));
    }

    #[test]
    fn proof_for_real_leaf_fails_out_of_bounds_position() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash256::digest(b"leaf");
        append(&mut mmr, leaf);
        let proof = prove(&mmr, 0).unwrap();
        let r = root(&mmr);

        assert!(
            !verify_proof(&r, &leaf, 999, &proof),
            "proof verifier must reject positions outside the proved MMR leaf set"
        );
    }

    #[test]
    fn proof_fails_when_replayed_at_another_peak_position() {
        let mut mmr = MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..5u8).map(|i| Hash256::digest(&[i])).collect();
        for leaf in &leaves {
            append(&mut mmr, *leaf);
        }
        let proof = prove(&mmr, 4).unwrap();
        let r = root(&mmr);

        assert!(
            !verify_proof(&r, &leaves[4], 0, &proof),
            "proof verifier must bind the position to the proof peak layout"
        );
    }

    #[test]
    fn proof_fails_when_leaf_count_is_tampered() {
        let mut mmr = MerkleMountainRange::new();
        let leaf = Hash256::digest(b"leaf");
        append(&mut mmr, leaf);
        let mut proof = prove(&mmr, 0).unwrap();
        proof.leaf_count = 2;
        let r = root(&mmr);

        assert!(
            !verify_proof(&r, &leaf, 0, &proof),
            "proof verifier must reject tampered MMR leaf counts"
        );
    }

    #[test]
    fn verify_empty_peaks_fails() {
        let proof = MmrProof {
            siblings: Vec::new(),
            peak_index: 0,
            peaks: Vec::new(),
            leaf_count: 0,
        };
        assert!(!verify_proof(&Hash256::ZERO, &Hash256::ZERO, 0, &proof));
    }

    #[test]
    fn verify_bad_peak_index_fails() {
        let proof = MmrProof {
            siblings: Vec::new(),
            peak_index: 5,
            peaks: vec![Hash256::ZERO],
            leaf_count: 1,
        };
        assert!(!verify_proof(&Hash256::ZERO, &Hash256::ZERO, 0, &proof));
    }

    #[test]
    fn verify_rejects_unexpected_proof_depth() {
        let overflowing_depth = usize::try_from(usize::BITS).unwrap_or(usize::MAX);
        let proof = MmrProof {
            siblings: vec![Hash256::ZERO; overflowing_depth],
            peak_index: 0,
            peaks: vec![Hash256::ZERO],
            leaf_count: 1,
        };
        assert!(!verify_proof(&Hash256::ZERO, &Hash256::ZERO, 0, &proof));
    }

    #[test]
    fn default_mmr() {
        let mmr = MerkleMountainRange::default();
        assert!(mmr.is_empty());
    }

    #[test]
    fn sixteen_leaves() {
        let mut mmr = MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..16u8).map(|i| Hash256::digest(&[i])).collect();
        for leaf in &leaves {
            append(&mut mmr, *leaf);
        }
        assert_eq!(mmr.peaks.len(), 1);
        let r = root(&mmr);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = prove(&mmr, i).unwrap();
            assert!(verify_proof(&r, leaf, i, &proof));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    fn arb_hash256() -> impl Strategy<Value = Hash256> {
        prop::array::uniform32(any::<u8>()).prop_map(Hash256::from_bytes)
    }

    proptest! {
        #[test]
        fn append_and_verify_all(
            leaves in prop::collection::vec(arb_hash256(), 1..17)
        ) {
            let mut mmr = MerkleMountainRange::new();
            for leaf in &leaves {
                append(&mut mmr, *leaf);
            }
            let r = root(&mmr);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = prove(&mmr, i).unwrap();
                prop_assert!(
                    verify_proof(&r, leaf, i, &proof),
                    "Failed at position {i} with {} leaves",
                    leaves.len()
                );
            }
        }

        #[test]
        fn root_is_deterministic(
            leaves in prop::collection::vec(arb_hash256(), 1..17)
        ) {
            let mut mmr1 = MerkleMountainRange::new();
            let mut mmr2 = MerkleMountainRange::new();
            for leaf in &leaves {
                append(&mut mmr1, *leaf);
                append(&mut mmr2, *leaf);
            }
            prop_assert_eq!(root(&mmr1), root(&mmr2));
        }

        #[test]
        fn wrong_leaf_never_verifies(
            leaves in prop::collection::vec(arb_hash256(), 1..9),
            wrong in arb_hash256(),
            pos_idx in 0usize..8
        ) {
            let mut mmr = MerkleMountainRange::new();
            for leaf in &leaves {
                append(&mut mmr, *leaf);
            }

            let pos = pos_idx % leaves.len();
            if wrong != leaves[pos] {
                let r = root(&mmr);
                let proof = prove(&mmr, pos).unwrap();
                prop_assert!(!verify_proof(&r, &wrong, pos, &proof));
            }
        }
    }
}
