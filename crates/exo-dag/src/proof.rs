//! Merkle proof types for event inclusion verification.
//!
//! Provides [`EventInclusionProof`], which verifies that a given event ID
//! exists within the MMR component of an event root.

use exo_core::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};

/// Merkle Proof for Event Inclusion.
/// Verifies that a specific Event ID exists within component of the Event Root (MMR).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventInclusionProof {
    /// The index of the leaf in the MMR (0-based).
    pub leaf_index: u64,

    /// The total size of the MMR at the time of proof (to determine structure).
    pub mmr_size: u64,

    /// The sibling hashes required to reconstruct the peak.
    /// Ordered from bottom (leaf) to top (peak).
    pub path: Vec<Blake3Hash>,

    /// The peak required to reconstruct the root (if the path leads to a peak).
    /// Standard MMR proof involves:
    /// 1. Reconstruct the peak for the leaf.
    /// 2. Bag this peak with other peaks to get the root.
    ///
    /// This field might contain the "other peaks" or a consolidated sibling?
    /// For simplicity in this implementation, we will assume the Bagging step is done by providing
    /// the sibling peaks necessary to hash up to the root.
    /// So `path` actually continues all the way to the Root?
    /// Or we verify up to a specific Peak?
    /// Let's stick to: verify up to Root.
    pub siblings: Vec<Blake3Hash>,
}

impl EventInclusionProof {
    /// Verify that `leaf` is included in `root` given this proof.
    pub fn verify(&self, root: &Blake3Hash, leaf: &Blake3Hash) -> bool {
        // 1. Hash up the mountain to find the peak for this leaf.
        let mut current_hash = *leaf;
        let mut current_index = self.leaf_index;
        let _current_size = self.mmr_size; // unused in simplified path (MVP)

        // This is a simplified Merkle Path verification.
        // In a real MMR, we need to know the structure (peaks) to know when to stop "mountain climbing"
        // and start "peak bagging".

        // For this version (Spec 9.4 MVP), let's assume `siblings` contains ALL hashes needed
        // to go from Leaf -> Root, in order.
        // We just need to know "Left or Right" at each step.
        // For MMR, this is determined by the index.

        for sibling in &self.siblings {
            let is_right_child = current_index % 2 == 1;

            let mut buf = Vec::with_capacity(64);
            if is_right_child {
                // H(Sibling | Current)
                buf.extend_from_slice(&sibling.0);
                buf.extend_from_slice(&current_hash.0);
            } else {
                // H(Current | Sibling)
                buf.extend_from_slice(&current_hash.0);
                buf.extend_from_slice(&sibling.0);
            }
            current_hash = hash_bytes(&buf);

            // Move up
            current_index /= 2;
        }

        // Check if computed hash matches root
        current_hash == *root
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use exo_core::hash_bytes;

    #[test]
    fn test_proof_verification() {
        // Construct a simple tree manually:
        //       Root
        //      /    \
        //    H1      H2
        //   /  \    /  \
        //  L0  L1  L2  L3

        let l0 = hash_bytes(&[0]);
        let l1 = hash_bytes(&[1]);

        let h1_input = [l0.0, l1.0].concat();
        let h1 = hash_bytes(&h1_input);

        // Proof for L0:
        // Path needs L1.
        // Then needs H2 (assuming H2 is root's other child, or root is H1 if size 2).

        // Let's assume size 2 tree (Root = H1).
        let proof = EventInclusionProof {
            leaf_index: 0,
            mmr_size: 2,
            path: vec![],
            siblings: vec![l1],
        };

        assert!(proof.verify(&h1, &l0));

        // Negative test
        assert!(!proof.verify(&l0, &l0)); // root != l0
    }
}
