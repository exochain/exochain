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

//! Canonical hashing utilities.
//!
//! All hashing in EXOCHAIN uses **blake3** and all structured data is
//! first serialized to **CBOR** (deterministic canonical encoding) before
//! hashing.  This guarantees that identical logical values always produce
//! the same hash regardless of serialization order or platform.

use serde::Serialize;

use crate::{
    error::{ExoError, Result},
    types::Hash256,
};

const MERKLE_LEAF_DOMAIN: u8 = 0x00;
const MERKLE_PARENT_DOMAIN: u8 = 0x01;
const MERKLE_COUNTED_ROOT_DOMAIN: u8 = 0x02;
const MERKLE_LEAF_COUNT_BYTES: usize = 16;

/// Compute the blake3 hash of raw bytes.
#[must_use]
pub fn canonical_hash(data: &[u8]) -> Hash256 {
    Hash256::digest(data)
}

/// Serialize `value` to CBOR, then compute the blake3 hash.
///
/// # Errors
///
/// Returns `ExoError::SerializationError` if CBOR encoding fails.
pub fn hash_structured<T: Serialize>(value: &T) -> Result<Hash256> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(canonical_hash(&buf))
}

/// Compute a deterministic Merkle root from a slice of leaf hashes.
///
/// - Empty input returns `Hash256::ZERO`.
/// - Single leaf returns `H(0x00 || leaf)`.
/// - Otherwise, leaves are paired left-to-right; an odd leaf is promoted
///   (duplicated) to fill the pair.  This process repeats until one root
///   remains.
#[must_use]
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256::ZERO;
    }

    let mut current: Vec<Hash256> = leaves.iter().map(hash_leaf).collect();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                // Odd leaf — duplicate
                left
            };
            next.push(hash_pair(left, right));
            i += 2;
        }
        current = next;
    }
    current[0]
}

/// Compute a Merkle root commitment that binds both the tree root and the
/// number of leaves represented by that tree.
#[must_use]
pub fn merkle_root_with_leaf_count(leaves: &[Hash256]) -> Hash256 {
    bind_merkle_root_to_leaf_count(&merkle_root(leaves), leaves.len())
}

/// Bind an existing Merkle tree root to a fixed-width leaf-count commitment.
#[must_use]
pub fn bind_merkle_root_to_leaf_count(root: &Hash256, leaf_count: usize) -> Hash256 {
    let mut combined = [0u8; 1 + MERKLE_LEAF_COUNT_BYTES + 32];
    let leaf_count_bytes = leaf_count.to_be_bytes();
    let count_end = 1 + MERKLE_LEAF_COUNT_BYTES;
    let count_start = count_end - leaf_count_bytes.len();

    combined[0] = MERKLE_COUNTED_ROOT_DOMAIN;
    combined[count_start..count_end].copy_from_slice(&leaf_count_bytes);
    combined[count_end..].copy_from_slice(root.as_bytes());
    canonical_hash(&combined)
}

/// Generate a Merkle proof for the leaf at `index`.
///
/// Returns the sibling node hashes needed to reconstruct the root. Leaf
/// siblings are returned in their domain-separated `H(0x00 || leaf)` form.
///
/// # Errors
///
/// Returns `ExoError::InvalidMerkleProof` if `index` is out of bounds.
pub fn merkle_proof(leaves: &[Hash256], index: usize) -> Result<Vec<Hash256>> {
    if index >= leaves.len() || leaves.is_empty() {
        return Err(ExoError::InvalidMerkleProof);
    }
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }

    let mut proof = Vec::new();
    let mut current: Vec<Hash256> = leaves.iter().map(hash_leaf).collect();
    let mut idx = index;

    while current.len() > 1 {
        // If odd number, duplicate the last element
        if current.len() % 2 != 0 {
            let last = current[current.len() - 1];
            current.push(last);
        }
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(current[sibling_idx]);

        // Build next level
        let mut next = Vec::with_capacity(current.len() / 2);
        let mut i = 0;
        while i < current.len() {
            next.push(hash_pair(&current[i], &current[i + 1]));
            i += 2;
        }
        current = next;
        idx /= 2;
    }

    Ok(proof)
}

/// Verify a Merkle proof.
///
/// Given the expected `root`, a raw `leaf` hash as supplied to
/// [`merkle_root`], the `proof` (domain-separated sibling node hashes),
/// and the `index` of the leaf in the original tree, returns `true` if
/// the proof is valid.
#[must_use]
pub fn verify_merkle_proof(
    root: &Hash256,
    leaf: &Hash256,
    proof: &[Hash256],
    index: usize,
) -> bool {
    let current = merkle_root_from_proof(leaf, proof, index);
    hash256_eq_constant_time(&current, root)
}

/// Reconstruct the Merkle root implied by a leaf, proof path, and leaf index.
#[must_use]
pub fn merkle_root_from_proof(leaf: &Hash256, proof: &[Hash256], index: usize) -> Hash256 {
    let mut current = hash_leaf(leaf);
    let mut idx = index;

    for sibling in proof {
        if idx % 2 == 0 {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        idx /= 2;
    }

    current
}

/// Verify a Merkle proof against a root commitment that binds the claimed leaf
/// count.
///
/// The `root` parameter must be produced by [`merkle_root_with_leaf_count`] or
/// [`bind_merkle_root_to_leaf_count`]. The compact proof path alone cannot
/// prove the size of opaque sibling subtrees, so count binding is enforced at
/// the root-commitment layer.
#[must_use]
pub fn verify_merkle_proof_with_leaf_count(
    root: &Hash256,
    leaf: &Hash256,
    proof: &[Hash256],
    index: usize,
    leaf_count: usize,
) -> bool {
    let Ok((current, duplicate_siblings_match)) =
        fold_merkle_proof_with_leaf_count(leaf, proof, index, leaf_count)
    else {
        return false;
    };
    let count_bound_root = bind_merkle_root_to_leaf_count(&current, leaf_count);
    duplicate_siblings_match && hash256_eq_constant_time(&count_bound_root, root)
}

/// Reconstruct the leaf-count-bound Merkle root implied by a leaf, proof path,
/// leaf index, and claimed leaf count.
///
/// # Errors
///
/// Returns `ExoError::InvalidMerkleProof` when `leaf_count` is zero, when
/// `index` is outside the claimed tree, or when the proof path length is not
/// the path length required by `leaf_count`, or when an odd duplicated sibling
/// does not match the duplicated current node.
pub fn merkle_root_from_proof_with_leaf_count(
    leaf: &Hash256,
    proof: &[Hash256],
    index: usize,
    leaf_count: usize,
) -> Result<Hash256> {
    let (root, duplicate_siblings_match) =
        fold_merkle_proof_with_leaf_count(leaf, proof, index, leaf_count)?;
    if duplicate_siblings_match {
        Ok(bind_merkle_root_to_leaf_count(&root, leaf_count))
    } else {
        Err(ExoError::InvalidMerkleProof)
    }
}

fn fold_merkle_proof_with_leaf_count(
    leaf: &Hash256,
    proof: &[Hash256],
    index: usize,
    leaf_count: usize,
) -> Result<(Hash256, bool)> {
    if leaf_count == 0 || index >= leaf_count {
        return Err(ExoError::InvalidMerkleProof);
    }

    let mut current = hash_leaf(leaf);
    let mut idx = index;
    let mut level_count = leaf_count;
    let mut duplicate_siblings_match = true;

    for sibling in proof {
        if level_count == 1 || idx >= level_count {
            return Err(ExoError::InvalidMerkleProof);
        }

        let is_duplicated_odd_leaf = level_count % 2 != 0 && idx == level_count - 1;
        if is_duplicated_odd_leaf {
            duplicate_siblings_match &= hash256_eq_constant_time(&current, sibling);
            current = hash_pair(&current, &current);
        } else if idx % 2 == 0 {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }

        idx /= 2;
        level_count = level_count.div_ceil(2);
    }

    if level_count == 1 {
        Ok((current, duplicate_siblings_match))
    } else {
        Err(ExoError::InvalidMerkleProof)
    }
}

/// Compare two `Hash256` values without data-dependent early exit.
#[must_use]
pub fn hash256_eq_constant_time(left: &Hash256, right: &Hash256) -> bool {
    let mut diff = 0u8;
    for (left_byte, right_byte) in left.as_bytes().iter().zip(right.as_bytes().iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

/// Hash a leaf into the Merkle leaf domain: `H(0x00 || leaf)`.
#[must_use]
fn hash_leaf(leaf: &Hash256) -> Hash256 {
    let mut combined = [0u8; 33];
    combined[0] = MERKLE_LEAF_DOMAIN;
    combined[1..].copy_from_slice(leaf.as_bytes());
    canonical_hash(&combined)
}

/// Hash two nodes together in the Merkle parent domain: `H(0x01 || left || right)`.
#[must_use]
fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = [0u8; 65];
    combined[0] = MERKLE_PARENT_DOMAIN;
    combined[1..33].copy_from_slice(left.as_bytes());
    combined[33..].copy_from_slice(right.as_bytes());
    canonical_hash(&combined)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_deterministic() {
        let h1 = canonical_hash(b"hello world");
        let h2 = canonical_hash(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn canonical_hash_different_inputs() {
        let h1 = canonical_hash(b"aaa");
        let h2 = canonical_hash(b"bbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_structured_deterministic() {
        #[derive(Serialize)]
        struct Foo {
            a: u32,
            b: String,
        }
        let v = Foo {
            a: 42,
            b: "hello".into(),
        };
        let h1 = hash_structured(&v).expect("ok");
        let h2 = hash_structured(&v).expect("ok");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_structured_different_values() {
        let h1 = hash_structured(&42u32).expect("ok");
        let h2 = hash_structured(&43u32).expect("ok");
        assert_ne!(h1, h2);
    }

    #[test]
    fn merkle_root_empty() {
        assert_eq!(merkle_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn merkle_root_single() {
        let leaf = Hash256::digest(b"only");
        assert_eq!(merkle_root(&[leaf]), hash_leaf(&leaf));
    }

    fn raw_concat_pair_hash_for_test(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(left.as_bytes());
        combined[32..].copy_from_slice(right.as_bytes());
        canonical_hash(&combined)
    }

    #[test]
    fn merkle_root_uses_distinct_leaf_and_parent_domains() {
        let leaf = Hash256::digest(b"domain-separated-leaf");
        assert_ne!(
            merkle_root(&[leaf]),
            leaf,
            "single-leaf Merkle roots must not be interchangeable with raw leaf hashes"
        );

        let right = Hash256::digest(b"domain-separated-right");
        let raw_parent_hash = raw_concat_pair_hash_for_test(&leaf, &right);
        assert_ne!(
            merkle_root(&[leaf, right]),
            raw_parent_hash,
            "interior Merkle nodes must not use the raw H(left || right) domain"
        );
    }

    #[test]
    fn merkle_root_two_leaves() {
        let a = Hash256::digest(b"a");
        let b = Hash256::digest(b"b");
        let root = merkle_root(&[a, b]);
        // Should be hash_pair(hash_leaf(a), hash_leaf(b)).
        let expected = hash_pair(&hash_leaf(&a), &hash_leaf(&b));
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_three_leaves_odd() {
        let a = Hash256::digest(b"a");
        let b = Hash256::digest(b"b");
        let c = Hash256::digest(b"c");
        let root = merkle_root(&[a, b, c]);
        // Level 1: hash_pair(hash_leaf(a), hash_leaf(b)), hash_pair(hash_leaf(c), hash_leaf(c))
        // Level 0: hash_pair(level_1_left, level_1_right)
        let a_leaf = hash_leaf(&a);
        let b_leaf = hash_leaf(&b);
        let c_leaf = hash_leaf(&c);
        let ab = hash_pair(&a_leaf, &b_leaf);
        let cc = hash_pair(&c_leaf, &c_leaf);
        let expected = hash_pair(&ab, &cc);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_four_leaves() {
        let leaves: Vec<Hash256> = (0..4u8).map(|i| Hash256::digest(&[i])).collect();
        let root = merkle_root(&leaves);
        let leaf_nodes: Vec<Hash256> = leaves.iter().map(hash_leaf).collect();
        let ab = hash_pair(&leaf_nodes[0], &leaf_nodes[1]);
        let cd = hash_pair(&leaf_nodes[2], &leaf_nodes[3]);
        let expected = hash_pair(&ab, &cd);
        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_with_leaf_count_binds_count_and_inner_root() {
        let leaves = [
            Hash256::digest(b"count-bound-a"),
            Hash256::digest(b"count-bound-b"),
            Hash256::digest(b"count-bound-c"),
            Hash256::digest(b"count-bound-d"),
        ];
        let inner_root = merkle_root(&leaves);
        let bound_root = merkle_root_with_leaf_count(&leaves);

        assert_eq!(
            bound_root,
            bind_merkle_root_to_leaf_count(&inner_root, leaves.len())
        );
        assert_ne!(
            bound_root,
            bind_merkle_root_to_leaf_count(&inner_root, 3),
            "same inner root must not verify under a different leaf count"
        );
        assert_ne!(
            bound_root, inner_root,
            "count-bound root must not be interchangeable with the raw Merkle root"
        );
    }

    #[test]
    fn merkle_root_deterministic() {
        let leaves: Vec<Hash256> = (0..7u8).map(|i| Hash256::digest(&[i])).collect();
        let r1 = merkle_root(&leaves);
        let r2 = merkle_root(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_proof_empty() {
        let result = merkle_proof(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn merkle_proof_out_of_bounds() {
        let leaf = Hash256::digest(b"x");
        let result = merkle_proof(&[leaf], 1);
        assert!(result.is_err());
    }

    #[test]
    fn merkle_proof_single_leaf() {
        let leaf = Hash256::digest(b"only");
        let proof = merkle_proof(&[leaf], 0).expect("ok");
        assert!(proof.is_empty());
        let root = merkle_root(&[leaf]);
        assert!(verify_merkle_proof(&root, &leaf, &proof, 0));
    }

    #[test]
    fn merkle_proof_two_leaves() {
        let leaves = vec![Hash256::digest(b"a"), Hash256::digest(b"b")];
        let root = merkle_root(&leaves);

        for i in 0..2 {
            let proof = merkle_proof(&leaves, i).expect("ok");
            assert!(verify_merkle_proof(&root, &leaves[i], &proof, i));
        }
    }

    #[test]
    fn merkle_proof_four_leaves() {
        let leaves: Vec<Hash256> = (0..4u8).map(|i| Hash256::digest(&[i])).collect();
        let root = merkle_root(&leaves);

        for i in 0..4 {
            let proof = merkle_proof(&leaves, i).expect("ok");
            assert!(
                verify_merkle_proof(&root, &leaves[i], &proof, i),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn merkle_proof_odd_leaves() {
        let leaves: Vec<Hash256> = (0..5u8).map(|i| Hash256::digest(&[i])).collect();
        let root = merkle_root(&leaves);

        for i in 0..5 {
            let proof = merkle_proof(&leaves, i).expect("ok");
            assert!(
                verify_merkle_proof(&root, &leaves[i], &proof, i),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn merkle_proof_seven_leaves() {
        let leaves: Vec<Hash256> = (0..7u8).map(|i| Hash256::digest(&[i])).collect();
        let root = merkle_root(&leaves);

        for i in 0..7 {
            let proof = merkle_proof(&leaves, i).expect("ok");
            assert!(
                verify_merkle_proof(&root, &leaves[i], &proof, i),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn verify_merkle_proof_rejects_wrong_leaf() {
        let leaves: Vec<Hash256> = (0..4u8).map(|i| Hash256::digest(&[i])).collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).expect("ok");
        let wrong_leaf = Hash256::digest(b"wrong");
        assert!(!verify_merkle_proof(&root, &wrong_leaf, &proof, 0));
    }

    #[test]
    fn verify_merkle_proof_rejects_wrong_index() {
        let leaves: Vec<Hash256> = (0..4u8).map(|i| Hash256::digest(&[i])).collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0).expect("ok");
        // Use correct leaf but wrong index
        assert!(!verify_merkle_proof(&root, &leaves[0], &proof, 1));
    }

    #[test]
    fn verify_merkle_proof_rejects_wrong_root() {
        let leaves: Vec<Hash256> = (0..4u8).map(|i| Hash256::digest(&[i])).collect();
        let proof = merkle_proof(&leaves, 0).expect("ok");
        let wrong_root = Hash256::digest(b"wrong root");
        assert!(!verify_merkle_proof(&wrong_root, &leaves[0], &proof, 0));
    }

    #[test]
    fn merkle_root_from_proof_matches_canonical_root() {
        let leaves = vec![
            Hash256::digest(b"root-proof-a"),
            Hash256::digest(b"root-proof-b"),
            Hash256::digest(b"root-proof-c"),
            Hash256::digest(b"root-proof-d"),
            Hash256::digest(b"root-proof-e"),
        ];
        let root = merkle_root(&leaves);

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, index).expect("proof");
            assert_eq!(merkle_root_from_proof(leaf, &proof, index), root);
        }
    }

    #[test]
    fn merkle_root_from_proof_with_leaf_count_matches_canonical_root() {
        let leaves = vec![
            Hash256::digest(b"count-proof-a"),
            Hash256::digest(b"count-proof-b"),
            Hash256::digest(b"count-proof-c"),
            Hash256::digest(b"count-proof-d"),
            Hash256::digest(b"count-proof-e"),
        ];
        let root = merkle_root_with_leaf_count(&leaves);

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, index).expect("proof");
            let computed =
                merkle_root_from_proof_with_leaf_count(leaf, &proof, index, leaves.len())
                    .expect("leaf-count-bound proof root");
            assert_eq!(computed, root);
            assert!(verify_merkle_proof_with_leaf_count(
                &root,
                leaf,
                &proof,
                index,
                leaves.len()
            ));
        }
    }

    #[test]
    fn verify_merkle_proof_with_leaf_count_rejects_false_leaf_count() {
        let leaves = [
            Hash256::digest(b"false-count-a"),
            Hash256::digest(b"false-count-b"),
            Hash256::digest(b"false-count-c"),
            Hash256::digest(b"false-count-d"),
        ];
        let root = merkle_root_with_leaf_count(&leaves);
        let target_index = 2;
        let proof = merkle_proof(&leaves, target_index).expect("proof");

        assert!(!verify_merkle_proof_with_leaf_count(
            &root,
            &leaves[target_index],
            &proof,
            target_index,
            3
        ));
    }

    #[test]
    fn verify_merkle_proof_with_leaf_count_rejects_false_prefix_leaf_count() {
        let leaves = [
            Hash256::digest(b"false-prefix-count-a"),
            Hash256::digest(b"false-prefix-count-b"),
            Hash256::digest(b"false-prefix-count-c"),
            Hash256::digest(b"false-prefix-count-d"),
        ];
        let root = merkle_root_with_leaf_count(&leaves);
        let target_index = 1;
        let proof = merkle_proof(&leaves, target_index).expect("proof");

        assert!(!verify_merkle_proof_with_leaf_count(
            &root,
            &leaves[target_index],
            &proof,
            target_index,
            3
        ));
    }

    #[test]
    fn verify_merkle_proof_with_leaf_count_rejects_bad_odd_duplicate_sibling() {
        let leaves = [
            Hash256::digest(b"odd-count-a"),
            Hash256::digest(b"odd-count-b"),
            Hash256::digest(b"odd-count-c"),
        ];
        let root = merkle_root_with_leaf_count(&leaves);
        let target_index = 2;
        let mut proof = merkle_proof(&leaves, target_index).expect("proof");
        proof[0] = Hash256::digest(b"attacker-supplied-non-duplicate");

        assert!(!verify_merkle_proof_with_leaf_count(
            &root,
            &leaves[target_index],
            &proof,
            target_index,
            leaves.len()
        ));
    }

    #[test]
    fn verify_merkle_proof_uses_constant_time_root_comparison() {
        let source = include_str!("hash.rs");
        let Some(after_verify_fn) = source.split("pub fn verify_merkle_proof").nth(1) else {
            panic!("verify_merkle_proof source exists");
        };
        let Some(verify_body) = after_verify_fn.split("/// Hash two nodes together").next() else {
            panic!("hash_pair marker follows verify_merkle_proof");
        };

        assert!(
            verify_body.contains("hash256_eq_constant_time(&current, root)"),
            "verify_merkle_proof must compare the reconstructed root in constant time"
        );
        assert!(
            !verify_body.contains("current == *root"),
            "verify_merkle_proof must not use direct Hash256 equality for the root check"
        );
    }

    #[test]
    fn hash256_eq_constant_time_matches_hash_equality() {
        let first = Hash256::digest(b"same");
        let same = Hash256::digest(b"same");
        let different_first_byte = Hash256::from_bytes({
            let mut bytes = *first.as_bytes();
            bytes[0] ^= 0x80;
            bytes
        });
        let different_last_byte = Hash256::from_bytes({
            let mut bytes = *first.as_bytes();
            bytes[31] ^= 0x01;
            bytes
        });

        assert!(hash256_eq_constant_time(&first, &same));
        assert!(!hash256_eq_constant_time(&first, &different_first_byte));
        assert!(!hash256_eq_constant_time(&first, &different_last_byte));
    }

    #[test]
    fn hash_pair_deterministic() {
        let a = Hash256::digest(b"left");
        let b = Hash256::digest(b"right");
        let h1 = hash_pair(&a, &b);
        let h2 = hash_pair(&a, &b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_pair_not_commutative() {
        let a = Hash256::digest(b"left");
        let b = Hash256::digest(b"right");
        assert_ne!(hash_pair(&a, &b), hash_pair(&b, &a));
    }
}
