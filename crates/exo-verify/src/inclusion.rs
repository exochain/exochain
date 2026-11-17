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

//! Property 2: inclusion and position of a receipt in the sealed AVC
//! receipt chain.
//!
//! The validator node keeps a Merkle Mountain Range over receipt IDs in
//! chain order (the linear `previous_receipt_hash` chain the registry
//! enforces). For each receipt it returns a proof of the receipt's leaf
//! index together with a validator-signed tree head over the MMR root and
//! size. The verifier recomputes the root from the proof and checks the
//! tree head signature, so the position is bound to a signed root.
//!
//! The hash construction matches `exo-dag`'s MMR exactly (verified by a
//! compatibility test), without depending on that crate.

use exo_core::{Did, Hash256, PublicKey, Signature, crypto};
use serde::{Deserialize, Serialize};

use crate::error::VerifyError;

/// Domain tag for the validator-signed receipt tree head.
pub const AVC_RECEIPT_TREE_HEAD_DOMAIN: &str = "exo.avc.receipt.tree_head.v1";

/// Validator-signed commitment to the receipt MMR at a given size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptTreeHead {
    /// Validator that signed this tree head.
    pub validator_did: Did,
    /// Number of receipts (leaves) in the chain at this head.
    pub tree_size: u64,
    /// MMR root over the receipt IDs, in chain order.
    pub root: Hash256,
    /// Receipt ID of the last leaf (the chain head at this size).
    pub chain_head: Hash256,
    /// Validator signature over [`ReceiptTreeHead::signing_payload`].
    pub signature: Signature,
}

#[derive(Serialize)]
struct TreeHeadSigningPayload<'a> {
    domain: &'static str,
    validator_did: &'a Did,
    tree_size: u64,
    root: &'a Hash256,
    chain_head: &'a Hash256,
}

impl ReceiptTreeHead {
    /// Canonical, domain-tagged CBOR bytes the validator signs.
    ///
    /// # Errors
    /// Returns [`VerifyError::MalformedBundle`] if CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, VerifyError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &TreeHeadSigningPayload {
                domain: AVC_RECEIPT_TREE_HEAD_DOMAIN,
                validator_did: &self.validator_did,
                tree_size: self.tree_size,
                root: &self.root,
                chain_head: &self.chain_head,
            },
            &mut buf,
        )
        .map_err(|_| VerifyError::MalformedBundle {
            reason: "tree head CBOR encoding failed".into(),
        })?;
        Ok(buf)
    }

    /// Verify the tree head signature with the validator's public key.
    ///
    /// # Errors
    /// Returns [`VerifyError::TreeHeadSignatureInvalid`] when it does not verify.
    pub fn verify_signature(&self, validator_public_key: &PublicKey) -> Result<(), VerifyError> {
        let payload = self.signing_payload()?;
        if self.signature.is_empty()
            || !crypto::verify(&payload, &self.signature, validator_public_key)
        {
            return Err(VerifyError::TreeHeadSignatureInvalid);
        }
        Ok(())
    }
}

/// Proof that a receipt is the leaf at `leaf_index` of the receipt MMR
/// committed to by `tree_head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptInclusionProof {
    /// Receipt the proof is for.
    pub receipt_id: Hash256,
    /// Zero-based position of the receipt in the chain.
    pub leaf_index: u64,
    /// Sibling hashes from the leaf up to its peak.
    pub siblings: Vec<Hash256>,
    /// Index of the peak containing the leaf.
    pub peak_index: u64,
    /// All peak hashes at `tree_head.tree_size`, tallest first.
    pub peaks: Vec<Hash256>,
    /// Signed tree head the proof verifies against.
    pub tree_head: ReceiptTreeHead,
}

impl ReceiptInclusionProof {
    /// Verify the proof's position and root against its tree head.
    ///
    /// This checks the Merkle path only; the caller must also verify the
    /// tree head signature against a trusted validator key.
    ///
    /// # Errors
    /// Returns [`VerifyError::InclusionProofInvalid`] when the path, position
    /// or peaks do not reproduce the tree head root.
    pub fn verify_path(&self) -> Result<(), VerifyError> {
        let invalid = || VerifyError::InclusionProofInvalid {
            position: self.leaf_index,
            tree_size: self.tree_head.tree_size,
        };
        let leaf_count = usize::try_from(self.tree_head.tree_size).map_err(|_| invalid())?;
        let position = usize::try_from(self.leaf_index).map_err(|_| invalid())?;
        let peak_index = usize::try_from(self.peak_index).map_err(|_| invalid())?;
        if leaf_count == 0 || position >= leaf_count {
            return Err(invalid());
        }
        if position + 1 == leaf_count && self.tree_head.chain_head != self.receipt_id {
            return Err(invalid());
        }
        let root = mmr_root_from_proof(
            &self.receipt_id,
            position,
            &self.siblings,
            peak_index,
            &self.peaks,
            leaf_count,
        )
        .ok_or_else(invalid)?;
        if root != self.tree_head.root {
            return Err(invalid());
        }
        Ok(())
    }
}

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

/// Recompute the MMR root from an inclusion proof, or `None` if the proof
/// is inconsistent with `position` and `leaf_count`.
fn mmr_root_from_proof(
    leaf: &Hash256,
    position: usize,
    siblings: &[Hash256],
    peak_index: usize,
    peaks: &[Hash256],
    leaf_count: usize,
) -> Option<Hash256> {
    let counts = peak_leaf_counts(leaf_count);
    if peaks.is_empty() || peaks.len() != counts.len() || peak_index >= peaks.len() {
        return None;
    }
    let peak_leaf_count = counts[peak_index];
    let depth = usize::try_from(peak_leaf_count.trailing_zeros()).ok()?;
    if siblings.len() != depth {
        return None;
    }
    let peak_offset: usize = counts[..peak_index].iter().sum();
    if position < peak_offset || position >= peak_offset + peak_leaf_count {
        return None;
    }
    let mut node_idx = (peak_leaf_count - 1) + (position - peak_offset);
    let mut current = hash_leaf(leaf);
    for sibling in siblings {
        current = if node_idx % 2 == 1 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        node_idx = (node_idx - 1) / 2;
    }
    if current != peaks[peak_index] {
        return None;
    }
    Some(bag_peaks(peaks))
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::KeyPair;
    use exo_dag::mmr;

    use super::*;

    fn leaf(i: u8) -> Hash256 {
        Hash256::digest(&[i])
    }

    fn proof_from_dag(
        tree: &mmr::MerkleMountainRange,
        leaves: &[Hash256],
        position: usize,
        validator: &KeyPair,
    ) -> ReceiptInclusionProof {
        let dag_proof = mmr::prove(tree, position).unwrap();
        let mut head = ReceiptTreeHead {
            validator_did: Did::new("did:exo:validator").unwrap(),
            tree_size: u64::try_from(leaves.len()).unwrap(),
            root: mmr::root(tree),
            chain_head: *leaves.last().unwrap(),
            signature: Signature::empty(),
        };
        head.signature = validator.sign(&head.signing_payload().unwrap());
        ReceiptInclusionProof {
            receipt_id: leaves[position],
            leaf_index: u64::try_from(position).unwrap(),
            siblings: dag_proof.siblings,
            peak_index: u64::try_from(dag_proof.peak_index).unwrap(),
            peaks: dag_proof.peaks,
            tree_head: head,
        }
    }

    #[test]
    fn exo_dag_proofs_verify_for_every_position_and_size() {
        let validator = KeyPair::from_secret_bytes([0x33; 32]).unwrap();
        for size in 1..=33u8 {
            let mut tree = mmr::MerkleMountainRange::new();
            let leaves: Vec<Hash256> = (0..size).map(leaf).collect();
            for l in &leaves {
                mmr::append(&mut tree, *l);
            }
            for position in 0..leaves.len() {
                let proof = proof_from_dag(&tree, &leaves, position, &validator);
                assert!(
                    mmr::verify_proof(
                        &proof.tree_head.root,
                        &leaves[position],
                        position,
                        &mmr::prove(&tree, position).unwrap()
                    ),
                    "exo-dag self-check"
                );
                proof.verify_path().unwrap();
                proof.tree_head.verify_signature(&validator.public).unwrap();
            }
        }
    }

    #[test]
    fn wrong_position_receipt_or_root_fails() {
        let validator = KeyPair::from_secret_bytes([0x33; 32]).unwrap();
        let mut tree = mmr::MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..11).map(leaf).collect();
        for l in &leaves {
            mmr::append(&mut tree, *l);
        }
        let proof = proof_from_dag(&tree, &leaves, 5, &validator);

        let mut moved = proof.clone();
        moved.leaf_index = 4;
        assert!(matches!(
            moved.verify_path(),
            Err(VerifyError::InclusionProofInvalid { .. })
        ));

        let mut beyond = proof.clone();
        beyond.leaf_index = 11;
        assert!(beyond.verify_path().is_err());

        let mut other = proof.clone();
        other.receipt_id = leaves[6];
        assert!(other.verify_path().is_err());

        let mut root = proof.clone();
        root.tree_head.root = Hash256::from_bytes([1; 32]);
        assert!(root.verify_path().is_err());

        let mut sibling = proof.clone();
        sibling.siblings[0] = Hash256::from_bytes([2; 32]);
        assert!(sibling.verify_path().is_err());

        let mut size = proof.clone();
        size.tree_head.tree_size = 12;
        assert!(size.verify_path().is_err());
    }

    #[test]
    fn last_leaf_must_be_signed_chain_head() {
        let validator = KeyPair::from_secret_bytes([0x33; 32]).unwrap();
        let mut tree = mmr::MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..4).map(leaf).collect();
        for l in &leaves {
            mmr::append(&mut tree, *l);
        }
        let mut proof = proof_from_dag(&tree, &leaves, 3, &validator);
        proof.verify_path().unwrap();
        proof.tree_head.chain_head = leaves[2];
        assert!(proof.verify_path().is_err());
    }

    #[test]
    fn tree_head_signature_covers_every_field() {
        let validator = KeyPair::from_secret_bytes([0x33; 32]).unwrap();
        let mut tree = mmr::MerkleMountainRange::new();
        mmr::append(&mut tree, leaf(0));
        let proof = proof_from_dag(&tree, &[leaf(0)], 0, &validator);
        let head = proof.tree_head;
        head.verify_signature(&validator.public).unwrap();
        let other = KeyPair::from_secret_bytes([0x44; 32]).unwrap();
        assert_eq!(
            head.verify_signature(&other.public),
            Err(VerifyError::TreeHeadSignatureInvalid)
        );
        let mutations: [fn(&mut ReceiptTreeHead); 5] = [
            |h| h.tree_size += 1,
            |h| h.root = Hash256::from_bytes([5; 32]),
            |h| h.chain_head = Hash256::from_bytes([6; 32]),
            |h| h.validator_did = Did::new("did:exo:other").unwrap(),
            |h| h.signature = Signature::empty(),
        ];
        for mutate in mutations {
            let mut changed = head.clone();
            mutate(&mut changed);
            assert_eq!(
                changed.verify_signature(&validator.public),
                Err(VerifyError::TreeHeadSignatureInvalid)
            );
        }
    }
}
