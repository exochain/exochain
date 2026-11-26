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
pub const AVC_RECEIPT_TREE_HEAD_DOMAIN: &str = "exo.avc.receipt.tree_head.v2";

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
    /// Receipt ID of the first leaf (the genesis receipt), identifying the
    /// chain this head belongs to.
    pub chain_id: Hash256,
    /// Validator signature over [`ReceiptTreeHead::signing_payload`].
    pub signature: Signature,
}

/// Signed tree-head fields. Declared in sorted key order (`chain_head`,
/// `chain_id`, `domain`, `root`, `tree_size`, `validator_did`), so the CBOR
/// map is encoded with sorted keys as the workspace rules require. This is
/// the same lexicographic key order the rest of the workspace gets from
/// `BTreeMap` keys. A unit test checks the encoded key order.
#[derive(Serialize)]
struct TreeHeadSigningPayload<'a> {
    chain_head: &'a Hash256,
    chain_id: &'a Hash256,
    domain: &'static str,
    root: &'a Hash256,
    tree_size: u64,
    validator_did: &'a Did,
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
                chain_head: &self.chain_head,
                chain_id: &self.chain_id,
                domain: AVC_RECEIPT_TREE_HEAD_DOMAIN,
                root: &self.root,
                tree_size: self.tree_size,
                validator_did: &self.validator_did,
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

/// Merkle path from one leaf up to its peak, under the peaks of the
/// enclosing [`ReceiptInclusionProof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafPath {
    /// Sibling hashes from the leaf up to its peak.
    pub siblings: Vec<Hash256>,
    /// Index of the peak containing the leaf.
    pub peak_index: u64,
}

/// Proof that a receipt is the leaf at `leaf_index` of the receipt MMR
/// committed to by `tree_head`.
///
/// Extra paths bind the position to the linear receipt chain under the same
/// root: `previous_leaf_path` proves that the leaf before the receipt is the
/// receipt's `previous_receipt_hash`, `chain_head_path` proves that the
/// signed `chain_head` is the last leaf, and `genesis_path` proves that the
/// signed `chain_id` is the first leaf.
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
    /// Path for the leaf at `leaf_index - 1`. Required when `leaf_index > 0`
    /// and absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_leaf_path: Option<LeafPath>,
    /// Path for the leaf at `tree_size - 1`. Required when the receipt is not
    /// the last leaf and absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_head_path: Option<LeafPath>,
    /// Path for the leaf at index 0. Required when `leaf_index >= 2`; for
    /// index 0 the chain ID is the receipt and for index 1 it is the
    /// previous receipt, both already proven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_path: Option<LeafPath>,
}

impl ReceiptInclusionProof {
    /// Verify the proof's position and root against its tree head, and bind
    /// the position to the receipt chain.
    ///
    /// This checks Merkle paths only; the caller must also verify the tree
    /// head signature against the receipt validator's key.
    ///
    /// # Errors
    /// Returns [`VerifyError::InclusionProofInvalid`] when the path, position
    /// or peaks do not reproduce the tree head root, and
    /// [`VerifyError::ChainBindingInvalid`] when the previous leaf is not
    /// `previous_receipt_hash`, the signed chain head is not the last leaf, or
    /// the signed chain ID is not the first leaf.
    pub fn verify_path(&self, previous_receipt_hash: Option<&Hash256>) -> Result<(), VerifyError> {
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

        let chain = |reason: &str| VerifyError::ChainBindingInvalid {
            reason: reason.into(),
        };
        match (position, previous_receipt_hash, &self.previous_leaf_path) {
            (0, None, None) => {}
            (0, _, _) => {
                return Err(chain(
                    "first leaf must have no previous receipt and no previous path",
                ));
            }
            (_, Some(previous), Some(path)) => {
                if !self.leaf_proves(previous, position - 1, path, leaf_count) {
                    return Err(chain(
                        "previous leaf is not the receipt's previous_receipt_hash",
                    ));
                }
            }
            (_, None, _) => {
                return Err(chain(
                    "receipt after the first leaf has no previous receipt",
                ));
            }
            (_, Some(_), None) => return Err(chain("previous leaf path is missing")),
        }
        let chain_id = &self.tree_head.chain_id;
        match (position, previous_receipt_hash, &self.genesis_path) {
            (0, _, None) if chain_id == &self.receipt_id => {}
            (1, Some(previous), None) if chain_id == previous => {}
            (0 | 1, _, _) => {
                return Err(chain("chain ID is not the first leaf"));
            }
            (_, _, Some(path)) => {
                if !self.leaf_proves(chain_id, 0, path, leaf_count) {
                    return Err(chain("chain ID is not the first leaf"));
                }
            }
            (_, _, None) => return Err(chain("genesis path is missing")),
        }
        if position + 1 == leaf_count {
            if self.tree_head.chain_head != self.receipt_id {
                return Err(chain("last leaf is not the signed chain head"));
            }
            if self.chain_head_path.is_some() {
                return Err(chain("chain head path given for the last leaf"));
            }
        } else {
            let Some(path) = &self.chain_head_path else {
                return Err(chain("chain head path is missing"));
            };
            if !self.leaf_proves(&self.tree_head.chain_head, leaf_count - 1, path, leaf_count) {
                return Err(chain("signed chain head is not the last leaf"));
            }
        }
        Ok(())
    }

    fn leaf_proves(
        &self,
        leaf: &Hash256,
        position: usize,
        path: &LeafPath,
        leaf_count: usize,
    ) -> bool {
        let Ok(peak_index) = usize::try_from(path.peak_index) else {
            return false;
        };
        mmr_root_from_proof(
            leaf,
            position,
            &path.siblings,
            peak_index,
            &self.peaks,
            leaf_count,
        )
        .is_some_and(|root| root == self.tree_head.root)
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

    /// Sorted-key encoding of the v2 tree head signing payload.
    const TREE_HEAD_VECTOR_HEX: &str = concat!(
        "a66a636861696e5f6865616498201822182218221822182218221822182218221822182218221822182218221822182218221822182218221822182218221822182218221822182218221822182268636861696e5f6964982018",
        "33183318331833183318331833183318331833183318331833183318331833183318331833183318331833183318331833183318331833183318331833183366646f6d61696e781c65786f2e6176632e726563656970742e7472",
        "65655f686561642e763264726f6f749820111111111111111111111111111111111111111111111111111111111111111169747265655f73697a65056d76616c696461746f725f646964716469643a65786f3a76616c69646174",
        "6f72",
    );

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
            chain_id: leaves[0],
            signature: Signature::empty(),
        };
        head.signature = validator.sign(&head.signing_payload().unwrap());
        let path = |at: usize| {
            let p = mmr::prove(tree, at).unwrap();
            LeafPath {
                siblings: p.siblings,
                peak_index: u64::try_from(p.peak_index).unwrap(),
            }
        };
        ReceiptInclusionProof {
            receipt_id: leaves[position],
            leaf_index: u64::try_from(position).unwrap(),
            siblings: dag_proof.siblings,
            peak_index: u64::try_from(dag_proof.peak_index).unwrap(),
            peaks: dag_proof.peaks,
            tree_head: head,
            previous_leaf_path: (position > 0).then(|| path(position - 1)),
            chain_head_path: (position + 1 < leaves.len()).then(|| path(leaves.len() - 1)),
            genesis_path: (position >= 2).then(|| path(0)),
        }
    }

    fn previous(leaves: &[Hash256], position: usize) -> Option<&Hash256> {
        position.checked_sub(1).map(|p| &leaves[p])
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
                proof.verify_path(previous(&leaves, position)).unwrap();
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
        let prev = Some(&leaves[4]);

        let mut moved = proof.clone();
        moved.leaf_index = 4;
        assert!(matches!(
            moved.verify_path(prev),
            Err(VerifyError::InclusionProofInvalid { .. })
        ));

        let mut beyond = proof.clone();
        beyond.leaf_index = 11;
        assert!(beyond.verify_path(prev).is_err());

        let mut other = proof.clone();
        other.receipt_id = leaves[6];
        assert!(other.verify_path(prev).is_err());

        let mut root = proof.clone();
        root.tree_head.root = Hash256::from_bytes([1; 32]);
        assert!(root.verify_path(prev).is_err());

        let mut sibling = proof.clone();
        sibling.siblings[0] = Hash256::from_bytes([2; 32]);
        assert!(sibling.verify_path(prev).is_err());

        let mut size = proof.clone();
        size.tree_head.tree_size = 12;
        assert!(size.verify_path(prev).is_err());
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
        proof.verify_path(Some(&leaves[2])).unwrap();
        proof.tree_head.chain_head = leaves[2];
        assert!(matches!(
            proof.verify_path(Some(&leaves[2])),
            Err(VerifyError::ChainBindingInvalid { .. })
        ));
    }

    #[test]
    fn position_is_bound_to_previous_receipt_and_chain_head() {
        let validator = KeyPair::from_secret_bytes([0x33; 32]).unwrap();
        let mut tree = mmr::MerkleMountainRange::new();
        let leaves: Vec<Hash256> = (0..7).map(leaf).collect();
        for l in &leaves {
            mmr::append(&mut tree, *l);
        }
        let proof = proof_from_dag(&tree, &leaves, 3, &validator);
        proof.verify_path(Some(&leaves[2])).unwrap();
        let chain_err = |p: &ReceiptInclusionProof, prev: Option<&Hash256>| {
            matches!(
                p.verify_path(prev),
                Err(VerifyError::ChainBindingInvalid { .. })
            )
        };

        // Predecessor in the tree is not the receipt's previous_receipt_hash.
        assert!(chain_err(&proof, Some(&leaves[1])));
        assert!(chain_err(&proof, None));
        let mut no_prev = proof.clone();
        no_prev.previous_leaf_path = None;
        assert!(chain_err(&no_prev, Some(&leaves[2])));

        // Signed chain head is not the last leaf (non-tip receipt).
        let mut head = proof.clone();
        head.tree_head.chain_head = leaves[5];
        head.tree_head.signature = validator.sign(&head.tree_head.signing_payload().unwrap());
        assert!(chain_err(&head, Some(&leaves[2])));
        let mut no_head = proof.clone();
        no_head.chain_head_path = None;
        assert!(chain_err(&no_head, Some(&leaves[2])));

        // Signed chain ID is not the first leaf.
        let mut wrong_chain = proof.clone();
        wrong_chain.tree_head.chain_id = leaves[1];
        assert!(chain_err(&wrong_chain, Some(&leaves[2])));
        let mut no_genesis = proof.clone();
        no_genesis.genesis_path = None;
        assert!(chain_err(&no_genesis, Some(&leaves[2])));
        let second = proof_from_dag(&tree, &leaves, 1, &validator);
        second.verify_path(Some(&leaves[0])).unwrap();
        let mut second_wrong = second.clone();
        second_wrong.tree_head.chain_id = leaves[3];
        assert!(chain_err(&second_wrong, Some(&leaves[0])));

        // First leaf must not claim a predecessor.
        let first = proof_from_dag(&tree, &leaves, 0, &validator);
        first.verify_path(None).unwrap();
        assert!(chain_err(&first, Some(&leaves[0])));
        let mut extra = first.clone();
        extra.previous_leaf_path = proof.previous_leaf_path.clone();
        assert!(chain_err(&extra, None));
    }

    /// Fixed byte vector for the tree head signing payload, for other
    /// implementations.
    #[test]
    fn tree_head_signing_payload_vector() {
        let head = ReceiptTreeHead {
            validator_did: Did::new("did:exo:validator").unwrap(),
            tree_size: 5,
            root: Hash256::from_bytes([0x11; 32]),
            chain_head: Hash256::from_bytes([0x22; 32]),
            chain_id: Hash256::from_bytes([0x33; 32]),
            signature: Signature::empty(),
        };
        let payload = head.signing_payload().unwrap();
        assert_eq!(hex::encode(&payload), TREE_HEAD_VECTOR_HEX);
    }

    #[test]
    fn tree_head_signing_payload_keys_are_sorted() {
        let head = ReceiptTreeHead {
            validator_did: Did::new("did:exo:validator").unwrap(),
            tree_size: 5,
            root: Hash256::from_bytes([0x11; 32]),
            chain_head: Hash256::from_bytes([0x22; 32]),
            chain_id: Hash256::from_bytes([0x33; 32]),
            signature: Signature::empty(),
        };
        let payload = head.signing_payload().unwrap();
        let value: ciborium::value::Value = ciborium::from_reader(payload.as_slice()).unwrap();
        let keys: Vec<String> = value
            .as_map()
            .unwrap()
            .iter()
            .map(|(key, _)| key.as_text().unwrap().to_owned())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(keys, sorted);
        assert_eq!(
            keys,
            [
                "chain_head",
                "chain_id",
                "domain",
                "root",
                "tree_size",
                "validator_did"
            ]
        );
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
        let mutations: [fn(&mut ReceiptTreeHead); 6] = [
            |h| h.chain_id = Hash256::from_bytes([7; 32]),
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
