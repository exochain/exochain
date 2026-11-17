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

//! Offline verification of the committed fixture bundle.
//!
//! The fixture is embedded at compile time, so these tests open no files
//! and no sockets: verification depends only on the bundle and the trust
//! inputs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use exo_core::{Did, Hash256, PublicKey, Timestamp, crypto::KeyPair};
use exo_dag::mmr;
use exo_verify::{
    KeyRole, LeafPath, ReceiptBundle, ReceiptInclusionProof, ReceiptTreeHead, TrustInputs,
    VerifyError, verify_receipt_bundle,
};

const BUNDLE_JSON: &str = include_str!("../fixtures/offline-bundle/receipt-bundle.json");
const TRUST_JSON: &str = include_str!("../fixtures/offline-bundle/trust-inputs.json");
const VALIDATOR_SIGNED_BYTES: &[u8] =
    include_bytes!("../fixtures/offline-bundle/validator-signed-bytes.cbor");
const SUBJECT_SIGNED_BYTES: &[u8] =
    include_bytes!("../fixtures/offline-bundle/subject-signed-bytes.cbor");
const TIMESTAMP_TOKEN_DER: &[u8] =
    include_bytes!("../fixtures/offline-bundle/rfc3161-timestamp-token.der");

fn fixture() -> (ReceiptBundle, TrustInputs) {
    (
        serde_json::from_str(BUNDLE_JSON).unwrap(),
        serde_json::from_str(TRUST_JSON).unwrap(),
    )
}

fn verify(bundle: &ReceiptBundle, trust: &TrustInputs) -> Result<(), VerifyError> {
    verify_receipt_bundle(bundle, trust).map(|_| ())
}

#[test]
fn fixture_verifies_all_four_properties_offline() {
    let (bundle, trust) = fixture();
    let verified = verify_receipt_bundle(&bundle, &trust).unwrap();
    assert_eq!(verified.receipt_id, bundle.receipt.receipt_id);
    assert_eq!(verified.leaf_index, 2);
    assert_eq!(verified.tree_size, 5);
    assert_eq!(verified.trusted_time, bundle.receipt.created_at);
    assert_ne!(verified.subject_signed_at, verified.trusted_time);
    assert!(verified.human_approval_present_unverified);
    let approval = bundle
        .receipt
        .verify_subject_attestation()
        .unwrap()
        .action
        .human_approval
        .unwrap();
    assert!(!approval.signature.is_empty());
}

#[test]
fn raw_material_files_match_the_bundle() {
    let (bundle, _) = fixture();
    let receipt = &bundle.receipt;
    assert_eq!(
        receipt.signed_payload.as_deref(),
        Some(VALIDATOR_SIGNED_BYTES)
    );
    assert_eq!(
        receipt.subject_attestation.as_ref().unwrap().signed_bytes,
        SUBJECT_SIGNED_BYTES
    );
    let token = &receipt
        .external_timestamp_proof
        .as_ref()
        .unwrap()
        .rfc3161
        .as_ref()
        .unwrap()
        .token_der_base64;
    assert_eq!(BASE64_STANDARD.decode(token).unwrap(), TIMESTAMP_TOKEN_DER);
}

// --- Property 1: signatures over the exact signed bytes -------------------

#[test]
fn tampered_validator_signed_bytes_fail() {
    let (mut bundle, trust) = fixture();
    let bytes = bundle.receipt.signed_payload.as_mut().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignedBytesMismatch { .. })
    ));
}

#[test]
fn tampered_receipt_field_fails() {
    let (mut bundle, trust) = fixture();
    bundle.receipt.reason_codes.clear();
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignedBytesMismatch { .. })
    ));
}

#[test]
fn tampered_subject_signed_bytes_fail() {
    let (mut bundle, trust) = fixture();
    let attestation = bundle.receipt.subject_attestation.as_mut().unwrap();
    let last = attestation.signed_bytes.len() - 1;
    attestation.signed_bytes[last] ^= 0x01;
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignedBytesMismatch { .. })
    ));
}

#[test]
fn forged_validator_signature_fails() {
    let (mut bundle, trust) = fixture();
    bundle.receipt.signature = exo_core::Signature::from_bytes([7u8; 64]);
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::ValidatorSignatureInvalid)
    );
}

// --- Property 2: inclusion and position -----------------------------------

#[test]
fn wrong_position_fails() {
    for leaf_index in [0, 1, 3, 4, 5] {
        let (mut bundle, trust) = fixture();
        bundle.inclusion_proof.leaf_index = leaf_index;
        assert!(
            matches!(
                verify(&bundle, &trust),
                Err(VerifyError::InclusionProofInvalid { .. })
            ),
            "position {leaf_index} must not verify"
        );
    }
}

#[test]
fn proof_for_another_receipt_fails() {
    let (mut bundle, trust) = fixture();
    bundle.inclusion_proof.receipt_id = Hash256::from_bytes([0x42; 32]);
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::InclusionProofReceiptMismatch)
    );
}

#[test]
fn tampered_tree_head_fails() {
    let (mut bundle, trust) = fixture();
    bundle.inclusion_proof.tree_head.tree_size = 6;
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::TreeHeadSignatureInvalid)
    );
    let (mut bundle, trust) = fixture();
    bundle.inclusion_proof.siblings.reverse();
    bundle.inclusion_proof.siblings[0] = Hash256::from_bytes([1; 32]);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::InclusionProofInvalid { .. })
    ));
}

// --- Property 3: signer identity -------------------------------------------

fn without(trust: &mut TrustInputs, role: KeyRole) {
    trust
        .key_bundle
        .keys
        .retain(|entry| !entry.roles.contains(&role));
}

#[test]
fn unknown_validator_key_fails() {
    let (bundle, mut trust) = fixture();
    without(&mut trust, KeyRole::Validator);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::UnknownSigner { did }) if did.contains("fixture-validator")
    ));
}

#[test]
fn unknown_agent_key_fails() {
    let (bundle, mut trust) = fixture();
    without(&mut trust, KeyRole::Agent);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::UnknownSigner { did }) if did.contains("fixture-agent")
    ));
}

#[test]
fn rotated_agent_key_fails() {
    let (bundle, mut trust) = fixture();
    for entry in &mut trust.key_bundle.keys {
        if entry.roles.contains(&KeyRole::Agent) {
            entry.public_key = PublicKey::from_bytes([9; 32]);
        }
    }
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignerKeyMismatch { .. })
    ));
}

#[test]
fn rotated_validator_key_fails_signature() {
    let (bundle, mut trust) = fixture();
    for entry in &mut trust.key_bundle.keys {
        if entry.roles.contains(&KeyRole::Validator) {
            entry.public_key = PublicKey::from_bytes([9; 32]);
        }
    }
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::ValidatorSignatureInvalid)
    );
}

#[test]
fn wrong_role_and_expired_key_fail() {
    let (bundle, mut trust) = fixture();
    for entry in &mut trust.key_bundle.keys {
        entry.roles = vec![KeyRole::Agent];
    }
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignerRoleMismatch {
            role: "validator",
            ..
        })
    ));
    let (bundle, mut trust) = fixture();
    for entry in &mut trust.key_bundle.keys {
        entry.valid_until = Some(Timestamp::new(1_767_225_600_001, 0));
    }
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignerKeyNotValidAtTime { .. })
    ));
}

// --- Property 4: trusted time ----------------------------------------------

#[test]
fn missing_timestamp_fails() {
    let (mut bundle, trust) = fixture();
    bundle.receipt.external_timestamp_proof = None;
    assert_eq!(verify(&bundle, &trust), Err(VerifyError::TimestampMissing));
}

#[test]
fn operator_signed_timestamp_is_not_rfc3161() {
    let (mut bundle, trust) = fixture();
    let proof = bundle.receipt.external_timestamp_proof.as_mut().unwrap();
    proof.proof_kind = exo_avc::AvcReceiptExternalTimestampProofKind::JsonEd25519;
    proof.rfc3161 = None;
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampNotRfc3161 { .. })
    ));
    let (mut bundle, trust) = fixture();
    bundle.receipt.timestamp_provenance =
        Some(exo_avc::AvcReceiptTimestampProvenance::LocalHybridLogicalClock);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampNotRfc3161 { .. })
    ));
}

#[test]
fn corrupted_timestamp_token_fails() {
    let (mut bundle, trust) = fixture();
    let rfc3161 = bundle
        .receipt
        .external_timestamp_proof
        .as_mut()
        .unwrap()
        .rfc3161
        .as_mut()
        .unwrap();
    let mut token = BASE64_STANDARD.decode(&rfc3161.token_der_base64).unwrap();
    let last = token.len() - 1;
    token[last] ^= 0x01;
    rfc3161.token_der_base64 = BASE64_STANDARD.encode(token);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampInvalid { .. })
    ));
}

#[test]
fn untrusted_timestamp_authority_fails() {
    let (bundle, mut trust) = fixture();
    // Pin the TSA signer certificate's issuer as an unrelated key.
    trust.tsa.issuing_ca_spki_der_hex = vec![format!("30{}", "00".repeat(40))];
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampInvalid { .. })
    ));
}

#[test]
fn timestamp_must_cover_this_receipt_and_its_time() {
    let (mut bundle, trust) = fixture();
    bundle
        .receipt
        .external_timestamp_proof
        .as_mut()
        .unwrap()
        .subject_hash = Hash256::from_bytes([3; 32]);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampSubjectMismatch { .. })
    ));
    let (mut bundle, trust) = fixture();
    bundle.receipt.created_at = Timestamp::new(bundle.receipt.created_at.physical_ms + 1, 0);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampSubjectMismatch { .. })
    ));
    let (mut bundle, trust) = fixture();
    bundle.receipt.previous_receipt_hash = Some(Hash256::from_bytes([4; 32]));
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampSubjectMismatch { .. })
    ));
}

// --- Legacy and malformed input ---------------------------------------------

#[test]
fn legacy_receipts_never_pass() {
    let (mut bundle, trust) = fixture();
    bundle.receipt.signed_payload = None;
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::LegacyReceipt {
            missing: "validator signed bytes"
        })
    );
    let (mut bundle, trust) = fixture();
    bundle.receipt.subject_attestation = None;
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::LegacyReceipt {
            missing: "subject attestation"
        })
    );
}

#[test]
fn malformed_inputs_fail() {
    let (mut bundle, trust) = fixture();
    bundle.format = "exo.verify.receipt_bundle.v0".into();
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::MalformedBundle { .. })
    ));
    let (bundle, mut trust) = fixture();
    trust.key_bundle.format = "other".into();
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::MalformedBundle { .. })
    ));
    let (bundle, mut trust) = fixture();
    trust.tsa.issuing_ca_spki_der_hex.clear();
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::MalformedBundle { .. })
    ));
}

#[test]
fn fixture_signers_are_did_exo_identities() {
    let (bundle, trust) = fixture();
    for entry in &trust.key_bundle.keys {
        assert!(entry.did.as_str().starts_with("did:exo:"));
    }
    assert_eq!(
        bundle.receipt.validator_did,
        Did::new("did:exo:fixture-validator").unwrap()
    );
}

// --- Adversarial review regressions (PR #912) ------------------------------

fn agent_entry(trust: &mut TrustInputs) -> &mut exo_verify::KeyBundleEntry {
    trust
        .key_bundle
        .keys
        .iter_mut()
        .find(|entry| entry.roles.contains(&KeyRole::Agent))
        .unwrap()
}

/// An agent key that expired after the agent's self-asserted
/// `validation_now` but before the RFC 3161 time must not pass: the agent
/// could otherwise backdate its signed time into the key's window.
#[test]
fn expired_agent_key_cannot_backdate_validation_now() {
    let (bundle, mut trust) = fixture();
    let subject_at = bundle
        .receipt
        .subject_attestation
        .as_ref()
        .unwrap()
        .validation_now;
    let trusted_at = bundle.receipt.created_at;
    let expiry = subject_at.physical_ms + 1;
    assert!(expiry <= trusted_at.physical_ms);
    agent_entry(&mut trust).valid_until = Some(Timestamp::new(expiry, 0));
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignerKeyNotValidAtTime { did }) if did.contains("fixture-agent")
    ));
}

/// The agent key must also be valid at the time the agent signed.
#[test]
fn agent_key_not_yet_valid_at_signing_time_fails() {
    let (bundle, mut trust) = fixture();
    let subject_at = bundle
        .receipt
        .subject_attestation
        .as_ref()
        .unwrap()
        .validation_now;
    agent_entry(&mut trust).valid_from = Some(Timestamp::new(subject_at.physical_ms + 1, 0));
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::SignerKeyNotValidAtTime { .. })
    ));
}

fn add_second_validator(trust: &mut TrustInputs, valid: Option<(u64, u64)>) -> KeyPair {
    let attacker = KeyPair::from_secret_bytes([0x5e; 32]).unwrap();
    trust.key_bundle.keys.push(exo_verify::KeyBundleEntry {
        did: Did::new("did:exo:second-validator").unwrap(),
        public_key: attacker.public,
        roles: vec![KeyRole::Validator],
        valid_from: valid.map(|(from, _)| Timestamp::new(from, 0)),
        valid_until: valid.map(|(_, until)| Timestamp::new(until, 0)),
    });
    attacker
}

fn resign(head: &mut ReceiptTreeHead, key: &KeyPair) {
    head.signature = key.sign(&head.signing_payload().unwrap());
}

/// A second trusted validator re-signs the honest Merkle path for the
/// receipt. Includes a key whose validity window excludes the receipt time.
#[test]
fn tree_head_signed_by_another_validator_fails() {
    for window in [None, Some((1, 2))] {
        let (mut bundle, mut trust) = fixture();
        let attacker = add_second_validator(&mut trust, window);
        let head = &mut bundle.inclusion_proof.tree_head;
        head.validator_did = Did::new("did:exo:second-validator").unwrap();
        resign(head, &attacker);
        assert_eq!(
            verify(&bundle, &trust),
            Err(VerifyError::TreeHeadValidatorMismatch),
            "window {window:?}"
        );

        // Claiming the receipt validator's DID with the other key fails too.
        let (mut bundle, mut trust) = fixture();
        let attacker = add_second_validator(&mut trust, window);
        resign(&mut bundle.inclusion_proof.tree_head, &attacker);
        assert_eq!(
            verify(&bundle, &trust),
            Err(VerifyError::TreeHeadSignatureInvalid)
        );
    }
}

/// The receipt moved to index 1 of a fresh 4-leaf tree whose signed chain
/// head is unrelated to the receipt chain, signed by a second validator.
#[test]
fn receipt_moved_into_an_unrelated_tree_fails() {
    let (mut bundle, mut trust) = fixture();
    let attacker = add_second_validator(&mut trust, None);
    let receipt_id = bundle.receipt.receipt_id;
    let leaves = [
        bundle.receipt.previous_receipt_hash.unwrap(),
        receipt_id,
        Hash256::digest(b"filler"),
        Hash256::digest(b"unrelated-chain-head"),
    ];
    let mut tree = mmr::MerkleMountainRange::new();
    for leaf in leaves {
        mmr::append(&mut tree, leaf);
    }
    let path = |at: usize| {
        let p = mmr::prove(&tree, at).unwrap();
        LeafPath {
            siblings: p.siblings,
            peak_index: u64::try_from(p.peak_index).unwrap(),
        }
    };
    let dag = mmr::prove(&tree, 1).unwrap();
    let mut head = ReceiptTreeHead {
        validator_did: Did::new("did:exo:second-validator").unwrap(),
        tree_size: 4,
        root: mmr::root(&tree),
        chain_head: leaves[3],
        signature: exo_core::Signature::empty(),
    };
    resign(&mut head, &attacker);
    bundle.inclusion_proof = ReceiptInclusionProof {
        receipt_id,
        leaf_index: 1,
        siblings: dag.siblings,
        peak_index: u64::try_from(dag.peak_index).unwrap(),
        peaks: dag.peaks,
        tree_head: head,
        previous_leaf_path: Some(path(0)),
        chain_head_path: Some(path(3)),
    };
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::TreeHeadValidatorMismatch)
    );

    // The alternate tree is well formed under the Merkle checks: its prior
    // leaf is the real previous receipt and its chain head is proven last.
    // Only the signer binding rejects it here. A receipt-validator signature
    // over such a tree is validator equivocation; the caller detects it by
    // pinning the latest head (see `proof_must_be_against_latest_trusted_head`).
    bundle
        .inclusion_proof
        .verify_path(bundle.receipt.previous_receipt_hash.as_ref())
        .unwrap();
}

/// The position must be bound to the receipt chain under the signed root:
/// the previous leaf and the signed chain head both need their own paths.
#[test]
fn position_must_be_bound_to_the_receipt_chain() {
    let (mut bundle, trust) = fixture();
    bundle.inclusion_proof.previous_leaf_path = None;
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::ChainBindingInvalid { .. })
    ));

    let (mut bundle, trust) = fixture();
    bundle.inclusion_proof.chain_head_path = None;
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::ChainBindingInvalid { .. })
    ));

    // Swap the two paths: neither proves its leaf at its position.
    let (mut bundle, trust) = fixture();
    let proof = &mut bundle.inclusion_proof;
    std::mem::swap(&mut proof.previous_leaf_path, &mut proof.chain_head_path);
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::ChainBindingInvalid { .. })
    ));

    // A receipt whose previous hash is not the leaf before it.
    let (mut bundle, trust) = fixture();
    bundle.inclusion_proof.previous_leaf_path = bundle.inclusion_proof.chain_head_path.clone();
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::ChainBindingInvalid { .. })
    ));
}

#[test]
fn timestamp_policy_outside_caller_allowlist_fails() {
    let (bundle, mut trust) = fixture();
    trust.tsa.allowed_policy_oids = vec!["1.2.3.4".into()];
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::TimestampInvalid { reason }) if reason.contains("allowed policies")
    ));
}

/// Bundles from before the chain-binding paths use format v1 and are
/// rejected with a version error rather than a proof failure.
#[test]
fn v1_bundles_are_rejected_with_a_version_error() {
    let (mut bundle, trust) = fixture();
    bundle.format = exo_verify::RECEIPT_BUNDLE_FORMAT_V1.into();
    assert!(matches!(
        verify(&bundle, &trust),
        Err(VerifyError::UnsupportedBundleVersion { format }) if format.ends_with(".v1")
    ));
}

/// The agent's signed time may not be later than the RFC 3161 time.
#[test]
fn subject_time_after_trusted_time_fails() {
    let (mut bundle, trust) = fixture();
    let trusted = bundle.receipt.created_at;
    bundle
        .receipt
        .subject_attestation
        .as_mut()
        .unwrap()
        .validation_now = Timestamp::new(trusted.physical_ms + 1, 0);
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::SubjectTimeAfterTrustedTime)
    );
}

/// With a caller-pinned latest head, a proof against any other head (for
/// example one issued before a rollback) is stale.
#[test]
fn proof_must_be_against_latest_trusted_head() {
    let (bundle, mut trust) = fixture();
    trust.latest_tree_head = Some(bundle.inclusion_proof.tree_head.clone());
    verify(&bundle, &trust).unwrap();

    let mut later = bundle.inclusion_proof.tree_head.clone();
    later.tree_size += 1;
    later.root = Hash256::digest(b"later-root");
    trust.latest_tree_head = Some(later);
    assert_eq!(
        verify(&bundle, &trust),
        Err(VerifyError::StaleTreeHead {
            proof_tree_size: 5,
            latest_tree_size: 6,
        })
    );
}
