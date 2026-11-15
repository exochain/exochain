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
use exo_core::{Did, Hash256, PublicKey, Timestamp};
use exo_verify::{KeyRole, ReceiptBundle, TrustInputs, VerifyError, verify_receipt_bundle};

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
    assert!(verified.human_approval_present);
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
    trust.tsa.issuing_ca_spki_der_hex = vec!["30".repeat(1) + &"00".repeat(40)];
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
