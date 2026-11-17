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

//! End-to-end offline verification of a receipt bundle.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use exo_avc::{
    AvcReceiptEvidenceSubject, AvcReceiptExternalTimestampProofKind, AvcReceiptTimestampProvenance,
    AvcTrustReceipt,
};
use exo_core::{Hash256, Timestamp, crypto};
use serde::{Deserialize, Serialize};

use crate::{
    error::VerifyError,
    inclusion::ReceiptInclusionProof,
    key_bundle::{KeyBundle, KeyRole},
    rfc3161::{
        Rfc3161TrustAnchors, deterministic_nonce_hex, verify_timestamp_token_with_trust_anchors,
    },
};

/// Format tag for [`ReceiptBundle`] version 1.
pub const RECEIPT_BUNDLE_FORMAT_V1: &str = "exo.verify.receipt_bundle.v1";

/// Everything needed to verify one receipt offline, apart from the caller's
/// trust inputs. The receipt carries its raw validator signed bytes, the
/// subject attestation with the subject's raw signed bytes, and the RFC 3161
/// token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptBundle {
    /// Must be [`RECEIPT_BUNDLE_FORMAT_V1`].
    pub format: String,
    pub receipt: AvcTrustReceipt,
    pub inclusion_proof: ReceiptInclusionProof,
}

/// Pinned RFC 3161 timestamp authority keys, as DER `SubjectPublicKeyInfo`
/// hex. At least one entry across both lists is required.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaTrust {
    /// SPKI of TSA signing certificates trusted directly.
    #[serde(default)]
    pub signer_spki_der_hex: Vec<String>,
    /// SPKI of CAs trusted to issue TSA signing certificates.
    #[serde(default)]
    pub issuing_ca_spki_der_hex: Vec<String>,
}

/// Caller-supplied trust inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustInputs {
    pub key_bundle: KeyBundle,
    pub tsa: TsaTrust,
}

/// Facts established by a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    pub receipt_id: Hash256,
    /// Zero-based position of the receipt in the receipt chain.
    pub leaf_index: u64,
    /// Chain size at the signed tree head the position was proven against.
    pub tree_size: u64,
    /// Time asserted by the RFC 3161 timestamp authority.
    pub trusted_time: Timestamp,
    /// Time the subject (agent) signed, distinct from `trusted_time`.
    pub subject_signed_at: Timestamp,
    pub validator_did: String,
    pub subject_did: String,
    /// Whether the subject's signed action carried a human approval. Its
    /// signature is not verified offline here (post-GA follow-up).
    pub human_approval_present: bool,
}

/// Verify all four level-3 properties of a receipt bundle offline.
///
/// Every property must pass. Checks run in this order and the first failure
/// is returned: legacy-receipt material, signer identity (property 3), RFC
/// 3161 trusted time (property 4), signatures over the exact stored bytes
/// (property 1), and inclusion and position under a signed tree head
/// (property 2). Time is checked before the validator signature so a
/// missing or bad timestamp reports as such, even though the timestamp proof
/// is also covered by the validator's signed bytes.
///
/// # Errors
/// Returns the [`VerifyError`] variant for the first failed check.
pub fn verify_receipt_bundle(
    bundle: &ReceiptBundle,
    trust: &TrustInputs,
) -> Result<VerifiedReceipt, VerifyError> {
    if bundle.format != RECEIPT_BUNDLE_FORMAT_V1 {
        return Err(VerifyError::MalformedBundle {
            reason: format!("unsupported receipt bundle format {:?}", bundle.format),
        });
    }
    trust.key_bundle.validate()?;
    let receipt = &bundle.receipt;

    // Legacy receipts never pass.
    let Some(signed_payload) = receipt.signed_payload.as_deref() else {
        return Err(VerifyError::LegacyReceipt {
            missing: "validator signed bytes",
        });
    };
    let Some(attestation) = receipt.subject_attestation.as_ref() else {
        return Err(VerifyError::LegacyReceipt {
            missing: "subject attestation",
        });
    };

    // Property 3: both signers resolve to known identities.
    let validator = trust.key_bundle.resolve(
        &receipt.validator_did,
        KeyRole::Validator,
        Some(&receipt.created_at),
    )?;
    trust.key_bundle.require_key(
        &attestation.subject_did,
        &attestation.subject_public_key,
        KeyRole::Agent,
        Some(&attestation.validation_now),
    )?;

    // Property 4: RFC 3161 trusted time over this receipt's evidence.
    let trusted_time = verify_trusted_time(receipt, &trust.tsa)?;

    // Property 1: validator signature over the exact stored bytes.
    let recomputed = receipt
        .signing_payload()
        .map_err(|error| VerifyError::MalformedBundle {
            reason: error.to_string(),
        })?;
    if recomputed != signed_payload {
        return Err(VerifyError::SignedBytesMismatch {
            reason: "stored bytes differ from the receipt's signed fields".into(),
        });
    }
    if Hash256::digest(signed_payload) != receipt.receipt_id {
        return Err(VerifyError::SignedBytesMismatch {
            reason: "receipt ID is not the digest of the stored bytes".into(),
        });
    }
    if receipt.signature.is_empty()
        || !crypto::verify(signed_payload, &receipt.signature, &validator.public_key)
    {
        return Err(VerifyError::ValidatorSignatureInvalid);
    }
    // Property 1: subject signature over its exact stored bytes, bound to
    // this receipt's credential, action and commitment.
    let decoded = receipt.verify_subject_attestation().map_err(|error| {
        VerifyError::SubjectAttestationInvalid {
            reason: error.to_string(),
        }
    })?;

    // Property 2: inclusion and position under a signed tree head.
    let proof = &bundle.inclusion_proof;
    if proof.receipt_id != receipt.receipt_id {
        return Err(VerifyError::InclusionProofReceiptMismatch);
    }
    let tree_head_signer =
        trust
            .key_bundle
            .resolve(&proof.tree_head.validator_did, KeyRole::Validator, None)?;
    proof
        .tree_head
        .verify_signature(&tree_head_signer.public_key)?;
    proof.verify_path()?;
    if (proof.leaf_index == 0) != receipt.previous_receipt_hash.is_none() {
        return Err(VerifyError::InclusionProofInvalid {
            position: proof.leaf_index,
            tree_size: proof.tree_head.tree_size,
        });
    }

    Ok(VerifiedReceipt {
        receipt_id: receipt.receipt_id,
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_head.tree_size,
        trusted_time,
        subject_signed_at: attestation.validation_now,
        validator_did: receipt.validator_did.to_string(),
        subject_did: attestation.subject_did.to_string(),
        human_approval_present: decoded.action.human_approval.is_some(),
    })
}

fn subject_mismatch(reason: &str) -> VerifyError {
    VerifyError::TimestampSubjectMismatch {
        reason: reason.into(),
    }
}

fn verify_trusted_time(
    receipt: &AvcTrustReceipt,
    tsa: &TsaTrust,
) -> Result<Timestamp, VerifyError> {
    let Some(proof) = receipt.external_timestamp_proof.as_ref() else {
        return Err(VerifyError::TimestampMissing);
    };
    let rfc3161 = match (&proof.proof_kind, proof.rfc3161.as_ref()) {
        (AvcReceiptExternalTimestampProofKind::Rfc3161, Some(rfc3161)) => rfc3161,
        (kind, _) => {
            return Err(VerifyError::TimestampNotRfc3161 {
                kind: format!("{kind:?}"),
            });
        }
    };
    if receipt.timestamp_provenance
        != Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority)
    {
        return Err(VerifyError::TimestampNotRfc3161 {
            kind: format!("provenance {:?}", receipt.timestamp_provenance),
        });
    }

    // Recompute the evidence subject the token must cover from the receipt.
    let (Some(action_id), Some(action_commitment_hash), Some(action_descriptor_hash)) = (
        receipt.action_id,
        receipt.action_commitment_hash,
        receipt.action_descriptor_hash,
    ) else {
        return Err(subject_mismatch(
            "receipt lacks the action fields the timestamp covers",
        ));
    };
    let subject = AvcReceiptEvidenceSubject {
        credential_id: receipt.credential_id,
        action_id,
        action_commitment_hash,
        action_descriptor_hash,
        previous_receipt_hash: receipt.previous_receipt_hash,
    };
    let encode_error = |error: exo_avc::AvcError| VerifyError::MalformedBundle {
        reason: error.to_string(),
    };
    let subject_hash = subject.hash().map_err(encode_error)?;
    if proof.subject_hash != subject_hash {
        return Err(subject_mismatch(
            "timestamp subject hash does not match the receipt",
        ));
    }
    let imprint = subject
        .rfc3161_sha256_message_imprint()
        .map_err(encode_error)?;
    if rfc3161.message_imprint_sha256_hex != hex::encode(imprint) {
        return Err(subject_mismatch(
            "timestamp message imprint does not match the receipt",
        ));
    }
    let canonical = subject.canonical_bytes().map_err(encode_error)?;
    let expected_nonce = deterministic_nonce_hex(&rfc3161.policy_oid, &canonical);
    if rfc3161.nonce_hex != expected_nonce {
        return Err(subject_mismatch(
            "timestamp nonce was not derived from the receipt",
        ));
    }

    let anchors = Rfc3161TrustAnchors::new(
        tsa.signer_spki_der_hex.clone(),
        tsa.issuing_ca_spki_der_hex.clone(),
    )
    .map_err(|error| VerifyError::MalformedBundle {
        reason: format!("TSA trust anchors: {error}"),
    })?;
    let token = BASE64_STANDARD
        .decode(rfc3161.token_der_base64.trim())
        .map_err(|error| VerifyError::TimestampInvalid {
            reason: format!("token is not base64: {error}"),
        })?;
    let verified = verify_timestamp_token_with_trust_anchors(
        &token,
        subject_hash,
        imprint,
        &expected_nonce,
        &rfc3161.policy_oid,
        &anchors,
    )
    .map_err(|error| VerifyError::TimestampInvalid {
        reason: error.to_string(),
    })?;
    if verified.issued_at != proof.issued_at || verified.issued_at != receipt.created_at {
        return Err(subject_mismatch(
            "receipt time does not equal the timestamp authority time",
        ));
    }
    Ok(verified.issued_at)
}
