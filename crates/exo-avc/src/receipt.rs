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

//! AVC trust receipts.
//!
//! A trust receipt records a validation decision (or executed action)
//! and is signed by the validator. Receipts are deterministic and
//! domain-tagged so they cannot be confused with credentials or
//! revocations on the wire.

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto, hash::hash_structured};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    credential::AVC_SCHEMA_VERSION,
    error::AvcError,
    validation::{
        AvcActionDescriptor, AvcDecision, AvcReasonCode, AvcValidationResult,
        avc_action_descriptor_hash,
    },
};

/// Domain tag for AVC trust receipts.
pub const AVC_RECEIPT_SIGNING_DOMAIN: &str = "exo.avc.receipt.v1";
/// Domain tag for externally signed AVC receipt timestamp proofs.
pub const AVC_RECEIPT_EXTERNAL_TIMESTAMP_DOMAIN: &str = "exo.avc.receipt.external_timestamp.v1";
/// Domain tag for the receipt evidence subject sent to external timestamp
/// authorities.
pub const AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN: &str = "exo.avc.receipt.evidence_subject.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcTrustReceipt {
    pub schema_version: u16,
    pub receipt_id: Hash256,
    pub credential_id: Hash256,
    pub action_id: Option<Hash256>,
    #[serde(default)]
    pub action_commitment_hash: Option<Hash256>,
    #[serde(default)]
    pub action_descriptor: Option<AvcActionDescriptor>,
    #[serde(default)]
    pub action_descriptor_hash: Option<Hash256>,
    #[serde(default)]
    pub previous_receipt_hash: Option<Hash256>,
    #[serde(default)]
    pub timestamp_provenance: Option<AvcReceiptTimestampProvenance>,
    #[serde(default)]
    pub external_timestamp_proof: Option<AvcReceiptExternalTimestampProof>,
    pub validator_did: Did,
    pub decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub created_at: Timestamp,
    pub validation_hash: Hash256,
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcReceiptTimestampProvenance {
    PostgresClockTimestamp,
    LocalHybridLogicalClock,
    FixedTestTimestamp,
    ExternalTimestampAuthority,
}

/// Optional local evidence included in extended trust receipt payloads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvcTrustReceiptEvidence {
    /// Hash committing to the credential action being receipted.
    pub action_commitment_hash: Option<Hash256>,
    /// Minimal canonical action meaning embedded for audit reconstruction.
    pub action_descriptor: Option<AvcActionDescriptor>,
    /// Previous receipt hash used to link extended receipts in order.
    pub previous_receipt_hash: Option<Hash256>,
    /// Source of the trusted timestamp used for this receipt.
    pub timestamp_provenance: Option<AvcReceiptTimestampProvenance>,
    /// Externally signed timestamp proof over the receipt evidence subject.
    pub external_timestamp_proof: Option<AvcReceiptExternalTimestampProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvcReceiptEvidenceSubject {
    pub credential_id: Hash256,
    pub action_id: Hash256,
    pub action_commitment_hash: Hash256,
    pub action_descriptor_hash: Hash256,
    pub previous_receipt_hash: Option<Hash256>,
}

#[derive(Serialize)]
struct AvcReceiptEvidenceSubjectPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    action_id: &'a Hash256,
    action_commitment_hash: &'a Hash256,
    action_descriptor_hash: &'a Hash256,
    previous_receipt_hash: Option<&'a Hash256>,
}

impl AvcReceiptEvidenceSubject {
    /// Return the exact canonical byte payload committed by the EXOCHAIN
    /// subject hash and sent to RFC 3161 timestamp authorities as the
    /// SHA-256 message-imprint preimage.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AvcError> {
        let payload = AvcReceiptEvidenceSubjectPayload {
            domain: AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN,
            schema_version: AVC_SCHEMA_VERSION,
            credential_id: &self.credential_id,
            action_id: &self.action_id,
            action_commitment_hash: &self.action_commitment_hash,
            action_descriptor_hash: &self.action_descriptor_hash,
            previous_receipt_hash: self.previous_receipt_hash.as_ref(),
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes)?;
        Ok(bytes)
    }

    /// Hash the exact receipt evidence subject that an external timestamp
    /// authority signs. This subject intentionally excludes the node signature
    /// and final receipt hash to avoid circular evidence.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn hash(&self) -> Result<Hash256, AvcError> {
        Ok(Hash256::digest(&self.canonical_bytes()?))
    }

    /// Compute the RFC 3161 SHA-256 `MessageImprint.hashedMessage` for the
    /// same canonical evidence-subject bytes committed by [`Self::hash`].
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn rfc3161_sha256_message_imprint(&self) -> Result<[u8; 32], AvcError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut imprint = [0u8; 32];
        imprint.copy_from_slice(&digest);
        Ok(imprint)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcReceiptExternalTimestampProofKind {
    #[default]
    JsonEd25519,
    Rfc3161,
}

impl AvcReceiptExternalTimestampProofKind {
    const fn is_json_ed25519(&self) -> bool {
        matches!(self, Self::JsonEd25519)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcReceiptRfc3161TimestampProof {
    pub message_imprint_sha256_hex: String,
    pub token_der_base64: String,
    pub policy_oid: String,
    pub serial_number_hex: String,
    pub nonce_hex: String,
    pub tsa_subject: String,
    pub tsa_public_key_spki_der_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcReceiptExternalTimestampProof {
    pub authority_did: Did,
    pub subject_hash: Hash256,
    pub issued_at: Timestamp,
    pub signature: Signature,
    #[serde(
        default,
        skip_serializing_if = "AvcReceiptExternalTimestampProofKind::is_json_ed25519"
    )]
    pub proof_kind: AvcReceiptExternalTimestampProofKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc3161: Option<AvcReceiptRfc3161TimestampProof>,
}

#[derive(Serialize)]
struct AvcReceiptExternalTimestampSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    authority_did: &'a Did,
    subject_hash: &'a Hash256,
    issued_at: &'a Timestamp,
}

impl AvcReceiptExternalTimestampProof {
    #[must_use]
    pub fn unsigned(authority_did: Did, subject_hash: Hash256, issued_at: Timestamp) -> Self {
        Self {
            authority_did,
            subject_hash,
            issued_at,
            signature: Signature::empty(),
            proof_kind: AvcReceiptExternalTimestampProofKind::JsonEd25519,
            rfc3161: None,
        }
    }

    #[must_use]
    pub fn rfc3161(
        authority_did: Did,
        subject_hash: Hash256,
        issued_at: Timestamp,
        rfc3161: AvcReceiptRfc3161TimestampProof,
    ) -> Self {
        Self {
            authority_did,
            subject_hash,
            issued_at,
            signature: Signature::empty(),
            proof_kind: AvcReceiptExternalTimestampProofKind::Rfc3161,
            rfc3161: Some(rfc3161),
        }
    }

    /// Build and sign an external timestamp proof.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signed<F>(
        authority_did: Did,
        subject_hash: Hash256,
        issued_at: Timestamp,
        sign: F,
    ) -> Result<Self, AvcError>
    where
        F: FnOnce(&[u8]) -> Signature,
    {
        let mut proof = Self::unsigned(authority_did, subject_hash, issued_at);
        let payload = proof.signing_payload()?;
        proof.signature = sign(&payload);
        Ok(proof)
    }

    /// Return the canonical payload signed by the external timestamp
    /// authority.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let payload = AvcReceiptExternalTimestampSigningPayload {
            domain: AVC_RECEIPT_EXTERNAL_TIMESTAMP_DOMAIN,
            schema_version: AVC_SCHEMA_VERSION,
            authority_did: &self.authority_did,
            subject_hash: &self.subject_hash,
            issued_at: &self.issued_at,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes)?;
        Ok(bytes)
    }

    /// Verify the external timestamp authority signature.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<bool, AvcError> {
        if self.proof_kind != AvcReceiptExternalTimestampProofKind::JsonEd25519 {
            return Ok(false);
        }
        if self.signature.is_empty() {
            return Ok(false);
        }
        Ok(crypto::verify(
            &self.signing_payload()?,
            &self.signature,
            public_key,
        ))
    }
}

#[derive(Serialize)]
struct ReceiptSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    action_id: Option<&'a Hash256>,
    validator_did: &'a Did,
    decision: &'a AvcDecision,
    reason_codes: &'a [AvcReasonCode],
    created_at: &'a Timestamp,
    validation_hash: &'a Hash256,
}

#[derive(Serialize)]
struct ExtendedReceiptSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    action_id: Option<&'a Hash256>,
    action_commitment_hash: Option<&'a Hash256>,
    action_descriptor: Option<&'a AvcActionDescriptor>,
    action_descriptor_hash: Option<&'a Hash256>,
    previous_receipt_hash: Option<&'a Hash256>,
    timestamp_provenance: Option<&'a AvcReceiptTimestampProvenance>,
    external_timestamp_proof: Option<&'a AvcReceiptExternalTimestampProof>,
    validator_did: &'a Did,
    decision: &'a AvcDecision,
    reason_codes: &'a [AvcReasonCode],
    created_at: &'a Timestamp,
    validation_hash: &'a Hash256,
}

impl AvcTrustReceipt {
    #[must_use]
    pub fn has_extended_evidence(&self) -> bool {
        self.action_commitment_hash.is_some()
            || self.action_descriptor.is_some()
            || self.action_descriptor_hash.is_some()
            || self.previous_receipt_hash.is_some()
            || self.timestamp_provenance.is_some()
            || self.external_timestamp_proof.is_some()
    }

    /// Compute the canonical signing payload bytes for this receipt.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let mut buf = Vec::new();
        if self.has_extended_evidence() {
            let payload = ExtendedReceiptSigningPayload {
                domain: AVC_RECEIPT_SIGNING_DOMAIN,
                schema_version: self.schema_version,
                credential_id: &self.credential_id,
                action_id: self.action_id.as_ref(),
                action_commitment_hash: self.action_commitment_hash.as_ref(),
                action_descriptor: self.action_descriptor.as_ref(),
                action_descriptor_hash: self.action_descriptor_hash.as_ref(),
                previous_receipt_hash: self.previous_receipt_hash.as_ref(),
                timestamp_provenance: self.timestamp_provenance.as_ref(),
                external_timestamp_proof: self.external_timestamp_proof.as_ref(),
                validator_did: &self.validator_did,
                decision: &self.decision,
                reason_codes: &self.reason_codes,
                created_at: &self.created_at,
                validation_hash: &self.validation_hash,
            };
            ciborium::ser::into_writer(&payload, &mut buf)?;
        } else {
            let payload = ReceiptSigningPayload {
                domain: AVC_RECEIPT_SIGNING_DOMAIN,
                schema_version: self.schema_version,
                credential_id: &self.credential_id,
                action_id: self.action_id.as_ref(),
                validator_did: &self.validator_did,
                decision: &self.decision,
                reason_codes: &self.reason_codes,
                created_at: &self.created_at,
                validation_hash: &self.validation_hash,
            };
            ciborium::ser::into_writer(&payload, &mut buf)?;
        }
        Ok(buf)
    }

    /// Recompute the receipt's content-addressed hash from its signed
    /// fields. Used to detect tampering.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn recompute_id(&self) -> Result<Hash256, AvcError> {
        Ok(Hash256::digest(&self.signing_payload()?))
    }

    /// Returns true when `receipt_id` matches the canonical hash of the
    /// signed fields.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn verify_id(&self) -> Result<bool, AvcError> {
        Ok(self.recompute_id()? == self.receipt_id)
    }
}

/// Build and sign a trust receipt for the given validation result.
///
/// The receipt's `validation_hash` is a canonical hash over the
/// `AvcValidationResult` so auditors can later prove which decision
/// produced this receipt.
///
/// # Errors
/// Returns [`AvcError::Serialization`] when CBOR encoding fails.
pub fn create_trust_receipt<F>(
    validation: &AvcValidationResult,
    action_id: Option<Hash256>,
    validator_did: Did,
    now: Timestamp,
    sign: F,
) -> Result<AvcTrustReceipt, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    create_trust_receipt_with_evidence(
        validation,
        action_id,
        AvcTrustReceiptEvidence::default(),
        validator_did,
        now,
        sign,
    )
}

/// Build and sign a trust receipt with local evidence fields.
///
/// When all evidence fields are absent, this preserves the legacy v1
/// signing payload exactly. When any evidence field is present, all
/// evidence fields are included in the signed payload and receipt ID.
///
/// # Errors
/// Returns [`AvcError::Serialization`] when CBOR encoding fails.
pub fn create_trust_receipt_with_evidence<F>(
    validation: &AvcValidationResult,
    action_id: Option<Hash256>,
    evidence: AvcTrustReceiptEvidence,
    validator_did: Did,
    now: Timestamp,
    sign: F,
) -> Result<AvcTrustReceipt, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    let validation_hash = hash_structured(validation).map_err(AvcError::from)?;
    let action_descriptor_hash = evidence
        .action_descriptor
        .as_ref()
        .map(avc_action_descriptor_hash)
        .transpose()?;

    // Build the receipt with an empty signature first so we can compute
    // its content-addressed ID over the canonical signing payload.
    let mut receipt = AvcTrustReceipt {
        schema_version: AVC_SCHEMA_VERSION,
        receipt_id: Hash256::ZERO,
        credential_id: validation.credential_id,
        action_id,
        action_commitment_hash: evidence.action_commitment_hash,
        action_descriptor: evidence.action_descriptor,
        action_descriptor_hash,
        previous_receipt_hash: evidence.previous_receipt_hash,
        timestamp_provenance: evidence.timestamp_provenance,
        external_timestamp_proof: evidence.external_timestamp_proof,
        validator_did,
        decision: validation.decision,
        reason_codes: validation.reason_codes.clone(),
        created_at: now,
        validation_hash,
        signature: Signature::empty(),
    };

    let payload = receipt.signing_payload()?;
    receipt.receipt_id = Hash256::digest(&payload);
    receipt.signature = sign(&payload);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use exo_core::crypto::KeyPair;

    use super::*;
    use crate::{
        credential::{
            issue_avc,
            test_support::{baseline_draft, did, ts},
        },
        registry::AvcRegistryWrite,
        validation::{
            AvcActionDescriptor, AvcActionRequest, AvcDecision, AvcReasonCode,
            AvcValidationRequest, avc_action_descriptor_hash, validate_avc,
        },
    };

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    fn fresh_issuer() -> KeyPair {
        KeyPair::from_secret_bytes([0x11; 32]).expect("valid seed")
    }

    fn sample_validation() -> (AvcValidationResult, Hash256) {
        // Build a registry with a known issuer key, issue a credential,
        // and validate it so we have a real validation result.
        let issuer_kp = fresh_issuer();
        let mut registry = crate::registry::InMemoryAvcRegistry::new();
        registry.put_public_key(did("issuer"), issuer_kp.public);
        let cred = issue_avc(baseline_draft(), |bytes| issuer_kp.sign(bytes)).unwrap();
        let id = cred.id().unwrap();
        let request = AvcValidationRequest {
            credential: cred,
            action: None,
            now: ts(1_500_000),
        };
        let result = validate_avc(&request, &registry).unwrap();
        (result, id)
    }

    fn sample_action_descriptor() -> AvcActionDescriptor {
        let action = AvcActionRequest {
            action_id: Hash256::from_bytes([0x42; 32]),
            actor_did: did("agent"),
            requested_permission: exo_authority::permission::Permission::Read,
            tool: Some("records.search".into()),
            target_did: Some(did("target")),
            data_class: None,
            estimated_budget_minor_units: Some(125),
            estimated_risk_bp: Some(25),
            human_approval: None,
            requires_human_approval: false,
            action_name: Some("records.search.case".into()),
        };
        AvcActionDescriptor::from_action(&action)
    }

    fn external_timestamp_proof(subject_hash: Hash256) -> AvcReceiptExternalTimestampProof {
        let authority = fresh_issuer();
        AvcReceiptExternalTimestampProof::signed(
            did("timestamp-authority"),
            subject_hash,
            ts(2_500),
            |bytes| authority.sign(bytes),
        )
        .unwrap()
    }

    #[test]
    fn evidence_subject_canonical_bytes_drive_stable_exochain_and_rfc3161_imprints() {
        let subject = AvcReceiptEvidenceSubject {
            credential_id: Hash256::from_bytes([0x01; 32]),
            action_id: Hash256::from_bytes([0x02; 32]),
            action_commitment_hash: Hash256::from_bytes([0x03; 32]),
            action_descriptor_hash: Hash256::from_bytes([0x04; 32]),
            previous_receipt_hash: Some(Hash256::from_bytes([0x05; 32])),
        };
        let same_subject = subject;
        let mut changed_subject = subject;
        changed_subject.previous_receipt_hash = Some(Hash256::from_bytes([0x06; 32]));

        let canonical = subject.canonical_bytes().unwrap();
        assert_eq!(canonical, same_subject.canonical_bytes().unwrap());
        assert_eq!(subject.hash().unwrap(), Hash256::digest(&canonical));
        assert_eq!(
            subject.rfc3161_sha256_message_imprint().unwrap(),
            same_subject.rfc3161_sha256_message_imprint().unwrap()
        );
        assert_ne!(
            subject.rfc3161_sha256_message_imprint().unwrap(),
            changed_subject.rfc3161_sha256_message_imprint().unwrap()
        );
        assert_ne!(
            subject.hash().unwrap(),
            changed_subject.hash().unwrap(),
            "EXOCHAIN BLAKE3 subject commitment must also stay bound to the canonical evidence subject"
        );
    }

    #[test]
    fn legacy_ed25519_and_rfc3161_timestamp_proofs_round_trip_without_shape_loss() {
        let subject_hash = Hash256::from_bytes([0xA7; 32]);
        let legacy = external_timestamp_proof(subject_hash);
        let mut legacy_bytes = Vec::new();
        ciborium::ser::into_writer(&legacy, &mut legacy_bytes).unwrap();
        let decoded_legacy: AvcReceiptExternalTimestampProof =
            ciborium::de::from_reader(legacy_bytes.as_slice()).unwrap();

        assert_eq!(
            decoded_legacy.proof_kind,
            AvcReceiptExternalTimestampProofKind::JsonEd25519
        );
        assert_eq!(decoded_legacy.rfc3161, None);
        assert!(
            decoded_legacy
                .verify_signature(&fresh_issuer().public)
                .unwrap()
        );

        let rfc3161 = AvcReceiptExternalTimestampProof::rfc3161(
            did("microsoft-public-rsa-tsa"),
            subject_hash,
            ts(4_200),
            AvcReceiptRfc3161TimestampProof {
                message_imprint_sha256_hex: "3f786850e387550fdab836ed7e6dc881de23001b".to_owned()
                    + "4b96a0c7bb5f37c2fdc7c7ab",
                token_der_base64: "MIIBywYJKoZIhvcNAQcCoIIBvDCCAbgCAQMxDzANBglghkgBZQMEAgEFADCB"
                    .to_owned(),
                policy_oid: "1.3.6.1.4.1.601.10.3.1".to_owned(),
                serial_number_hex: "01".to_owned(),
                nonce_hex: "0102030405060708090a0b0c0d0e0f10".to_owned(),
                tsa_subject:
                    "CN=Microsoft Public RSA Time Stamping Authority,O=Microsoft Corporation,C=US"
                        .to_owned(),
                tsa_public_key_spki_der_hex: "30820122300d06092a864886f70d01010105000382010f"
                    .to_owned(),
            },
        );
        let mut rfc3161_bytes = Vec::new();
        ciborium::ser::into_writer(&rfc3161, &mut rfc3161_bytes).unwrap();
        let decoded_rfc3161: AvcReceiptExternalTimestampProof =
            ciborium::de::from_reader(rfc3161_bytes.as_slice()).unwrap();

        assert_eq!(
            decoded_rfc3161.proof_kind,
            AvcReceiptExternalTimestampProofKind::Rfc3161
        );
        assert!(decoded_rfc3161.signature.is_empty());
        assert_eq!(decoded_rfc3161.rfc3161, rfc3161.rfc3161);
        assert!(
            !decoded_rfc3161
                .verify_signature(&fresh_issuer().public)
                .unwrap()
        );
    }

    #[test]
    fn create_trust_receipt_produces_signed_record() {
        let (validation, id) = sample_validation();
        let receipt = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        assert_eq!(receipt.credential_id, id);
        assert_eq!(receipt.signature, fixed_signature());
        assert_eq!(receipt.decision, AvcDecision::Allow);
        assert_eq!(receipt.reason_codes, vec![AvcReasonCode::Valid]);
        assert_ne!(receipt.receipt_id, Hash256::ZERO);
    }

    #[test]
    fn receipt_id_is_deterministic_for_same_inputs() {
        let (validation, _id) = sample_validation();
        let r1 = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        let r2 = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn receipt_id_changes_when_validator_changes() {
        let (validation, _id) = sample_validation();
        let r1 = create_trust_receipt(&validation, None, did("alice"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        let r2 = create_trust_receipt(&validation, None, did("bob"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        assert_ne!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn signing_payload_contains_domain_tag() {
        let (validation, _id) = sample_validation();
        let receipt = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        let payload = receipt.signing_payload().unwrap();
        let needle = AVC_RECEIPT_SIGNING_DOMAIN.as_bytes();
        assert!(payload.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn verify_id_returns_true_for_unmodified_receipt() {
        let (validation, _id) = sample_validation();
        let receipt = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        assert!(receipt.verify_id().unwrap());
    }

    #[test]
    fn verify_id_returns_false_when_field_tampered() {
        let (validation, _id) = sample_validation();
        let mut receipt =
            create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
                fixed_signature()
            })
            .unwrap();
        receipt.created_at = ts(9_999_999);
        assert!(!receipt.verify_id().unwrap());
    }

    #[test]
    fn receipt_includes_action_id_when_provided() {
        let (validation, _id) = sample_validation();
        let action_id = Hash256::from_bytes([0x42; 32]);
        let r1 = create_trust_receipt(
            &validation,
            Some(action_id),
            did("validator"),
            ts(2_000),
            |_| fixed_signature(),
        )
        .unwrap();
        assert_eq!(r1.action_id, Some(action_id));
    }

    #[test]
    fn legacy_receipt_payload_stays_v1_when_evidence_absent() {
        let (validation, _id) = sample_validation();
        let receipt = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        assert!(!receipt.has_extended_evidence());

        let legacy_payload = ReceiptSigningPayload {
            domain: AVC_RECEIPT_SIGNING_DOMAIN,
            schema_version: receipt.schema_version,
            credential_id: &receipt.credential_id,
            action_id: receipt.action_id.as_ref(),
            validator_did: &receipt.validator_did,
            decision: &receipt.decision,
            reason_codes: &receipt.reason_codes,
            created_at: &receipt.created_at,
            validation_hash: &receipt.validation_hash,
        };
        let mut expected = Vec::new();
        ciborium::ser::into_writer(&legacy_payload, &mut expected).unwrap();

        assert_eq!(receipt.signing_payload().unwrap(), expected);
        assert!(receipt.verify_id().unwrap());
    }

    #[test]
    fn legacy_receipt_deserializes_with_absent_evidence_fields() {
        #[derive(Serialize)]
        struct LegacyReceiptWire<'a> {
            schema_version: u16,
            receipt_id: &'a Hash256,
            credential_id: &'a Hash256,
            action_id: Option<&'a Hash256>,
            validator_did: &'a Did,
            decision: &'a AvcDecision,
            reason_codes: &'a [AvcReasonCode],
            created_at: &'a Timestamp,
            validation_hash: &'a Hash256,
            signature: &'a Signature,
        }

        let (validation, _id) = sample_validation();
        let receipt = create_trust_receipt(&validation, None, did("validator"), ts(2_000), |_| {
            fixed_signature()
        })
        .unwrap();
        let legacy_wire = LegacyReceiptWire {
            schema_version: receipt.schema_version,
            receipt_id: &receipt.receipt_id,
            credential_id: &receipt.credential_id,
            action_id: receipt.action_id.as_ref(),
            validator_did: &receipt.validator_did,
            decision: &receipt.decision,
            reason_codes: &receipt.reason_codes,
            created_at: &receipt.created_at,
            validation_hash: &receipt.validation_hash,
            signature: &receipt.signature,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&legacy_wire, &mut bytes).unwrap();

        let decoded: AvcTrustReceipt = ciborium::de::from_reader(bytes.as_slice()).unwrap();

        assert_eq!(decoded.action_commitment_hash, None);
        assert_eq!(decoded.previous_receipt_hash, None);
        assert_eq!(decoded.timestamp_provenance, None);
        assert_eq!(
            decoded.signing_payload().unwrap(),
            receipt.signing_payload().unwrap()
        );
        assert!(decoded.verify_id().unwrap());
    }

    #[test]
    fn extended_evidence_changes_signed_receipt_payload_and_id() {
        let (validation, _id) = sample_validation();
        let action_id = Hash256::from_bytes([0x42; 32]);
        let legacy = create_trust_receipt(
            &validation,
            Some(action_id),
            did("validator"),
            ts(2_000),
            |_| fixed_signature(),
        )
        .unwrap();
        let extended = create_trust_receipt_with_evidence(
            &validation,
            Some(action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(Hash256::from_bytes([0xA1; 32])),
                action_descriptor: None,
                previous_receipt_hash: None,
                timestamp_provenance: Some(AvcReceiptTimestampProvenance::LocalHybridLogicalClock),
                external_timestamp_proof: None,
            },
            did("validator"),
            ts(2_000),
            |_| fixed_signature(),
        )
        .unwrap();

        assert!(extended.has_extended_evidence());
        assert_ne!(
            legacy.signing_payload().unwrap(),
            extended.signing_payload().unwrap()
        );
        assert_ne!(legacy.receipt_id, extended.receipt_id);
        assert!(extended.verify_id().unwrap());
    }

    #[test]
    fn extended_receipt_embeds_signed_action_descriptor_and_external_timestamp_proof() {
        let (validation, _id) = sample_validation();
        let action_descriptor = sample_action_descriptor();
        let action_descriptor_hash = avc_action_descriptor_hash(&action_descriptor).unwrap();
        let evidence_subject = AvcReceiptEvidenceSubject {
            credential_id: validation.credential_id,
            action_id: action_descriptor.action_id,
            action_commitment_hash: Hash256::from_bytes([0xA1; 32]),
            action_descriptor_hash,
            previous_receipt_hash: None,
        };
        let subject_hash = evidence_subject.hash().unwrap();
        let external_timestamp_proof = external_timestamp_proof(subject_hash);
        assert!(
            external_timestamp_proof
                .verify_signature(&fresh_issuer().public)
                .unwrap()
        );

        let receipt = create_trust_receipt_with_evidence(
            &validation,
            Some(action_descriptor.action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(evidence_subject.action_commitment_hash),
                action_descriptor: Some(action_descriptor.clone()),
                previous_receipt_hash: None,
                timestamp_provenance: Some(
                    AvcReceiptTimestampProvenance::ExternalTimestampAuthority,
                ),
                external_timestamp_proof: Some(external_timestamp_proof.clone()),
            },
            did("validator"),
            external_timestamp_proof.issued_at,
            |_| fixed_signature(),
        )
        .unwrap();

        assert_eq!(receipt.action_descriptor, Some(action_descriptor));
        assert_eq!(receipt.action_descriptor_hash, Some(action_descriptor_hash));
        assert_eq!(
            receipt.timestamp_provenance,
            Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority)
        );
        assert_eq!(
            receipt.external_timestamp_proof,
            Some(external_timestamp_proof)
        );
        assert!(receipt.has_extended_evidence());
        assert!(receipt.verify_id().unwrap());
    }

    #[test]
    fn changing_embedded_action_descriptor_changes_receipt_identity() {
        let (validation, _id) = sample_validation();
        let mut action_descriptor = sample_action_descriptor();
        let baseline = create_trust_receipt_with_evidence(
            &validation,
            Some(action_descriptor.action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(Hash256::from_bytes([0xA1; 32])),
                action_descriptor: Some(action_descriptor.clone()),
                previous_receipt_hash: None,
                timestamp_provenance: Some(
                    AvcReceiptTimestampProvenance::ExternalTimestampAuthority,
                ),
                external_timestamp_proof: None,
            },
            did("validator"),
            ts(2_500),
            |_| fixed_signature(),
        )
        .unwrap();

        action_descriptor.action_name = Some("records.search.changed".into());
        let changed = create_trust_receipt_with_evidence(
            &validation,
            Some(action_descriptor.action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(Hash256::from_bytes([0xA1; 32])),
                action_descriptor: Some(action_descriptor),
                previous_receipt_hash: None,
                timestamp_provenance: Some(
                    AvcReceiptTimestampProvenance::ExternalTimestampAuthority,
                ),
                external_timestamp_proof: None,
            },
            did("validator"),
            ts(2_500),
            |_| fixed_signature(),
        )
        .unwrap();

        assert_ne!(baseline.receipt_id, changed.receipt_id);
    }
}
