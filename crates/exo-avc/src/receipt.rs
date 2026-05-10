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

use exo_core::{Did, Hash256, Signature, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    credential::AVC_SCHEMA_VERSION,
    error::AvcError,
    validation::{AvcDecision, AvcReasonCode, AvcValidationResult},
};

/// Domain tag for AVC trust receipts.
pub const AVC_RECEIPT_SIGNING_DOMAIN: &str = "exo.avc.receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcTrustReceipt {
    pub schema_version: u16,
    pub receipt_id: Hash256,
    pub credential_id: Hash256,
    pub action_id: Option<Hash256>,
    pub validator_did: Did,
    pub decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub created_at: Timestamp,
    pub validation_hash: Hash256,
    pub signature: Signature,
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

impl AvcTrustReceipt {
    /// Compute the canonical signing payload bytes for this receipt.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
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
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)?;
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
    let validation_hash = hash_structured(validation).map_err(AvcError::from)?;

    // Build the receipt with an empty signature first so we can compute
    // its content-addressed ID over the canonical signing payload.
    let mut receipt = AvcTrustReceipt {
        schema_version: AVC_SCHEMA_VERSION,
        receipt_id: Hash256::ZERO,
        credential_id: validation.credential_id,
        action_id,
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
        validation::{AvcDecision, AvcReasonCode, AvcValidationRequest, validate_avc},
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
}
