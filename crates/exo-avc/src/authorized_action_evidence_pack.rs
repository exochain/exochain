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

//! Authorized Action Evidence Pack (SKU A).
//!
//! Productizes one exportable artifact from an Allow receipt: AVC decision,
//! action commitments, LYNK evidence hash, optional RFC 3161 proof, and the
//! previous-receipt link. Validation stays free; this pack is the paid SKU.

use exo_core::{Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    error::AvcError,
    receipt::{AvcReceiptRfc3161TimestampProof, AvcTrustReceipt},
    validation::{AvcDecision, AvcReasonCode},
};

/// Wire schema id for the assembled pack.
pub const AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA: &str = "authorized_action_evidence_pack.v1";
/// Domain tag for the canonical pack hash.
pub const AUTHORIZED_ACTION_EVIDENCE_PACK_DOMAIN: &str =
    "exo.avc.authorized_action_evidence_pack.v1";
const AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA_VERSION: u16 = 1;

/// Caller-supplied assembly input. Timestamps come from the surrounding HLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembleAuthorizedActionEvidencePackInput {
    pub receipt: AvcTrustReceipt,
    pub commercially_gated: bool,
    pub created_at: Timestamp,
}

/// Hosted-node evidence pack sold as SKU A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedActionEvidencePack {
    pub schema: String,
    pub receipt_id: Hash256,
    pub credential_id: Hash256,
    pub decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub action_commitment_hash: Option<Hash256>,
    pub action_descriptor_hash: Option<Hash256>,
    pub llm_usage_evidence_hash: Option<Hash256>,
    pub payment_evidence_hash: Option<Hash256>,
    pub previous_receipt_hash: Option<Hash256>,
    pub rfc3161_proof: Option<AvcReceiptRfc3161TimestampProof>,
    pub validation_hash: Hash256,
    pub created_at: Timestamp,
    pub pack_hash: Hash256,
}

#[derive(Serialize)]
struct AuthorizedActionEvidencePackHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    schema: &'a str,
    receipt_id: &'a Hash256,
    credential_id: &'a Hash256,
    decision: &'a AvcDecision,
    reason_codes: &'a [AvcReasonCode],
    action_commitment_hash: Option<&'a Hash256>,
    action_descriptor_hash: Option<&'a Hash256>,
    llm_usage_evidence_hash: Option<&'a Hash256>,
    payment_evidence_hash: Option<&'a Hash256>,
    previous_receipt_hash: Option<&'a Hash256>,
    rfc3161_proof: Option<&'a AvcReceiptRfc3161TimestampProof>,
    validation_hash: &'a Hash256,
    created_at: &'a Timestamp,
}

/// Assemble an evidence pack from an Allow receipt.
///
/// # Errors
/// Returns [`AvcError::InvalidInput`] when the receipt is not `Allow`, when a
/// commercially gated receipt lacks bound payment evidence, or when required
/// identifiers are zero. Returns [`AvcError::Serialization`] if CBOR hashing
/// fails.
pub fn assemble_authorized_action_evidence_pack(
    input: &AssembleAuthorizedActionEvidencePackInput,
) -> Result<AuthorizedActionEvidencePack, AvcError> {
    let receipt = &input.receipt;
    if receipt.decision != AvcDecision::Allow {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "authorized action evidence pack requires decision Allow, got {:?}",
                receipt.decision
            ),
        });
    }
    if receipt.receipt_id == Hash256::ZERO {
        return Err(AvcError::InvalidInput {
            reason: "authorized action evidence pack requires a non-zero receipt_id".into(),
        });
    }
    if input.created_at == Timestamp::ZERO {
        return Err(AvcError::InvalidTimestamp {
            reason: "authorized action evidence pack created_at must be a caller-supplied HLC timestamp"
                .into(),
        });
    }
    let payment_evidence_hash = receipt
        .payment_evidence_hash
        .filter(|hash| *hash != Hash256::ZERO);
    if input.commercially_gated && payment_evidence_hash.is_none() {
        return Err(AvcError::InvalidInput {
            reason: "commercially gated evidence pack requires bound payment_evidence_hash".into(),
        });
    }
    let rfc3161_proof = receipt
        .external_timestamp_proof
        .as_ref()
        .and_then(|proof| proof.rfc3161.clone());

    let mut pack = AuthorizedActionEvidencePack {
        schema: AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA.into(),
        receipt_id: receipt.receipt_id,
        credential_id: receipt.credential_id,
        decision: receipt.decision,
        reason_codes: receipt.reason_codes.clone(),
        action_commitment_hash: receipt.action_commitment_hash,
        action_descriptor_hash: receipt.action_descriptor_hash,
        llm_usage_evidence_hash: receipt.llm_usage_evidence_hash,
        payment_evidence_hash,
        previous_receipt_hash: receipt.previous_receipt_hash,
        rfc3161_proof,
        validation_hash: receipt.validation_hash,
        created_at: input.created_at,
        pack_hash: Hash256::ZERO,
    };
    pack.pack_hash = hash_authorized_action_evidence_pack(&pack)?;
    Ok(pack)
}

fn hash_authorized_action_evidence_pack(
    pack: &AuthorizedActionEvidencePack,
) -> Result<Hash256, AvcError> {
    let payload = AuthorizedActionEvidencePackHashPayload {
        domain: AUTHORIZED_ACTION_EVIDENCE_PACK_DOMAIN,
        schema_version: AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA_VERSION,
        schema: &pack.schema,
        receipt_id: &pack.receipt_id,
        credential_id: &pack.credential_id,
        decision: &pack.decision,
        reason_codes: &pack.reason_codes,
        action_commitment_hash: pack.action_commitment_hash.as_ref(),
        action_descriptor_hash: pack.action_descriptor_hash.as_ref(),
        llm_usage_evidence_hash: pack.llm_usage_evidence_hash.as_ref(),
        payment_evidence_hash: pack.payment_evidence_hash.as_ref(),
        previous_receipt_hash: pack.previous_receipt_hash.as_ref(),
        rfc3161_proof: pack.rfc3161_proof.as_ref(),
        validation_hash: &pack.validation_hash,
        created_at: &pack.created_at,
    };
    hash_structured(&payload).map_err(AvcError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AVC_SCHEMA_VERSION, AvcConstraints, AvcDraft, AvcSubjectKind, AvcTrustReceiptEvidence,
        AvcValidationRequest, AutonomyLevel, AuthorityScope, DelegatedIntent, InMemoryAvcRegistry,
        create_trust_receipt_with_evidence, issue_avc, validate_avc,
    };
    use crate::receipt::{
        AvcReceiptExternalTimestampProof, AvcReceiptRfc3161TrustAnchorKind,
    };
    use exo_authority::permission::Permission;
    use exo_core::{Did, Signature, crypto::KeyPair};

    fn did(suffix: &str) -> Did {
        Did::new(&format!("did:exo:{suffix}")).unwrap()
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn issuer_kp() -> KeyPair {
        KeyPair::from_secret_bytes([0x11; 32]).unwrap()
    }

    fn allow_receipt(payment: Option<Hash256>) -> AvcTrustReceipt {
        let issuer = issuer_kp();
        let mut registry = InMemoryAvcRegistry::new();
        registry.put_public_key(did("issuer"), issuer.public);
        let draft = AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: did("issuer"),
            principal_did: did("issuer"),
            subject_did: did("agent"),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: None,
            },
            created_at: ts(1_000),
            expires_at: Some(ts(2_000_000)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([0xAA; 32]),
                purpose: "research".into(),
                allowed_objectives: vec!["primary".into()],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::Draft,
                delegation_allowed: false,
            },
            authority_scope: AuthorityScope {
                permissions: vec![Permission::Read],
                tools: vec![],
                data_classes: vec![],
                counterparties: vec![],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints::permissive(),
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        };
        let credential = issue_avc(draft, |bytes| issuer.sign(bytes)).unwrap();
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: ts(1_500),
        };
        let validation = validate_avc(&request, &registry).unwrap();
        create_trust_receipt_with_evidence(
            &validation,
            Some(Hash256::from_bytes([0x42; 32])),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(Hash256::from_bytes([0xA1; 32])),
                action_descriptor: None,
                llm_usage_evidence_hash: Some(Hash256::from_bytes([0xB2; 32])),
                payment_evidence_hash: payment,
                previous_receipt_hash: Some(Hash256::from_bytes([0xC3; 32])),
                timestamp_provenance: None,
                external_timestamp_proof: Some(AvcReceiptExternalTimestampProof::rfc3161(
                    did("tsa"),
                    Hash256::from_bytes([0xD4; 32]),
                    ts(1_600),
                    AvcReceiptRfc3161TimestampProof {
                        message_imprint_sha256_hex: "aa".repeat(32),
                        token_der_base64: "Zg==".into(),
                        policy_oid: "1.2.3".into(),
                        serial_number_hex: "01".into(),
                        nonce_hex: "02".into(),
                        tsa_subject: "CN=Test TSA".into(),
                        tsa_public_key_spki_der_hex: "03".into(),
                        tsa_trust_anchor_kind: Some(AvcReceiptRfc3161TrustAnchorKind::SignerSpki),
                        tsa_trust_anchor_spki_der_hex: None,
                        tsa_issuer_subject: None,
                    },
                )),
            },
            did("validator"),
            ts(1_700),
            |_| Signature::from_bytes([0x55; 64]),
        )
        .unwrap()
    }

    fn deny_receipt() -> AvcTrustReceipt {
        let mut receipt = allow_receipt(None);
        receipt.decision = AvcDecision::Deny;
        receipt
    }

    #[test]
    fn assembles_allow_pack_deterministically() {
        let receipt = allow_receipt(Some(Hash256::from_bytes([0xC1; 32])));
        let input = AssembleAuthorizedActionEvidencePackInput {
            receipt,
            commercially_gated: true,
            created_at: ts(1_800),
        };
        let left = assemble_authorized_action_evidence_pack(&input).unwrap();
        let right = assemble_authorized_action_evidence_pack(&input).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.schema, AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA);
        assert_eq!(left.decision, AvcDecision::Allow);
        assert_eq!(
            left.payment_evidence_hash,
            Some(Hash256::from_bytes([0xC1; 32]))
        );
        assert!(left.rfc3161_proof.is_some());
        assert_ne!(left.pack_hash, Hash256::ZERO);
    }

    #[test]
    fn rejects_non_allow_decision() {
        let err = assemble_authorized_action_evidence_pack(
            &AssembleAuthorizedActionEvidencePackInput {
                receipt: deny_receipt(),
                commercially_gated: false,
                created_at: ts(1_800),
            },
        )
        .unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
    }

    #[test]
    fn commercially_gated_pack_requires_bound_payment_evidence() {
        let err = assemble_authorized_action_evidence_pack(
            &AssembleAuthorizedActionEvidencePackInput {
                receipt: allow_receipt(None),
                commercially_gated: true,
                created_at: ts(1_800),
            },
        )
        .unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
        assert!(
            assemble_authorized_action_evidence_pack(&AssembleAuthorizedActionEvidencePackInput {
                receipt: allow_receipt(None),
                commercially_gated: false,
                created_at: ts(1_800),
            })
            .is_ok()
        );
    }

    #[test]
    fn zero_payment_hash_is_unpaid_for_commercially_gated_pack() {
        let err = assemble_authorized_action_evidence_pack(
            &AssembleAuthorizedActionEvidencePackInput {
                receipt: allow_receipt(Some(Hash256::ZERO)),
                commercially_gated: true,
                created_at: ts(1_800),
            },
        )
        .unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
    }

    #[test]
    fn pack_hash_changes_when_lynk_hash_changes() {
        let first = allow_receipt(Some(Hash256::from_bytes([0xC1; 32])));
        let mut second = first.clone();
        second.llm_usage_evidence_hash = Some(Hash256::from_bytes([0xEE; 32]));
        let left = assemble_authorized_action_evidence_pack(
            &AssembleAuthorizedActionEvidencePackInput {
                receipt: first,
                commercially_gated: true,
                created_at: ts(1_800),
            },
        )
        .unwrap();
        let right = assemble_authorized_action_evidence_pack(
            &AssembleAuthorizedActionEvidencePackInput {
                receipt: second,
                commercially_gated: true,
                created_at: ts(1_800),
            },
        )
        .unwrap();
        assert_ne!(left.pack_hash, right.pack_hash);
    }
}
