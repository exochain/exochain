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

//! Narrow EXOCHAIN-core proof for LiveSafe public adapter output.
//!
//! This module is intentionally scoped to the LiveSafe public trust-status
//! adapter. It never returns raw credential bytes, authority-chain internals,
//! private keys, bearer tokens, or actor-signed request material.

use exo_authority::permission::Permission;
use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    AvcRegistryRead,
    credential::{AVC_SCHEMA_VERSION, AutonomousVolitionCredential, AvcSubjectKind, DataClass},
    error::AvcError,
    livesafe_public_output_ceremony::{
        LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID,
        LivesafePublicOutputCredentialCeremonyIntentInput,
        livesafe_public_output_credential_ceremony_intent_id,
    },
    validation::{
        AvcActionRequest, AvcDecision, AvcValidationRequest, AvcValidationResult,
        avc_action_commitment_hash, validate_avc,
    },
};

/// Canonical signing domain for LiveSafe public adapter-output authorization.
pub const LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN: &str =
    "livesafe.public_adapter_output_authorization.v1";
/// The only public subject admitted by this proof surface.
pub const LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT: &str = "livesafe.ai";
/// The only public audience admitted by this proof surface.
pub const LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE: &str =
    "https://livesafe.ai/api/trust/status";
const LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ACTION_NAME: &str =
    "livesafe.public_adapter_output_authorization";

/// Redacted revocation state carried in the public proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LivesafePublicAdapterOutputAuthorizationRevocationStatus {
    /// The backing AVC was not revoked at proof mint time.
    NotRevoked,
}

/// Core minting draft. The raw AVC is consumed only for validation and
/// content-addressed IDs; it is not returned in the public envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicAdapterOutputAuthorizationDraft {
    pub credential: AutonomousVolitionCredential,
    pub subject: String,
    pub audience: String,
    pub evidence_hash: Hash256,
    pub credential_id: Option<Hash256>,
    pub receipt_id: Hash256,
    pub action_commitment_hash: Hash256,
    pub idempotency_key_hash: Hash256,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub signer_did: Did,
}

/// Redacted public proof. All authority and credential internals are replaced
/// by canonical hashes and identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicAdapterOutputAuthorizationProof {
    pub schema_version: u16,
    pub domain: String,
    pub subject: String,
    pub audience: String,
    pub evidence_hash: Hash256,
    pub credential_id: Hash256,
    pub receipt_id: Hash256,
    pub action_commitment_hash: Hash256,
    pub idempotency_key_hash: Hash256,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub revocation_status: LivesafePublicAdapterOutputAuthorizationRevocationStatus,
    pub signer_did: Did,
    pub proof_hash: Hash256,
    pub signature: Signature,
}

/// Public envelope returned by runtime adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicAdapterOutputAuthorizationEnvelope {
    pub schema_version: u16,
    pub domain: String,
    pub proof: LivesafePublicAdapterOutputAuthorizationProof,
}

#[derive(Serialize)]
struct IdempotencyHashPayload<'a> {
    domain: &'static str,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct ActionNamePayload<'a> {
    domain: &'static str,
    subject: &'a str,
    audience: &'a str,
    evidence_hash: &'a Hash256,
    idempotency_key_hash: &'a Hash256,
    expires_at: &'a Timestamp,
}

#[derive(Serialize)]
struct ProofSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    subject: &'a str,
    audience: &'a str,
    evidence_hash: &'a Hash256,
    credential_id: &'a Hash256,
    receipt_id: &'a Hash256,
    action_commitment_hash: &'a Hash256,
    idempotency_key_hash: &'a Hash256,
    issued_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    revocation_status: &'a LivesafePublicAdapterOutputAuthorizationRevocationStatus,
    signer_did: &'a Did,
}

/// Deterministically hash a caller idempotency key without exposing the raw key
/// in the public proof.
///
/// # Errors
/// Returns [`AvcError::EmptyField`] when the key is blank.
pub fn livesafe_public_adapter_output_authorization_idempotency_hash(
    idempotency_key: &str,
) -> Result<Hash256, AvcError> {
    let trimmed = idempotency_key.trim();
    if trimmed.is_empty() {
        return Err(AvcError::EmptyField {
            field: "public_output_authorization.idempotency_key",
        });
    }
    hash_structured(&IdempotencyHashPayload {
        domain: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
        idempotency_key: trimmed,
    })
    .map_err(AvcError::from)
}

/// Build the deterministic AVC action represented by a public-output proof.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical action-name hashing fails.
pub fn livesafe_public_adapter_output_authorization_action_request(
    credential: &AutonomousVolitionCredential,
    subject: &str,
    audience: &str,
    evidence_hash: Hash256,
    idempotency_key_hash: Hash256,
    expires_at: &Timestamp,
) -> Result<AvcActionRequest, AvcError> {
    let action_name_hash = hash_structured(&ActionNamePayload {
        domain: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
        subject,
        audience,
        evidence_hash: &evidence_hash,
        idempotency_key_hash: &idempotency_key_hash,
        expires_at,
    })
    .map_err(AvcError::from)?;
    Ok(AvcActionRequest {
        action_id: idempotency_key_hash,
        actor_did: credential.effective_holder().clone(),
        requested_permission: Permission::Read,
        tool: Some(LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into()),
        target_did: None,
        data_class: Some(DataClass::Public),
        estimated_budget_minor_units: None,
        estimated_risk_bp: None,
        human_approval: None,
        requires_human_approval: false,
        action_name: Some(format!(
            "{LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ACTION_NAME}:{action_name_hash}"
        )),
    })
}

/// Compute the AVC action commitment for a public-output authorization draft.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical hashing fails.
pub fn livesafe_public_adapter_output_authorization_action_commitment_hash(
    credential: &AutonomousVolitionCredential,
    subject: &str,
    audience: &str,
    evidence_hash: Hash256,
    idempotency_key_hash: Hash256,
    issued_at: &Timestamp,
    expires_at: &Timestamp,
) -> Result<Hash256, AvcError> {
    let action = livesafe_public_adapter_output_authorization_action_request(
        credential,
        subject,
        audience,
        evidence_hash,
        idempotency_key_hash,
        expires_at,
    )?;
    avc_action_commitment_hash(credential, &action, issued_at)
}

/// Validate the narrow LiveSafe public-output authorization and return the
/// underlying AVC validation result for receipt anchoring.
///
/// # Errors
/// Returns [`AvcError`] for any denied or malformed proof input.
pub fn validate_livesafe_public_adapter_output_authorization<R: AvcRegistryRead>(
    draft: &LivesafePublicAdapterOutputAuthorizationDraft,
    registry: &R,
) -> Result<AvcValidationResult, AvcError> {
    validate_fixed_public_claim(draft)?;
    let credential_id = draft.credential.id()?;
    if let Some(expected) = draft.credential_id {
        if expected != credential_id {
            return Err(AvcError::InvalidInput {
                reason: format!(
                    "LiveSafe public adapter output credential_id {expected} does not match computed AVC id {credential_id}"
                ),
            });
        }
    }
    validate_registered_issuer_grant(&draft.credential, registry)?;
    validate_subject_kind(&draft.credential)?;
    validate_credential_subject_did(&draft.credential)?;
    validate_allowed_public_output_objectives(&draft.credential)?;
    validate_ceremony_evidence_hash_binding(draft)?;
    validate_expiry_bounds(draft)?;

    let action = livesafe_public_adapter_output_authorization_action_request(
        &draft.credential,
        &draft.subject,
        &draft.audience,
        draft.evidence_hash,
        draft.idempotency_key_hash,
        &draft.expires_at,
    )?;
    let expected_action_commitment =
        avc_action_commitment_hash(&draft.credential, &action, &draft.issued_at)?;
    if expected_action_commitment != draft.action_commitment_hash {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output action commitment mismatch: expected {expected_action_commitment}, got {}",
                draft.action_commitment_hash
            ),
        });
    }

    let validation = validate_avc(
        &AvcValidationRequest {
            credential: draft.credential.clone(),
            action: Some(action),
            now: draft.issued_at,
        },
        registry,
    )?;
    if validation.decision != AvcDecision::Allow {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output authorization denied: {:?}",
                validation.reason_codes
            ),
        });
    }
    Ok(validation)
}

/// Mint a validated, redacted public proof envelope.
///
/// # Errors
/// Returns [`AvcError`] when the draft is outside the narrow LiveSafe public
/// adapter-output authorization contract or the backing AVC validation denies.
pub fn mint_livesafe_public_adapter_output_authorization_proof<R, F>(
    draft: LivesafePublicAdapterOutputAuthorizationDraft,
    registry: &R,
    sign: F,
) -> Result<LivesafePublicAdapterOutputAuthorizationEnvelope, AvcError>
where
    R: AvcRegistryRead,
    F: FnOnce(&[u8]) -> Signature,
{
    validate_livesafe_public_adapter_output_authorization(&draft, registry)?;
    sign_livesafe_public_adapter_output_authorization_proof_unchecked(draft, sign)
}

pub(crate) fn sign_livesafe_public_adapter_output_authorization_proof_unchecked<F>(
    draft: LivesafePublicAdapterOutputAuthorizationDraft,
    sign: F,
) -> Result<LivesafePublicAdapterOutputAuthorizationEnvelope, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    let credential_id = draft.credential_id.unwrap_or(draft.credential.id()?);
    let mut proof = LivesafePublicAdapterOutputAuthorizationProof {
        schema_version: AVC_SCHEMA_VERSION,
        domain: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
        subject: draft.subject,
        audience: draft.audience,
        evidence_hash: draft.evidence_hash,
        credential_id,
        receipt_id: draft.receipt_id,
        action_commitment_hash: draft.action_commitment_hash,
        idempotency_key_hash: draft.idempotency_key_hash,
        issued_at: draft.issued_at,
        expires_at: draft.expires_at,
        revocation_status: LivesafePublicAdapterOutputAuthorizationRevocationStatus::NotRevoked,
        signer_did: draft.signer_did,
        proof_hash: Hash256::ZERO,
        signature: Signature::empty(),
    };
    let payload = proof.signing_payload()?;
    proof.proof_hash = Hash256::digest(&payload);
    proof.signature = sign(&payload);
    Ok(LivesafePublicAdapterOutputAuthorizationEnvelope {
        schema_version: AVC_SCHEMA_VERSION,
        domain: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
        proof,
    })
}

/// Verify the redacted public proof against a signer public key.
///
/// # Errors
/// Returns [`AvcError`] if fixed LiveSafe fields, proof hash, or signature
/// verification fail.
pub fn verify_livesafe_public_adapter_output_authorization_proof(
    proof: &LivesafePublicAdapterOutputAuthorizationProof,
    signer_public_key: &PublicKey,
) -> Result<(), AvcError> {
    validate_fixed_proof(proof)?;
    let payload = proof.signing_payload()?;
    let computed_hash = Hash256::digest(&payload);
    if computed_hash != proof.proof_hash {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output proof hash/signature mismatch: expected {computed_hash}, got {}",
                proof.proof_hash
            ),
        });
    }
    if proof.signature.is_empty() || !crypto::verify(&payload, &proof.signature, signer_public_key)
    {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public adapter output proof signature is invalid".into(),
        });
    }
    Ok(())
}

impl LivesafePublicAdapterOutputAuthorizationProof {
    fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let payload = ProofSigningPayload {
            domain: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
            schema_version: self.schema_version,
            subject: &self.subject,
            audience: &self.audience,
            evidence_hash: &self.evidence_hash,
            credential_id: &self.credential_id,
            receipt_id: &self.receipt_id,
            action_commitment_hash: &self.action_commitment_hash,
            idempotency_key_hash: &self.idempotency_key_hash,
            issued_at: &self.issued_at,
            expires_at: &self.expires_at,
            revocation_status: &self.revocation_status,
            signer_did: &self.signer_did,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)?;
        Ok(buf)
    }
}

fn validate_fixed_public_claim(
    draft: &LivesafePublicAdapterOutputAuthorizationDraft,
) -> Result<(), AvcError> {
    if draft.subject != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output subject must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT
            ),
        });
    }
    if draft.audience != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output audience must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE
            ),
        });
    }
    Ok(())
}

fn validate_fixed_proof(
    proof: &LivesafePublicAdapterOutputAuthorizationProof,
) -> Result<(), AvcError> {
    if proof.schema_version != AVC_SCHEMA_VERSION {
        return Err(AvcError::UnsupportedSchema {
            got: proof.schema_version,
            supported: AVC_SCHEMA_VERSION,
        });
    }
    if proof.domain != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public adapter output proof domain is invalid".into(),
        });
    }
    if proof.subject != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output subject must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT
            ),
        });
    }
    if proof.audience != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output audience must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE
            ),
        });
    }
    if proof.expires_at <= proof.issued_at {
        return Err(AvcError::InvalidTimestamp {
            reason: "LiveSafe public adapter output proof expires_at must be after issued_at"
                .into(),
        });
    }
    Ok(())
}

fn validate_subject_kind(credential: &AutonomousVolitionCredential) -> Result<(), AvcError> {
    match &credential.subject_kind {
        AvcSubjectKind::Service { service_id }
            if service_id == LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT =>
        {
            Ok(())
        }
        _ => Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output credential subject service must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT
            ),
        }),
    }
}

fn validate_credential_subject_did(
    credential: &AutonomousVolitionCredential,
) -> Result<(), AvcError> {
    let expected =
        Did::new(LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID).map_err(|error| {
            AvcError::InvalidInput {
                reason: format!(
                    "LiveSafe public adapter output credential subject DID is invalid: {error}"
                ),
            }
        })?;
    if credential.subject_did != expected {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output credential subject DID must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID
            ),
        });
    }
    Ok(())
}

fn validate_allowed_public_output_objectives(
    credential: &AutonomousVolitionCredential,
) -> Result<(), AvcError> {
    let mut allowed_objectives = credential.delegated_intent.allowed_objectives.clone();
    allowed_objectives.sort();
    allowed_objectives.dedup();
    if allowed_objectives != vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.to_owned()] {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output allowed objectives must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN
            ),
        });
    }
    Ok(())
}

fn validate_ceremony_evidence_hash_binding(
    draft: &LivesafePublicAdapterOutputAuthorizationDraft,
) -> Result<(), AvcError> {
    let Some(credential_expires_at) = draft.credential.expires_at else {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public adapter output credential must carry a ceremony expiry".into(),
        });
    };
    let expected_intent_id = livesafe_public_output_credential_ceremony_intent_id(
        &LivesafePublicOutputCredentialCeremonyIntentInput {
            issuer_did: &draft.credential.issuer_did,
            credential_subject_did: &draft.credential.subject_did,
            public_subject: &draft.subject,
            public_audience: &draft.audience,
            allowed_claim_names: &draft.credential.delegated_intent.allowed_objectives,
            evidence_hash: &draft.evidence_hash,
            not_before: &draft.credential.created_at,
            expires_at: &credential_expires_at,
        },
    )?;
    if draft.credential.delegated_intent.intent_id != expected_intent_id {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public adapter output evidence hash does not match the signed ceremony credential binding".into(),
        });
    }
    Ok(())
}

fn validate_expiry_bounds(
    draft: &LivesafePublicAdapterOutputAuthorizationDraft,
) -> Result<(), AvcError> {
    if draft.expires_at <= draft.issued_at {
        return Err(AvcError::InvalidTimestamp {
            reason: "LiveSafe public adapter output proof expires_at must be after issued_at"
                .into(),
        });
    }
    if let Some(credential_expiry) = draft.credential.expires_at {
        if credential_expiry <= draft.issued_at {
            return Err(AvcError::InvalidInput {
                reason: "LiveSafe public adapter output authorization denied: [Expired]".into(),
            });
        }
        if draft.expires_at > credential_expiry {
            return Err(AvcError::InvalidTimestamp {
                reason: "LiveSafe public adapter output proof expires after its AVC credential"
                    .into(),
            });
        }
    }
    Ok(())
}

fn validate_registered_issuer_grant<R: AvcRegistryRead>(
    credential: &AutonomousVolitionCredential,
    registry: &R,
) -> Result<(), AvcError> {
    let Some(granted_permissions) =
        registry.resolve_issuer_permission_grant(&credential.issuer_did)
    else {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output issuer grant is missing for {}",
                credential.issuer_did
            ),
        });
    };
    if !granted_permissions.contains(&Permission::Read) {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public adapter output issuer grant for {} lacks narrow Permission::Read",
                credential.issuer_did
            ),
        });
    }
    Ok(())
}
