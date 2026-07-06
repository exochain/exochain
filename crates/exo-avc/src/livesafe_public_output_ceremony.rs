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

//! Deterministic LiveSafe public-output AVC credential ceremony.
//!
//! The ceremony emits a signed, narrow AVC credential plus the JSON-shaped
//! registration and authorization material an operator can submit to the node.
//! It never generates signing keys, reads clocks, accepts bearer tokens, or
//! serializes raw evidence bytes into the output package.

use exo_authority::permission::Permission;
use exo_core::{Did, Hash256, Signature, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    AVC_SCHEMA_VERSION, AuthorityScope, AutonomousVolitionCredential, AutonomyLevel,
    AvcConstraints, AvcDraft, AvcSubjectKind, DataClass, DelegatedIntent, TimeWindow,
    error::AvcError,
    issue_avc,
    public_output_authorization::{
        LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
        LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
        livesafe_public_adapter_output_authorization_idempotency_hash,
    },
};

/// The only AVC subject DID admitted by the LiveSafe public-output ceremony.
pub const LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID: &str =
    "did:exo:livesafe-public-adapter";
/// Domain for the deterministic ceremony intent hash.
pub const LIVESAFE_PUBLIC_OUTPUT_CREDENTIAL_CEREMONY_DOMAIN: &str =
    "livesafe.public_output_credential_ceremony.v1";

const CEREMONY_PURPOSE: &str =
    "Authorize narrow LiveSafe public adapter output for redacted public trust status";
const FORBIDDEN_CLAIM_FRAGMENTS: &[&str] = &[
    "custody",
    "consent",
    "emergency",
    "legal",
    "medical",
    "exochain.constitutional",
    "exochain.core",
];

/// Canonical LiveSafe evidence-summary hash supplied to the ceremony.
///
/// The hash is produced outside this Rust ceremony by the LiveSafe evidence
/// contract and is consumed here only as already-canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicOutputCredentialCeremonyEvidence {
    pub sha256_hash: Hash256,
}

/// Deterministic inputs for the LiveSafe public-output credential ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicOutputCredentialCeremonyInput {
    pub issuer_did: Did,
    pub issuer_authority_scope: AuthorityScope,
    pub credential_subject_did: Did,
    pub public_subject: String,
    pub public_audience: String,
    pub allowed_claim_names: Vec<String>,
    pub evidence: LivesafePublicOutputCredentialCeremonyEvidence,
    pub not_before: Timestamp,
    pub expires_at: Timestamp,
    pub idempotency_key: String,
}

/// Node `/api/v1/avc/issue` request body emitted by the ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicOutputCredentialIssueRequest {
    pub credential: AutonomousVolitionCredential,
}

/// Node public-output authorization request material emitted by the ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicOutputAuthorizationRequestMaterial {
    #[serde(with = "sha256_hash_serde")]
    pub credential_id: Hash256,
    pub subject: String,
    pub audience: String,
    #[serde(with = "sha256_hash_serde")]
    pub evidence_hash: Hash256,
    pub idempotency_key: String,
    pub idempotency_key_hash: Hash256,
    pub expires_at: Timestamp,
}

/// Redacted ceremony output suitable for operator review and registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivesafePublicOutputCredentialCeremonyOutput {
    pub schema_version: u16,
    pub ceremony_domain: String,
    pub credential_id: Hash256,
    pub credential: AutonomousVolitionCredential,
    pub issue_request: LivesafePublicOutputCredentialIssueRequest,
    pub authorization_request: LivesafePublicOutputAuthorizationRequestMaterial,
    pub evidence_hash: Hash256,
    pub not_before: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Serialize)]
struct CeremonyIntentPayload<'a> {
    domain: &'static str,
    issuer_did: &'a Did,
    credential_subject_did: &'a Did,
    public_subject: &'a str,
    public_audience: &'a str,
    allowed_claim_names: &'a [String],
    evidence_hash: &'a Hash256,
    not_before: &'a Timestamp,
    expires_at: &'a Timestamp,
}

/// Borrowed inputs for the signed LiveSafe public-output ceremony intent hash.
pub(crate) struct LivesafePublicOutputCredentialCeremonyIntentInput<'a> {
    pub(crate) issuer_did: &'a Did,
    pub(crate) credential_subject_did: &'a Did,
    pub(crate) public_subject: &'a str,
    pub(crate) public_audience: &'a str,
    pub(crate) allowed_claim_names: &'a [String],
    pub(crate) evidence_hash: &'a Hash256,
    pub(crate) not_before: &'a Timestamp,
    pub(crate) expires_at: &'a Timestamp,
}

mod sha256_hash_serde {
    use exo_core::Hash256;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(hash: &Hash256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("sha256:{hash}"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Hash256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        super::parse_livesafe_public_output_evidence_sha256(&value).map_err(de::Error::custom)
    }
}

/// Parse a LiveSafe public-output evidence hash from exact `sha256:` lowercase
/// hex.
///
/// # Errors
/// Returns [`AvcError::InvalidInput`] unless the value is exactly
/// `sha256:<64 lowercase hex characters>`.
pub fn parse_livesafe_public_output_evidence_sha256(value: &str) -> Result<Hash256, AvcError> {
    const PREFIX: &str = "sha256:";
    let Some(hex) = value.strip_prefix(PREFIX) else {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public-output evidence hash must be sha256:<64 lowercase hex>".into(),
        });
    };
    if hex.len() != 64
        || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit)
        || hex.as_bytes().iter().any(u8::is_ascii_uppercase)
    {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public-output evidence hash must be sha256:<64 lowercase hex>".into(),
        });
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Hash256::from_bytes(bytes))
}

/// Compute the signed ceremony intent id that binds a credential to LiveSafe's
/// canonical evidence hash and fixed public-output claim identity.
///
/// # Errors
/// Returns [`AvcError::Serialization`] if canonical intent hashing fails.
pub(crate) fn livesafe_public_output_credential_ceremony_intent_id(
    input: &LivesafePublicOutputCredentialCeremonyIntentInput<'_>,
) -> Result<Hash256, AvcError> {
    let mut normalized_allowed_claim_names = input.allowed_claim_names.to_vec();
    normalized_allowed_claim_names.sort();
    normalized_allowed_claim_names.dedup();
    hash_structured(&CeremonyIntentPayload {
        domain: LIVESAFE_PUBLIC_OUTPUT_CREDENTIAL_CEREMONY_DOMAIN,
        issuer_did: input.issuer_did,
        credential_subject_did: input.credential_subject_did,
        public_subject: input.public_subject,
        public_audience: input.public_audience,
        allowed_claim_names: &normalized_allowed_claim_names,
        evidence_hash: input.evidence_hash,
        not_before: input.not_before,
        expires_at: input.expires_at,
    })
    .map_err(AvcError::from)
}

/// Issue the narrow LiveSafe public-output AVC credential and redacted
/// registration package.
///
/// # Errors
/// Returns [`AvcError`] if any input widens beyond the public-output ceremony
/// contract or if AVC issuance fails.
pub fn issue_livesafe_public_output_credential_ceremony<F>(
    input: LivesafePublicOutputCredentialCeremonyInput,
    sign: F,
) -> Result<LivesafePublicOutputCredentialCeremonyOutput, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    validate_input(&input)?;
    let evidence_hash = input.evidence.sha256_hash;
    let mut allowed_claim_names = input.allowed_claim_names.clone();
    allowed_claim_names.sort();
    allowed_claim_names.dedup();
    let intent_id = livesafe_public_output_credential_ceremony_intent_id(
        &LivesafePublicOutputCredentialCeremonyIntentInput {
            issuer_did: &input.issuer_did,
            credential_subject_did: &input.credential_subject_did,
            public_subject: &input.public_subject,
            public_audience: &input.public_audience,
            allowed_claim_names: &allowed_claim_names,
            evidence_hash: &evidence_hash,
            not_before: &input.not_before,
            expires_at: &input.expires_at,
        },
    )?;
    let jurisdiction = input
        .issuer_authority_scope
        .jurisdictions
        .first()
        .cloned()
        .ok_or(AvcError::InvalidInput {
            reason: "LiveSafe public-output issuer authority must declare a jurisdiction".into(),
        })?;
    let authority_scope = AuthorityScope {
        permissions: vec![Permission::Read],
        tools: vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into()],
        data_classes: vec![DataClass::Public],
        counterparties: vec![],
        jurisdictions: vec![jurisdiction],
    };
    let draft = AvcDraft {
        schema_version: AVC_SCHEMA_VERSION,
        issuer_did: input.issuer_did.clone(),
        principal_did: input.issuer_did.clone(),
        subject_did: input.credential_subject_did,
        holder_did: None,
        subject_kind: AvcSubjectKind::Service {
            service_id: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
        },
        created_at: input.not_before,
        expires_at: Some(input.expires_at),
        delegated_intent: DelegatedIntent {
            intent_id,
            purpose: CEREMONY_PURPOSE.into(),
            allowed_objectives: allowed_claim_names,
            prohibited_objectives: forbidden_claims(),
            autonomy_level: AutonomyLevel::ExecuteWithinBounds,
            delegation_allowed: false,
        },
        authority_scope,
        constraints: AvcConstraints {
            allowed_time_window: Some(TimeWindow {
                not_before: input.not_before,
                not_after: input.expires_at,
            }),
            ..AvcConstraints::permissive()
        },
        authority_chain: None,
        consent_refs: vec![],
        policy_refs: vec![],
        parent_avc_id: None,
    };
    let credential = issue_avc(draft, sign)?;
    let credential_id = credential.id()?;
    let idempotency_key_hash =
        livesafe_public_adapter_output_authorization_idempotency_hash(&input.idempotency_key)?;
    let authorization_request = LivesafePublicOutputAuthorizationRequestMaterial {
        credential_id,
        subject: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
        audience: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE.into(),
        evidence_hash,
        idempotency_key: input.idempotency_key,
        idempotency_key_hash,
        expires_at: input.expires_at,
    };
    Ok(LivesafePublicOutputCredentialCeremonyOutput {
        schema_version: AVC_SCHEMA_VERSION,
        ceremony_domain: LIVESAFE_PUBLIC_OUTPUT_CREDENTIAL_CEREMONY_DOMAIN.into(),
        credential_id,
        credential: credential.clone(),
        issue_request: LivesafePublicOutputCredentialIssueRequest { credential },
        authorization_request,
        evidence_hash,
        not_before: input.not_before,
        expires_at: input.expires_at,
    })
}

fn validate_input(input: &LivesafePublicOutputCredentialCeremonyInput) -> Result<(), AvcError> {
    validate_issuer_authority(&input.issuer_authority_scope)?;
    validate_public_claims(input)?;
    if input.expires_at <= input.not_before {
        return Err(AvcError::InvalidTimestamp {
            reason: "LiveSafe public-output ceremony expires_at must be after not_before".into(),
        });
    }
    livesafe_public_adapter_output_authorization_idempotency_hash(&input.idempotency_key)?;
    Ok(())
}

fn validate_issuer_authority(scope: &AuthorityScope) -> Result<(), AvcError> {
    let mut permissions = scope.permissions.clone();
    permissions.sort();
    permissions.dedup();
    let mut tools = scope.tools.clone();
    tools.sort();
    tools.dedup();
    let mut data_classes = scope.data_classes.clone();
    data_classes.sort();
    data_classes.dedup();

    if permissions != vec![Permission::Read]
        || tools != vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.to_owned()]
        || data_classes != vec![DataClass::Public]
        || !scope.counterparties.is_empty()
    {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public-output issuer authority must be exactly Permission::Read, tool {}, DataClass::Public, and no counterparties",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN
            ),
        });
    }
    if scope
        .jurisdictions
        .iter()
        .any(|jurisdiction| jurisdiction.trim().is_empty())
        || scope.jurisdictions.is_empty()
    {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public-output issuer authority must declare a jurisdiction".into(),
        });
    }
    Ok(())
}

fn validate_public_claims(
    input: &LivesafePublicOutputCredentialCeremonyInput,
) -> Result<(), AvcError> {
    let expected_subject_did = Did::new(LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID)
        .map_err(|error| AvcError::InvalidInput {
            reason: format!("LiveSafe public-output credential subject DID is invalid: {error}"),
        })?;
    if input.credential_subject_did != expected_subject_did {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public-output credential subject DID must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID
            ),
        });
    }
    if input.public_subject != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public-output subject must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT
            ),
        });
    }
    if input.public_audience != LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public-output audience must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE
            ),
        });
    }
    let mut claims = input.allowed_claim_names.clone();
    claims.sort();
    claims.dedup();
    if claims.is_empty() {
        return Err(AvcError::InvalidInput {
            reason: "LiveSafe public-output allowed claim names must not be empty".into(),
        });
    }
    for claim in &claims {
        if contains_forbidden_claim_fragment(claim) {
            return Err(AvcError::InvalidInput {
                reason: format!("LiveSafe public-output forbidden claim cap rejected: {claim}"),
            });
        }
    }
    if claims != vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.to_owned()] {
        return Err(AvcError::InvalidInput {
            reason: format!(
                "LiveSafe public-output allowed claim names must be exactly {}",
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN
            ),
        });
    }
    Ok(())
}

fn contains_forbidden_claim_fragment(claim: &str) -> bool {
    let lower = claim.to_ascii_lowercase();
    FORBIDDEN_CLAIM_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn forbidden_claims() -> Vec<String> {
    FORBIDDEN_CLAIM_FRAGMENTS
        .iter()
        .map(|fragment| format!("forbid:{fragment}"))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, AvcError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AvcError::InvalidInput {
            reason: "LiveSafe public-output evidence hash must be sha256:<64 lowercase hex>".into(),
        }),
    }
}
