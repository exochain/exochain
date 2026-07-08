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

//! EXOCHAIN LYNK Protocol evidence for receipted LLM and MCP usage.

use exo_core::{Did, Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{AVC_SCHEMA_VERSION, error::AvcError};

/// Human-facing name for the governed LLM/MCP receipt evidence protocol.
pub const EXOCHAIN_LYNK_PROTOCOL_NAME: &str = "EXOCHAIN LYNK Protocol";
/// Domain tag for canonical EXOCHAIN LYNK Protocol LLM usage evidence.
pub const AVC_LLM_USAGE_EVIDENCE_DOMAIN: &str = "exo.avc.lynk.llm_usage.evidence.v1";
/// Domain tag for adapter signatures over EXOCHAIN LYNK Protocol evidence.
pub const AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN: &str =
    "exo.avc.lynk.llm_usage.evidence_signature.v1";

/// Storage and custody posture for the payload material represented by
/// LYNK evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmUsageCustodyMode {
    /// AVC receipt contains minimized evidence only.
    ReceiptMinimized,
    /// Payload material is stored outside EXOCHAIN behind opaque references.
    ExternalPayloadRef,
    /// DAG DB stores governed tenant data under explicit custody policy.
    DagDbCustody,
}

/// Integer-only provider usage counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUsageMetrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_minor_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_currency: Option<String>,
    pub usage_complete: bool,
}

/// Opaque external payload reference represented only by hashes and policy
/// commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedPayloadRef {
    pub ref_id_hash: Hash256,
    pub ciphertext_hash: Hash256,
    pub storage_policy_hash: Hash256,
    pub key_policy_hash: Hash256,
    pub payload_kind: String,
    pub byte_length: u64,
}

/// Canonical LYNK evidence for one LLM or MCP usage event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmUsageEvidence {
    pub schema_version: u16,
    pub tenant_id: String,
    pub namespace: String,
    pub actor_did: Did,
    pub provider: String,
    pub provider_endpoint: String,
    pub model_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id_hash: Option<Hash256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id_hash: Option<Hash256>,
    pub idempotency_key_hash: Hash256,
    pub action_id: Hash256,
    pub prompt_hash: Hash256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_hash: Option<Hash256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_hash: Option<Hash256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_result_hash: Option<Hash256>,
    pub usage: ProviderUsageMetrics,
    pub custody_mode: LlmUsageCustodyMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub encrypted_payload_refs: Vec<EncryptedPayloadRef>,
    pub custody_policy_hash: Hash256,
    pub created_at: Timestamp,
}

/// Adapter-signed envelope for LYNK evidence. The signature itself is carried
/// by the route DTO so signature bytes never alter the canonical payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmUsageEvidenceEnvelope {
    pub schema_version: u16,
    pub adapter_did: Did,
    pub issued_at: Timestamp,
    pub evidence: LlmUsageEvidence,
}

#[derive(Serialize)]
struct LlmUsageEvidenceHashPayload<'a> {
    domain: &'static str,
    protocol_name: &'static str,
    schema_version: u16,
    evidence: &'a LlmUsageEvidence,
}

#[derive(Serialize)]
struct LlmUsageEvidenceSignaturePayload<'a> {
    domain: &'static str,
    protocol_name: &'static str,
    schema_version: u16,
    adapter_did: &'a Did,
    issued_at: &'a Timestamp,
    evidence_hash: &'a Hash256,
}

/// Compute the canonical LYNK evidence hash.
///
/// # Errors
/// Returns [`AvcError::Serialization`] when canonical CBOR encoding fails.
pub fn llm_usage_evidence_hash(evidence: &LlmUsageEvidence) -> Result<Hash256, AvcError> {
    hash_structured(&LlmUsageEvidenceHashPayload {
        domain: AVC_LLM_USAGE_EVIDENCE_DOMAIN,
        protocol_name: EXOCHAIN_LYNK_PROTOCOL_NAME,
        schema_version: evidence.schema_version,
        evidence,
    })
    .map_err(AvcError::from)
}

/// Build canonical adapter-signature bytes for a LYNK evidence envelope.
///
/// # Errors
/// Returns [`AvcError`] when the envelope is structurally invalid or CBOR
/// encoding fails.
pub fn llm_usage_evidence_signature_payload(
    envelope: &LlmUsageEvidenceEnvelope,
) -> Result<Vec<u8>, AvcError> {
    if envelope.schema_version != AVC_SCHEMA_VERSION {
        return Err(AvcError::UnsupportedSchema {
            got: envelope.schema_version,
            supported: AVC_SCHEMA_VERSION,
        });
    }
    validate_llm_usage_evidence(&envelope.evidence)?;
    let evidence_hash = llm_usage_evidence_hash(&envelope.evidence)?;
    let payload = LlmUsageEvidenceSignaturePayload {
        domain: AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN,
        protocol_name: EXOCHAIN_LYNK_PROTOCOL_NAME,
        schema_version: envelope.schema_version,
        adapter_did: &envelope.adapter_did,
        issued_at: &envelope.issued_at,
        evidence_hash: &evidence_hash,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf)?;
    Ok(buf)
}

/// Validate LYNK evidence before it can be used to emit an AVC receipt.
///
/// # Errors
/// Returns [`AvcError`] with field-specific context for malformed evidence.
pub fn validate_llm_usage_evidence(evidence: &LlmUsageEvidence) -> Result<(), AvcError> {
    if evidence.schema_version != AVC_SCHEMA_VERSION {
        return Err(AvcError::UnsupportedSchema {
            got: evidence.schema_version,
            supported: AVC_SCHEMA_VERSION,
        });
    }
    require_non_empty("llm_usage.tenant_id", &evidence.tenant_id)?;
    require_non_empty("llm_usage.namespace", &evidence.namespace)?;
    require_non_empty("llm_usage.provider", &evidence.provider)?;
    require_non_empty("llm_usage.provider_endpoint", &evidence.provider_endpoint)?;
    require_non_empty("llm_usage.model_id", &evidence.model_id)?;
    require_hash(
        "llm_usage.idempotency_key_hash",
        &evidence.idempotency_key_hash,
    )?;
    require_hash("llm_usage.action_id", &evidence.action_id)?;
    require_hash("llm_usage.prompt_hash", &evidence.prompt_hash)?;
    require_hash(
        "llm_usage.custody_policy_hash",
        &evidence.custody_policy_hash,
    )?;
    require_optional_hash(
        "llm_usage.provider_request_id_hash",
        evidence.provider_request_id_hash.as_ref(),
    )?;
    require_optional_hash(
        "llm_usage.session_id_hash",
        evidence.session_id_hash.as_ref(),
    )?;
    require_optional_hash(
        "llm_usage.completion_hash",
        evidence.completion_hash.as_ref(),
    )?;
    require_optional_hash("llm_usage.tool_call_hash", evidence.tool_call_hash.as_ref())?;
    require_optional_hash(
        "llm_usage.tool_result_hash",
        evidence.tool_result_hash.as_ref(),
    )?;
    validate_usage_metrics(&evidence.usage)?;
    validate_encrypted_refs(&evidence.encrypted_payload_refs)?;

    match evidence.custody_mode {
        LlmUsageCustodyMode::ReceiptMinimized => {
            if !evidence.encrypted_payload_refs.is_empty() {
                return Err(AvcError::InvalidInput {
                    reason: "llm_usage.encrypted_payload_refs must be empty for receipt_minimized custody".into(),
                });
            }
        }
        LlmUsageCustodyMode::ExternalPayloadRef => {
            if evidence.encrypted_payload_refs.is_empty() {
                return Err(AvcError::InvalidInput {
                    reason: "llm_usage.encrypted_payload_refs must be present for external_payload_ref custody".into(),
                });
            }
        }
        LlmUsageCustodyMode::DagDbCustody => {
            if evidence.custody_policy_hash == Hash256::ZERO {
                return Err(AvcError::InvalidInput {
                    reason: "llm_usage.custody_policy_hash must be nonzero for dagdb_custody"
                        .into(),
                });
            }
        }
    }

    Ok(())
}

fn validate_usage_metrics(usage: &ProviderUsageMetrics) -> Result<(), AvcError> {
    let visible_total = usage
        .input_tokens
        .checked_add(usage.output_tokens)
        .ok_or_else(|| AvcError::InvalidInput {
            reason: "llm_usage.usage input_tokens plus output_tokens overflowed u64".into(),
        })?;
    if usage.total_tokens < visible_total {
        return Err(AvcError::InvalidInput {
            reason: "llm_usage.usage.total_tokens must be at least input_tokens plus output_tokens"
                .into(),
        });
    }
    if let Some(cached) = usage.cached_input_tokens {
        if cached > usage.input_tokens {
            return Err(AvcError::InvalidInput {
                reason: "llm_usage.usage.cached_input_tokens must not exceed input_tokens".into(),
            });
        }
    }
    if let Some(reasoning) = usage.reasoning_tokens {
        if reasoning > usage.output_tokens {
            return Err(AvcError::InvalidInput {
                reason: "llm_usage.usage.reasoning_tokens must not exceed output_tokens".into(),
            });
        }
    }
    match (usage.cost_minor_units, usage.cost_currency.as_ref()) {
        (Some(_), Some(currency)) => require_non_empty("llm_usage.usage.cost_currency", currency),
        (Some(_), None) => Err(AvcError::EmptyField {
            field: "llm_usage.usage.cost_currency",
        }),
        (None, Some(currency)) if currency.trim().is_empty() => Err(AvcError::EmptyField {
            field: "llm_usage.usage.cost_currency",
        }),
        (None, _) => Ok(()),
    }
}

fn validate_encrypted_refs(refs: &[EncryptedPayloadRef]) -> Result<(), AvcError> {
    for reference in refs {
        require_hash(
            "llm_usage.encrypted_payload_refs.ref_id_hash",
            &reference.ref_id_hash,
        )?;
        require_hash(
            "llm_usage.encrypted_payload_refs.ciphertext_hash",
            &reference.ciphertext_hash,
        )?;
        require_hash(
            "llm_usage.encrypted_payload_refs.storage_policy_hash",
            &reference.storage_policy_hash,
        )?;
        require_hash(
            "llm_usage.encrypted_payload_refs.key_policy_hash",
            &reference.key_policy_hash,
        )?;
        require_non_empty(
            "llm_usage.encrypted_payload_refs.payload_kind",
            &reference.payload_kind,
        )?;
        if reference.byte_length == 0 {
            return Err(AvcError::InvalidInput {
                reason: "llm_usage.encrypted_payload_refs.byte_length must be greater than zero"
                    .into(),
            });
        }
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), AvcError> {
    if value.trim().is_empty() {
        return Err(AvcError::EmptyField { field });
    }
    Ok(())
}

fn require_hash(field: &'static str, value: &Hash256) -> Result<(), AvcError> {
    if *value == Hash256::ZERO {
        return Err(AvcError::InvalidInput {
            reason: format!("{field} must be nonzero"),
        });
    }
    Ok(())
}

fn require_optional_hash(field: &'static str, value: Option<&Hash256>) -> Result<(), AvcError> {
    if let Some(hash) = value {
        require_hash(field, hash)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, Timestamp};

    use super::*;

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn did(value: &str) -> Did {
        Did::new(value).expect("valid DID")
    }

    fn sample_usage() -> ProviderUsageMetrics {
        ProviderUsageMetrics {
            input_tokens: 101,
            output_tokens: 37,
            total_tokens: 138,
            cached_input_tokens: Some(11),
            reasoning_tokens: Some(7),
            cost_minor_units: Some(42),
            cost_currency: Some("USD".into()),
            usage_complete: true,
        }
    }

    fn sample_evidence() -> LlmUsageEvidence {
        LlmUsageEvidence {
            schema_version: crate::AVC_SCHEMA_VERSION,
            tenant_id: "tenant-alpha".into(),
            namespace: "default".into(),
            actor_did: did("did:exo:lynk-agent"),
            provider: "openai".into(),
            provider_endpoint: "responses".into(),
            model_id: "gpt-test".into(),
            provider_request_id_hash: Some(h(0x10)),
            session_id_hash: Some(h(0x11)),
            idempotency_key_hash: h(0x12),
            action_id: h(0x13),
            prompt_hash: h(0x14),
            completion_hash: Some(h(0x15)),
            tool_call_hash: None,
            tool_result_hash: None,
            usage: sample_usage(),
            custody_mode: LlmUsageCustodyMode::ReceiptMinimized,
            encrypted_payload_refs: vec![],
            custody_policy_hash: h(0x16),
            created_at: Timestamp::new(1_700_000_000_000, 7),
        }
    }

    fn sample_ref() -> EncryptedPayloadRef {
        EncryptedPayloadRef {
            ref_id_hash: h(0x21),
            ciphertext_hash: h(0x22),
            storage_policy_hash: h(0x23),
            key_policy_hash: h(0x24),
            payload_kind: "provider_exchange".into(),
            byte_length: 256,
        }
    }

    #[test]
    fn llm_usage_evidence_hash_is_deterministic_for_identical_evidence() {
        let left = sample_evidence();
        let right = sample_evidence();

        assert_eq!(
            llm_usage_evidence_hash(&left).expect("hash left"),
            llm_usage_evidence_hash(&right).expect("hash right")
        );
    }

    #[test]
    fn llm_usage_evidence_hash_changes_for_material_fields() {
        let baseline = sample_evidence();
        let baseline_hash = llm_usage_evidence_hash(&baseline).expect("baseline hash");

        let mut changed = baseline.clone();
        changed.model_id = "gpt-other".into();
        assert_ne!(
            baseline_hash,
            llm_usage_evidence_hash(&changed).expect("changed model hash")
        );

        let mut changed = baseline.clone();
        changed.prompt_hash = h(0x31);
        assert_ne!(
            baseline_hash,
            llm_usage_evidence_hash(&changed).expect("changed prompt hash")
        );

        let mut changed = baseline.clone();
        changed.completion_hash = Some(h(0x32));
        assert_ne!(
            baseline_hash,
            llm_usage_evidence_hash(&changed).expect("changed completion hash")
        );

        let mut changed = baseline.clone();
        changed.usage.input_tokens = 102;
        changed.usage.total_tokens = 139;
        assert_ne!(
            baseline_hash,
            llm_usage_evidence_hash(&changed).expect("changed input tokens hash")
        );

        let mut changed = baseline.clone();
        changed.usage.output_tokens = 38;
        changed.usage.total_tokens = 139;
        assert_ne!(
            baseline_hash,
            llm_usage_evidence_hash(&changed).expect("changed output tokens hash")
        );

        let mut changed = baseline.clone();
        changed.custody_mode = LlmUsageCustodyMode::DagDbCustody;
        assert_ne!(
            baseline_hash,
            llm_usage_evidence_hash(&changed).expect("changed custody hash")
        );
    }

    #[test]
    fn validate_llm_usage_evidence_accepts_minimized_receipt_mode() {
        validate_llm_usage_evidence(&sample_evidence()).expect("valid minimized evidence");
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_empty_required_fields() {
        let mut evidence = sample_evidence();
        evidence.provider = "  ".into();

        assert!(matches!(
            validate_llm_usage_evidence(&evidence),
            Err(AvcError::EmptyField {
                field: "llm_usage.provider"
            })
        ));
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_token_total_contradiction() {
        let mut evidence = sample_evidence();
        evidence.usage.total_tokens =
            evidence.usage.input_tokens + evidence.usage.output_tokens - 1;

        let err = validate_llm_usage_evidence(&evidence).expect_err("token total rejected");
        assert!(err.to_string().contains("total_tokens"));
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_unsupported_schema() {
        let mut evidence = sample_evidence();
        evidence.schema_version = crate::AVC_SCHEMA_VERSION + 1;

        assert!(matches!(
            validate_llm_usage_evidence(&evidence),
            Err(AvcError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_zero_required_and_optional_hashes() {
        let mutations: [fn(&mut LlmUsageEvidence); 7] = [
            |evidence: &mut LlmUsageEvidence| evidence.action_id = Hash256::ZERO,
            |evidence: &mut LlmUsageEvidence| evidence.prompt_hash = Hash256::ZERO,
            |evidence: &mut LlmUsageEvidence| {
                evidence.provider_request_id_hash = Some(Hash256::ZERO)
            },
            |evidence: &mut LlmUsageEvidence| evidence.session_id_hash = Some(Hash256::ZERO),
            |evidence: &mut LlmUsageEvidence| evidence.completion_hash = Some(Hash256::ZERO),
            |evidence: &mut LlmUsageEvidence| evidence.tool_call_hash = Some(Hash256::ZERO),
            |evidence: &mut LlmUsageEvidence| evidence.tool_result_hash = Some(Hash256::ZERO),
        ];
        for mutate in mutations {
            let mut evidence = sample_evidence();
            mutate(&mut evidence);

            assert!(
                validate_llm_usage_evidence(&evidence).is_err(),
                "zero hash mutation must be rejected"
            );
        }
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_token_overflow() {
        let mut evidence = sample_evidence();
        evidence.usage.input_tokens = u64::MAX;
        evidence.usage.output_tokens = 1;
        evidence.usage.total_tokens = u64::MAX;

        let err = validate_llm_usage_evidence(&evidence).expect_err("overflow rejected");
        assert!(err.to_string().contains("overflowed"));
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_usage_detail_contradictions() {
        let mut cached = sample_evidence();
        cached.usage.cached_input_tokens = Some(cached.usage.input_tokens + 1);
        assert!(
            validate_llm_usage_evidence(&cached)
                .expect_err("cached tokens rejected")
                .to_string()
                .contains("cached_input_tokens")
        );

        let mut reasoning = sample_evidence();
        reasoning.usage.reasoning_tokens = Some(reasoning.usage.output_tokens + 1);
        assert!(
            validate_llm_usage_evidence(&reasoning)
                .expect_err("reasoning tokens rejected")
                .to_string()
                .contains("reasoning_tokens")
        );
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_cost_without_nonempty_currency() {
        let mut missing = sample_evidence();
        missing.usage.cost_currency = None;
        assert!(matches!(
            validate_llm_usage_evidence(&missing),
            Err(AvcError::EmptyField {
                field: "llm_usage.usage.cost_currency"
            })
        ));

        let mut blank = sample_evidence();
        blank.usage.cost_currency = Some(" ".into());
        assert!(matches!(
            validate_llm_usage_evidence(&blank),
            Err(AvcError::EmptyField {
                field: "llm_usage.usage.cost_currency"
            })
        ));
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_minimized_mode_refs() {
        let mut evidence = sample_evidence();
        evidence.encrypted_payload_refs = vec![sample_ref()];

        let err = validate_llm_usage_evidence(&evidence).expect_err("refs rejected");
        assert!(err.to_string().contains("receipt_minimized"));
    }

    #[test]
    fn validate_llm_usage_evidence_requires_external_refs() {
        let mut evidence = sample_evidence();
        evidence.custody_mode = LlmUsageCustodyMode::ExternalPayloadRef;

        let err = validate_llm_usage_evidence(&evidence).expect_err("missing refs rejected");
        assert!(err.to_string().contains("external_payload_ref"));
    }

    #[test]
    fn validate_llm_usage_evidence_accepts_external_refs() {
        let mut evidence = sample_evidence();
        evidence.custody_mode = LlmUsageCustodyMode::ExternalPayloadRef;
        evidence.encrypted_payload_refs = vec![sample_ref()];

        validate_llm_usage_evidence(&evidence).expect("valid external ref evidence");
    }

    #[test]
    fn validate_llm_usage_evidence_rejects_bad_encrypted_ref_fields() {
        let mutations: [fn(&mut EncryptedPayloadRef); 6] = [
            |reference: &mut EncryptedPayloadRef| reference.ref_id_hash = Hash256::ZERO,
            |reference: &mut EncryptedPayloadRef| reference.ciphertext_hash = Hash256::ZERO,
            |reference: &mut EncryptedPayloadRef| reference.storage_policy_hash = Hash256::ZERO,
            |reference: &mut EncryptedPayloadRef| reference.key_policy_hash = Hash256::ZERO,
            |reference: &mut EncryptedPayloadRef| reference.payload_kind = " ".into(),
            |reference: &mut EncryptedPayloadRef| reference.byte_length = 0,
        ];
        for mutate in mutations {
            let mut evidence = sample_evidence();
            let mut reference = sample_ref();
            mutate(&mut reference);
            evidence.custody_mode = LlmUsageCustodyMode::ExternalPayloadRef;
            evidence.encrypted_payload_refs = vec![reference];

            assert!(
                validate_llm_usage_evidence(&evidence).is_err(),
                "bad encrypted payload ref mutation must be rejected"
            );
        }
    }

    #[test]
    fn validate_llm_usage_evidence_requires_dagdb_custody_policy() {
        let mut evidence = sample_evidence();
        evidence.custody_mode = LlmUsageCustodyMode::DagDbCustody;
        evidence.custody_policy_hash = Hash256::ZERO;

        let err = validate_llm_usage_evidence(&evidence).expect_err("policy rejected");
        assert!(err.to_string().contains("custody_policy_hash"));
    }

    #[test]
    fn llm_usage_evidence_signature_payload_is_deterministic_and_context_bound() {
        let envelope = LlmUsageEvidenceEnvelope {
            schema_version: crate::AVC_SCHEMA_VERSION,
            adapter_did: did("did:exo:lynk-adapter"),
            issued_at: Timestamp::new(1_700_000_000_001, 0),
            evidence: sample_evidence(),
        };

        let left = llm_usage_evidence_signature_payload(&envelope).expect("left signature payload");
        let right =
            llm_usage_evidence_signature_payload(&envelope).expect("right signature payload");
        assert_eq!(left, right);

        let mut changed = envelope.clone();
        changed.adapter_did = did("did:exo:other-lynk-adapter");
        let changed_payload =
            llm_usage_evidence_signature_payload(&changed).expect("changed signature payload");
        assert_ne!(left, changed_payload);
    }

    #[test]
    fn llm_usage_evidence_signature_payload_rejects_bad_envelope_schema() {
        let envelope = LlmUsageEvidenceEnvelope {
            schema_version: crate::AVC_SCHEMA_VERSION + 1,
            adapter_did: did("did:exo:lynk-adapter"),
            issued_at: Timestamp::new(1_700_000_000_001, 0),
            evidence: sample_evidence(),
        };

        assert!(matches!(
            llm_usage_evidence_signature_payload(&envelope),
            Err(AvcError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn lynk_domains_are_versioned_and_named() {
        assert_eq!(EXOCHAIN_LYNK_PROTOCOL_NAME, "EXOCHAIN LYNK Protocol");
        assert!(AVC_LLM_USAGE_EVIDENCE_DOMAIN.contains(".lynk."));
        assert!(AVC_LLM_USAGE_EVIDENCE_DOMAIN.ends_with(".v1"));
        assert!(AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN.contains(".lynk."));
        assert!(AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN.ends_with(".v1"));
    }

    #[test]
    fn production_source_excludes_decryptable_field_names() {
        let production = include_str!("llm_usage_receipt.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        for token in [
            "raw_prompt",
            "raw_output",
            "response_text",
            "provider_api_key",
            "bearer_token",
            "kms_key",
            "kms_key_id",
            "raw_uri",
            "object_uri",
            "completion_text",
            "message_text",
        ] {
            assert!(
                !production.contains(token),
                "LYNK production evidence must not define `{token}`"
            );
        }
    }
}
