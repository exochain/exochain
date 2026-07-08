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

//! # exo-avc — Autonomous Volition Credential
//!
//! `AVC` is a portable, signed, machine-verifiable credential that
//! defines what an autonomous actor is **authorized to pursue** under a
//! human or organizational principal.
//!
//! Identity proves *who* an actor is. Authority proves *who delegated*
//! power. Consent proves *what posture* applies. AVC proves *what
//! autonomous intent is allowed* before action occurs.
//!
//! In this crate, **volition** strictly means delegated operational
//! intent. It does **not** denote consciousness, sentience, emotion, or
//! human-like free will.
//!
//! ## Determinism contract
//!
//! - All collections in signed payloads are sorted and deduplicated.
//! - All hashing is BLAKE3 over canonical CBOR — only ordered maps and
//!   sets (`BTreeMap`, `BTreeSet`), no platform-dependent integer widths,
//!   and no floating-point arithmetic.
//! - Validation never reads system time; the caller passes `now`.
//! - Validation is fail-closed: any unresolved key, missing required
//!   reference, malformed structural value, scope violation, expiration,
//!   or revocation produces an explicit `Deny` decision with reason
//!   codes describing why.
//!
//! ## High-level API
//!
//! ```
//! use exo_avc::{
//!     AutonomyLevel, AuthorityScope, AvcConstraints, AvcDraft, AvcSubjectKind,
//!     DelegatedIntent, InMemoryAvcRegistry, AvcRegistryWrite, AvcValidationRequest,
//!     AvcDecision, issue_avc, validate_avc, AVC_SCHEMA_VERSION,
//! };
//! use exo_authority::permission::Permission;
//! use exo_core::{Did, Hash256, Timestamp};
//! use exo_core::crypto::KeyPair;
//!
//! let issuer_keypair = KeyPair::from_secret_bytes([0x11; 32]).unwrap();
//! let issuer_did = Did::new("did:exo:issuer").unwrap();
//! let mut registry = InMemoryAvcRegistry::new();
//! registry.put_public_key(issuer_did.clone(), issuer_keypair.public);
//!
//! let draft = AvcDraft {
//!     schema_version: AVC_SCHEMA_VERSION,
//!     issuer_did: issuer_did.clone(),
//!     principal_did: issuer_did.clone(),
//!     subject_did: Did::new("did:exo:agent").unwrap(),
//!     holder_did: None,
//!     subject_kind: AvcSubjectKind::AiAgent {
//!         model_id: "alpha".into(),
//!         agent_version: None,
//!     },
//!     created_at: Timestamp::new(1_000, 0),
//!     expires_at: Some(Timestamp::new(2_000, 0)),
//!     delegated_intent: DelegatedIntent {
//!         intent_id: Hash256::from_bytes([0xAA; 32]),
//!         purpose: "research".into(),
//!         allowed_objectives: vec!["primary".into()],
//!         prohibited_objectives: vec![],
//!         autonomy_level: AutonomyLevel::Draft,
//!         delegation_allowed: false,
//!     },
//!     authority_scope: AuthorityScope {
//!         permissions: vec![Permission::Read],
//!         tools: vec![],
//!         data_classes: vec![],
//!         counterparties: vec![],
//!         jurisdictions: vec!["US".into()],
//!     },
//!     constraints: AvcConstraints::permissive(),
//!     authority_chain: None,
//!     consent_refs: vec![],
//!     policy_refs: vec![],
//!     parent_avc_id: None,
//! };
//!
//! let credential = issue_avc(draft, |bytes| issuer_keypair.sign(bytes)).unwrap();
//! let request = AvcValidationRequest {
//!     credential,
//!     action: None,
//!     now: Timestamp::new(1_500, 0),
//! };
//! let result = validate_avc(&request, &registry).unwrap();
//! assert_eq!(result.decision, AvcDecision::Allow);
//! ```

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod credential;
pub mod delegation;
pub mod error;
pub mod livesafe_public_output_ceremony;
pub mod llm_usage_receipt;
pub mod public_output_authorization;
pub mod receipt;
pub mod registry;
pub mod revocation;
pub mod validation;

pub use credential::{
    AVC_CREDENTIAL_SIGNING_DOMAIN, AVC_MAX_SUPPORTED_PROTOCOL_VERSION,
    AVC_MIN_SUPPORTED_PROTOCOL_VERSION, AVC_PROTOCOL_DEPRECATION_WINDOW_DAYS, AVC_PROTOCOL_VERSION,
    AVC_SCHEMA_VERSION, AuthorityChainRef, AuthorityScope, AutonomousVolitionCredential,
    AutonomyLevel, AvcConstraints, AvcDraft, AvcSubjectKind, ConsentRef, DataClass,
    DelegatedIntent, MAX_BASIS_POINTS, PolicyRef, TimeWindow, issue_avc,
    require_supported_avc_protocol_version,
};
pub use delegation::{delegate_avc, parent_id_of};
pub use error::AvcError;
pub use livesafe_public_output_ceremony::{
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID,
    LIVESAFE_PUBLIC_OUTPUT_CREDENTIAL_CEREMONY_DOMAIN,
    LivesafePublicOutputAuthorizationRequestMaterial,
    LivesafePublicOutputCredentialCeremonyEvidence, LivesafePublicOutputCredentialCeremonyInput,
    LivesafePublicOutputCredentialCeremonyOutput, LivesafePublicOutputCredentialIssueRequest,
    issue_livesafe_public_output_credential_ceremony, parse_livesafe_public_output_evidence_sha256,
};
pub use llm_usage_receipt::{
    AVC_LLM_USAGE_EVIDENCE_DOMAIN, AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN,
    EXOCHAIN_LYNK_PROTOCOL_NAME, EncryptedPayloadRef, LlmUsageCustodyMode, LlmUsageEvidence,
    LlmUsageEvidenceEnvelope, ProviderUsageMetrics, llm_usage_evidence_hash,
    llm_usage_evidence_signature_payload, validate_llm_usage_evidence,
};
pub use public_output_authorization::{
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
    LivesafePublicAdapterOutputAuthorizationDraft,
    LivesafePublicAdapterOutputAuthorizationEnvelope,
    LivesafePublicAdapterOutputAuthorizationProof,
    LivesafePublicAdapterOutputAuthorizationRevocationStatus,
    livesafe_public_adapter_output_authorization_action_commitment_hash,
    livesafe_public_adapter_output_authorization_action_request,
    livesafe_public_adapter_output_authorization_idempotency_hash,
    mint_livesafe_public_adapter_output_authorization_proof,
    validate_livesafe_public_adapter_output_authorization,
    verify_livesafe_public_adapter_output_authorization_proof,
};
pub use receipt::{
    AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN, AVC_RECEIPT_EXTERNAL_TIMESTAMP_DOMAIN,
    AVC_RECEIPT_SIGNING_DOMAIN, AvcReceiptEvidenceSubject, AvcReceiptExternalTimestampProof,
    AvcReceiptExternalTimestampProofKind, AvcReceiptRfc3161TimestampProof,
    AvcReceiptRfc3161TrustAnchorKind, AvcReceiptTimestampProvenance, AvcTrustReceipt,
    AvcTrustReceiptEvidence, create_trust_receipt, create_trust_receipt_with_evidence,
};
pub use registry::{
    AvcRegistryDurableState, AvcRegistryRead, AvcRegistryWrite, InMemoryAvcRegistry,
    RegisteredIssuerKey,
};
pub use revocation::{
    AVC_REVOCATION_SIGNING_DOMAIN, AvcRevocation, AvcRevocationReason, revoke_avc,
};
pub use validation::{
    AVC_ACTION_COMMITMENT_DOMAIN, AVC_ACTION_DESCRIPTOR_DOMAIN, AVC_ACTION_SIGNING_DOMAIN,
    AVC_HUMAN_APPROVAL_SIGNING_DOMAIN, AVC_LLM_USAGE_ACTION_NAME, AvcActionDescriptor,
    AvcActionRequest, AvcDecision, AvcHumanApproval, AvcReasonCode, AvcValidationRequest,
    AvcValidationResult, avc_action_commitment_hash, avc_action_descriptor_hash,
    avc_action_signature_payload, avc_llm_usage_action_request, human_approval_signature_payload,
    validate_avc,
};

/// All AVC signing domains as a sorted slice — used by hygiene tests
/// and external auditors who need to ensure no domain collisions.
pub const AVC_SIGNING_DOMAINS: &[&str] = &[
    AVC_ACTION_COMMITMENT_DOMAIN,
    AVC_ACTION_DESCRIPTOR_DOMAIN,
    AVC_ACTION_SIGNING_DOMAIN,
    AVC_CREDENTIAL_SIGNING_DOMAIN,
    AVC_HUMAN_APPROVAL_SIGNING_DOMAIN,
    AVC_LLM_USAGE_EVIDENCE_DOMAIN,
    AVC_LLM_USAGE_EVIDENCE_SIGNATURE_DOMAIN,
    LIVESAFE_PUBLIC_OUTPUT_CREDENTIAL_CEREMONY_DOMAIN,
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
    AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN,
    AVC_RECEIPT_EXTERNAL_TIMESTAMP_DOMAIN,
    AVC_RECEIPT_SIGNING_DOMAIN,
    AVC_REVOCATION_SIGNING_DOMAIN,
];

#[cfg(test)]
mod hygiene_tests {
    use super::*;

    #[test]
    fn signing_domains_are_distinct() {
        let mut sorted = AVC_SIGNING_DOMAINS.to_vec();
        sorted.sort_unstable();
        let original_len = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), original_len, "signing domains must be unique");
    }

    #[test]
    fn signing_domains_are_versioned() {
        for d in AVC_SIGNING_DOMAINS {
            assert!(d.contains(".v1"), "domain {d} must be version-tagged");
        }
    }

    #[test]
    fn no_hashmap_or_hashset_in_production_sources() {
        let sources = [
            include_str!("credential.rs"),
            include_str!("delegation.rs"),
            include_str!("error.rs"),
            include_str!("livesafe_public_output_ceremony.rs"),
            include_str!("lib.rs"),
            include_str!("llm_usage_receipt.rs"),
            include_str!("public_output_authorization.rs"),
            include_str!("receipt.rs"),
            include_str!("registry.rs"),
            include_str!("revocation.rs"),
            include_str!("validation.rs"),
        ];
        let banned_map = ["Hash", "Map"].concat();
        let banned_set = ["Hash", "Set"].concat();
        for src in sources {
            // Strip everything from `#[cfg(test)]` onward — tests may
            // reference banned tokens in identifiers.
            let production = src.split("#[cfg(test)]").next().unwrap();
            assert!(
                !production.contains(&banned_map),
                "AVC production sources must not use HashMap"
            );
            assert!(
                !production.contains(&banned_set),
                "AVC production sources must not use HashSet"
            );
        }
    }

    #[test]
    fn no_floating_point_in_production_sources() {
        let sources = [
            include_str!("credential.rs"),
            include_str!("delegation.rs"),
            include_str!("error.rs"),
            include_str!("livesafe_public_output_ceremony.rs"),
            include_str!("lib.rs"),
            include_str!("llm_usage_receipt.rs"),
            include_str!("public_output_authorization.rs"),
            include_str!("receipt.rs"),
            include_str!("registry.rs"),
            include_str!("revocation.rs"),
            include_str!("validation.rs"),
        ];
        for src in sources {
            let production = src.split("#[cfg(test)]").next().unwrap();
            for token in [": f32", ": f64", "as f32", "as f64", "f32::", "f64::"] {
                assert!(
                    !production.contains(token),
                    "AVC production sources must not contain `{token}`"
                );
            }
        }
    }
}

#[cfg(test)]
mod public_output_authorization_tests {
    use exo_authority::permission::Permission;
    use exo_core::{Did, Hash256, Timestamp, crypto::KeyPair};

    use super::*;

    const ISSUER_SEED: [u8; 32] = [0x11; 32];
    const PROOF_SIGNER_SEED: [u8; 32] = [0x33; 32];

    fn issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ISSUER_SEED).expect("valid issuer seed")
    }

    fn proof_signer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(PROOF_SIGNER_SEED).expect("valid proof signer seed")
    }

    fn did(value: &str) -> Did {
        Did::new(value).expect("valid DID")
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn h256(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn livesafe_draft() -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: did("did:exo:livesafe-issuer"),
            principal_did: did("did:exo:livesafe-issuer"),
            subject_did: did("did:exo:livesafe-public-adapter"),
            holder_did: None,
            subject_kind: AvcSubjectKind::Service {
                service_id: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
            },
            created_at: ts(1_000_000),
            expires_at: Some(ts(2_000_000)),
            delegated_intent: DelegatedIntent {
                intent_id: h256(0xA1),
                purpose: "Authorize narrow LiveSafe public adapter output".into(),
                allowed_objectives: vec![
                    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
                ],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::ExecuteWithinBounds,
                delegation_allowed: false,
            },
            authority_scope: AuthorityScope {
                permissions: vec![Permission::Read],
                tools: vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into()],
                data_classes: vec![DataClass::Public],
                counterparties: vec![],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints {
                allowed_time_window: Some(TimeWindow {
                    not_before: ts(1_000_000),
                    not_after: ts(2_000_000),
                }),
                ..AvcConstraints::permissive()
            },
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        }
    }

    fn bind_ceremony_intent(draft: &mut AvcDraft, evidence_hash: Hash256) {
        let expires_at = draft
            .expires_at
            .expect("LiveSafe public-output test credential expiry");
        draft.delegated_intent.intent_id =
            crate::livesafe_public_output_ceremony::livesafe_public_output_credential_ceremony_intent_id(
                &crate::livesafe_public_output_ceremony::LivesafePublicOutputCredentialCeremonyIntentInput {
                    issuer_did: &draft.issuer_did,
                    credential_subject_did: &draft.subject_did,
                    public_subject: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
                    public_audience: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
                    allowed_claim_names: &draft.delegated_intent.allowed_objectives,
                    evidence_hash: &evidence_hash,
                    not_before: &draft.created_at,
                    expires_at: &expires_at,
                },
            )
            .expect("LiveSafe public-output test ceremony intent id");
    }

    fn issue_credential(mut draft: AvcDraft) -> AutonomousVolitionCredential {
        let issuer = issuer_keypair();
        if draft.issuer_did != did("did:exo:livesafe-issuer") {
            draft.issuer_did = did("did:exo:livesafe-issuer");
            draft.principal_did = did("did:exo:livesafe-issuer");
        }
        bind_ceremony_intent(&mut draft, h256(0xE1));
        issue_avc(draft, |bytes| issuer.sign(bytes)).expect("valid LiveSafe AVC")
    }

    fn registry_with_issuer(grant: Option<Vec<Permission>>) -> InMemoryAvcRegistry {
        let mut registry = InMemoryAvcRegistry::new();
        registry.put_public_key(did("did:exo:livesafe-issuer"), issuer_keypair().public);
        if let Some(granted_permissions) = grant {
            registry
                .put_issuer_permission_grant(did("did:exo:livesafe-issuer"), granted_permissions);
        }
        registry
    }

    fn draft_for(
        credential: AutonomousVolitionCredential,
    ) -> LivesafePublicAdapterOutputAuthorizationDraft {
        let idempotency_key_hash =
            livesafe_public_adapter_output_authorization_idempotency_hash("idem-live-1")
                .expect("idempotency hash");
        let evidence_hash = h256(0xE1);
        let issued_at = ts(1_500_000);
        let expires_at = ts(1_700_000);
        let action_commitment_hash =
            livesafe_public_adapter_output_authorization_action_commitment_hash(
                &credential,
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
                LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
                evidence_hash,
                idempotency_key_hash,
                &issued_at,
                &expires_at,
            )
            .expect("action commitment");
        LivesafePublicAdapterOutputAuthorizationDraft {
            credential,
            subject: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
            audience: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE.into(),
            evidence_hash,
            credential_id: None,
            receipt_id: h256(0xC1),
            action_commitment_hash,
            idempotency_key_hash,
            issued_at,
            expires_at,
            signer_did: did("did:exo:public-output-proof-signer"),
        }
    }

    fn mint(
        draft: LivesafePublicAdapterOutputAuthorizationDraft,
        registry: &InMemoryAvcRegistry,
    ) -> Result<LivesafePublicAdapterOutputAuthorizationEnvelope, AvcError> {
        mint_livesafe_public_adapter_output_authorization_proof(draft, registry, |bytes| {
            proof_signer_keypair().sign(bytes)
        })
    }

    fn sign_unchecked(
        draft: LivesafePublicAdapterOutputAuthorizationDraft,
    ) -> Result<LivesafePublicAdapterOutputAuthorizationEnvelope, AvcError> {
        crate::public_output_authorization::sign_livesafe_public_adapter_output_authorization_proof_unchecked(
            draft,
            |bytes| proof_signer_keypair().sign(bytes),
        )
    }

    #[test]
    fn public_output_authorization_denies_missing_issuer_grant() {
        let credential = issue_credential(livesafe_draft());
        let registry = registry_with_issuer(None);

        let error = mint(draft_for(credential), &registry).expect_err("missing issuer grant");

        assert!(error.to_string().contains("issuer grant"));
    }

    #[test]
    fn public_output_authorization_denies_grant_without_narrow_permission() {
        let credential = issue_credential(livesafe_draft());
        let registry = registry_with_issuer(Some(vec![Permission::Write]));

        let error = mint(draft_for(credential), &registry).expect_err("missing Read grant");

        assert!(error.to_string().contains("Permission::Read"));
    }

    #[test]
    fn public_output_authorization_denies_expired_credential() {
        let mut draft = livesafe_draft();
        draft.expires_at = Some(ts(1_400_000));
        let credential = issue_credential(draft);
        let registry = registry_with_issuer(Some(vec![Permission::Read]));

        let error = mint(draft_for(credential), &registry).expect_err("expired credential");

        assert!(error.to_string().contains("Expired"));
    }

    #[test]
    fn public_output_authorization_denies_revoked_credential() {
        let credential = issue_credential(livesafe_draft());
        let credential_id = credential.id().expect("credential id");
        let mut registry = registry_with_issuer(Some(vec![Permission::Read]));
        registry
            .put_credential(credential.clone())
            .expect("stored credential");
        let revocation = revoke_avc(
            credential_id,
            did("did:exo:livesafe-issuer"),
            AvcRevocationReason::IssuerRevoked,
            ts(1_450_000),
            |bytes| issuer_keypair().sign(bytes),
        )
        .expect("signed revocation");
        registry
            .put_revocation(revocation)
            .expect("stored revocation");

        let error = mint(draft_for(credential), &registry).expect_err("revoked credential");

        assert!(error.to_string().contains("Revoked"));
    }

    #[test]
    fn public_output_authorization_denies_non_livesafe_service_subject() {
        let mut draft = livesafe_draft();
        draft.subject_kind = AvcSubjectKind::Service {
            service_id: "example.invalid".into(),
        };
        let credential = issue_credential(draft);
        let registry = registry_with_issuer(Some(vec![Permission::Read]));

        let error = mint(draft_for(credential), &registry).expect_err("wrong service subject");

        assert!(error.to_string().contains("livesafe.ai"));
    }

    #[test]
    fn public_output_authorization_denies_wrong_audience() {
        let credential = issue_credential(livesafe_draft());
        let registry = registry_with_issuer(Some(vec![Permission::Read]));
        let mut draft = draft_for(credential);
        draft.audience = "https://example.invalid/trust/status".into();

        let error = mint(draft, &registry).expect_err("wrong audience");

        assert!(error.to_string().contains("audience"));
    }

    #[test]
    fn public_output_authorization_denies_tampered_evidence_hash_after_signing() {
        let credential = issue_credential(livesafe_draft());
        let registry = registry_with_issuer(Some(vec![Permission::Read]));
        let mut envelope = mint(draft_for(credential), &registry).expect("mint proof");
        envelope.proof.evidence_hash = h256(0xE2);

        let error = verify_livesafe_public_adapter_output_authorization_proof(
            &envelope.proof,
            &proof_signer_keypair().public,
        )
        .expect_err("tampered proof rejected");

        assert!(error.to_string().contains("signature"));
    }

    #[test]
    fn public_output_authorization_action_commitment_binds_expiry() {
        let credential = issue_credential(livesafe_draft());
        let base = draft_for(credential.clone());
        let mut changed_expiry = draft_for(credential);
        changed_expiry.expires_at = ts(1_800_000);
        changed_expiry.action_commitment_hash =
            livesafe_public_adapter_output_authorization_action_commitment_hash(
                &changed_expiry.credential,
                &changed_expiry.subject,
                &changed_expiry.audience,
                changed_expiry.evidence_hash,
                changed_expiry.idempotency_key_hash,
                &changed_expiry.issued_at,
                &changed_expiry.expires_at,
            )
            .expect("changed-expiry commitment");

        assert_ne!(
            base.action_commitment_hash, changed_expiry.action_commitment_hash,
            "public-output action commitment must bind expires_at"
        );
    }

    #[test]
    fn public_output_authorization_payload_binds_public_claim_identity() {
        let credential = issue_credential(livesafe_draft());
        let base = sign_unchecked(draft_for(credential.clone()))
            .expect("base proof")
            .proof;

        let mut changed_subject = draft_for(credential.clone());
        changed_subject.subject = "example.invalid".into();
        let changed_subject = sign_unchecked(changed_subject)
            .expect("changed subject signed payload")
            .proof;
        assert_ne!(base.proof_hash, changed_subject.proof_hash);
        assert_ne!(base.signature, changed_subject.signature);

        let mut changed_audience = draft_for(credential.clone());
        changed_audience.audience = "https://livesafe.ai/api/trust/status?variant=preview".into();
        let changed_audience = sign_unchecked(changed_audience)
            .expect("changed audience signed payload")
            .proof;
        assert_ne!(base.proof_hash, changed_audience.proof_hash);
        assert_ne!(base.signature, changed_audience.signature);

        for variant in [
            {
                let mut d = draft_for(credential.clone());
                d.evidence_hash = h256(0xE3);
                d.action_commitment_hash =
                    livesafe_public_adapter_output_authorization_action_commitment_hash(
                        &d.credential,
                        &d.subject,
                        &d.audience,
                        d.evidence_hash,
                        d.idempotency_key_hash,
                        &d.issued_at,
                        &d.expires_at,
                    )
                    .expect("variant commitment");
                d
            },
            {
                let mut d = draft_for(credential.clone());
                d.expires_at = ts(1_800_000);
                d.action_commitment_hash =
                    livesafe_public_adapter_output_authorization_action_commitment_hash(
                        &d.credential,
                        &d.subject,
                        &d.audience,
                        d.evidence_hash,
                        d.idempotency_key_hash,
                        &d.issued_at,
                        &d.expires_at,
                    )
                    .expect("variant commitment");
                d
            },
            {
                let mut altered = livesafe_draft();
                altered.created_at = ts(1_000_001);
                altered.constraints.allowed_time_window = Some(TimeWindow {
                    not_before: ts(1_000_001),
                    not_after: ts(2_000_000),
                });
                draft_for(issue_credential(altered))
            },
            {
                let mut d = draft_for(credential.clone());
                d.idempotency_key_hash =
                    livesafe_public_adapter_output_authorization_idempotency_hash("idem-live-2")
                        .expect("idempotency hash");
                d.action_commitment_hash =
                    livesafe_public_adapter_output_authorization_action_commitment_hash(
                        &d.credential,
                        &d.subject,
                        &d.audience,
                        d.evidence_hash,
                        d.idempotency_key_hash,
                        &d.issued_at,
                        &d.expires_at,
                    )
                    .expect("variant commitment");
                d
            },
        ] {
            let proof = sign_unchecked(variant).expect("variant proof").proof;
            assert_ne!(base.proof_hash, proof.proof_hash);
            assert_ne!(base.signature, proof.signature);
        }
    }
}
