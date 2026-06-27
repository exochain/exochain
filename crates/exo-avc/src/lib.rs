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
pub use receipt::{
    AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN, AVC_RECEIPT_EXTERNAL_TIMESTAMP_DOMAIN,
    AVC_RECEIPT_SIGNING_DOMAIN, AvcReceiptEvidenceSubject, AvcReceiptExternalTimestampProof,
    AvcReceiptExternalTimestampProofKind, AvcReceiptRfc3161TimestampProof,
    AvcReceiptTimestampProvenance, AvcTrustReceipt, AvcTrustReceiptEvidence, create_trust_receipt,
    create_trust_receipt_with_evidence,
};
pub use registry::{
    AvcRegistryDurableState, AvcRegistryRead, AvcRegistryWrite, InMemoryAvcRegistry,
};
pub use revocation::{
    AVC_REVOCATION_SIGNING_DOMAIN, AvcRevocation, AvcRevocationReason, revoke_avc,
};
pub use validation::{
    AVC_ACTION_COMMITMENT_DOMAIN, AVC_ACTION_DESCRIPTOR_DOMAIN, AVC_ACTION_SIGNING_DOMAIN,
    AVC_HUMAN_APPROVAL_SIGNING_DOMAIN, AvcActionDescriptor, AvcActionRequest, AvcDecision,
    AvcHumanApproval, AvcReasonCode, AvcValidationRequest, AvcValidationResult,
    avc_action_commitment_hash, avc_action_descriptor_hash, avc_action_signature_payload,
    human_approval_signature_payload, validate_avc,
};

/// All AVC signing domains as a sorted slice — used by hygiene tests
/// and external auditors who need to ensure no domain collisions.
pub const AVC_SIGNING_DOMAINS: &[&str] = &[
    AVC_ACTION_COMMITMENT_DOMAIN,
    AVC_ACTION_DESCRIPTOR_DOMAIN,
    AVC_ACTION_SIGNING_DOMAIN,
    AVC_CREDENTIAL_SIGNING_DOMAIN,
    AVC_HUMAN_APPROVAL_SIGNING_DOMAIN,
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
            include_str!("lib.rs"),
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
            include_str!("lib.rs"),
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
