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

//! Authorized Action Evidence Pack — Counsel Edition (SKU B).
//!
//! Wraps an evidence-pack hash, an [`EvidenceBundle`] hash, a FRE 902(11)
//! certificate hash, and an optional AI transparency report hash. This is
//! not a LegalDyne product and is not a legal opinion. Human declarant
//! completion and counsel review remain mandatory before filing.

use exo_core::{Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    bundle::EvidenceBundle,
    cert_902_11::Cert902_11,
    error::{LegalError, Result},
};

/// Wire schema id for the counsel pack.
pub const AUTHORIZED_ACTION_COUNSEL_PACK_SCHEMA: &str = "authorized_action_counsel_pack.v1";
/// Domain tag for the canonical counsel-pack hash.
pub const AUTHORIZED_ACTION_COUNSEL_PACK_DOMAIN: &str =
    "exo.legal.authorized_action_counsel_pack.v1";
const AUTHORIZED_ACTION_COUNSEL_PACK_SCHEMA_VERSION: u16 = 1;
const DECLARANT_TEMPLATE: &str =
    "[DECLARANT NAME, TITLE, ORGANIZATION — COMPLETE BEFORE FILING]";

/// Hash-only assembly input. Callers supply HLC time; this module does not
/// read the wall clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembleAuthorizedActionCounselPackInput {
    pub evidence_pack_hash: Hash256,
    pub bundle_hash: Hash256,
    pub cert_902_11_hash: Hash256,
    pub declarant_placeholder: String,
    pub ai_transparency_report_hash: Option<Hash256>,
    pub counsel_attested: bool,
    pub created_at: Timestamp,
}

/// Counsel / compliance export. `filing_ready` is true only after a human
/// declarant is completed and counsel has attested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedActionCounselPack {
    pub schema: String,
    pub evidence_pack_hash: Hash256,
    pub bundle_hash: Hash256,
    pub cert_902_11_hash: Hash256,
    pub ai_transparency_report_hash: Option<Hash256>,
    pub declarant_completed: bool,
    pub counsel_review_required: bool,
    pub counsel_attested: bool,
    pub filing_ready: bool,
    pub filing_disclaimer: String,
    pub created_at: Timestamp,
    pub pack_hash: Hash256,
}

#[derive(Serialize)]
struct AuthorizedActionCounselPackHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    schema: &'a str,
    evidence_pack_hash: &'a Hash256,
    bundle_hash: &'a Hash256,
    cert_902_11_hash: &'a Hash256,
    ai_transparency_report_hash: Option<&'a Hash256>,
    declarant_completed: bool,
    counsel_review_required: bool,
    counsel_attested: bool,
    filing_ready: bool,
    filing_disclaimer: &'a str,
    created_at: &'a Timestamp,
}

/// True when the 902(11) declarant field is still the generator template.
#[must_use]
pub fn declarant_placeholder_incomplete(declarant: &str) -> bool {
    let trimmed = declarant.trim();
    trimmed.is_empty()
        || trimmed == DECLARANT_TEMPLATE
        || trimmed.contains("COMPLETE BEFORE FILING")
        || trimmed.contains("DECLARANT NAME")
}

/// Assemble the counsel pack from hashes and the 902(11) declarant field.
///
/// # Errors
/// Returns [`LegalError::InvalidStateTransition`] when the declarant
/// placeholder is still present, required hashes are zero, or `created_at`
/// is zero.
pub fn assemble_authorized_action_counsel_pack(
    input: &AssembleAuthorizedActionCounselPackInput,
) -> Result<AuthorizedActionCounselPack> {
    if input.evidence_pack_hash == Hash256::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "counsel pack requires a non-zero evidence_pack_hash".into(),
        });
    }
    if input.bundle_hash == Hash256::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "counsel pack requires a non-zero bundle_hash".into(),
        });
    }
    if input.cert_902_11_hash == Hash256::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "counsel pack requires a non-zero cert_902_11_hash".into(),
        });
    }
    if input.created_at == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "counsel pack created_at must be a caller-supplied HLC timestamp".into(),
        });
    }
    if declarant_placeholder_incomplete(&input.declarant_placeholder) {
        return Err(LegalError::InvalidStateTransition {
            reason: "FRE 902(11) declarant_placeholder must be completed by a qualified human declarant"
                .into(),
        });
    }
    let declarant_completed = true;
    let counsel_review_required = true;
    let filing_ready = declarant_completed && input.counsel_attested;
    let mut pack = AuthorizedActionCounselPack {
        schema: AUTHORIZED_ACTION_COUNSEL_PACK_SCHEMA.into(),
        evidence_pack_hash: input.evidence_pack_hash,
        bundle_hash: input.bundle_hash,
        cert_902_11_hash: input.cert_902_11_hash,
        ai_transparency_report_hash: input.ai_transparency_report_hash,
        declarant_completed,
        counsel_review_required,
        counsel_attested: input.counsel_attested,
        filing_ready,
        filing_disclaimer: Cert902_11::FILING_DISCLAIMER.into(),
        created_at: input.created_at,
        pack_hash: Hash256::ZERO,
    };
    pack.pack_hash = hash_counsel_pack(&pack)?;
    Ok(pack)
}

/// Assemble from an evidence bundle snapshot plus the SKU A pack hash.
///
/// # Errors
/// Returns [`LegalError::InvalidStateTransition`] when the bundle has no
/// 902(11) certification or the declarant is still a placeholder.
pub fn assemble_authorized_action_counsel_pack_from_bundle(
    evidence_pack_hash: Hash256,
    bundle: &EvidenceBundle,
    ai_transparency_report_hash: Option<Hash256>,
    counsel_attested: bool,
    created_at: Timestamp,
) -> Result<AuthorizedActionCounselPack> {
    let certification = bundle.certification.as_ref().ok_or_else(|| {
        LegalError::InvalidStateTransition {
            reason: "counsel pack requires an EvidenceBundle with FRE 902(11) certification"
                .into(),
        }
    })?;
    assemble_authorized_action_counsel_pack(&AssembleAuthorizedActionCounselPackInput {
        evidence_pack_hash,
        bundle_hash: bundle.bundle_hash,
        cert_902_11_hash: certification.cert_hash,
        declarant_placeholder: certification.declarant_placeholder.clone(),
        ai_transparency_report_hash,
        counsel_attested,
        created_at,
    })
}

fn hash_counsel_pack(pack: &AuthorizedActionCounselPack) -> Result<Hash256> {
    let payload = AuthorizedActionCounselPackHashPayload {
        domain: AUTHORIZED_ACTION_COUNSEL_PACK_DOMAIN,
        schema_version: AUTHORIZED_ACTION_COUNSEL_PACK_SCHEMA_VERSION,
        schema: &pack.schema,
        evidence_pack_hash: &pack.evidence_pack_hash,
        bundle_hash: &pack.bundle_hash,
        cert_902_11_hash: &pack.cert_902_11_hash,
        ai_transparency_report_hash: pack.ai_transparency_report_hash.as_ref(),
        declarant_completed: pack.declarant_completed,
        counsel_review_required: pack.counsel_review_required,
        counsel_attested: pack.counsel_attested,
        filing_ready: pack.filing_ready,
        filing_disclaimer: &pack.filing_disclaimer,
        created_at: &pack.created_at,
    };
    hash_structured(&payload).map_err(|err| LegalError::InvalidStateTransition {
        reason: format!("counsel pack hash encoding failed: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bundle::{
            BundleAssemblyInput, BundleEvent, BundleSubject, DagAnchor, SubjectType, ValidatorSig,
            assemble,
        },
        cert_902_11::generate_902_11_cert,
        evidence::create_evidence,
    };
    use exo_core::{Did, Signature};
    use uuid::Uuid;

    fn did(suffix: &str) -> Did {
        Did::new(&format!("did:exo:{suffix}")).unwrap()
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn completed_input(counsel_attested: bool) -> AssembleAuthorizedActionCounselPackInput {
        AssembleAuthorizedActionCounselPackInput {
            evidence_pack_hash: h(0xA1),
            bundle_hash: h(0xB2),
            cert_902_11_hash: h(0xC3),
            declarant_placeholder: "Jane Custodian, Records Officer, Example Org".into(),
            ai_transparency_report_hash: Some(h(0xD4)),
            counsel_attested,
            created_at: ts(1_800),
        }
    }

    fn make_event() -> BundleEvent {
        BundleEvent {
            sequence: 0,
            event_hash: Hash256::digest(b"event-0"),
            event_type: "test.event.0".into(),
            actor: did("alice"),
            timestamp: ts(1_000),
            payload_summary: "genesis".into(),
            parent_hashes: vec![],
            dag_node_hash: Hash256::digest(b"dag-0"),
        }
    }

    fn assemble_bundle_with_placeholder_cert() -> EvidenceBundle {
        let evidence = create_evidence(
            Uuid::from_u128(0x900),
            b"test-data",
            &did("bob"),
            "document",
            ts(900),
        )
        .unwrap();
        let cert =
            generate_902_11_cert(&evidence, "EXOCHAIN AVC evidence pack v1", 1_700_000_001_000)
                .unwrap();
        assemble(BundleAssemblyInput {
            id: "bundle-counsel".into(),
            created_at: ts(2_500),
            subject: BundleSubject {
                subject_type: SubjectType::Decision,
                subject_id: "DEC-COUNSEL".into(),
                title: "Authorized action".into(),
                description: "Counsel export fixture".into(),
            },
            events: vec![make_event()],
            evidence_items: vec![evidence],
            consent_records: vec![],
            contract_summary: None,
            certification: Some(cert),
            dag_anchor: DagAnchor {
                checkpoint_height: 1,
                event_root: Hash256::digest(b"mmr"),
                state_root: Hash256::digest(b"smt"),
                validator_signatures: vec![ValidatorSig {
                    validator_did: did("validator"),
                    signature: Signature::from_bytes([0xaa; 64]),
                }],
                anchored_at: ts(2_000),
            },
        })
        .unwrap()
    }

    #[test]
    fn completed_declarant_without_counsel_is_not_filing_ready() {
        let pack = assemble_authorized_action_counsel_pack(&completed_input(false)).unwrap();
        assert_eq!(pack.schema, AUTHORIZED_ACTION_COUNSEL_PACK_SCHEMA);
        assert!(pack.declarant_completed);
        assert!(pack.counsel_review_required);
        assert!(!pack.counsel_attested);
        assert!(!pack.filing_ready);
        assert_eq!(pack.filing_disclaimer, Cert902_11::FILING_DISCLAIMER);
        assert_ne!(pack.pack_hash, Hash256::ZERO);
    }

    #[test]
    fn filing_ready_requires_declarant_and_counsel() {
        let pack = assemble_authorized_action_counsel_pack(&completed_input(true)).unwrap();
        assert!(pack.filing_ready);
        let again = assemble_authorized_action_counsel_pack(&completed_input(true)).unwrap();
        assert_eq!(pack, again);
    }

    #[test]
    fn rejects_generator_placeholder() {
        let mut input = completed_input(true);
        input.declarant_placeholder = DECLARANT_TEMPLATE.into();
        let err = assemble_authorized_action_counsel_pack(&input).unwrap_err();
        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
    }

    #[test]
    fn bundle_with_generated_902_11_cert_fails_closed() {
        let bundle = assemble_bundle_with_placeholder_cert();
        let err = assemble_authorized_action_counsel_pack_from_bundle(
            h(0xA1),
            &bundle,
            None,
            true,
            ts(1_800),
        )
        .unwrap_err();
        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
    }

    #[test]
    fn pack_hash_changes_when_evidence_pack_hash_changes() {
        let left = assemble_authorized_action_counsel_pack(&completed_input(true)).unwrap();
        let mut changed = completed_input(true);
        changed.evidence_pack_hash = h(0xFF);
        let right = assemble_authorized_action_counsel_pack(&changed).unwrap();
        assert_ne!(left.pack_hash, right.pack_hash);
    }
}
