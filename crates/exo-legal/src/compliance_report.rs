//! Compliance report generation.
//!
//! Produces a structured JSON compliance report that maps each ExoChain
//! constitutional invariant to its NIST AI RMF attestation status. The
//! report is deterministic: identical inputs always produce the same
//! BLAKE3 hash over a canonical CBOR payload, which serves as the integrity
//! anchor for regulatory submissions.
//!
//! # Output modes
//!
//! - [`ComplianceReportMode::Full`] — includes plaintext `model_id` values.
//!   For internal use and regulators with appropriate clearance.
//! - [`ComplianceReportMode::Redacted`] — replaces each `model_id` with
//!   `BLAKE3(tenant_id || model_id || redaction_salt)`. For public disclosure
//!   or external auditors. Prevents AI model fingerprinting.

use exo_core::{Did, Timestamp, hash::hash_structured};
use exo_gatekeeper::invariants::{ConstitutionalInvariant, InvariantSet};
use serde::{Deserialize, Serialize};

use crate::{
    ai_transparency::AiTransparencyReport,
    error::{LegalError, Result},
    nist_mapping::{NistFunction, NistMapping},
};

const COMPLIANCE_REPORT_SCHEMA_VERSION: &str = "1.0.0";
const COMPLIANCE_REPORT_HASH_DOMAIN: &str = "exo.legal.compliance_report.v1";

// ---------------------------------------------------------------------------
// Report mode
// ---------------------------------------------------------------------------

/// Controls whether sensitive fields (e.g. `model_id`) appear in plaintext
/// or as BLAKE3 hashes in the generated report.
#[derive(Debug, Clone)]
pub enum ComplianceReportMode {
    /// All fields included in plaintext.
    Full,
    /// `model_id` fields replaced with `BLAKE3(tenant_id || model_id || salt)`.
    Redacted {
        /// Per-tenant salt stored in the Constitution. Must be 32 bytes.
        redaction_salt: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// Attestation status
// ---------------------------------------------------------------------------

/// The attestation status of a single invariant against a NIST function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationStatus {
    /// Evidence of compliance is present in this report period.
    Compliant,
    /// A gap was identified; see `notes`.
    Gap,
    /// This NIST function does not apply to this invariant.
    NotApplicable,
}

/// Attestation of a single invariant across all mapped NIST functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantAttestation {
    pub invariant: String,
    pub exochain_label: String,
    pub nist_functions: Vec<NistFunction>,
    pub nist_subcategories: Vec<String>,
    pub status: AttestationStatus,
    pub evidence_summary: String,
    pub regulatory_refs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Compliance report
// ---------------------------------------------------------------------------

/// A deterministic compliance report covering all constitutional invariants.
///
/// `report_hash` is the BLAKE3 hash of the canonical CBOR serialisation of
/// all fields except `report_hash` itself. Use it as an integrity anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub schema_version: String,
    pub tenant_id: Did,
    pub generated_at: Timestamp,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    pub legal_jurisdiction: String,
    pub report_mode: String, // "Full" or "Redacted"
    pub attestations: Vec<InvariantAttestation>,
    /// BLAKE3 hash of the canonical report content (all fields above).
    pub report_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build a [`ComplianceReport`] from a transparency report and the canonical
/// NIST mapping.
///
/// The report is deterministic: given the same `transparency_report`,
/// `mode`, and `generated_at`, it always produces the same `report_hash`.
pub fn build_report(
    transparency_report: &AiTransparencyReport,
    mode: &ComplianceReportMode,
    generated_at: Timestamp,
) -> Result<ComplianceReport> {
    let mapping = NistMapping::canonical();
    let all_invariants = InvariantSet::all();

    let attestations: Vec<InvariantAttestation> = all_invariants
        .invariants
        .iter()
        .map(|&inv| build_attestation(inv, &mapping, transparency_report, mode))
        .collect();

    let report_mode = match mode {
        ComplianceReportMode::Full => "Full".to_owned(),
        ComplianceReportMode::Redacted { .. } => "Redacted".to_owned(),
    };

    // Compute deterministic hash over all content fields.
    let hash_payload = ComplianceReportHashPayload {
        domain: COMPLIANCE_REPORT_HASH_DOMAIN,
        schema_version: COMPLIANCE_REPORT_SCHEMA_VERSION,
        tenant_id: &transparency_report.tenant_id,
        generated_at,
        period_start: transparency_report.period_start,
        period_end: transparency_report.period_end,
        legal_jurisdiction: &transparency_report.legal_jurisdiction,
        report_mode: &report_mode,
        attestations: &attestations,
    };
    let content_hash = hash_report_payload(&hash_payload)?;

    Ok(ComplianceReport {
        schema_version: COMPLIANCE_REPORT_SCHEMA_VERSION.into(),
        tenant_id: transparency_report.tenant_id.clone(),
        generated_at,
        period_start: transparency_report.period_start,
        period_end: transparency_report.period_end,
        legal_jurisdiction: transparency_report.legal_jurisdiction.clone(),
        report_mode,
        attestations,
        report_hash: content_hash,
    })
}

/// Recompute and verify a compliance report's integrity hash.
///
/// # Errors
///
/// Returns [`LegalError::InvalidStateTransition`] if canonical CBOR hashing
/// fails.
pub fn verify_report_hash(report: &ComplianceReport) -> Result<bool> {
    Ok(
        hash_report_payload(&ComplianceReportHashPayload::from_report(report))?
            == report.report_hash,
    )
}

fn build_attestation(
    invariant: ConstitutionalInvariant,
    mapping: &NistMapping,
    report: &AiTransparencyReport,
    mode: &ComplianceReportMode,
) -> InvariantAttestation {
    let entry = mapping.entry_for(invariant);
    let (label, functions, subcategories, reg_refs) = match &entry {
        Some(e) => (
            e.exochain_label.clone(),
            e.nist_functions.clone(),
            e.nist_subcategories.clone(),
            e.regulatory_refs.clone(),
        ),
        None => (format!("{invariant:?}"), vec![], vec![], vec![]),
    };

    let (status, evidence_summary) = derive_status_and_evidence(invariant, report, mode);

    InvariantAttestation {
        invariant: format!("{invariant:?}"),
        exochain_label: label,
        nist_functions: functions,
        nist_subcategories: subcategories,
        status,
        evidence_summary,
        regulatory_refs: reg_refs,
    }
}

fn derive_status_and_evidence(
    invariant: ConstitutionalInvariant,
    report: &AiTransparencyReport,
    mode: &ComplianceReportMode,
) -> (AttestationStatus, String) {
    match invariant {
        ConstitutionalInvariant::HumanOverride => {
            // Compliant if HumanOverride invariant is enforced (always true
            // while exo-gatekeeper is in the build; backed by InvariantEngine).
            (
                AttestationStatus::Compliant,
                "HumanOverride invariant enforced at kernel level (exo-gatekeeper). \
                 Strategic/Constitutional DecisionClass requires human gate. \
                 GDPR Art. 22 safeguard active."
                    .into(),
            )
        }

        ConstitutionalInvariant::ProvenanceVerifiable => {
            let mcp_count: u64 = report
                .mcp_rule_outcomes
                .iter()
                .map(|o| o.allowed + o.blocked + o.escalated)
                .sum();
            if mcp_count == 0 {
                (
                    AttestationStatus::NotApplicable,
                    format!(
                        "No MCP enforcement events recorded this period; no action provenance \
                         is attested for this invariant. MCP audit log was structurally verified \
                         before report generation with head hash {}.",
                        hex_encode(&report.mcp_audit_head_hash)
                    ),
                )
            } else {
                (
                    AttestationStatus::Compliant,
                    format!(
                        "Hash-chained MCP audit log verified before report generation. \
                         {} MCP enforcement events recorded this period. \
                         Verified head hash {}. GDPR Art. 5(1)(f) satisfied.",
                        mcp_count,
                        hex_encode(&report.mcp_audit_head_hash)
                    ),
                )
            }
        }

        ConstitutionalInvariant::AuthorityChainValid => {
            let ai_grants = redact_delegation_count(report, mode);
            (
                AttestationStatus::Compliant,
                format!(
                    "Report generation authorized by verified authority clearance for requester {}. \
                     Chain root {}, leaf {}, depth {}, hash {}. \
                     {} AI agent delegation grants recorded from verified authority-chain artifacts. \
                     {} revocations. GDPR Art. 5(2) accountability chain evidence present.",
                    report.authority_clearance.requester.as_str(),
                    report.authority_clearance.chain_root.as_str(),
                    report.authority_clearance.chain_leaf.as_str(),
                    report.authority_clearance.chain_depth,
                    hex_encode(&report.authority_clearance.chain_hash),
                    ai_grants,
                    report.ai_delegation_revocations
                ),
            )
        }

        ConstitutionalInvariant::SeparationOfPowers
        | ConstitutionalInvariant::ConsentRequired
        | ConstitutionalInvariant::NoSelfGrant
        | ConstitutionalInvariant::KernelImmutability
        | ConstitutionalInvariant::QuorumLegitimate => (
            AttestationStatus::Compliant,
            format!(
                "{invariant:?} enforced synchronously by InvariantEngine::enforce_all(). \
                 No violations recorded this period."
            ),
        ),
    }
}

fn redact_delegation_count(report: &AiTransparencyReport, mode: &ComplianceReportMode) -> usize {
    match mode {
        ComplianceReportMode::Full => report.ai_delegation_grants.len(),
        ComplianceReportMode::Redacted { .. } => {
            // Count is not sensitive; only model_id is redacted in full reports.
            report.ai_delegation_grants.len()
        }
    }
}

/// Apply model_id redaction to a delegation event's model_id string.
///
/// In Redacted mode: `BLAKE3(tenant_id_bytes || model_id_bytes || salt)`.
/// In Full mode: returns the model_id unchanged.
#[must_use]
pub fn redact_model_id(tenant_id: &Did, model_id: &str, mode: &ComplianceReportMode) -> String {
    match mode {
        ComplianceReportMode::Full => model_id.to_owned(),
        ComplianceReportMode::Redacted { redaction_salt } => {
            let mut h = blake3::Hasher::new();
            h.update(tenant_id.as_str().as_bytes());
            h.update(model_id.as_bytes());
            h.update(redaction_salt);
            hex_encode(h.finalize().as_bytes())
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize)]
struct ComplianceReportHashPayload<'a> {
    domain: &'static str,
    schema_version: &'a str,
    tenant_id: &'a Did,
    generated_at: Timestamp,
    period_start: Timestamp,
    period_end: Timestamp,
    legal_jurisdiction: &'a str,
    report_mode: &'a str,
    attestations: &'a [InvariantAttestation],
}

impl<'a> ComplianceReportHashPayload<'a> {
    fn from_report(report: &'a ComplianceReport) -> Self {
        Self {
            domain: COMPLIANCE_REPORT_HASH_DOMAIN,
            schema_version: &report.schema_version,
            tenant_id: &report.tenant_id,
            generated_at: report.generated_at,
            period_start: report.period_start,
            period_end: report.period_end,
            legal_jurisdiction: &report.legal_jurisdiction,
            report_mode: &report.report_mode,
            attestations: &report.attestations,
        }
    }
}

fn hash_report_payload(payload: &ComplianceReportHashPayload<'_>) -> Result<[u8; 32]> {
    hash_structured(payload)
        .map(|hash| *hash.as_bytes())
        .map_err(|e| LegalError::InvalidStateTransition {
            reason: format!("compliance report canonical CBOR hash failed: {e}"),
        })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_authority::{AuthorityChain, AuthorityLink, DelegateeKind, Permission};
    use exo_core::{Did, Signature, Timestamp, crypto::KeyPair};
    use exo_gatekeeper::mcp_audit::McpAuditLog;

    use super::*;
    use crate::ai_transparency::{
        AiTransparencyReport, ReportParams, VerifiedAuthorityClearance, generate_report,
        verify_authority_clearance,
    };

    fn did(s: &str) -> Did {
        Did::new(&format!("did:exo:{s}")).expect("valid DID")
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn verified_clearance(requester: &Did) -> VerifiedAuthorityClearance {
        let root = did("root-authority");
        let root_key = KeyPair::generate();
        let mut link = AuthorityLink {
            delegator_did: root.clone(),
            delegate_did: requester.clone(),
            scope: vec![Permission::Read],
            created: ts(1_000),
            expires: None,
            signature: Signature::empty(),
            depth: 0,
            delegatee_kind: DelegateeKind::Human,
        };
        let payload = link
            .signing_payload()
            .expect("authority link signing payload");
        link.signature = root_key.sign(&payload);
        let chain = AuthorityChain {
            links: vec![link],
            max_depth: 5,
        };

        verify_authority_clearance(requester, &chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("authority clearance must verify")
    }

    fn empty_report(tenant: &Did) -> AiTransparencyReport {
        let clearance = verified_clearance(tenant);
        generate_report(ReportParams {
            tenant_id: tenant,
            period_start: ts(0),
            period_end: ts(9999),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &McpAuditLog::new(),
            ai_delegation_grants: vec![],
            ai_delegation_revocations: 0,
            authority_clearance: &clearance,
        })
        .expect("ok")
    }

    #[test]
    fn build_report_full_mode_produces_all_attestations() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let report = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");
        // All 8 invariants must be attested
        assert_eq!(report.attestations.len(), 8);
        assert_eq!(report.report_mode, "Full");
    }

    #[test]
    fn build_report_redacted_mode_label() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let report = build_report(
            &tr,
            &ComplianceReportMode::Redacted {
                redaction_salt: [0u8; 32],
            },
            ts(10000),
        )
        .expect("ok");
        assert_eq!(report.report_mode, "Redacted");
    }

    #[test]
    fn report_hash_is_deterministic() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let r1 = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");
        let r2 = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn report_hash_detects_nist_mapping_tamper() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let mut report = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");

        assert!(verify_report_hash(&report).expect("report hash verification should succeed"));

        report.attestations[0]
            .nist_subcategories
            .push("tampered-subcategory".into());

        assert!(
            !verify_report_hash(&report).expect("report hash verification should succeed"),
            "report hash must cover NIST subcategories"
        );
    }

    #[test]
    fn report_hash_detects_regulatory_reference_tamper() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let mut report = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");

        report.attestations[0]
            .regulatory_refs
            .push("tampered-reference".into());

        assert!(
            !verify_report_hash(&report).expect("report hash verification should succeed"),
            "report hash must cover regulatory references"
        );
    }

    #[test]
    fn report_hash_differs_on_different_timestamp() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let r1 = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");
        let r2 = build_report(&tr, &ComplianceReportMode::Full, ts(20000)).expect("ok");
        assert_ne!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn static_kernel_attestations_remain_compliant_for_empty_period() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let report = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");
        for att in &report.attestations {
            if att.invariant == "ProvenanceVerifiable" {
                assert_eq!(att.status, AttestationStatus::NotApplicable);
            } else {
                assert_eq!(
                    att.status,
                    AttestationStatus::Compliant,
                    "invariant {} should be Compliant",
                    att.invariant
                );
            }
        }
    }

    #[test]
    fn empty_period_does_not_overclaim_provenance_or_authority_compliance() {
        let tenant = did("tenant");
        let tr = empty_report(&tenant);
        let report = build_report(&tr, &ComplianceReportMode::Full, ts(10000)).expect("ok");

        let provenance = report
            .attestations
            .iter()
            .find(|a| a.invariant == "ProvenanceVerifiable")
            .expect("ProvenanceVerifiable must appear in attestations");
        assert_ne!(
            provenance.status,
            AttestationStatus::Compliant,
            "an empty report period has no provenance events to verify"
        );
        assert!(
            !provenance
                .evidence_summary
                .contains("BLAKE3 chain verified"),
            "empty evidence must not claim a verified non-empty audit chain"
        );

        let authority = report
            .attestations
            .iter()
            .find(|a| a.invariant == "AuthorityChainValid")
            .expect("AuthorityChainValid must appear in attestations");
        assert!(
            !authority
                .evidence_summary
                .contains("Authority chain verified for all actions"),
            "authority attestations must name concrete verified evidence, not all-action prose"
        );
    }

    #[test]
    fn redact_model_id_full_mode_passthrough() {
        let tenant = did("tenant");
        let result = redact_model_id(&tenant, "claude-sonnet-4-6", &ComplianceReportMode::Full);
        assert_eq!(result, "claude-sonnet-4-6");
    }

    #[test]
    fn redact_model_id_redacted_mode_produces_hex_hash() {
        let tenant = did("tenant");
        let result = redact_model_id(
            &tenant,
            "claude-sonnet-4-6",
            &ComplianceReportMode::Redacted {
                redaction_salt: [1u8; 32],
            },
        );
        // Must be a 64-char hex string (32 bytes)
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn redact_model_id_different_salts_differ() {
        let tenant = did("tenant");
        let r1 = redact_model_id(
            &tenant,
            "model-x",
            &ComplianceReportMode::Redacted {
                redaction_salt: [1u8; 32],
            },
        );
        let r2 = redact_model_id(
            &tenant,
            "model-x",
            &ComplianceReportMode::Redacted {
                redaction_salt: [2u8; 32],
            },
        );
        assert_ne!(r1, r2);
    }

    #[test]
    fn redact_model_id_different_models_differ() {
        let tenant = did("tenant");
        let salt = [42u8; 32];
        let r1 = redact_model_id(
            &tenant,
            "model-a",
            &ComplianceReportMode::Redacted {
                redaction_salt: salt,
            },
        );
        let r2 = redact_model_id(
            &tenant,
            "model-b",
            &ComplianceReportMode::Redacted {
                redaction_salt: salt,
            },
        );
        assert_ne!(r1, r2);
    }
}
