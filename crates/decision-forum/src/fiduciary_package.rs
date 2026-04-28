//! Structured Fiduciary Defense Package (LEG-008 / LEG-012).
//!
//! Generates a machine-readable, cryptographically-sealed artifact documenting
//! the four-prong Business Judgment Rule (BJR) analysis for a terminal decision.
//!
//! # BJR Four Prongs (Aronson v. Lewis, Smith v. Van Gorkom)
//!
//! 1. **Disinterestedness** — majority of decision-makers were free of material conflicts.
//! 2. **Informed Basis** — decision-makers reviewed relevant materials before voting.
//! 3. **Good Faith** — deliberation was conducted in good faith with alternatives considered.
//! 4. **Rational Basis** — a rational person could have reached the same conclusion.
//!
//! # Legal disclaimer
//!
//! This package is a structured evidentiary aid, not a legal opinion.
//! Review by qualified counsel is required before use in litigation.
//!
//! # Scoring
//!
//! Each prong is scored in basis points (0–10,000 ≡ 0.00%–100.00%).
//! `bjr_defensibility_score_bps()` returns the mean.
//! A score ≥ 8,000 bps suggests strong defensibility; < 5,000 bps suggests exposure.
//!
//! All scoring uses integer arithmetic only — no floating-point — per
//! constitutional determinism requirement (`float_arithmetic = "deny"`).

use exo_core::{hash::hash_structured, types::Hash256};
use serde::{Deserialize, Serialize};

use crate::error::{ForumError, Result};

const FIDUCIARY_PACKAGE_HASH_DOMAIN: &str = "decision.forum.fiduciary_package.v1";
const FIDUCIARY_PACKAGE_HASH_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Prong evidence containers
// ---------------------------------------------------------------------------

/// Evidence for BJR Prong 1: Disinterestedness.
///
/// Populated from the conflict disclosure register and recusal records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProngDisinterestedness {
    /// Total number of decision-makers.
    pub total_members: usize,
    /// Number of members who recused due to material/disqualifying conflicts.
    pub recused_count: usize,
    /// Number of disinterested members who voted.
    pub disinterested_voters: usize,
    /// Whether a majority of voters were disinterested.
    pub majority_disinterested: bool,
    /// Hashes of conflict disclosure records reviewed.
    pub disclosure_record_hashes: Vec<Hash256>,
}

impl ProngDisinterestedness {
    /// Score in basis points (0–10_000 ≡ 0.00%–100.00%).
    ///
    /// Uses integer arithmetic only — no floats — per constitutional determinism
    /// requirement (`float_arithmetic = "deny"` in workspace lints).
    #[must_use]
    pub fn score_bps(&self) -> u64 {
        let eligible = self.total_members.saturating_sub(self.recused_count);
        if eligible == 0 {
            return 0;
        }
        let numer = u64::try_from(self.disinterested_voters).unwrap_or(0);
        let denom = u64::try_from(eligible).unwrap_or(1);
        (numer * 10_000 / denom).min(10_000)
    }
}

/// Evidence for BJR Prong 2: Informed Basis.
///
/// Populated from information package manifests and voter attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProngInformedBasis {
    /// Number of voters who attested to reviewing the information package.
    pub voters_who_reviewed: usize,
    /// Total voters.
    pub total_voters: usize,
    /// Hashes of evidence items available to decision-makers.
    pub evidence_manifest_hashes: Vec<Hash256>,
    /// Whether all required materials were available before the vote closed.
    pub materials_complete_before_vote: bool,
}

impl ProngInformedBasis {
    /// Score in basis points (0–10_000 ≡ 0.00%–100.00%).
    ///
    /// Uses integer arithmetic only — no floats — per constitutional determinism
    /// requirement (`float_arithmetic = "deny"` in workspace lints).
    #[must_use]
    pub fn score_bps(&self) -> u64 {
        if self.total_voters == 0 {
            return 0;
        }
        let numer = u64::try_from(self.voters_who_reviewed).unwrap_or(0);
        let denom = u64::try_from(self.total_voters).unwrap_or(1);
        (numer * 10_000 / denom).min(10_000)
    }
}

/// Evidence for BJR Prong 3: Good Faith.
///
/// Populated from deliberation transcripts, alternatives considered, and dissent records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProngGoodFaith {
    /// Number of alternatives formally considered (minimum 1 required).
    pub alternatives_count: usize,
    /// Number of dissent records captured (Against/Abstain votes with reasoning).
    pub dissent_records: usize,
    /// Hashes of deliberation transcript entries.
    pub deliberation_hashes: Vec<Hash256>,
    /// Whether process followed the constitutional governance timeline.
    pub process_compliant: bool,
}

impl ProngGoodFaith {
    /// Score in basis points (0–10_000 ≡ 0.00%–100.00%).
    ///
    /// Composite of alternatives (≥2 = full credit), process compliance, and
    /// dissent capture.  Uses integer arithmetic only — no floats — per
    /// constitutional determinism requirement.
    #[must_use]
    pub fn score_bps(&self) -> u64 {
        // Each sub-score is 0–10_000 bps.
        let alt_bps: u64 = if self.alternatives_count >= 2 {
            10_000
        } else {
            u64::try_from(self.alternatives_count).unwrap_or(0) * 5_000 // 0→0, 1→5000
        };
        let process_bps: u64 = if self.process_compliant { 10_000 } else { 0 };
        let dissent_bps: u64 = if self.dissent_records > 0 || self.deliberation_hashes.len() > 1 {
            10_000
        } else {
            5_000
        };
        // Mean of three sub-scores, clamped to 10_000.
        ((alt_bps + process_bps + dissent_bps) / 3).min(10_000)
    }
}

/// Evidence for BJR Prong 4: Rational Basis.
///
/// Populated from the selected alternative rationale and risk assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProngRationalBasis {
    /// Hash of the rationale document for the selected alternative.
    pub selected_rationale_hash: Option<Hash256>,
    /// Hash of the risk assessment artifact.
    pub risk_assessment_hash: Option<Hash256>,
    /// Hashes of supporting evidence referenced in the rationale.
    pub supporting_evidence_hashes: Vec<Hash256>,
}

impl ProngRationalBasis {
    /// Score in basis points (0–10_000 ≡ 0.00%–100.00%).
    ///
    /// 10_000 if both rationale and risk assessment present; 5_000 if one; 0 if neither.
    /// Uses integer arithmetic only — no floats.
    #[must_use]
    pub fn score_bps(&self) -> u64 {
        let has_rationale = self.selected_rationale_hash.is_some();
        let has_risk = self.risk_assessment_hash.is_some();
        match (has_rationale, has_risk) {
            (true, true) => 10_000,
            (true, false) | (false, true) => 5_000,
            (false, false) => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Package
// ---------------------------------------------------------------------------

/// Structured Fiduciary Defense Package.
///
/// A cryptographically-sealed artifact documenting all four BJR prongs for
/// a terminal governance decision.  Generated by `generate()`.
///
/// # Legal disclaimer
///
/// This package is a structured evidentiary aid, not a legal opinion.
/// Review by qualified counsel is required before use in litigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiduciaryDefensePackage {
    /// BLAKE3 hash of the decision being defended.
    pub decision_hash: Hash256,
    /// Prong 1: Disinterestedness evidence.
    pub prong_disinterestedness: ProngDisinterestedness,
    /// Prong 2: Informed Basis evidence.
    pub prong_informed_basis: ProngInformedBasis,
    /// Prong 3: Good Faith evidence.
    pub prong_good_faith: ProngGoodFaith,
    /// Prong 4: Rational Basis evidence.
    pub prong_rational_basis: ProngRationalBasis,
    /// BLAKE3 hash sealing all prong fields — tamper-evident.
    pub package_hash: Hash256,
    /// Mandatory legal disclaimer.
    pub disclaimer: &'static str,
}

impl FiduciaryDefensePackage {
    /// Legal disclaimer text included in every package.
    pub const DISCLAIMER: &'static str = "This package is a structured evidentiary aid, not a legal opinion. \
         Review by qualified counsel is required before use in litigation.";

    /// Generate a FiduciaryDefensePackage for a decision.
    ///
    /// Computes `package_hash` over all prong data so any field mutation is
    /// detectable.
    pub fn generate(
        decision_hash: Hash256,
        prong_disinterestedness: ProngDisinterestedness,
        prong_informed_basis: ProngInformedBasis,
        prong_good_faith: ProngGoodFaith,
        prong_rational_basis: ProngRationalBasis,
    ) -> Result<Self> {
        let package_hash = compute_package_hash(
            &decision_hash,
            &prong_disinterestedness,
            &prong_informed_basis,
            &prong_good_faith,
            &prong_rational_basis,
            Self::DISCLAIMER,
        )?;
        Ok(Self {
            decision_hash,
            prong_disinterestedness,
            prong_informed_basis,
            prong_good_faith,
            prong_rational_basis,
            package_hash,
            disclaimer: Self::DISCLAIMER,
        })
    }

    /// Overall BJR defensibility score in basis points (0–10_000 ≡ 0.00%–100.00%).
    ///
    /// Mean of four prong scores.  Uses integer arithmetic only — no floats.
    ///
    /// Interpretation:
    /// - ≥ 8_000 bps : strong BJR defensibility
    /// - 5_000–8_000 bps : moderate — counsel should review gaps
    /// - < 5_000 bps : significant exposure
    #[must_use]
    pub fn bjr_defensibility_score_bps(&self) -> u64 {
        let sum = self.prong_disinterestedness.score_bps()
            + self.prong_informed_basis.score_bps()
            + self.prong_good_faith.score_bps()
            + self.prong_rational_basis.score_bps();
        (sum / 4).min(10_000)
    }

    /// Verify the package has not been tampered with since generation.
    pub fn verify(&self) -> Result<bool> {
        let expected = compute_package_hash(
            &self.decision_hash,
            &self.prong_disinterestedness,
            &self.prong_informed_basis,
            &self.prong_good_faith,
            &self.prong_rational_basis,
            self.disclaimer,
        )?;
        Ok(expected == self.package_hash)
    }
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct FiduciaryPackageHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    decision_hash: &'a Hash256,
    prong_disinterestedness: &'a ProngDisinterestedness,
    prong_informed_basis: &'a ProngInformedBasis,
    prong_good_faith: &'a ProngGoodFaith,
    prong_rational_basis: &'a ProngRationalBasis,
    disclaimer: &'a str,
}

fn fiduciary_package_hash_payload<'a>(
    decision_hash: &'a Hash256,
    p1: &'a ProngDisinterestedness,
    p2: &'a ProngInformedBasis,
    p3: &'a ProngGoodFaith,
    p4: &'a ProngRationalBasis,
) -> FiduciaryPackageHashPayload<'a> {
    FiduciaryPackageHashPayload {
        domain: FIDUCIARY_PACKAGE_HASH_DOMAIN,
        schema_version: FIDUCIARY_PACKAGE_HASH_SCHEMA_VERSION,
        decision_hash,
        prong_disinterestedness: p1,
        prong_informed_basis: p2,
        prong_good_faith: p3,
        prong_rational_basis: p4,
        disclaimer: FiduciaryDefensePackage::DISCLAIMER,
    }
}

fn compute_package_hash(
    decision_hash: &Hash256,
    p1: &ProngDisinterestedness,
    p2: &ProngInformedBasis,
    p3: &ProngGoodFaith,
    p4: &ProngRationalBasis,
    disclaimer: &str,
) -> Result<Hash256> {
    let mut payload = fiduciary_package_hash_payload(decision_hash, p1, p2, p3, p4);
    payload.disclaimer = disclaimer;
    hash_structured(&payload).map_err(ForumError::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn decision_hash() -> Hash256 {
        Hash256::digest(b"decision-abc-123")
    }

    fn full_prong1() -> ProngDisinterestedness {
        ProngDisinterestedness {
            total_members: 5,
            recused_count: 1,
            disinterested_voters: 4,
            majority_disinterested: true,
            disclosure_record_hashes: vec![Hash256::digest(b"disclosure1")],
        }
    }

    fn full_prong2() -> ProngInformedBasis {
        ProngInformedBasis {
            voters_who_reviewed: 4,
            total_voters: 4,
            evidence_manifest_hashes: vec![Hash256::digest(b"ev1"), Hash256::digest(b"ev2")],
            materials_complete_before_vote: true,
        }
    }

    fn full_prong3() -> ProngGoodFaith {
        ProngGoodFaith {
            alternatives_count: 3,
            dissent_records: 1,
            deliberation_hashes: vec![Hash256::digest(b"delib1"), Hash256::digest(b"delib2")],
            process_compliant: true,
        }
    }

    fn full_prong4() -> ProngRationalBasis {
        ProngRationalBasis {
            selected_rationale_hash: Some(Hash256::digest(b"rationale")),
            risk_assessment_hash: Some(Hash256::digest(b"risk")),
            supporting_evidence_hashes: vec![Hash256::digest(b"sup1")],
        }
    }

    #[test]
    fn fiduciary_package_hash_payload_is_domain_separated_cbor() {
        let decision_hash = decision_hash();
        let p1 = full_prong1();
        let p2 = full_prong2();
        let p3 = full_prong3();
        let p4 = full_prong4();
        let payload = fiduciary_package_hash_payload(&decision_hash, &p1, &p2, &p3, &p4);
        assert_eq!(payload.domain, FIDUCIARY_PACKAGE_HASH_DOMAIN);
        assert_eq!(
            payload.schema_version,
            FIDUCIARY_PACKAGE_HASH_SCHEMA_VERSION
        );
        assert_eq!(*payload.decision_hash, decision_hash);
    }

    #[test]
    fn package_hash_distinguishes_optional_rationale_and_risk_slots() {
        let shared = Hash256::digest(b"shared-optional-hash");
        let p4_rationale = ProngRationalBasis {
            selected_rationale_hash: Some(shared),
            risk_assessment_hash: None,
            supporting_evidence_hashes: vec![],
        };
        let p4_risk = ProngRationalBasis {
            selected_rationale_hash: None,
            risk_assessment_hash: Some(shared),
            supporting_evidence_hashes: vec![],
        };
        let pkg_rationale = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            p4_rationale,
        )
        .expect("package");
        let pkg_risk = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            p4_risk,
        )
        .expect("package");
        assert_ne!(pkg_rationale.package_hash, pkg_risk.package_hash);
    }

    #[test]
    fn fiduciary_production_source_has_no_raw_package_hashing() {
        let production = include_str!("fiduciary_package.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(!production.contains("blake3::Hasher"));
        assert!(!production.contains("hasher.update"));
        assert!(!production.contains("to_le_bytes"));
    }

    #[test]
    fn defense_package_four_prong_completeness() {
        let pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        )
        .expect("package");
        // All four prongs have content.
        assert!(pkg.prong_disinterestedness.total_members > 0);
        assert!(pkg.prong_informed_basis.total_voters > 0);
        assert!(pkg.prong_good_faith.alternatives_count > 0);
        assert!(pkg.prong_rational_basis.selected_rationale_hash.is_some());
    }

    #[test]
    fn bjr_defensibility_score_range() {
        let pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        )
        .expect("package");
        let score = pkg.bjr_defensibility_score_bps();
        assert!(score <= 10_000, "score must be in [0, 10_000] bps");
        assert!(
            score >= 8_000,
            "fully-evidenced decision must score ≥ 8_000 bps, got {score}"
        );
    }

    #[test]
    fn defense_package_sealed_hash() {
        let pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        )
        .expect("package");
        assert!(
            pkg.verify().expect("verify"),
            "package must verify immediately after generation"
        );
    }

    #[test]
    fn defense_package_tamper_detected() {
        let mut pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        )
        .expect("package");
        // Mutate a field after sealing.
        pkg.prong_disinterestedness.recused_count = 99;
        assert!(
            !pkg.verify().expect("verify"),
            "tampered package must fail verification"
        );
    }

    #[test]
    fn defense_package_contains_disclaimer() {
        let pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        )
        .expect("package");
        assert!(
            pkg.disclaimer.contains("not a legal opinion"),
            "package must include legal disclaimer"
        );
    }

    #[test]
    fn prong_scores_clamped_to_basis_points() {
        // Edge: all zeros — scores must not underflow.
        let p1 = ProngDisinterestedness {
            total_members: 0,
            recused_count: 0,
            disinterested_voters: 0,
            majority_disinterested: false,
            disclosure_record_hashes: vec![],
        };
        let p2 = ProngInformedBasis {
            voters_who_reviewed: 0,
            total_voters: 0,
            evidence_manifest_hashes: vec![],
            materials_complete_before_vote: false,
        };
        let p3 = ProngGoodFaith {
            alternatives_count: 0,
            dissent_records: 0,
            deliberation_hashes: vec![],
            process_compliant: false,
        };
        let p4 = ProngRationalBasis {
            selected_rationale_hash: None,
            risk_assessment_hash: None,
            supporting_evidence_hashes: vec![],
        };
        assert!(
            p1.score_bps() <= 10_000,
            "p1 score must be in [0, 10_000] bps"
        );
        assert!(
            p2.score_bps() <= 10_000,
            "p2 score must be in [0, 10_000] bps"
        );
        assert!(
            p3.score_bps() <= 10_000,
            "p3 score must be in [0, 10_000] bps"
        );
        assert!(
            p4.score_bps() <= 10_000,
            "p4 score must be in [0, 10_000] bps"
        );
        // All-zero inputs should produce 0 bps
        assert_eq!(p1.score_bps(), 0);
        assert_eq!(p2.score_bps(), 0);
    }

    #[test]
    fn bjr_disinterestedness_score_two_thirds() {
        // 2 out of 3 disinterested voters → 6_666 bps (integer truncation of 20000/3)
        let p1 = ProngDisinterestedness {
            total_members: 3,
            recused_count: 0,
            disinterested_voters: 2,
            majority_disinterested: true,
            disclosure_record_hashes: vec![],
        };
        let score = p1.score_bps();
        // 2 * 10_000 / 3 = 6_666 (integer division)
        assert_eq!(score, 6_666);
    }

    #[test]
    fn bjr_informed_basis_all_reviewed() {
        let p2 = ProngInformedBasis {
            voters_who_reviewed: 5,
            total_voters: 5,
            evidence_manifest_hashes: vec![],
            materials_complete_before_vote: true,
        };
        // 5/5 = 10_000 bps (100%)
        assert_eq!(p2.score_bps(), 10_000);
    }
}
