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
//! Each prong is scored 0.0–1.0.  `bjr_defensibility_score()` returns the mean.
//! A score ≥ 0.8 suggests strong defensibility; < 0.5 suggests exposure.

use exo_core::types::Hash256;
use serde::{Deserialize, Serialize};

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
    /// Score: ratio of disinterested voters to total eligible voters (0.0–1.0).
    #[must_use]
    #[allow(clippy::float_arithmetic, clippy::as_conversions)]
    pub fn score(&self) -> f64 {
        let eligible = self.total_members.saturating_sub(self.recused_count);
        if eligible == 0 {
            return 0.0;
        }
        (self.disinterested_voters as f64 / eligible as f64).clamp(0.0, 1.0)
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
    /// Score: fraction of voters who reviewed materials (0.0–1.0).
    #[must_use]
    #[allow(clippy::float_arithmetic, clippy::as_conversions)]
    pub fn score(&self) -> f64 {
        if self.total_voters == 0 {
            return 0.0;
        }
        (self.voters_who_reviewed as f64 / self.total_voters as f64).clamp(0.0, 1.0)
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
    /// Score: composite of alternatives (≥2 = full credit), process compliance, and
    /// dissent capture (any dissent captured = full credit for that element).
    #[must_use]
    #[allow(clippy::float_arithmetic, clippy::as_conversions)]
    pub fn score(&self) -> f64 {
        let alt_score = if self.alternatives_count >= 2 {
            1.0
        } else {
            self.alternatives_count as f64 / 2.0
        };
        let process_score = if self.process_compliant { 1.0 } else { 0.0 };
        // Dissent: presence of captured dissent is a good-faith signal.
        let dissent_score = if self.dissent_records > 0 || self.deliberation_hashes.len() > 1 {
            1.0
        } else {
            0.5
        };
        ((alt_score + process_score + dissent_score) / 3.0).clamp(0.0, 1.0)
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
    /// Score: 1.0 if both rationale and risk assessment are present; 0.5 if one; 0.0 if neither.
    #[must_use]
    pub fn score(&self) -> f64 {
        let has_rationale = self.selected_rationale_hash.is_some();
        let has_risk = self.risk_assessment_hash.is_some();
        match (has_rationale, has_risk) {
            (true, true) => 1.0,
            (true, false) | (false, true) => 0.5,
            (false, false) => 0.0,
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
    #[must_use]
    pub fn generate(
        decision_hash: Hash256,
        prong_disinterestedness: ProngDisinterestedness,
        prong_informed_basis: ProngInformedBasis,
        prong_good_faith: ProngGoodFaith,
        prong_rational_basis: ProngRationalBasis,
    ) -> Self {
        let package_hash = compute_package_hash(
            &decision_hash,
            &prong_disinterestedness,
            &prong_informed_basis,
            &prong_good_faith,
            &prong_rational_basis,
        );
        Self {
            decision_hash,
            prong_disinterestedness,
            prong_informed_basis,
            prong_good_faith,
            prong_rational_basis,
            package_hash,
            disclaimer: Self::DISCLAIMER,
        }
    }

    /// Overall BJR defensibility score (mean of four prong scores), 0.0–1.0.
    ///
    /// Interpretation:
    /// - ≥ 0.8 : strong BJR defensibility
    /// - 0.5–0.8 : moderate — counsel should review gaps
    /// - < 0.5 : significant exposure
    #[must_use]
    #[allow(clippy::float_arithmetic)]
    pub fn bjr_defensibility_score(&self) -> f64 {
        let sum = self.prong_disinterestedness.score()
            + self.prong_informed_basis.score()
            + self.prong_good_faith.score()
            + self.prong_rational_basis.score();
        (sum / 4.0).clamp(0.0, 1.0)
    }

    /// Verify the package has not been tampered with since generation.
    #[must_use]
    pub fn verify(&self) -> bool {
        let expected = compute_package_hash(
            &self.decision_hash,
            &self.prong_disinterestedness,
            &self.prong_informed_basis,
            &self.prong_good_faith,
            &self.prong_rational_basis,
        );
        expected == self.package_hash
    }
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn compute_package_hash(
    decision_hash: &Hash256,
    p1: &ProngDisinterestedness,
    p2: &ProngInformedBasis,
    p3: &ProngGoodFaith,
    p4: &ProngRationalBasis,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fjp:v1:");
    hasher.update(decision_hash.as_bytes());
    // Prong 1
    hasher.update(&p1.total_members.to_le_bytes());
    hasher.update(&p1.recused_count.to_le_bytes());
    hasher.update(&p1.disinterested_voters.to_le_bytes());
    hasher.update(&[u8::from(p1.majority_disinterested)]);
    for h in &p1.disclosure_record_hashes {
        hasher.update(h.as_bytes());
    }
    // Prong 2
    hasher.update(&p2.voters_who_reviewed.to_le_bytes());
    hasher.update(&p2.total_voters.to_le_bytes());
    hasher.update(&[u8::from(p2.materials_complete_before_vote)]);
    for h in &p2.evidence_manifest_hashes {
        hasher.update(h.as_bytes());
    }
    // Prong 3
    hasher.update(&p3.alternatives_count.to_le_bytes());
    hasher.update(&p3.dissent_records.to_le_bytes());
    hasher.update(&[u8::from(p3.process_compliant)]);
    for h in &p3.deliberation_hashes {
        hasher.update(h.as_bytes());
    }
    // Prong 4
    if let Some(h) = &p4.selected_rationale_hash {
        hasher.update(h.as_bytes());
    }
    if let Some(h) = &p4.risk_assessment_hash {
        hasher.update(h.as_bytes());
    }
    for h in &p4.supporting_evidence_hashes {
        hasher.update(h.as_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
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
    fn defense_package_four_prong_completeness() {
        let pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        );
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
        );
        let score = pkg.bjr_defensibility_score();
        assert!((0.0..=1.0).contains(&score), "score must be in [0.0, 1.0]");
        assert!(
            score >= 0.8,
            "fully-evidenced decision must score ≥ 0.8, got {score}"
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
        );
        assert!(
            pkg.verify(),
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
        );
        // Mutate a field after sealing.
        pkg.prong_disinterestedness.recused_count = 99;
        assert!(!pkg.verify(), "tampered package must fail verification");
    }

    #[test]
    fn defense_package_contains_disclaimer() {
        let pkg = FiduciaryDefensePackage::generate(
            decision_hash(),
            full_prong1(),
            full_prong2(),
            full_prong3(),
            full_prong4(),
        );
        assert!(
            pkg.disclaimer.contains("not a legal opinion"),
            "package must include legal disclaimer"
        );
    }

    #[test]
    fn prong_scores_clamped_to_unit_interval() {
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
        assert!((0.0..=1.0).contains(&p1.score()));
        assert!((0.0..=1.0).contains(&p2.score()));
        assert!((0.0..=1.0).contains(&p3.score()));
        assert!((0.0..=1.0).contains(&p4.score()));
    }

    #[test]
    fn bjr_disinterestedness_score_two_thirds() {
        // 2 out of 3 disinterested voters → score ≈ 0.67
        let p1 = ProngDisinterestedness {
            total_members: 3,
            recused_count: 0,
            disinterested_voters: 2,
            majority_disinterested: true,
            disclosure_record_hashes: vec![],
        };
        let score = p1.score();
        assert!((score - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn bjr_informed_basis_all_reviewed() {
        let p2 = ProngInformedBasis {
            voters_who_reviewed: 5,
            total_voters: 5,
            evidence_manifest_hashes: vec![],
            materials_complete_before_vote: true,
        };
        assert!((p2.score() - 1.0).abs() < 1e-9);
    }
}
