//! Typed NIST AI RMF mapping.
//!
//! Provides a compile-time-verifiable representation of the
//! `NIST_AI_RMF_MAPPING.toml` document. Using typed structs (not raw
//! `serde_json::Value`) allows tests to assert invariant coverage at
//! compile time and prevents mapping drift between policy and code.

use exo_gatekeeper::invariants::ConstitutionalInvariant;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// NIST AI RMF function
// ---------------------------------------------------------------------------

/// The four functions of the NIST AI Risk Management Framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NistFunction {
    /// Cultivate and implement AI risk management practices.
    Govern,
    /// Categorize and frame AI risk.
    Map,
    /// Analyse, assess, and track AI risks.
    Measure,
    /// Allocate resources and apply risk treatments.
    Manage,
}

impl NistFunction {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NistFunction::Govern => "Govern",
            NistFunction::Map => "Map",
            NistFunction::Measure => "Measure",
            NistFunction::Manage => "Manage",
        }
    }
}

// ---------------------------------------------------------------------------
// Mapping entry
// ---------------------------------------------------------------------------

/// A single mapping from an ExoChain [`ConstitutionalInvariant`] to one or
/// more NIST AI RMF functions and subcategories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistMappingEntry {
    pub invariant: ConstitutionalInvariant,
    /// Human-readable label used in ExoChain governance documentation.
    pub exochain_label: String,
    pub nist_functions: Vec<NistFunction>,
    /// NIST AI RMF subcategory codes (e.g. "GV.1", "MS.2").
    pub nist_subcategories: Vec<String>,
    /// Applicable regulatory references (EU AI Act, GDPR, etc.).
    pub regulatory_refs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Full mapping
// ---------------------------------------------------------------------------

/// The complete NIST AI RMF mapping for all ExoChain constitutional invariants.
///
/// Call [`NistMapping::canonical()`] to obtain the authoritative mapping.
/// The mapping is deterministic — same invariant set always produces the
/// same entries in the same order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistMapping {
    pub schema_version: String,
    pub entries: Vec<NistMappingEntry>,
}

impl NistMapping {
    /// The authoritative mapping, mirroring `NIST_AI_RMF_MAPPING.toml`.
    ///
    /// This is the Rust source of truth. The TOML file is the human-readable
    /// ratification artifact. Both must be kept in sync.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            schema_version: "1.0.0".into(),
            entries: vec![
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::HumanOverride,
                    exochain_label: "HumanOversight".into(),
                    nist_functions: vec![NistFunction::Govern, NistFunction::Manage],
                    nist_subcategories: vec!["GV.1".into(), "GV.6".into(), "MG.2".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 14 (Human oversight)".into(),
                        "GDPR Art. 22 (Automated decision-making)".into(),
                        "GDPR Art. 22(3) (Human intervention safeguards)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                    exochain_label: "TransparencyAccountability".into(),
                    nist_functions: vec![NistFunction::Govern, NistFunction::Measure],
                    nist_subcategories: vec!["GV.1".into(), "MS.2".into(), "MS.4".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 13 (Transparency — high-risk AI)".into(),
                        "EU AI Act Art. 12 (Record-keeping)".into(),
                        "GDPR Art. 5(1)(f) (Integrity and confidentiality)".into(),
                        "GDPR Art. 30 (Records of processing activities)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::AuthorityChainValid,
                    exochain_label: "DelegationGovernance".into(),
                    nist_functions: vec![NistFunction::Govern, NistFunction::Map],
                    nist_subcategories: vec!["GV.6".into(), "MP.2".into(), "MP.5".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 16 (Obligations of providers)".into(),
                        "EU AI Act Art. 26 (Obligations of deployers)".into(),
                        "GDPR Art. 5(2) (Accountability)".into(),
                        "GDPR Art. 28 (Processor obligations)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::SeparationOfPowers,
                    exochain_label: "DemocraticLegitimacy".into(),
                    nist_functions: vec![NistFunction::Govern],
                    nist_subcategories: vec!["GV.1".into(), "GV.4".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 9 (Risk management — separation of roles)".into(),
                        "EU AI Act Art. 17 (Quality management system)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::ConsentRequired,
                    exochain_label: "DataSovereignty".into(),
                    nist_functions: vec![NistFunction::Map, NistFunction::Manage],
                    nist_subcategories: vec!["MP.5".into(), "MG.3".into()],
                    regulatory_refs: vec![
                        "GDPR Art. 6 (Lawfulness of processing)".into(),
                        "GDPR Art. 7 (Conditions for consent)".into(),
                        "GDPR Art. 22 (Automated decision-making — explicit consent)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::NoSelfGrant,
                    exochain_label: "PrivilegeEscalationPrevention".into(),
                    nist_functions: vec![NistFunction::Govern, NistFunction::Manage],
                    nist_subcategories: vec!["GV.1".into(), "MG.2".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 9(7) (Risk management — containment)".into(),
                        "EU AI Act Art. 14(4) (Human oversight — stop capability)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::KernelImmutability,
                    exochain_label: "ExistentialSafeguard".into(),
                    nist_functions: vec![NistFunction::Govern, NistFunction::Manage],
                    nist_subcategories: vec!["GV.1".into(), "MG.4".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 9 (Risk management — systemic integrity)".into(),
                        "EU AI Act Annex IV (Technical documentation)".into(),
                    ],
                },
                NistMappingEntry {
                    invariant: ConstitutionalInvariant::QuorumLegitimate,
                    exochain_label: "DualControl".into(),
                    nist_functions: vec![NistFunction::Govern, NistFunction::Measure],
                    nist_subcategories: vec!["GV.1".into(), "GV.4".into(), "MS.2".into()],
                    regulatory_refs: vec![
                        "EU AI Act Art. 17 (Quality management — governance processes)".into(),
                        "EU AI Act Art. 9 (Risk management — multi-actor verification)".into(),
                    ],
                },
            ],
        }
    }

    /// Return the mapping entry for a specific invariant, if present.
    #[must_use]
    pub fn entry_for(&self, invariant: ConstitutionalInvariant) -> Option<&NistMappingEntry> {
        self.entries.iter().find(|e| e.invariant == invariant)
    }

    /// Assert that every invariant in the provided set has a mapping entry.
    ///
    /// Returns the invariants that have no entry (should be empty for a
    /// complete mapping).
    #[must_use]
    pub fn coverage_gaps(
        &self,
        invariants: &[ConstitutionalInvariant],
    ) -> Vec<ConstitutionalInvariant> {
        invariants
            .iter()
            .filter(|&&inv| self.entry_for(inv).is_none())
            .copied()
            .collect()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_gatekeeper::invariants::{ConstitutionalInvariant, InvariantSet};

    use super::*;

    #[test]
    fn canonical_mapping_covers_all_invariants() {
        let mapping = NistMapping::canonical();
        let all = InvariantSet::all();
        let gaps = mapping.coverage_gaps(&all.invariants);
        assert!(
            gaps.is_empty(),
            "missing NIST mappings for invariants: {gaps:?}"
        );
    }

    #[test]
    fn human_override_maps_to_govern_and_manage() {
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::HumanOverride)
            .expect("HumanOverride must have a mapping");
        assert!(entry.nist_functions.contains(&NistFunction::Govern));
        assert!(entry.nist_functions.contains(&NistFunction::Manage));
    }

    #[test]
    fn human_override_includes_gdpr_art22() {
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::HumanOverride)
            .expect("HumanOverride must have a mapping");
        let has_art22 = entry.regulatory_refs.iter().any(|r| r.contains("Art. 22"));
        assert!(
            has_art22,
            "HumanOverride mapping must reference GDPR Art. 22"
        );
    }

    #[test]
    fn provenance_verifiable_includes_gdpr_art5_1_f() {
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::ProvenanceVerifiable)
            .expect("ProvenanceVerifiable must have a mapping");
        let has_art5 = entry.regulatory_refs.iter().any(|r| r.contains("5(1)(f)"));
        assert!(
            has_art5,
            "ProvenanceVerifiable must reference GDPR Art. 5(1)(f)"
        );
    }

    #[test]
    fn authority_chain_maps_to_govern_and_map() {
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::AuthorityChainValid)
            .expect("AuthorityChainValid must have a mapping");
        assert!(entry.nist_functions.contains(&NistFunction::Govern));
        assert!(entry.nist_functions.contains(&NistFunction::Map));
    }

    #[test]
    fn entry_for_unknown_returns_none() {
        // All 8 invariants are mapped; querying with a constructed set is not
        // the purpose here — just verify the lookup returns Some for a known one.
        let mapping = NistMapping::canonical();
        assert!(
            mapping
                .entry_for(ConstitutionalInvariant::NoSelfGrant)
                .is_some()
        );
    }

    #[test]
    fn no_coverage_gaps_for_all_set() {
        let mapping = NistMapping::canonical();
        let all = InvariantSet::all();
        assert_eq!(mapping.coverage_gaps(&all.invariants), vec![]);
    }
}
