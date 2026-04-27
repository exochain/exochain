use std::collections::BTreeSet;

/// Scoring inputs for the Panel Confidence Index.
pub struct PanelConfidenceInputs {
    pub models_agreeing: u32,
    pub total_models: u32,
    pub rounds_to_convergence: u32,
    pub max_rounds: u32,
    pub devil_found_serious_objection: bool,
    pub minority_reports_count: u32,
}

/// Return a canonical deterministic claim set: trimmed, lowercased, sorted, and
/// deduplicated. Empty claims are removed.
pub fn canonical_claim_set(claims: &[String]) -> Vec<String> {
    claims
        .iter()
        .map(|claim| claim.trim().to_lowercase())
        .filter(|claim| !claim.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Calculate convergence between structured key-claim sets (in bps, 0-10000).
/// Free-form text is not parsed here; callers must provide explicit claim
/// evidence for each model position.
pub fn calculate_convergence(claim_sets: &[Vec<String>]) -> u64 {
    if claim_sets.is_empty() {
        return 0;
    }

    let mut all_claims = BTreeSet::new();
    let mut model_claims = Vec::new();

    for claims in claim_sets {
        let canonical = canonical_claim_set(claims);
        let set = canonical.into_iter().collect::<BTreeSet<_>>();
        for claim in &set {
            all_claims.insert(claim.clone());
        }
        model_claims.push(set);
    }

    if all_claims.is_empty() {
        return 0;
    }
    if claim_sets.len() == 1 {
        return 10000;
    }

    let total_unique = u64::try_from(all_claims.len()).unwrap_or(0);
    let shared_claims = u64::try_from(
        all_claims
            .iter()
            .filter(|c| model_claims.iter().all(|mc| mc.contains(*c)))
            .count(),
    )
    .unwrap_or(0);

    (shared_claims * 10000) / total_unique
}

/// Return claims whose support across models meets the configured threshold.
pub fn consensus_claims_at_threshold(
    claim_sets: &[Vec<String>],
    threshold_bps: u64,
) -> Vec<String> {
    if claim_sets.is_empty() {
        return Vec::new();
    }

    let canonical_sets = claim_sets
        .iter()
        .map(|claims| {
            canonical_claim_set(claims)
                .into_iter()
                .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    let mut all_claims = BTreeSet::new();
    for claims in &canonical_sets {
        for claim in claims {
            all_claims.insert(claim.clone());
        }
    }

    let model_count = u64::try_from(canonical_sets.len()).unwrap_or(0);
    if model_count == 0 {
        return Vec::new();
    }

    all_claims
        .into_iter()
        .filter(|claim| {
            let support = u64::try_from(
                canonical_sets
                    .iter()
                    .filter(|claims| claims.contains(claim))
                    .count(),
            )
            .unwrap_or(0);
            (support * 10000) / model_count >= threshold_bps
        })
        .collect()
}

/// Calculate Panel Confidence Index in bps (0–10000).
/// Weights: model agreement (50%), speed of convergence (30%), devil's advocate (20%).
///
/// Inputs are clamped defensively: `models_agreeing` is capped at `total_models`,
/// and the speed-component numerator is capped at `max_rounds`, so callers that
/// pass out-of-range values (e.g. `rounds_to_convergence = 0`, which the original
/// formula would otherwise translate to > 3000 bps) still receive a bounded score.
pub fn calculate_panel_confidence(inputs: &PanelConfidenceInputs) -> u64 {
    let mut score = 0;

    // 1. Model Agreement (50%)
    if inputs.total_models > 0 {
        // Clamp agreeing to total so callers that pass malformed inputs
        // (agreeing > total) cannot produce a score above 5000.
        let agreeing = std::cmp::min(
            u64::from(inputs.models_agreeing),
            u64::from(inputs.total_models),
        );
        let agreement_bps = (agreeing * 5000) / u64::from(inputs.total_models);
        score += agreement_bps;
    }

    // 2. Speed of Convergence (30%)
    if inputs.max_rounds > 0 {
        // Original formula: (max - r + 1) / max * 3000.
        // When r = 1 and max = N, this gives the full 3000 (fastest observed convergence).
        // Guard against r = 0 (or any r < 1) which would push numerator above max
        // and overshoot 3000.
        let r = std::cmp::min(inputs.rounds_to_convergence, inputs.max_rounds);
        let remainder = u64::from(inputs.max_rounds)
            .saturating_sub(u64::from(r))
            .saturating_add(1);
        let numerator = std::cmp::min(remainder, u64::from(inputs.max_rounds));
        let speed_bps = (numerator * 3000) / u64::from(inputs.max_rounds);
        score += speed_bps;
    }

    // 3. Devil's Advocate (20%)
    if !inputs.devil_found_serious_objection {
        score += 2000;
    }

    score
}

// ===========================================================================
// Property tests — A-010: prove convergence scoring never panics and always
// returns a score in [0, 10000] regardless of input shape.
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// `calculate_convergence` must never panic on arbitrary input and
        /// must always return a score within the valid bps range.
        #[test]
        fn convergence_never_panics_and_bounded(positions in proptest::collection::vec(proptest::collection::vec(".*", 0..10), 0..20)) {
            let score = calculate_convergence(&positions);
            prop_assert!(score <= 10000, "score {score} out of range");
        }

        /// Identical positions must always score 10000 (perfect convergence),
        /// regardless of claim shape.
        #[test]
        fn identical_positions_always_ten_thousand(
            pos in proptest::collection::vec("[A-Za-z0-9][A-Za-z0-9 _-]{0,32}", 1..10)
        ) {
            let refs = vec![pos; 5];
            let score = calculate_convergence(&refs);
            prop_assert_eq!(score, 10000);
        }

        /// `calculate_panel_confidence` must never panic and always return
        /// a bounded score.
        #[test]
        fn panel_confidence_bounded(
            models_agreeing in 0u32..=1000,
            total_models in 0u32..=1000,
            rounds_to_convergence in 0u32..=100,
            max_rounds in 0u32..=100,
            devil in any::<bool>(),
            minority in 0u32..=1000,
        ) {
            let inputs = PanelConfidenceInputs {
                models_agreeing,
                total_models,
                rounds_to_convergence,
                max_rounds,
                devil_found_serious_objection: devil,
                minority_reports_count: minority,
            };
            let score = calculate_panel_confidence(&inputs);
            // Max theoretical: 5000 (agreement) + 3000 (speed) + 2000 (devil) = 10000.
            prop_assert!(score <= 10000, "score {score} exceeds 10000 bps ceiling");
        }
    }

    /// Boundary: empty input returns 0.
    #[test]
    fn empty_positions_returns_zero() {
        assert_eq!(calculate_convergence(&[]), 0);
    }

    /// Boundary: single position returns 10000 (trivially self-consistent).
    #[test]
    fn single_position_returns_ten_thousand() {
        assert_eq!(calculate_convergence(&[vec!["only one".into()]]), 10000);
    }

    /// Boundary: all-empty claim sets should not panic and should yield 0
    /// because no explicit claim evidence exists.
    #[test]
    fn all_empty_strings_do_not_panic() {
        let score = calculate_convergence(&[Vec::new(), Vec::new(), Vec::new()]);
        assert_eq!(score, 0);
    }

    /// Boundary: single-claim positions with disjoint claims score zero.
    #[test]
    fn disjoint_single_claims_score_zero() {
        let score = calculate_convergence(&[
            vec!["A".to_string()],
            vec!["B".to_string()],
            vec!["C".to_string()],
        ]);
        assert_eq!(score, 0);
    }
}
