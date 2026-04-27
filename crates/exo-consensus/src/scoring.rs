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

/// Calculate convergence between a set of positions (in bps, 0–10000).
/// This extracts mock "key claims" by splitting the text by lines or using provided claims
/// but for the real system we expect structured claims. Here we simulate it by comparing
/// the sets of words or using the actual key_claims array if we can pass it.
/// Actually, the prompt says:
/// `calculate_convergence(positions: &[&str]) -> u64`
/// "Use categorical comparison: count matching key claims across positions divided by total unique claims."
/// We'll assume the positions string represents a comma-separated or line-separated list of claims if it's raw text,
/// but let's implement it robustly: tokenize and find overlap.
pub fn calculate_convergence(positions: &[&str]) -> u64 {
    if positions.is_empty() {
        return 0;
    }
    if positions.len() == 1 {
        return 10000;
    }

    // A simple categorical extraction: split by common delimiters and trim.
    // In production, these would be structured key_claims provided to the function.
    let mut all_claims = BTreeSet::new();
    let mut model_claims = Vec::new();

    for pos in positions {
        let mut claims = BTreeSet::new();
        // Extract claims by splitting on commas or newlines for simplistic proxy
        let parts: Vec<&str> = pos.split([',', '\n', ';']).collect();
        for p in parts {
            let clean = p.trim().to_lowercase();
            if !clean.is_empty() {
                claims.insert(clean.clone());
                all_claims.insert(clean);
            }
        }
        model_claims.push(claims);
    }

    if all_claims.is_empty() {
        return 10000; // If they all submitted empty, they agree.
    }

    let _match_score = 0;
    let total_unique = u64::try_from(all_claims.len()).unwrap_or(0);

    for claim in &all_claims {
        let _count =
            u64::try_from(model_claims.iter().filter(|c| c.contains(claim)).count()).unwrap_or(0);
        // The more models share the claim, the more "matching" it is.
        // A claim shared by ALL models is a perfect match (worth 1).
        // Here we just say: if a claim is shared by more than half, it's a majority claim.
        // Let's use a simple ratio: sum(count) / (total_unique * num_models)
        // match_score += count; // Keeping for reference if needed
    }

    let max_possible_score = total_unique * u64::try_from(positions.len()).unwrap_or(0);
    // Invariant chain: positions.len() >= 2 (early-returned 0/1 above) and
    // all_claims.len() >= 1 (early-returned empty above). u64::try_from only
    // fails for usize > 2^64, impossible for in-memory collections. Guard
    // remains for defense-in-depth against pathological platforms.
    if max_possible_score == 0 {
        return 10000;
    }

    // If we want identical positions to be 10000 and 0 overlap to be 0:
    // This formula works: match_score / max_possible_score
    // Example: 2 positions. "A, B" and "A, C".
    // all_claims: A, B, C.
    // A count = 2. B count = 1. C count = 1.
    // match_score = 4. max_possible_score = 3 * 2 = 6.
    // 4 / 6 = 66%. Wait, 50% overlap.
    // Let's refine based on "matching key claims across positions divided by total unique claims".
    // A matching claim means it's present in ALL positions.
    let shared_claims = u64::try_from(
        all_claims
            .iter()
            .filter(|c| model_claims.iter().all(|mc| mc.contains(*c)))
            .count(),
    )
    .unwrap_or(0);

    (shared_claims * 10000) / total_unique
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
        fn convergence_never_panics_and_bounded(positions in proptest::collection::vec(".*", 0..20)) {
            let refs: Vec<&str> = positions.iter().map(String::as_str).collect();
            let score = calculate_convergence(&refs);
            prop_assert!(score <= 10000, "score {score} out of range");
        }

        /// Identical positions must always score 10000 (perfect convergence),
        /// regardless of claim shape.
        #[test]
        fn identical_positions_always_ten_thousand(pos in ".+") {
            let refs = vec![pos.as_str(); 5];
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
        assert_eq!(calculate_convergence(&["only one"]), 10000);
    }

    /// Boundary: all-empty strings should not panic and should yield 10000
    /// (no claims to disagree on).
    #[test]
    fn all_empty_strings_do_not_panic() {
        let score = calculate_convergence(&["", "", ""]);
        assert_eq!(score, 10000);
    }

    /// Boundary: single-claim positions with disjoint claims score zero.
    #[test]
    fn disjoint_single_claims_score_zero() {
        let score = calculate_convergence(&["A", "B", "C"]);
        assert_eq!(score, 0);
    }
}
