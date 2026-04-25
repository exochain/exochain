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

/// Calculate Panel Confidence Index in bps.
/// model agreement (50%), speed of convergence (30%), devil's advocate (20%).
pub fn calculate_panel_confidence(inputs: &PanelConfidenceInputs) -> u64 {
    let mut score = 0;

    // 1. Model Agreement (50%)
    if inputs.total_models > 0 {
        let agreement_bps =
            (u64::from(inputs.models_agreeing) * 5000) / u64::from(inputs.total_models);
        score += agreement_bps;
    }

    // 2. Speed of Convergence (30%)
    if inputs.max_rounds > 0 {
        // Faster is better: (max - rounds + 1) / max
        // If max_rounds=3, rounds_to_convergence=1 -> 3/3 = 100% -> 3000 bps
        // rounds_to_convergence=3 -> 1/3 -> 1000 bps
        // If it never converged (rounds_to_convergence > max_rounds), maybe 0?
        let r = std::cmp::min(inputs.rounds_to_convergence, inputs.max_rounds);
        let speed_bps = ((u64::from(inputs.max_rounds) - u64::from(r) + 1) * 3000)
            / u64::from(inputs.max_rounds);
        score += speed_bps;
    }

    // 3. Devil's Advocate (20%)
    if !inputs.devil_found_serious_objection {
        score += 2000;
    }

    score
}
