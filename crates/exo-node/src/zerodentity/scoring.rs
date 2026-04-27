//! 0dentity polar-decomposition scoring engine.
//!
//! Implements `ZerodentityScore::compute()` — the canonical algorithm all
//! nodes must execute identically for constitutional determinism (spec §5).
//!
//! ## Determinism guarantees
//!
//! - All intermediate values are `u32` basis points (0–10_000 = 0%–100.00%).
//!   No `f64` is used anywhere; `int_ln_milli` and `isqrt` replace the
//!   spec's `f64::ln` and `f64::sqrt` with workspace-compliant integer math.
//! - Distinct-DID / distinct-signal-type counts use `BTreeSet`, not `HashSet`.
//! - Input slices must be sorted by `created_ms` ascending before calling
//!   `compute()`.  The caller is responsible for this invariant.
// The scoring engine performs extensive integer arithmetic with safe `as`
// casts between bounded integer types (e.g. `usize` → `u32` for counts
// that are capped by `.min()` before conversion).  All values are in
// basis-points (0–10_000) so overflow is impossible in practice.
#![allow(
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::manual_range_contains
)]

use std::collections::BTreeSet;

use exo_core::types::{Did, Hash256, Signature};

use super::{
    device_behavioral_axes_enabled,
    types::{
        BehavioralSample, BehavioralSignalType, ClaimStatus, ClaimType, DeviceFingerprint,
        IdentityClaim, PolarAxes, ZerodentityScore,
    },
};

// ---------------------------------------------------------------------------
// Integer math helpers
// ---------------------------------------------------------------------------

/// Integer floor of `ln(x) * 1000` for `x >= 1`.
///
/// Uses bit-length for `floor(log2)` and a second-order Taylor expansion for
/// the fractional part.  Error < 5% for all `x ≥ 2`, which is within scoring
/// tolerance.
fn int_ln_milli(x: u64) -> u64 {
    if x <= 1 {
        return 0;
    }
    const LN2_MILLI: u64 = 693; // ln(2) × 1000
    let k = (63 - x.leading_zeros()) as u64; // floor(log2(x))
    let power = 1u64 << (k as u32);
    // Encode fractional part f = x/2^k − 1 as f_num ∈ [0, 1024).
    let f_num = (x.saturating_sub(power) << 10) / power;
    // ln(1 + f) ≈ f − f²/2  (second-order Taylor)
    let term1 = f_num * 1000 / 1024;
    let term2 = f_num * f_num * 500 / (1024 * 1024);
    let ln_frac = term1.saturating_sub(term2);
    k * LN2_MILLI + ln_frac
}

/// Integer square root (Newton-Raphson, converges in ≤ 64 iterations).
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// ZerodentityScore::compute
// ---------------------------------------------------------------------------

impl ZerodentityScore {
    /// Recompute the full polar score from the current evidence set.
    ///
    /// This is the canonical scoring algorithm.  All nodes must produce the
    /// same output for the same inputs (constitutional determinism, spec §5.1).
    ///
    /// Pass the stored `computed_ms` when recomputing to verify sentinel
    /// integrity.
    #[must_use]
    pub fn compute(
        subject_did: &Did,
        claims: &[IdentityClaim],
        fingerprints: &[DeviceFingerprint],
        behavioral_samples: &[BehavioralSample],
        now_ms: u64,
    ) -> Self {
        let axes = PolarAxes {
            communication: score_communication(claims),
            credential_depth: score_credential_depth(claims),
            device_trust: if device_behavioral_axes_enabled() {
                score_device_trust(fingerprints)
            } else {
                0
            },
            behavioral_signature: if device_behavioral_axes_enabled() {
                score_behavioral(behavioral_samples)
            } else {
                0
            },
            network_reputation: score_network_reputation(claims),
            temporal_stability: score_temporal_stability(claims, now_ms),
            cryptographic_strength: score_cryptographic_strength(claims),
            constitutional_standing: score_constitutional_standing(claims),
        };

        let axis_values = axes.as_array();
        let composite = axis_values.iter().copied().sum::<u32>() / 8;
        let symmetry = compute_symmetry(&axis_values);
        let dag_state_hash = hash_claim_set(claims);
        let claim_count = claims
            .iter()
            .filter(|c| c.status == ClaimStatus::Verified)
            .count() as u32;

        ZerodentityScore {
            subject_did: subject_did.clone(),
            axes,
            composite,
            computed_ms: now_ms,
            dag_state_hash,
            claim_count,
            symmetry,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-axis scoring functions (spec §5.2)
// ---------------------------------------------------------------------------

/// Communication axis (0–10_000 bp).
fn score_communication(claims: &[IdentityClaim]) -> u32 {
    let mut score: u32 = 0;

    let verified_email = claims
        .iter()
        .any(|c| c.claim_type == ClaimType::Email && c.status == ClaimStatus::Verified);
    let verified_phone = claims
        .iter()
        .any(|c| c.claim_type == ClaimType::Phone && c.status == ClaimStatus::Verified);

    if verified_email {
        score += 3500;
    }
    if verified_phone {
        score += 3700;
    }
    if verified_email && verified_phone {
        score += 1500; // both-channels bonus
    }

    let extra = claims
        .iter()
        .filter(|c| {
            matches!(c.claim_type, ClaimType::ProfessionalCredential { .. })
                && c.status == ClaimStatus::Verified
        })
        .count() as u32;
    score += (extra * 400).min(1300);

    score.min(10_000)
}

/// Credential Depth axis (0–10_000 bp).
fn score_credential_depth(claims: &[IdentityClaim]) -> u32 {
    let mut score: u32 = 0;

    if claims
        .iter()
        .any(|c| c.claim_type == ClaimType::DisplayName)
    {
        score += 500;
    }
    if claims
        .iter()
        .any(|c| c.claim_type == ClaimType::GovernmentId && c.status == ClaimStatus::Verified)
    {
        score += 3500;
    }
    if claims
        .iter()
        .any(|c| c.claim_type == ClaimType::BiometricLiveness && c.status == ClaimStatus::Verified)
    {
        score += 3000;
    }
    let pro_count = claims
        .iter()
        .filter(|c| {
            matches!(c.claim_type, ClaimType::ProfessionalCredential { .. })
                && c.status == ClaimStatus::Verified
        })
        .count() as u32;
    score += (pro_count * 1000).min(3000);

    score.min(10_000)
}

/// Device Trust axis (0–10_000 bp).
fn score_device_trust(fingerprints: &[DeviceFingerprint]) -> u32 {
    if fingerprints.is_empty() {
        return 0;
    }

    let mut score: u32 = 2000; // base for having any fingerprint

    let latest = &fingerprints[fingerprints.len() - 1];

    // Signal coverage: max 15 signal types → up to 2500 bp contribution.
    let signal_count = (latest.signal_hashes.len() as u32).min(15);
    let coverage_bp = signal_count * 10_000 / 15;
    score += coverage_bp / 4; // coverage_bp * 25 / 100

    // Consistency score.
    if let Some(consistency_bp) = latest.consistency_score_bp {
        score += consistency_bp * 2 / 5; // consistency * 40/100 → * 2/5
    } else {
        score += 1600; // first session — partial credit
    }

    // Multi-session consistency bonus.
    if fingerprints.len() >= 3 {
        let with_score: Vec<u32> = fingerprints
            .iter()
            .filter_map(|f| f.consistency_score_bp)
            .collect();
        if !with_score.is_empty() {
            let avg_bp = with_score.iter().copied().sum::<u32>() / with_score.len() as u32;
            score += avg_bp * 3 / 20; // avg_consistency * 15/100 → * 3/20
        }
    }

    score.min(10_000)
}

/// Behavioral Signature axis (0–10_000 bp).
fn score_behavioral(samples: &[BehavioralSample]) -> u32 {
    if samples.is_empty() {
        return 0;
    }

    let mut score: u32 = 1000; // base for any behavioral data

    // Diversity of signal types (BTreeSet for deterministic ordering).
    let signal_types: BTreeSet<&BehavioralSignalType> =
        samples.iter().map(|s| &s.signal_type).collect();
    score += ((signal_types.len() as u32) * 600).min(1800);

    // Baseline similarity.
    let similarities: Vec<u32> = samples
        .iter()
        .filter_map(|s| s.baseline_similarity_bp)
        .collect();
    if similarities.is_empty() {
        score += 1600; // first session — establishing baseline
    } else {
        let avg_bp = similarities.iter().copied().sum::<u32>() / similarities.len() as u32;
        score += avg_bp * 2 / 5; // avg_similarity * 40/100 → * 2/5
    }

    // Sample volume: ln(count) * 500 bp, capped at 1600.
    let count = samples.len() as u64;
    let ln_contrib = (int_ln_milli(count) * 500 / 1000) as u32;
    score += ln_contrib.min(1600);

    score.min(10_000)
}

/// Network Reputation axis (0–10_000 bp).
fn score_network_reputation(claims: &[IdentityClaim]) -> u32 {
    let mut score: u32 = 1000; // base

    // Peer attestations from distinct verifiers.
    let attesters: BTreeSet<&Did> = claims
        .iter()
        .filter_map(|c| match &c.claim_type {
            ClaimType::PeerAttestation { attester_did } if c.status == ClaimStatus::Verified => {
                Some(attester_did)
            }
            _ => None,
        })
        .collect();
    score += ((attesters.len() as u32) * 500).min(4000);

    // Delegation grants.
    let delegations = claims
        .iter()
        .filter(|c| {
            matches!(c.claim_type, ClaimType::DelegationGrant { .. })
                && c.status == ClaimStatus::Verified
        })
        .count() as u32;
    score += (delegations * 800).min(2400);

    // Sybil challenge resolutions.
    let resolved = claims
        .iter()
        .filter(|c| {
            matches!(c.claim_type, ClaimType::SybilChallengeResolution { .. })
                && c.status == ClaimStatus::Verified
        })
        .count() as u32;
    score += (resolved * 1200).min(3600);

    score.min(10_000)
}

/// Temporal Stability axis (0–10_000 bp).
fn score_temporal_stability(claims: &[IdentityClaim], now_ms: u64) -> u32 {
    if claims.is_empty() {
        return 0;
    }

    let mut score: u32 = 0;

    // Account age: ln(age_days) * 800 bp, capped at 3500.
    let oldest_ms = claims.iter().map(|c| c.created_ms).min().unwrap_or(now_ms);
    let age_days = now_ms.saturating_sub(oldest_ms) / 86_400_000;
    if age_days > 0 {
        let contrib = (int_ln_milli(age_days) * 800 / 1000) as u32;
        score += contrib.min(3500);
    }

    // Verification freshness. `checked_div` handles total_verified == 0
    // without an outer `if`, satisfying clippy::manual_checked_ops.
    let verified: Vec<&IdentityClaim> = claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Verified)
        .collect();
    let total_verified = verified.len() as u32;
    let fresh = verified
        .iter()
        .filter(|c| c.expires_ms.is_none_or(|exp| exp > now_ms))
        .count() as u32;
    if let Some(freshness_bp) = fresh
        .checked_mul(10_000)
        .and_then(|n| n.checked_div(total_verified))
    {
        score += freshness_bp * 30 / 100;
    }

    // Claim renewal activity.
    let renewals = claims
        .iter()
        .filter(|c| c.verified_ms.is_some_and(|v| v != c.created_ms))
        .count() as u32;
    score += (renewals * 500).min(2000);

    // Session continuity claims.
    let sessions = claims
        .iter()
        .filter(|c| c.claim_type == ClaimType::SessionContinuity)
        .count() as u32;
    score += (sessions * 200).min(1500);

    score.min(10_000)
}

/// Cryptographic Strength axis (0–10_000 bp).
fn score_cryptographic_strength(claims: &[IdentityClaim]) -> u32 {
    let mut score: u32 = 1500; // base for having any key

    if let Some(latest) = claims.last() {
        match &latest.signature {
            Signature::Ed25519(_) => score += 2500,
            Signature::Hybrid { .. } => score += 4000, // classical + PQ = best
            Signature::PostQuantum(_) => score += 3500,
            Signature::Empty => {}
        }
    }

    let rotations = claims
        .iter()
        .filter(|c| matches!(c.claim_type, ClaimType::KeyRotation { .. }))
        .count() as u32;
    score += (rotations * 800).min(2400);

    if claims
        .iter()
        .any(|c| c.claim_type == ClaimType::EntropyAttestation)
    {
        score += 1000;
    }

    // Penalty: account > 90 days without a key rotation.
    if rotations == 0 && !claims.is_empty() {
        let oldest = claims.iter().map(|c| c.created_ms).min().unwrap_or(0);
        let newest = claims.iter().map(|c| c.created_ms).max().unwrap_or(0);
        let age_days = newest.saturating_sub(oldest) / 86_400_000;
        if age_days > 90 {
            score = score.saturating_sub(1000);
        }
    }

    score.min(10_000)
}

/// Constitutional Standing axis (0–10_000 bp).
fn score_constitutional_standing(claims: &[IdentityClaim]) -> u32 {
    let mut score: u32 = 1000; // base

    let votes = claims
        .iter()
        .filter(|c| matches!(c.claim_type, ClaimType::GovernanceVote { .. }))
        .count() as u32;
    score += (votes * 400).min(2000);

    let proposals = claims
        .iter()
        .filter(|c| matches!(c.claim_type, ClaimType::ProposalAuthored { .. }))
        .count() as u32;
    score += (proposals * 700).min(2100);

    let validator = claims
        .iter()
        .filter(|c| matches!(c.claim_type, ClaimType::ValidatorService { .. }))
        .count() as u32;
    score += (validator * 500).min(2500);

    let resolutions = claims
        .iter()
        .filter(|c| matches!(c.claim_type, ClaimType::SybilChallengeResolution { .. }))
        .count() as u32;
    score += (resolutions * 800).min(2400);

    score.min(10_000)
}

// ---------------------------------------------------------------------------
// Symmetry (spec §5.3)
// ---------------------------------------------------------------------------

/// Symmetry index (0–10_000 bp): how evenly the score is spread across axes.
///
/// 10_000 = perfect octagon (all axes equal).
/// 0 = all score on one axis.
///
/// Formula: `symmetry = 1 − (σ / μ)` in basis points.
pub(crate) fn compute_symmetry(axes: &[u32; 8]) -> u32 {
    let sum: u32 = axes.iter().copied().sum();
    let mean = sum / 8;
    if mean == 0 {
        return 0;
    }
    let variance: u64 = axes
        .iter()
        .map(|&a| {
            let diff = a.abs_diff(mean);
            (diff as u64) * (diff as u64)
        })
        .sum::<u64>()
        / 8;
    let std_dev = isqrt(variance) as u32;
    let cv_bp = (std_dev as u64 * 10_000 / mean as u64) as u32;
    10_000u32.saturating_sub(cv_bp)
}

// ---------------------------------------------------------------------------
// Claim-set hash (spec §5)
// ---------------------------------------------------------------------------

/// BLAKE3 digest of the sorted claim hashes.
///
/// Uniquely identifies the claim DAG state at computation time, enabling
/// deterministic recomputation from any node.
pub(crate) fn hash_claim_set(claims: &[IdentityClaim]) -> Hash256 {
    let mut sorted: Vec<&[u8; 32]> = claims.iter().map(|c| c.claim_hash.as_bytes()).collect();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for h in sorted {
        hasher.update(h);
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use exo_core::types::Did;

    use super::*;
    use crate::zerodentity::types::{
        BehavioralSample, BehavioralSignalType, DeviceFingerprint, FingerprintSignal,
    };

    fn did() -> Did {
        Did::new("did:exo:test0001").unwrap()
    }

    fn h() -> Hash256 {
        Hash256::digest(b"test")
    }

    fn fingerprint_sample() -> DeviceFingerprint {
        DeviceFingerprint {
            composite_hash: h(),
            signal_hashes: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(FingerprintSignal::CanvasRendering, h());
                m.insert(FingerprintSignal::UserAgent, h());
                m
            },
            captured_ms: 1000,
            consistency_score_bp: Some(9000),
        }
    }

    fn behavioral_sample(signal_type: BehavioralSignalType, similarity: u32) -> BehavioralSample {
        BehavioralSample {
            sample_hash: h(),
            signal_type,
            captured_ms: 1000,
            baseline_similarity_bp: Some(similarity),
        }
    }

    fn claim(ct: ClaimType, status: ClaimStatus) -> IdentityClaim {
        IdentityClaim {
            claim_hash: h(),
            subject_did: did(),
            claim_type: ct,
            status,
            created_ms: 1_000_000,
            verified_ms: None,
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: h(),
        }
    }

    // ---- integer helpers ----

    #[test]
    fn ln_milli_edge_cases() {
        assert_eq!(int_ln_milli(0), 0);
        assert_eq!(int_ln_milli(1), 0);
    }

    #[test]
    fn ln_milli_approx_ln2() {
        let v = int_ln_milli(2);
        // ln(2)*1000 ≈ 693 ± 30
        assert!(v >= 663 && v <= 723, "int_ln_milli(2) = {v}, expected ~693");
    }

    #[test]
    fn isqrt_perfect_squares() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(10_000), 100);
    }

    #[test]
    fn isqrt_rounds_down() {
        assert_eq!(isqrt(2), 1);
        assert_eq!(isqrt(8), 2);
        assert_eq!(isqrt(15), 3);
    }

    // ---- axis functions ----

    #[test]
    fn communication_no_claims() {
        assert_eq!(score_communication(&[]), 0);
    }

    #[test]
    fn communication_email_and_phone_verified() {
        let claims = vec![
            claim(ClaimType::Email, ClaimStatus::Verified),
            claim(ClaimType::Phone, ClaimStatus::Verified),
        ];
        // 3500 + 3700 + 1500 = 8700
        assert_eq!(score_communication(&claims), 8700);
    }

    #[test]
    fn communication_cap() {
        let mut claims = vec![
            claim(ClaimType::Email, ClaimStatus::Verified),
            claim(ClaimType::Phone, ClaimStatus::Verified),
        ];
        for i in 0..20u32 {
            claims.push(claim(
                ClaimType::ProfessionalCredential {
                    provider: format!("p{i}"),
                },
                ClaimStatus::Verified,
            ));
        }
        assert_eq!(score_communication(&claims), 10_000);
    }

    #[test]
    fn device_trust_no_fingerprints() {
        assert_eq!(score_device_trust(&[]), 0);
    }

    #[test]
    fn device_trust_first_session_no_consistency() {
        let fp = DeviceFingerprint {
            composite_hash: h(),
            signal_hashes: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(FingerprintSignal::CanvasRendering, h());
                m.insert(FingerprintSignal::UserAgent, h());
                m
            },
            captured_ms: 1000,
            consistency_score_bp: None,
        };
        let score = score_device_trust(&[fp]);
        // base 2000 + coverage(2/15*2500/10000=) + 1600 partial ≈ 3700+
        assert!(score >= 3500 && score <= 4500, "got {score}");
    }

    #[test]
    fn behavioral_no_samples() {
        assert_eq!(score_behavioral(&[]), 0);
    }

    #[test]
    fn behavioral_diverse_signals() {
        let samples = vec![
            BehavioralSample {
                sample_hash: h(),
                signal_type: BehavioralSignalType::KeystrokeDynamics,
                captured_ms: 1000,
                baseline_similarity_bp: Some(8000),
            },
            BehavioralSample {
                sample_hash: h(),
                signal_type: BehavioralSignalType::MouseDynamics,
                captured_ms: 2000,
                baseline_similarity_bp: Some(9000),
            },
        ];
        let score = score_behavioral(&samples);
        // base 1000 + diversity(2*600=1200) + avg_similarity(8500*2/5=3400) + ln(2)*500/1000
        assert!(score > 5000, "got {score}");
    }

    #[test]
    fn network_reputation_base() {
        assert_eq!(score_network_reputation(&[]), 1000);
    }

    #[test]
    fn temporal_stability_empty() {
        assert_eq!(score_temporal_stability(&[], 1_000_000), 0);
    }

    #[test]
    fn constitutional_standing_base() {
        assert_eq!(score_constitutional_standing(&[]), 1000);
    }

    // ---- symmetry ----

    #[test]
    fn symmetry_uniform() {
        let axes = [5000u32; 8];
        assert_eq!(compute_symmetry(&axes), 10_000);
    }

    #[test]
    fn symmetry_all_zero() {
        assert_eq!(compute_symmetry(&[0u32; 8]), 0);
    }

    #[test]
    fn symmetry_highly_skewed() {
        let mut axes = [0u32; 8];
        axes[0] = 10_000;
        let sym = compute_symmetry(&axes);
        assert!(sym < 5000, "skewed → symmetry should be low, got {sym}");
    }

    // ---- full compute ----

    #[test]
    fn compute_deterministic() {
        let d = did();
        let claims = vec![
            claim(ClaimType::Email, ClaimStatus::Verified),
            claim(ClaimType::Phone, ClaimStatus::Verified),
        ];
        let s1 = ZerodentityScore::compute(&d, &claims, &[], &[], 10_000_000);
        let s2 = ZerodentityScore::compute(&d, &claims, &[], &[], 10_000_000);
        assert_eq!(s1.composite, s2.composite);
        assert_eq!(s1.symmetry, s2.symmetry);
        assert_eq!(s1.dag_state_hash, s2.dag_state_hash);
    }

    #[test]
    fn compute_zero_drift_on_recompute() {
        // Sentinel integrity property: recomputed score == stored score.
        let d = did();
        let claims = vec![
            claim(ClaimType::Email, ClaimStatus::Verified),
            claim(ClaimType::GovernmentId, ClaimStatus::Verified),
        ];
        let stored = ZerodentityScore::compute(&d, &claims, &[], &[], 5_000_000);
        let recomputed = ZerodentityScore::compute(&d, &claims, &[], &[], stored.computed_ms);
        let drift = stored.composite.abs_diff(recomputed.composite);
        assert_eq!(drift, 0, "deterministic algorithm must produce zero drift");
    }

    #[cfg(not(feature = "unaudited-zerodentity-device-behavioral-axes"))]
    #[test]
    fn compute_ignores_device_behavioral_samples_without_feature_flag() {
        let d = did();
        let fingerprints = vec![fingerprint_sample()];
        let behavioral = vec![
            behavioral_sample(BehavioralSignalType::KeystrokeDynamics, 9000),
            behavioral_sample(BehavioralSignalType::MouseDynamics, 8000),
        ];
        let score = ZerodentityScore::compute(&d, &[], &fingerprints, &behavioral, 10_000_000);

        assert_eq!(
            score.axes.device_trust, 0,
            "device_trust must stay zero while R3 axes are feature-gated"
        );
        assert_eq!(
            score.axes.behavioral_signature, 0,
            "behavioral_signature must stay zero while R3 axes are feature-gated"
        );
    }

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[test]
    fn compute_uses_device_behavioral_samples_with_feature_flag() {
        let d = did();
        let fingerprints = vec![fingerprint_sample()];
        let behavioral = vec![
            behavioral_sample(BehavioralSignalType::KeystrokeDynamics, 9000),
            behavioral_sample(BehavioralSignalType::MouseDynamics, 8000),
        ];
        let score = ZerodentityScore::compute(&d, &[], &fingerprints, &behavioral, 10_000_000);

        assert!(
            score.axes.device_trust > 0,
            "feature-on build must preserve existing device_trust scoring"
        );
        assert!(
            score.axes.behavioral_signature > 0,
            "feature-on build must preserve existing behavioral scoring"
        );
    }
}
