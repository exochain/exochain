//! Behavioral biometric baseline comparison.
//!
//! Computes the similarity between a new behavioral sample and the established
//! baseline (the average of prior samples for the same signal type).
//!
//! All values in basis points (0–10_000 = 0%–100%).
//!
//! Spec reference: §3.2.

use exo_core::types::Hash256;

use super::types::{BehavioralSample, BehavioralSignalType};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Quantize a sequence of timing values into a histogram.
///
/// Each value is placed in one of `buckets` equal-width buckets, and the
/// bucket counts are returned as a `Vec<u32>`.
///
/// Spec §3.2: inter-key intervals (μs) are quantised into 20 buckets.
#[allow(dead_code)]
pub fn quantize_to_histogram(values: &[u64], buckets: usize) -> Vec<u32> {
    if values.is_empty() || buckets == 0 {
        return vec![0u32; buckets];
    }

    let min = *values.iter().min().unwrap_or(&0);
    let max = *values.iter().max().unwrap_or(&0);

    // Edge case: all values identical → one bucket is full
    if min == max {
        let mut hist = vec![0u32; buckets];
        hist[0] = u32::try_from(values.len()).unwrap_or(u32::MAX);
        return hist;
    }

    let range = max - min;
    let mut hist = vec![0u32; buckets];
    for &v in values {
        // Compute bucket index; clamp to [0, buckets-1]
        let idx = usize::try_from(
            u128::from(v - min) * u128::try_from(buckets).unwrap_or(0) / (u128::from(range) + 1),
        )
        .unwrap_or(0);
        let idx = idx.min(buckets - 1);
        hist[idx] += 1;
    }
    hist
}

/// Compute the similarity between two histograms in basis points (0–10_000).
///
/// Uses the intersection-over-union metric (Jaccard on histogram bins):
/// ```text
/// sim = Σ min(a_i, b_i) / Σ max(a_i, b_i)  (scaled to 10_000)
/// ```
/// Returns 10_000 if both histograms are empty.
#[allow(dead_code)]
pub fn histogram_similarity(a: &[u32], b: &[u32]) -> u32 {
    let len = a.len().max(b.len());
    if len == 0 {
        return 10_000;
    }

    let sum_min: u64 = (0..len)
        .map(|i| {
            let ai = u64::from(a.get(i).copied().unwrap_or(0));
            let bi = u64::from(b.get(i).copied().unwrap_or(0));
            ai.min(bi)
        })
        .sum();

    let sum_max: u64 = (0..len)
        .map(|i| {
            let ai = u64::from(a.get(i).copied().unwrap_or(0));
            let bi = u64::from(b.get(i).copied().unwrap_or(0));
            ai.max(bi)
        })
        .sum();

    if sum_max == 0 {
        return 10_000; // all zeros = trivially identical
    }

    u32::try_from((sum_min * 10_000) / sum_max).unwrap_or(u32::MAX)
}

/// Compute the baseline similarity for a new sample hash against prior samples.
///
/// For each prior sample of the same signal type, treats the `sample_hash`
/// bytes as a compact fingerprint and computes byte-level Jaccard similarity.
///
/// Returns `None` if there are no prior samples (first session = no baseline).
#[allow(dead_code)]
pub fn compute_baseline_similarity(
    prior_samples: &[BehavioralSample],
    new_hash: &Hash256,
    signal_type: &BehavioralSignalType,
) -> Option<u32> {
    let matching: Vec<&BehavioralSample> = prior_samples
        .iter()
        .filter(|s| s.signal_type == *signal_type)
        .collect();

    if matching.is_empty() {
        return None;
    }

    // Compute byte-level Jaccard similarity between new_hash and each prior hash,
    // then return the average.
    let sum: u64 = matching
        .iter()
        .map(|s| {
            u64::from(byte_similarity(
                new_hash.as_bytes(),
                s.sample_hash.as_bytes(),
            ))
        })
        .sum();

    Some(u32::try_from(sum / u64::try_from(matching.len()).unwrap_or(1)).unwrap_or(u32::MAX))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Byte-level Jaccard similarity between two 32-byte hashes.
///
/// For each byte position, computes min/max overlap:
/// `sim = Σ min(a[i], b[i]) / Σ max(a[i], b[i])` (scaled to 10_000)
#[allow(dead_code)]
fn byte_similarity(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    let sum_min: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(&ai, &bi)| u32::from(ai.min(bi)))
        .sum();
    let sum_max: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(&ai, &bi)| u32::from(ai.max(bi)))
        .sum();
    if sum_max == 0 {
        return 10_000;
    }
    u32::try_from(u64::from(sum_min) * 10_000 / u64::from(sum_max)).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(b: &[u8]) -> Hash256 {
        Hash256::digest(b)
    }

    fn sample(st: BehavioralSignalType, h: Hash256) -> BehavioralSample {
        BehavioralSample {
            sample_hash: h,
            signal_type: st,
            captured_ms: 1000,
            baseline_similarity_bp: None,
        }
    }

    // ---- quantize_to_histogram ----

    #[test]
    fn quantize_empty_returns_zero_buckets() {
        let h = quantize_to_histogram(&[], 5);
        assert_eq!(h.len(), 5);
        assert!(h.iter().all(|&v| v == 0));
    }

    #[test]
    fn quantize_all_same_value() {
        let h = quantize_to_histogram(&[100, 100, 100, 100], 4);
        assert_eq!(h[0], 4, "all same value goes to bucket 0");
    }

    #[test]
    fn quantize_spread() {
        let vals: Vec<u64> = (0..100).collect();
        let h = quantize_to_histogram(&vals, 10);
        // Each bucket should have ~10 values
        assert_eq!(h.iter().sum::<u32>(), 100);
        assert_eq!(h.len(), 10);
    }

    // ---- histogram_similarity ----

    #[test]
    fn histogram_sim_identical() {
        let hist = vec![5, 10, 3, 2];
        assert_eq!(histogram_similarity(&hist, &hist), 10_000);
    }

    #[test]
    fn histogram_sim_completely_different() {
        let a = vec![10, 0, 0, 0];
        let b = vec![0, 0, 0, 10];
        assert_eq!(histogram_similarity(&a, &b), 0);
    }

    #[test]
    fn histogram_sim_partial() {
        let a = vec![5, 5];
        let b = vec![5, 0]; // 5 overlap out of max(5+5, 5+0) = 10 sum_max
        // sum_min = min(5,5) + min(5,0) = 5 + 0 = 5
        // sum_max = max(5,5) + max(5,0) = 5 + 5 = 10
        // sim = 5 * 10_000 / 10 = 5000
        assert_eq!(histogram_similarity(&a, &b), 5000);
    }

    #[test]
    fn histogram_sim_empty() {
        assert_eq!(histogram_similarity(&[], &[]), 10_000);
    }

    // ---- compute_baseline_similarity ----

    #[test]
    fn baseline_similarity_no_prior() {
        let new_hash = hash(b"new");
        let result =
            compute_baseline_similarity(&[], &new_hash, &BehavioralSignalType::KeystrokeDynamics);
        assert!(result.is_none(), "no prior samples = no baseline");
    }

    #[test]
    fn baseline_similarity_identical_hash() {
        let h = hash(b"exact-same");
        let prior = vec![sample(BehavioralSignalType::KeystrokeDynamics, h)];
        let result =
            compute_baseline_similarity(&prior, &h, &BehavioralSignalType::KeystrokeDynamics);
        assert_eq!(result, Some(10_000), "identical hash → max similarity");
    }

    #[test]
    fn baseline_similarity_filters_by_type() {
        let h = hash(b"mouse");
        let mouse_sample = sample(BehavioralSignalType::MouseDynamics, h);
        // Prior has MouseDynamics, but we're querying KeystrokeDynamics → no baseline
        let result = compute_baseline_similarity(
            &[mouse_sample],
            &hash(b"keystroke"),
            &BehavioralSignalType::KeystrokeDynamics,
        );
        assert!(result.is_none());
    }

    #[test]
    fn baseline_similarity_range_0_to_10000() {
        let prior_hash = hash(b"old-baseline-data");
        let new_hash = hash(b"completely-different-xyz");
        let prior = vec![sample(BehavioralSignalType::KeystrokeDynamics, prior_hash)];
        let result = compute_baseline_similarity(
            &prior,
            &new_hash,
            &BehavioralSignalType::KeystrokeDynamics,
        );
        assert!(result.is_some());
        let v = result.unwrap();
        assert!(v <= 10_000, "similarity must be <= 10_000, got {v}");
    }

    // ---- byte_similarity internal ----

    #[test]
    fn byte_similarity_identical() {
        let h = hash(b"identical");
        assert_eq!(byte_similarity(h.as_bytes(), h.as_bytes()), 10_000);
    }
}
