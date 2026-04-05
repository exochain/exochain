//! Device fingerprint consistency computation.
//!
//! Computes the Jaccard-like overlap between two signal hash maps and produces
//! a consistency score in basis points (0–10_000 = 0%–100%).
//!
//! The composite hash is BLAKE3 of all signal hashes concatenated in
//! deterministic (sorted) key order.
//!
//! Spec reference: §3.1.

use std::collections::BTreeMap;

use exo_core::types::Hash256;

use super::types::{DeviceFingerprint, FingerprintSignal};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the composite BLAKE3 hash from a set of signal hashes.
///
/// Signal hashes are fed to BLAKE3 in sorted key order (BTreeMap iteration)
/// to guarantee determinism.
#[allow(dead_code)]
pub fn compute_composite_hash(signal_hashes: &BTreeMap<FingerprintSignal, Hash256>) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    // BTreeMap guarantees sorted iteration — deterministic
    for hash in signal_hashes.values() {
        hasher.update(hash.as_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

/// Compute the consistency score between a previous fingerprint and new signal hashes.
///
/// Returns a value in basis points (0–10_000):
/// - 10_000 = identical fingerprint (all signals present and matching)
/// - 0       = completely different (no signals match)
/// - intermediate = partial overlap
///
/// Algorithm:
/// 1. Matching signals = signals present in both maps with identical hashes
/// 2. Total signals = union of all keys from both maps
/// 3. score_bp = (matching / total) * 10_000
///
/// Spec property: identical → 1.0, completely different → 0.0, partial → intermediate.
#[allow(dead_code)]
pub fn compute_consistency(
    previous: &DeviceFingerprint,
    new_signals: &BTreeMap<FingerprintSignal, Hash256>,
) -> u32 {
    let prev_signals = &previous.signal_hashes;

    if prev_signals.is_empty() && new_signals.is_empty() {
        return 10_000; // both empty = trivially identical
    }

    let total_keys: std::collections::BTreeSet<&FingerprintSignal> =
        prev_signals.keys().chain(new_signals.keys()).collect();
    let total = u64::try_from(total_keys.len()).unwrap_or(0);
    if total == 0 {
        return 10_000;
    }

    let matching = u64::try_from(
        total_keys
            .iter()
            .filter(|&&k| {
                prev_signals.get(k) == new_signals.get(k)
                    && prev_signals.contains_key(k)
                    && new_signals.contains_key(k)
            })
            .count(),
    )
    .unwrap_or(0);

    u32::try_from((matching * 10_000) / total).unwrap_or(u32::MAX)
}

/// Build a new `DeviceFingerprint` from raw signal hashes.
///
/// If a previous fingerprint is provided, computes the consistency score.
#[allow(dead_code)]
pub fn build_fingerprint(
    signal_hashes: BTreeMap<FingerprintSignal, Hash256>,
    previous: Option<&DeviceFingerprint>,
    captured_ms: u64,
) -> DeviceFingerprint {
    let composite_hash = compute_composite_hash(&signal_hashes);
    let consistency_score_bp = previous.map(|prev| compute_consistency(prev, &signal_hashes));

    DeviceFingerprint {
        composite_hash,
        signal_hashes,
        captured_ms,
        consistency_score_bp,
    }
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

    fn sig(name: &str) -> FingerprintSignal {
        match name {
            "Canvas" => FingerprintSignal::CanvasRendering,
            "UserAgent" => FingerprintSignal::UserAgent,
            "Screen" => FingerprintSignal::ScreenGeometry,
            "WebGL" => FingerprintSignal::WebGLParameters,
            "Audio" => FingerprintSignal::AudioContext,
            _ => FingerprintSignal::Platform,
        }
    }

    fn fp(signals: Vec<(&str, &[u8])>) -> DeviceFingerprint {
        let mut map = BTreeMap::new();
        for (name, data) in signals {
            map.insert(sig(name), hash(data));
        }
        let composite = compute_composite_hash(&map);
        DeviceFingerprint {
            composite_hash: composite,
            signal_hashes: map,
            captured_ms: 0,
            consistency_score_bp: None,
        }
    }

    // ---- Consistency: identical ----

    #[test]
    fn consistency_identical_is_10000() {
        let prev = fp(vec![
            ("Canvas", b"canvas-data"),
            ("UserAgent", b"ua-data"),
            ("Screen", b"screen-data"),
        ]);
        let new_map = prev.signal_hashes.clone();
        assert_eq!(compute_consistency(&prev, &new_map), 10_000);
    }

    // ---- Consistency: completely different ----

    #[test]
    fn consistency_completely_different_is_0() {
        let prev = fp(vec![("Canvas", b"canvas-A")]);
        let mut new_map = BTreeMap::new();
        new_map.insert(sig("Canvas"), hash(b"canvas-B"));
        assert_eq!(compute_consistency(&prev, &new_map), 0);
    }

    // ---- Consistency: partial overlap ----

    #[test]
    fn consistency_partial_overlap_is_intermediate() {
        let prev = fp(vec![("Canvas", b"data"), ("UserAgent", b"ua")]);
        // Same Canvas, different UserAgent
        let mut new_map = BTreeMap::new();
        new_map.insert(sig("Canvas"), hash(b"data")); // matches
        new_map.insert(sig("UserAgent"), hash(b"ua-new")); // different
        let score = compute_consistency(&prev, &new_map);
        // 1 match out of 2 total = 5000
        assert_eq!(score, 5000);
    }

    #[test]
    fn consistency_one_match_out_of_three() {
        let prev = fp(vec![
            ("Canvas", b"canvas"),
            ("UserAgent", b"ua"),
            ("Screen", b"screen"),
        ]);
        let mut new_map = BTreeMap::new();
        new_map.insert(sig("Canvas"), hash(b"canvas")); // matches
        new_map.insert(sig("UserAgent"), hash(b"ua-new")); // different
        new_map.insert(sig("Screen"), hash(b"screen-new")); // different
        let score = compute_consistency(&prev, &new_map);
        // 1/3 ≈ 3333
        assert_eq!(score, 3333);
    }

    // ---- Consistency: empty maps ----

    #[test]
    fn consistency_both_empty_is_10000() {
        let prev = fp(vec![]);
        let new_map = BTreeMap::new();
        assert_eq!(compute_consistency(&prev, &new_map), 10_000);
    }

    // ---- Composite hash determinism ----

    #[test]
    fn composite_hash_deterministic() {
        let mut m1 = BTreeMap::new();
        m1.insert(sig("Canvas"), hash(b"a"));
        m1.insert(sig("UserAgent"), hash(b"b"));

        let mut m2 = BTreeMap::new();
        // Insert in different order — BTreeMap sorts, so result must match
        m2.insert(sig("UserAgent"), hash(b"b"));
        m2.insert(sig("Canvas"), hash(b"a"));

        assert_eq!(compute_composite_hash(&m1), compute_composite_hash(&m2));
    }

    #[test]
    fn composite_hash_changes_with_different_signals() {
        let mut m1 = BTreeMap::new();
        m1.insert(sig("Canvas"), hash(b"a"));
        let mut m2 = BTreeMap::new();
        m2.insert(sig("Canvas"), hash(b"b"));
        assert_ne!(compute_composite_hash(&m1), compute_composite_hash(&m2));
    }

    // ---- build_fingerprint ----

    #[test]
    fn build_fingerprint_first_session_no_consistency() {
        let mut signals = BTreeMap::new();
        signals.insert(sig("Canvas"), hash(b"canvas-data"));
        let fp = build_fingerprint(signals, None, 1_000_000);
        assert!(
            fp.consistency_score_bp.is_none(),
            "first session has no consistency"
        );
    }

    #[test]
    fn build_fingerprint_second_session_identical() {
        let signals: BTreeMap<_, _> = {
            let mut m = BTreeMap::new();
            m.insert(sig("Canvas"), hash(b"same"));
            m
        };
        let first = build_fingerprint(signals.clone(), None, 1_000);
        let second = build_fingerprint(signals, Some(&first), 2_000);
        assert_eq!(second.consistency_score_bp, Some(10_000));
    }
}
