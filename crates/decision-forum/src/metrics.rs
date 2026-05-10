// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Production monitoring metrics (M1–M12).
//!
//! Tracks all 12 governance metrics including authority verification coverage,
//! revocation latency, evidence completeness, and more.

use serde::{Deserialize, Serialize};

const MAX_LATENCY_SAMPLES: usize = 4_096;

/// All 12 governance metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCollector {
    /// M1: Authority verification coverage (target: 100%).
    pub authority_verification_total: u64,
    pub authority_verification_passed: u64,

    /// M2: Revocation latency P95 in milliseconds (target: <60,000ms).
    pub revocation_latencies_ms: Vec<u64>,

    /// M3: Evidence completeness rate (target: >=99%).
    pub evidence_checks_total: u64,
    pub evidence_checks_complete: u64,

    /// M4: Quorum compliance rate.
    pub quorum_checks_total: u64,
    pub quorum_checks_met: u64,

    /// M5: Human gate enforcement rate.
    pub human_gate_checks_total: u64,
    pub human_gate_checks_satisfied: u64,

    /// M6: Constitutional binding rate.
    pub constitutional_binding_total: u64,
    pub constitutional_binding_valid: u64,

    /// M7: Challenge resolution time P95 in milliseconds.
    pub challenge_resolution_times_ms: Vec<u64>,

    /// M8: Emergency ratification rate.
    pub emergency_total: u64,
    pub emergency_ratified: u64,

    /// M9: Accountability action completion rate.
    pub accountability_total: u64,
    pub accountability_completed: u64,

    /// M10: Consent verification rate.
    pub consent_checks_total: u64,
    pub consent_checks_verified: u64,

    /// M11: Identity verification rate.
    pub identity_checks_total: u64,
    pub identity_checks_verified: u64,

    /// M12: Self-modification compliance rate.
    pub self_mod_total: u64,
    pub self_mod_compliant: u64,
}

impl MetricsCollector {
    /// Create a new metrics collector with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            authority_verification_total: 0,
            authority_verification_passed: 0,
            revocation_latencies_ms: Vec::new(),
            evidence_checks_total: 0,
            evidence_checks_complete: 0,
            quorum_checks_total: 0,
            quorum_checks_met: 0,
            human_gate_checks_total: 0,
            human_gate_checks_satisfied: 0,
            constitutional_binding_total: 0,
            constitutional_binding_valid: 0,
            challenge_resolution_times_ms: Vec::new(),
            emergency_total: 0,
            emergency_ratified: 0,
            accountability_total: 0,
            accountability_completed: 0,
            consent_checks_total: 0,
            consent_checks_verified: 0,
            identity_checks_total: 0,
            identity_checks_verified: 0,
            self_mod_total: 0,
            self_mod_compliant: 0,
        }
    }

    /// M1: Authority verification coverage percentage (0–100).
    #[must_use]
    pub fn m1_authority_pct(&self) -> u64 {
        pct(
            self.authority_verification_passed,
            self.authority_verification_total,
        )
    }

    /// M2: Revocation latency P95 in milliseconds.
    #[must_use]
    pub fn m2_revocation_p95_ms(&self) -> u64 {
        percentile_95(&self.revocation_latencies_ms)
    }

    /// M3: Evidence completeness percentage.
    #[must_use]
    pub fn m3_evidence_pct(&self) -> u64 {
        pct(self.evidence_checks_complete, self.evidence_checks_total)
    }

    /// M4: Quorum compliance percentage.
    #[must_use]
    pub fn m4_quorum_pct(&self) -> u64 {
        pct(self.quorum_checks_met, self.quorum_checks_total)
    }

    /// M5: Human gate satisfaction percentage.
    #[must_use]
    pub fn m5_human_gate_pct(&self) -> u64 {
        pct(
            self.human_gate_checks_satisfied,
            self.human_gate_checks_total,
        )
    }

    /// M6: Constitutional binding validity percentage.
    #[must_use]
    pub fn m6_constitutional_pct(&self) -> u64 {
        pct(
            self.constitutional_binding_valid,
            self.constitutional_binding_total,
        )
    }

    /// M7: Challenge resolution time P95 in milliseconds.
    #[must_use]
    pub fn m7_challenge_p95_ms(&self) -> u64 {
        percentile_95(&self.challenge_resolution_times_ms)
    }

    /// M8: Emergency ratification percentage.
    #[must_use]
    pub fn m8_emergency_pct(&self) -> u64 {
        pct(self.emergency_ratified, self.emergency_total)
    }

    /// M9: Accountability completion percentage.
    #[must_use]
    pub fn m9_accountability_pct(&self) -> u64 {
        pct(self.accountability_completed, self.accountability_total)
    }

    /// M10: Consent verification percentage.
    #[must_use]
    pub fn m10_consent_pct(&self) -> u64 {
        pct(self.consent_checks_verified, self.consent_checks_total)
    }

    /// M11: Identity verification percentage.
    #[must_use]
    pub fn m11_identity_pct(&self) -> u64 {
        pct(self.identity_checks_verified, self.identity_checks_total)
    }

    /// M12: Self-modification compliance percentage.
    #[must_use]
    pub fn m12_self_mod_pct(&self) -> u64 {
        pct(self.self_mod_compliant, self.self_mod_total)
    }

    // -- Recording helpers ------------------------------------------------

    /// Record an authority verification result.
    pub fn record_authority_check(&mut self, passed: bool) {
        increment_counter(&mut self.authority_verification_total);
        if passed {
            increment_counter(&mut self.authority_verification_passed);
        }
    }

    /// Record a revocation latency measurement.
    pub fn record_revocation_latency(&mut self, ms: u64) {
        push_bounded_latency_sample(&mut self.revocation_latencies_ms, ms);
    }

    /// Record an evidence completeness check.
    pub fn record_evidence_check(&mut self, complete: bool) {
        increment_counter(&mut self.evidence_checks_total);
        if complete {
            increment_counter(&mut self.evidence_checks_complete);
        }
    }

    /// Record a quorum check.
    pub fn record_quorum_check(&mut self, met: bool) {
        increment_counter(&mut self.quorum_checks_total);
        if met {
            increment_counter(&mut self.quorum_checks_met);
        }
    }

    /// Record a human gate check.
    pub fn record_human_gate_check(&mut self, satisfied: bool) {
        increment_counter(&mut self.human_gate_checks_total);
        if satisfied {
            increment_counter(&mut self.human_gate_checks_satisfied);
        }
    }

    /// Record a constitutional binding check.
    pub fn record_constitutional_check(&mut self, valid: bool) {
        increment_counter(&mut self.constitutional_binding_total);
        if valid {
            increment_counter(&mut self.constitutional_binding_valid);
        }
    }

    /// Record a challenge resolution time.
    pub fn record_challenge_resolution(&mut self, ms: u64) {
        push_bounded_latency_sample(&mut self.challenge_resolution_times_ms, ms);
    }

    /// Record an emergency action.
    pub fn record_emergency(&mut self, ratified: bool) {
        increment_counter(&mut self.emergency_total);
        if ratified {
            increment_counter(&mut self.emergency_ratified);
        }
    }

    /// Record an accountability action.
    pub fn record_accountability(&mut self, completed: bool) {
        increment_counter(&mut self.accountability_total);
        if completed {
            increment_counter(&mut self.accountability_completed);
        }
    }

    /// Record a consent check.
    pub fn record_consent_check(&mut self, verified: bool) {
        increment_counter(&mut self.consent_checks_total);
        if verified {
            increment_counter(&mut self.consent_checks_verified);
        }
    }

    /// Record an identity check.
    pub fn record_identity_check(&mut self, verified: bool) {
        increment_counter(&mut self.identity_checks_total);
        if verified {
            increment_counter(&mut self.identity_checks_verified);
        }
    }

    /// Record a self-modification check.
    pub fn record_self_mod(&mut self, compliant: bool) {
        increment_counter(&mut self.self_mod_total);
        if compliant {
            increment_counter(&mut self.self_mod_compliant);
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a percentage (0–100), returning 100 if total is 0.
fn pct(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 100;
    }
    let pct = (u128::from(numerator) * 100) / u128::from(denominator);
    u64::try_from(pct.min(100)).unwrap_or(100)
}

fn increment_counter(value: &mut u64) {
    *value = value.saturating_add(1);
}

fn push_bounded_latency_sample(values: &mut Vec<u64>, value: u64) {
    let projected_len = values.len().saturating_add(1);
    if projected_len > MAX_LATENCY_SAMPLES {
        let excess = projected_len - MAX_LATENCY_SAMPLES;
        let drain_end = excess.min(values.len());
        drop(values.drain(0..drain_end));
    }
    values.push(value);
}

/// Compute the 95th percentile of a latency distribution.
fn percentile_95(values: &[u64]) -> u64 {
    let window_start = values.len().saturating_sub(MAX_LATENCY_SAMPLES);
    let recent_values = &values[window_start..];
    if recent_values.is_empty() {
        return 0;
    }
    let mut sorted = recent_values.to_vec();
    sorted.sort_unstable();
    // Integer 95th-percentile: index = ceil(len * 95 / 100) - 1, clamped to last element.
    let idx = ((sorted.len() * 95).div_ceil(100)).min(sorted.len()) - 1;
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_all_100pct() {
        let m = MetricsCollector::new();
        assert_eq!(m.m1_authority_pct(), 100);
        assert_eq!(m.m3_evidence_pct(), 100);
        assert_eq!(m.m4_quorum_pct(), 100);
    }

    #[test]
    fn record_and_compute() {
        let mut m = MetricsCollector::new();
        m.record_authority_check(true);
        m.record_authority_check(true);
        m.record_authority_check(false);
        assert_eq!(m.m1_authority_pct(), 66);
    }

    #[test]
    fn revocation_p95() {
        let mut m = MetricsCollector::new();
        for i in 1..=100 {
            m.record_revocation_latency(i * 100);
        }
        let p95 = m.m2_revocation_p95_ms();
        assert!(p95 >= 9500);
    }

    #[test]
    fn empty_p95() {
        let m = MetricsCollector::new();
        assert_eq!(m.m2_revocation_p95_ms(), 0);
        assert_eq!(m.m7_challenge_p95_ms(), 0);
    }

    #[test]
    fn latency_recorders_retain_only_bounded_recent_samples() {
        const EXPECTED_SAMPLE_LIMIT: usize = 4_096;
        const SAMPLE_COUNT: u64 = 4_101;

        let mut m = MetricsCollector::new();
        for latency in 0..SAMPLE_COUNT {
            m.record_revocation_latency(latency);
            m.record_challenge_resolution(latency + 10_000);
        }

        assert_eq!(m.revocation_latencies_ms.len(), EXPECTED_SAMPLE_LIMIT);
        assert_eq!(m.challenge_resolution_times_ms.len(), EXPECTED_SAMPLE_LIMIT);
        assert_eq!(m.revocation_latencies_ms.first().copied(), Some(5));
        assert_eq!(m.revocation_latencies_ms.last().copied(), Some(4_100));
        assert_eq!(
            m.challenge_resolution_times_ms.first().copied(),
            Some(10_005)
        );
    }

    #[test]
    fn latency_percentiles_use_bounded_recent_window_for_public_vectors() {
        const EXPECTED_SAMPLE_LIMIT: usize = 4_096;

        let mut m = MetricsCollector::new();
        m.revocation_latencies_ms
            .extend(std::iter::repeat_n(1_000_000, EXPECTED_SAMPLE_LIMIT));
        m.revocation_latencies_ms
            .extend(std::iter::repeat_n(10, EXPECTED_SAMPLE_LIMIT));
        m.challenge_resolution_times_ms
            .extend(std::iter::repeat_n(2_000_000, EXPECTED_SAMPLE_LIMIT));
        m.challenge_resolution_times_ms
            .extend(std::iter::repeat_n(20, EXPECTED_SAMPLE_LIMIT));

        assert_eq!(m.m2_revocation_p95_ms(), 10);
        assert_eq!(m.m7_challenge_p95_ms(), 20);
    }

    #[test]
    fn all_metrics_recorded() {
        let mut m = MetricsCollector::new();
        m.record_authority_check(true);
        m.record_revocation_latency(50);
        m.record_evidence_check(true);
        m.record_quorum_check(true);
        m.record_human_gate_check(true);
        m.record_constitutional_check(true);
        m.record_challenge_resolution(100);
        m.record_emergency(true);
        m.record_accountability(true);
        m.record_consent_check(true);
        m.record_identity_check(true);
        m.record_self_mod(true);

        assert_eq!(m.m1_authority_pct(), 100);
        assert_eq!(m.m3_evidence_pct(), 100);
        assert_eq!(m.m4_quorum_pct(), 100);
        assert_eq!(m.m5_human_gate_pct(), 100);
        assert_eq!(m.m6_constitutional_pct(), 100);
        assert_eq!(m.m8_emergency_pct(), 100);
        assert_eq!(m.m9_accountability_pct(), 100);
        assert_eq!(m.m10_consent_pct(), 100);
        assert_eq!(m.m11_identity_pct(), 100);
        assert_eq!(m.m12_self_mod_pct(), 100);
    }

    #[test]
    fn mixed_results() {
        let mut m = MetricsCollector::new();
        for _ in 0..99 {
            m.record_evidence_check(true);
        }
        m.record_evidence_check(false);
        assert_eq!(m.m3_evidence_pct(), 99);
    }

    #[test]
    fn pct_handles_deserialized_overflow_shapes_without_panicking() {
        assert_eq!(pct(u64::MAX, 1), 100);
        assert_eq!(pct(u64::MAX, u64::MAX), 100);
        assert_eq!(pct(u64::MAX - 1, u64::MAX), 99);
    }

    #[test]
    fn recorders_saturate_deserialized_counter_maxima_without_panicking() {
        let mut m = MetricsCollector {
            authority_verification_total: u64::MAX,
            authority_verification_passed: u64::MAX,
            revocation_latencies_ms: Vec::new(),
            evidence_checks_total: u64::MAX,
            evidence_checks_complete: u64::MAX,
            quorum_checks_total: u64::MAX,
            quorum_checks_met: u64::MAX,
            human_gate_checks_total: u64::MAX,
            human_gate_checks_satisfied: u64::MAX,
            constitutional_binding_total: u64::MAX,
            constitutional_binding_valid: u64::MAX,
            challenge_resolution_times_ms: Vec::new(),
            emergency_total: u64::MAX,
            emergency_ratified: u64::MAX,
            accountability_total: u64::MAX,
            accountability_completed: u64::MAX,
            consent_checks_total: u64::MAX,
            consent_checks_verified: u64::MAX,
            identity_checks_total: u64::MAX,
            identity_checks_verified: u64::MAX,
            self_mod_total: u64::MAX,
            self_mod_compliant: u64::MAX,
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            m.record_authority_check(true);
            m.record_evidence_check(true);
            m.record_quorum_check(true);
            m.record_human_gate_check(true);
            m.record_constitutional_check(true);
            m.record_emergency(true);
            m.record_accountability(true);
            m.record_consent_check(true);
            m.record_identity_check(true);
            m.record_self_mod(true);
        }));

        assert!(result.is_ok());
        assert_eq!(m.authority_verification_total, u64::MAX);
        assert_eq!(m.authority_verification_passed, u64::MAX);
        assert_eq!(m.self_mod_total, u64::MAX);
        assert_eq!(m.self_mod_compliant, u64::MAX);
    }

    #[test]
    fn default_impl() {
        let m = MetricsCollector::default();
        assert_eq!(m.authority_verification_total, 0);
    }

    #[test]
    fn serde_roundtrip() {
        let mut m = MetricsCollector::new();
        m.record_authority_check(true);
        let json = serde_json::to_string(&m).expect("ser");
        let m2: MetricsCollector = serde_json::from_str(&json).expect("de");
        assert_eq!(m2.authority_verification_total, 1);
    }
}
