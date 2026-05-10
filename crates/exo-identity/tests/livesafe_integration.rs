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

//! LiveSafe.ai ↔ EXOCHAIN Integration Tests
//!
//! Tests the current PACE and Shamir APIs as used in the LiveSafe integration:
//! - `PaceConfig` construction and validation
//! - `PaceState` enum transitions (escalate / deescalate)
//! - `resolve_operator` resolution at each PACE level
//! - Escalation and de-escalation flows
//! - Shamir secret split + reconstruct (success and failure paths)
//! - Operator continuity through state transitions

#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::Did;
use exo_identity::{
    pace::{PaceConfig, PaceState, deescalate, escalate, resolve_operator},
    shamir::{ShamirConfig, Share, reconstruct, split_with_entropy},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SHAMIR_ENTROPY: &[u8] = b"livesafe-integration-shamir-entropy";

fn did(label: &str) -> Did {
    match Did::new(&format!("did:exo:{label}")) {
        Ok(did) => did,
        Err(err) => panic!("test fixture DID must be valid for label {label}: {err}"),
    }
}

fn livesafe_pace_config() -> PaceConfig {
    PaceConfig {
        primary: did("livesafe:primary"),
        alternates: vec![did("livesafe:alt1"), did("livesafe:alt2")],
        contingency: vec![did("livesafe:cont1")],
        emergency: vec![did("livesafe:emerg1")],
    }
}

fn escalate_ok(state: &mut PaceState) -> PaceState {
    match escalate(state) {
        Ok(next_state) => next_state,
        Err(err) => panic!("expected PACE escalation to succeed: {err}"),
    }
}

fn deescalate_ok(state: &mut PaceState) -> PaceState {
    match deescalate(state) {
        Ok(next_state) => next_state,
        Err(err) => panic!("expected PACE de-escalation to succeed: {err}"),
    }
}

fn split_ok(secret: &[u8], config: &ShamirConfig) -> Vec<Share> {
    match split_with_entropy(secret, config, TEST_SHAMIR_ENTROPY) {
        Ok(shares) => shares,
        Err(err) => panic!("expected Shamir split to succeed: {err}"),
    }
}

fn reconstruct_ok(shares: &[Share], config: &ShamirConfig) -> Vec<u8> {
    match reconstruct(shares, config) {
        Ok(secret) => secret,
        Err(err) => panic!("expected Shamir reconstruct to succeed: {err}"),
    }
}

fn reconstruct_error(shares: &[Share], config: &ShamirConfig) -> String {
    match reconstruct(shares, config) {
        Ok(secret) => panic!("expected Shamir reconstruct to fail, recovered {secret:?}"),
        Err(err) => format!("{err:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. PaceConfig creation and validation
// ---------------------------------------------------------------------------

#[test]
fn test_pace_config_creation() {
    let config = livesafe_pace_config();

    // Fields populated correctly.
    assert_eq!(config.primary.as_str(), "did:exo:livesafe:primary");
    assert_eq!(config.alternates.len(), 2);
    assert_eq!(config.contingency.len(), 1);
    assert_eq!(config.emergency.len(), 1);

    // Validation passes.
    assert!(
        config.validate().is_ok(),
        "valid LiveSafe PACE config must pass validation"
    );
}

#[test]
fn test_pace_config_invalid_empty_alternates() {
    let mut config = livesafe_pace_config();
    config.alternates.clear();
    assert!(
        config.validate().is_err(),
        "empty alternates must fail validation"
    );
}

#[test]
fn test_pace_config_invalid_empty_contingency() {
    let mut config = livesafe_pace_config();
    config.contingency.clear();
    assert!(
        config.validate().is_err(),
        "empty contingency must fail validation"
    );
}

#[test]
fn test_pace_config_invalid_empty_emergency() {
    let mut config = livesafe_pace_config();
    config.emergency.clear();
    assert!(
        config.validate().is_err(),
        "empty emergency must fail validation"
    );
}

#[test]
fn test_pace_config_duplicate_did_rejected() {
    // Primary DID reused in contingency — must be rejected.
    let config = PaceConfig {
        primary: did("shared"),
        alternates: vec![did("alt1")],
        contingency: vec![did("shared")], // duplicate
        emergency: vec![did("emerg1")],
    };
    assert!(
        config.validate().is_err(),
        "duplicate DID across PACE levels must fail"
    );
}

// ---------------------------------------------------------------------------
// 2. PaceState transitions
// ---------------------------------------------------------------------------

#[test]
fn test_pace_state_transitions() {
    // Initial state is Normal.
    let state = PaceState::Normal;
    assert_eq!(state, PaceState::Normal);

    // Full escalation path.
    let mut s = PaceState::Normal;
    assert_eq!(escalate_ok(&mut s), PaceState::AlternateActive);
    assert_eq!(s, PaceState::AlternateActive);

    assert_eq!(escalate_ok(&mut s), PaceState::ContingencyActive);
    assert_eq!(s, PaceState::ContingencyActive);

    assert_eq!(escalate_ok(&mut s), PaceState::EmergencyActive);
    assert_eq!(s, PaceState::EmergencyActive);

    // Cannot escalate beyond Emergency.
    assert!(
        escalate(&mut s).is_err(),
        "escalating past EmergencyActive must fail"
    );

    // Full de-escalation path from Emergency back to Normal.
    assert_eq!(deescalate_ok(&mut s), PaceState::ContingencyActive);
    assert_eq!(deescalate_ok(&mut s), PaceState::AlternateActive);
    assert_eq!(deescalate_ok(&mut s), PaceState::Normal);

    // Cannot de-escalate below Normal.
    assert!(
        deescalate(&mut s).is_err(),
        "de-escalating below Normal must fail"
    );
}

// ---------------------------------------------------------------------------
// 3. resolve_operator at each PACE level
// ---------------------------------------------------------------------------

#[test]
fn test_pace_resolve_operator() {
    let config = livesafe_pace_config();

    assert_eq!(
        resolve_operator(&config, &PaceState::Normal)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:primary"
    );
    assert_eq!(
        resolve_operator(&config, &PaceState::AlternateActive)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:alt1"
    );
    assert_eq!(
        resolve_operator(&config, &PaceState::ContingencyActive)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:cont1"
    );
    assert_eq!(
        resolve_operator(&config, &PaceState::EmergencyActive)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:emerg1"
    );
}

// ---------------------------------------------------------------------------
// 4. Escalation and de-escalation flow
// ---------------------------------------------------------------------------

#[test]
fn test_pace_escalate_deescalate() {
    let config = livesafe_pace_config();
    let mut state = PaceState::Normal;

    // Escalate to Alternate.
    escalate_ok(&mut state);
    assert_eq!(
        resolve_operator(&config, &state)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:alt1"
    );

    // Escalate further to Contingency.
    escalate_ok(&mut state);
    assert_eq!(
        resolve_operator(&config, &state)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:cont1"
    );

    // De-escalate back to Alternate.
    deescalate_ok(&mut state);
    assert_eq!(state, PaceState::AlternateActive);
    assert_eq!(
        resolve_operator(&config, &state)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:alt1"
    );

    // De-escalate back to Normal.
    deescalate_ok(&mut state);
    assert_eq!(state, PaceState::Normal);
    assert_eq!(
        resolve_operator(&config, &state)
            .expect("valid PACE config")
            .as_str(),
        "did:exo:livesafe:primary"
    );
}

// ---------------------------------------------------------------------------
// 5. Shamir split + reconstruct — success
// ---------------------------------------------------------------------------

#[test]
fn test_shamir_split_reconstruct() {
    // Simulate splitting a LiveSafe subscriber emergency recovery seed.
    let secret = b"livesafe-subscriber-recovery-seed-v1";
    let config = ShamirConfig {
        threshold: 3,
        shares: 5,
    };

    let shares = split_ok(secret, &config);
    assert_eq!(shares.len(), 5, "must produce exactly 5 shares");

    // Reconstruct with exactly the threshold number of shares.
    let subset: Vec<_> = shares.iter().take(3).cloned().collect();
    let recovered = reconstruct_ok(&subset, &config);
    assert_eq!(recovered, secret, "recovered secret must match original");

    // All shares carry the same commitment.
    let expected_commitment = *blake3::hash(secret).as_bytes();
    for share in &shares {
        assert_eq!(
            share.commitment, expected_commitment,
            "every share must commit to the same secret"
        );
    }
}

#[test]
fn test_shamir_split_reconstruct_any_threshold_subset() {
    let secret = b"pace-shard-data";
    let config = ShamirConfig {
        threshold: 2,
        shares: 4,
    };
    let shares = split_ok(secret, &config);

    // Any 2-of-4 combination must reconstruct correctly.
    for i in 0..4 {
        for j in (i + 1)..4 {
            let subset = vec![shares[i].clone(), shares[j].clone()];
            let recovered = reconstruct_ok(&subset, &config);
            assert_eq!(recovered, secret, "combo ({i},{j}) must reconstruct");
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Shamir insufficient shares — must fail
// ---------------------------------------------------------------------------

#[test]
fn test_shamir_insufficient_shares() {
    let secret = b"trustee-shard-secret";
    let config = ShamirConfig {
        threshold: 3,
        shares: 5,
    };
    let shares = split_ok(secret, &config);

    // Provide only 2 shares when 3 are required.
    let insufficient: Vec<_> = shares.iter().take(2).cloned().collect();
    let err_str = reconstruct_error(&insufficient, &config);

    // The error must name the required and provided counts.
    assert!(
        err_str.contains('3') && err_str.contains('2'),
        "error must indicate need=3, got=2; got: {err_str}"
    );
}

// ---------------------------------------------------------------------------
// 7. Operator continuity through state transitions
// ---------------------------------------------------------------------------

#[test]
fn test_pace_operator_continuity() {
    // Verify that operator identity is stable within a state and changes only
    // on transition — the core LiveSafe continuity guarantee.
    let config = livesafe_pace_config();
    let mut state = PaceState::Normal;

    let primary = resolve_operator(&config, &state)
        .expect("valid PACE config")
        .clone();
    assert_eq!(primary.as_str(), "did:exo:livesafe:primary");

    // Repeated resolution at same state must be stable.
    assert_eq!(
        resolve_operator(&config, &state).expect("valid PACE config"),
        &primary
    );
    assert_eq!(
        resolve_operator(&config, &state).expect("valid PACE config"),
        &primary
    );

    // After escalation, operator must change.
    escalate_ok(&mut state);
    let alternate = resolve_operator(&config, &state)
        .expect("valid PACE config")
        .clone();
    assert_ne!(alternate, primary, "alternate must differ from primary");
    assert_eq!(alternate.as_str(), "did:exo:livesafe:alt1");

    // Operator at this new level is stable.
    assert_eq!(
        resolve_operator(&config, &state).expect("valid PACE config"),
        &alternate
    );

    // After de-escalation back to Normal, primary is restored.
    deescalate_ok(&mut state);
    assert_eq!(
        resolve_operator(&config, &state).expect("valid PACE config"),
        &primary
    );
}
