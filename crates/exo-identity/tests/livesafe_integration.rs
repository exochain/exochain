//! LiveSafe.ai ↔ EXOCHAIN Integration Tests
//!
//! Tests the current PACE and Shamir APIs as used in the LiveSafe integration:
//! - `PaceConfig` construction and validation
//! - `PaceState` enum transitions (escalate / deescalate)
//! - `resolve_operator` resolution at each PACE level
//! - Escalation and de-escalation flows
//! - Shamir secret split + reconstruct (success and failure paths)
//! - Operator continuity through state transitions

use exo_core::Did;
use exo_identity::{
    pace::{PaceConfig, PaceState, deescalate, escalate, resolve_operator},
    shamir::{ShamirConfig, reconstruct, split},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn did(label: &str) -> Did {
    Did::new(&format!("did:exo:{label}")).expect("valid DID")
}

fn livesafe_pace_config() -> PaceConfig {
    PaceConfig {
        primary: did("livesafe:primary"),
        alternates: vec![did("livesafe:alt1"), did("livesafe:alt2")],
        contingency: vec![did("livesafe:cont1")],
        emergency: vec![did("livesafe:emerg1")],
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
    config.validate().expect("valid LiveSafe PACE config");
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
    assert_eq!(escalate(&mut s).unwrap(), PaceState::AlternateActive);
    assert_eq!(s, PaceState::AlternateActive);

    assert_eq!(escalate(&mut s).unwrap(), PaceState::ContingencyActive);
    assert_eq!(s, PaceState::ContingencyActive);

    assert_eq!(escalate(&mut s).unwrap(), PaceState::EmergencyActive);
    assert_eq!(s, PaceState::EmergencyActive);

    // Cannot escalate beyond Emergency.
    assert!(
        escalate(&mut s).is_err(),
        "escalating past EmergencyActive must fail"
    );

    // Full de-escalation path from Emergency back to Normal.
    assert_eq!(deescalate(&mut s).unwrap(), PaceState::ContingencyActive);
    assert_eq!(deescalate(&mut s).unwrap(), PaceState::AlternateActive);
    assert_eq!(deescalate(&mut s).unwrap(), PaceState::Normal);

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
        resolve_operator(&config, &PaceState::Normal).as_str(),
        "did:exo:livesafe:primary"
    );
    assert_eq!(
        resolve_operator(&config, &PaceState::AlternateActive).as_str(),
        "did:exo:livesafe:alt1"
    );
    assert_eq!(
        resolve_operator(&config, &PaceState::ContingencyActive).as_str(),
        "did:exo:livesafe:cont1"
    );
    assert_eq!(
        resolve_operator(&config, &PaceState::EmergencyActive).as_str(),
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
    escalate(&mut state).unwrap();
    assert_eq!(
        resolve_operator(&config, &state).as_str(),
        "did:exo:livesafe:alt1"
    );

    // Escalate further to Contingency.
    escalate(&mut state).unwrap();
    assert_eq!(
        resolve_operator(&config, &state).as_str(),
        "did:exo:livesafe:cont1"
    );

    // De-escalate back to Alternate.
    deescalate(&mut state).unwrap();
    assert_eq!(state, PaceState::AlternateActive);
    assert_eq!(
        resolve_operator(&config, &state).as_str(),
        "did:exo:livesafe:alt1"
    );

    // De-escalate back to Normal.
    deescalate(&mut state).unwrap();
    assert_eq!(state, PaceState::Normal);
    assert_eq!(
        resolve_operator(&config, &state).as_str(),
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

    let shares = split(secret, &config).expect("split must succeed");
    assert_eq!(shares.len(), 5, "must produce exactly 5 shares");

    // Reconstruct with exactly the threshold number of shares.
    let subset: Vec<_> = shares.iter().take(3).cloned().collect();
    let recovered = reconstruct(&subset, &config).expect("reconstruct must succeed");
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
    let shares = split(secret, &config).unwrap();

    // Any 2-of-4 combination must reconstruct correctly.
    for i in 0..4 {
        for j in (i + 1)..4 {
            let subset = vec![shares[i].clone(), shares[j].clone()];
            let recovered = reconstruct(&subset, &config).unwrap();
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
    let shares = split(secret, &config).unwrap();

    // Provide only 2 shares when 3 are required.
    let insufficient: Vec<_> = shares.iter().take(2).cloned().collect();
    let err = reconstruct(&insufficient, &config)
        .expect_err("reconstruct with fewer than threshold shares must fail");

    // The error must name the required and provided counts.
    let err_str = format!("{err:?}");
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

    let primary = resolve_operator(&config, &state).clone();
    assert_eq!(primary.as_str(), "did:exo:livesafe:primary");

    // Repeated resolution at same state must be stable.
    assert_eq!(resolve_operator(&config, &state), &primary);
    assert_eq!(resolve_operator(&config, &state), &primary);

    // After escalation, operator must change.
    escalate(&mut state).unwrap();
    let alternate = resolve_operator(&config, &state).clone();
    assert_ne!(alternate, primary, "alternate must differ from primary");
    assert_eq!(alternate.as_str(), "did:exo:livesafe:alt1");

    // Operator at this new level is stable.
    assert_eq!(resolve_operator(&config, &state), &alternate);

    // After de-escalation back to Normal, primary is restored.
    deescalate(&mut state).unwrap();
    assert_eq!(resolve_operator(&config, &state), &primary);
}
