//! Integration tests verifying that exo-proofs *refuses* to execute when
//! the `unaudited-pedagogical-proofs` opt-in feature is OFF.
//!
//! These tests run in the default build (feature OFF). They assert that every
//! public proof entry point returns `Err(ProofError::UnauditedImplementation)`,
//! preventing accidental reliance on the unaudited skeleton in production.

#![cfg(not(feature = "unaudited-pedagogical-proofs"))]

use exo_proofs::error::ProofError;

#[test]
fn guard_unaudited_refuses_by_default() {
    // Direct guard check — this is the canonical refusal signal.
    let result = exo_proofs::guard_unaudited("test");
    assert!(matches!(
        result,
        Err(ProofError::UnauditedImplementation { .. })
    ));
}

#[test]
fn snark_verify_refuses_by_default() {
    use exo_proofs::snark::{Proof, VerifyingKey};
    // We can still construct types — the refusal is at the verify entry point.
    let vk = VerifyingKey {
        circuit_hash: exo_core::types::Hash256([0u8; 32]),
        num_public_inputs: 0,
    };
    let proof = Proof {
        a: [0u8; 32],
        b: [0u8; 32],
        c: [0u8; 32],
    };
    let result = exo_proofs::snark::verify(&vk, &proof, &[]);
    assert!(matches!(
        result,
        Err(ProofError::UnauditedImplementation { .. })
    ));
}
