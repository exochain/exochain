//! SNARK proof generation/verification (simplified Groth16-like).
//!
//! This is a pedagogical/structural implementation demonstrating the
//! structure of a SNARK proof system. It is NOT cryptographically hardened.
//! All operations use integer arithmetic (no floating point).

use exo_core::types::Hash256;
use serde::{Deserialize, Serialize};

use crate::{
    circuit::{Circuit, ConstraintSystem},
    error::{ProofError, Result},
};

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A proving key derived from the circuit structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvingKey {
    /// Number of variables in the circuit.
    pub num_variables: usize,
    /// Number of constraints.
    pub num_constraints: usize,
    /// Number of public inputs.
    pub num_public_inputs: usize,
    /// Circuit fingerprint (hash of the constraint structure).
    pub circuit_hash: Hash256,
}

/// A verifying key used to check proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// Number of public inputs expected.
    pub num_public_inputs: usize,
    /// Circuit fingerprint.
    pub circuit_hash: Hash256,
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// A SNARK proof. In a real Groth16, a/b/c would be elliptic curve points.
/// Here we use deterministic byte arrays derived from the witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// "A" component (32 bytes -- hash-based stand-in for a curve point).
    pub a: [u8; 32],
    /// "B" component.
    pub b: [u8; 32],
    /// "C" component.
    pub c: [u8; 32],
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// Run the setup phase: synthesize the circuit with no witness to determine
/// its structure, then produce proving and verifying keys.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
pub fn setup(circuit: &dyn Circuit) -> Result<(ProvingKey, VerifyingKey)> {
    crate::guard_unaudited("snark::setup")?;
    let mut cs = ConstraintSystem::new();
    circuit
        .synthesize(&mut cs)
        .map_err(|e| ProofError::SetupError(e.to_string()))?;

    if cs.num_constraints() == 0 {
        return Err(ProofError::SetupError(
            "circuit has no constraints".to_string(),
        ));
    }

    // Compute a deterministic fingerprint of the circuit structure.
    let circuit_hash =
        compute_circuit_hash(&cs).map_err(|e| ProofError::SetupError(e.to_string()))?;

    let pk = ProvingKey {
        num_variables: cs.num_variables(),
        num_constraints: cs.num_constraints(),
        num_public_inputs: cs.num_public_inputs,
        circuit_hash,
    };

    let vk = VerifyingKey {
        num_public_inputs: cs.num_public_inputs,
        circuit_hash,
    };

    Ok((pk, vk))
}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Generate a proof for the given circuit with the provided witness values.
///
/// The witness must contain values for ALL variables (public + private).
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
pub fn prove(pk: &ProvingKey, circuit: &dyn Circuit, witness: &[u64]) -> Result<Proof> {
    crate::guard_unaudited("snark::prove")?;
    // Re-synthesize with witness
    let mut cs = ConstraintSystem::new();
    circuit
        .synthesize(&mut cs)
        .map_err(|e| ProofError::ProofGenerationFailed(e.to_string()))?;

    // Populate witness values
    if witness.len() != cs.num_variables() {
        return Err(ProofError::InvalidWitness(format!(
            "expected {} witness values, got {}",
            cs.num_variables(),
            witness.len()
        )));
    }

    for (i, var) in cs.variables.iter_mut().enumerate() {
        var.value = Some(witness[i]);
    }

    // Verify the circuit fingerprint matches
    let circuit_hash =
        compute_circuit_hash(&cs).map_err(|e| ProofError::ProofGenerationFailed(e.to_string()))?;
    if circuit_hash != pk.circuit_hash {
        return Err(ProofError::ProofGenerationFailed(
            "circuit structure does not match proving key".to_string(),
        ));
    }

    // Check that constraints are actually satisfied
    if !cs.is_satisfied() {
        return Err(ProofError::ProofGenerationFailed(
            "witness does not satisfy constraints".to_string(),
        ));
    }

    // Compute proof components deterministically from the witness.
    // In real Groth16 these would be elliptic curve pairings.
    // a and b encode the full witness (prover knowledge).
    let a = compute_proof_component(b"snark:a:", &circuit_hash, witness);
    let b = compute_proof_component(b"snark:b:", &circuit_hash, witness);

    // c is derived from (a, b, circuit_hash, public_inputs) so the verifier
    // can recompute it without the private witness.
    let public_inputs: Vec<u64> = cs
        .public_input_indices
        .iter()
        .map(|&idx| witness[idx])
        .collect();
    let c = compute_c_component(&circuit_hash, &public_inputs, &a, &b);

    Ok(Proof { a, b, c })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify a SNARK proof given a verifying key and public inputs.
///
/// Public inputs are the first `vk.num_public_inputs` values.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
pub fn verify(vk: &VerifyingKey, proof: &Proof, public_inputs: &[u64]) -> Result<bool> {
    crate::guard_unaudited("snark::verify")?;
    if public_inputs.len() != vk.num_public_inputs {
        return Ok(false);
    }

    // Recompute what c should be from (circuit_hash, public_inputs, a, b).
    // This mirrors how the prover computed c.
    let expected_c = compute_c_component(&vk.circuit_hash, public_inputs, &proof.a, &proof.b);

    Ok(proof.c == expected_c)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn usize_to_u64(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| ProofError::SetupError(format!("value {n} overflows u64")))
}

fn compute_circuit_hash(cs: &ConstraintSystem) -> Result<Hash256> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"snark:circuit:");
    hasher.update(&usize_to_u64(cs.num_variables())?.to_le_bytes());
    hasher.update(&usize_to_u64(cs.num_constraints())?.to_le_bytes());
    hasher.update(&usize_to_u64(cs.num_public_inputs)?.to_le_bytes());

    for constraint in &cs.constraints {
        for &(coeff, idx) in &constraint.a_terms.terms {
            hasher.update(&coeff.to_le_bytes());
            hasher.update(&usize_to_u64(idx)?.to_le_bytes());
        }
        hasher.update(b"|");
        for &(coeff, idx) in &constraint.b_terms.terms {
            hasher.update(&coeff.to_le_bytes());
            hasher.update(&usize_to_u64(idx)?.to_le_bytes());
        }
        hasher.update(b"|");
        for &(coeff, idx) in &constraint.c_terms.terms {
            hasher.update(&coeff.to_le_bytes());
            hasher.update(&usize_to_u64(idx)?.to_le_bytes());
        }
        hasher.update(b"#");
    }

    Ok(Hash256::from_bytes(*hasher.finalize().as_bytes()))
}

fn compute_proof_component(prefix: &[u8], circuit_hash: &Hash256, witness: &[u64]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix);
    hasher.update(circuit_hash.as_bytes());
    for &w in witness {
        hasher.update(&w.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn compute_c_component(
    circuit_hash: &Hash256,
    public_inputs: &[u64],
    a: &[u8; 32],
    b: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"snark:c:verify:");
    hasher.update(circuit_hash.as_bytes());
    for &inp in public_inputs {
        hasher.update(&inp.to_le_bytes());
    }
    hasher.update(a);
    hasher.update(b);
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "unaudited-pedagogical-proofs"))]
mod tests {
    use super::*;
    use crate::circuit::{LinearCombination, allocate, allocate_public, enforce};

    /// x * y = z
    #[derive(Debug)]
    struct MulCircuit {
        x: Option<u64>,
        y: Option<u64>,
        z: Option<u64>,
    }

    impl Circuit for MulCircuit {
        fn synthesize(&self, cs: &mut ConstraintSystem) -> crate::error::Result<()> {
            let x = allocate_public(cs, self.x);
            let y = allocate(cs, self.y);
            let z = allocate_public(cs, self.z);
            enforce(
                cs,
                &LinearCombination::from_variable(x),
                &LinearCombination::from_variable(y),
                &LinearCombination::from_variable(z),
            );
            Ok(())
        }
    }

    fn make_mul_circuit(x: u64, y: u64) -> MulCircuit {
        MulCircuit {
            x: Some(x),
            y: Some(y),
            z: Some(x.wrapping_mul(y)),
        }
    }

    #[test]
    fn setup_produces_keys() {
        let circuit = make_mul_circuit(3, 4);
        let (pk, vk) = setup(&circuit).unwrap();
        assert_eq!(pk.num_variables, 3);
        assert_eq!(pk.num_constraints, 1);
        assert_eq!(pk.num_public_inputs, 2);
        assert_eq!(vk.num_public_inputs, 2);
        assert_eq!(pk.circuit_hash, vk.circuit_hash);
    }

    #[test]
    fn valid_proof_verifies() {
        let circuit = make_mul_circuit(3, 4);
        let (pk, vk) = setup(&circuit).unwrap();

        // witness: [x=3, y=4, z=12]
        let proof = prove(&pk, &circuit, &[3, 4, 12]).unwrap();
        // public inputs: [x=3, z=12]
        assert!(verify(&vk, &proof, &[3, 12]).unwrap());
    }

    #[test]
    fn invalid_proof_rejected() {
        let circuit = make_mul_circuit(3, 4);
        let (pk, vk) = setup(&circuit).unwrap();

        let proof = prove(&pk, &circuit, &[3, 4, 12]).unwrap();

        // Wrong public inputs
        assert!(!verify(&vk, &proof, &[3, 13]).unwrap());
        assert!(!verify(&vk, &proof, &[4, 12]).unwrap());
    }

    #[test]
    fn different_witnesses_produce_different_proofs() {
        let c1 = make_mul_circuit(3, 4);
        let c2 = make_mul_circuit(6, 2);
        let (pk1, _) = setup(&c1).unwrap();
        let (pk2, _) = setup(&c2).unwrap();

        let proof1 = prove(&pk1, &c1, &[3, 4, 12]).unwrap();
        let proof2 = prove(&pk2, &c2, &[6, 2, 12]).unwrap();

        // Same result (12) but different witnesses
        assert_ne!(proof1, proof2);
    }

    #[test]
    fn wrong_witness_count_rejected() {
        let circuit = make_mul_circuit(3, 4);
        let (pk, _) = setup(&circuit).unwrap();
        let err = prove(&pk, &circuit, &[3, 4]).unwrap_err();
        assert!(matches!(err, ProofError::InvalidWitness(_)));
    }

    #[test]
    fn unsatisfied_witness_rejected() {
        let circuit = MulCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(12),
        };
        let (pk, _) = setup(&circuit).unwrap();

        // Wrong z value
        let err = prove(&pk, &circuit, &[3, 4, 13]).unwrap_err();
        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn wrong_public_input_count_rejected() {
        let circuit = make_mul_circuit(3, 4);
        let (pk, vk) = setup(&circuit).unwrap();

        let proof = prove(&pk, &circuit, &[3, 4, 12]).unwrap();
        assert!(!verify(&vk, &proof, &[3]).unwrap()); // too few
        assert!(!verify(&vk, &proof, &[3, 12, 99]).unwrap()); // too many
    }

    #[test]
    fn tampered_proof_rejected() {
        let circuit = make_mul_circuit(3, 4);
        let (pk, vk) = setup(&circuit).unwrap();
        let mut proof = prove(&pk, &circuit, &[3, 4, 12]).unwrap();
        proof.a[0] ^= 0xFF;
        assert!(!verify(&vk, &proof, &[3, 12]).unwrap());
    }

    #[test]
    fn setup_empty_circuit_rejected() {
        struct EmptyCircuit;
        impl Circuit for EmptyCircuit {
            fn synthesize(&self, _cs: &mut ConstraintSystem) -> crate::error::Result<()> {
                Ok(())
            }
        }
        let err = setup(&EmptyCircuit).unwrap_err();
        assert!(matches!(err, ProofError::SetupError(_)));
    }

    #[test]
    fn proof_deterministic() {
        let circuit = make_mul_circuit(5, 6);
        let (pk, _) = setup(&circuit).unwrap();
        let p1 = prove(&pk, &circuit, &[5, 6, 30]).unwrap();
        let p2 = prove(&pk, &circuit, &[5, 6, 30]).unwrap();
        assert_eq!(p1, p2);
    }
}
