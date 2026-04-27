//! Unified proof verifier -- dispatches to the appropriate proof system.

use serde::{Deserialize, Serialize};

use crate::{
    error::{ProofError, Result},
    snark, stark, zkml,
};

// ---------------------------------------------------------------------------
// ProofType
// ---------------------------------------------------------------------------

/// The type of zero-knowledge proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// SNARK proof (succinct, pairing-based structure).
    Snark,
    /// STARK proof (hash-based, post-quantum).
    Stark,
    /// ZKML inference proof.
    Zkml,
}

// ---------------------------------------------------------------------------
// Serialized proof formats
// ---------------------------------------------------------------------------

/// A serialized SNARK verification bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkBundle {
    pub vk: snark::VerifyingKey,
    pub proof: snark::Proof,
}

/// A serialized STARK verification bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkBundle {
    pub proof: stark::StarkProof,
}

/// A serialized ZKML verification bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlBundle {
    pub proof: zkml::InferenceProof,
}

// ---------------------------------------------------------------------------
// verify_any
// ---------------------------------------------------------------------------

/// Verify any proof type given its serialized form and public inputs.
///
/// The `proof_bytes` should be a JSON-encoded bundle appropriate for the
/// proof type. The `public_inputs_bytes` contains the JSON-encoded public inputs.
pub fn verify_any(
    proof_type: ProofType,
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool> {
    match proof_type {
        ProofType::Snark => verify_snark(proof_bytes, public_inputs_bytes),
        ProofType::Stark => verify_stark(proof_bytes, public_inputs_bytes),
        ProofType::Zkml => verify_zkml(proof_bytes),
    }
}

fn verify_snark(proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Result<bool> {
    let bundle: SnarkBundle = serde_json::from_slice(proof_bytes)
        .map_err(|e| ProofError::DeserializationError(e.to_string()))?;

    let public_inputs: Vec<u64> = serde_json::from_slice(public_inputs_bytes)
        .map_err(|e| ProofError::DeserializationError(e.to_string()))?;

    snark::verify(&bundle.vk, &bundle.proof, &public_inputs)
}

fn verify_stark(proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Result<bool> {
    let bundle: StarkBundle = serde_json::from_slice(proof_bytes)
        .map_err(|e| ProofError::DeserializationError(e.to_string()))?;

    let public_inputs: Vec<u64> = serde_json::from_slice(public_inputs_bytes)
        .map_err(|e| ProofError::DeserializationError(e.to_string()))?;

    stark::verify_stark(&bundle.proof, &public_inputs)
}

fn verify_zkml(proof_bytes: &[u8]) -> Result<bool> {
    let bundle: ZkmlBundle = serde_json::from_slice(proof_bytes)
        .map_err(|e| ProofError::DeserializationError(e.to_string()))?;

    zkml::verify_inference(&bundle.proof)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "unaudited-pedagogical-proofs"))]
mod tests {
    use super::*;
    use crate::{
        circuit::{
            Circuit, ConstraintSystem, LinearCombination, allocate, allocate_public, enforce,
        },
        snark,
        stark::StarkConfig,
        zkml::{self, ModelCommitment},
    };

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

    #[test]
    fn verify_any_snark() {
        let circuit = MulCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(12),
        };
        let (pk, vk) = snark::setup(&circuit).unwrap();
        let proof = snark::prove(&pk, &circuit, &[3, 4, 12]).unwrap();

        let bundle = SnarkBundle { vk, proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();
        let public_inputs_bytes = serde_json::to_vec(&vec![3u64, 12u64]).unwrap();

        let result = verify_any(ProofType::Snark, &proof_bytes, &public_inputs_bytes).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_snark_invalid() {
        let circuit = MulCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(12),
        };
        let (pk, vk) = snark::setup(&circuit).unwrap();
        let proof = snark::prove(&pk, &circuit, &[3, 4, 12]).unwrap();

        let bundle = SnarkBundle { vk, proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();
        let wrong_inputs = serde_json::to_vec(&vec![3u64, 13u64]).unwrap();

        let result = verify_any(ProofType::Snark, &proof_bytes, &wrong_inputs).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_any_stark() {
        let config = StarkConfig::default_config();
        let trace: Vec<Vec<u64>> = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let proof = crate::stark::prove_stark(&trace, &[], &config).unwrap();

        let bundle = StarkBundle { proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();
        let public_inputs_bytes = serde_json::to_vec(&vec![1u64, 2u64]).unwrap();

        let result = verify_any(ProofType::Stark, &proof_bytes, &public_inputs_bytes).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_zkml() {
        let model = ModelCommitment::new(b"arch", b"weights", 1);
        let proof = zkml::prove_inference(&model, b"input", b"output").unwrap();

        let bundle = ZkmlBundle { proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();

        let result = verify_any(ProofType::Zkml, &proof_bytes, b"[]").unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_zkml_tampered() {
        let model = ModelCommitment::new(b"arch", b"weights", 1);
        let mut proof = zkml::prove_inference(&model, b"input", b"output").unwrap();
        proof.output_hash = exo_core::types::Hash256::ZERO;

        let bundle = ZkmlBundle { proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();

        let result = verify_any(ProofType::Zkml, &proof_bytes, b"[]").unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_any_bad_proof_bytes() {
        let err = verify_any(ProofType::Snark, b"not json", b"[]").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_bad_public_inputs_bytes() {
        let circuit = MulCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(12),
        };
        let (pk, vk) = snark::setup(&circuit).unwrap();
        let proof = snark::prove(&pk, &circuit, &[3, 4, 12]).unwrap();

        let bundle = SnarkBundle { vk, proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();

        let err = verify_any(ProofType::Snark, &proof_bytes, b"not json").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn proof_type_serde() {
        let types = vec![ProofType::Snark, ProofType::Stark, ProofType::Zkml];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let t2: ProofType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, &t2);
        }
    }

    #[test]
    fn proof_type_eq() {
        assert_eq!(ProofType::Snark, ProofType::Snark);
        assert_ne!(ProofType::Snark, ProofType::Stark);
        assert_ne!(ProofType::Stark, ProofType::Zkml);
    }

    #[test]
    fn verify_any_stark_bad_proof_bytes() {
        let err = verify_any(ProofType::Stark, b"not json", b"[]").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_stark_bad_public_inputs_bytes() {
        let config = StarkConfig::default_config();
        let trace: Vec<Vec<u64>> = vec![vec![1, 2], vec![3, 4]];
        let proof = crate::stark::prove_stark(&trace, &[], &config).unwrap();
        let bundle = StarkBundle { proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();
        let err = verify_any(ProofType::Stark, &proof_bytes, b"not json").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_zkml_bad_proof_bytes() {
        let err = verify_any(ProofType::Zkml, b"not json", b"[]").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }
}
