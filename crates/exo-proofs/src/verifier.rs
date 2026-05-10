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

//! Unified proof verifier -- dispatches to the appropriate proof system.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    error::{ProofError, Result},
    snark, stark, zkml,
};

const MAX_VERIFIER_CBOR_BYTES: usize = 1_048_576;

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

/// Public STARK statement supplied by the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkPublicInputs {
    /// Public inputs, currently the first row of the committed trace.
    pub inputs: Vec<u64>,
    /// Public transition constraints the proof must satisfy.
    pub constraints: Vec<stark::StarkConstraint>,
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
/// The `proof_bytes` must be a canonical CBOR bundle appropriate for the proof
/// type. The `public_inputs_bytes` contains canonical CBOR public inputs.
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

fn decode_cbor<T: DeserializeOwned>(bytes: &[u8], label: &'static str) -> Result<T> {
    if bytes.len() > MAX_VERIFIER_CBOR_BYTES {
        return Err(ProofError::DeserializationError(format!(
            "{label}: canonical CBOR input exceeds maximum size of {MAX_VERIFIER_CBOR_BYTES} bytes"
        )));
    }
    ciborium::from_reader(bytes).map_err(|e| {
        ProofError::DeserializationError(format!("{label}: canonical CBOR decode failed: {e}"))
    })
}

fn verify_snark(proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Result<bool> {
    let bundle: SnarkBundle = decode_cbor(proof_bytes, "snark proof bundle")?;
    let public_inputs: Vec<u64> = decode_cbor(public_inputs_bytes, "snark public inputs")?;

    snark::verify(&bundle.vk, &bundle.proof, &public_inputs)
}

fn verify_stark(proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Result<bool> {
    let bundle: StarkBundle = decode_cbor(proof_bytes, "stark proof bundle")?;
    let public_inputs: StarkPublicInputs = decode_cbor(public_inputs_bytes, "stark public inputs")?;

    stark::verify_stark_with_constraints(
        &bundle.proof,
        &public_inputs.inputs,
        &public_inputs.constraints,
    )
}

fn verify_zkml(proof_bytes: &[u8]) -> Result<bool> {
    let bundle: ZkmlBundle = decode_cbor(proof_bytes, "zkml proof bundle")?;

    zkml::verify_inference(&bundle.proof)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod canonical_encoding_contract_tests {
    #[test]
    fn verify_any_uses_canonical_cbor_not_json() {
        let source = include_str!("verifier.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section exists");

        assert!(
            !production.contains("serde_json::from_slice"),
            "proof verifier must not decode proof bundles or public inputs as JSON"
        );
        assert!(
            production.contains("ciborium::from_reader"),
            "proof verifier must decode proof bundles and public inputs as canonical CBOR"
        );
    }

    #[test]
    fn decode_cbor_rejects_oversized_inputs_before_deserialization() {
        let oversized = vec![0u8; 1_048_577];
        let err = super::decode_cbor::<Vec<u8>>(&oversized, "oversized proof").unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "oversized proof input must fail before CBOR decode: {err}"
        );
    }
}

#[cfg(all(test, feature = "unaudited-pedagogical-proofs"))]
mod tests {
    use super::*;
    use crate::{
        circuit::{
            Circuit, ConstraintSystem, LinearCombination, allocate, allocate_public, enforce,
        },
        snark,
        stark::{StarkConfig, StarkConstraint},
        zkml::{self, ModelCommitment},
    };

    fn cbor_bytes<T: Serialize>(value: &T) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::into_writer(value, &mut encoded).expect("canonical CBOR encode");
        encoded
    }

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
        let proof_bytes = cbor_bytes(&bundle);
        let public_inputs_bytes = cbor_bytes(&vec![3u64, 12u64]);

        let result = verify_any(ProofType::Snark, &proof_bytes, &public_inputs_bytes).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_snark_accepts_canonical_cbor() {
        let circuit = MulCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(12),
        };
        let (pk, vk) = snark::setup(&circuit).unwrap();
        let proof = snark::prove(&pk, &circuit, &[3, 4, 12]).unwrap();

        let bundle = SnarkBundle { vk, proof };
        let proof_bytes = cbor_bytes(&bundle);
        let public_inputs_bytes = cbor_bytes(&vec![3u64, 12u64]);

        let result = verify_any(ProofType::Snark, &proof_bytes, &public_inputs_bytes).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_rejects_json_snark_bundle() {
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

        let err = verify_any(ProofType::Snark, &proof_bytes, &public_inputs_bytes).unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_rejects_json_stark_bundle() {
        let config = StarkConfig {
            num_queries: 2,
            ..StarkConfig::default_config()
        };
        let trace: Vec<Vec<u64>> = vec![vec![1], vec![1], vec![1]];
        let constraints = vec![StarkConstraint {
            name: "constant".to_string(),
            column_indices: vec![0],
            coefficients: vec![(1, config.field_size - 1)],
        }];
        let proof = crate::stark::prove_stark(&trace, &constraints, &config).unwrap();

        let bundle = StarkBundle { proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();
        let public_inputs_bytes = cbor_bytes(&StarkPublicInputs {
            inputs: vec![1u64],
            constraints,
        });

        let err = verify_any(ProofType::Stark, &proof_bytes, &public_inputs_bytes).unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_rejects_json_zkml_bundle() {
        let model = ModelCommitment::new(b"arch", b"weights", 1);
        let proof = zkml::prove_inference(&model, b"input", b"output").unwrap();

        let bundle = ZkmlBundle { proof };
        let proof_bytes = serde_json::to_vec(&bundle).unwrap();

        let err = verify_any(ProofType::Zkml, &proof_bytes, b"[]").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
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
        let proof_bytes = cbor_bytes(&bundle);
        let wrong_inputs = cbor_bytes(&vec![3u64, 13u64]);

        let result = verify_any(ProofType::Snark, &proof_bytes, &wrong_inputs).unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_any_stark() {
        let config = StarkConfig {
            num_queries: 2,
            ..StarkConfig::default_config()
        };
        let trace: Vec<Vec<u64>> = vec![vec![1], vec![1], vec![1]];
        let constraints = vec![StarkConstraint {
            name: "constant".to_string(),
            column_indices: vec![0],
            coefficients: vec![(1, config.field_size - 1)],
        }];
        let proof = crate::stark::prove_stark(&trace, &constraints, &config).unwrap();

        let bundle = StarkBundle { proof };
        let proof_bytes = cbor_bytes(&bundle);
        let public_inputs_bytes = cbor_bytes(&StarkPublicInputs {
            inputs: vec![1u64],
            constraints,
        });

        let result = verify_any(ProofType::Stark, &proof_bytes, &public_inputs_bytes).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_zkml() {
        let model = ModelCommitment::new(b"arch", b"weights", 1);
        let proof = zkml::prove_inference(&model, b"input", b"output").unwrap();

        let bundle = ZkmlBundle { proof };
        let proof_bytes = cbor_bytes(&bundle);

        let result = verify_any(ProofType::Zkml, &proof_bytes, b"[]").unwrap();
        assert!(result);
    }

    #[test]
    fn verify_any_zkml_tampered() {
        let model = ModelCommitment::new(b"arch", b"weights", 1);
        let mut proof = zkml::prove_inference(&model, b"input", b"output").unwrap();
        proof.output_hash = exo_core::types::Hash256::ZERO;

        let bundle = ZkmlBundle { proof };
        let proof_bytes = cbor_bytes(&bundle);

        let result = verify_any(ProofType::Zkml, &proof_bytes, b"[]").unwrap();
        assert!(!result);
    }

    #[test]
    fn verify_any_bad_proof_bytes() {
        let err = verify_any(ProofType::Snark, b"not cbor", b"[]").unwrap_err();
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
        let proof_bytes = cbor_bytes(&bundle);
        let legacy_json_inputs = serde_json::to_vec(&vec![3u64, 12u64]).unwrap();

        let err = verify_any(ProofType::Snark, &proof_bytes, &legacy_json_inputs).unwrap_err();
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
        let err = verify_any(ProofType::Stark, b"not cbor", b"[]").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_stark_bad_public_inputs_bytes() {
        let config = StarkConfig {
            num_queries: 1,
            ..StarkConfig::default_config()
        };
        let trace: Vec<Vec<u64>> = vec![vec![1], vec![1]];
        let constraints = vec![StarkConstraint {
            name: "constant".to_string(),
            column_indices: vec![0],
            coefficients: vec![(1, config.field_size - 1)],
        }];
        let proof = crate::stark::prove_stark(&trace, &constraints, &config).unwrap();
        let bundle = StarkBundle { proof };
        let proof_bytes = cbor_bytes(&bundle);
        // Legacy bare public-input arrays are rejected because STARK
        // verification now requires caller-supplied public constraints.
        let legacy_json_inputs = serde_json::to_vec(&vec![1u64]).unwrap();
        let err = verify_any(ProofType::Stark, &proof_bytes, &legacy_json_inputs).unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }

    #[test]
    fn verify_any_zkml_bad_proof_bytes() {
        let err = verify_any(ProofType::Zkml, b"not cbor", b"[]").unwrap_err();
        assert!(matches!(err, ProofError::DeserializationError(_)));
    }
}
