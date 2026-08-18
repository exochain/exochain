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

//! Server-side CGR RISC Zero proving.
//!
//! Envelope construction is always available. Generating a receipt requires
//! the `prove` feature (the RISC Zero proving toolchain).

use exo_gatekeeper::{CGR_TRACE_SPEC, CgrReductionTrace};
#[cfg(feature = "prove")]
use exo_gatekeeper::{Combinator, CombinatorInput};
use exo_proofs::envelope::{
    BackendId, CgrZkPublicInputs, ProofEnvelope, ProofStatementKind,
};
use exo_proofs::error::{ProofError, Result};

/// Build the RISC Zero envelope for a produced CGR reduction trace.
pub fn cgr_proof_envelope(
    trace: &CgrReductionTrace,
    image_id: &[u8],
) -> Result<ProofEnvelope> {
    let public = CgrZkPublicInputs {
        combinator_hash: trace.combinator_hash,
        input_hash: trace.input_hash,
        output_hash: trace.output_hash,
        trace_hash: trace.trace_hash,
    };
    Ok(ProofEnvelope {
        statement_kind: ProofStatementKind::ExecutionReceipt,
        backend_id: BackendId::RiscZero,
        version: 1,
        public_inputs: public.to_public_inputs(),
        commitment_roots: vec![trace.trace_hash],
        verifier_key_or_image_id: image_id.to_vec(),
        domain_separator: CGR_TRACE_SPEC.as_bytes().to_vec(),
    })
}

/// Canonical-CBOR encode a RISC Zero receipt for [`ProofEnvelope::verify`].
pub fn encode_receipt_cbor<T: serde::Serialize>(receipt: &T) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(receipt, &mut encoded).map_err(|err| {
        ProofError::InvalidProofFormat(format!("failed to CBOR-encode RISC Zero receipt: {err}"))
    })?;
    Ok(encoded)
}

/// Prove that `combinator` reduces `input` and bind the sealed trace into a
/// RISC Zero receipt.
#[cfg(feature = "prove")]
pub fn prove_cgr_reduction(
    combinator: &Combinator,
    input: &CombinatorInput,
) -> Result<(ProofEnvelope, Vec<u8>, CgrReductionTrace)> {
    use exo_cgr_methods::{EXOCHAIN_CGR_GUEST_ELF, EXOCHAIN_CGR_GUEST_ID};
    use risc0_zkvm::{ExecutorEnv, default_prover};

    let (_output, trace) = exo_gatekeeper::reduce_with_trace(combinator, input).map_err(|err| {
        ProofError::VerificationFailed(format!("host CGR reduction failed: {err}"))
    })?;
    let image_id = image_id_bytes(EXOCHAIN_CGR_GUEST_ID);
    let envelope = cgr_proof_envelope(&trace, &image_id)?;

    let env = ExecutorEnv::builder()
        .write(&envelope)
        .map_err(|err| ProofError::VerificationFailed(format!("executor write envelope: {err}")))?
        .write(combinator)
        .map_err(|err| ProofError::VerificationFailed(format!("executor write combinator: {err}")))?
        .write(input)
        .map_err(|err| ProofError::VerificationFailed(format!("executor write input: {err}")))?
        .build()
        .map_err(|err| ProofError::VerificationFailed(format!("executor env build: {err}")))?;

    let prove_info = default_prover()
        .prove(env, EXOCHAIN_CGR_GUEST_ELF)
        .map_err(|err| ProofError::VerificationFailed(format!("risc0 prove failed: {err}")))?;
    let receipt_bytes = encode_receipt_cbor(&prove_info.receipt)?;
    Ok((envelope, receipt_bytes, trace))
}

#[cfg(feature = "prove")]
fn image_id_bytes(id: [u32; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    for word in id {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use exo_gatekeeper::{reduce_with_trace, Combinator, CombinatorInput};

    #[test]
    fn envelope_public_inputs_match_produced_trace() {
        let combinator = Combinator::Identity;
        let input = CombinatorInput::new().with("k", "v");
        let (_out, trace) = reduce_with_trace(&combinator, &input).unwrap();
        let envelope = cgr_proof_envelope(&trace, &[7u8; 32]).unwrap();
        let public = CgrZkPublicInputs::from_public_inputs(&envelope.public_inputs).unwrap();
        assert_eq!(public.trace_hash, trace.trace_hash);
        assert_eq!(envelope.backend_id, BackendId::RiscZero);
        assert_eq!(envelope.domain_separator, CGR_TRACE_SPEC.as_bytes());
    }
}
