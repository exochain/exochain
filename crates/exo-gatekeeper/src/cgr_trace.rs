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

//! CGR reduction traces — produced by combinator reduction, carried in
//! evidence bundles, and verified by deterministic replay.

use exo_core::{Did, Hash256, events::EventPayload, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    combinator::{Combinator, CombinatorInput, CombinatorOutput, reduce_with_trace},
    error::GatekeeperError,
    invariants::ConstitutionalInvariant,
};

/// Domain for the sealed reduction-trace hash.
pub const CGR_TRACE_SPEC: &str = "exo.cgr.reduction_trace.v1";
const CGR_TRACE_SIGNING_SCHEMA_VERSION: u16 = 1;

/// Evidence type tag placed on legal evidence items that carry a trace.
pub const CGR_TRACE_EVIDENCE_TYPE: &str = "cgr.reduction_trace.v1";

/// One reduction node: kind, depth, input/output hashes, success or error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgrTraceStep {
    pub seq: u64,
    pub depth: u32,
    pub kind: String,
    pub input_hash: Hash256,
    pub output_hash: Option<Hash256>,
    pub ok: bool,
    pub error: Option<String>,
}

/// Result of checking one constitutional invariant during the step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgrInvariantCheck {
    pub name: String,
    pub passed: bool,
}

/// Complete, hash-sealed CGR reduction trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgrReductionTrace {
    pub spec: String,
    pub combinator_hash: Hash256,
    pub input_hash: Hash256,
    pub output_hash: Hash256,
    pub steps: Vec<CgrTraceStep>,
    pub invariants_checked: Vec<CgrInvariantCheck>,
    pub kernel_constitution_hash: Option<Hash256>,
    pub checkpoint: Option<String>,
    pub trace_hash: Hash256,
}

#[derive(Serialize)]
struct TraceSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    spec: &'a str,
    combinator_hash: &'a Hash256,
    input_hash: &'a Hash256,
    output_hash: &'a Hash256,
    steps: &'a [CgrTraceStep],
    invariants_checked: &'a [CgrInvariantCheck],
    kernel_constitution_hash: Option<&'a Hash256>,
    checkpoint: Option<&'a str>,
}

impl CgrReductionTrace {
    /// Seal a produced step log into a content-addressed trace.
    pub fn seal(
        combinator: &Combinator,
        input: &CombinatorInput,
        output: &CombinatorOutput,
        steps: Vec<CgrTraceStep>,
        invariants_checked: Vec<CgrInvariantCheck>,
    ) -> Result<Self, GatekeeperError> {
        if steps.is_empty() {
            return Err(GatekeeperError::CombinatorError(
                "CGR reduction trace must contain at least one step".into(),
            ));
        }
        let combinator_hash = hash_structured(combinator).map_err(|e| {
            GatekeeperError::CombinatorError(format!("combinator hash failed: {e}"))
        })?;
        let input_hash = hash_structured(input)
            .map_err(|e| GatekeeperError::CombinatorError(format!("input hash failed: {e}")))?;
        let output_hash = hash_structured(output)
            .map_err(|e| GatekeeperError::CombinatorError(format!("output hash failed: {e}")))?;
        let checkpoint = output.checkpoint.as_ref().map(|c| c.0.clone());
        let mut trace = Self {
            spec: CGR_TRACE_SPEC.into(),
            combinator_hash,
            input_hash,
            output_hash,
            steps,
            invariants_checked,
            kernel_constitution_hash: None,
            checkpoint,
            trace_hash: Hash256::ZERO,
        };
        trace.trace_hash = trace.compute_hash()?;
        Ok(trace)
    }

    /// Replace invariant results and re-seal the hash.
    pub fn with_invariants(
        self,
        invariants_checked: Vec<CgrInvariantCheck>,
    ) -> Result<Self, GatekeeperError> {
        let kernel_constitution_hash = self.kernel_constitution_hash;
        self.with_attestation(invariants_checked, kernel_constitution_hash)
    }

    /// Bind kernel invariant results and constitution hash, then re-seal.
    pub fn with_attestation(
        mut self,
        invariants_checked: Vec<CgrInvariantCheck>,
        kernel_constitution_hash: Option<Hash256>,
    ) -> Result<Self, GatekeeperError> {
        self.invariants_checked = invariants_checked;
        self.kernel_constitution_hash = kernel_constitution_hash;
        self.trace_hash = Hash256::ZERO;
        self.trace_hash = self.compute_hash()?;
        Ok(self)
    }

    fn signing_payload(&self) -> Result<Vec<u8>, GatekeeperError> {
        let payload = TraceSigningPayload {
            domain: CGR_TRACE_SPEC,
            schema_version: CGR_TRACE_SIGNING_SCHEMA_VERSION,
            spec: &self.spec,
            combinator_hash: &self.combinator_hash,
            input_hash: &self.input_hash,
            output_hash: &self.output_hash,
            steps: &self.steps,
            invariants_checked: &self.invariants_checked,
            kernel_constitution_hash: self.kernel_constitution_hash.as_ref(),
            checkpoint: self.checkpoint.as_deref(),
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes)
            .map_err(|e| GatekeeperError::CombinatorError(format!("trace CBOR failed: {e}")))?;
        Ok(bytes)
    }

    fn compute_hash(&self) -> Result<Hash256, GatekeeperError> {
        Ok(Hash256::digest(&self.signing_payload()?))
    }

    /// Recompute the sealed hash and require it match `trace_hash`.
    pub fn verify_hash(&self) -> Result<(), GatekeeperError> {
        if self.spec != CGR_TRACE_SPEC {
            return Err(GatekeeperError::CombinatorError(format!(
                "unknown CGR trace spec {}",
                self.spec
            )));
        }
        if self.trace_hash == Hash256::ZERO {
            return Err(GatekeeperError::CombinatorError(
                "CGR trace hash must not be zero".into(),
            ));
        }
        let recomputed = self.compute_hash()?;
        if recomputed != self.trace_hash {
            return Err(GatekeeperError::CombinatorError(
                "CGR trace hash does not match sealed contents".into(),
            ));
        }
        Ok(())
    }

    /// Replay the combinator and require the produced trace to match this one.
    pub fn verify_replay(
        &self,
        combinator: &Combinator,
        input: &CombinatorInput,
    ) -> Result<(), GatekeeperError> {
        self.verify_hash()?;
        let (output, replayed) = reduce_with_trace(combinator, input)?;
        let replayed = replayed.with_attestation(
            self.invariants_checked.clone(),
            self.kernel_constitution_hash,
        )?;
        if replayed.trace_hash != self.trace_hash {
            return Err(GatekeeperError::CombinatorError(
                "replayed CGR trace hash does not match presented trace".into(),
            ));
        }
        let output_hash = hash_structured(&output)
            .map_err(|e| GatekeeperError::CombinatorError(format!("replay output hash: {e}")))?;
        if output_hash != self.output_hash {
            return Err(GatekeeperError::CombinatorError(
                "replayed combinator output hash does not match trace".into(),
            ));
        }
        Ok(())
    }

    /// Canonical event payloads for a verified holon reduction.
    #[must_use]
    pub fn event_payloads(&self, holon_did: Did) -> Vec<EventPayload> {
        let invariant_count = u32::try_from(self.invariants_checked.len()).unwrap_or(u32::MAX);
        let proof_id = self.steps.last().map(|s| s.seq).unwrap_or(0);
        vec![
            EventPayload::HolonActionVerified {
                holon_did: holon_did.clone(),
                action_hash: self.output_hash,
                cgr_proof_hash: self.trace_hash,
            },
            EventPayload::CgrProofIssued {
                proof_id,
                invariants_checked: invariant_count,
                registry_hash: self.combinator_hash,
            },
        ]
    }
}

/// Record one invariant result from a live kernel check.
#[must_use]
pub fn invariant_check(invariant: ConstitutionalInvariant, passed: bool) -> CgrInvariantCheck {
    CgrInvariantCheck {
        name: invariant.id().to_string(),
        passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combinator::{Combinator, CombinatorInput, TransformFn};

    fn sample_program() -> Combinator {
        Combinator::Sequence(vec![
            Combinator::Identity,
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "tag".into(),
                    output_key: "tagged".into(),
                    output_value: "yes".into(),
                },
            ),
        ])
    }

    #[test]
    fn produced_trace_replays() {
        let program = sample_program();
        let input = CombinatorInput::new().with("k", "v");
        let (_out, trace) = reduce_with_trace(&program, &input).unwrap();
        trace.verify_replay(&program, &input).unwrap();
        assert!(trace.steps.len() >= 3);
        assert_ne!(trace.trace_hash, Hash256::ZERO);
        assert!(trace.steps.iter().all(|s| s.ok));
    }

    #[test]
    fn tampered_trace_fails_replay() {
        let program = sample_program();
        let input = CombinatorInput::new().with("k", "v");
        let (_out, mut trace) = reduce_with_trace(&program, &input).unwrap();
        trace.steps[0].kind = "Forged".into();
        assert!(trace.verify_replay(&program, &input).is_err());
    }

    #[test]
    fn different_input_fails_replay() {
        let program = sample_program();
        let input = CombinatorInput::new().with("k", "v");
        let (_out, trace) = reduce_with_trace(&program, &input).unwrap();
        let other = CombinatorInput::new().with("k", "other");
        assert!(trace.verify_replay(&program, &other).is_err());
    }

    #[test]
    fn event_payloads_bind_trace_hash() {
        let program = Combinator::Identity;
        let input = CombinatorInput::new();
        let (_out, trace) = reduce_with_trace(&program, &input).unwrap();
        let holon = Did::new("did:exo:holon").unwrap();
        let events = trace.event_payloads(holon.clone());
        match &events[0] {
            EventPayload::HolonActionVerified {
                holon_did,
                cgr_proof_hash,
                ..
            } => {
                assert_eq!(holon_did, &holon);
                assert_eq!(cgr_proof_hash, &trace.trace_hash);
            }
            other => panic!("expected HolonActionVerified, got {other:?}"),
        }
        match &events[1] {
            EventPayload::CgrProofIssued {
                invariants_checked,
                registry_hash,
                ..
            } => {
                assert_eq!(*invariants_checked, 0);
                assert_eq!(registry_hash, &trace.combinator_hash);
            }
            other => panic!("expected CgrProofIssued, got {other:?}"),
        }
    }

    #[test]
    fn kernel_attestation_is_bound_into_trace_hash() {
        let program = Combinator::Identity;
        let input = CombinatorInput::new();
        let (_out, trace) = reduce_with_trace(&program, &input).unwrap();
        let constitution = Hash256::digest(b"constitution");
        let attested = trace
            .clone()
            .with_attestation(
                vec![CgrInvariantCheck {
                    name: "consent-required".into(),
                    passed: true,
                }],
                Some(constitution),
            )
            .unwrap();
        assert_ne!(attested.trace_hash, trace.trace_hash);
        attested.verify_replay(&program, &input).unwrap();
        assert_eq!(attested.kernel_constitution_hash, Some(constitution));
        assert_eq!(attested.invariants_checked.len(), 1);
    }
}
