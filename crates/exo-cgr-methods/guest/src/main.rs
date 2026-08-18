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

#![no_main]

use exo_gatekeeper::{reduce_with_trace, Combinator, CombinatorInput};
use exo_proofs::envelope::{CgrZkPublicInputs, ProofEnvelope};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let envelope: ProofEnvelope = env::read();
    let combinator: Combinator = env::read();
    let input: CombinatorInput = env::read();

    let (_output, trace) =
        reduce_with_trace(&combinator, &input).expect("CGR combinator reduction failed");
    let declared = CgrZkPublicInputs::from_public_inputs(&envelope.public_inputs)
        .expect("CGR public inputs are not four 32-byte hashes");
    assert_eq!(
        declared.combinator_hash, trace.combinator_hash,
        "combinator hash mismatch"
    );
    assert_eq!(declared.input_hash, trace.input_hash, "input hash mismatch");
    assert_eq!(
        declared.output_hash, trace.output_hash,
        "output hash mismatch"
    );
    assert_eq!(declared.trace_hash, trace.trace_hash, "trace hash mismatch");

    let journal = envelope
        .binding_payload()
        .expect("envelope binding payload failed");
    env::commit_slice(journal.as_slice());
}
