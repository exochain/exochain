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

//! Generate a committed RISC Zero receipt fixture for CGR Identity reduction.

use std::{fs, path::PathBuf};

use exo_cgr_prover::prove_cgr_reduction;
use exo_gatekeeper::{Combinator, CombinatorInput};

fn main() {
    let combinator = Combinator::Identity;
    let input = CombinatorInput::new().with("k", "v");
    let (envelope, receipt_bytes, trace) =
        prove_cgr_reduction(&combinator, &input).expect("prove CGR Identity reduction");

    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    fs::create_dir_all(&out_dir).expect("create fixtures dir");
    fs::write(out_dir.join("cgr_identity_receipt.cbor"), &receipt_bytes)
        .expect("write receipt fixture");

    let mut envelope_cbor = Vec::new();
    ciborium::into_writer(&envelope, &mut envelope_cbor).expect("encode envelope");
    fs::write(out_dir.join("cgr_identity_envelope.cbor"), envelope_cbor)
        .expect("write envelope fixture");

    println!(
        "wrote CGR Identity RISC Zero fixture; trace_hash={} receipt_bytes={}",
        trace.trace_hash,
        receipt_bytes.len()
    );
}
