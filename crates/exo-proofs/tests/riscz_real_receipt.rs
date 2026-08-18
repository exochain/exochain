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

//! Verifies a committed RISC Zero receipt for CGR Identity reduction.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_proofs::envelope::ProofEnvelope;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../exo-cgr-prover/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|err| {
        panic!("missing CGR RISC Zero fixture {path}: {err}; run `cargo run -p exochain-cgr-prover --features prove --bin generate-cgr-receipt-fixture`")
    })
}

#[test]
fn verifies_committed_cgr_identity_receipt() {
    let receipt = fixture("cgr_identity_receipt.cbor");
    let envelope_bytes = fixture("cgr_identity_envelope.cbor");
    let envelope: ProofEnvelope =
        ciborium::from_reader(envelope_bytes.as_slice()).expect("decode envelope fixture");
    assert_eq!(
        envelope.backend_id,
        exo_proofs::envelope::BackendId::RiscZero
    );
    let ok = envelope
        .verify(&receipt)
        .expect("real RISC Zero receipt must verify");
    assert!(ok);
}
