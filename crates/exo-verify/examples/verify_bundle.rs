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

//! Verify a receipt bundle offline.
//!
//! ```text
//! cargo run -p exochain-verify --example verify_bundle -- \
//!     crates/exo-verify/fixtures/offline-bundle/receipt-bundle.json \
//!     crates/exo-verify/fixtures/offline-bundle/trust-inputs.json
//! ```
//!
//! Reads two local JSON files and opens no network connections. Exits 0
//! when all four properties verify and 1 otherwise, printing the failure.

use std::{fs, process::ExitCode};

use exo_verify::{ReceiptBundle, TrustInputs, verify_receipt_bundle};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [bundle_path, trust_path] = args.as_slice() else {
        eprintln!("usage: verify_bundle <receipt-bundle.json> <trust-inputs.json>");
        return ExitCode::from(2);
    };
    let bundle: ReceiptBundle = match read_json(bundle_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cannot read receipt bundle {bundle_path}: {error}");
            return ExitCode::from(2);
        }
    };
    let trust: TrustInputs = match read_json(trust_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cannot read trust inputs {trust_path}: {error}");
            return ExitCode::from(2);
        }
    };
    match verify_receipt_bundle(&bundle, &trust) {
        Ok(verified) => {
            println!("receipt {}", verified.receipt_id);
            println!(
                "  1. signatures       OK  validator {} and subject {} signed the stored bytes",
                verified.validator_did, verified.subject_did
            );
            println!(
                "  2. inclusion        OK  position {} of {} under a signed tree head",
                verified.leaf_index, verified.tree_size
            );
            println!("  3. signer identity  OK  both keys resolve in the key bundle");
            println!(
                "  4. trusted time     OK  RFC 3161 time {} ms (subject signed at {} ms)",
                verified.trusted_time.physical_ms, verified.subject_signed_at.physical_ms
            );
            println!(
                "  human approval present: {} (signature not verified offline; see #911)",
                verified.human_approval_present
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("receipt {}", bundle.receipt.receipt_id);
            println!("  FAILED: {error}");
            ExitCode::from(1)
        }
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}
