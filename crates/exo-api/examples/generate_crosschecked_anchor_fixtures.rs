// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Writes the locked CrossChecked anchor fixtures from the independent literal
//! reference builder used by integration tests. It does not call the production
//! `exo_api::crosschecked_anchor` codec.

#[path = "../tests/support/crosschecked_anchor_fixture_reference.rs"]
mod fixture_reference;

use std::{error::Error, fs, path::PathBuf};

use fixture_reference::build_reference_fixtures;

fn main() -> Result<(), Box<dyn Error>> {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("crosschecked-anchor-v1");
    fs::create_dir_all(&fixture_dir)?;
    let fixtures = build_reference_fixtures();
    for (name, bytes) in [
        ("request.cbor", fixtures.request.as_slice()),
        (
            "request-signing-preimage.cbor",
            fixtures.request_signing_preimage.as_slice(),
        ),
        (
            "request-signature.ed25519",
            fixtures.request_signature.as_slice(),
        ),
        ("request-hash.blake3-256", fixtures.request_hash.as_slice()),
        (
            "idempotency-key.blake3-256",
            fixtures.idempotency_key.as_slice(),
        ),
        (
            "authority-public-key.ed25519",
            fixtures.authority_public_key.as_slice(),
        ),
        (
            "nested-trust-receipt.cbor",
            fixtures.nested_receipt.as_slice(),
        ),
        ("response.cbor", fixtures.response.as_slice()),
        (
            "response-signing-preimage.cbor",
            fixtures.response_signing_preimage.as_slice(),
        ),
        (
            "response-signature.ed25519",
            fixtures.response_signature.as_slice(),
        ),
        (
            "node-public-key.ed25519",
            fixtures.node_public_key.as_slice(),
        ),
    ] {
        fs::write(fixture_dir.join(name), bytes)?;
    }
    Ok(())
}
