// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/crosschecked_anchor_fixture_reference.rs"]
mod fixture_reference;

use exo_api::crosschecked_anchor::{
    ANCHOR_PATH, RequestValidationContext, ResponseValidationContext, decode_and_validate_request,
    decode_and_validate_response,
};
use exo_core::types::{Hash256, PublicKey};
use fixture_reference::build_reference_fixtures;
use sha2::{Digest, Sha256};

const FIXTURE_ROOT: &str = "../fixtures/crosschecked-anchor-v1";

#[test]
fn locked_binary_fixtures_equal_the_independent_reference_generator() {
    let reference = build_reference_fixtures();
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/request.cbor"),
        reference.request.as_slice()
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/request-signing-preimage.cbor"),
        reference.request_signing_preimage.as_slice()
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/request-signature.ed25519"),
        &reference.request_signature
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/request-hash.blake3-256"),
        &reference.request_hash
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/idempotency-key.blake3-256"),
        &reference.idempotency_key
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/authority-public-key.ed25519"),
        &reference.authority_public_key
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/nested-trust-receipt.cbor"),
        reference.nested_receipt.as_slice()
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/response.cbor"),
        reference.response.as_slice()
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/response-signing-preimage.cbor"),
        reference.response_signing_preimage.as_slice()
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/response-signature.ed25519"),
        &reference.response_signature
    );
    assert_eq!(
        include_bytes!("../fixtures/crosschecked-anchor-v1/node-public-key.ed25519"),
        &reference.node_public_key
    );
}

#[test]
fn locked_fixture_manifest_matches_every_binary() {
    let fixtures: [(&str, &[u8]); 11] = [
        (
            "authority-public-key.ed25519",
            include_bytes!("../fixtures/crosschecked-anchor-v1/authority-public-key.ed25519"),
        ),
        (
            "idempotency-key.blake3-256",
            include_bytes!("../fixtures/crosschecked-anchor-v1/idempotency-key.blake3-256"),
        ),
        (
            "nested-trust-receipt.cbor",
            include_bytes!("../fixtures/crosschecked-anchor-v1/nested-trust-receipt.cbor"),
        ),
        (
            "node-public-key.ed25519",
            include_bytes!("../fixtures/crosschecked-anchor-v1/node-public-key.ed25519"),
        ),
        (
            "request-hash.blake3-256",
            include_bytes!("../fixtures/crosschecked-anchor-v1/request-hash.blake3-256"),
        ),
        (
            "request-signature.ed25519",
            include_bytes!("../fixtures/crosschecked-anchor-v1/request-signature.ed25519"),
        ),
        (
            "request-signing-preimage.cbor",
            include_bytes!("../fixtures/crosschecked-anchor-v1/request-signing-preimage.cbor"),
        ),
        (
            "request.cbor",
            include_bytes!("../fixtures/crosschecked-anchor-v1/request.cbor"),
        ),
        (
            "response-signature.ed25519",
            include_bytes!("../fixtures/crosschecked-anchor-v1/response-signature.ed25519"),
        ),
        (
            "response-signing-preimage.cbor",
            include_bytes!("../fixtures/crosschecked-anchor-v1/response-signing-preimage.cbor"),
        ),
        (
            "response.cbor",
            include_bytes!("../fixtures/crosschecked-anchor-v1/response.cbor"),
        ),
    ];
    let expected = fixtures
        .into_iter()
        .map(|(name, bytes)| {
            let digest = Sha256::digest(bytes);
            let hex = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("{hex}  {name}\n")
        })
        .collect::<String>();
    assert_eq!(
        include_str!("../fixtures/crosschecked-anchor-v1/MANIFEST.sha256"),
        expected
    );
}

#[test]
fn locked_fixtures_validate_and_single_byte_poisoning_fails_closed() {
    let reference = build_reference_fixtures();
    let authority_key = PublicKey::from_bytes(reference.authority_public_key);
    let node_key = PublicKey::from_bytes(reference.node_public_key);

    decode_and_validate_request(
        &reference.request,
        RequestValidationContext {
            method: "POST",
            path: ANCHOR_PATH,
            content_type: "application/cbor",
            expected_audience: "crosschecked.production",
            now_ms: 1_800_000_000_000,
            authority_public_key: &authority_key,
        },
    )
    .expect("locked request validates");
    decode_and_validate_response(
        &reference.response,
        ResponseValidationContext {
            expected_request_hash: Hash256::from_bytes(reference.request_hash),
            expected_action_hash: Hash256::from_bytes([0x53; 32]),
            expected_authority_chain_hash: Hash256::from_bytes([0x71; 32]),
            expected_node_did: "did:exo:anchor-node",
            expected_node_key_id: "did:exo:anchor-node#response-2026",
            expected_node_recorded_at: exo_core::types::Timestamp::new(1_800_000_000_123, 7),
            expected_node_public_key: &node_key,
        },
    )
    .expect("locked response validates");

    for index in 0..reference.request.len() {
        let mut poisoned = reference.request.clone();
        poisoned[index] ^= 1;
        assert!(
            decode_and_validate_request(
                &poisoned,
                RequestValidationContext {
                    method: "POST",
                    path: ANCHOR_PATH,
                    content_type: "application/cbor",
                    expected_audience: "crosschecked.production",
                    now_ms: 1_800_000_000_000,
                    authority_public_key: &authority_key,
                },
            )
            .is_err(),
            "poisoned request byte {index} was accepted from {FIXTURE_ROOT}"
        );
    }
    for index in 0..reference.response.len() {
        let mut poisoned = reference.response.clone();
        poisoned[index] ^= 1;
        assert!(
            decode_and_validate_response(
                &poisoned,
                ResponseValidationContext {
                    expected_request_hash: Hash256::from_bytes(reference.request_hash),
                    expected_action_hash: Hash256::from_bytes([0x53; 32]),
                    expected_authority_chain_hash: Hash256::from_bytes([0x71; 32]),
                    expected_node_did: "did:exo:anchor-node",
                    expected_node_key_id: "did:exo:anchor-node#response-2026",
                    expected_node_recorded_at: exo_core::types::Timestamp::new(
                        1_800_000_000_123,
                        7,
                    ),
                    expected_node_public_key: &node_key,
                },
            )
            .is_err(),
            "poisoned response byte {index} was accepted from {FIXTURE_ROOT}"
        );
    }
}
