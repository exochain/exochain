// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Independent literal fixture builder. This module intentionally does not
//! import `exo_api::crosschecked_anchor` or call any production codec method.

use ciborium::Value;
use exo_core::{
    crypto::KeyPair,
    types::{Did, Hash256, ReceiptOutcome, Timestamp, TrustReceipt},
};

pub struct ReferenceFixtures {
    pub request: Vec<u8>,
    pub request_signing_preimage: Vec<u8>,
    pub request_signature: [u8; 64],
    pub request_hash: [u8; 32],
    pub idempotency_key: [u8; 32],
    pub authority_public_key: [u8; 32],
    pub nested_receipt: Vec<u8>,
    pub response: Vec<u8>,
    pub response_signing_preimage: Vec<u8>,
    pub response_signature: [u8; 64],
    pub receipt_actor_public_key: [u8; 32],
    pub node_public_key: [u8; 32],
}

pub fn build_reference_fixtures() -> ReferenceFixtures {
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed authority key");
    let receipt_actor_key =
        KeyPair::from_secret_bytes([0x23; 32]).expect("fixed receipt actor key");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("fixed node key");
    let authority_did = "did:exo:crosschecked-fixture-authority";
    let grant_id = [0x31; 32];
    let scope_alias = [0x42; 32];
    let action_hash = [0x53; 32];
    let idempotency_key = hash(&encode_canonical(Value::Array(vec![
        text("exo.crosschecked.anchor_idempotency.v1"),
        text(authority_did),
        bytes(&grant_id),
        bytes(&scope_alias),
        bytes(&action_hash),
    ])));
    let request_signing_preimage = encode_canonical(Value::Array(vec![
        text("exo.crosschecked.anchor_request.v1"),
        text("POST"),
        text("/api/v1/anchors/crosschecked"),
        unsigned(1),
        text("crosschecked"),
        text("action_receipt_v3"),
        text("crosschecked.production"),
        text(authority_did),
        text("did:exo:crosschecked-fixture-authority#anchor-2026"),
        bytes(&grant_id),
        bytes(&scope_alias),
        text("blake3-256"),
        bytes(&action_hash),
        bytes(&idempotency_key),
        bytes(&[0x64; 32]),
        unsigned(1_800_000_000_000),
        unsigned(1_800_000_300_000),
        text("ed25519"),
    ]));
    let request_signature = *authority_key
        .sign(&request_signing_preimage)
        .ed25519_bytes()
        .expect("Ed25519 signature");
    let request = encode_canonical(map(vec![
        ("protocol_version", unsigned(1)),
        ("source_code", text("crosschecked")),
        ("receipt_format", text("action_receipt_v3")),
        ("audience", text("crosschecked.production")),
        ("authority_did", text(authority_did)),
        (
            "authority_key_id",
            text("did:exo:crosschecked-fixture-authority#anchor-2026"),
        ),
        ("grant_id", bytes(&grant_id)),
        ("scope_alias", bytes(&scope_alias)),
        ("action_hash_algorithm", text("blake3-256")),
        ("action_hash", bytes(&action_hash)),
        ("idempotency_key", bytes(&idempotency_key)),
        ("nonce", bytes(&[0x64; 32])),
        ("issued_at_ms", unsigned(1_800_000_000_000)),
        ("expires_at_ms", unsigned(1_800_000_300_000)),
        ("signature_algorithm", text("ed25519")),
        ("signature", bytes(&request_signature)),
    ]));
    let request_hash = hash(&request);

    let receipt = TrustReceipt::new(
        Did::new("did:exo:receipt-actor").expect("receipt actor DID"),
        Hash256::from_bytes([0x71; 32]),
        Some(Hash256::from_bytes([0x72; 32])),
        "crosschecked.anchor_commitment".to_owned(),
        Hash256::from_bytes(action_hash),
        ReceiptOutcome::Executed,
        Timestamp::new(1_800_000_000_123, 7),
        &|message| receipt_actor_key.sign(message),
    )
    .expect("receipt");
    let receipt_value = anchor_receipt_value(&receipt);
    let nested_receipt = encode_canonical(receipt_value.clone());
    let response_signing_preimage = encode_canonical(Value::Array(vec![
        text("exo.crosschecked.anchor_response.v1"),
        unsigned(1),
        bytes(&request_hash),
        bytes(&action_hash),
        receipt_value.clone(),
        text("node_recorded"),
        text("not_asserted"),
        text("did:exo:anchor-node"),
        text("did:exo:anchor-node#response-2026"),
        hlc(1_800_000_000_123, 7),
    ]));
    let response_signature = *node_key
        .sign(&response_signing_preimage)
        .ed25519_bytes()
        .expect("Ed25519 signature");
    let response = encode_canonical(map(vec![
        ("protocol_version", unsigned(1)),
        ("request_hash", bytes(&request_hash)),
        ("action_hash", bytes(&action_hash)),
        ("exochain_receipt", receipt_value),
        ("recording_status", text("node_recorded")),
        ("consensus_finality", text("not_asserted")),
        ("node_did", text("did:exo:anchor-node")),
        ("node_key_id", text("did:exo:anchor-node#response-2026")),
        ("node_recorded_at", hlc(1_800_000_000_123, 7)),
        ("wrapper_signature", bytes(&response_signature)),
    ]));

    ReferenceFixtures {
        request,
        request_signing_preimage,
        request_signature,
        request_hash,
        idempotency_key,
        authority_public_key: *authority_key.public_key().as_bytes(),
        nested_receipt,
        response,
        response_signing_preimage,
        response_signature,
        receipt_actor_public_key: *receipt_actor_key.public_key().as_bytes(),
        node_public_key: *node_key.public_key().as_bytes(),
    }
}

fn anchor_receipt_value(receipt: &TrustReceipt) -> Value {
    let mut encoded = Vec::new();
    ciborium::into_writer(receipt, &mut encoded).expect("generic receipt serialization");
    let mut value: Value = ciborium::from_reader(encoded.as_slice()).expect("generic receipt");
    let Value::Map(fields) = &mut value else {
        panic!("generic receipt is a map");
    };
    let (_, timestamp) = fields
        .iter_mut()
        .find(|(key, _)| key == &text("timestamp"))
        .expect("receipt timestamp");
    *timestamp = hlc(receipt.timestamp.physical_ms, receipt.timestamp.logical);
    canonicalize(&mut value);
    value
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

fn hlc(physical_ms: u64, logical: u32) -> Value {
    Value::Array(vec![unsigned(physical_ms), unsigned(u64::from(logical))])
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("literal CBOR encoding");
    encoded
}

fn encode_canonical(mut value: Value) -> Vec<u8> {
    canonicalize(&mut value);
    encode(&value)
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Map(entries) => {
            for (key, value) in entries.iter_mut() {
                canonicalize(key);
                canonicalize(value);
            }
            entries.sort_by(|(left, _), (right, _)| {
                let left = encode(left);
                let right = encode(right);
                left.len().cmp(&right.len()).then_with(|| left.cmp(&right))
            });
        }
        _ => {}
    }
}
