// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ciborium::Value;
use exo_api::crosschecked_anchor::{
    AnchorCodecError, CrossCheckedAnchorResponseV1, MAX_RESPONSE_BODY_BYTES,
    ResponseValidationContext, decode_and_validate_response,
};
use exo_core::{
    crypto::KeyPair,
    types::{Did, Hash256, ReceiptOutcome, Timestamp, TrustReceipt},
};

const NODE_DID: &str = "did:exo:anchor-node";
const NODE_KEY_ID: &str = "did:exo:anchor-node#response-2026";

fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("literal CBOR encodes");
    encoded
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

fn encode_canonical(mut value: Value) -> Vec<u8> {
    canonicalize(&mut value);
    encode(&value)
}

fn fixture_receipt(node_key: &KeyPair) -> TrustReceipt {
    TrustReceipt::new(
        Did::new(NODE_DID).expect("DID"),
        Hash256::from_bytes([0x71; 32]),
        None,
        "crosschecked.receipt_commitment.record.v1".to_owned(),
        Hash256::from_bytes([0x53; 32]),
        ReceiptOutcome::Executed,
        Timestamp::new(1_800_000_000_123, 7),
        &|message| node_key.sign(message),
    )
    .expect("receipt")
}

fn independent_anchor_receipt_value(receipt: &TrustReceipt) -> Value {
    let mut generic = Vec::new();
    ciborium::into_writer(receipt, &mut generic).expect("generic receipt CBOR");
    let mut value: Value = ciborium::from_reader(generic.as_slice()).expect("receipt value");
    let Value::Map(fields) = &mut value else {
        panic!("receipt is a map");
    };
    let (_, timestamp) = fields
        .iter_mut()
        .find(|(key, _)| key == &Value::Text("timestamp".to_owned()))
        .expect("timestamp field");
    *timestamp = Value::Array(vec![
        Value::Integer(receipt.timestamp.physical_ms.into()),
        Value::Integer(receipt.timestamp.logical.into()),
    ]);
    canonicalize(&mut value);
    value
}

fn unsigned_response(node_key: &KeyPair) -> CrossCheckedAnchorResponseV1 {
    CrossCheckedAnchorResponseV1 {
        protocol_version: 1,
        request_hash: Hash256::from_bytes([0x81; 32]),
        action_hash: Hash256::from_bytes([0x53; 32]),
        exochain_receipt: fixture_receipt(node_key),
        recording_status: "node_recorded".to_owned(),
        consensus_finality: "not_asserted".to_owned(),
        node_did: "did:exo:anchor-node".to_owned(),
        node_key_id: "did:exo:anchor-node#response-2026".to_owned(),
        node_recorded_at: Timestamp::new(1_800_000_000_123, 7),
        wrapper_signature: [0; 64],
    }
}

fn sign_response(response: &mut CrossCheckedAnchorResponseV1, node_key: &KeyPair) {
    response.wrapper_signature = *node_key
        .sign(&response.signing_preimage().expect("wrapper preimage"))
        .ed25519_bytes()
        .expect("Ed25519 signature");
}

fn semantic_receipt(
    actor_key: &KeyPair,
    actor_did: &str,
    action_type: &str,
    outcome: ReceiptOutcome,
    consent_reference: Option<Hash256>,
    challenge_reference: Option<Hash256>,
) -> TrustReceipt {
    let mut receipt = TrustReceipt::new(
        Did::new(actor_did).expect("semantic poison DID"),
        Hash256::from_bytes([0x71; 32]),
        consent_reference,
        action_type.to_owned(),
        Hash256::from_bytes([0x53; 32]),
        outcome,
        Timestamp::new(1_800_000_000_123, 7),
        &|message| actor_key.sign(message),
    )
    .expect("semantic poison receipt");
    receipt.challenge_reference = challenge_reference;
    receipt
}

fn closed_receipt(
    node_key: &KeyPair,
    node_did: &str,
    authority_chain_hash: Hash256,
    timestamp: Timestamp,
) -> TrustReceipt {
    TrustReceipt::new(
        Did::new(node_did).expect("node DID"),
        authority_chain_hash,
        None,
        "crosschecked.receipt_commitment.record.v1".to_owned(),
        Hash256::from_bytes([0x53; 32]),
        ReceiptOutcome::Executed,
        timestamp,
        &|message| node_key.sign(message),
    )
    .expect("closed node receipt")
}

fn semantic_poison_is_accepted(
    node_key: &KeyPair,
    receipt: TrustReceipt,
    node_did: &str,
    node_key_id: &str,
) -> bool {
    let mut response = CrossCheckedAnchorResponseV1 {
        protocol_version: 1,
        request_hash: Hash256::from_bytes([0x81; 32]),
        action_hash: Hash256::from_bytes([0x53; 32]),
        exochain_receipt: receipt,
        recording_status: "node_recorded".to_owned(),
        consensus_finality: "not_asserted".to_owned(),
        node_did: node_did.to_owned(),
        node_key_id: node_key_id.to_owned(),
        node_recorded_at: Timestamp::new(1_800_000_000_123, 7),
        wrapper_signature: [0; 64],
    };
    sign_response(&mut response, node_key);
    let body = response.to_canonical_cbor().expect("semantic poison body");
    decode_and_validate_response(
        &body,
        ResponseValidationContext {
            expected_request_hash: Hash256::from_bytes([0x81; 32]),
            expected_action_hash: Hash256::from_bytes([0x53; 32]),
            expected_authority_chain_hash: Hash256::from_bytes([0x71; 32]),
            expected_node_did: NODE_DID,
            expected_node_key_id: NODE_KEY_ID,
            expected_node_recorded_at: Timestamp::new(1_800_000_000_123, 7),
            expected_node_public_key: node_key.public_key(),
        },
    )
    .is_ok()
}

fn context(node_key: &KeyPair) -> ResponseValidationContext<'_> {
    ResponseValidationContext {
        expected_request_hash: Hash256::from_bytes([0x81; 32]),
        expected_action_hash: Hash256::from_bytes([0x53; 32]),
        expected_authority_chain_hash: Hash256::from_bytes([0x71; 32]),
        expected_node_did: NODE_DID,
        expected_node_key_id: NODE_KEY_ID,
        expected_node_recorded_at: Timestamp::new(1_800_000_000_123, 7),
        expected_node_public_key: node_key.public_key(),
    }
}

fn signed_body(response: &mut CrossCheckedAnchorResponseV1, node_key: &KeyPair) -> Vec<u8> {
    sign_response(response, node_key);
    response.to_canonical_cbor().expect("response body")
}

#[test]
fn exact_response_preimage_nested_receipt_and_signatures_are_verified() {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("fixed node key");
    let mut response = unsigned_response(&node_key);
    let receipt_value = independent_anchor_receipt_value(&response.exochain_receipt);
    let timestamp = Value::Array(vec![
        Value::Integer(1_800_000_000_123_u64.into()),
        Value::Integer(7_u64.into()),
    ]);
    let expected_preimage = encode_canonical(Value::Array(vec![
        Value::Text("exo.crosschecked.anchor_response.v1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes([0x81; 32].to_vec()),
        Value::Bytes([0x53; 32].to_vec()),
        receipt_value,
        Value::Text("node_recorded".to_owned()),
        Value::Text("not_asserted".to_owned()),
        Value::Text("did:exo:anchor-node".to_owned()),
        Value::Text("did:exo:anchor-node#response-2026".to_owned()),
        timestamp,
    ]));
    assert_eq!(
        response.signing_preimage().expect("preimage"),
        expected_preimage
    );
    sign_response(&mut response, &node_key);

    let body = response.to_canonical_cbor().expect("response CBOR");
    let validated =
        decode_and_validate_response(&body, context(&node_key)).expect("valid response");

    assert_eq!(validated.response, response);
    assert_eq!(validated.canonical_body, body);
}

#[test]
fn every_response_field_and_both_signatures_are_closed() {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("fixed node key");

    let mut responses = Vec::new();
    let mut response = unsigned_response(&node_key);
    response.protocol_version = 2;
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.request_hash = Hash256::from_bytes([0x82; 32]);
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.action_hash = Hash256::from_bytes([0x54; 32]);
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.exochain_receipt.receipt_hash = Hash256::from_bytes([0x91; 32]);
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.recording_status = "consensus_recorded".to_owned();
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.consensus_finality = "asserted".to_owned();
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.node_did = "did:web:invalid".to_owned();
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.node_key_id.push('!');
    responses.push(response);
    let mut response = unsigned_response(&node_key);
    response.node_recorded_at.logical += 1;
    responses.push(response);

    for mut response in responses {
        let body = signed_body(&mut response, &node_key);
        assert!(decode_and_validate_response(&body, context(&node_key)).is_err());
    }

    let mut response = unsigned_response(&node_key);
    let mut body_value: Value =
        ciborium::from_reader(signed_body(&mut response, &node_key).as_slice())
            .expect("response map");
    let Value::Map(fields) = &mut body_value else {
        panic!("response is a map");
    };
    let (_, Value::Bytes(signature)) = fields
        .iter_mut()
        .find(|(key, _)| key == &Value::Text("wrapper_signature".to_owned()))
        .expect("wrapper signature")
    else {
        panic!("wrapper signature is bytes");
    };
    signature[0] ^= 1;
    let body = encode_canonical(body_value);
    assert_eq!(
        decode_and_validate_response(&body, context(&node_key)),
        Err(AnchorCodecError::InvalidSignature)
    );

    let wrong_node = KeyPair::from_secret_bytes([0x24; 32]).expect("wrong node key");
    let mut response = unsigned_response(&node_key);
    let body = signed_body(&mut response, &node_key);
    assert_eq!(
        decode_and_validate_response(
            &body,
            ResponseValidationContext {
                expected_node_public_key: wrong_node.public_key(),
                ..context(&node_key)
            }
        ),
        Err(AnchorCodecError::InvalidReceipt)
    );

    let wrong_wrapper_signer =
        KeyPair::from_secret_bytes([0x25; 32]).expect("wrong wrapper signer");
    let mut response = unsigned_response(&node_key);
    let body = signed_body(&mut response, &wrong_wrapper_signer);
    assert_eq!(
        decode_and_validate_response(&body, context(&node_key)),
        Err(AnchorCodecError::InvalidSignature)
    );
}

#[test]
fn reviewer_semantic_poisons_fail_closed_after_rehash_and_resign() {
    let actor_key = KeyPair::from_secret_bytes([0x23; 32]).expect("actor key");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let cases = [
        (
            "actor_did_not_node_did_and_receipt_signed_by_other_role",
            semantic_receipt(
                &actor_key,
                "did:exo:receipt-actor",
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                None,
                None,
            ),
            NODE_DID,
            NODE_KEY_ID,
        ),
        (
            "wrong_action_type",
            semantic_receipt(
                &actor_key,
                "did:exo:receipt-actor",
                "crosschecked.anchor_commitment",
                ReceiptOutcome::Executed,
                None,
                None,
            ),
            NODE_DID,
            NODE_KEY_ID,
        ),
        (
            "denied_outcome",
            semantic_receipt(
                &actor_key,
                "did:exo:receipt-actor",
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Denied,
                None,
                None,
            ),
            NODE_DID,
            NODE_KEY_ID,
        ),
        (
            "consent_reference_present",
            semantic_receipt(
                &actor_key,
                "did:exo:receipt-actor",
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                Some(Hash256::from_bytes([0xa1; 32])),
                None,
            ),
            NODE_DID,
            NODE_KEY_ID,
        ),
        (
            "challenge_reference_present",
            semantic_receipt(
                &actor_key,
                "did:exo:receipt-actor",
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                None,
                Some(Hash256::from_bytes([0xa2; 32])),
            ),
            NODE_DID,
            NODE_KEY_ID,
        ),
        (
            "unbound_node_identity_and_key_id",
            semantic_receipt(
                &actor_key,
                "did:exo:receipt-actor",
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                None,
                None,
            ),
            "did:exo:other-node",
            "did:exo:other-node#untrusted-label",
        ),
    ];

    for (name, receipt, node_did, node_key_id) in cases {
        assert!(
            !semantic_poison_is_accepted(&node_key, receipt, node_did, node_key_id,),
            "accepted reviewed semantic poison: {name}"
        );
    }
}

#[test]
fn each_receipt_semantic_field_fails_independently_with_node_identity_and_key() {
    let other_role_key = KeyPair::from_secret_bytes([0x23; 32]).expect("other role key");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let cases = [
        (
            "actor_did_not_node_did",
            semantic_receipt(
                &node_key,
                "did:exo:other-actor",
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                None,
                None,
            ),
        ),
        (
            "receipt_signed_by_other_role",
            semantic_receipt(
                &other_role_key,
                NODE_DID,
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                None,
                None,
            ),
        ),
        (
            "wrong_action_type",
            semantic_receipt(
                &node_key,
                NODE_DID,
                "crosschecked.anchor_commitment",
                ReceiptOutcome::Executed,
                None,
                None,
            ),
        ),
        (
            "denied_outcome",
            semantic_receipt(
                &node_key,
                NODE_DID,
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Denied,
                None,
                None,
            ),
        ),
        (
            "consent_reference_present",
            semantic_receipt(
                &node_key,
                NODE_DID,
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                Some(Hash256::from_bytes([0xa1; 32])),
                None,
            ),
        ),
        (
            "challenge_reference_present",
            semantic_receipt(
                &node_key,
                NODE_DID,
                "crosschecked.receipt_commitment.record.v1",
                ReceiptOutcome::Executed,
                None,
                Some(Hash256::from_bytes([0xa2; 32])),
            ),
        ),
    ];

    for (name, receipt) in cases {
        assert!(
            !semantic_poison_is_accepted(&node_key, receipt, NODE_DID, NODE_KEY_ID),
            "accepted independently isolated semantic poison: {name}"
        );
    }
}

#[test]
fn pinned_node_chain_and_timestamp_substitutions_fail_closed_after_resign() {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let expected_timestamp = Timestamp::new(1_800_000_000_123, 7);
    let cases = [
        (
            "unpinned_node_did",
            closed_receipt(
                &node_key,
                "did:exo:other-node",
                Hash256::from_bytes([0x71; 32]),
                expected_timestamp,
            ),
            "did:exo:other-node",
            "did:exo:other-node#response-2026",
            expected_timestamp,
        ),
        (
            "unpinned_node_key_id",
            closed_receipt(
                &node_key,
                NODE_DID,
                Hash256::from_bytes([0x71; 32]),
                expected_timestamp,
            ),
            NODE_DID,
            "did:exo:anchor-node#alternate-label",
            expected_timestamp,
        ),
        (
            "wrong_authority_chain",
            closed_receipt(
                &node_key,
                NODE_DID,
                Hash256::from_bytes([0x72; 32]),
                expected_timestamp,
            ),
            NODE_DID,
            NODE_KEY_ID,
            expected_timestamp,
        ),
        (
            "unexpected_timestamp",
            closed_receipt(
                &node_key,
                NODE_DID,
                Hash256::from_bytes([0x71; 32]),
                Timestamp::new(1_800_000_000_124, 0),
            ),
            NODE_DID,
            NODE_KEY_ID,
            Timestamp::new(1_800_000_000_124, 0),
        ),
    ];

    for (name, receipt, node_did, node_key_id, node_recorded_at) in cases {
        let mut response = CrossCheckedAnchorResponseV1 {
            protocol_version: 1,
            request_hash: Hash256::from_bytes([0x81; 32]),
            action_hash: Hash256::from_bytes([0x53; 32]),
            exochain_receipt: receipt,
            recording_status: "node_recorded".to_owned(),
            consensus_finality: "not_asserted".to_owned(),
            node_did: node_did.to_owned(),
            node_key_id: node_key_id.to_owned(),
            node_recorded_at,
            wrapper_signature: [0; 64],
        };
        let body = signed_body(&mut response, &node_key);
        assert!(
            decode_and_validate_response(&body, context(&node_key)).is_err(),
            "accepted independently resigned binding poison: {name}"
        );
    }
}

#[test]
fn response_wire_has_no_algorithm_alias_and_both_timestamps_are_hlc_arrays() {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("fixed node key");
    let mut response = unsigned_response(&node_key);
    let body = signed_body(&mut response, &node_key);
    let Value::Map(fields) =
        ciborium::from_reader::<Value, _>(body.as_slice()).expect("response map")
    else {
        panic!("response is a map");
    };
    assert_eq!(fields.len(), 10);
    assert!(
        !fields
            .iter()
            .any(|(key, _)| key == &Value::Text("signature_algorithm".to_owned()))
    );
    assert!(matches!(
        fields
            .iter()
            .find(|(key, _)| key == &Value::Text("node_recorded_at".to_owned()))
            .map(|(_, value)| value),
        Some(Value::Array(parts)) if parts.len() == 2
    ));
    let nested = fields
        .iter()
        .find(|(key, _)| key == &Value::Text("exochain_receipt".to_owned()))
        .map(|(_, value)| value)
        .expect("nested receipt");
    let Value::Map(receipt_fields) = nested else {
        panic!("nested receipt map");
    };
    assert!(matches!(
        receipt_fields
            .iter()
            .find(|(key, _)| key == &Value::Text("timestamp".to_owned()))
            .map(|(_, value)| value),
        Some(Value::Array(parts)) if parts.len() == 2
    ));
}

#[test]
fn response_rejects_map_shape_type_hlc_and_size_mutations() {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("fixed node key");
    let mut response = unsigned_response(&node_key);
    let body = signed_body(&mut response, &node_key);
    let Value::Map(entries) =
        ciborium::from_reader::<Value, _>(body.as_slice()).expect("response map")
    else {
        panic!("response is a map");
    };

    let mut missing = entries.clone();
    missing.pop();
    let missing = encode_canonical(Value::Map(missing));
    assert!(decode_and_validate_response(&missing, context(&node_key)).is_err());

    let mut extra = entries.clone();
    extra.push((
        Value::Text("signature_algorithm".to_owned()),
        Value::Text("ed25519".to_owned()),
    ));
    let extra = encode_canonical(Value::Map(extra));
    assert!(decode_and_validate_response(&extra, context(&node_key)).is_err());

    for field in [
        "protocol_version",
        "request_hash",
        "action_hash",
        "exochain_receipt",
        "recording_status",
        "consensus_finality",
        "node_did",
        "node_key_id",
        "node_recorded_at",
        "wrapper_signature",
    ] {
        let mut wrong = entries.clone();
        let (_, value) = wrong
            .iter_mut()
            .find(|(key, _)| key == &Value::Text(field.to_owned()))
            .expect("field");
        *value = Value::Null;
        let wrong = encode_canonical(Value::Map(wrong));
        assert!(decode_and_validate_response(&wrong, context(&node_key)).is_err());
    }

    let mut nested_map_timestamp = entries.clone();
    let (_, Value::Map(receipt)) = nested_map_timestamp
        .iter_mut()
        .find(|(key, _)| key == &Value::Text("exochain_receipt".to_owned()))
        .expect("receipt")
    else {
        panic!("receipt map");
    };
    let (_, timestamp) = receipt
        .iter_mut()
        .find(|(key, _)| key == &Value::Text("timestamp".to_owned()))
        .expect("timestamp");
    *timestamp = Value::Map(vec![
        (
            Value::Text("physical_ms".to_owned()),
            Value::Integer(1_800_000_000_123_u64.into()),
        ),
        (Value::Text("logical".to_owned()), Value::Integer(7.into())),
    ]);
    let nested_map_timestamp = encode_canonical(Value::Map(nested_map_timestamp));
    assert!(decode_and_validate_response(&nested_map_timestamp, context(&node_key)).is_err());

    let mut overflowing_hlc = entries.clone();
    let (_, timestamp) = overflowing_hlc
        .iter_mut()
        .find(|(key, _)| key == &Value::Text("node_recorded_at".to_owned()))
        .expect("node HLC");
    *timestamp = Value::Array(vec![
        Value::Integer(1_800_000_000_123_u64.into()),
        Value::Integer((u64::from(u32::MAX) + 1).into()),
    ]);
    let overflowing_hlc = encode_canonical(Value::Map(overflowing_hlc));
    assert!(decode_and_validate_response(&overflowing_hlc, context(&node_key)).is_err());

    assert_ne!(
        decode_and_validate_response(&vec![0; MAX_RESPONSE_BODY_BYTES], context(&node_key)),
        Err(AnchorCodecError::InvalidBodyLength)
    );
    assert_eq!(
        decode_and_validate_response(&vec![0; MAX_RESPONSE_BODY_BYTES + 1], context(&node_key)),
        Err(AnchorCodecError::InvalidBodyLength)
    );
}
