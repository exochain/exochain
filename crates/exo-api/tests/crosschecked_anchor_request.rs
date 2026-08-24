// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ciborium::Value;
use exo_api::crosschecked_anchor::{
    ANCHOR_PATH, AnchorCodecError, CrossCheckedAnchorRequestV1, MAX_REQUEST_BODY_BYTES,
    RequestValidationContext, decode_and_validate_request, decode_unverified_replay_locator,
    validate_preferred_cbor,
};
use exo_core::{crypto::KeyPair, types::Hash256};

type RequestMutation = Box<dyn Fn(&mut CrossCheckedAnchorRequestV1)>;

fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("literal CBOR encodes");
    encoded
}

fn bytes32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn independently_derive_idempotency(
    authority_did: &str,
    grant_id: [u8; 32],
    scope_alias: [u8; 32],
    action_hash: [u8; 32],
) -> [u8; 32] {
    let bytes = encode(&Value::Array(vec![
        Value::Text("exo.crosschecked.anchor_idempotency.v1".to_owned()),
        Value::Text(authority_did.to_owned()),
        Value::Bytes(grant_id.to_vec()),
        Value::Bytes(scope_alias.to_vec()),
        Value::Bytes(action_hash.to_vec()),
    ]));
    *blake3::hash(&bytes).as_bytes()
}

fn unsigned_request() -> CrossCheckedAnchorRequestV1 {
    let authority_did = "did:exo:crosschecked-fixture-authority".to_owned();
    let grant_id = bytes32(0x31);
    let scope_alias = bytes32(0x42);
    let action_hash = bytes32(0x53);
    CrossCheckedAnchorRequestV1 {
        protocol_version: 1,
        source_code: "crosschecked".to_owned(),
        receipt_format: "action_receipt_v3".to_owned(),
        audience: "crosschecked.production".to_owned(),
        authority_key_id: format!("{authority_did}#anchor-2026"),
        authority_did: authority_did.clone(),
        grant_id,
        scope_alias,
        action_hash_algorithm: "blake3-256".to_owned(),
        action_hash,
        idempotency_key: independently_derive_idempotency(
            &authority_did,
            grant_id,
            scope_alias,
            action_hash,
        ),
        nonce: bytes32(0x64),
        issued_at_ms: 1_800_000_000_000,
        expires_at_ms: 1_800_000_300_000,
        signature_algorithm: "ed25519".to_owned(),
        signature: [0; 64],
    }
}

fn sign_request(request: &mut CrossCheckedAnchorRequestV1, key: &KeyPair) {
    request.signature = *key
        .sign(&request.signing_preimage().expect("signing preimage"))
        .ed25519_bytes()
        .expect("Ed25519 signature");
}

fn context<'a>(key: &'a KeyPair, now_ms: u64) -> RequestValidationContext<'a> {
    RequestValidationContext {
        method: "POST",
        path: ANCHOR_PATH,
        content_type: "application/cbor",
        expected_audience: "crosschecked.production",
        now_ms,
        authority_public_key: key.public_key(),
    }
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

fn signed_body(request: &mut CrossCheckedAnchorRequestV1, key: &KeyPair) -> Vec<u8> {
    sign_request(request, key);
    request.to_canonical_cbor().expect("request body")
}

fn assert_rejected_after_resigning(
    mut request: CrossCheckedAnchorRequestV1,
    key: &KeyPair,
    now_ms: u64,
) {
    let body = signed_body(&mut request, key);
    assert!(decode_and_validate_request(&body, context(key, now_ms)).is_err());
}

fn refresh_idempotency(request: &mut CrossCheckedAnchorRequestV1) {
    request.idempotency_key = independently_derive_idempotency(
        &request.authority_did,
        request.grant_id,
        request.scope_alias,
        request.action_hash,
    );
}

#[test]
fn exact_request_preimage_and_complete_body_hash_are_verified() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let mut request = unsigned_request();
    let expected_preimage = encode(&Value::Array(vec![
        Value::Text("exo.crosschecked.anchor_request.v1".to_owned()),
        Value::Text("POST".to_owned()),
        Value::Text(ANCHOR_PATH.to_owned()),
        Value::Integer(1.into()),
        Value::Text("crosschecked".to_owned()),
        Value::Text("action_receipt_v3".to_owned()),
        Value::Text("crosschecked.production".to_owned()),
        Value::Text("did:exo:crosschecked-fixture-authority".to_owned()),
        Value::Text("did:exo:crosschecked-fixture-authority#anchor-2026".to_owned()),
        Value::Bytes(bytes32(0x31).to_vec()),
        Value::Bytes(bytes32(0x42).to_vec()),
        Value::Text("blake3-256".to_owned()),
        Value::Bytes(bytes32(0x53).to_vec()),
        Value::Bytes(request.idempotency_key.to_vec()),
        Value::Bytes(bytes32(0x64).to_vec()),
        Value::Integer(1_800_000_000_000_u64.into()),
        Value::Integer(1_800_000_300_000_u64.into()),
        Value::Text("ed25519".to_owned()),
    ]));

    assert_eq!(
        request.signing_preimage().expect("preimage"),
        expected_preimage
    );
    sign_request(&mut request, &key);

    let body = request.to_canonical_cbor().expect("canonical request");
    assert!(body.len() <= MAX_REQUEST_BODY_BYTES);
    let validated = decode_and_validate_request(
        &body,
        RequestValidationContext {
            method: "POST",
            path: ANCHOR_PATH,
            content_type: "application/cbor",
            expected_audience: "crosschecked.production",
            now_ms: 1_800_000_000_000,
            authority_public_key: key.public_key(),
        },
    )
    .expect("valid signed request");

    assert_eq!(validated.request, request);
    assert_eq!(validated.canonical_body, body);
    assert_eq!(validated.request_hash, Hash256::digest(&body));
}

#[test]
fn replay_locator_parses_only_a_canonical_static_request_without_authorizing_it() {
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let wrong_key = KeyPair::from_secret_bytes([0x18; 32]).expect("wrong key");
    let mut request = unsigned_request();
    sign_request(&mut request, &wrong_key);
    let body = request.to_canonical_cbor().expect("canonical body");

    let locator = decode_unverified_replay_locator(&body, "POST", ANCHOR_PATH, "application/cbor")
        .expect("canonical static envelope can be located after expiry");

    assert_eq!(locator.source_code, "crosschecked");
    assert_eq!(locator.authority_did, request.authority_did);
    assert_eq!(locator.authority_key_id, request.authority_key_id);
    assert_eq!(locator.idempotency_key, request.idempotency_key);
    assert_eq!(locator.action_hash, request.action_hash);
    assert_eq!(locator.request_hash, Hash256::digest(&body));
    assert_eq!(locator.issued_at_ms, request.issued_at_ms);
    assert_eq!(locator.expires_at_ms, request.expires_at_ms);

    assert_eq!(
        decode_and_validate_request(
            &body,
            context(&authority_key, request.expires_at_ms.saturating_add(1))
        ),
        Err(AnchorCodecError::InvalidValidity),
        "the unverified locator must not be confused with live authorization"
    );
}

#[test]
fn replay_locator_rejects_noncanonical_or_statically_invalid_requests() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let mut request = unsigned_request();
    request.idempotency_key[0] ^= 1;
    let body = signed_body(&mut request, &key);
    assert_eq!(
        decode_unverified_replay_locator(&body, "POST", ANCHOR_PATH, "application/cbor"),
        Err(AnchorCodecError::IdempotencyMismatch)
    );

    let mut request = unsigned_request();
    let body = signed_body(&mut request, &key);
    assert_eq!(
        decode_unverified_replay_locator(&body, "GET", ANCHOR_PATH, "application/cbor"),
        Err(AnchorCodecError::InvalidContext("method"))
    );

    let mut trailing = body;
    trailing.push(0);
    assert!(
        decode_unverified_replay_locator(&trailing, "POST", ANCHOR_PATH, "application/cbor")
            .is_err()
    );
}

#[test]
fn every_request_field_is_closed_and_validated_independently_of_signature() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let now = 1_800_000_000_000;

    let mut mutations: Vec<RequestMutation> = vec![
        Box::new(|request| request.protocol_version = 2),
        Box::new(|request| request.source_code = "other".to_owned()),
        Box::new(|request| request.receipt_format = "action_receipt_v2".to_owned()),
        Box::new(|request| request.audience = "UPPERCASE".to_owned()),
        Box::new(|request| request.authority_did = "did:web:invalid".to_owned()),
        Box::new(|request| request.authority_key_id.push('!')),
        Box::new(|request| request.grant_id = [0; 32]),
        Box::new(|request| request.scope_alias = [0; 32]),
        Box::new(|request| request.action_hash_algorithm = "sha256".to_owned()),
        Box::new(|request| request.action_hash = [0; 32]),
        Box::new(|request| request.idempotency_key[0] ^= 1),
        Box::new(|request| request.nonce = [0; 32]),
        Box::new(move |request| {
            request.issued_at_ms = now + 60_001;
            request.expires_at_ms = request.issued_at_ms + 1;
        }),
        Box::new(|request| request.expires_at_ms = request.issued_at_ms),
        Box::new(|request| request.signature_algorithm = "other".to_owned()),
    ];

    for mutate in mutations.drain(..) {
        let mut request = unsigned_request();
        mutate(&mut request);
        assert_rejected_after_resigning(request, &key, now);
    }

    let mut request = unsigned_request();
    let body = signed_body(&mut request, &key);
    let mut value: Value = ciborium::from_reader(body.as_slice()).expect("request map");
    let Value::Map(entries) = &mut value else {
        panic!("request is a map");
    };
    let (_, Value::Bytes(signature)) = entries
        .iter_mut()
        .find(|(field, _)| field == &Value::Text("signature".to_owned()))
        .expect("signature field")
    else {
        panic!("signature is bytes");
    };
    signature[0] ^= 1;
    let body = encode_canonical(value);
    assert_eq!(
        decode_and_validate_request(&body, context(&key, now)),
        Err(AnchorCodecError::InvalidSignature)
    );
}

#[test]
fn request_time_and_body_boundaries_are_exact() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let now = 1_800_000_000_000;

    let mut request = unsigned_request();
    request.issued_at_ms = now + 60_000;
    request.expires_at_ms = request.issued_at_ms + 300_000;
    let body = signed_body(&mut request, &key);
    decode_and_validate_request(&body, context(&key, now)).expect("inclusive boundaries");

    let mut request = unsigned_request();
    request.issued_at_ms = now + 60_001;
    request.expires_at_ms = request.issued_at_ms + 300_000;
    assert_rejected_after_resigning(request, &key, now);

    let mut request = unsigned_request();
    request.expires_at_ms = request.issued_at_ms + 300_001;
    assert_rejected_after_resigning(request, &key, now);

    assert_ne!(
        decode_and_validate_request(&vec![0; MAX_REQUEST_BODY_BYTES], context(&key, now)),
        Err(AnchorCodecError::InvalidBodyLength)
    );
    assert_eq!(
        decode_and_validate_request(&vec![0; MAX_REQUEST_BODY_BYTES + 1], context(&key, now)),
        Err(AnchorCodecError::InvalidBodyLength)
    );
}

#[test]
fn transport_binding_is_exact() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let now = 1_800_000_000_000;
    let mut request = unsigned_request();
    let body = signed_body(&mut request, &key);

    for invalid in [
        RequestValidationContext {
            method: "GET",
            ..context(&key, now)
        },
        RequestValidationContext {
            path: "/api/v1/anchors/crosschecked/",
            ..context(&key, now)
        },
        RequestValidationContext {
            content_type: "application/cbor; charset=utf-8",
            ..context(&key, now)
        },
        RequestValidationContext {
            expected_audience: "crosschecked.staging",
            ..context(&key, now)
        },
    ] {
        assert!(decode_and_validate_request(&body, invalid).is_err());
    }
}

#[test]
fn request_map_rejects_missing_unknown_nontext_and_wrong_types() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let now = 1_800_000_000_000;
    let mut request = unsigned_request();
    let body = signed_body(&mut request, &key);
    let Value::Map(entries) =
        ciborium::from_reader::<Value, _>(body.as_slice()).expect("decode baseline")
    else {
        panic!("request is a map");
    };

    let mut missing = entries.clone();
    missing.pop();
    let missing = encode_canonical(Value::Map(missing));
    assert!(decode_and_validate_request(&missing, context(&key, now)).is_err());

    let mut unknown = entries.clone();
    let (_, value) = unknown.pop().expect("one field");
    unknown.push((Value::Text("unknown".to_owned()), value));
    let unknown = encode_canonical(Value::Map(unknown));
    assert!(decode_and_validate_request(&unknown, context(&key, now)).is_err());

    let mut nontext = entries.clone();
    nontext[0].0 = Value::Integer(7.into());
    let nontext = encode_canonical(Value::Map(nontext));
    assert!(decode_and_validate_request(&nontext, context(&key, now)).is_err());

    for field in [
        "protocol_version",
        "source_code",
        "receipt_format",
        "audience",
        "authority_did",
        "authority_key_id",
        "grant_id",
        "scope_alias",
        "action_hash_algorithm",
        "action_hash",
        "idempotency_key",
        "nonce",
        "issued_at_ms",
        "expires_at_ms",
        "signature_algorithm",
        "signature",
    ] {
        let mut wrong = entries.clone();
        let (_, value) = wrong
            .iter_mut()
            .find(|(key, _)| key == &Value::Text(field.to_owned()))
            .expect("field exists");
        *value = Value::Null;
        let wrong = encode_canonical(Value::Map(wrong));
        assert!(decode_and_validate_request(&wrong, context(&key, now)).is_err());
    }
}

#[test]
fn audience_did_and_key_id_length_boundaries_are_exact() {
    let key = KeyPair::from_secret_bytes([0x17; 32]).expect("fixed key");
    let now = 1_800_000_000_000;

    let mut request = unsigned_request();
    request.audience = "a".repeat(128);
    let expected_audience = request.audience.clone();
    let body = signed_body(&mut request, &key);
    decode_and_validate_request(
        &body,
        RequestValidationContext {
            expected_audience: &expected_audience,
            ..context(&key, now)
        },
    )
    .expect("128-byte audience");

    let mut request = unsigned_request();
    request.audience = "a".repeat(129);
    let expected_audience = request.audience.clone();
    let body = signed_body(&mut request, &key);
    assert!(
        decode_and_validate_request(
            &body,
            RequestValidationContext {
                expected_audience: &expected_audience,
                ..context(&key, now)
            }
        )
        .is_err()
    );

    let mut request = unsigned_request();
    request.authority_did = format!("did:exo:{}", "a".repeat(248));
    request.authority_key_id = format!("{}#{}", request.authority_did, "z".repeat(64));
    refresh_idempotency(&mut request);
    let body = signed_body(&mut request, &key);
    decode_and_validate_request(&body, context(&key, now))
        .expect("256-byte DID and 64-byte key fragment");

    let mut request = unsigned_request();
    request.authority_did = format!("did:exo:{}", "a".repeat(249));
    request.authority_key_id = format!("{}#key", request.authority_did);
    refresh_idempotency(&mut request);
    assert_rejected_after_resigning(request, &key, now);

    let mut request = unsigned_request();
    request.authority_key_id = format!("{}#{}", request.authority_did, "z".repeat(65));
    assert_rejected_after_resigning(request, &key, now);
}

#[test]
fn deterministic_cbor_validator_rejects_all_ambiguous_forms() {
    for valid in [
        vec![0x00],
        vec![0x17],
        vec![0x18, 0x18],
        vec![0x82, 0x01, 0x02],
        vec![0xa2, 0x61, b'a', 0x01, 0x61, b'b', 0x02],
    ] {
        validate_preferred_cbor(&valid).expect("preferred CBOR");
    }

    let mut depth_33 = vec![0x81; 33];
    depth_33.push(0x00);
    let invalid = [
        vec![],
        vec![0x00, 0x00],
        vec![0x18, 0x01],
        vec![0x19, 0x00, 0xff],
        vec![0x1a, 0x00, 0x00, 0xff, 0xff],
        vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
        vec![0x5f, 0xff],
        vec![0x9f, 0xff],
        vec![0xc0, 0xf6],
        vec![0xf7],
        vec![0xf8, 0x14],
        vec![0xf9, 0x00, 0x00],
        vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02],
        vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
        vec![0x61, 0xff],
        vec![0x58],
        depth_33,
    ];
    for bytes in invalid {
        assert!(
            validate_preferred_cbor(&bytes).is_err(),
            "accepted {bytes:02x?}"
        );
    }
}
