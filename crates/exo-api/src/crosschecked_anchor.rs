// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Commitment-only CrossChecked anchor wire types.
//!
//! This module deliberately contains no HTTP listener, route registration,
//! persistence, signer custody, or authority construction. It only validates
//! and encodes protocol bytes for a caller that already possesses an
//! independently authorized verification key.

use std::{cmp::Ordering, collections::BTreeMap};

use ciborium::Value;
use exo_core::{
    crypto,
    types::{Did, Hash256, PublicKey, Signature, Timestamp, TrustReceipt},
};
use thiserror::Error;

/// Exact commitment-only anchor path.
pub const ANCHOR_PATH: &str = "/api/v1/anchors/crosschecked";
/// Maximum accepted request body size.
pub const MAX_REQUEST_BODY_BYTES: usize = 8_192;
/// Maximum permitted request issue-time skew into the future.
pub const MAX_FUTURE_SKEW_MS: u64 = 60_000;
/// Maximum positive request validity interval.
pub const MAX_VALIDITY_MS: u64 = 300_000;
/// Maximum accepted encoded response size.
pub const MAX_RESPONSE_BODY_BYTES: usize = 65_536;

const REQUEST_DOMAIN: &str = "exo.crosschecked.anchor_request.v1";
const IDEMPOTENCY_DOMAIN: &str = "exo.crosschecked.anchor_idempotency.v1";
const RESPONSE_DOMAIN: &str = "exo.crosschecked.anchor_response.v1";

/// Errors returned before a request can reach authority or persistence code.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AnchorCodecError {
    /// The HTTP-bound protocol context is not the exact commitment-only route.
    #[error("invalid request context: {0}")]
    InvalidContext(&'static str),
    /// The body is empty or exceeds the protocol limit.
    #[error("invalid body length")]
    InvalidBodyLength,
    /// The body is not deterministic RFC 8949 CBOR.
    #[error("non-canonical CBOR: {0}")]
    NonCanonicalCbor(&'static str),
    /// The CBOR shape or an exact field type is invalid.
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    /// The request's independently derived idempotency value is wrong.
    #[error("idempotency mismatch")]
    IdempotencyMismatch,
    /// The request is outside the closed validity interval rules.
    #[error("invalid request validity")]
    InvalidValidity,
    /// The request signature does not verify over the exact domain.
    #[error("invalid request signature")]
    InvalidSignature,
    /// A response does not bind the expected request or action commitment.
    #[error("response commitment mismatch")]
    CommitmentMismatch,
    /// The nested generic receipt failed its hash, signature, or wire checks.
    #[error("invalid nested trust receipt")]
    InvalidReceipt,
    /// Deterministic serialization failed.
    #[error("CBOR serialization failed")]
    Serialization,
}

/// Exact 16-key commitment-only request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossCheckedAnchorRequestV1 {
    pub protocol_version: u64,
    pub source_code: String,
    pub receipt_format: String,
    pub audience: String,
    pub authority_did: String,
    pub authority_key_id: String,
    pub grant_id: [u8; 32],
    pub scope_alias: [u8; 32],
    pub action_hash_algorithm: String,
    pub action_hash: [u8; 32],
    pub idempotency_key: [u8; 32],
    pub nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature_algorithm: String,
    pub signature: [u8; 64],
}

impl CrossCheckedAnchorRequestV1 {
    /// Encode the exact request signature preimage.
    ///
    /// # Errors
    /// Returns an error only if the in-memory CBOR value cannot be serialized.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, AnchorCodecError> {
        encode_value(&Value::Array(vec![
            text(REQUEST_DOMAIN),
            text("POST"),
            text(ANCHOR_PATH),
            unsigned(self.protocol_version),
            text(&self.source_code),
            text(&self.receipt_format),
            text(&self.audience),
            text(&self.authority_did),
            text(&self.authority_key_id),
            bytes(&self.grant_id),
            bytes(&self.scope_alias),
            text(&self.action_hash_algorithm),
            bytes(&self.action_hash),
            bytes(&self.idempotency_key),
            bytes(&self.nonce),
            unsigned(self.issued_at_ms),
            unsigned(self.expires_at_ms),
            text(&self.signature_algorithm),
        ]))
    }

    /// Derive the exact protocol idempotency key from semantic commitments.
    ///
    /// # Errors
    /// Returns an error only if the in-memory CBOR value cannot be serialized.
    pub fn derive_idempotency_key(&self) -> Result<[u8; 32], AnchorCodecError> {
        let encoded = encode_value(&Value::Array(vec![
            text(IDEMPOTENCY_DOMAIN),
            text(&self.authority_did),
            bytes(&self.grant_id),
            bytes(&self.scope_alias),
            bytes(&self.action_hash),
        ]))?;
        Ok(*blake3::hash(&encoded).as_bytes())
    }

    /// Encode the exact 16-key deterministic request map.
    ///
    /// # Errors
    /// Returns an error only if the in-memory CBOR value cannot be serialized.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, AnchorCodecError> {
        encode_value(&canonical_map(vec![
            ("protocol_version", unsigned(self.protocol_version)),
            ("source_code", text(&self.source_code)),
            ("receipt_format", text(&self.receipt_format)),
            ("audience", text(&self.audience)),
            ("authority_did", text(&self.authority_did)),
            ("authority_key_id", text(&self.authority_key_id)),
            ("grant_id", bytes(&self.grant_id)),
            ("scope_alias", bytes(&self.scope_alias)),
            ("action_hash_algorithm", text(&self.action_hash_algorithm)),
            ("action_hash", bytes(&self.action_hash)),
            ("idempotency_key", bytes(&self.idempotency_key)),
            ("nonce", bytes(&self.nonce)),
            ("issued_at_ms", unsigned(self.issued_at_ms)),
            ("expires_at_ms", unsigned(self.expires_at_ms)),
            ("signature_algorithm", text(&self.signature_algorithm)),
            ("signature", bytes(&self.signature)),
        ]))
    }
}

/// Transport-bound inputs needed to validate, but not authorize, a request.
#[derive(Clone, Copy, Debug)]
pub struct RequestValidationContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: &'a str,
    pub expected_audience: &'a str,
    pub now_ms: u64,
    pub authority_public_key: &'a PublicKey,
}

/// A validated request together with its exact body and signed-body hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCrossCheckedAnchorRequestV1 {
    pub request: CrossCheckedAnchorRequestV1,
    pub canonical_body: Vec<u8>,
    pub request_hash: Hash256,
}

/// Exact 10-key commitment-only response.
///
/// `exochain_receipt` remains the generic [`TrustReceipt`] semantic type. Its
/// anchor-local wire adapter changes only the nested `timestamp` encoding from
/// generic serde's map into the protocol-mandated `[physical_ms, logical]`
/// array. The generic receipt serializer, hasher, signer, and RFC 3161 paths
/// are not modified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossCheckedAnchorResponseV1 {
    pub protocol_version: u64,
    pub request_hash: Hash256,
    pub action_hash: Hash256,
    pub exochain_receipt: TrustReceipt,
    pub recording_status: String,
    pub consensus_finality: String,
    pub node_did: String,
    pub node_key_id: String,
    pub node_recorded_at: Timestamp,
    pub wrapper_signature: [u8; 64],
}

impl CrossCheckedAnchorResponseV1 {
    /// Encode the exact response-wrapper signature preimage.
    ///
    /// # Errors
    /// Returns an error if nested receipt or CBOR serialization fails.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, AnchorCodecError> {
        encode_value(&Value::Array(vec![
            text(RESPONSE_DOMAIN),
            unsigned(self.protocol_version),
            bytes(self.request_hash.as_bytes()),
            bytes(self.action_hash.as_bytes()),
            receipt_to_anchor_value(&self.exochain_receipt)?,
            text(&self.recording_status),
            text(&self.consensus_finality),
            text(&self.node_did),
            text(&self.node_key_id),
            timestamp_value(self.node_recorded_at),
        ]))
    }

    /// Encode the exact 10-key deterministic response map.
    ///
    /// # Errors
    /// Returns an error if nested receipt or CBOR serialization fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, AnchorCodecError> {
        encode_value(&canonical_map(vec![
            ("protocol_version", unsigned(self.protocol_version)),
            ("request_hash", bytes(self.request_hash.as_bytes())),
            ("action_hash", bytes(self.action_hash.as_bytes())),
            (
                "exochain_receipt",
                receipt_to_anchor_value(&self.exochain_receipt)?,
            ),
            ("recording_status", text(&self.recording_status)),
            ("consensus_finality", text(&self.consensus_finality)),
            ("node_did", text(&self.node_did)),
            ("node_key_id", text(&self.node_key_id)),
            ("node_recorded_at", timestamp_value(self.node_recorded_at)),
            ("wrapper_signature", bytes(&self.wrapper_signature)),
        ]))
    }
}

/// Independent commitments and verification keys required for response decode.
#[derive(Clone, Copy, Debug)]
pub struct ResponseValidationContext<'a> {
    pub expected_request_hash: Hash256,
    pub expected_action_hash: Hash256,
    pub receipt_actor_public_key: &'a PublicKey,
    pub node_public_key: &'a PublicKey,
}

/// A validated response together with its exact stable body bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCrossCheckedAnchorResponseV1 {
    pub response: CrossCheckedAnchorResponseV1,
    pub canonical_body: Vec<u8>,
}

/// Strictly decode and validate a commitment-only response.
///
/// # Errors
/// Returns a closed error for any CBOR, commitment, nested receipt, timestamp,
/// or signature mismatch.
pub fn decode_and_validate_response(
    body: &[u8],
    context: ResponseValidationContext<'_>,
) -> Result<ValidatedCrossCheckedAnchorResponseV1, AnchorCodecError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(AnchorCodecError::InvalidBodyLength);
    }
    validate_preferred_cbor(body)?;
    let value: Value =
        ciborium::from_reader(body).map_err(|_| AnchorCodecError::NonCanonicalCbor("decode"))?;
    let response = response_from_value(value)?;
    validate_response_fields(&response, context)?;
    if response.to_canonical_cbor()? != body {
        return Err(AnchorCodecError::NonCanonicalCbor("round trip"));
    }
    let signature = Signature::from_bytes(response.wrapper_signature);
    if !crypto::verify(
        &response.signing_preimage()?,
        &signature,
        context.node_public_key,
    ) {
        return Err(AnchorCodecError::InvalidSignature);
    }
    Ok(ValidatedCrossCheckedAnchorResponseV1 {
        response,
        canonical_body: body.to_vec(),
    })
}

/// Strictly decode and validate an exact commitment-only anchor request.
///
/// This function performs protocol validation only. A successful return is
/// not authority, replay-journal, persistence, or route-activation proof.
///
/// # Errors
/// Returns a closed protocol error for any context, CBOR, field, time,
/// idempotency, or signature mismatch.
pub fn decode_and_validate_request(
    body: &[u8],
    context: RequestValidationContext<'_>,
) -> Result<ValidatedCrossCheckedAnchorRequestV1, AnchorCodecError> {
    validate_request_context(body, context)?;
    validate_preferred_cbor(body)?;
    let value: Value =
        ciborium::from_reader(body).map_err(|_| AnchorCodecError::NonCanonicalCbor("decode"))?;
    let request = request_from_value(value)?;
    validate_request_fields(&request, context.expected_audience, context.now_ms)?;
    if request.to_canonical_cbor()? != body {
        return Err(AnchorCodecError::NonCanonicalCbor("round trip"));
    }
    let signature = Signature::from_bytes(request.signature);
    if !crypto::verify(
        &request.signing_preimage()?,
        &signature,
        context.authority_public_key,
    ) {
        return Err(AnchorCodecError::InvalidSignature);
    }
    Ok(ValidatedCrossCheckedAnchorRequestV1 {
        request,
        canonical_body: body.to_vec(),
        request_hash: Hash256::digest(body),
    })
}

fn validate_request_context(
    body: &[u8],
    context: RequestValidationContext<'_>,
) -> Result<(), AnchorCodecError> {
    if body.is_empty() || body.len() > MAX_REQUEST_BODY_BYTES {
        return Err(AnchorCodecError::InvalidBodyLength);
    }
    if context.method != "POST" {
        return Err(AnchorCodecError::InvalidContext("method"));
    }
    if context.path != ANCHOR_PATH {
        return Err(AnchorCodecError::InvalidContext("path"));
    }
    if context.content_type != "application/cbor" {
        return Err(AnchorCodecError::InvalidContext("content type"));
    }
    Ok(())
}

fn validate_request_fields(
    request: &CrossCheckedAnchorRequestV1,
    expected_audience: &str,
    now_ms: u64,
) -> Result<(), AnchorCodecError> {
    if request.protocol_version != 1 {
        return Err(AnchorCodecError::InvalidField("protocol_version"));
    }
    require_exact(&request.source_code, "crosschecked", "source_code")?;
    require_exact(
        &request.receipt_format,
        "action_receipt_v3",
        "receipt_format",
    )?;
    require_exact(
        &request.action_hash_algorithm,
        "blake3-256",
        "action_hash_algorithm",
    )?;
    require_exact(
        &request.signature_algorithm,
        "ed25519",
        "signature_algorithm",
    )?;
    validate_audience(&request.audience)?;
    if request.audience != expected_audience {
        return Err(AnchorCodecError::InvalidField("audience"));
    }
    validate_did_and_key_id(&request.authority_did, &request.authority_key_id)?;
    for (name, value) in [
        ("grant_id", &request.grant_id),
        ("scope_alias", &request.scope_alias),
        ("action_hash", &request.action_hash),
        ("idempotency_key", &request.idempotency_key),
        ("nonce", &request.nonce),
    ] {
        if value.iter().all(|byte| *byte == 0) {
            return Err(AnchorCodecError::InvalidField(name));
        }
    }
    if request.signature.iter().all(|byte| *byte == 0) {
        return Err(AnchorCodecError::InvalidField("signature"));
    }
    if request.derive_idempotency_key()? != request.idempotency_key {
        return Err(AnchorCodecError::IdempotencyMismatch);
    }
    let validity = request
        .expires_at_ms
        .checked_sub(request.issued_at_ms)
        .ok_or(AnchorCodecError::InvalidValidity)?;
    if validity == 0 || validity > MAX_VALIDITY_MS || request.expires_at_ms <= now_ms {
        return Err(AnchorCodecError::InvalidValidity);
    }
    if request.issued_at_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err(AnchorCodecError::InvalidValidity);
    }
    Ok(())
}

fn validate_audience(audience: &str) -> Result<(), AnchorCodecError> {
    if audience.is_empty()
        || audience.len() > 128
        || !audience.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(AnchorCodecError::InvalidField("audience"));
    }
    Ok(())
}

fn validate_did_and_key_id(did: &str, key_id: &str) -> Result<(), AnchorCodecError> {
    if did.is_empty() || did.len() > 256 || Did::new(did).is_err() {
        return Err(AnchorCodecError::InvalidField("authority_did"));
    }
    let prefix = format!("{did}#");
    let fragment = key_id
        .strip_prefix(&prefix)
        .ok_or(AnchorCodecError::InvalidField("authority_key_id"))?;
    if key_id.len() > 321
        || fragment.is_empty()
        || fragment.len() > 64
        || !fragment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AnchorCodecError::InvalidField("authority_key_id"));
    }
    Ok(())
}

fn require_exact(actual: &str, expected: &str, name: &'static str) -> Result<(), AnchorCodecError> {
    if actual != expected {
        return Err(AnchorCodecError::InvalidField(name));
    }
    Ok(())
}

fn request_from_value(value: Value) -> Result<CrossCheckedAnchorRequestV1, AnchorCodecError> {
    let mut fields = exact_text_map(value, 16)?;
    let request = CrossCheckedAnchorRequestV1 {
        protocol_version: take_u64(&mut fields, "protocol_version")?,
        source_code: take_text(&mut fields, "source_code")?,
        receipt_format: take_text(&mut fields, "receipt_format")?,
        audience: take_text(&mut fields, "audience")?,
        authority_did: take_text(&mut fields, "authority_did")?,
        authority_key_id: take_text(&mut fields, "authority_key_id")?,
        grant_id: take_bytes(&mut fields, "grant_id")?,
        scope_alias: take_bytes(&mut fields, "scope_alias")?,
        action_hash_algorithm: take_text(&mut fields, "action_hash_algorithm")?,
        action_hash: take_bytes(&mut fields, "action_hash")?,
        idempotency_key: take_bytes(&mut fields, "idempotency_key")?,
        nonce: take_bytes(&mut fields, "nonce")?,
        issued_at_ms: take_u64(&mut fields, "issued_at_ms")?,
        expires_at_ms: take_u64(&mut fields, "expires_at_ms")?,
        signature_algorithm: take_text(&mut fields, "signature_algorithm")?,
        signature: take_bytes(&mut fields, "signature")?,
    };
    if !fields.is_empty() {
        return Err(AnchorCodecError::InvalidField("unknown key"));
    }
    Ok(request)
}

fn response_from_value(value: Value) -> Result<CrossCheckedAnchorResponseV1, AnchorCodecError> {
    let mut fields = exact_text_map(value, 10)?;
    let response = CrossCheckedAnchorResponseV1 {
        protocol_version: take_u64(&mut fields, "protocol_version")?,
        request_hash: Hash256::from_bytes(take_bytes(&mut fields, "request_hash")?),
        action_hash: Hash256::from_bytes(take_bytes(&mut fields, "action_hash")?),
        exochain_receipt: receipt_from_anchor_value(take_value(&mut fields, "exochain_receipt")?)?,
        recording_status: take_text(&mut fields, "recording_status")?,
        consensus_finality: take_text(&mut fields, "consensus_finality")?,
        node_did: take_text(&mut fields, "node_did")?,
        node_key_id: take_text(&mut fields, "node_key_id")?,
        node_recorded_at: timestamp_from_value(take_value(&mut fields, "node_recorded_at")?)?,
        wrapper_signature: take_bytes(&mut fields, "wrapper_signature")?,
    };
    if !fields.is_empty() {
        return Err(AnchorCodecError::InvalidField("unknown key"));
    }
    Ok(response)
}

fn validate_response_fields(
    response: &CrossCheckedAnchorResponseV1,
    context: ResponseValidationContext<'_>,
) -> Result<(), AnchorCodecError> {
    if response.protocol_version != 1 {
        return Err(AnchorCodecError::InvalidField("protocol_version"));
    }
    require_exact(
        &response.recording_status,
        "node_recorded",
        "recording_status",
    )?;
    require_exact(
        &response.consensus_finality,
        "not_asserted",
        "consensus_finality",
    )?;
    validate_did_and_key_id(&response.node_did, &response.node_key_id)?;
    if response.request_hash == Hash256::ZERO
        || response.action_hash == Hash256::ZERO
        || response.wrapper_signature.iter().all(|byte| *byte == 0)
    {
        return Err(AnchorCodecError::InvalidField("zero response field"));
    }
    if response.request_hash != context.expected_request_hash
        || response.action_hash != context.expected_action_hash
        || response.exochain_receipt.action_hash != response.action_hash
    {
        return Err(AnchorCodecError::CommitmentMismatch);
    }
    if response.node_recorded_at != response.exochain_receipt.timestamp {
        return Err(AnchorCodecError::InvalidField("node_recorded_at"));
    }
    if Did::new(response.exochain_receipt.actor_did.as_str()).is_err() {
        return Err(AnchorCodecError::InvalidReceipt);
    }
    let valid_hash = response
        .exochain_receipt
        .verify_hash()
        .map_err(|_| AnchorCodecError::InvalidReceipt)?;
    let valid_signature = response
        .exochain_receipt
        .verify_signature(context.receipt_actor_public_key)
        .map_err(|_| AnchorCodecError::InvalidReceipt)?;
    if !valid_hash || !valid_signature {
        return Err(AnchorCodecError::InvalidReceipt);
    }
    Ok(())
}

fn receipt_to_anchor_value(receipt: &TrustReceipt) -> Result<Value, AnchorCodecError> {
    let mut generic = Vec::new();
    ciborium::into_writer(receipt, &mut generic).map_err(|_| AnchorCodecError::Serialization)?;
    let mut value: Value =
        ciborium::from_reader(generic.as_slice()).map_err(|_| AnchorCodecError::Serialization)?;
    validate_receipt_field_names(&value)?;
    let Value::Map(fields) = &mut value else {
        return Err(AnchorCodecError::InvalidReceipt);
    };
    let (_, timestamp) = fields
        .iter_mut()
        .find(|(key, _)| key == &text("timestamp"))
        .ok_or(AnchorCodecError::InvalidReceipt)?;
    *timestamp = timestamp_value(receipt.timestamp);
    canonicalize_value(&mut value)?;
    Ok(value)
}

fn receipt_from_anchor_value(mut value: Value) -> Result<TrustReceipt, AnchorCodecError> {
    validate_receipt_field_names(&value)?;
    let Value::Map(fields) = &mut value else {
        return Err(AnchorCodecError::InvalidReceipt);
    };
    let (_, timestamp_value) = fields
        .iter_mut()
        .find(|(key, _)| key == &text("timestamp"))
        .ok_or(AnchorCodecError::InvalidReceipt)?;
    let timestamp = timestamp_from_value(timestamp_value.clone())?;
    *timestamp_value = canonical_map(vec![
        ("physical_ms", unsigned(timestamp.physical_ms)),
        ("logical", unsigned(u64::from(timestamp.logical))),
    ]);
    let generic = encode_value(&value)?;
    ciborium::from_reader(generic.as_slice()).map_err(|_| AnchorCodecError::InvalidReceipt)
}

fn validate_receipt_field_names(value: &Value) -> Result<(), AnchorCodecError> {
    let Value::Map(fields) = value else {
        return Err(AnchorCodecError::InvalidReceipt);
    };
    const EXPECTED: [&str; 10] = [
        "receipt_hash",
        "actor_did",
        "authority_chain_hash",
        "consent_reference",
        "action_type",
        "action_hash",
        "outcome",
        "timestamp",
        "signature",
        "challenge_reference",
    ];
    if fields.len() != EXPECTED.len() {
        return Err(AnchorCodecError::InvalidReceipt);
    }
    let mut seen = BTreeMap::new();
    for (key, _) in fields {
        let Value::Text(key) = key else {
            return Err(AnchorCodecError::InvalidReceipt);
        };
        if !EXPECTED.contains(&key.as_str()) || seen.insert(key.as_str(), ()).is_some() {
            return Err(AnchorCodecError::InvalidReceipt);
        }
    }
    Ok(())
}

fn timestamp_value(timestamp: Timestamp) -> Value {
    Value::Array(vec![
        unsigned(timestamp.physical_ms),
        unsigned(u64::from(timestamp.logical)),
    ])
}

fn timestamp_from_value(value: Value) -> Result<Timestamp, AnchorCodecError> {
    let Value::Array(mut components) = value else {
        return Err(AnchorCodecError::InvalidField("timestamp"));
    };
    if components.len() != 2 {
        return Err(AnchorCodecError::InvalidField("timestamp"));
    }
    let logical = value_to_u64(
        components
            .pop()
            .ok_or(AnchorCodecError::InvalidField("timestamp"))?,
        "timestamp",
    )?;
    let physical_ms = value_to_u64(
        components
            .pop()
            .ok_or(AnchorCodecError::InvalidField("timestamp"))?,
        "timestamp",
    )?;
    let logical =
        u32::try_from(logical).map_err(|_| AnchorCodecError::InvalidField("timestamp"))?;
    Ok(Timestamp::new(physical_ms, logical))
}

fn value_to_u64(value: Value, name: &'static str) -> Result<u64, AnchorCodecError> {
    let Value::Integer(value) = value else {
        return Err(AnchorCodecError::InvalidField(name));
    };
    u64::try_from(value).map_err(|_| AnchorCodecError::InvalidField(name))
}

fn exact_text_map(
    value: Value,
    expected_len: usize,
) -> Result<BTreeMap<String, Value>, AnchorCodecError> {
    let Value::Map(entries) = value else {
        return Err(AnchorCodecError::InvalidField("root map"));
    };
    if entries.len() != expected_len {
        return Err(AnchorCodecError::InvalidField("map length"));
    }
    let mut fields = BTreeMap::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err(AnchorCodecError::InvalidField("non-text key"));
        };
        if fields.insert(key, value).is_some() {
            return Err(AnchorCodecError::InvalidField("duplicate key"));
        }
    }
    Ok(fields)
}

fn take_text(
    fields: &mut BTreeMap<String, Value>,
    name: &'static str,
) -> Result<String, AnchorCodecError> {
    match fields.remove(name) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(AnchorCodecError::InvalidField(name)),
    }
}

fn take_u64(
    fields: &mut BTreeMap<String, Value>,
    name: &'static str,
) -> Result<u64, AnchorCodecError> {
    match fields.remove(name) {
        Some(Value::Integer(value)) => {
            u64::try_from(value).map_err(|_| AnchorCodecError::InvalidField(name))
        }
        _ => Err(AnchorCodecError::InvalidField(name)),
    }
}

fn take_value(
    fields: &mut BTreeMap<String, Value>,
    name: &'static str,
) -> Result<Value, AnchorCodecError> {
    fields
        .remove(name)
        .ok_or(AnchorCodecError::InvalidField(name))
}

fn take_bytes<const N: usize>(
    fields: &mut BTreeMap<String, Value>,
    name: &'static str,
) -> Result<[u8; N], AnchorCodecError> {
    match fields.remove(name) {
        Some(Value::Bytes(value)) => value
            .try_into()
            .map_err(|_| AnchorCodecError::InvalidField(name)),
        _ => Err(AnchorCodecError::InvalidField(name)),
    }
}

fn canonical_map(entries: Vec<(&str, Value)>) -> Value {
    let mut encoded_entries: Vec<(Vec<u8>, String, Value)> = entries
        .into_iter()
        .map(|(key, value)| {
            let encoded = deterministic_text_key_bytes(key);
            (encoded, key.to_owned(), value)
        })
        .collect();
    encoded_entries.sort_by(|left, right| canonical_key_cmp(&left.0, &right.0));
    Value::Map(
        encoded_entries
            .into_iter()
            .map(|(_, key, value)| (Value::Text(key), value))
            .collect(),
    )
}

fn deterministic_text_key_bytes(key: &str) -> Vec<u8> {
    let length = key.len();
    let mut encoded = Vec::with_capacity(length.saturating_add(9));
    match length {
        0..=23 => encoded.push(0x60 | u8::try_from(length).unwrap_or(0)),
        24..=255 => {
            encoded.push(0x78);
            encoded.push(u8::try_from(length).unwrap_or(u8::MAX));
        }
        256..=65_535 => {
            encoded.push(0x79);
            encoded.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            encoded.push(0x7a);
            encoded.extend_from_slice(&u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes());
        }
        _ => {
            encoded.push(0x7b);
            encoded.extend_from_slice(&u64::try_from(length).unwrap_or(u64::MAX).to_be_bytes());
        }
    }
    encoded.extend_from_slice(key.as_bytes());
    encoded
}

fn canonicalize_value(value: &mut Value) -> Result<(), AnchorCodecError> {
    match value {
        Value::Array(values) => {
            for value in values {
                canonicalize_value(value)?;
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries.iter_mut() {
                canonicalize_value(key)?;
                canonicalize_value(value)?;
            }
            let mut keyed = Vec::with_capacity(entries.len());
            for (key, value) in std::mem::take(entries) {
                keyed.push((encode_value(&key)?, key, value));
            }
            keyed.sort_by(|left, right| canonical_key_cmp(&left.0, &right.0));
            *entries = keyed
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
        }
        _ => {}
    }
    Ok(())
}

fn canonical_key_cmp(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
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

fn encode_value(value: &Value) -> Result<Vec<u8>, AnchorCodecError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).map_err(|_| AnchorCodecError::Serialization)?;
    Ok(encoded)
}

/// Validate one complete deterministic RFC 8949 CBOR data item.
pub fn validate_preferred_cbor(input: &[u8]) -> Result<(), AnchorCodecError> {
    if input.is_empty() {
        return Err(AnchorCodecError::NonCanonicalCbor("empty"));
    }
    let end = scan_item(input, 0, 1)?;
    if end != input.len() {
        return Err(AnchorCodecError::NonCanonicalCbor("trailing bytes"));
    }
    Ok(())
}

fn scan_item(input: &[u8], start: usize, depth: usize) -> Result<usize, AnchorCodecError> {
    if depth > 32 {
        return Err(AnchorCodecError::NonCanonicalCbor("nesting depth"));
    }
    let initial = *input
        .get(start)
        .ok_or(AnchorCodecError::NonCanonicalCbor("truncated item"))?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    if additional == 31 {
        return Err(AnchorCodecError::NonCanonicalCbor("indefinite length"));
    }
    if major == 7 {
        return match additional {
            20..=22 => Ok(start + 1),
            _ => Err(AnchorCodecError::NonCanonicalCbor("simple or float")),
        };
    }
    if major > 6 {
        return Err(AnchorCodecError::NonCanonicalCbor("major type"));
    }
    if major == 6 {
        return Err(AnchorCodecError::NonCanonicalCbor("tag"));
    }
    let (argument, mut cursor) = read_argument(input, start, additional)?;
    match major {
        0 | 1 => Ok(cursor),
        2 | 3 => {
            let length = usize::try_from(argument)
                .map_err(|_| AnchorCodecError::NonCanonicalCbor("length overflow"))?;
            let end = cursor
                .checked_add(length)
                .ok_or(AnchorCodecError::NonCanonicalCbor("length overflow"))?;
            let payload = input
                .get(cursor..end)
                .ok_or(AnchorCodecError::NonCanonicalCbor("truncated bytes"))?;
            if major == 3 && std::str::from_utf8(payload).is_err() {
                return Err(AnchorCodecError::NonCanonicalCbor("invalid UTF-8"));
            }
            Ok(end)
        }
        4 => {
            for _ in 0..argument {
                cursor = scan_item(input, cursor, depth + 1)?;
            }
            Ok(cursor)
        }
        5 => {
            let mut previous_key: Option<&[u8]> = None;
            for _ in 0..argument {
                let key_start = cursor;
                cursor = scan_item(input, cursor, depth + 1)?;
                let key = &input[key_start..cursor];
                if previous_key
                    .is_some_and(|previous| canonical_key_cmp(previous, key) != Ordering::Less)
                {
                    return Err(AnchorCodecError::NonCanonicalCbor(
                        "map key order or duplicate",
                    ));
                }
                previous_key = Some(key);
                cursor = scan_item(input, cursor, depth + 1)?;
            }
            Ok(cursor)
        }
        _ => Err(AnchorCodecError::NonCanonicalCbor("major type")),
    }
}

fn read_argument(
    input: &[u8],
    start: usize,
    additional: u8,
) -> Result<(u64, usize), AnchorCodecError> {
    match additional {
        value @ 0..=23 => Ok((u64::from(value), start + 1)),
        24 => {
            let value = u64::from(read_fixed::<1>(input, start)?[0]);
            if value < 24 {
                return Err(AnchorCodecError::NonCanonicalCbor("integer width"));
            }
            Ok((value, start + 2))
        }
        25 => {
            let value = u64::from(u16::from_be_bytes(read_fixed(input, start)?));
            if value <= u64::from(u8::MAX) {
                return Err(AnchorCodecError::NonCanonicalCbor("integer width"));
            }
            Ok((value, start + 3))
        }
        26 => {
            let value = u64::from(u32::from_be_bytes(read_fixed(input, start)?));
            if value <= u64::from(u16::MAX) {
                return Err(AnchorCodecError::NonCanonicalCbor("integer width"));
            }
            Ok((value, start + 5))
        }
        27 => {
            let value = u64::from_be_bytes(read_fixed(input, start)?);
            if value <= u64::from(u32::MAX) {
                return Err(AnchorCodecError::NonCanonicalCbor("integer width"));
            }
            Ok((value, start + 9))
        }
        _ => Err(AnchorCodecError::NonCanonicalCbor("reserved argument")),
    }
}

fn read_fixed<const N: usize>(input: &[u8], start: usize) -> Result<[u8; N], AnchorCodecError> {
    let end = start
        .checked_add(1 + N)
        .ok_or(AnchorCodecError::NonCanonicalCbor("truncated argument"))?;
    input
        .get(start + 1..end)
        .ok_or(AnchorCodecError::NonCanonicalCbor("truncated argument"))?
        .try_into()
        .map_err(|_| AnchorCodecError::NonCanonicalCbor("truncated argument"))
}
