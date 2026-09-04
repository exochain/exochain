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

//! Messaging bindings: X25519 key exchange, message encrypt/decrypt, death verification

use std::collections::BTreeMap;

use serde::Deserialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::serde_bridge::*;

const MAX_WASM_AUTHORIZED_TRUSTEES: usize = 1_024;
const MAX_CLAIM_NONCE_BYTES: usize = 64;
const MAX_CLAIM_NONCE_HEX_LEN: usize = MAX_CLAIM_NONCE_BYTES * 2;
const CLAIM_NONCE_LIMIT_ERROR: &str =
    "claim nonce hex must not exceed 128 characters (64 decoded bytes)";
const WASM_MESSAGE_PLAINTEXT_LIMIT_ERROR: &str = exo_messaging::ENVELOPE_PLAINTEXT_LIMIT_ERROR;

#[derive(Deserialize)]
struct WasmAuthorizedTrustee {
    did: String,
    public_key_hex: String,
}

/// Legacy X25519 key generation entrypoint.
///
/// This fails closed because the WASM bridge must not fabricate X25519 key
/// material internally.
#[wasm_bindgen]
pub fn wasm_generate_x25519_keypair() -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "X25519 key generation is disabled at the WASM boundary; use external key management and pass caller-supplied ephemeral material to wasm_prepare_encrypted_message",
    ))
}

/// Derive an X25519 public key from a secret key hex string.
/// Returns `{ public_key_hex }`.
#[wasm_bindgen]
pub fn wasm_x25519_public_from_secret(_secret_hex: &str) -> Result<JsValue, JsValue> {
    Err(JsValue::from_str(
        "raw X25519 secret public derivation is disabled at the WASM boundary; derive public keys in external key management before calling WASM",
    ))
}

/// Derive the public key for caller-managed X25519 material.
///
/// The bridge does not generate, persist, or export secret material. Browser or
/// service key management supplies the secret bytes explicitly and receives only
/// the corresponding public key.
#[wasm_bindgen]
pub fn wasm_caller_managed_x25519_public_from_secret(secret_hex: &str) -> Result<JsValue, JsValue> {
    ensure_fixed_hex_encoded_len::<32>("caller-managed X25519 secret", secret_hex)
        .map_err(|error| JsValue::from_str(&error))?;
    let secret = exo_messaging::X25519SecretKey::from_hex(secret_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid caller-managed X25519 secret: {e}")))?;
    let public = secret.public_key();
    to_js_value(&serde_json::json!({
        "public_key_hex": public.to_hex(),
    }))
}

/// Encrypt a message for a specific recipient (Lock & Send).
///
/// # Parameters
/// - `plaintext`: The message content (UTF-8 string)
/// - `content_type_json`: Content type as JSON string (e.g., `"\"Text\""`)
/// - `sender_did`: Sender's DID string
/// - `recipient_did`: Recipient's DID string
/// - `_legacy_sender_key_hex`: ignored; raw sender signing keys are refused
/// - `recipient_x25519_public_hex`: Recipient's X25519 public key (hex)
/// - `message_id`: Caller-supplied non-nil message UUID
/// - `created_physical_ms`: Caller-supplied non-zero HLC physical milliseconds
/// - `created_logical`: Caller-supplied HLC logical counter
/// - `release_on_death`: Whether to release after sender's death
/// - `release_delay_hours`: Hours to wait after death verification
///
/// # Returns
/// The encrypted envelope as JSON.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
// Mirrors `exo_messaging::compose::lock_and_send`; the WASM boundary
// cannot take Rust structs directly, so envelope metadata crosses as
// primitive fields and is validated before encryption.
pub fn wasm_encrypt_message(
    plaintext: &str,
    content_type_json: &str,
    sender_did: &str,
    recipient_did: &str,
    _legacy_sender_key_hex: &str,
    recipient_x25519_public_hex: &str,
    message_id: &str,
    created_physical_ms: u64,
    created_logical: u32,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<JsValue, JsValue> {
    let _ = (
        plaintext,
        content_type_json,
        sender_did,
        recipient_did,
        recipient_x25519_public_hex,
        message_id,
        created_physical_ms,
        created_logical,
        release_on_death,
        release_delay_hours,
    );
    Err(JsValue::from_str(
        "raw Ed25519 sender signing is disabled at the WASM boundary; call wasm_prepare_encrypted_message with caller-supplied ephemeral X25519 material, sign externally, then call wasm_attach_message_signature",
    ))
}

/// Encrypt a message and return an unsigned envelope plus canonical signing bytes.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn wasm_prepare_encrypted_message(
    plaintext: &str,
    content_type_json: &str,
    sender_did: &str,
    recipient_did: &str,
    recipient_x25519_public_hex: &str,
    ephemeral_x25519_secret_hex: &str,
    message_id: &str,
    created_physical_ms: u64,
    created_logical: u32,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<JsValue, JsValue> {
    validate_wasm_message_plaintext(plaintext).map_err(JsValue::from_str)?;
    let content_type: exo_messaging::ContentType = from_json_str(content_type_json)?;

    let sender = exo_core::Did::new(sender_did)
        .map_err(|e| JsValue::from_str(&format!("invalid sender DID: {e}")))?;
    let recipient = exo_core::Did::new(recipient_did)
        .map_err(|e| JsValue::from_str(&format!("invalid recipient DID: {e}")))?;

    ensure_fixed_hex_encoded_len::<32>("recipient X25519 public key", recipient_x25519_public_hex)
        .map_err(|error| JsValue::from_str(&error))?;
    let recipient_pub = exo_messaging::X25519PublicKey::from_hex(recipient_x25519_public_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid recipient X25519 key: {e}")))?;
    let ephemeral_keypair =
        parse_x25519_keypair_hex("ephemeral X25519 secret", ephemeral_x25519_secret_hex)?;
    let message_uuid = uuid::Uuid::parse_str(message_id)
        .map_err(|e| JsValue::from_str(&format!("invalid message id: {e}")))?;
    let metadata = exo_messaging::ComposeMetadata::new(
        message_uuid,
        exo_core::Timestamp::new(created_physical_ms, created_logical),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid envelope metadata: {e}")))?;

    let envelope = exo_messaging::prepare_envelope_for_signing_with_ephemeral(
        plaintext.as_bytes(),
        content_type,
        &sender,
        &recipient,
        &recipient_pub,
        &ephemeral_keypair,
        metadata,
        release_on_death,
        release_delay_hours,
    )
    .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;
    let signing_payload = envelope
        .signing_payload()
        .map_err(|e| JsValue::from_str(&format!("signature payload failed: {e}")))?;

    to_js_value(&serde_json::json!({
        "envelope": envelope,
        "signing_payload_hex": hex::encode(signing_payload),
    }))
}

fn validate_wasm_message_plaintext(plaintext: &str) -> Result<(), &'static str> {
    if plaintext.len() > exo_messaging::MAX_ENVELOPE_PLAINTEXT_LEN {
        return Err(WASM_MESSAGE_PLAINTEXT_LIMIT_ERROR);
    }
    Ok(())
}

fn parse_x25519_keypair_hex(
    label: &str,
    secret_hex: &str,
) -> Result<exo_messaging::X25519KeyPair, JsValue> {
    ensure_fixed_hex_encoded_len::<32>(label, secret_hex)
        .map_err(|error| JsValue::from_str(&error))?;
    let bytes = Zeroizing::new(
        hex::decode(secret_hex)
            .map_err(|e| JsValue::from_str(&format!("{label} must be hex: {e}")))?,
    );
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!("{label} must be 32 bytes")));
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(bytes.as_slice());
    exo_messaging::X25519KeyPair::from_secret_bytes(*secret)
        .map_err(|e| JsValue::from_str(&format!("invalid {label}: {e}")))
}

/// Attach a caller-produced Ed25519 signature to a prepared encrypted envelope.
#[wasm_bindgen]
pub fn wasm_attach_message_signature(
    envelope_json: &str,
    sender_ed25519_public_hex: &str,
    signature_hex: &str,
) -> Result<JsValue, JsValue> {
    let envelope: exo_messaging::EncryptedEnvelope = from_json_str(envelope_json)?;
    let sender_public =
        parse_ed25519_public_key_hex("sender Ed25519 public key", sender_ed25519_public_hex)?;
    let signature = parse_ed25519_signature_hex("sender envelope signature", signature_hex)?;
    let envelope = exo_messaging::attach_verified_signature(envelope, signature, &sender_public)
        .map_err(|e| JsValue::from_str(&format!("signature attachment failed: {e}")))?;

    to_js_value(&envelope)
}

/// Decrypt an encrypted message envelope.
///
/// # Parameters
/// - `envelope_json`: The encrypted envelope as JSON string
/// - `recipient_x25519_secret_hex`: Recipient's X25519 secret key (hex)
/// - `sender_ed25519_public_hex`: Sender's Ed25519 public key (hex)
///
/// # Returns
/// `{ plaintext: string, content_type: string }`
#[wasm_bindgen]
pub fn wasm_decrypt_message(
    envelope_json: &str,
    recipient_x25519_secret_hex: &str,
    sender_ed25519_public_hex: &str,
) -> Result<JsValue, JsValue> {
    let envelope: exo_messaging::EncryptedEnvelope = from_json_str(envelope_json)?;

    ensure_fixed_hex_encoded_len::<32>("recipient X25519 secret", recipient_x25519_secret_hex)
        .map_err(|error| JsValue::from_str(&error))?;
    let recipient_secret = exo_messaging::X25519SecretKey::from_hex(recipient_x25519_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid recipient secret: {e}")))?;

    let sender_pk =
        parse_ed25519_public_key_hex("sender Ed25519 public key", sender_ed25519_public_hex)?;

    let plaintext = exo_messaging::unlock(&envelope, &recipient_secret, &sender_pk)
        .map_err(|e| JsValue::from_str(&format!("decryption failed: {e}")))?;

    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|e| JsValue::from_str(&format!("plaintext is not valid UTF-8: {e}")))?;

    to_js_value(&serde_json::json!({
        "plaintext": plaintext_str,
        "content_type": envelope.content_type,
    }))
}

/// Verify the sender's signature on an encrypted envelope without decrypting.
#[wasm_bindgen]
pub fn wasm_verify_message_signature(
    envelope_json: &str,
    sender_ed25519_public_hex: &str,
) -> Result<bool, JsValue> {
    let envelope: exo_messaging::EncryptedEnvelope = from_json_str(envelope_json)?;

    let sender_pk =
        parse_ed25519_public_key_hex("sender Ed25519 public key", sender_ed25519_public_hex)?;

    let signable = envelope
        .signing_payload()
        .map_err(|e| JsValue::from_str(&format!("signature payload failed: {e}")))?;
    Ok(exo_core::crypto::verify(
        &signable,
        &envelope.signature,
        &sender_pk,
    ))
}

fn ensure_fixed_hex_encoded_len<const N: usize>(label: &str, value: &str) -> Result<(), String> {
    let expected_hex_len = N
        .checked_mul(2)
        .ok_or_else(|| format!("{label} encoded length overflow"))?;
    if value.len() != expected_hex_len {
        return Err(format!(
            "{label} must be {N} bytes encoded as {expected_hex_len} hex characters"
        ));
    }
    Ok(())
}

fn decode_fixed_hex<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    ensure_fixed_hex_encoded_len::<N>(label, value)?;
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|error| format!("invalid {label} hex: {error}"))?;
    Ok(bytes)
}

fn parse_ed25519_public_key_hex(label: &str, value: &str) -> Result<exo_core::PublicKey, JsValue> {
    let bytes = decode_fixed_hex::<32>(label, value).map_err(|error| JsValue::from_str(&error))?;
    Ok(exo_core::PublicKey::from_bytes(bytes))
}

fn parse_ed25519_signature_hex(label: &str, value: &str) -> Result<exo_core::Signature, JsValue> {
    let bytes = decode_fixed_hex::<64>(label, value).map_err(|error| JsValue::from_str(&error))?;
    Ok(exo_core::Signature::from_bytes(bytes))
}

fn parse_claim_nonce_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > MAX_CLAIM_NONCE_HEX_LEN {
        return Err(CLAIM_NONCE_LIMIT_ERROR.to_owned());
    }
    let nonce = hex::decode(value).map_err(|error| format!("invalid claim nonce hex: {error}"))?;
    if nonce.len() > MAX_CLAIM_NONCE_BYTES {
        return Err(CLAIM_NONCE_LIMIT_ERROR.to_owned());
    }
    Ok(nonce)
}

fn parse_authorized_trustees_json(
    authorized_trustees_json: &str,
) -> Result<BTreeMap<exo_core::Did, exo_core::PublicKey>, JsValue> {
    let trustees: Vec<WasmAuthorizedTrustee> = from_json_bounded_vec(
        authorized_trustees_json,
        "authorized trustees",
        MAX_WASM_AUTHORIZED_TRUSTEES,
    )?;
    let mut authorized = BTreeMap::new();
    for trustee in trustees {
        let did = exo_core::Did::new(&trustee.did)
            .map_err(|e| JsValue::from_str(&format!("invalid trustee DID: {e}")))?;
        let public_key =
            parse_ed25519_public_key_hex("trustee Ed25519 public key", &trustee.public_key_hex)?;
        if authorized.insert(did.clone(), public_key).is_some() {
            return Err(JsValue::from_str(&format!(
                "duplicate authorized trustee: {}",
                did.as_str()
            )));
        }
    }
    Ok(authorized)
}

/// Compute the canonical death-verification initial confirmation payload.
///
/// Returns the CBOR bytes that `initiated_by_did` signs before calling
/// [`wasm_death_verification_new`].
#[wasm_bindgen]
pub fn wasm_death_verification_initial_signing_payload(
    subject_did: &str,
    initiated_by_did: &str,
    required_confirmations: u8,
    authorized_trustees_json: &str,
    claim_nonce_hex: &str,
    created_physical_ms: u64,
    created_logical: u32,
) -> Result<Vec<u8>, JsValue> {
    let subject = exo_core::Did::new(subject_did)
        .map_err(|e| JsValue::from_str(&format!("invalid subject DID: {e}")))?;
    let initiator = exo_core::Did::new(initiated_by_did)
        .map_err(|e| JsValue::from_str(&format!("invalid initiator DID: {e}")))?;
    let authorized_trustees = parse_authorized_trustees_json(authorized_trustees_json)?;
    let claim_nonce =
        parse_claim_nonce_hex(claim_nonce_hex).map_err(|error| JsValue::from_str(&error))?;
    let metadata = exo_messaging::death_trigger::DeathVerificationCreationMetadata::new(
        exo_core::Timestamp::new(created_physical_ms, created_logical),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid death verification metadata: {e}")))?;

    exo_messaging::death_trigger::initial_confirmation_signing_payload(
        &subject,
        &initiator,
        required_confirmations,
        &authorized_trustees,
        &claim_nonce,
        &metadata.created_at,
    )
    .map_err(|e| JsValue::from_str(&format!("death verification signing payload failed: {e}")))
}

/// Create a new death verification request.
///
/// `authorized_trustees_json` must be an array of
/// `{ "did": "...", "public_key_hex": "..." }` objects. `claim_nonce_hex`
/// and `initiator_signature_hex` bind the initiator's first confirmation to
/// this claim instance.
/// Returns the verification state as JSON.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
// WASM cannot take Rust metadata structs directly, so the death-verification
// creation boundary exposes the HLC metadata as primitive fields and validates
// it before touching the state machine.
pub fn wasm_death_verification_new(
    subject_did: &str,
    initiated_by_did: &str,
    required_confirmations: u8,
    authorized_trustees_json: &str,
    claim_nonce_hex: &str,
    initiator_signature_hex: &str,
    created_physical_ms: u64,
    created_logical: u32,
) -> Result<JsValue, JsValue> {
    let subject = exo_core::Did::new(subject_did)
        .map_err(|e| JsValue::from_str(&format!("invalid subject DID: {e}")))?;
    let initiator = exo_core::Did::new(initiated_by_did)
        .map_err(|e| JsValue::from_str(&format!("invalid initiator DID: {e}")))?;
    let authorized_trustees = parse_authorized_trustees_json(authorized_trustees_json)?;
    let claim_nonce =
        parse_claim_nonce_hex(claim_nonce_hex).map_err(|error| JsValue::from_str(&error))?;
    let initiator_signature =
        parse_ed25519_signature_hex("initiator confirmation signature", initiator_signature_hex)?;
    let metadata = exo_messaging::death_trigger::DeathVerificationCreationMetadata::new(
        exo_core::Timestamp::new(created_physical_ms, created_logical),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid death verification metadata: {e}")))?;

    let dv = exo_messaging::death_trigger::DeathVerification::new(
        subject,
        initiator,
        required_confirmations,
        authorized_trustees,
        claim_nonce,
        initiator_signature,
        metadata,
    )
    .map_err(|e| JsValue::from_str(&format!("death verification creation failed: {e}")))?;
    to_js_value(&dv)
}

/// Compute the canonical trustee confirmation payload for an existing claim.
///
/// Returns the CBOR bytes that `trustee_did` signs before calling
/// [`wasm_death_verification_confirm`].
#[wasm_bindgen]
pub fn wasm_death_verification_confirmation_signing_payload(
    state_json: &str,
    trustee_did: &str,
    confirmed_physical_ms: u64,
    confirmed_logical: u32,
) -> Result<Vec<u8>, JsValue> {
    let dv: exo_messaging::death_trigger::DeathVerification = from_json_str(state_json)?;
    let trustee = exo_core::Did::new(trustee_did)
        .map_err(|e| JsValue::from_str(&format!("invalid trustee DID: {e}")))?;
    let metadata = exo_messaging::death_trigger::DeathConfirmationMetadata::new(
        exo_core::Timestamp::new(confirmed_physical_ms, confirmed_logical),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid death confirmation metadata: {e}")))?;
    dv.confirmation_signing_payload(&trustee, &metadata.confirmed_at)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "death verification confirmation payload failed: {e}"
            ))
        })
}

/// Add a trustee confirmation to a death verification.
/// Returns `{ verified: bool, confirmations_remaining: number, state: object }`.
#[wasm_bindgen]
pub fn wasm_death_verification_confirm(
    state_json: &str,
    trustee_did: &str,
    trustee_public_key_hex: &str,
    signature_hex: &str,
    confirmed_physical_ms: u64,
    confirmed_logical: u32,
) -> Result<JsValue, JsValue> {
    let mut dv: exo_messaging::death_trigger::DeathVerification = from_json_str(state_json)?;
    let trustee = exo_core::Did::new(trustee_did)
        .map_err(|e| JsValue::from_str(&format!("invalid trustee DID: {e}")))?;
    let trustee_public_key =
        parse_ed25519_public_key_hex("trustee Ed25519 public key", trustee_public_key_hex)?;
    let signature = parse_ed25519_signature_hex("trustee confirmation signature", signature_hex)?;
    let metadata = exo_messaging::death_trigger::DeathConfirmationMetadata::new(
        exo_core::Timestamp::new(confirmed_physical_ms, confirmed_logical),
    )
    .map_err(|e| JsValue::from_str(&format!("invalid death confirmation metadata: {e}")))?;

    let verified = dv
        .confirm(trustee, trustee_public_key, signature, metadata)
        .map_err(|e| JsValue::from_str(&format!("confirmation failed: {e}")))?;

    to_js_value(&serde_json::json!({
        "verified": verified,
        "confirmations_remaining": dv.confirmations_remaining(),
        "state": dv,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_plaintext_bound_accepts_exact_limit_and_rejects_one_byte_over() {
        let exact = "a".repeat(exo_messaging::MAX_ENVELOPE_PLAINTEXT_LEN);
        validate_wasm_message_plaintext(&exact).expect("exact maximum plaintext is accepted");

        let oversized = "a".repeat(exo_messaging::MAX_ENVELOPE_PLAINTEXT_LEN + 1);
        assert_eq!(
            validate_wasm_message_plaintext(&oversized)
                .expect_err("one byte over maximum plaintext must be rejected"),
            WASM_MESSAGE_PLAINTEXT_LIMIT_ERROR
        );
    }

    #[test]
    fn wasm_prepare_checks_plaintext_before_parsing_or_cryptography() {
        let source = include_str!("messaging_bindings.rs");
        let production = source.split("\n#[cfg(test)]").next().unwrap_or(source);
        let prepare = production
            .split("pub fn wasm_prepare_encrypted_message")
            .nth(1)
            .expect("WASM encrypted-message constructor")
            .split("fn parse_x25519_keypair_hex")
            .next()
            .expect("WASM encrypted-message constructor body");
        let bound_check = prepare
            .find("validate_wasm_message_plaintext(plaintext)")
            .expect("WASM plaintext validation call");

        for operation in [
            "from_json_str(content_type_json)",
            "Did::new(sender_did)",
            "parse_x25519_keypair_hex",
            "prepare_envelope_for_signing_with_ephemeral",
        ] {
            let operation_index = prepare.find(operation).expect("bounded operation");
            assert!(
                bound_check < operation_index,
                "WASM plaintext bound must be checked before {operation}"
            );
        }
    }

    #[test]
    fn claim_nonce_decoder_accepts_64_bytes_and_rejects_65_before_decode() {
        let exact_hex = "ab".repeat(MAX_CLAIM_NONCE_BYTES);
        assert_eq!(
            parse_claim_nonce_hex(&exact_hex).expect("64 decoded nonce bytes are accepted"),
            vec![0xab; MAX_CLAIM_NONCE_BYTES]
        );

        let oversized_invalid_hex = "zz".repeat(MAX_CLAIM_NONCE_BYTES + 1);
        assert_eq!(
            parse_claim_nonce_hex(&oversized_invalid_hex)
                .expect_err("65 decoded nonce bytes must fail before hex decoding"),
            CLAIM_NONCE_LIMIT_ERROR
        );
    }

    #[test]
    fn fixed_size_key_and_signature_hex_lengths_are_checked_before_decode() {
        assert_eq!(
            decode_fixed_hex::<32>("test public key", &"AB".repeat(32))
                .expect("32-byte public key"),
            [0xab; 32]
        );
        assert_eq!(
            decode_fixed_hex::<64>("test signature", &"CD".repeat(64)).expect("64-byte signature"),
            [0xcd; 64]
        );

        assert_eq!(
            decode_fixed_hex::<32>("test public key", &"zz".repeat(33))
                .expect_err("33-byte key encoding must fail before hex decoding"),
            "test public key must be 32 bytes encoded as 64 hex characters"
        );
        assert_eq!(
            decode_fixed_hex::<64>("test signature", &"zz".repeat(65))
                .expect_err("65-byte signature encoding must fail before hex decoding"),
            "test signature must be 64 bytes encoded as 128 hex characters"
        );
    }

    #[test]
    fn both_nonce_taking_death_verification_exports_use_shared_decoder() {
        let source = include_str!("messaging_bindings.rs");
        let production = source.split("\n#[cfg(test)]").next().unwrap_or(source);
        let initial_payload = production
            .split("pub fn wasm_death_verification_initial_signing_payload")
            .nth(1)
            .and_then(|section| {
                section
                    .split("/// Create a new death verification request")
                    .next()
            })
            .expect("initial signing-payload export");
        let creation = production
            .split("pub fn wasm_death_verification_new")
            .nth(1)
            .and_then(|section| {
                section
                    .split("/// Compute the canonical trustee confirmation payload")
                    .next()
            })
            .expect("death-verification creation export");

        for section in [initial_payload, creation] {
            assert!(
                section.contains("parse_claim_nonce_hex(claim_nonce_hex)"),
                "each nonce-taking export must use the shared bounded decoder"
            );
            assert!(
                !section.contains("hex::decode(claim_nonce_hex)"),
                "nonce-taking exports must not bypass the bounded decoder"
            );
        }
        assert_eq!(
            production
                .matches("parse_claim_nonce_hex(claim_nonce_hex)")
                .count(),
            2,
            "exactly both nonce-taking primitive exports must call the shared decoder"
        );
    }
}
