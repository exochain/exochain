//! Messaging bindings: X25519 key exchange, message encrypt/decrypt, death verification

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Generate a new X25519 keypair for Diffie-Hellman key exchange.
/// Returns `{ public_key_hex, secret_key_hex }`.
#[wasm_bindgen]
pub fn wasm_generate_x25519_keypair() -> Result<JsValue, JsValue> {
    let kp = exo_messaging::kex::X25519KeyPair::generate();
    to_js_value(&serde_json::json!({
        "public_key_hex": kp.public.to_hex(),
        "secret_key_hex": kp.secret.to_hex(),
    }))
}

/// Derive an X25519 public key from a secret key hex string.
/// Returns `{ public_key_hex }`.
#[wasm_bindgen]
pub fn wasm_x25519_public_from_secret(secret_hex: &str) -> Result<JsValue, JsValue> {
    let secret = exo_messaging::X25519SecretKey::from_hex(secret_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid secret key: {e}")))?;
    let kp = exo_messaging::kex::X25519KeyPair::from_secret_bytes(secret.0);
    to_js_value(&serde_json::json!({
        "public_key_hex": kp.public.to_hex(),
    }))
}

/// Encrypt a message for a specific recipient (Lock & Send).
///
/// # Parameters
/// - `plaintext`: The message content (UTF-8 string)
/// - `content_type_json`: Content type as JSON string (e.g., `"\"Text\""`)
/// - `sender_did`: Sender's DID string
/// - `recipient_did`: Recipient's DID string
/// - `sender_signing_key_hex`: Sender's Ed25519 secret key (hex)
/// - `recipient_x25519_public_hex`: Recipient's X25519 public key (hex)
/// - `release_on_death`: Whether to release after sender's death
/// - `release_delay_hours`: Hours to wait after death verification
///
/// # Returns
/// The encrypted envelope as JSON.
#[wasm_bindgen]
pub fn wasm_encrypt_message(
    plaintext: &str,
    content_type_json: &str,
    sender_did: &str,
    recipient_did: &str,
    sender_signing_key_hex: &str,
    recipient_x25519_public_hex: &str,
    release_on_death: bool,
    release_delay_hours: u32,
) -> Result<JsValue, JsValue> {
    let content_type: exo_messaging::ContentType = from_json_str(content_type_json)?;

    let sender = exo_core::Did::new(sender_did)
        .map_err(|e| JsValue::from_str(&format!("invalid sender DID: {e}")))?;
    let recipient = exo_core::Did::new(recipient_did)
        .map_err(|e| JsValue::from_str(&format!("invalid recipient DID: {e}")))?;

    let sk_bytes = hex::decode(sender_signing_key_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid sender key hex: {e}")))?;
    if sk_bytes.len() != 32 {
        return Err(JsValue::from_str("sender signing key must be 32 bytes"));
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let sender_sk = exo_core::SecretKey::from_bytes(sk_arr);

    let recipient_pub = exo_messaging::X25519PublicKey::from_hex(recipient_x25519_public_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid recipient X25519 key: {e}")))?;

    let envelope = exo_messaging::lock_and_send(
        plaintext.as_bytes(),
        content_type,
        &sender,
        &recipient,
        &sender_sk,
        &recipient_pub,
        release_on_death,
        release_delay_hours,
    )
    .map_err(|e| JsValue::from_str(&format!("encryption failed: {e}")))?;

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

    let recipient_secret = exo_messaging::X25519SecretKey::from_hex(recipient_x25519_secret_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid recipient secret: {e}")))?;

    let pk_bytes = hex::decode(sender_ed25519_public_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid sender public key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str(
            "sender Ed25519 public key must be 32 bytes",
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let sender_pk = exo_core::PublicKey::from_bytes(pk_arr);

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

    let pk_bytes = hex::decode(sender_ed25519_public_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid public key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str("public key must be 32 bytes"));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let sender_pk = exo_core::PublicKey::from_bytes(pk_arr);

    let signable = envelope.signable_bytes();
    Ok(exo_core::crypto::verify(
        &signable,
        &envelope.signature,
        &sender_pk,
    ))
}

/// Create a new death verification request.
/// Returns the verification state as JSON.
#[wasm_bindgen]
pub fn wasm_death_verification_new(
    subject_did: &str,
    initiated_by_did: &str,
    required_confirmations: u8,
) -> Result<JsValue, JsValue> {
    let subject = exo_core::Did::new(subject_did)
        .map_err(|e| JsValue::from_str(&format!("invalid subject DID: {e}")))?;
    let initiator = exo_core::Did::new(initiated_by_did)
        .map_err(|e| JsValue::from_str(&format!("invalid initiator DID: {e}")))?;

    let dv = exo_messaging::death_trigger::DeathVerification::new(
        subject,
        initiator,
        required_confirmations,
    );
    to_js_value(&dv)
}

/// Add a trustee confirmation to a death verification.
/// Returns `{ verified: bool, confirmations_remaining: number, state: object }`.
#[wasm_bindgen]
pub fn wasm_death_verification_confirm(
    state_json: &str,
    trustee_did: &str,
) -> Result<JsValue, JsValue> {
    let mut dv: exo_messaging::death_trigger::DeathVerification = from_json_str(state_json)?;
    let trustee = exo_core::Did::new(trustee_did)
        .map_err(|e| JsValue::from_str(&format!("invalid trustee DID: {e}")))?;

    let verified = dv
        .confirm(trustee)
        .map_err(|e| JsValue::from_str(&format!("confirmation failed: {e}")))?;

    to_js_value(&serde_json::json!({
        "verified": verified,
        "confirmations_remaining": dv.confirmations_remaining(),
        "state": dv,
    }))
}
