//! Consent bindings: bailment lifecycle, consent enforcement

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
fn consent_bridge_error(_message: impl AsRef<str>) -> JsValue {
    JsValue::NULL
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
fn consent_bridge_error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

fn untrusted_wasm_bailment_termination_error() -> JsValue {
    consent_bridge_error(
        "WASM bailment termination cannot trust caller-supplied DID key material; use wasm_bailment_termination_payload and submit the signed request to a core runtime adapter with a trusted DID registry",
    )
}

/// Propose a new bailment (consent-conditioned data sharing)
#[wasm_bindgen]
pub fn wasm_propose_bailment(
    bailor_did: &str,
    bailee_did: &str,
    terms: &[u8],
    bailment_type_json: &str,
    bailment_id: &str,
    created_json: &str,
) -> Result<JsValue, JsValue> {
    let bailor = exo_core::Did::new(bailor_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let bailee = exo_core::Did::new(bailee_did)
        .map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    let bailment_type: exo_consent::BailmentType = from_json_str(bailment_type_json)?;
    let created: exo_core::Timestamp = from_json_str(created_json)?;
    let bailment = exo_consent::bailment::propose(
        &bailor,
        &bailee,
        terms,
        bailment_type,
        bailment_id,
        created,
    )
    .map_err(|e| JsValue::from_str(&format!("Propose error: {e}")))?;
    to_js_value(&bailment)
}

/// Check if a bailment is currently active
#[wasm_bindgen]
pub fn wasm_bailment_is_active(bailment_json: &str, now_json: &str) -> Result<bool, JsValue> {
    let bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    let now: exo_core::Timestamp = from_json_str(now_json)?;
    Ok(exo_consent::bailment::is_active(&bailment, &now))
}

/// Accept a proposed bailment (bailee countersigns, status → Active).
///
/// `bailee_public_key_json` — JSON-serialized bailee PublicKey. Required
/// to verify `signature_json` against the canonical bailment payload.
/// Closes GAP-012: previously this binding passed the signature through
/// unchecked, which flipped bailments to Active on any non-empty bytes.
///
/// `signature_json` — JSON-serialized bailee Signature over
/// `exo_consent::bailment::signing_payload(&bailment)`.
#[wasm_bindgen]
pub fn wasm_accept_bailment(
    bailment_json: &str,
    bailee_public_key_json: &str,
    signature_json: &str,
) -> Result<JsValue, JsValue> {
    let mut bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    let pk: exo_core::PublicKey = from_json_str(bailee_public_key_json)?;
    let sig: exo_core::Signature = from_json_str(signature_json)?;
    exo_consent::bailment::accept(&mut bailment, &pk, &sig)
        .map_err(|e| JsValue::from_str(&format!("Accept error: {e}")))?;
    to_js_value(&bailment)
}

/// Compute the canonical signing payload for a bailment.
///
/// Returns the CBOR bytes that the bailee must sign for
/// [`wasm_accept_bailment`] to succeed. Mirrors
/// [`exo_consent::bailment::signing_payload`].
///
/// # Errors
/// Returns the underlying consent error serialized to a string if the
/// bailment cannot be encoded.
#[wasm_bindgen]
pub fn wasm_bailment_signing_payload(bailment_json: &str) -> Result<Vec<u8>, JsValue> {
    let bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    exo_consent::bailment::signing_payload(&bailment)
        .map_err(|e| JsValue::from_str(&format!("Signing payload error: {e}")))
}

/// Compute the canonical termination payload for external signing.
#[wasm_bindgen]
pub fn wasm_bailment_termination_payload(
    bailment_json: &str,
    actor_did: &str,
) -> Result<Vec<u8>, JsValue> {
    let bailment: exo_consent::Bailment = from_json_str(bailment_json)?;
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;
    exo_consent::bailment::termination_signing_payload(&bailment, &actor)
        .map_err(|e| JsValue::from_str(&format!("Termination payload error: {e}")))
}

/// Unsigned bailment termination is disabled.
///
/// Use [`wasm_bailment_termination_payload`] to construct the signable bytes,
/// sign them outside WASM, then submit the signed request to a core runtime
/// adapter that owns trusted DID resolution.
#[wasm_bindgen]
pub fn wasm_terminate_bailment(_bailment_json: &str, _actor_did: &str) -> Result<JsValue, JsValue> {
    Err(consent_bridge_error(
        "unsigned bailment termination is disabled; use wasm_bailment_termination_payload and submit the signed request to a core runtime adapter with a trusted DID registry",
    ))
}

/// Refuse WASM-local bailment termination from caller-supplied identity data.
///
/// WASM can construct the canonical payload for external signing, but it cannot
/// prove that a caller-supplied DID-to-key binding came from the trusted
/// EXOCHAIN identity registry. Submit the signed payload to a core runtime
/// adapter that owns trusted DID resolution instead.
#[wasm_bindgen]
pub fn wasm_terminate_bailment_signed(
    _bailment_json: &str,
    _actor_did: &str,
    _public_keys_json: &str,
    _signature_json: &str,
) -> Result<JsValue, JsValue> {
    Err(untrusted_wasm_bailment_termination_error())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use exo_core::{Timestamp, crypto};

    use super::*;

    fn did(value: &str) -> exo_core::Did {
        exo_core::Did::new(value).expect("valid did")
    }

    fn active_bailment() -> exo_consent::Bailment {
        let bailor = did("did:exo:alice");
        let bailee = did("did:exo:bob");
        let mut bailment = exo_consent::bailment::propose(
            &bailor,
            &bailee,
            b"wasm consent terms",
            exo_consent::BailmentType::Custody,
            "wasm-consent-test",
            Timestamp::new(1_000, 0),
        )
        .expect("proposal");
        let (bailee_pk, bailee_sk) = crypto::generate_keypair();
        let acceptance_payload =
            exo_consent::bailment::signing_payload(&bailment).expect("acceptance payload");
        let acceptance_signature = crypto::sign(&acceptance_payload, &bailee_sk);
        exo_consent::bailment::accept(&mut bailment, &bailee_pk, &acceptance_signature)
            .expect("accept");
        bailment
    }

    fn public_keys_json(did: &exo_core::Did, public_key: &exo_core::PublicKey) -> String {
        serde_json::to_string(&vec![(did.as_str(), hex::encode(public_key.as_bytes()))])
            .expect("public keys json")
    }

    fn signature_json(signature: &exo_core::Signature) -> String {
        serde_json::to_string(signature).expect("signature json")
    }

    #[test]
    fn bailment_termination_payload_bridge_matches_core_payload() {
        let bailment = active_bailment();
        let bailment_json = serde_json::to_string(&bailment).expect("bailment json");
        let actor = did("did:exo:alice");
        let core_payload =
            exo_consent::bailment::termination_signing_payload(&bailment, &actor).expect("payload");

        let bridge_payload =
            wasm_bailment_termination_payload(&bailment_json, actor.as_str()).expect("payload");

        assert_eq!(bridge_payload, core_payload);
    }

    #[test]
    fn wasm_terminate_bailment_signed_rejects_missing_actor_key() {
        let bailment = active_bailment();
        let bailment_json = serde_json::to_string(&bailment).expect("bailment json");
        let actor = did("did:exo:alice");
        let other = did("did:exo:charlie");
        let (actor_pk, actor_sk) = crypto::generate_keypair();
        let payload =
            exo_consent::bailment::termination_signing_payload(&bailment, &actor).expect("payload");
        let signature = crypto::sign(&payload, &actor_sk);

        let result = wasm_terminate_bailment_signed(
            &bailment_json,
            actor.as_str(),
            &public_keys_json(&other, &actor_pk),
            &signature_json(&signature),
        );

        assert!(result.is_err(), "missing actor key must fail");
    }

    #[test]
    fn wasm_terminate_bailment_signed_rejects_caller_substituted_actor_key() {
        let bailment = active_bailment();
        let bailment_json = serde_json::to_string(&bailment).expect("bailment json");
        let actor = did("did:exo:alice");
        let (attacker_pk, attacker_sk) = crypto::generate_keypair();
        let payload =
            exo_consent::bailment::termination_signing_payload(&bailment, &actor).expect("payload");
        let attacker_signature = crypto::sign(&payload, &attacker_sk);

        let result = wasm_terminate_bailment_signed(
            &bailment_json,
            actor.as_str(),
            &public_keys_json(&actor, &attacker_pk),
            &signature_json(&attacker_signature),
        );

        assert!(
            result.is_err(),
            "WASM consent termination must not trust a caller-supplied DID-to-key binding"
        );
    }

    #[test]
    fn wasm_terminate_bailment_signed_rejects_wrong_signature() {
        let bailment = active_bailment();
        let bailment_json = serde_json::to_string(&bailment).expect("bailment json");
        let actor = did("did:exo:alice");
        let (actor_pk, _actor_sk) = crypto::generate_keypair();
        let (_wrong_pk, wrong_sk) = crypto::generate_keypair();
        let payload =
            exo_consent::bailment::termination_signing_payload(&bailment, &actor).expect("payload");
        let wrong_signature = crypto::sign(&payload, &wrong_sk);

        let result = wasm_terminate_bailment_signed(
            &bailment_json,
            actor.as_str(),
            &public_keys_json(&actor, &actor_pk),
            &signature_json(&wrong_signature),
        );

        assert!(result.is_err(), "wrong signature must fail");
    }
}
