//! Session proof-of-possession helpers for 0dentity.
//!
//! Session bootstrap and mutating authenticated requests are signed over
//! domain-tagged CBOR payloads so the same logical authorization challenge has
//! one deterministic byte representation.

use exo_core::types::{Did, Hash256, PublicKey, Signature};
use serde::Serialize;

pub(crate) const BOOTSTRAP_SIGNING_DOMAIN: &str = "exo.zerodentity.session_bootstrap.v1";
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
pub(crate) const CLAIM_SUBMISSION_SIGNING_DOMAIN: &str = "exo.zerodentity.claim_submission.v1";
pub(crate) const REQUEST_SIGNING_DOMAIN: &str = "exo.zerodentity.session_request.v1";
pub(crate) const SESSION_TOKEN_DOMAIN: &str = "exo.zerodentity.session_token.v1";

#[derive(Serialize)]
struct BootstrapSigningPayload<'a> {
    domain: &'static str,
    challenge_id: &'a str,
    subject_did: &'a str,
    public_key: &'a PublicKey,
}

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
#[derive(Serialize)]
struct ClaimSubmissionSigningPayload<'a> {
    domain: &'static str,
    subject_did: &'a str,
    claim_type: &'a str,
    provider: Option<&'a str>,
    verification_channel: Option<&'a str>,
    created_ms: u64,
    public_key: &'a PublicKey,
}

#[derive(Serialize)]
struct RequestSigningPayload<'a> {
    domain: &'static str,
    method: &'a str,
    path_and_query: &'a str,
    session_token: &'a str,
    nonce: &'a str,
    body_hash: &'a Hash256,
}

#[derive(Serialize)]
struct SessionTokenPayload<'a> {
    domain: &'static str,
    challenge_id: &'a str,
    subject_did: &'a str,
    public_key: &'a PublicKey,
    bootstrap_signature: &'a Signature,
    hmac_secret: &'a [u8; 32],
}

fn encode_cbor<T: Serialize>(payload: &T) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    ciborium::into_writer(payload, &mut encoded)
        .map_err(|e| format!("canonical CBOR encoding failed: {e:?}"))?;
    Ok(encoded)
}

pub(crate) fn bootstrap_signing_payload(
    challenge_id: &str,
    subject_did: &Did,
    public_key: &PublicKey,
) -> Result<Vec<u8>, String> {
    encode_cbor(&BootstrapSigningPayload {
        domain: BOOTSTRAP_SIGNING_DOMAIN,
        challenge_id,
        subject_did: subject_did.as_str(),
        public_key,
    })
}

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
pub(crate) fn claim_submission_signing_payload(
    subject_did: &Did,
    claim_type: &str,
    provider: Option<&str>,
    verification_channel: Option<&str>,
    created_ms: u64,
    public_key: &PublicKey,
) -> Result<Vec<u8>, String> {
    encode_cbor(&ClaimSubmissionSigningPayload {
        domain: CLAIM_SUBMISSION_SIGNING_DOMAIN,
        subject_did: subject_did.as_str(),
        claim_type,
        provider,
        verification_channel,
        created_ms,
        public_key,
    })
}

pub(crate) fn request_signing_payload(
    method: &str,
    path_and_query: &str,
    session_token: &str,
    nonce: &str,
    body_hash: &Hash256,
) -> Result<Vec<u8>, String> {
    encode_cbor(&RequestSigningPayload {
        domain: REQUEST_SIGNING_DOMAIN,
        method,
        path_and_query,
        session_token,
        nonce,
        body_hash,
    })
}

pub(crate) fn session_token_from_bootstrap(
    challenge_id: &str,
    subject_did: &Did,
    public_key: &PublicKey,
    bootstrap_signature: &Signature,
    hmac_secret: &[u8; 32],
) -> Result<String, String> {
    let encoded = encode_cbor(&SessionTokenPayload {
        domain: SESSION_TOKEN_DOMAIN,
        challenge_id,
        subject_did: subject_did.as_str(),
        public_key,
        bootstrap_signature,
        hmac_secret,
    })?;
    Ok(hex::encode(Hash256::digest(&encoded).as_bytes()))
}

pub(crate) fn public_key_from_hex(value: &str) -> Result<PublicKey, String> {
    let bytes = hex::decode(value).map_err(|_| "public_key must be hex".to_owned())?;
    if bytes.len() != 32 {
        return Err(format!("public_key must be 32 bytes, got {}", bytes.len()));
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("public_key must not be all zero".to_owned());
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(public_key))
}

pub(crate) fn signature_from_hex(value: &str) -> Result<Signature, String> {
    let bytes = hex::decode(value).map_err(|_| "signature must be hex".to_owned())?;
    if bytes.len() != 64 {
        return Err(format!("signature must be 64 bytes, got {}", bytes.len()));
    }

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(signature))
}

pub(crate) fn did_from_public_key(public_key: &PublicKey) -> Result<Did, String> {
    let key_hash = Hash256::digest(public_key.as_bytes());
    let method_specific = bs58::encode(key_hash.as_bytes()).into_string();
    Did::new(&format!("did:exo:{method_specific}"))
        .map_err(|e| format!("public key DID derivation failed: {e}"))
}

pub(crate) fn public_key_from_session_bytes(value: &[u8]) -> Result<PublicKey, String> {
    if value.len() != 32 {
        return Err(format!(
            "session public key must be 32 bytes, got {}",
            value.len()
        ));
    }
    if value.iter().all(|byte| *byte == 0) {
        return Err("session public key must not be all zero".to_owned());
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(value);
    Ok(PublicKey::from_bytes(public_key))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use exo_core::types::Hash256;

    use super::*;

    fn must<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    fn did() -> Did {
        must(Did::new("did:exo:session-auth"))
    }

    fn public_key() -> PublicKey {
        PublicKey::from_bytes([7u8; 32])
    }

    #[test]
    fn bootstrap_payload_is_deterministic() {
        let first = must(bootstrap_signing_payload(
            "challenge-1",
            &did(),
            &public_key(),
        ));
        let second = must(bootstrap_signing_payload(
            "challenge-1",
            &did(),
            &public_key(),
        ));
        assert_eq!(first, second);
    }

    #[test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    fn did_derivation_is_deterministic_and_did_formatted() {
        let first = must(did_from_public_key(&public_key()));
        let second = must(did_from_public_key(&public_key()));

        assert_eq!(first, second);
        assert!(first.as_str().starts_with("did:exo:"));
    }

    #[test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    fn claim_submission_payload_is_domain_separated_and_deterministic() {
        let did = did();
        let first = must(claim_submission_signing_payload(
            &did,
            "Email",
            None,
            Some("Email"),
            123,
            &public_key(),
        ));
        let second = must(claim_submission_signing_payload(
            &did,
            "Email",
            None,
            Some("Email"),
            123,
            &public_key(),
        ));
        let different_time = must(claim_submission_signing_payload(
            &did,
            "Email",
            None,
            Some("Email"),
            124,
            &public_key(),
        ));

        assert_eq!(first, second);
        assert_ne!(first, different_time);
        assert!(
            first
                .windows(CLAIM_SUBMISSION_SIGNING_DOMAIN.len())
                .any(|w| { w == CLAIM_SUBMISSION_SIGNING_DOMAIN.as_bytes() })
        );
    }

    #[test]
    fn request_payload_changes_with_nonce_and_body() {
        let body_a = Hash256::digest(b"a");
        let body_b = Hash256::digest(b"b");
        let first = must(request_signing_payload(
            "POST", "/path", "token", "nonce-1", &body_a,
        ));
        let different_nonce = must(request_signing_payload(
            "POST", "/path", "token", "nonce-2", &body_a,
        ));
        let different_body = must(request_signing_payload(
            "POST", "/path", "token", "nonce-1", &body_b,
        ));

        assert_ne!(first, different_nonce);
        assert_ne!(first, different_body);
    }

    #[test]
    fn session_token_is_deterministic_and_bound_to_bootstrap_material() {
        let did = did();
        let public_key = public_key();
        let signature = Signature::from_bytes([9u8; 64]);
        let secret = [8u8; 32];

        let first = must(session_token_from_bootstrap(
            "challenge-1",
            &did,
            &public_key,
            &signature,
            &secret,
        ));
        let second = must(session_token_from_bootstrap(
            "challenge-1",
            &did,
            &public_key,
            &signature,
            &secret,
        ));
        let different_challenge = must(session_token_from_bootstrap(
            "challenge-2",
            &did,
            &public_key,
            &signature,
            &secret,
        ));
        let different_signature = must(session_token_from_bootstrap(
            "challenge-1",
            &did,
            &public_key,
            &Signature::from_bytes([10u8; 64]),
            &secret,
        ));

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(first, different_challenge);
        assert_ne!(first, different_signature);
    }

    #[test]
    fn parsers_reject_wrong_lengths_and_zero_key() {
        assert!(public_key_from_hex(&hex::encode([0u8; 32])).is_err());
        assert!(public_key_from_hex(&hex::encode([1u8; 31])).is_err());
        assert!(signature_from_hex(&hex::encode([1u8; 63])).is_err());
    }
}
