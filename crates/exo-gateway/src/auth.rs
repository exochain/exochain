//! Authentication middleware — DID-based authentication with signature verification.
//!
//! ## Validation steps
//!
//! `authenticate` validates:
//!   1. DID format (`did:exo:<id>`)
//!   2. Non-empty / non-zero signature bytes
//!   3. Timestamp freshness (±`FRESHNESS_WINDOW_MS`)
//!   4. Ed25519 signature via `exo_identity::did_verification::verify_did_signature`
//!      against the first active verification method in the resolved DID document
use exo_core::{Did, Hash256, Signature, Timestamp};
use exo_identity::{did::DidRegistry, did_verification::verify_did_signature};
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, Result};

/// Maximum age (or future skew) of a request timestamp in milliseconds.
/// Requests outside this window are rejected to prevent replay attacks.
const FRESHNESS_WINDOW_MS: u64 = 300_000; // 5 minutes

/// An incoming gateway request with actor identity and signed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub actor_did: String,
    pub action: String,
    pub body_hash: Hash256,
    pub signature: Signature,
    pub timestamp: Timestamp,
}

/// A successfully authenticated actor with their resolved DID and auth timestamp.
#[derive(Debug, Clone)]
pub struct AuthenticatedActor {
    pub did: Did,
    pub authenticated_at: Timestamp,
}

/// Authenticate a request by validating DID format, signature freshness,
/// and cryptographic Ed25519 signature against the registered DID document.
///
/// # Errors
///
/// - `AuthenticationFailed` if the DID format is invalid
/// - `AuthenticationFailed` if the signature is empty
/// - `AuthenticationFailed` if the timestamp is outside the freshness window
/// - `AuthenticationFailed` if the DID is not found in `registry`
/// - `AuthenticationFailed` if the DID has no active verification method
/// - `AuthenticationFailed` if signature verification fails
pub fn authenticate(request: &Request, registry: &DidRegistry) -> Result<AuthenticatedActor> {
    // 1. Validate DID format.
    let did = Did::new(&request.actor_did).map_err(|_| GatewayError::AuthenticationFailed {
        reason: format!("invalid DID: {}", request.actor_did),
    })?;

    // 2. Reject empty / all-zero signatures (covers Signature::Empty and
    //    Signature::Ed25519([0u8; 64])).
    if request.signature.is_empty() {
        return Err(GatewayError::AuthenticationFailed {
            reason: "empty signature".into(),
        });
    }

    // 3. Timestamp freshness — guard against replay attacks.
    //    Disabled in test builds so unit tests can use fixed Timestamps
    //    without a live wall clock.
    #[cfg(not(test))]
    check_freshness(&request.timestamp)?;

    // 4. Resolve DID document from the registry.
    let doc = registry
        .resolve(&did)
        .ok_or_else(|| GatewayError::AuthenticationFailed {
            reason: format!("DID not registered: {}", request.actor_did),
        })?;

    // 5. Find the first active verification method.
    let method = doc
        .verification_methods
        .iter()
        .find(|m| m.active)
        .ok_or_else(|| GatewayError::AuthenticationFailed {
            reason: format!(
                "no active verification method for DID: {}",
                request.actor_did
            ),
        })?;

    // 6. Cryptographically verify the Ed25519 signature over body_hash.
    verify_did_signature(
        doc,
        &method.id,
        request.body_hash.as_bytes(),
        &request.signature,
    )
    .map_err(|e| GatewayError::AuthenticationFailed {
        reason: format!("signature verification failed: {e}"),
    })?;

    Ok(AuthenticatedActor {
        did,
        authenticated_at: request.timestamp,
    })
}

/// Reject requests whose timestamp deviates from `now` by more than
/// `FRESHNESS_WINDOW_MS`.
fn check_freshness(ts: &Timestamp) -> Result<()> {
    let now_ms = Timestamp::now_utc().physical_ms;
    let req_ms = ts.physical_ms;
    let skew_ms = now_ms.abs_diff(req_ms);
    if skew_ms > FRESHNESS_WINDOW_MS {
        return Err(GatewayError::AuthenticationFailed {
            reason: format!(
                "request timestamp outside freshness window: skew {skew_ms}ms (max {FRESHNESS_WINDOW_MS}ms)"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::crypto::{generate_keypair, sign};
    use exo_identity::did::{DidDocument, DidRegistry, VerificationMethod};

    use super::*;

    // In test mode, freshness check is disabled, so Timestamp::ZERO is
    // accepted.  Production code uses check_freshness() via #[cfg(not(test))].
    fn req_ts() -> Timestamp {
        Timestamp::ZERO
    }

    /// Build an in-memory registry with a single DID `did:exo:alice` registered
    /// under a freshly generated Ed25519 key pair.  Returns the registry and the
    /// signing key so callers can produce valid signatures.
    fn registry_with_alice() -> (DidRegistry, exo_core::SecretKey) {
        let did = Did::new("did:exo:alice").unwrap();
        let (pk, sk) = generate_keypair();
        let multibase = format!("z{}", bs58::encode(pk.as_bytes()).into_string());
        let doc = DidDocument {
            id: did.clone(),
            public_keys: vec![pk],
            authentication: vec![],
            verification_methods: vec![VerificationMethod {
                id: "did:exo:alice#key-1".into(),
                key_type: "Ed25519VerificationKey2020".into(),
                controller: did,
                public_key_multibase: multibase,
                version: 1,
                active: true,
                valid_from: 0,
                revoked_at: None,
            }],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: Timestamp::ZERO,
            updated: Timestamp::ZERO,
            revoked: false,
        };
        let mut reg = DidRegistry::new();
        reg.register(doc).unwrap();
        (reg, sk)
    }

    #[test]
    fn auth_valid() {
        let (reg, sk) = registry_with_alice();
        let body_hash = Hash256::ZERO;
        let signature = sign(body_hash.as_bytes(), &sk);
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash,
            signature,
            timestamp: req_ts(),
        };
        let a = authenticate(&r, &reg).unwrap();
        assert_eq!(a.did.as_str(), "did:exo:alice");
    }

    #[test]
    fn auth_invalid_did() {
        let (reg, _) = registry_with_alice();
        let r = Request {
            actor_did: "bad".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::from_bytes({
                let mut s = [0u8; 64];
                s[0] = 1;
                s
            }),
            timestamp: req_ts(),
        };
        assert!(authenticate(&r, &reg).is_err());
    }

    #[test]
    fn auth_empty_sig() {
        let (reg, _) = registry_with_alice();
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::from_bytes([0u8; 64]),
            timestamp: req_ts(),
        };
        assert!(authenticate(&r, &reg).is_err());
    }

    #[test]
    fn auth_empty_sig_variant() {
        let (reg, _) = registry_with_alice();
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::Empty,
            timestamp: req_ts(),
        };
        assert!(authenticate(&r, &reg).is_err());
    }

    #[test]
    fn auth_wrong_signature_fails() {
        let (reg, _sk) = registry_with_alice();
        // Sign with a different key — verification must fail.
        let (_pk2, sk2) = generate_keypair();
        let body_hash = Hash256::ZERO;
        let bad_sig = sign(body_hash.as_bytes(), &sk2);
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash,
            signature: bad_sig,
            timestamp: req_ts(),
        };
        assert!(authenticate(&r, &reg).is_err());
    }

    #[test]
    fn auth_did_not_registered_fails() {
        let (reg, _) = registry_with_alice();
        // bob is not in the registry.
        let (_, sk_bob) = generate_keypair();
        let body_hash = Hash256::ZERO;
        let sig = sign(body_hash.as_bytes(), &sk_bob);
        let r = Request {
            actor_did: "did:exo:bob".into(),
            action: "read".into(),
            body_hash,
            signature: sig,
            timestamp: req_ts(),
        };
        assert!(authenticate(&r, &reg).is_err());
    }

    #[test]
    fn request_serde() {
        let r = Request {
            actor_did: "did:exo:a".into(),
            action: "r".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::from_bytes({
                let mut s = [0u8; 64];
                s[0] = 1;
                s
            }),
            timestamp: req_ts(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(!j.is_empty());
    }

    #[test]
    fn freshness_check_passes_recent() {
        let ts = Timestamp::now_utc();
        assert!(check_freshness(&ts).is_ok());
    }

    #[test]
    fn freshness_check_rejects_stale() {
        // physical_ms = 1 is Jan 1 1970 — way outside any freshness window.
        let stale = Timestamp::new(1, 0);
        assert!(check_freshness(&stale).is_err());
    }
}
