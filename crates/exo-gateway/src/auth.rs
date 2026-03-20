//! Authentication middleware — DID-based authentication with signature verification.
//!
//! ## Security note
//!
//! `authenticate` currently validates:
//!   1. DID format (`did:exo:<id>`)
//!   2. Non-empty / non-zero signature bytes
//!   3. Timestamp freshness (±`FRESHNESS_WINDOW_MS`)
//!
//! Full Ed25519 cryptographic verification against the actor's public key
//! requires a DID resolver that maps `did:exo:*` to a `PublicKey`.  That
//! integration is tracked as a follow-up blocker and must land before the
//! gateway is exposed to untrusted callers on a public network.
use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, Result};

/// Maximum age (or future skew) of a request timestamp in milliseconds.
/// Requests outside this window are rejected to prevent replay attacks.
const FRESHNESS_WINDOW_MS: u64 = 300_000; // 5 minutes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub actor_did: String,
    pub action: String,
    pub body_hash: Hash256,
    pub signature: Signature,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedActor {
    pub did: Did,
    pub authenticated_at: Timestamp,
}

pub fn authenticate(request: &Request) -> Result<AuthenticatedActor> {
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

    // TODO: verify Ed25519 signature against the public key resolved from
    // `did` via the DID registry (EXOCHAIN-REM-002).  Until the resolver
    // is wired, any non-empty signature from a valid DID is accepted.

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
    let skew_ms = if now_ms >= req_ms {
        now_ms - req_ms
    } else {
        req_ms - now_ms
    };
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
mod tests {
    use super::*;

    fn sig() -> Signature {
        let mut s = [0u8; 64];
        s[0] = 1;
        Signature::from_bytes(s)
    }

    // In test mode, freshness check is disabled, so Timestamp::ZERO is
    // accepted.  Production code uses check_freshness() via #[cfg(not(test))].
    fn req_ts() -> Timestamp {
        Timestamp::ZERO
    }

    #[test]
    fn auth_valid() {
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: sig(),
            timestamp: req_ts(),
        };
        let a = authenticate(&r).unwrap();
        assert_eq!(a.did.as_str(), "did:exo:alice");
    }
    #[test]
    fn auth_invalid_did() {
        let r = Request {
            actor_did: "bad".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: sig(),
            timestamp: req_ts(),
        };
        assert!(authenticate(&r).is_err());
    }
    #[test]
    fn auth_empty_sig() {
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::from_bytes([0u8; 64]),
            timestamp: req_ts(),
        };
        assert!(authenticate(&r).is_err());
    }
    #[test]
    fn auth_empty_sig_variant() {
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash: Hash256::ZERO,
            signature: Signature::Empty,
            timestamp: req_ts(),
        };
        assert!(authenticate(&r).is_err());
    }
    #[test]
    fn request_serde() {
        let r = Request {
            actor_did: "did:exo:a".into(),
            action: "r".into(),
            body_hash: Hash256::ZERO,
            signature: sig(),
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
