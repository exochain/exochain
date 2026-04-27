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
//!
//! ## Multi-credential support
//!
//! `resolve_credential` accepts any [`Credential`] variant (DID signature, API key,
//! or bearer token) and resolves it to an [`AuthenticatedActor`].  Every credential
//! resolves to a DID — there is no identity outside the DID system.
use std::collections::BTreeMap;

use exo_core::{Did, Hash256, Signature, Timestamp};
use exo_identity::{did_verification::verify_did_signature, registry::DidRegistry};
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, Result};

/// Maximum age (or future skew) of a request timestamp in milliseconds.
/// Requests outside this window are rejected to prevent replay attacks.
const FRESHNESS_WINDOW_MS: u64 = 300_000; // 5 minutes

// ---------------------------------------------------------------------------
// Existing types (backward-compatible)
// ---------------------------------------------------------------------------

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

/// Caller-supplied metadata for an authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationMetadata {
    pub observed_at: Timestamp,
}

impl AuthenticationMetadata {
    /// Validate caller-supplied authentication metadata.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::BadRequest` if `observed_at` is `Timestamp::ZERO`.
    pub fn new(observed_at: Timestamp) -> Result<Self> {
        if observed_at == Timestamp::ZERO {
            return Err(GatewayError::BadRequest(
                "authentication observed_at must be caller-supplied and non-zero".into(),
            ));
        }
        Ok(Self { observed_at })
    }
}

// ---------------------------------------------------------------------------
// Credential enum
// ---------------------------------------------------------------------------

/// Supported authentication credential types.
/// All credentials resolve to a DID — there is no identity outside the DID system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credential {
    /// Direct DID signature authentication (strongest).
    /// The actor signs a challenge with their DID key.
    DidSignature {
        actor_did: String,
        body_hash: Hash256,
        signature: Signature,
        timestamp: Timestamp,
    },
    /// API key authentication (convenience, DID-bound).
    /// The key is a random 256-bit token that maps to a DID in the key registry.
    ApiKey(String),
    /// Bearer token authentication (HTTP-friendly, DID-bound).
    /// A bearer token that maps to a DID in the session registry.
    BearerToken(String),
}

// ---------------------------------------------------------------------------
// API key registry
// ---------------------------------------------------------------------------

/// A registered API key bound to a DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    /// BLAKE3 hash of the plaintext API key.
    pub key_hash: Hash256,
    /// The DID this key is bound to.
    pub did: Did,
    /// Human-readable label for this key.
    pub label: String,
    /// When this key was created (HLC timestamp).
    pub created_at: Timestamp,
    /// Optional expiration timestamp. `None` = never expires.
    pub expires_at: Option<Timestamp>,
    /// Whether this key has been revoked.
    pub revoked: bool,
}

/// Caller-supplied metadata for API key creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiKeyMetadata {
    pub created_at: Timestamp,
}

impl ApiKeyMetadata {
    /// Validate caller-supplied API key metadata.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::BadRequest` if `created_at` is `Timestamp::ZERO`.
    pub fn new(created_at: Timestamp) -> Result<Self> {
        if created_at == Timestamp::ZERO {
            return Err(GatewayError::BadRequest(
                "API key created_at must be caller-supplied and non-zero".into(),
            ));
        }
        Ok(Self { created_at })
    }
}

/// Registry of API keys mapped to DIDs.
/// Uses `BTreeMap` (not `HashMap`) for deterministic iteration.
#[derive(Debug, Clone, Default)]
pub struct ApiKeyRegistry {
    /// Maps `BLAKE3(api_key)` to `ApiKeyRecord`.
    /// Keys are stored hashed — the plaintext key is only shown once at creation.
    keys: BTreeMap<Hash256, ApiKeyRecord>,
}

impl ApiKeyRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new API key for `did` with a human-readable `label`.
    ///
    /// Returns `(plaintext_key_hex, record)`.  The plaintext key is shown **once**
    /// at creation and never stored — only its BLAKE3 hash is persisted.
    /// # Panics
    ///
    /// Panics if the OS entropy source is unavailable (unrecoverable).
    #[allow(clippy::expect_used)] // OS entropy failure is unrecoverable.
    pub fn register(
        &mut self,
        did: Did,
        label: String,
        metadata: ApiKeyMetadata,
    ) -> (String, ApiKeyRecord) {
        // Generate 32 random bytes via getrandom.
        let mut key_bytes = [0u8; 32];
        getrandom::getrandom(&mut key_bytes).expect("OS entropy source unavailable");

        let plaintext_hex = hex::encode(key_bytes);
        let key_hash = Hash256::digest(&key_bytes);

        let record = ApiKeyRecord {
            key_hash,
            did,
            label,
            created_at: metadata.created_at,
            expires_at: None,
            revoked: false,
        };

        self.keys.insert(key_hash, record.clone());
        (plaintext_hex, record)
    }

    /// Resolve a plaintext API key (hex-encoded) to its record.
    ///
    /// Returns `None` if the key is not found.
    #[must_use]
    pub fn resolve(&self, api_key: &str) -> Option<&ApiKeyRecord> {
        let key_bytes = hex::decode(api_key).ok()?;
        let key_hash = Hash256::digest(&key_bytes);
        self.keys.get(&key_hash)
    }

    /// Revoke a key by its hash.  Returns `true` if the key existed (and was
    /// marked revoked), `false` if the hash was not found.
    pub fn revoke(&mut self, key_hash: &Hash256) -> bool {
        if let Some(record) = self.keys.get_mut(key_hash) {
            record.revoked = true;
            true
        } else {
            false
        }
    }

    /// List all key records bound to `did`.
    #[must_use]
    pub fn keys_for_did(&self, did: &Did) -> Vec<&ApiKeyRecord> {
        self.keys.values().filter(|r| r.did == *did).collect()
    }
}

// ---------------------------------------------------------------------------
// authenticate() — DID-signature path
// ---------------------------------------------------------------------------

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
pub fn authenticate(
    request: &Request,
    registry: &dyn DidRegistry,
    metadata: AuthenticationMetadata,
) -> Result<AuthenticatedActor> {
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
    check_freshness(&request.timestamp, &metadata.observed_at)?;

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
        authenticated_at: metadata.observed_at,
    })
}

// ---------------------------------------------------------------------------
// resolve_credential() — unified entry point
// ---------------------------------------------------------------------------

/// Resolve any credential type to an authenticated actor.
///
/// This is the unified entry point — all downstream code sees only
/// [`AuthenticatedActor`].
///
/// # Errors
///
/// Returns `GatewayError::AuthenticationFailed` with a descriptive reason
/// when the credential is invalid, revoked, expired, or unknown.
pub fn resolve_credential(
    credential: &Credential,
    did_registry: &dyn DidRegistry,
    api_key_registry: &ApiKeyRegistry,
    metadata: AuthenticationMetadata,
) -> Result<AuthenticatedActor> {
    match credential {
        Credential::DidSignature {
            actor_did,
            body_hash,
            signature,
            timestamp,
        } => {
            let request = Request {
                actor_did: actor_did.clone(),
                action: String::new(),
                body_hash: *body_hash,
                signature: signature.clone(),
                timestamp: *timestamp,
            };
            authenticate(&request, did_registry, metadata)
        }

        Credential::ApiKey(key) => resolve_token(key, api_key_registry, "API key", metadata),

        Credential::BearerToken(token) => {
            resolve_token(token, api_key_registry, "bearer token", metadata)
        }
    }
}

/// Shared resolution logic for API key and bearer token credentials.
fn resolve_token(
    token: &str,
    registry: &ApiKeyRegistry,
    kind: &str,
    metadata: AuthenticationMetadata,
) -> Result<AuthenticatedActor> {
    let record = registry
        .resolve(token)
        .ok_or_else(|| GatewayError::AuthenticationFailed {
            reason: format!("unknown {kind}"),
        })?;

    if record.revoked {
        return Err(GatewayError::AuthenticationFailed {
            reason: format!("{kind} has been revoked"),
        });
    }

    if let Some(expires_at) = record.expires_at {
        if metadata.observed_at > expires_at {
            return Err(GatewayError::AuthenticationFailed {
                reason: format!("{kind} has expired"),
            });
        }
    }

    Ok(AuthenticatedActor {
        did: record.did.clone(),
        authenticated_at: metadata.observed_at,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reject requests whose timestamp deviates from `observed_at` by more than
/// `FRESHNESS_WINDOW_MS`.
fn check_freshness(ts: &Timestamp, observed_at: &Timestamp) -> Result<()> {
    let now_ms = observed_at.physical_ms;
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::crypto::{generate_keypair, sign};
    use exo_identity::{
        did::{DidDocument, VerificationMethod},
        registry::LocalDidRegistry,
    };

    use super::*;

    fn req_ts() -> Timestamp {
        Timestamp::new(10_000, 0)
    }

    fn auth_metadata() -> AuthenticationMetadata {
        AuthenticationMetadata::new(Timestamp::new(10_000, 0)).unwrap()
    }

    fn api_key_metadata() -> ApiKeyMetadata {
        ApiKeyMetadata::new(Timestamp::new(1_000, 0)).unwrap()
    }

    /// Build an in-memory registry with a single DID `did:exo:alice` registered
    /// under a freshly generated Ed25519 key pair.  Returns the registry and the
    /// signing key so callers can produce valid signatures.
    fn registry_with_alice() -> (LocalDidRegistry, exo_core::SecretKey) {
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
        let mut reg = LocalDidRegistry::new();
        reg.register(doc).unwrap();
        (reg, sk)
    }

    // -----------------------------------------------------------------------
    // Original authenticate() tests (unchanged)
    // -----------------------------------------------------------------------

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
        let a = authenticate(&r, &reg, auth_metadata()).unwrap();
        assert_eq!(a.did.as_str(), "did:exo:alice");
        assert_eq!(a.authenticated_at, auth_metadata().observed_at);
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
        assert!(authenticate(&r, &reg, auth_metadata()).is_err());
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
        assert!(authenticate(&r, &reg, auth_metadata()).is_err());
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
        assert!(authenticate(&r, &reg, auth_metadata()).is_err());
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
        assert!(authenticate(&r, &reg, auth_metadata()).is_err());
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
        assert!(authenticate(&r, &reg, auth_metadata()).is_err());
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
        let observed_at = Timestamp::new(10_000, 0);
        assert!(check_freshness(&observed_at, &observed_at).is_ok());
    }

    #[test]
    fn freshness_check_rejects_stale() {
        let stale = Timestamp::new(1, 0);
        let observed_at = Timestamp::new(FRESHNESS_WINDOW_MS + 2, 0);
        assert!(check_freshness(&stale, &observed_at).is_err());
    }

    #[test]
    fn authentication_metadata_rejects_zero_observed_at() {
        let metadata = AuthenticationMetadata::new(Timestamp::ZERO);

        assert!(
            matches!(metadata, Err(GatewayError::BadRequest(reason)) if reason.contains("observed_at"))
        );
    }

    #[test]
    fn authenticate_rejects_stale_against_supplied_metadata() {
        let (reg, sk) = registry_with_alice();
        let body_hash = Hash256::ZERO;
        let signature = sign(body_hash.as_bytes(), &sk);
        let r = Request {
            actor_did: "did:exo:alice".into(),
            action: "read".into(),
            body_hash,
            signature,
            timestamp: Timestamp::new(1, 0),
        };
        let metadata =
            AuthenticationMetadata::new(Timestamp::new(FRESHNESS_WINDOW_MS + 2, 0)).unwrap();

        let err = authenticate(&r, &reg, metadata).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("freshness window"),
            "expected freshness-window error in: {msg}"
        );
    }

    #[test]
    fn auth_production_does_not_fabricate_auth_timestamps() {
        let source = include_str!("auth.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        let forbidden_timestamp = ["Timestamp", "::now_utc"].concat();
        assert!(
            !production.contains(&forbidden_timestamp),
            "gateway auth must use caller-supplied authentication timestamps"
        );
        let forbidden_system_time = ["SystemTime", "::now"].concat();
        assert!(
            !production.contains(&forbidden_system_time),
            "gateway auth must not read wall-clock time"
        );
    }

    // -----------------------------------------------------------------------
    // Credential / resolve_credential tests
    // -----------------------------------------------------------------------

    #[test]
    fn credential_did_signature_valid() {
        let (reg, sk) = registry_with_alice();
        let body_hash = Hash256::ZERO;
        let signature = sign(body_hash.as_bytes(), &sk);
        let cred = Credential::DidSignature {
            actor_did: "did:exo:alice".into(),
            body_hash,
            signature,
            timestamp: req_ts(),
        };
        let api_reg = ApiKeyRegistry::new();
        let actor = resolve_credential(&cred, &reg, &api_reg, auth_metadata()).unwrap();
        assert_eq!(actor.did.as_str(), "did:exo:alice");
    }

    #[test]
    fn credential_did_signature_invalid() {
        let (reg, _sk) = registry_with_alice();
        let (_pk2, sk2) = generate_keypair();
        let body_hash = Hash256::ZERO;
        let bad_sig = sign(body_hash.as_bytes(), &sk2);
        let cred = Credential::DidSignature {
            actor_did: "did:exo:alice".into(),
            body_hash,
            signature: bad_sig,
            timestamp: req_ts(),
        };
        let api_reg = ApiKeyRegistry::new();
        assert!(resolve_credential(&cred, &reg, &api_reg, auth_metadata()).is_err());
    }

    #[test]
    fn credential_api_key_valid() {
        let did_reg = LocalDidRegistry::new();
        let mut api_reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:alice").unwrap();
        let (plaintext, _record) = api_reg.register(did, "test key".into(), api_key_metadata());

        let cred = Credential::ApiKey(plaintext);
        let actor = resolve_credential(&cred, &did_reg, &api_reg, auth_metadata()).unwrap();
        assert_eq!(actor.did.as_str(), "did:exo:alice");
    }

    #[test]
    fn credential_api_key_revoked() {
        let did_reg = LocalDidRegistry::new();
        let mut api_reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:alice").unwrap();
        let (plaintext, record) = api_reg.register(did, "test key".into(), api_key_metadata());
        api_reg.revoke(&record.key_hash);

        let cred = Credential::ApiKey(plaintext);
        let err = resolve_credential(&cred, &did_reg, &api_reg, auth_metadata()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("revoked"), "expected 'revoked' in: {msg}");
    }

    #[test]
    fn credential_api_key_expired() {
        let did_reg = LocalDidRegistry::new();
        let mut api_reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:alice").unwrap();
        let (plaintext, record) = api_reg.register(did, "test key".into(), api_key_metadata());

        // Manually set expiration to the past.
        let key_hash = record.key_hash;
        api_reg.keys.get_mut(&key_hash).unwrap().expires_at = Some(Timestamp::new(1, 0));

        let cred = Credential::ApiKey(plaintext);
        let err = resolve_credential(&cred, &did_reg, &api_reg, auth_metadata()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expired"), "expected 'expired' in: {msg}");
    }

    #[test]
    fn credential_api_key_unknown() {
        let did_reg = LocalDidRegistry::new();
        let api_reg = ApiKeyRegistry::new();
        let cred = Credential::ApiKey("deadbeef".repeat(8));
        let err = resolve_credential(&cred, &did_reg, &api_reg, auth_metadata()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown"), "expected 'unknown' in: {msg}");
    }

    #[test]
    fn credential_bearer_valid() {
        let did_reg = LocalDidRegistry::new();
        let mut api_reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:bob").unwrap();
        let (plaintext, _record) =
            api_reg.register(did, "bearer session".into(), api_key_metadata());

        let cred = Credential::BearerToken(plaintext);
        let actor = resolve_credential(&cred, &did_reg, &api_reg, auth_metadata()).unwrap();
        assert_eq!(actor.did.as_str(), "did:exo:bob");
    }

    #[test]
    fn api_key_registry_register() {
        let mut reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:carol").unwrap();
        let (plaintext, record) = reg.register(did.clone(), "my key".into(), api_key_metadata());

        // Plaintext is 64 hex chars (32 bytes).
        assert_eq!(plaintext.len(), 64);
        assert!(hex::decode(&plaintext).is_ok());

        // Record fields are set correctly.
        assert_eq!(record.did, did);
        assert_eq!(record.label, "my key");
        assert!(!record.revoked);
        assert!(record.expires_at.is_none());

        // The registry contains exactly one entry.
        assert_eq!(reg.keys.len(), 1);
    }

    #[test]
    fn api_key_registry_revoke() {
        let mut reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:carol").unwrap();
        let (_plaintext, record) = reg.register(did, "my key".into(), api_key_metadata());

        assert!(reg.revoke(&record.key_hash));
        assert!(reg.keys.get(&record.key_hash).unwrap().revoked);

        // Revoking a non-existent hash returns false.
        assert!(!reg.revoke(&Hash256::ZERO));
    }

    #[test]
    fn api_key_registry_keys_for_did() {
        let mut reg = ApiKeyRegistry::new();
        let alice = Did::new("did:exo:alice").unwrap();
        let bob = Did::new("did:exo:bob").unwrap();

        reg.register(alice.clone(), "alice-1".into(), api_key_metadata());
        reg.register(alice.clone(), "alice-2".into(), api_key_metadata());
        reg.register(bob.clone(), "bob-1".into(), api_key_metadata());

        let alice_keys = reg.keys_for_did(&alice);
        assert_eq!(alice_keys.len(), 2);
        assert!(alice_keys.iter().all(|r| r.did == alice));

        let bob_keys = reg.keys_for_did(&bob);
        assert_eq!(bob_keys.len(), 1);
        assert_eq!(bob_keys[0].did, bob);
    }

    #[test]
    fn api_key_plaintext_shown_once() {
        let mut reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:alice").unwrap();
        let (plaintext, record) = reg.register(did, "test".into(), api_key_metadata());

        // The plaintext key, when hashed with BLAKE3, must equal the stored key_hash.
        let key_bytes = hex::decode(&plaintext).unwrap();
        let computed_hash = Hash256::digest(&key_bytes);
        assert_eq!(computed_hash, record.key_hash);

        // Resolve round-trips through the same hash.
        let resolved = reg.resolve(&plaintext).unwrap();
        assert_eq!(resolved.key_hash, record.key_hash);
    }

    #[test]
    fn api_key_metadata_rejects_zero_created_at() {
        let metadata = ApiKeyMetadata::new(Timestamp::ZERO);

        assert!(
            matches!(metadata, Err(GatewayError::BadRequest(reason)) if reason.contains("created_at"))
        );
    }

    #[test]
    fn resolve_credential_uses_supplied_authentication_metadata() {
        let did_reg = LocalDidRegistry::new();
        let mut api_reg = ApiKeyRegistry::new();
        let did = Did::new("did:exo:alice").unwrap();
        let key_metadata = ApiKeyMetadata::new(Timestamp::new(1_000, 0)).unwrap();
        let (plaintext, record) = api_reg.register(did, "test key".into(), key_metadata);

        assert_eq!(record.created_at, Timestamp::new(1_000, 0));

        let auth_metadata = AuthenticationMetadata::new(Timestamp::new(2_000, 0)).unwrap();
        let cred = Credential::ApiKey(plaintext);
        let actor = resolve_credential(&cred, &did_reg, &api_reg, auth_metadata).unwrap();

        assert_eq!(actor.authenticated_at, Timestamp::new(2_000, 0));
    }
}
