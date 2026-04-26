//! API route definitions — BCTS lifecycle, identity, governance endpoints.
use exo_core::Did;
use exo_identity::registry::LocalDidRegistry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{Request, authenticate},
    error::{GatewayError, Result},
    middleware::{AuditLog, Verdict, audit_middleware, consent_middleware, governance_middleware},
};

/// Gateway route identifiers for the BCTS lifecycle and governance operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    CreateTransaction,
    TransitionState,
    QueryTransaction,
    GetReceipt,
    ResolveIdentity,
    RegisterIdentity,
    Deliberate,
    Vote,
    Challenge,
}

/// Result of processing a request through the middleware chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteResult {
    pub route: Route,
    pub status: String,
    pub correlation_id: Uuid,
}

/// Caller-supplied route metadata bound into the gateway audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteMetadata {
    pub correlation_id: Uuid,
    pub audit_timestamp: exo_core::Timestamp,
}

impl RouteMetadata {
    /// Validate caller-supplied route metadata.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::BadRequest` if the correlation ID is nil or the
    /// audit timestamp is `Timestamp::ZERO`.
    pub fn new(correlation_id: Uuid, audit_timestamp: exo_core::Timestamp) -> Result<Self> {
        if correlation_id.is_nil() {
            return Err(GatewayError::BadRequest(
                "route correlation_id must be caller-supplied and non-nil".into(),
            ));
        }
        if audit_timestamp == exo_core::Timestamp::ZERO {
            return Err(GatewayError::BadRequest(
                "route audit timestamp must be caller-supplied and non-zero".into(),
            ));
        }
        Ok(Self {
            correlation_id,
            audit_timestamp,
        })
    }
}

/// Process a request through the full middleware chain: auth -> consent -> governance -> execution.
pub fn process_request(
    request: &Request,
    registry: &LocalDidRegistry,
    route: Route,
    consent: bool,
    verdict: &Verdict,
    metadata: RouteMetadata,
    log: &mut AuditLog,
) -> Result<RouteResult> {
    let actor = authenticate(request, registry)?;
    consent_middleware(&actor.did, &request.action, consent)?;
    governance_middleware(&actor.did, &request.action, verdict)?;
    let result = RouteResult {
        route: route.clone(),
        status: "ok".into(),
        correlation_id: metadata.correlation_id,
    };
    audit_middleware(
        &actor.did,
        &request.action,
        "success",
        &metadata.audit_timestamp,
        log,
    )?;
    Ok(result)
}

/// Default-deny: a request with no consent is always rejected.
pub fn default_deny_check(actor: &Did, action: &str) -> Result<()> {
    Err(GatewayError::ConsentDenied {
        reason: format!("default-deny: {actor} cannot {action} without explicit consent"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use exo_core::{
        Hash256, Timestamp,
        crypto::{generate_keypair, sign},
    };
    use exo_identity::{
        did::{DidDocument, VerificationMethod},
        registry::{DidRegistry, LocalDidRegistry},
    };

    use super::*;

    /// Create a registry with `did:exo:alice` and return the registry +
    /// a signed request using alice's key.
    fn alice_registry_and_req() -> (LocalDidRegistry, Request) {
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

        let body_hash = Hash256::digest(b"route-test");
        let signature = sign(body_hash.as_bytes(), &sk);
        let req = Request {
            actor_did: "did:exo:alice".into(),
            action: "create".into(),
            body_hash,
            signature,
            timestamp: Timestamp::ZERO,
        };
        (reg, req)
    }

    fn route_metadata() -> RouteMetadata {
        RouteMetadata::new(
            Uuid::parse_str("018f7a96-8ad0-7c4f-8e0f-333333333333").unwrap(),
            Timestamp::new(7_000, 1),
        )
        .expect("valid route metadata")
    }

    #[test]
    fn full_chain_ok() {
        let (reg, req) = alice_registry_and_req();
        let mut log = AuditLog::new();
        let metadata = route_metadata();
        let r = process_request(
            &req,
            &reg,
            Route::CreateTransaction,
            true,
            &Verdict::Allow,
            metadata,
            &mut log,
        );
        assert!(r.is_ok());
        assert_eq!(
            r.unwrap().correlation_id,
            Uuid::parse_str("018f7a96-8ad0-7c4f-8e0f-333333333333").unwrap()
        );
        assert_eq!(log.len(), 1);
        assert_eq!(log.entries[0].timestamp, Timestamp::new(7_000, 1));
    }

    #[test]
    fn route_metadata_rejects_nil_correlation_id() {
        let result = RouteMetadata::new(Uuid::nil(), Timestamp::new(7_000, 0));

        assert!(
            matches!(result, Err(GatewayError::BadRequest(reason)) if reason.contains("correlation"))
        );
    }

    #[test]
    fn route_metadata_rejects_zero_audit_timestamp() {
        let result = RouteMetadata::new(
            Uuid::parse_str("018f7a96-8ad0-7c4f-8e0f-444444444444").unwrap(),
            Timestamp::ZERO,
        );

        assert!(
            matches!(result, Err(GatewayError::BadRequest(reason)) if reason.contains("timestamp"))
        );
    }

    #[test]
    fn process_request_does_not_fabricate_route_metadata() {
        let source = include_str!("routes.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        let forbidden_uuid = ["Uuid", "::new_v4"].concat();
        assert!(
            !production.contains(&forbidden_uuid),
            "route processing must not fabricate correlation IDs"
        );
        let forbidden_time = ["Timestamp", "::now_utc"].concat();
        assert!(
            !production.contains(&forbidden_time),
            "route processing must not fabricate audit timestamps"
        );
    }

    #[test]
    fn auth_fails() {
        let (reg, req) = alice_registry_and_req();
        let mut log = AuditLog::new();
        let bad = Request {
            actor_did: "bad".into(),
            ..req
        };
        assert!(
            process_request(
                &bad,
                &reg,
                Route::CreateTransaction,
                true,
                &Verdict::Allow,
                route_metadata(),
                &mut log
            )
            .is_err()
        );
    }

    #[test]
    fn consent_fails() {
        let (reg, req) = alice_registry_and_req();
        let mut log = AuditLog::new();
        assert!(
            process_request(
                &req,
                &reg,
                Route::CreateTransaction,
                false,
                &Verdict::Allow,
                route_metadata(),
                &mut log
            )
            .is_err()
        );
    }

    #[test]
    fn governance_fails() {
        let (reg, req) = alice_registry_and_req();
        let mut log = AuditLog::new();
        assert!(
            process_request(
                &req,
                &reg,
                Route::CreateTransaction,
                true,
                &Verdict::Deny {
                    reason: "no".into()
                },
                route_metadata(),
                &mut log
            )
            .is_err()
        );
    }
    #[test]
    fn default_deny() {
        let did = Did::new("did:exo:alice").unwrap();
        assert!(default_deny_check(&did, "write").is_err());
    }
    #[test]
    fn route_serde() {
        for r in [
            Route::CreateTransaction,
            Route::TransitionState,
            Route::QueryTransaction,
            Route::GetReceipt,
            Route::ResolveIdentity,
            Route::RegisterIdentity,
            Route::Deliberate,
            Route::Vote,
            Route::Challenge,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let rr: Route = serde_json::from_str(&j).unwrap();
            assert_eq!(rr, r);
        }
    }
}
