//! API route definitions — BCTS lifecycle, identity, governance endpoints.
use exo_core::Did;
use exo_identity::did::DidRegistry;
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

/// Process a request through the full middleware chain: auth -> consent -> governance -> execution.
pub fn process_request(
    request: &Request,
    registry: &DidRegistry,
    route: Route,
    consent: bool,
    verdict: &Verdict,
    log: &mut AuditLog,
) -> Result<RouteResult> {
    let actor = authenticate(request, registry)?;
    consent_middleware(&actor.did, &request.action, consent)?;
    governance_middleware(&actor.did, &request.action, verdict)?;
    let result = RouteResult {
        route: route.clone(),
        status: "ok".into(),
        correlation_id: Uuid::new_v4(),
    };
    let now = exo_core::Timestamp::now_utc();
    audit_middleware(&actor.did, &request.action, "success", &now, log)?;
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
    use exo_identity::did::{DidDocument, DidRegistry, VerificationMethod};

    use super::*;

    /// Create a registry with `did:exo:alice` and return the registry +
    /// a signed request using alice's key.
    fn alice_registry_and_req() -> (DidRegistry, Request) {
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

    #[test]
    fn full_chain_ok() {
        let (reg, req) = alice_registry_and_req();
        let mut log = AuditLog::new();
        let r = process_request(
            &req,
            &reg,
            Route::CreateTransaction,
            true,
            &Verdict::Allow,
            &mut log,
        );
        assert!(r.is_ok());
        assert_eq!(log.len(), 1);
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
