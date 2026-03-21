//! API route definitions — BCTS lifecycle, identity, governance endpoints.
use exo_core::Did;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{Request, authenticate},
    error::{GatewayError, Result},
    middleware::{AuditLog, Verdict, audit_middleware, consent_middleware, governance_middleware},
};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteResult {
    pub route: Route,
    pub status: String,
    pub correlation_id: Uuid,
}

/// Process a request through the full middleware chain: auth -> consent -> governance -> execution.
pub fn process_request(
    request: &Request,
    route: Route,
    consent: bool,
    verdict: &Verdict,
    log: &mut AuditLog,
) -> Result<RouteResult> {
    let actor = authenticate(request)?;
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
mod tests {
    use exo_core::{
        Hash256, Timestamp,
        crypto::{generate_keypair, sign},
    };

    use super::*;

    fn req() -> Request {
        let (pk, sk) = generate_keypair();
        let body_hash = Hash256::digest(b"route-test");
        let signature = sign(body_hash.as_ref(), &sk);
        Request {
            actor_did: "did:exo:alice".into(),
            action: "create".into(),
            body_hash,
            signature,
            timestamp: Timestamp::ZERO,
            public_key: pk,
        }
    }

    #[test]
    fn full_chain_ok() {
        let mut log = AuditLog::new();
        let r = process_request(
            &req(),
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
        let mut log = AuditLog::new();
        let bad = Request {
            actor_did: "bad".into(),
            ..req()
        };
        assert!(
            process_request(
                &bad,
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
        let mut log = AuditLog::new();
        assert!(
            process_request(
                &req(),
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
        let mut log = AuditLog::new();
        assert!(
            process_request(
                &req(),
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
