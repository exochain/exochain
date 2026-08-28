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

//! Axum routes for the policy decision point.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use exo_authority::{DelegateeKind, DelegationGrant, Permission};
use exo_core::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    error::PdpError,
    mandate::{MandateAdapter, ProposedAction, WireMandate},
    policy::DecisionRequest,
    service::{DecideResponse, SharedPdp},
    x402::{self, X402VerifyRequest, X402VerifyResponse},
};

type PersistHook =
    Arc<dyn Fn(&crate::service::PolicyDecisionPoint) -> crate::error::Result<()> + Send + Sync>;

const MAX_PDP_BODY_BYTES: usize = 1_048_576;
const MAX_DELEGATION_SCOPE_ITEMS: usize = 64;

/// Opaque authorization boundary required by every PDP mutation router.
#[derive(Clone)]
pub struct PdpMutationAuthorizer(Arc<dyn Fn(&HeaderMap) -> bool + Send + Sync + 'static>);

impl PdpMutationAuthorizer {
    /// Construct a mutation authorizer from the embedding runtime's verifier.
    pub fn new<F>(authorize: F) -> Self
    where
        F: Fn(&HeaderMap) -> bool + Send + Sync + 'static,
    {
        Self(Arc::new(authorize))
    }

    fn authorizes(&self, headers: &HeaderMap) -> bool {
        (self.0)(headers)
    }
}

#[derive(Clone)]
struct PdpHttpState {
    pdp: SharedPdp,
    persist: Option<PersistHook>,
}

impl PdpHttpState {
    fn checkpoint(
        &self,
        pdp: &crate::service::PolicyDecisionPoint,
    ) -> crate::error::Result<Option<crate::service::PdpSnapshot>> {
        self.persist
            .as_ref()
            .map(|_| pdp.export_snapshot())
            .transpose()
    }

    fn persist_or_rollback(
        &self,
        pdp: &mut crate::service::PolicyDecisionPoint,
        checkpoint: Option<crate::service::PdpSnapshot>,
    ) -> crate::error::Result<()> {
        let Some(persist) = &self.persist else {
            return Ok(());
        };
        if let Err(persistence_error) = persist(pdp) {
            if let Some(checkpoint) = checkpoint {
                pdp.import_snapshot(checkpoint).map_err(|rollback_error| {
                    PdpError::Persistence(format!(
                        "{persistence_error}; in-memory rollback failed: {rollback_error}"
                    ))
                })?;
            }
            return Err(persistence_error);
        }
        Ok(())
    }
}

/// Build only the PDP read and independent-verification routes.
///
/// This compatibility constructor deliberately installs no mutation routes.
pub fn pdp_router(pdp: SharedPdp) -> Router {
    pdp_read_router(pdp)
}

/// Build the complete PDP router with an explicit mutation authorizer.
pub fn pdp_router_with_authorizer(pdp: SharedPdp, authorizer: PdpMutationAuthorizer) -> Router {
    build_pdp_router(PdpHttpState { pdp, persist: None }, authorizer)
}

/// Build read and independent-verification routes with persistence state.
///
/// This compatibility constructor deliberately installs no mutation routes.
pub fn pdp_router_with_persistence<F>(pdp: SharedPdp, persist: F) -> Router
where
    F: Fn(&crate::service::PolicyDecisionPoint) -> crate::error::Result<()> + Send + Sync + 'static,
{
    build_pdp_read_router(PdpHttpState {
        pdp,
        persist: Some(Arc::new(persist)),
    })
    .layer(DefaultBodyLimit::max(MAX_PDP_BODY_BYTES))
}

/// Build the complete PDP router with authorization and fail-closed persistence.
pub fn pdp_router_with_authorized_persistence<F>(
    pdp: SharedPdp,
    authorizer: PdpMutationAuthorizer,
    persist: F,
) -> Router
where
    F: Fn(&crate::service::PolicyDecisionPoint) -> crate::error::Result<()> + Send + Sync + 'static,
{
    build_pdp_router(
        PdpHttpState {
            pdp,
            persist: Some(Arc::new(persist)),
        },
        authorizer,
    )
}

/// Build only read and independent verification routes.
pub fn pdp_read_router(pdp: SharedPdp) -> Router {
    build_pdp_read_router(PdpHttpState { pdp, persist: None })
        .layer(DefaultBodyLimit::max(MAX_PDP_BODY_BYTES))
}

async fn require_mutation_authorization(
    State(authorizer): State<PdpMutationAuthorizer>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if !authorizer.authorizes(request.headers()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

fn build_pdp_router(state: PdpHttpState, authorizer: PdpMutationAuthorizer) -> Router {
    build_pdp_read_router(state.clone())
        .merge(build_pdp_mutation_router(state, authorizer))
        .layer(DefaultBodyLimit::max(MAX_PDP_BODY_BYTES))
}

fn build_pdp_read_router(state: PdpHttpState) -> Router {
    Router::new()
        .route("/api/v1/authority/evidence/:hash", get(handle_evidence))
        .route(
            "/api/v1/authority/evidence/:hash/verify",
            get(handle_verify_evidence),
        )
        .route("/api/v1/authority/pack", get(handle_export_pack))
        .route("/api/v1/authority/pack/verify", post(handle_verify_pack))
        .with_state(state)
}

fn build_pdp_mutation_router(state: PdpHttpState, authorizer: PdpMutationAuthorizer) -> Router {
    Router::new()
        .route("/api/v1/authority/decide", post(handle_decide))
        .route("/api/v1/authority/register-key", post(handle_register_key))
        .route("/api/v1/authority/delegate", post(handle_delegate))
        .route("/api/v1/authority/revoke", post(handle_revoke))
        .route("/api/v1/authority/reserve", post(handle_reserve))
        .route("/api/v1/authority/commit", post(handle_commit))
        .route("/api/v1/authority/release", post(handle_release))
        .route("/x402/verify", post(handle_x402_verify))
        .route_layer(middleware::from_fn_with_state(
            authorizer,
            require_mutation_authorization,
        ))
        .with_state(state)
}

fn require_now_ms(now_ms: Option<u64>) -> crate::error::Result<Timestamp> {
    match now_ms {
        Some(ms) if ms > 0 => Ok(Timestamp::new(ms, 0)),
        _ => Err(PdpError::BadRequest(
            "now_ms is required (HLC physical milliseconds, non-zero)".into(),
        )),
    }
}

fn err(e: PdpError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match e {
        PdpError::BadRequest(_) | PdpError::InvalidMandate(_) => StatusCode::BAD_REQUEST,
        PdpError::EvidenceNotFound | PdpError::ReservationNotFound(_) => StatusCode::NOT_FOUND,
        PdpError::Denied(_)
        | PdpError::Revoked
        | PdpError::Expired
        | PdpError::AlreadyConsumed
        | PdpError::AlreadyReserved
        | PdpError::CaveatFailed(_)
        | PdpError::DelegationRequired
        | PdpError::InvalidSignature => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({ "error": e.to_string(), "never_moves_money": true })),
    )
}

#[derive(Debug, Deserialize)]
struct DecideBody {
    mandate: WireMandate,
    #[serde(default)]
    proposed: Option<ProposedAction>,
    #[serde(default)]
    payment_evidence_hash_hex: Option<String>,
    #[serde(default)]
    now_ms: Option<u64>,
}

async fn handle_decide(
    State(state): State<PdpHttpState>,
    Json(body): Json<DecideBody>,
) -> Result<Json<DecideResponse>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let mandate = body.mandate.into_mandate().map_err(err)?;
    let proposed = body.proposed.unwrap_or_else(|| ProposedAction {
        action: mandate.action.clone(),
        amount_minor: mandate.amount_minor,
        currency: mandate.currency.clone(),
        merchant: mandate.merchant.clone(),
        rail: None,
    });
    let payment_evidence_hash = match body.payment_evidence_hash_hex.as_deref() {
        None | Some("") => None,
        Some(raw) => {
            let bytes = hex::decode(raw).map_err(|e| err(PdpError::BadRequest(e.to_string())))?;
            if bytes.len() != 32 {
                return Err(err(PdpError::BadRequest(
                    "payment_evidence_hash_hex must be 32 bytes".into(),
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(Hash256::from_bytes(arr))
        }
    };
    let req = DecisionRequest {
        mandate,
        proposed,
        payment_evidence_hash,
        now: require_now_ms(body.now_ms).map_err(err)?,
    };
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    let out = guard.decide(req).map_err(err)?;
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(DecideResponse::from(&out)))
}

#[derive(Debug, Deserialize)]
struct RegisterKeyBody {
    did: String,
    public_key_hex: String,
}

async fn handle_register_key(
    State(state): State<PdpHttpState>,
    Json(body): Json<RegisterKeyBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let did = crate::mandate::coerce_did(&body.did).map_err(err)?;
    let bytes =
        hex::decode(&body.public_key_hex).map_err(|e| err(PdpError::BadRequest(e.to_string())))?;
    if bytes.len() != 32 {
        return Err(err(PdpError::BadRequest(
            "public key must be 32 bytes".into(),
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    guard.register_key(did.clone(), exo_core::PublicKey::from_bytes(arr));
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(
        serde_json::json!({ "did": did.to_string(), "registered": true }),
    ))
}

#[derive(Debug, Deserialize)]
struct DelegateBody {
    from: String,
    to: String,
    scope: Vec<String>,
    expires_ms: u64,
    now_ms: u64,
    #[serde(default)]
    model_id: Option<String>,
    /// Hex signature from the delegator over the link payload.
    /// If omitted, the request is rejected — unsigned delegations are closed.
    signature_hex: String,
}

fn parse_perm(s: &str) -> Result<Permission, PdpError> {
    match s.to_ascii_lowercase().as_str() {
        "read" => Ok(Permission::Read),
        "write" => Ok(Permission::Write),
        "execute" => Ok(Permission::Execute),
        "delegate" => Ok(Permission::Delegate),
        "govern" => Ok(Permission::Govern),
        "escalate" => Ok(Permission::Escalate),
        "challenge" => Ok(Permission::Challenge),
        "spend" => Ok(Permission::Spend),
        other => Err(PdpError::BadRequest(format!("unknown permission {other}"))),
    }
}

async fn handle_delegate(
    State(state): State<PdpHttpState>,
    Json(body): Json<DelegateBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    if body.scope.len() > MAX_DELEGATION_SCOPE_ITEMS {
        return Err(err(PdpError::BadRequest(format!(
            "delegation scope exceeds maximum of {MAX_DELEGATION_SCOPE_ITEMS} permissions"
        ))));
    }
    let from = crate::mandate::coerce_did(&body.from).map_err(err)?;
    let to = crate::mandate::coerce_did(&body.to).map_err(err)?;
    let mut scope = Vec::new();
    for s in &body.scope {
        scope.push(parse_perm(s).map_err(err)?);
    }
    let sig = crate::mandate::parse_sig_hex(&body.signature_hex).map_err(err)?;
    let kind = match body.model_id {
        Some(id) => DelegateeKind::AiAgent { model_id: id },
        None => DelegateeKind::Human,
    };
    let mut guard = pdp.lock().map_err(err)?;
    let pk = guard
        .resolve_public(&from)
        .ok_or_else(|| err(PdpError::UnknownActor(from.to_string())))?;
    let now = require_now_ms(Some(body.now_ms)).map_err(err)?;
    let grant = DelegationGrant {
        from: &from,
        to: &to,
        scope: &scope,
        expires: Timestamp::new(body.expires_ms, 0),
        now: &now,
        parent_link_id: None,
        delegatee_kind: kind,
        delegator_public_key: &pk,
    };
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    let link = guard.delegate(grant, move |_| sig).map_err(err)?;
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    let link_id = link.id().map_err(|e| err(PdpError::from(e)))?;
    Ok(Json(serde_json::json!({
        "link_id": link_id.to_string(),
        "from": from.to_string(),
        "to": to.to_string(),
    })))
}

#[derive(Debug, Deserialize)]
struct RevokeBody {
    #[serde(default)]
    mandate_hash: Option<String>,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    delegation_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    now_ms: Option<u64>,
}

fn parse_hash(s: &str) -> Result<Hash256, PdpError> {
    let bytes = hex::decode(s).map_err(|e| PdpError::BadRequest(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(PdpError::BadRequest("hash must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(arr))
}

async fn handle_revoke(
    State(state): State<PdpHttpState>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let now = require_now_ms(body.now_ms).map_err(err)?;
    let reason = body.reason.unwrap_or_else(|| "revoked".into());
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    if let Some(h) = body.mandate_hash {
        let hash = parse_hash(&h).map_err(err)?;
        guard.revoke_mandate(hash, now, reason.clone());
    }
    if let Some(a) = body.agent {
        let did = crate::mandate::coerce_did(&a).map_err(err)?;
        guard.revoke_agent(did, now, reason.clone());
    }
    if let Some(d) = body.delegation_id {
        let hash = parse_hash(&d).map_err(err)?;
        guard.revoke_delegation(hash, now, reason);
    }
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

#[derive(Debug, Deserialize)]
struct HashBody {
    mandate_hash: String,
    #[serde(default)]
    now_ms: Option<u64>,
}

async fn handle_reserve(
    State(state): State<PdpHttpState>,
    Json(body): Json<HashBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let hash = parse_hash(&body.mandate_hash).map_err(err)?;
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    guard
        .reserve(hash, require_now_ms(body.now_ms).map_err(err)?)
        .map_err(err)?;
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(serde_json::json!({ "state": "reserved" })))
}

async fn handle_commit(
    State(state): State<PdpHttpState>,
    Json(body): Json<HashBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let hash = parse_hash(&body.mandate_hash).map_err(err)?;
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    guard.commit(&hash).map_err(err)?;
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(serde_json::json!({ "state": "committed" })))
}

async fn handle_release(
    State(state): State<PdpHttpState>,
    Json(body): Json<HashBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let hash = parse_hash(&body.mandate_hash).map_err(err)?;
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    guard.release(&hash).map_err(err)?;
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(serde_json::json!({ "state": "released" })))
}

async fn handle_evidence(
    State(state): State<PdpHttpState>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let h = parse_hash(&hash).map_err(err)?;
    let guard = pdp.lock().map_err(err)?;
    let entry = guard
        .evidence(&h)
        .ok_or_else(|| err(PdpError::EvidenceNotFound))?;
    serde_json::to_value(entry)
        .map(Json)
        .map_err(|e| err(PdpError::BadRequest(e.to_string())))
}

async fn handle_verify_evidence(
    State(state): State<PdpHttpState>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let h = parse_hash(&hash).map_err(err)?;
    let guard = pdp.lock().map_err(err)?;
    let entry = guard.verify_evidence(&h).map_err(err)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "evidence_hash": entry.entry_hash.to_string(),
        "decision": entry.decision,
        "independently_verifiable": true,
    })))
}

async fn handle_export_pack(
    State(state): State<PdpHttpState>,
) -> Result<Json<crate::pack::EvidencePack>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let guard = pdp.lock().map_err(err)?;
    guard.export_pack().map(Json).map_err(err)
}

#[derive(Debug, Deserialize)]
struct VerifyPackBody {
    pack: crate::pack::EvidencePack,
    expected_service_public_key_hex: String,
}

async fn handle_verify_pack(
    Json(body): Json<VerifyPackBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let expected_key =
        crate::pack::parse_public_key_hex(&body.expected_service_public_key_hex).map_err(err)?;
    body.pack.verify_with_key(&expected_key).map_err(err)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "independently_verifiable": true,
        "never_moves_money": true,
        "article_26": body.pack.article_26,
        "entries": body.pack.entries.len(),
        "tip": body.pack.tip_hex,
    })))
}

async fn handle_x402_verify(
    State(state): State<PdpHttpState>,
    Json(body): Json<X402VerifyRequest>,
) -> Result<Json<X402VerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    let pdp = &state.pdp;
    let mut guard = pdp.lock().map_err(err)?;
    let checkpoint = state.checkpoint(&guard).map_err(err)?;
    let resp = x402::verify(&mut guard, body).map_err(err)?;
    state
        .persist_or_rollback(&mut guard, checkpoint)
        .map_err(err)?;
    Ok(Json(resp))
}

/// Shared-pdp snapshot used by the agent passport.
#[derive(Debug, Serialize)]
pub struct DelegationSnapshot {
    pub granted: u64,
    pub received: u64,
    pub permissions: Vec<String>,
}

impl SharedPdp {
    pub fn snapshot_for(&self, did: &exo_core::Did) -> crate::error::Result<DelegationSnapshot> {
        let guard = self.lock()?;
        Ok(DelegationSnapshot {
            granted: u64::try_from(guard.granted_by(did)).unwrap_or(0),
            received: u64::try_from(guard.received_by(did)).unwrap_or(0),
            permissions: guard.permissions_for(did),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use exo_authority::AuthorityLink;
    use exo_core::{Did, Signature, crypto::KeyPair};
    use tower::ServiceExt;

    use super::*;
    use crate::mandate::{Caveat, Mandate, MandateKind};

    const TEST_AUTHORIZATION: &str = "Bearer pdp-test-token";

    fn mutation_test_router(pdp: SharedPdp) -> Router {
        pdp_router_with_authorizer(
            pdp,
            PdpMutationAuthorizer::new(|headers| {
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    == Some(TEST_AUTHORIZATION)
            }),
        )
    }

    fn register_key_request(
        did: &Did,
        key: &KeyPair,
        authorization: Option<&str>,
    ) -> Request<Body> {
        let body = serde_json::json!({
            "did": did.to_string(),
            "public_key_hex": hex::encode(key.public_key().as_bytes()),
        });
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/authority/register-key")
            .header("content-type", "application/json");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        request.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn exported_router_rejects_unauthorized_mutation_and_allows_configured_authorizer() {
        let pdp = SharedPdp::ephemeral();
        let actor = Did::new("did:exo:http-auth-boundary").unwrap();
        let actor_key = KeyPair::from_secret_bytes([0x31; 32]).unwrap();
        let router = mutation_test_router(pdp);

        let register_key_without_authorization = router
            .clone()
            .oneshot(register_key_request(&actor, &actor_key, None))
            .await
            .unwrap();
        let register_key_with_authorization = router
            .oneshot(register_key_request(
                &actor,
                &actor_key,
                Some(TEST_AUTHORIZATION),
            ))
            .await
            .unwrap();

        assert_eq!(
            register_key_without_authorization.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(register_key_with_authorization.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorized_router_keeps_x402_verify_reachable() {
        let pdp = SharedPdp::ephemeral();
        let principal = Did::new("did:exo:x402-router-principal").unwrap();
        let agent = Did::new("did:exo:x402-router-agent").unwrap();
        let principal_key = KeyPair::from_secret_bytes([0x34; 32]).unwrap();
        pdp.lock()
            .unwrap()
            .register_key(principal.clone(), *principal_key.public_key());

        let mut mandate = Mandate {
            kind: MandateKind::X402Payload,
            principal: principal.clone(),
            agent: agent.clone(),
            action: "payment.settle".into(),
            amount_minor: Some(99),
            currency: Some("USD".into()),
            merchant: None,
            caveats: vec![Caveat::AmountMax {
                minor: 1,
                currency: "USD".into(),
            }],
            expires: None,
            consume_once: false,
            signature: Signature::empty(),
            raw_hash: Hash256::ZERO,
        };
        mandate.signature = principal_key.sign(&mandate.signable_payload().unwrap());
        let body = X402VerifyRequest {
            mandate: WireMandate {
                kind: MandateKind::X402Payload,
                principal: principal.to_string(),
                agent: agent.to_string(),
                action: mandate.action,
                amount_minor: mandate.amount_minor,
                currency: mandate.currency,
                merchant: None,
                caveats: mandate.caveats,
                expires_ms: None,
                consume_once: false,
                signature_hex: hex::encode(
                    mandate
                        .signature
                        .ed25519_bytes()
                        .expect("Ed25519 test signature"),
                ),
                raw_hex: None,
            },
            proposed: None,
            payment_evidence_hash_hex: Some(hex::encode([0x11_u8; 32])),
            payment_signature_header: None,
            now_ms: Some(1),
        };
        let request = Request::builder()
            .method("POST")
            .uri("/x402/verify")
            .header("content-type", "application/json")
            .header("authorization", TEST_AUTHORIZATION)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = mutation_test_router(pdp).oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn compatibility_routers_omit_mutation_and_x402_routes() {
        let pdp = SharedPdp::ephemeral();
        let actor = Did::new("did:exo:compatibility-read-only").unwrap();
        let actor_key = KeyPair::from_secret_bytes([0x35; 32]).unwrap();
        let routers = [
            pdp_router(pdp.clone()),
            pdp_router_with_persistence(pdp, |_| Ok(())),
        ];

        for router in routers {
            let mutation = router
                .clone()
                .oneshot(register_key_request(&actor, &actor_key, None))
                .await
                .unwrap();
            let x402 = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/x402/verify")
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(mutation.status(), StatusCode::NOT_FOUND);
            assert_eq!(x402.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn exported_router_rejects_oversized_mutation_body_before_json_extraction() {
        let pdp = SharedPdp::ephemeral();
        let actor = Did::new("did:exo:http-body-boundary").unwrap();
        let actor_key = KeyPair::from_secret_bytes([0x32; 32]).unwrap();
        let body = serde_json::json!({
            "did": actor.to_string(),
            "public_key_hex": hex::encode(actor_key.public_key().as_bytes()),
            "padding": "x".repeat(1_048_576),
        });
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/authority/register-key")
            .header("content-type", "application/json")
            .header("authorization", TEST_AUTHORIZATION)
            .body(Body::from(body.to_string()))
            .unwrap();

        let oversized_delegate = mutation_test_router(pdp).oneshot(request).await.unwrap();

        assert_eq!(oversized_delegate.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn exported_router_rejects_delegation_scope_above_sixty_four_items() {
        let pdp = SharedPdp::ephemeral();
        let from = Did::new("did:exo:http-scope-from").unwrap();
        let to = Did::new("did:exo:http-scope-to").unwrap();
        let key = KeyPair::from_secret_bytes([0x33; 32]).unwrap();
        pdp.lock()
            .unwrap()
            .register_key(from.clone(), *key.public_key());

        let now = Timestamp::new(10, 0);
        let link = AuthorityLink {
            delegator_did: from.clone(),
            delegate_did: to.clone(),
            scope: vec![Permission::Read],
            created: now,
            expires: Some(Timestamp::new(1_000, 0)),
            signature: Signature::empty(),
            depth: 0,
            delegatee_kind: DelegateeKind::Human,
        };
        let signature = key.sign(&link.signing_payload().unwrap());
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/authority/delegate")
            .header("content-type", "application/json")
            .header("authorization", TEST_AUTHORIZATION)
            .body(Body::from(
                serde_json::json!({
                    "from": from.to_string(),
                    "to": to.to_string(),
                    "scope": vec!["read"; 65],
                    "expires_ms": 1_000,
                    "now_ms": 10,
                    "signature_hex": hex::encode(
                        signature.ed25519_bytes().expect("Ed25519 test signature")
                    ),
                })
                .to_string(),
            ))
            .unwrap();

        let delegate_with_max_scope_plus_one =
            mutation_test_router(pdp).oneshot(request).await.unwrap();

        assert_eq!(
            delegate_with_max_scope_plus_one.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn failed_persistence_rolls_back_authority_mutation() {
        let state = PdpHttpState {
            pdp: SharedPdp::ephemeral(),
            persist: Some(Arc::new(|_| {
                Err(PdpError::Persistence("disk unavailable".into()))
            })),
        };
        let actor = Did::new("did:exo:persistence-test").unwrap();
        let key = KeyPair::generate();
        let mut guard = state.pdp.lock().unwrap();
        let checkpoint = state.checkpoint(&guard).unwrap();
        guard.register_key(actor.clone(), *key.public_key());

        assert_eq!(
            state.persist_or_rollback(&mut guard, checkpoint),
            Err(PdpError::Persistence("disk unavailable".into()))
        );
        assert!(guard.resolve_public(&actor).is_none());
    }

    #[test]
    fn http_helpers_cover_router_inputs_and_successful_persistence() {
        let pdp = SharedPdp::ephemeral();
        let no_persist = PdpHttpState {
            pdp: pdp.clone(),
            persist: None,
        };
        let mut guard = no_persist.pdp.lock().unwrap();
        assert!(no_persist.checkpoint(&guard).unwrap().is_none());
        assert!(no_persist.persist_or_rollback(&mut guard, None).is_ok());
        drop(guard);

        let persisted = PdpHttpState {
            pdp: pdp.clone(),
            persist: Some(Arc::new(|_| Ok(()))),
        };
        let mut guard = persisted.pdp.lock().unwrap();
        let checkpoint = persisted.checkpoint(&guard).unwrap();
        assert!(checkpoint.is_some());
        assert!(
            persisted
                .persist_or_rollback(&mut guard, checkpoint)
                .is_ok()
        );
        drop(guard);

        let authorizer = PdpMutationAuthorizer::new(|_| true);
        let _ephemeral_router = pdp_router_with_authorizer(pdp.clone(), authorizer.clone());
        let _persistent_router =
            pdp_router_with_authorized_persistence(pdp.clone(), authorizer, |_| Ok(()));
        let _compat_read_router = pdp_router(pdp.clone());
        let _compat_persistent_read_router = pdp_router_with_persistence(pdp.clone(), |_| Ok(()));
        let _read_router = pdp_read_router(pdp.clone());

        assert_eq!(require_now_ms(Some(7)).unwrap(), Timestamp::new(7, 0));
        assert!(matches!(require_now_ms(None), Err(PdpError::BadRequest(_))));
        assert!(matches!(
            require_now_ms(Some(0)),
            Err(PdpError::BadRequest(_))
        ));

        let expected = [
            ("READ", Permission::Read),
            ("write", Permission::Write),
            ("execute", Permission::Execute),
            ("delegate", Permission::Delegate),
            ("govern", Permission::Govern),
            ("escalate", Permission::Escalate),
            ("challenge", Permission::Challenge),
            ("spend", Permission::Spend),
        ];
        for (wire, permission) in expected {
            assert_eq!(parse_perm(wire).unwrap(), permission);
        }
        assert!(matches!(parse_perm("mint"), Err(PdpError::BadRequest(_))));

        let hash_hex = "ab".repeat(32);
        assert_eq!(parse_hash(&hash_hex).unwrap().to_string(), hash_hex);
        assert!(matches!(parse_hash("zz"), Err(PdpError::BadRequest(_))));
        assert!(matches!(parse_hash("ab"), Err(PdpError::BadRequest(_))));

        assert_eq!(
            err(PdpError::BadRequest("bad".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(err(PdpError::EvidenceNotFound).0, StatusCode::NOT_FOUND);
        assert_eq!(err(PdpError::Revoked).0, StatusCode::FORBIDDEN);
        let internal = err(PdpError::Persistence("disk".into()));
        assert_eq!(internal.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(internal.1.0["never_moves_money"], true);

        let actor = Did::new("did:exo:snapshot-test").unwrap();
        let snapshot = pdp.snapshot_for(&actor).unwrap();
        assert_eq!(snapshot.granted, 0);
        assert_eq!(snapshot.received, 0);
        assert!(snapshot.permissions.is_empty());
    }

    #[tokio::test]
    async fn mutation_and_pack_handlers_cover_fail_closed_http_boundary() {
        let state = PdpHttpState {
            pdp: SharedPdp::ephemeral(),
            persist: Some(Arc::new(|_| Ok(()))),
        };
        let actor = Did::new("did:exo:http-handler-test").unwrap();
        let actor_key = KeyPair::generate();

        let registered = handle_register_key(
            State(state.clone()),
            Json(RegisterKeyBody {
                did: actor.to_string(),
                public_key_hex: hex::encode(actor_key.public_key().as_bytes()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(registered.0["registered"], true);
        assert_eq!(registered.0["did"], actor.to_string());

        let invalid_key = handle_register_key(
            State(state.clone()),
            Json(RegisterKeyBody {
                did: actor.to_string(),
                public_key_hex: "ab".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(invalid_key.0, StatusCode::BAD_REQUEST);

        let mandate_hash = "11".repeat(32);
        let reserved = handle_reserve(
            State(state.clone()),
            Json(HashBody {
                mandate_hash: mandate_hash.clone(),
                now_ms: Some(10),
            }),
        )
        .await
        .unwrap();
        assert_eq!(reserved.0["state"], "reserved");

        let released = handle_release(
            State(state.clone()),
            Json(HashBody {
                mandate_hash: mandate_hash.clone(),
                now_ms: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(released.0["state"], "released");

        let _ = handle_reserve(
            State(state.clone()),
            Json(HashBody {
                mandate_hash: mandate_hash.clone(),
                now_ms: Some(11),
            }),
        )
        .await
        .unwrap();
        let committed = handle_commit(
            State(state.clone()),
            Json(HashBody {
                mandate_hash: mandate_hash.clone(),
                now_ms: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(committed.0["state"], "committed");

        let delegation_hash = "22".repeat(32);
        let revoked = handle_revoke(
            State(state.clone()),
            Json(RevokeBody {
                mandate_hash: Some(mandate_hash.clone()),
                agent: Some(actor.to_string()),
                delegation_id: Some(delegation_hash),
                reason: None,
                now_ms: Some(12),
            }),
        )
        .await
        .unwrap();
        assert_eq!(revoked.0["revoked"], true);

        let missing = handle_evidence(State(state.clone()), Path("33".repeat(32)))
            .await
            .unwrap_err();
        assert_eq!(missing.0, StatusCode::NOT_FOUND);

        let (pack, service_key_hex) = {
            let guard = state.pdp.lock().unwrap();
            (
                guard.export_pack().unwrap(),
                hex::encode(guard.service_public_key().as_bytes()),
            )
        };
        let exported = handle_export_pack(State(state.clone())).await.unwrap();
        assert_eq!(exported.0.spec, pack.spec);

        let verified = handle_verify_pack(Json(VerifyPackBody {
            pack,
            expected_service_public_key_hex: service_key_hex,
        }))
        .await
        .unwrap();
        assert_eq!(verified.0["ok"], true);
        assert_eq!(verified.0["independently_verifiable"], true);
        assert_eq!(verified.0["never_moves_money"], true);
    }
}
