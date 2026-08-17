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
    extract::{Path, State},
    http::StatusCode,
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

/// Build the PDP router (own state — merge after gateway `with_state`).
pub fn pdp_router(pdp: SharedPdp) -> Router {
    build_pdp_router(PdpHttpState { pdp, persist: None })
}

/// Build the PDP router with a fail-closed mutation persistence boundary.
pub fn pdp_router_with_persistence<F>(pdp: SharedPdp, persist: F) -> Router
where
    F: Fn(&crate::service::PolicyDecisionPoint) -> crate::error::Result<()> + Send + Sync + 'static,
{
    build_pdp_router(PdpHttpState {
        pdp,
        persist: Some(Arc::new(persist)),
    })
}

fn build_pdp_router(state: PdpHttpState) -> Router {
    Router::new()
        .route("/api/v1/authority/decide", post(handle_decide))
        .route("/api/v1/authority/register-key", post(handle_register_key))
        .route("/api/v1/authority/delegate", post(handle_delegate))
        .route("/api/v1/authority/revoke", post(handle_revoke))
        .route("/api/v1/authority/reserve", post(handle_reserve))
        .route("/api/v1/authority/commit", post(handle_commit))
        .route("/api/v1/authority/release", post(handle_release))
        .route("/api/v1/authority/evidence/:hash", get(handle_evidence))
        .route(
            "/api/v1/authority/evidence/:hash/verify",
            get(handle_verify_evidence),
        )
        .route("/api/v1/authority/pack", get(handle_export_pack))
        .route("/api/v1/authority/pack/verify", post(handle_verify_pack))
        .route("/x402/verify", post(handle_x402_verify))
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
    use exo_core::{Did, crypto::KeyPair};

    use super::*;

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

        let _ephemeral_router = pdp_router(pdp.clone());
        let _persistent_router = pdp_router_with_persistence(pdp.clone(), |_| Ok(()));

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
