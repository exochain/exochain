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

/// Build the PDP router (own state — merge after gateway `with_state`).
pub fn pdp_router(pdp: SharedPdp) -> Router {
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
        .with_state(pdp)
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
    payment_valid: bool,
    #[serde(default)]
    now_ms: Option<u64>,
}

async fn handle_decide(
    State(pdp): State<SharedPdp>,
    Json(body): Json<DecideBody>,
) -> Result<Json<DecideResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mandate = body.mandate.into_mandate().map_err(err)?;
    let proposed = body.proposed.unwrap_or_else(|| ProposedAction {
        action: mandate.action.clone(),
        amount_minor: mandate.amount_minor,
        currency: mandate.currency.clone(),
        merchant: mandate.merchant.clone(),
        rail: None,
    });
    let req = DecisionRequest {
        mandate,
        proposed,
        payment_valid: body.payment_valid,
        now: require_now_ms(body.now_ms).map_err(err)?,
    };
    let mut guard = pdp.lock().map_err(err)?;
    let out = guard.decide(req).map_err(err)?;
    Ok(Json(DecideResponse::from(&out)))
}

#[derive(Debug, Deserialize)]
struct RegisterKeyBody {
    did: String,
    public_key_hex: String,
}

async fn handle_register_key(
    State(pdp): State<SharedPdp>,
    Json(body): Json<RegisterKeyBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
    guard.register_key(did.clone(), exo_core::PublicKey::from_bytes(arr));
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
    State(pdp): State<SharedPdp>,
    Json(body): Json<DelegateBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
    let link = guard.delegate(grant, move |_| sig).map_err(err)?;
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
    State(pdp): State<SharedPdp>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let now = Timestamp::new(body.now_ms.unwrap_or(0), 0);
    let reason = body.reason.unwrap_or_else(|| "revoked".into());
    let mut guard = pdp.lock().map_err(err)?;
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
    Ok(Json(serde_json::json!({ "revoked": true })))
}

#[derive(Debug, Deserialize)]
struct HashBody {
    mandate_hash: String,
    #[serde(default)]
    now_ms: Option<u64>,
}

async fn handle_reserve(
    State(pdp): State<SharedPdp>,
    Json(body): Json<HashBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let hash = parse_hash(&body.mandate_hash).map_err(err)?;
    let mut guard = pdp.lock().map_err(err)?;
    guard
        .reserve(hash, require_now_ms(body.now_ms).map_err(err)?)
        .map_err(err)?;
    Ok(Json(serde_json::json!({ "state": "reserved" })))
}

async fn handle_commit(
    State(pdp): State<SharedPdp>,
    Json(body): Json<HashBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let hash = parse_hash(&body.mandate_hash).map_err(err)?;
    let mut guard = pdp.lock().map_err(err)?;
    guard.commit(&hash).map_err(err)?;
    Ok(Json(serde_json::json!({ "state": "committed" })))
}

async fn handle_release(
    State(pdp): State<SharedPdp>,
    Json(body): Json<HashBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let hash = parse_hash(&body.mandate_hash).map_err(err)?;
    let mut guard = pdp.lock().map_err(err)?;
    guard.release(&hash).map_err(err)?;
    Ok(Json(serde_json::json!({ "state": "released" })))
}

async fn handle_evidence(
    State(pdp): State<SharedPdp>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
    State(pdp): State<SharedPdp>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
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
    State(pdp): State<SharedPdp>,
) -> Result<Json<crate::pack::EvidencePack>, (StatusCode, Json<serde_json::Value>)> {
    let guard = pdp.lock().map_err(err)?;
    Ok(Json(guard.export_pack()))
}

async fn handle_verify_pack(
    Json(pack): Json<crate::pack::EvidencePack>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    pack.verify().map_err(err)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "independently_verifiable": true,
        "never_moves_money": true,
        "article_26": pack.article_26,
        "entries": pack.entries.len(),
        "tip": pack.tip_hex,
    })))
}

async fn handle_x402_verify(
    State(pdp): State<SharedPdp>,
    Json(body): Json<X402VerifyRequest>,
) -> Result<Json<X402VerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut guard = pdp.lock().map_err(err)?;
    let resp = x402::verify(&mut guard, body).map_err(err)?;
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
