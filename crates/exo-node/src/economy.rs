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

//! Node API surface for the custody-native economy layer.
//!
//! Routes are merged into the gateway's axum router via the same
//! `serve_with_extra_routes` pattern used elsewhere on the node. POSTs
//! inherit bearer-token auth from the merged write guard. Reads are
//! public so quoting is free of authentication friction.
//!
//! All settlement mechanics are preserved end-to-end. During the launch
//! phase, every quote and settlement returns `charged_amount_micro_exo
//! = 0` with an explicit `zero_fee_reason`. Trust is never paywalled.
//!
//! ## Routes
//!
//! | Method | Path | Purpose |
//! |--------|------|---------|
//! | `POST` | `/api/v1/economy/quote` | Build a deterministic settlement quote. |
//! | `POST` | `/api/v1/economy/settle` | Settle a previously issued quote. |
//! | `GET`  | `/api/v1/economy/receipts/:id` | Fetch a settlement receipt. |
//! | `GET`  | `/api/v1/economy/policy/active` | Inspect the active pricing policy. |

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_core::{Hash256, Signature, Timestamp};
use exo_economy::{
    AdoptionEvent, AuthorityEnvelopeRef, AutomatedSettlementEvent, AutomatedSettlementInputs,
    AutomatedSettlementRiskState, BailmentTerms, BailmentWrapper, BailmentWrapperStatus,
    ContributionAcceptance, ContributionOffer, ContributionOfferStatus, ContributionReceipt,
    EconomyError, EconomyObjectKind, EconomyRecordAnchor, EconomyStore, HonorGoodRuleset,
    InMemoryEconomyStore, LegacyReceipt, MicroExo, Mission, MissionSettlement, PricingInputs,
    PricingPolicy, RulesetStatus, SettlementBasis, SettlementContext, SettlementQuote,
    SettlementReceipt, UseEvent, ValueContributionNode, ValueContributionStatus, ValueEvent,
    ZeroFeeReason, quote, settle,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tower::limit::ConcurrencyLimitLayer;

use crate::store::SqliteDagStore;

const MAX_ECONOMY_API_BODY_BYTES: usize = 64 * 1024;
const MAX_ECONOMY_API_CONCURRENT_REQUESTS: usize = 64;

pub type SettlementSigner = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;

/// Shared state for economy route handlers.
#[derive(Clone)]
pub struct EconomyApiState {
    pub store: Arc<Mutex<InMemoryEconomyStore>>,
    pub durable_store: Option<Arc<Mutex<SqliteDagStore>>>,
    settlement_signer: SettlementSigner,
}

impl EconomyApiState {
    /// Construct a fresh state seeded with the zero-launch policy.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(settlement_signer: SettlementSigner) -> Self {
        Self {
            store: Arc::new(Mutex::new(InMemoryEconomyStore::new())),
            durable_store: None,
            settlement_signer,
        }
    }

    /// Construct a state that persists HonorGood and mission-economics
    /// objects to the node's SQLite DAG database.
    #[must_use]
    pub fn with_durable_store(
        settlement_signer: SettlementSigner,
        durable_store: Arc<Mutex<SqliteDagStore>>,
    ) -> Self {
        Self {
            store: Arc::new(Mutex::new(InMemoryEconomyStore::new())),
            durable_store: Some(durable_store),
            settlement_signer,
        }
    }
}

// ---------------------------------------------------------------------------
// Request / Response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteRequest {
    pub quote_id: String,
    pub inputs: PricingInputs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SettleRequest {
    pub quote_hash_hex: String,
    pub context: SettlementContext,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub policy: PricingPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EconomyObjectResponse<T> {
    pub object: T,
    pub anchor: EconomyRecordAnchor,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MissionSettlementRequest {
    pub mission_id: Hash256,
    pub ruleset_id: Hash256,
    pub gross_revenue_micro_exo: MicroExo,
    pub pass_through_expenses_micro_exo: MicroExo,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub prev_settlement_hash: Option<Hash256>,
    pub created_at: Timestamp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomatedSettlementRequest {
    pub value_event_id: Hash256,
    pub automation_authority_ref: exo_economy::AuthorityEnvelopeRef,
    pub preapproved_terms_hash: Hash256,
    pub basis_amounts: BTreeMap<SettlementBasis, MicroExo>,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub created_at_hlc: Timestamp,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ApiError = (StatusCode, String);
type ApiResult<T> = Result<T, ApiError>;

fn parse_hash_field(raw: &str, field: &'static str) -> ApiResult<Hash256> {
    let bytes = hex::decode(raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("{field} must be lowercase hex"),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be 32 bytes (64 hex chars)"),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(buf))
}

fn parse_hash(raw: &str) -> ApiResult<Hash256> {
    parse_hash_field(raw, "quote_hash_hex")
}

async fn with_store_blocking<T, F>(state: Arc<EconomyApiState>, op: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut InMemoryEconomyStore) -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut guard = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "economy store unavailable".into(),
            )
        })?;
        op(&mut guard)
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "economy store task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "economy store task failed".into(),
        )
    })?
}

async fn persist_economy_object<T, F>(
    state: Arc<EconomyApiState>,
    object_kind: EconomyObjectKind,
    object_id: Hash256,
    content_hash: Hash256,
    created_at: Timestamp,
    object: T,
    put_memory: F,
) -> ApiResult<EconomyRecordAnchor>
where
    T: Clone + Serialize + Send + 'static,
    F: FnOnce(&mut InMemoryEconomyStore, T) -> Result<EconomyRecordAnchor, EconomyError>
        + Send
        + 'static,
{
    tokio::task::spawn_blocking(move || {
        if let Some(durable_store) = &state.durable_store {
            let mut guard = durable_store.lock().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "economy durable store unavailable".into(),
                )
            })?;
            return guard
                .put_economy_object_sync(object_kind, &object_id, &content_hash, created_at, &object)
                .map_err(|err| {
                    tracing::warn!(err = %err, kind = object_kind.label(), "economy durable object rejected");
                    (StatusCode::UNPROCESSABLE_ENTITY, err.to_string())
                });
        }

        let mut guard = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "economy store unavailable".into(),
            )
        })?;
        put_memory(&mut guard, object).map_err(map_economy_error)
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "economy object persistence task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "economy object persistence task failed".into(),
        )
    })?
}

async fn read_economy_object<T, F>(
    state: Arc<EconomyApiState>,
    object_kind: EconomyObjectKind,
    object_id: Hash256,
    get_memory: F,
) -> ApiResult<Option<T>>
where
    T: Clone + DeserializeOwned + Send + 'static,
    F: FnOnce(&InMemoryEconomyStore, &Hash256) -> Result<Option<T>, EconomyError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        if let Some(durable_store) = &state.durable_store {
            let guard = durable_store.lock().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "economy durable store unavailable".into(),
                )
            })?;
            return guard
                .get_economy_object_sync(object_kind, &object_id)
                .map_err(|err| {
                    tracing::warn!(err = %err, kind = object_kind.label(), "economy durable object read failed");
                    (StatusCode::INTERNAL_SERVER_ERROR, "economy durable read failed".into())
                });
        }

        let guard = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "economy store unavailable".into(),
            )
        })?;
        get_memory(&guard, &object_id).map_err(map_economy_error)
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "economy object read task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "economy object read task failed".into(),
        )
    })?
}

async fn require_economy_object<T, F>(
    state: Arc<EconomyApiState>,
    object_kind: EconomyObjectKind,
    object_id: Hash256,
    get_memory: F,
    label: &'static str,
) -> ApiResult<T>
where
    T: Clone + DeserializeOwned + Send + 'static,
    F: FnOnce(&InMemoryEconomyStore, &Hash256) -> Result<Option<T>, EconomyError> + Send + 'static,
{
    read_economy_object(state, object_kind, object_id, get_memory)
        .await?
        .ok_or((StatusCode::NOT_FOUND, format!("{label} not found")))
}

async fn latest_economy_anchor_hash(state: Arc<EconomyApiState>) -> ApiResult<Hash256> {
    tokio::task::spawn_blocking(move || {
        if let Some(durable_store) = &state.durable_store {
            let guard = durable_store.lock().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "economy durable store unavailable".into(),
                )
            })?;
            return guard.latest_economy_anchor_hash_sync().map_err(|err| {
                tracing::warn!(err = %err, "economy durable latest anchor read failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "economy durable latest anchor read failed".into(),
                )
            });
        }

        let guard = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "economy store unavailable".into(),
            )
        })?;
        Ok(guard.latest_economy_anchor_hash())
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "economy latest anchor task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "economy latest anchor task failed".into(),
        )
    })?
}

async fn read_economy_anchor(
    state: Arc<EconomyApiState>,
    anchor_hash: Hash256,
) -> ApiResult<Option<EconomyRecordAnchor>> {
    tokio::task::spawn_blocking(move || {
        if let Some(durable_store) = &state.durable_store {
            let guard = durable_store.lock().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "economy durable store unavailable".into(),
                )
            })?;
            return guard.get_economy_anchor_sync(&anchor_hash).map_err(|err| {
                tracing::warn!(err = %err, "economy durable anchor read failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "economy durable anchor read failed".into(),
                )
            });
        }

        let guard = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "economy store unavailable".into(),
            )
        })?;
        guard
            .get_economy_anchor(&anchor_hash)
            .map_err(map_economy_error)
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "economy anchor read task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "economy anchor read task failed".into(),
        )
    })?
}

fn map_economy_error(err: EconomyError) -> ApiError {
    tracing::warn!(?err, "economy operation rejected");
    match err {
        EconomyError::EmptyField { .. }
        | EconomyError::BasisPointOutOfRange { .. }
        | EconomyError::FloorAboveCeiling { .. }
        | EconomyError::UnsupportedSettlementBasis { .. }
        | EconomyError::InvalidInput { .. } => (StatusCode::BAD_REQUEST, err.to_string()),
        EconomyError::QuoteExpired => (StatusCode::CONFLICT, err.to_string()),
        EconomyError::QuoteNotFound | EconomyError::UnknownPolicy { .. } => {
            (StatusCode::NOT_FOUND, err.to_string())
        }
        EconomyError::QuoteHashMismatch
        | EconomyError::ReceiptHashMismatch
        | EconomyError::HashMismatch { .. }
        | EconomyError::RevenueShareOverAllocated { .. }
        | EconomyError::SettlementOverAllocated { .. }
        | EconomyError::ArithmeticOverflow { .. }
        | EconomyError::ArithmeticUnderflow { .. }
        | EconomyError::UnsupportedStatusTransition { .. }
        | EconomyError::AutomatedSettlementRejected { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, err.to_string())
        }
        EconomyError::Serialization { .. }
        | EconomyError::EmptySettlementSignature { .. }
        | EconomyError::ZeroLaunchInvariantViolated { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "economy error".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_quote(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<QuoteRequest>,
) -> ApiResult<Json<SettlementQuote>> {
    let result = with_store_blocking(state, move |store| {
        let policy = store.get_active_policy().map_err(map_economy_error)?;
        let quote_record =
            quote(&policy, &payload.inputs, payload.quote_id).map_err(map_economy_error)?;
        // Allow re-quoting the same canonical inputs by ignoring duplicate-hash
        // errors on the put: the stored record is identical to the new one.
        if let Err(EconomyError::InvalidInput { .. }) = store.put_quote(quote_record.clone()) {
            // Existing canonical quote already stored — no-op.
        }
        Ok(quote_record)
    })
    .await?;
    Ok(Json(result))
}

async fn handle_settle(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<SettleRequest>,
) -> ApiResult<Json<SettlementReceipt>> {
    let quote_hash = parse_hash(&payload.quote_hash_hex)?;
    let mut context = payload.context;
    let settlement_signer = Arc::clone(&state.settlement_signer);
    let receipt = with_store_blocking(state, move |store| {
        let stored = store
            .get_quote(&quote_hash)
            .map_err(map_economy_error)?
            .ok_or_else(|| map_economy_error(EconomyError::QuoteNotFound))?;
        context.prev_settlement_receipt = store.latest_receipt_hash();
        let receipt = settle(&stored, &context, |payload| (settlement_signer)(payload))
            .map_err(map_economy_error)?;
        store
            .put_receipt(receipt.clone())
            .map_err(map_economy_error)?;
        Ok(receipt)
    })
    .await?;
    Ok(Json(receipt))
}

async fn handle_get_receipt(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<SettlementReceipt>> {
    let receipt = with_store_blocking(state, move |store| {
        store
            .get_receipt(&id)
            .map_err(map_economy_error)?
            .ok_or((StatusCode::NOT_FOUND, "receipt not found".into()))
    })
    .await?;
    Ok(Json(receipt))
}

async fn handle_active_policy(
    State(state): State<Arc<EconomyApiState>>,
) -> ApiResult<Json<PolicyResponse>> {
    let policy = with_store_blocking(state, move |store| {
        store.get_active_policy().map_err(map_economy_error)
    })
    .await?;
    Ok(Json(PolicyResponse { policy }))
}

async fn handle_get_latest_economy_anchor(
    State(state): State<Arc<EconomyApiState>>,
) -> ApiResult<Json<EconomyRecordAnchor>> {
    let anchor_hash = latest_economy_anchor_hash(Arc::clone(&state)).await?;
    if anchor_hash == Hash256::ZERO {
        return Err((StatusCode::NOT_FOUND, "economy anchor not found".into()));
    }
    let anchor = read_economy_anchor(state, anchor_hash)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "economy anchor not found".into()))?;
    Ok(Json(anchor))
}

async fn handle_get_economy_anchor(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<EconomyRecordAnchor>> {
    let anchor_hash = parse_hash_field(&id, "economy_anchor_hash")?;
    let anchor = read_economy_anchor(state, anchor_hash)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "economy anchor not found".into()))?;
    Ok(Json(anchor))
}

macro_rules! simple_post_get_handlers {
    (
        $post_fn:ident,
        $get_fn:ident,
        $ty:ty,
        $kind:ident,
        $id_field:ident,
        $created_field:ident,
        $put_method:ident,
        $get_method:ident,
        $label:literal
    ) => {
        async fn $post_fn(
            State(state): State<Arc<EconomyApiState>>,
            Json(payload): Json<$ty>,
        ) -> ApiResult<Json<EconomyObjectResponse<$ty>>> {
            let object = payload.anchor().map_err(map_economy_error)?;
            let anchor = persist_economy_object(
                state,
                EconomyObjectKind::$kind,
                object.$id_field,
                object.content_hash,
                object.$created_field,
                object.clone(),
                |store, value| store.$put_method(value),
            )
            .await?;
            Ok(Json(EconomyObjectResponse { object, anchor }))
        }

        async fn $get_fn(
            State(state): State<Arc<EconomyApiState>>,
            Path(id): Path<String>,
        ) -> ApiResult<Json<$ty>> {
            let id = parse_hash_field(&id, concat!($label, "_id"))?;
            let object = require_economy_object(
                state,
                EconomyObjectKind::$kind,
                id,
                |store, value| store.$get_method(value),
                $label,
            )
            .await?;
            Ok(Json(object))
        }
    };
}

simple_post_get_handlers!(
    handle_post_mission,
    handle_get_mission,
    Mission,
    Mission,
    mission_id,
    created_at,
    put_mission,
    get_mission,
    "mission"
);

simple_post_get_handlers!(
    handle_post_legacy_receipt,
    handle_get_legacy_receipt,
    LegacyReceipt,
    LegacyReceipt,
    legacy_receipt_id,
    created_at,
    put_legacy_receipt,
    get_legacy_receipt,
    "legacy_receipt"
);

simple_post_get_handlers!(
    handle_post_ruleset,
    handle_get_ruleset,
    HonorGoodRuleset,
    HonorGoodRuleset,
    ruleset_id,
    created_at,
    put_ruleset,
    get_ruleset,
    "ruleset"
);

simple_post_get_handlers!(
    handle_post_value_contribution_node,
    handle_get_value_contribution_node,
    ValueContributionNode,
    ValueContributionNode,
    contribution_node_id,
    created_at_hlc,
    put_value_contribution_node,
    get_value_contribution_node,
    "contribution_node"
);

simple_post_get_handlers!(
    handle_post_bailment_terms,
    handle_get_bailment_terms,
    BailmentTerms,
    BailmentTerms,
    terms_id,
    created_at_hlc,
    put_bailment_terms,
    get_bailment_terms,
    "bailment_terms"
);

async fn handle_post_contribution_receipt(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<ContributionReceipt>,
) -> ApiResult<Json<EconomyObjectResponse<ContributionReceipt>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    if let Some(mission_id) = object.mission_id {
        let _mission: Mission = require_economy_object(
            Arc::clone(&state),
            EconomyObjectKind::Mission,
            mission_id,
            |store, value| store.get_mission(value),
            "mission",
        )
        .await?;
    }
    if let Some(contribution_node_id) = object.contribution_node_id {
        let _node: ValueContributionNode = require_economy_object(
            Arc::clone(&state),
            EconomyObjectKind::ValueContributionNode,
            contribution_node_id,
            |store, value| store.get_value_contribution_node(value),
            "value contribution node",
        )
        .await?;
    }
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::ContributionReceipt,
        object.receipt_id,
        object.content_hash,
        object.created_at,
        object.clone(),
        |store, value| store.put_contribution_receipt(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_contribution_receipt(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ContributionReceipt>> {
    let id = parse_hash_field(&id, "contribution_receipt_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::ContributionReceipt,
        id,
        |store, value| store.get_contribution_receipt(value),
        "contribution receipt",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_contribution_offer(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<ContributionOffer>,
) -> ApiResult<Json<EconomyObjectResponse<ContributionOffer>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::ContributionOffer,
        object.offer_id,
        object.content_hash,
        object.created_at_hlc,
        object.clone(),
        |store, value| store.put_contribution_offer(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_contribution_offer(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ContributionOffer>> {
    let id = parse_hash_field(&id, "contribution_offer_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::ContributionOffer,
        id,
        |store, value| store.get_contribution_offer(value),
        "contribution offer",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_contribution_acceptance(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<ContributionAcceptance>,
) -> ApiResult<Json<EconomyObjectResponse<ContributionAcceptance>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    let offer: ContributionOffer = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionOffer,
        object.offer_id,
        |store, value| store.get_contribution_offer(value),
        "contribution offer",
    )
    .await?;
    object
        .validate_against_offer(&offer)
        .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::ContributionAcceptance,
        object.acceptance_id,
        object.content_hash,
        object.accepted_at_hlc,
        object.clone(),
        |store, value| store.put_contribution_acceptance(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_contribution_acceptance(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ContributionAcceptance>> {
    let id = parse_hash_field(&id, "contribution_acceptance_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::ContributionAcceptance,
        id,
        |store, value| store.get_contribution_acceptance(value),
        "contribution acceptance",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_bailment_wrapper(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<BailmentWrapper>,
) -> ApiResult<Json<EconomyObjectResponse<BailmentWrapper>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    let offer: ContributionOffer = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionOffer,
        object.offer_id,
        |store, value| store.get_contribution_offer(value),
        "contribution offer",
    )
    .await?;
    let acceptance: ContributionAcceptance = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionAcceptance,
        object.acceptance_id,
        |store, value| store.get_contribution_acceptance(value),
        "contribution acceptance",
    )
    .await?;
    let terms: BailmentTerms = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::BailmentTerms,
        object.accepted_bailment_terms_hash,
        |store, value| store.get_bailment_terms(value),
        "bailment terms",
    )
    .await?;
    object
        .validate_against(&offer, &acceptance, &terms)
        .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::BailmentWrapper,
        object.wrapper_id,
        object.content_hash,
        object.created_at_hlc,
        object.clone(),
        |store, value| store.put_bailment_wrapper(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_bailment_wrapper(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<BailmentWrapper>> {
    let id = parse_hash_field(&id, "bailment_wrapper_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::BailmentWrapper,
        id,
        |store, value| store.get_bailment_wrapper(value),
        "bailment wrapper",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_adoption_event(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<AdoptionEvent>,
) -> ApiResult<Json<EconomyObjectResponse<AdoptionEvent>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    let offer: ContributionOffer = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionOffer,
        object.offer_id,
        |store, value| store.get_contribution_offer(value),
        "contribution offer",
    )
    .await?;
    let acceptance: ContributionAcceptance = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionAcceptance,
        object.acceptance_id,
        |store, value| store.get_contribution_acceptance(value),
        "contribution acceptance",
    )
    .await?;
    let wrapper: BailmentWrapper = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::BailmentWrapper,
        object.bailment_wrapper_id,
        |store, value| store.get_bailment_wrapper(value),
        "bailment wrapper",
    )
    .await?;
    object
        .validate_against(&offer, &acceptance, &wrapper)
        .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::AdoptionEvent,
        object.adoption_id,
        object.content_hash,
        object.created_at_hlc,
        object.clone(),
        |store, value| store.put_adoption_event(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_adoption_event(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<AdoptionEvent>> {
    let id = parse_hash_field(&id, "adoption_event_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::AdoptionEvent,
        id,
        |store, value| store.get_adoption_event(value),
        "adoption event",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_use_event(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<UseEvent>,
) -> ApiResult<Json<EconomyObjectResponse<UseEvent>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    let adoption: AdoptionEvent = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::AdoptionEvent,
        object.adoption_id,
        |store, value| store.get_adoption_event(value),
        "adoption event",
    )
    .await?;
    object
        .validate_against_adoption(&adoption)
        .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::UseEvent,
        object.use_event_id,
        object.content_hash,
        object.created_at_hlc,
        object.clone(),
        |store, value| store.put_use_event(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_use_event(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<UseEvent>> {
    let id = parse_hash_field(&id, "use_event_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::UseEvent,
        id,
        |store, value| store.get_use_event(value),
        "use event",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_value_event(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<ValueEvent>,
) -> ApiResult<Json<EconomyObjectResponse<ValueEvent>>> {
    let object = payload.anchor().map_err(map_economy_error)?;
    let use_event: UseEvent = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::UseEvent,
        object.use_event_id,
        |store, value| store.get_use_event(value),
        "use event",
    )
    .await?;
    object
        .validate_against_use_event(&use_event)
        .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::ValueEvent,
        object.value_event_id,
        object.content_hash,
        object.created_at_hlc,
        object.clone(),
        |store, value| store.put_value_event(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_value_event(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<ValueEvent>> {
    let id = parse_hash_field(&id, "value_event_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::ValueEvent,
        id,
        |store, value| store.get_value_event(value),
        "value event",
    )
    .await?;
    Ok(Json(object))
}

async fn handle_post_mission_settlement(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<MissionSettlementRequest>,
) -> ApiResult<Json<EconomyObjectResponse<MissionSettlement>>> {
    let _mission: Mission = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::Mission,
        payload.mission_id,
        |store, value| store.get_mission(value),
        "mission",
    )
    .await?;
    let ruleset: HonorGoodRuleset = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::HonorGoodRuleset,
        payload.ruleset_id,
        |store, value| store.get_ruleset(value),
        "ruleset",
    )
    .await?;
    let object = MissionSettlement::from_ruleset(
        payload.mission_id,
        &ruleset,
        payload.gross_revenue_micro_exo,
        payload.pass_through_expenses_micro_exo,
        payload.zero_fee_reason,
        payload.prev_settlement_hash,
        payload.created_at,
    )
    .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::MissionSettlement,
        object.settlement_id,
        object.content_hash,
        object.created_at,
        object.clone(),
        |store, value| store.put_mission_settlement(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_mission_settlement(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<MissionSettlement>> {
    let id = parse_hash_field(&id, "mission_settlement_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::MissionSettlement,
        id,
        |store, value| store.get_mission_settlement(value),
        "mission settlement",
    )
    .await?;
    Ok(Json(object))
}

struct AutomatedSettlementEvidenceSource<'a> {
    offer: &'a ContributionOffer,
    acceptance: &'a ContributionAcceptance,
    terms: &'a BailmentTerms,
    wrapper: &'a BailmentWrapper,
    adoption: &'a AdoptionEvent,
    use_event: &'a UseEvent,
    value_event: &'a ValueEvent,
    contribution_node: &'a ValueContributionNode,
    ruleset: &'a HonorGoodRuleset,
    automation_authority_ref: &'a AuthorityEnvelopeRef,
}

fn derive_automated_settlement_risk_state(
    source: AutomatedSettlementEvidenceSource<'_>,
) -> Result<AutomatedSettlementRiskState, EconomyError> {
    source.contribution_node.validate()?;
    source.ruleset.validate()?;
    source.acceptance.validate_against_offer(source.offer)?;
    source
        .wrapper
        .validate_against(source.offer, source.acceptance, source.terms)?;
    source
        .adoption
        .validate_against(source.offer, source.acceptance, source.wrapper)?;
    source
        .use_event
        .validate_against_adoption(source.adoption)?;
    source
        .value_event
        .validate_against_use_event(source.use_event)?;
    source.automation_authority_ref.validate()?;

    let authority_matches_acceptance = source.automation_authority_ref
        == &source.acceptance.authority_envelope
        && source.acceptance.authority_envelope.authority_proof_hash
            == source.adoption.authority_proof_hash;
    let ruleset_matches_evidence = source.ruleset.ruleset_id
        == source.contribution_node.settlement_ruleset_id
        && source.ruleset.ruleset_id == source.wrapper.settlement_ruleset_id
        && source.ruleset.ruleset_id == source.offer.settlement_ruleset_id;
    let revocation_active = matches!(source.offer.status, ContributionOfferStatus::Revoked)
        || matches!(source.wrapper.status, BailmentWrapperStatus::Revoked)
        || matches!(source.ruleset.status, RulesetStatus::Revoked)
        || matches!(
            source.contribution_node.status,
            ValueContributionStatus::Revoked
        );
    if !matches!(source.offer.status, ContributionOfferStatus::Accepted) {
        return Err(EconomyError::AutomatedSettlementRejected {
            reason: "automated settlement requires an accepted offer".into(),
        });
    }
    if !authority_matches_acceptance {
        return Err(EconomyError::AutomatedSettlementRejected {
            reason: "delegated authority is invalid".into(),
        });
    }
    if !ruleset_matches_evidence {
        return Err(EconomyError::AutomatedSettlementRejected {
            reason: "ruleset hash does not match".into(),
        });
    }
    if !source.value_event.settlement_triggered {
        return Err(EconomyError::AutomatedSettlementRejected {
            reason: "value event is invalid".into(),
        });
    }
    if !source.offer.legal_effect.permits_settlement() {
        return Err(EconomyError::AutomatedSettlementRejected {
            reason: "legal effect is insufficient for automated settlement".into(),
        });
    }
    let risk_state = AutomatedSettlementRiskState {
        dispute_active: false,
        revocation_active,
        materiality_disputed: false,
    };
    risk_state.validate()?;
    Ok(risk_state)
}

async fn handle_post_automated_settlement_event(
    State(state): State<Arc<EconomyApiState>>,
    Json(payload): Json<AutomatedSettlementRequest>,
) -> ApiResult<Json<EconomyObjectResponse<AutomatedSettlementEvent>>> {
    let value_event: ValueEvent = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ValueEvent,
        payload.value_event_id,
        |store, value| store.get_value_event(value),
        "value event",
    )
    .await?;
    let use_event: UseEvent = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::UseEvent,
        value_event.use_event_id,
        |store, value| store.get_use_event(value),
        "use event",
    )
    .await?;
    let adoption: AdoptionEvent = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::AdoptionEvent,
        use_event.adoption_id,
        |store, value| store.get_adoption_event(value),
        "adoption event",
    )
    .await?;
    let contribution_node: ValueContributionNode = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ValueContributionNode,
        value_event.contribution_node_id,
        |store, value| store.get_value_contribution_node(value),
        "value contribution node",
    )
    .await?;
    let ruleset: HonorGoodRuleset = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::HonorGoodRuleset,
        contribution_node.settlement_ruleset_id,
        |store, value| store.get_ruleset(value),
        "ruleset",
    )
    .await?;
    let wrapper: BailmentWrapper = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::BailmentWrapper,
        adoption.bailment_wrapper_id,
        |store, value| store.get_bailment_wrapper(value),
        "bailment wrapper",
    )
    .await?;
    let acceptance: ContributionAcceptance = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionAcceptance,
        wrapper.acceptance_id,
        |store, value| store.get_contribution_acceptance(value),
        "contribution acceptance",
    )
    .await?;
    let offer: ContributionOffer = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::ContributionOffer,
        acceptance.offer_id,
        |store, value| store.get_contribution_offer(value),
        "contribution offer",
    )
    .await?;
    let terms: BailmentTerms = require_economy_object(
        Arc::clone(&state),
        EconomyObjectKind::BailmentTerms,
        acceptance.accepted_bailment_terms_hash,
        |store, value| store.get_bailment_terms(value),
        "bailment terms",
    )
    .await?;
    if adoption.acceptance_id != acceptance.acceptance_id
        || wrapper.acceptance_id != acceptance.acceptance_id
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "automated settlement authority acceptance does not match adoption or wrapper".into(),
        ));
    }
    let risk_state = derive_automated_settlement_risk_state(AutomatedSettlementEvidenceSource {
        offer: &offer,
        acceptance: &acceptance,
        terms: &terms,
        wrapper: &wrapper,
        adoption: &adoption,
        use_event: &use_event,
        value_event: &value_event,
        contribution_node: &contribution_node,
        ruleset: &ruleset,
        automation_authority_ref: &payload.automation_authority_ref,
    })
    .map_err(map_economy_error)?;
    let object = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
        value_event: &value_event,
        use_event: &use_event,
        contribution_node: &contribution_node,
        offer: &offer,
        acceptance: &acceptance,
        bailment_terms: &terms,
        adoption: &adoption,
        ruleset: &ruleset,
        wrapper: &wrapper,
        automation_authority_ref: acceptance.authority_envelope.clone(),
        preapproved_terms_hash: payload.preapproved_terms_hash,
        basis_amounts: &payload.basis_amounts,
        zero_fee_reason: payload.zero_fee_reason,
        risk_state,
        created_at_hlc: payload.created_at_hlc,
    })
    .map_err(map_economy_error)?;
    let anchor = persist_economy_object(
        state,
        EconomyObjectKind::AutomatedSettlementEvent,
        object.automated_settlement_id,
        object.content_hash,
        object.created_at_hlc,
        object.clone(),
        |store, value| store.put_automated_settlement_event(value),
    )
    .await?;
    Ok(Json(EconomyObjectResponse { object, anchor }))
}

async fn handle_get_automated_settlement_event(
    State(state): State<Arc<EconomyApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<AutomatedSettlementEvent>> {
    let id = parse_hash_field(&id, "automated_settlement_id")?;
    let object = require_economy_object(
        state,
        EconomyObjectKind::AutomatedSettlementEvent,
        id,
        |store, value| store.get_automated_settlement_event(value),
        "automated settlement event",
    )
    .await?;
    Ok(Json(object))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn economy_router(state: Arc<EconomyApiState>) -> Router {
    Router::new()
        .route("/api/v1/economy/quote", post(handle_quote))
        .route("/api/v1/economy/settle", post(handle_settle))
        .route("/api/v1/economy/receipts/:id", get(handle_get_receipt))
        .route("/api/v1/economy/policy/active", get(handle_active_policy))
        .route(
            "/api/v1/economy/anchors/latest",
            get(handle_get_latest_economy_anchor),
        )
        .route(
            "/api/v1/economy/anchors/:id",
            get(handle_get_economy_anchor),
        )
        .route("/api/v1/economy/missions", post(handle_post_mission))
        .route("/api/v1/economy/missions/:id", get(handle_get_mission))
        .route(
            "/api/v1/economy/contribution-receipts",
            post(handle_post_contribution_receipt),
        )
        .route(
            "/api/v1/economy/contribution-receipts/:id",
            get(handle_get_contribution_receipt),
        )
        .route(
            "/api/v1/economy/legacy-receipts",
            post(handle_post_legacy_receipt),
        )
        .route(
            "/api/v1/economy/legacy-receipts/:id",
            get(handle_get_legacy_receipt),
        )
        .route("/api/v1/economy/rulesets", post(handle_post_ruleset))
        .route("/api/v1/economy/rulesets/:id", get(handle_get_ruleset))
        .route(
            "/api/v1/economy/contribution-nodes",
            post(handle_post_value_contribution_node),
        )
        .route(
            "/api/v1/economy/contribution-nodes/:id",
            get(handle_get_value_contribution_node),
        )
        .route(
            "/api/v1/economy/contribution-offers",
            post(handle_post_contribution_offer),
        )
        .route(
            "/api/v1/economy/contribution-offers/:id",
            get(handle_get_contribution_offer),
        )
        .route(
            "/api/v1/economy/contribution-acceptances",
            post(handle_post_contribution_acceptance),
        )
        .route(
            "/api/v1/economy/contribution-acceptances/:id",
            get(handle_get_contribution_acceptance),
        )
        .route(
            "/api/v1/economy/bailment-terms",
            post(handle_post_bailment_terms),
        )
        .route(
            "/api/v1/economy/bailment-terms/:id",
            get(handle_get_bailment_terms),
        )
        .route(
            "/api/v1/economy/bailment-wrappers",
            post(handle_post_bailment_wrapper),
        )
        .route(
            "/api/v1/economy/bailment-wrappers/:id",
            get(handle_get_bailment_wrapper),
        )
        .route(
            "/api/v1/economy/adoption-events",
            post(handle_post_adoption_event),
        )
        .route(
            "/api/v1/economy/adoption-events/:id",
            get(handle_get_adoption_event),
        )
        .route("/api/v1/economy/use-events", post(handle_post_use_event))
        .route("/api/v1/economy/use-events/:id", get(handle_get_use_event))
        .route(
            "/api/v1/economy/value-events",
            post(handle_post_value_event),
        )
        .route(
            "/api/v1/economy/value-events/:id",
            get(handle_get_value_event),
        )
        .route(
            "/api/v1/economy/mission-settlements",
            post(handle_post_mission_settlement),
        )
        .route(
            "/api/v1/economy/mission-settlements/:id",
            get(handle_get_mission_settlement),
        )
        .route(
            "/api/v1/economy/automated-settlements",
            post(handle_post_automated_settlement_event),
        )
        .route(
            "/api/v1/economy/automated-settlements/:id",
            get(handle_get_automated_settlement_event),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_ECONOMY_API_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(
            MAX_ECONOMY_API_CONCURRENT_REQUESTS,
        ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        body::{self, Body},
        http::{Method, Request},
        response::Response,
    };
    use exo_core::{
        Did, Hash256, Timestamp,
        crypto::{self, KeyPair},
        types::PublicKey,
    };
    use exo_economy::{
        ActorClass, AdopterType, AdoptionEvent, ApprovalStatus, AssuranceClass,
        AuthorityEnvelopeRef, BailmentTerms, BailmentWrapper, BailmentWrapperStatus,
        ContributionAcceptance, ContributionCategory, ContributionContributorType,
        ContributionOffer, ContributionOfferStatus, ContributionReceipt, ContributionType,
        ContributorType, EventClass, ExpirationOrReview, HonorGoodRuleset, LegalEffect,
        MaterialityTier, Mission, MissionSettlement, ParticipantRef, RequiredAuthorityLevel,
        UseEvent, UseType, ValueBasis, ValueContributionNode, ValueContributionStatus, ValueEvent,
        ZeroFeeReason, apex_velocity_catalyst_client_services_mission,
        apex_velocity_catalyst_client_services_ruleset, archon_exoforge_legacy_receipt,
    };
    use serde::{Serialize, de::DeserializeOwned};
    use tower::ServiceExt;

    use super::*;

    fn test_keypair() -> KeyPair {
        KeyPair::from_secret_bytes([0xEC; 32]).unwrap()
    }

    fn fresh_signed_state() -> (Arc<EconomyApiState>, PublicKey) {
        let keypair = test_keypair();
        let public_key = *keypair.public_key();
        let signer: SettlementSigner = Arc::new(move |payload: &[u8]| keypair.sign(payload));
        (Arc::new(EconomyApiState::new(signer)), public_key)
    }

    fn fresh_state() -> Arc<EconomyApiState> {
        fresh_signed_state().0
    }

    fn baseline_inputs() -> PricingInputs {
        PricingInputs {
            actor_did: Did::new("did:exo:agent").unwrap(),
            actor_class: ActorClass::Holon,
            event_class: EventClass::HolonCommercialAction,
            assurance_class: AssuranceClass::Standard,
            declared_value_micro_exo: Some(1_000_000),
            realized_value_micro_exo: None,
            compute_units: 100,
            storage_bytes: 4_096,
            verification_ops: 5,
            network_load_bp: 10_000,
            risk_bp: 1_500,
            market_domain: None,
            timestamp: Timestamp::new(1_000_000, 0),
        }
    }

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn participant(label: &str) -> ParticipantRef {
        ParticipantRef::Did(Did::new(&format!("did:exo:{label}")).unwrap())
    }

    fn authority(label: &str) -> AuthorityEnvelopeRef {
        AuthorityEnvelopeRef {
            envelope_id: h(0xA1),
            authority_proof_hash: h(0xA2),
            principal_ref: participant(label),
        }
    }

    async fn read_body(response: axum::response::Response) -> Vec<u8> {
        body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    async fn post_json<T: Serialize>(app: &Router, uri: &str, payload: &T) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn get_response(app: &Router, uri: String) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn decode_body<T: DeserializeOwned>(response: Response) -> T {
        serde_json::from_slice(&read_body(response).await).unwrap()
    }

    async fn post_object<T>(app: &Router, uri: &str, payload: &T) -> EconomyObjectResponse<T>
    where
        T: Clone + Serialize + DeserializeOwned,
    {
        let response = post_json(app, uri, payload).await;
        assert_eq!(response.status(), StatusCode::OK);
        decode_body(response).await
    }

    async fn get_object<T>(app: &Router, uri: String) -> T
    where
        T: DeserializeOwned,
    {
        let response = get_response(app, uri).await;
        assert_eq!(response.status(), StatusCode::OK);
        decode_body(response).await
    }

    fn value_contribution_node(ruleset: &HonorGoodRuleset) -> ValueContributionNode {
        ValueContributionNode {
            contribution_node_id: Hash256::ZERO,
            contributor_ref: participant("contributor"),
            contributor_type: ContributorType::Human,
            contribution_name: "governed implementation workflow".into(),
            contribution_type: ContributionType::Workflow,
            source_uri: Some("https://example.test/workflow".into()),
            evidence_hash: h(0x31),
            provenance_hash: h(0x32),
            license_or_compact_ref: "docs/honorgood/HONOR_GOOD_COMPACT.md".into(),
            honor_good_terms_hash: h(0x33),
            bailment_terms_hash: h(0x34),
            settlement_ruleset_id: ruleset.ruleset_id,
            beneficiary_ref: ParticipantRef::HashedReference(h(0x35)),
            materiality_policy_id: h(0x36),
            adoption_policy_id: h(0x37),
            revocation_policy_id: h(0x38),
            dispute_policy_id: h(0x39),
            status: ValueContributionStatus::Active,
            created_at_hlc: Timestamp::new(30_000, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn bailment_terms(node: &ValueContributionNode) -> BailmentTerms {
        BailmentTerms {
            terms_id: Hash256::ZERO,
            terms_version: "honorgood-bailment-v1".into(),
            bailor_ref: node.contributor_ref.clone(),
            bailee_ref_policy: h(0x41),
            contribution_node_id: node.contribution_node_id,
            permitted_use: "governed adoption, execution, audit, and settlement".into(),
            prohibited_use: "off-policy custody or resale".into(),
            custody_scope: "limited delegated workflow use".into(),
            attribution_required: true,
            settlement_required: true,
            beneficiary_ref: node.beneficiary_ref.clone(),
            revocation_policy_id: node.revocation_policy_id,
            dispute_policy_id: node.dispute_policy_id,
            audit_policy_id: h(0x42),
            jurisdiction_ref: "off-ledger:jurisdiction-policy".into(),
            human_approval_required_for: vec![
                "new legal template".into(),
                "dispute".into(),
                "revocation".into(),
            ],
            agent_execution_allowed: true,
            created_at_hlc: Timestamp::new(30_100, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn contribution_offer(
        node: &ValueContributionNode,
        terms: &BailmentTerms,
        ruleset: &HonorGoodRuleset,
    ) -> ContributionOffer {
        ContributionOffer {
            offer_id: Hash256::ZERO,
            contribution_node_id: node.contribution_node_id,
            offeror_ref: node.contributor_ref.clone(),
            terms_hash: node.honor_good_terms_hash,
            bailment_terms_hash: terms.terms_id,
            permitted_use_policy: h(0x43),
            prohibited_use_policy: h(0x44),
            adoption_policy_id: node.adoption_policy_id,
            settlement_ruleset_id: ruleset.ruleset_id,
            required_authority_level: RequiredAuthorityLevel::DelegatedAgent,
            expiration_or_review: ExpirationOrReview::ReviewAt(Timestamp::new(40_000, 0)),
            legal_effect: LegalEffect::AcceptedTerms,
            status: ContributionOfferStatus::Accepted,
            created_at_hlc: Timestamp::new(30_200, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn contribution_acceptance(
        offer: &ContributionOffer,
        proof: AuthorityEnvelopeRef,
    ) -> ContributionAcceptance {
        ContributionAcceptance {
            acceptance_id: Hash256::ZERO,
            offer_id: offer.offer_id,
            contribution_node_id: offer.contribution_node_id,
            adopter_ref: participant("adopter"),
            adopter_type: AdopterType::Agent,
            accepted_terms_hash: offer.terms_hash,
            accepted_bailment_terms_hash: offer.bailment_terms_hash,
            authority_proof_hash: proof.authority_proof_hash,
            authority_envelope: proof,
            intended_use: "adopt into a governed EXOCHAIN workflow".into(),
            custody_scope: "limited execution and audit custody".into(),
            signature_ref: h(0x45),
            accepted_at_hlc: Timestamp::new(30_300, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn bailment_wrapper(
        node: &ValueContributionNode,
        offer: &ContributionOffer,
        acceptance: &ContributionAcceptance,
        terms: &BailmentTerms,
        ruleset: &HonorGoodRuleset,
    ) -> BailmentWrapper {
        BailmentWrapper {
            wrapper_id: Hash256::ZERO,
            contribution_node_id: node.contribution_node_id,
            offer_id: offer.offer_id,
            acceptance_id: acceptance.acceptance_id,
            accepted_terms_hash: offer.terms_hash,
            accepted_bailment_terms_hash: terms.terms_id,
            bailor_ref: node.contributor_ref.clone(),
            bailee_ref: acceptance.adopter_ref.clone(),
            custody_scope: "limited execution and audit custody".into(),
            settlement_ruleset_id: ruleset.ruleset_id,
            signatures_or_authority_refs: vec![acceptance.signature_ref],
            status: BailmentWrapperStatus::Active,
            created_at_hlc: Timestamp::new(30_400, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn adoption_event(
        node: &ValueContributionNode,
        offer: &ContributionOffer,
        acceptance: &ContributionAcceptance,
        wrapper: &BailmentWrapper,
        mission: &Mission,
    ) -> AdoptionEvent {
        AdoptionEvent {
            adoption_id: Hash256::ZERO,
            contribution_node_id: node.contribution_node_id,
            offer_id: offer.offer_id,
            acceptance_id: acceptance.acceptance_id,
            adopter_ref: acceptance.adopter_ref.clone(),
            adopting_system: "CommandBase".into(),
            mission_id: Some(mission.mission_id),
            accepted_terms_hash: offer.terms_hash,
            bailment_wrapper_id: wrapper.wrapper_id,
            intended_use: "operational cockpit workflow".into(),
            materiality_at_adoption: MaterialityTier::Foundational,
            authority_proof_hash: acceptance.authority_proof_hash,
            created_at_hlc: Timestamp::new(30_500, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn use_event(node: &ValueContributionNode, adoption: &AdoptionEvent) -> UseEvent {
        UseEvent {
            use_event_id: Hash256::ZERO,
            adoption_id: adoption.adoption_id,
            contribution_node_id: node.contribution_node_id,
            using_system: "CommandBase".into(),
            mission_id: adoption.mission_id,
            use_type: UseType::AgentWorkflow,
            materiality_observed: MaterialityTier::Foundational,
            evidence_hash: h(0x46),
            bailment_wrapper_id: adoption.bailment_wrapper_id,
            created_at_hlc: Timestamp::new(30_600, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    fn value_event(node: &ValueContributionNode, use_event: &UseEvent) -> ValueEvent {
        ValueEvent {
            value_event_id: Hash256::ZERO,
            use_event_id: use_event.use_event_id,
            contribution_node_id: node.contribution_node_id,
            mission_id: use_event.mission_id,
            value_basis: ValueBasis::Revenue,
            measured_value_micro_exo: 0,
            measurement_evidence_hash: h(0x47),
            measurement_policy_id: h(0x48),
            settlement_triggered: true,
            zero_fee_reason_required: true,
            created_at_hlc: Timestamp::new(30_700, 0),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    struct AutomatedSettlementPrereqs {
        node: ValueContributionNode,
        authority_ref: AuthorityEnvelopeRef,
        value_event: ValueEvent,
    }

    async fn seed_automated_settlement_prereqs(app: &Router) -> AutomatedSettlementPrereqs {
        let ruleset = apex_velocity_catalyst_client_services_ruleset().unwrap();
        let _: EconomyObjectResponse<HonorGoodRuleset> =
            post_object(app, "/api/v1/economy/rulesets", &ruleset).await;

        let mission = apex_velocity_catalyst_client_services_mission(Some(1_000_000)).unwrap();
        let _: EconomyObjectResponse<Mission> =
            post_object(app, "/api/v1/economy/missions", &mission).await;

        let node = value_contribution_node(&ruleset);
        let _: EconomyObjectResponse<ValueContributionNode> =
            post_object(app, "/api/v1/economy/contribution-nodes", &node).await;

        let terms = bailment_terms(&node);
        let _: EconomyObjectResponse<BailmentTerms> =
            post_object(app, "/api/v1/economy/bailment-terms", &terms).await;

        let offer = contribution_offer(&node, &terms, &ruleset);
        let _: EconomyObjectResponse<ContributionOffer> =
            post_object(app, "/api/v1/economy/contribution-offers", &offer).await;

        let authority_ref = authority("principal");
        let acceptance = contribution_acceptance(&offer, authority_ref.clone());
        let _: EconomyObjectResponse<ContributionAcceptance> =
            post_object(app, "/api/v1/economy/contribution-acceptances", &acceptance).await;

        let wrapper = bailment_wrapper(&node, &offer, &acceptance, &terms, &ruleset);
        let _: EconomyObjectResponse<BailmentWrapper> =
            post_object(app, "/api/v1/economy/bailment-wrappers", &wrapper).await;

        let adoption = adoption_event(&node, &offer, &acceptance, &wrapper, &mission);
        let _: EconomyObjectResponse<AdoptionEvent> =
            post_object(app, "/api/v1/economy/adoption-events", &adoption).await;

        let use_event = use_event(&node, &adoption);
        let _: EconomyObjectResponse<UseEvent> =
            post_object(app, "/api/v1/economy/use-events", &use_event).await;

        let value_event = value_event(&node, &use_event);
        let _: EconomyObjectResponse<ValueEvent> =
            post_object(app, "/api/v1/economy/value-events", &value_event).await;

        AutomatedSettlementPrereqs {
            node,
            authority_ref,
            value_event,
        }
    }

    fn automated_settlement_request(
        value_event_id: Hash256,
        automation_authority_ref: AuthorityEnvelopeRef,
        preapproved_terms_hash: Hash256,
    ) -> AutomatedSettlementRequest {
        let mut basis_amounts = BTreeMap::new();
        basis_amounts.insert(SettlementBasis::NetRevenue, 0);
        AutomatedSettlementRequest {
            value_event_id,
            automation_authority_ref,
            preapproved_terms_hash,
            basis_amounts,
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            created_at_hlc: Timestamp::new(30_800, 0),
        }
    }

    #[tokio::test]
    async fn quote_returns_zero_amount_with_zero_fee_reason() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));
        let payload = QuoteRequest {
            quote_id: "q-1".into(),
            inputs: baseline_inputs(),
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/quote")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: SettlementQuote = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.charged_amount_micro_exo, 0);
        assert!(parsed.zero_fee_reason.is_some());
    }

    #[tokio::test]
    async fn settle_creates_zero_priced_receipt() {
        let (state, public_key) = fresh_signed_state();
        let app = economy_router(Arc::clone(&state));

        // Step 1: quote.
        let payload = QuoteRequest {
            quote_id: "q-1".into(),
            inputs: baseline_inputs(),
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/quote")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let issued: SettlementQuote = serde_json::from_slice(&read_body(response).await).unwrap();

        // Step 2: settle.
        let settle_request = SettleRequest {
            quote_hash_hex: format!("{}", issued.quote_hash),
            context: SettlementContext {
                receipt_id: "rec-1".into(),
                custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
                prev_settlement_receipt: Hash256::ZERO,
                now: Timestamp::new(1_010_000, 0),
            },
        };
        let body = serde_json::to_vec(&settle_request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/settle")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt: SettlementReceipt =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(receipt.charged_amount_micro_exo, 0);
        assert!(receipt.zero_fee_reason.is_some());
        assert!(
            !receipt.signature.is_empty(),
            "economy settlement receipts must be signed by the node identity"
        );
        assert!(
            crypto::verify(
                receipt.content_hash.as_bytes(),
                &receipt.signature,
                &public_key
            ),
            "economy settlement receipt signature must verify against the node identity"
        );
    }

    #[tokio::test]
    async fn settle_derives_previous_receipt_from_store_not_payload() {
        let (state, _) = fresh_signed_state();
        let app = economy_router(Arc::clone(&state));

        let first_quote_request = QuoteRequest {
            quote_id: "q-1".into(),
            inputs: baseline_inputs(),
        };
        let first_quote_body = serde_json::to_vec(&first_quote_request).unwrap();
        let first_quote_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/quote")
                    .header("content-type", "application/json")
                    .body(Body::from(first_quote_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let first_quote: SettlementQuote =
            serde_json::from_slice(&read_body(first_quote_response).await).unwrap();

        let first_settle_request = SettleRequest {
            quote_hash_hex: format!("{}", first_quote.quote_hash),
            context: SettlementContext {
                receipt_id: "rec-1".into(),
                custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
                prev_settlement_receipt: Hash256::from_bytes([0xAA; 32]),
                now: Timestamp::new(1_010_000, 0),
            },
        };
        let first_settle_body = serde_json::to_vec(&first_settle_request).unwrap();
        let first_settle_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/settle")
                    .header("content-type", "application/json")
                    .body(Body::from(first_settle_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first_settle_response.status(), StatusCode::OK);
        let first_receipt: SettlementReceipt =
            serde_json::from_slice(&read_body(first_settle_response).await).unwrap();
        assert_eq!(first_receipt.prev_settlement_receipt, Hash256::ZERO);

        let mut second_inputs = baseline_inputs();
        second_inputs.compute_units = 200;
        let second_quote_request = QuoteRequest {
            quote_id: "q-2".into(),
            inputs: second_inputs,
        };
        let second_quote_body = serde_json::to_vec(&second_quote_request).unwrap();
        let second_quote_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/quote")
                    .header("content-type", "application/json")
                    .body(Body::from(second_quote_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second_quote: SettlementQuote =
            serde_json::from_slice(&read_body(second_quote_response).await).unwrap();

        let second_settle_request = SettleRequest {
            quote_hash_hex: format!("{}", second_quote.quote_hash),
            context: SettlementContext {
                receipt_id: "rec-2".into(),
                custody_transaction_hash: Hash256::from_bytes([0x44; 32]),
                prev_settlement_receipt: Hash256::from_bytes([0xBB; 32]),
                now: Timestamp::new(1_020_000, 0),
            },
        };
        let second_settle_body = serde_json::to_vec(&second_settle_request).unwrap();
        let second_settle_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/settle")
                    .header("content-type", "application/json")
                    .body(Body::from(second_settle_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_settle_response.status(), StatusCode::OK);
        let second_receipt: SettlementReceipt =
            serde_json::from_slice(&read_body(second_settle_response).await).unwrap();
        assert_eq!(
            second_receipt.prev_settlement_receipt,
            first_receipt.content_hash
        );
    }

    #[tokio::test]
    async fn settle_returns_404_for_unknown_quote() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));
        let settle_request = SettleRequest {
            quote_hash_hex: "11".repeat(32),
            context: SettlementContext {
                receipt_id: "rec-1".into(),
                custody_transaction_hash: Hash256::ZERO,
                prev_settlement_receipt: Hash256::ZERO,
                now: Timestamp::new(1_010_000, 0),
            },
        };
        let body = serde_json::to_vec(&settle_request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/settle")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn settle_returns_400_for_invalid_quote_hash_hex() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));
        let settle_request = SettleRequest {
            quote_hash_hex: "not-hex".into(),
            context: SettlementContext {
                receipt_id: "rec-1".into(),
                custody_transaction_hash: Hash256::ZERO,
                prev_settlement_receipt: Hash256::ZERO,
                now: Timestamp::new(1_010_000, 0),
            },
        };
        let body = serde_json::to_vec(&settle_request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/settle")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_receipt_404_when_unknown() {
        let state = fresh_state();
        let app = economy_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/economy/receipts/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn active_policy_returns_zero_launch_default() {
        let state = fresh_state();
        let app = economy_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/economy/policy/active")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: PolicyResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.policy.id, "exo.economy.zero-launch");
        assert_eq!(parsed.policy.compute_unit_price_micro_exo, 0);
    }

    #[tokio::test]
    async fn mission_ruleset_and_settlement_routes_record_core_objects() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));

        let ruleset = apex_velocity_catalyst_client_services_ruleset().unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/rulesets")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ruleset).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ruleset_response: EconomyObjectResponse<HonorGoodRuleset> =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(ruleset_response.anchor.object_hash, ruleset.content_hash);

        let mission = apex_velocity_catalyst_client_services_mission(Some(5_000_000)).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/missions")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&mission).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mission_response: EconomyObjectResponse<Mission> =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(
            mission_response.anchor.previous_anchor_hash,
            ruleset_response.anchor.anchor_hash
        );

        let settlement_request = MissionSettlementRequest {
            mission_id: mission.mission_id,
            ruleset_id: ruleset.ruleset_id,
            gross_revenue_micro_exo: 0,
            pass_through_expenses_micro_exo: 0,
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            prev_settlement_hash: None,
            created_at: Timestamp::new(20_000, 0),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/mission-settlements")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&settlement_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let settlement_response: EconomyObjectResponse<MissionSettlement> =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(
            settlement_response.anchor.previous_anchor_hash,
            mission_response.anchor.anchor_hash
        );
        assert_eq!(settlement_response.object.charged_amount_micro_exo, 0);
        assert!(settlement_response.object.zero_fee_reason.is_some());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/api/v1/economy/mission-settlements/{}",
                        settlement_response.object.settlement_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/economy/anchors/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let latest_anchor: EconomyRecordAnchor =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(
            latest_anchor.anchor_hash,
            settlement_response.anchor.anchor_hash
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/api/v1/economy/anchors/{}",
                        settlement_response.anchor.anchor_hash
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn honorgood_value_contribution_routes_record_full_lifecycle() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));

        let ruleset = apex_velocity_catalyst_client_services_ruleset().unwrap();
        let ruleset_response: EconomyObjectResponse<HonorGoodRuleset> =
            post_object(&app, "/api/v1/economy/rulesets", &ruleset).await;
        assert_eq!(
            ruleset_response.object.status,
            exo_economy::RulesetStatus::Active
        );

        let mission = apex_velocity_catalyst_client_services_mission(Some(1_000_000)).unwrap();
        let mission_response: EconomyObjectResponse<Mission> =
            post_object(&app, "/api/v1/economy/missions", &mission).await;
        assert_eq!(
            mission_response.anchor.previous_anchor_hash,
            ruleset_response.anchor.anchor_hash
        );

        let node = value_contribution_node(&ruleset);
        let node_response: EconomyObjectResponse<ValueContributionNode> =
            post_object(&app, "/api/v1/economy/contribution-nodes", &node).await;
        assert_eq!(node_response.object.status, ValueContributionStatus::Active);

        let receipt = ContributionReceipt {
            receipt_id: Hash256::ZERO,
            mission_id: Some(mission.mission_id),
            contribution_node_id: Some(node.contribution_node_id),
            contributor: participant("contributor"),
            contributor_type: ContributionContributorType::Human,
            action_type: "prepared governed implementation workflow".into(),
            contribution_category: ContributionCategory::Governance,
            evidence_hash: h(0x49),
            evidence_uri: Some("ipfs://honorgood-evidence".into()),
            claimed_value_micro_exo: Some(1_000),
            accepted_value_micro_exo: Some(1_000),
            approval_status: ApprovalStatus::Accepted,
            approver_did: Some(Did::new("did:exo:approver").unwrap()),
            created_at: Timestamp::new(30_050, 0),
            content_hash: Hash256::ZERO,
        };
        let receipt_response: EconomyObjectResponse<ContributionReceipt> =
            post_object(&app, "/api/v1/economy/contribution-receipts", &receipt).await;
        assert_eq!(receipt_response.object.mission_id, Some(mission.mission_id));

        let terms = bailment_terms(&node);
        let terms_response: EconomyObjectResponse<BailmentTerms> =
            post_object(&app, "/api/v1/economy/bailment-terms", &terms).await;
        assert!(terms_response.object.agent_execution_allowed);

        let offer = contribution_offer(&node, &terms, &ruleset);
        let offer_response: EconomyObjectResponse<ContributionOffer> =
            post_object(&app, "/api/v1/economy/contribution-offers", &offer).await;
        assert_eq!(
            offer_response.object.legal_effect,
            LegalEffect::AcceptedTerms
        );

        let authority_ref = authority("principal");
        let acceptance = contribution_acceptance(&offer, authority_ref.clone());
        let acceptance_response: EconomyObjectResponse<ContributionAcceptance> = post_object(
            &app,
            "/api/v1/economy/contribution-acceptances",
            &acceptance,
        )
        .await;
        assert_eq!(
            acceptance_response.object.authority_proof_hash,
            authority_ref.authority_proof_hash
        );

        let wrapper = bailment_wrapper(&node, &offer, &acceptance, &terms, &ruleset);
        let wrapper_response: EconomyObjectResponse<BailmentWrapper> =
            post_object(&app, "/api/v1/economy/bailment-wrappers", &wrapper).await;
        assert_eq!(
            wrapper_response.object.status,
            BailmentWrapperStatus::Active
        );

        let adoption = adoption_event(&node, &offer, &acceptance, &wrapper, &mission);
        let adoption_response: EconomyObjectResponse<AdoptionEvent> =
            post_object(&app, "/api/v1/economy/adoption-events", &adoption).await;
        assert_eq!(
            adoption_response.object.mission_id,
            Some(mission.mission_id)
        );

        let use_event = use_event(&node, &adoption);
        let use_response: EconomyObjectResponse<UseEvent> =
            post_object(&app, "/api/v1/economy/use-events", &use_event).await;
        assert_eq!(use_response.object.adoption_id, adoption.adoption_id);

        let value_event = value_event(&node, &use_event);
        let value_response: EconomyObjectResponse<ValueEvent> =
            post_object(&app, "/api/v1/economy/value-events", &value_event).await;
        assert!(value_response.object.settlement_triggered);

        let mut basis_amounts = BTreeMap::new();
        basis_amounts.insert(SettlementBasis::NetRevenue, 0);
        let automated_request = AutomatedSettlementRequest {
            value_event_id: value_event.value_event_id,
            automation_authority_ref: authority_ref,
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts,
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            created_at_hlc: Timestamp::new(30_800, 0),
        };
        let response = post_json(
            &app,
            "/api/v1/economy/automated-settlements",
            &automated_request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let automated_response: EconomyObjectResponse<AutomatedSettlementEvent> =
            decode_body(response).await;
        assert!(!automated_response.object.human_approval_required);
        assert_eq!(
            automated_response.object.bailment_wrapper_id,
            wrapper.wrapper_id
        );
        assert!(
            automated_response
                .object
                .settlement_lines
                .iter()
                .all(|line| line.zero_fee_reason == Some(ZeroFeeReason::PolicyConfiguredZero))
        );

        let legacy = archon_exoforge_legacy_receipt().unwrap();
        let legacy_response: EconomyObjectResponse<LegacyReceipt> =
            post_object(&app, "/api/v1/economy/legacy-receipts", &legacy).await;
        assert_eq!(
            legacy_response.object.legal_effect,
            LegalEffect::VoluntaryRecognitionOnly
        );

        let _: HonorGoodRuleset = get_object(
            &app,
            format!("/api/v1/economy/rulesets/{}", ruleset.ruleset_id),
        )
        .await;
        let _: Mission = get_object(
            &app,
            format!("/api/v1/economy/missions/{}", mission.mission_id),
        )
        .await;
        let _: ValueContributionNode = get_object(
            &app,
            format!(
                "/api/v1/economy/contribution-nodes/{}",
                node.contribution_node_id
            ),
        )
        .await;
        let _: ContributionReceipt = get_object(
            &app,
            format!(
                "/api/v1/economy/contribution-receipts/{}",
                receipt_response.object.receipt_id
            ),
        )
        .await;
        let _: BailmentTerms = get_object(
            &app,
            format!("/api/v1/economy/bailment-terms/{}", terms.terms_id),
        )
        .await;
        let _: ContributionOffer = get_object(
            &app,
            format!("/api/v1/economy/contribution-offers/{}", offer.offer_id),
        )
        .await;
        let _: ContributionAcceptance = get_object(
            &app,
            format!(
                "/api/v1/economy/contribution-acceptances/{}",
                acceptance.acceptance_id
            ),
        )
        .await;
        let _: BailmentWrapper = get_object(
            &app,
            format!("/api/v1/economy/bailment-wrappers/{}", wrapper.wrapper_id),
        )
        .await;
        let _: AdoptionEvent = get_object(
            &app,
            format!("/api/v1/economy/adoption-events/{}", adoption.adoption_id),
        )
        .await;
        let _: UseEvent = get_object(
            &app,
            format!("/api/v1/economy/use-events/{}", use_event.use_event_id),
        )
        .await;
        let _: ValueEvent = get_object(
            &app,
            format!(
                "/api/v1/economy/value-events/{}",
                value_event.value_event_id
            ),
        )
        .await;
        let _: AutomatedSettlementEvent = get_object(
            &app,
            format!(
                "/api/v1/economy/automated-settlements/{}",
                automated_response.object.automated_settlement_id
            ),
        )
        .await;
        let _: LegacyReceipt = get_object(
            &app,
            format!(
                "/api/v1/economy/legacy-receipts/{}",
                legacy.legacy_receipt_id
            ),
        )
        .await;

        let latest_anchor: EconomyRecordAnchor =
            get_object(&app, "/api/v1/economy/anchors/latest".to_string()).await;
        assert_eq!(
            latest_anchor.anchor_hash, legacy_response.anchor.anchor_hash,
            "latest economy anchor should track the last core object recorded through the adapter"
        );
        let direct_anchor: EconomyRecordAnchor = get_object(
            &app,
            format!("/api/v1/economy/anchors/{}", latest_anchor.anchor_hash),
        )
        .await;
        assert_eq!(direct_anchor, latest_anchor);
    }

    #[tokio::test]
    async fn automated_settlement_requires_stored_offer_when_evidence_is_derived() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));
        let ruleset = apex_velocity_catalyst_client_services_ruleset().unwrap();
        let node = value_contribution_node(&ruleset);
        let terms = bailment_terms(&node);
        let offer = contribution_offer(&node, &terms, &ruleset);
        let authority_ref = authority("principal");
        let acceptance = contribution_acceptance(&offer, authority_ref.clone());
        let wrapper = bailment_wrapper(&node, &offer, &acceptance, &terms, &ruleset);
        let mission = apex_velocity_catalyst_client_services_mission(Some(1_000_000)).unwrap();
        let adoption = adoption_event(&node, &offer, &acceptance, &wrapper, &mission);
        let use_event = use_event(&node, &adoption);
        let value_event = value_event(&node, &use_event);
        {
            let mut store = state.store.lock().unwrap();
            store.put_ruleset(ruleset).unwrap();
            store.put_value_contribution_node(node.clone()).unwrap();
            store.put_bailment_terms(terms).unwrap();
            store.put_contribution_acceptance(acceptance).unwrap();
            store.put_bailment_wrapper(wrapper).unwrap();
            store.put_adoption_event(adoption).unwrap();
            store.put_use_event(use_event).unwrap();
            store.put_value_event(value_event.clone()).unwrap();
        }

        let response = post_json(
            &app,
            "/api/v1/economy/automated-settlements",
            &automated_settlement_request(
                value_event.value_event_id,
                authority_ref,
                node.honor_good_terms_hash,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = String::from_utf8(read_body(response).await).unwrap();
        assert!(body.contains("contribution offer"));
    }

    #[tokio::test]
    async fn automated_settlement_rejects_client_supplied_preconditions() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));
        let prereqs = seed_automated_settlement_prereqs(&app).await;
        let request = automated_settlement_request(
            prereqs.value_event.value_event_id,
            prereqs.authority_ref,
            prereqs.node.honor_good_terms_hash,
        );
        let mut body = serde_json::to_value(&request).unwrap();
        body["preconditions"] = serde_json::json!({
            "caller_supplied_validity_flags": true
        });

        let response = post_json(&app, "/api/v1/economy/automated-settlements", &body).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = String::from_utf8(read_body(response).await).unwrap();
        assert!(body.contains("preconditions"));
    }

    #[tokio::test]
    async fn automated_settlement_rejects_request_authority_not_bound_to_stored_acceptance() {
        let state = fresh_state();
        let app = economy_router(Arc::clone(&state));
        let prereqs = seed_automated_settlement_prereqs(&app).await;
        let mut forged_authority = prereqs.authority_ref.clone();
        forged_authority.envelope_id = h(0xA9);
        forged_authority.authority_proof_hash = h(0xAA);
        forged_authority.principal_ref = participant("forged-principal");

        let response = post_json(
            &app,
            "/api/v1/economy/automated-settlements",
            &automated_settlement_request(
                prereqs.value_event.value_event_id,
                forged_authority,
                prereqs.node.honor_good_terms_hash,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = String::from_utf8(read_body(response).await).unwrap();
        assert!(body.contains("authority"));
    }

    #[tokio::test]
    async fn contribution_acceptance_route_requires_stored_offer() {
        let state = fresh_state();
        let app = economy_router(state);
        let acceptance = ContributionAcceptance {
            acceptance_id: Hash256::ZERO,
            offer_id: h(0x21),
            contribution_node_id: h(0x22),
            adopter_ref: participant("adopter"),
            adopter_type: AdopterType::Agent,
            accepted_terms_hash: h(0x23),
            accepted_bailment_terms_hash: h(0x24),
            authority_proof_hash: h(0xA2),
            authority_envelope: authority("principal"),
            intended_use: "governed workflow adoption".into(),
            custody_scope: "limited execution".into(),
            signature_ref: h(0x25),
            accepted_at_hlc: Timestamp::new(21_000, 0),
            content_hash: Hash256::ZERO,
        };
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/contribution-acceptances")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&acceptance).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn quote_returns_400_for_blank_quote_id() {
        let state = fresh_state();
        let app = economy_router(state);
        let payload = QuoteRequest {
            quote_id: "   ".into(),
            inputs: baseline_inputs(),
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/quote")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn quote_zero_fee_reason_for_human_avc_validate_is_agent_validation() {
        let state = fresh_state();
        let app = economy_router(state);
        let mut inputs = baseline_inputs();
        inputs.actor_class = ActorClass::Human;
        inputs.event_class = EventClass::AvcValidate;
        let payload = QuoteRequest {
            quote_id: "q-h".into(),
            inputs,
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/economy/quote")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let parsed: SettlementQuote = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.zero_fee_reason, Some(ZeroFeeReason::AgentValidation));
    }

    #[test]
    fn router_uses_blocking_store_access_and_local_admission_control() {
        let source = include_str!("economy.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "economy handlers must isolate sync store access from Tokio workers"
        );
        assert!(
            production.contains("DefaultBodyLimit::max(MAX_ECONOMY_API_BODY_BYTES)"),
            "economy router must cap body size locally"
        );
        assert!(
            production.contains("ConcurrencyLimitLayer::new("),
            "economy router must apply local admission control"
        );
        assert!(
            production.contains("settlement_signer"),
            "economy settlement must use the configured node identity signer"
        );
        assert!(
            !production.contains("Signature::empty()"),
            "production economy settlement must not fabricate empty receipt signatures"
        );
    }

    #[test]
    fn settle_handler_derives_chain_head_from_store_before_signing_receipt() {
        let source = include_str!("economy.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let derivation_index = production
            .find("context.prev_settlement_receipt = store.latest_receipt_hash()")
            .expect("settlement handler must derive prev_settlement_receipt from the store");
        let settle_index = production
            .find("let receipt = settle(&stored, &context")
            .expect("settlement handler must call settle with the derived context");
        assert!(
            derivation_index < settle_index,
            "settlement handler must derive the chain head before signing the receipt"
        );
    }
}
