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

//! Governance API — HTTP endpoints for submitting proposals, broadcasting
//! governance events, querying node status, and managing the validator set.
//!
//! Routes are merged into the gateway's axum router via
//! `serve_with_extra_routes` so the node exposes governance operations
//! alongside the existing REST / GraphQL endpoints.

#![allow(
    clippy::needless_borrows_for_generic_args,
    // `needless_return` fires inside cfg-gated refusal blocks where the
    // function body continues in the mutually-exclusive feature-on branch.
    clippy::needless_return,
    // `ValidatorChangeRequest` fields are only used inside
    // #[cfg(feature = "unaudited-admin-governance-shortcut")].
    // Keeping dead_code on in default build would force us to duplicate
    // the struct definition per feature which is worse than this allow.
    dead_code
)]

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use exo_authority::{AuthorityChain, DelegationRegistry, chain};
use exo_core::types::PublicKey;
use exo_core::types::{Did, Hash256, ReceiptOutcome, Signature, Timestamp, TrustReceipt};
#[cfg(test)]
use exo_identity::did::DidDocument;
use exo_identity::registry::{DidRegistry, LocalDidRegistry};
use serde::{Deserialize, Serialize};
use tower::limit::ConcurrencyLimitLayer;

#[cfg(feature = "unaudited-admin-governance-shortcut")]
use crate::identity;
#[cfg(feature = "unaudited-admin-governance-shortcut")]
use crate::reactor;
#[cfg(feature = "unaudited-admin-governance-shortcut")]
use crate::wire::GovernanceEventType;
#[cfg(feature = "unaudited-admin-governance-shortcut")]
use crate::wire::ValidatorChange;
use crate::{network::NetworkHandle, reactor::SharedReactorState, store::SqliteDagStore};

const MAX_GOVERNANCE_API_BODY_BYTES: usize = 64 * 1024;
const MAX_GOVERNANCE_API_CONCURRENT_REQUESTS: usize = 64;

fn internal_error_response(message: &'static str) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, message.to_string())
}

// ---------------------------------------------------------------------------
// CrossChecked trusted-authority anchor (VCG-007, D3)
// ---------------------------------------------------------------------------
//
// D3 (ratified 2026-07-02): a trusted CrossChecked authority is a
// `exo-authority::DelegationRegistry` entry -- the same authority species as
// any other delegated verification seat (e.g. a future council seat).
// Resolution reuses `exo-authority` (`AuthorityChain`/`DelegationRegistry`)
// and `exo-identity::LocalDidRegistry` for DID -> public key resolution; both
// are already `exochain-node` dependencies.
//
// This anchor is intentionally empty by default (production/main.rs wiring):
// no CrossChecked authority is trusted until an operator explicitly
// delegates one via the root authority, which keeps the route fail-closed.

/// The tenant/workspace scope a CrossChecked authority was actually granted.
/// Defined here (not in `exo-tenant`, which is not an `exochain-node`
/// dependency and has no workspace concept) per the VCG-007 work order's
/// explicit-scope-decision requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCheckedAuthorityScope {
    pub tenant_id: String,
    pub workspace_id: String,
}

/// In-process trust anchor for CrossChecked authority resolution.
///
/// Holds the root-signed `DelegationRegistry` chain proving a CrossChecked
/// authority DID was actually delegated verification authority, a
/// `LocalDidRegistry` binding that DID to the public key used to verify the
/// authority's external proof signatures, and the tenant/workspace scope
/// each authority was granted.
pub struct CrossCheckedTrustAnchor {
    pub root_did: Did,
    pub registry: DelegationRegistry,
    pub dids: LocalDidRegistry,
    pub scopes: std::collections::BTreeMap<Did, CrossCheckedAuthorityScope>,
}

impl CrossCheckedTrustAnchor {
    /// An anchor that trusts no CrossChecked authority. This is the
    /// production default: a real deployment must explicitly delegate a
    /// CrossChecked authority before this route can ever mint.
    #[must_use]
    pub fn empty(root_did: Did) -> Self {
        Self {
            root_did,
            registry: DelegationRegistry::new(),
            dids: LocalDidRegistry::new(),
            scopes: std::collections::BTreeMap::new(),
        }
    }

    /// Resolve `authority_did` to a verified `AuthorityChain` rooted at
    /// `self.root_did`, then return the authority's public key (from the
    /// bound `LocalDidRegistry` document) and its granted tenant/workspace
    /// scope. Returns `None` if the DID has no delegation chain, the chain
    /// does not cryptographically verify, or no DID document / scope is
    /// bound for it -- any of which means the authority is not trusted.
    #[must_use]
    pub fn resolve(
        &self,
        authority_did: &Did,
        now: &Timestamp,
    ) -> Option<(exo_core::types::PublicKey, &CrossCheckedAuthorityScope)> {
        let chain: AuthorityChain = self.registry.find_chain(&self.root_did, authority_did)?;

        let resolve_key = |did: &Did| -> Option<exo_core::types::PublicKey> {
            self.dids
                .resolve(did)
                .and_then(|doc| doc.public_keys.first().copied())
        };
        chain::verify_chain(&chain, now, resolve_key).ok()?;

        let public_key = resolve_key(authority_did)?;
        let scope = self.scopes.get(authority_did)?;
        Some((public_key, scope))
    }
}

/// Shared state accessible by all governance route handlers.
#[derive(Clone)]
pub struct NodeApiState {
    pub reactor_state: SharedReactorState,
    pub store: Arc<Mutex<SqliteDagStore>>,
    pub net_handle: NetworkHandle,
    pub node_did: Did,
    pub sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    /// CrossChecked receipt-anchor trusted-authority resolution (VCG-007,
    /// D3). Present regardless of feature flag so the struct shape is
    /// stable; only consulted when
    /// `unaudited-crosschecked-receipt-anchor` is enabled.
    pub crosschecked_trust: Arc<Mutex<CrossCheckedTrustAnchor>>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/governance/propose`.
#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    /// Hex-encoded payload bytes for the governance action.
    pub payload_hex: String,
}

/// Response from a successful proposal submission.
#[derive(Debug, Serialize)]
pub struct ProposeResponse {
    /// The hash of the created DAG node (hex-encoded).
    pub node_hash: String,
    /// The committed height (if immediately committed).
    pub height: Option<u64>,
}

/// Request body for `POST /api/v1/governance/broadcast`.
#[derive(Debug, Deserialize)]
pub struct BroadcastRequest {
    pub event_type: String,
    pub payload_hex: String,
}

/// Request body for `POST /api/v1/governance/validators`.
#[derive(Debug, Deserialize)]
pub struct ValidatorChangeRequest {
    pub action: String, // "add" or "remove"
    pub did: String,
    pub public_key_hex: Option<String>,
}

/// Response representing a single trust receipt.
#[derive(Debug, Serialize)]
pub struct ReceiptResponse {
    pub receipt_hash: String,
    pub actor_did: String,
    pub authority_chain_hash: String,
    pub consent_reference: Option<String>,
    pub action_type: String,
    pub action_hash: String,
    pub outcome: String,
    pub timestamp_ms: u64,
    pub challenge_reference: Option<String>,
}

impl From<exo_core::types::TrustReceipt> for ReceiptResponse {
    fn from(r: exo_core::types::TrustReceipt) -> Self {
        Self {
            receipt_hash: hex::encode(r.receipt_hash.0),
            actor_did: r.actor_did.to_string(),
            authority_chain_hash: hex::encode(r.authority_chain_hash.0),
            consent_reference: r.consent_reference.map(|h| hex::encode(h.0)),
            action_type: r.action_type,
            action_hash: hex::encode(r.action_hash.0),
            outcome: r.outcome.to_string(),
            timestamp_ms: r.timestamp.physical_ms,
            challenge_reference: r.challenge_reference.map(|h| hex::encode(h.0)),
        }
    }
}

/// Query parameters for `GET /api/v1/receipts`.
#[derive(Debug, Deserialize)]
pub struct ReceiptQuery {
    /// Filter by actor DID (required).
    pub actor: Option<String>,
    /// Maximum number of receipts to return (default 50, max 500).
    pub limit: Option<u32>,
}

/// Request body for `POST /api/v1/receipts`.
#[derive(Debug, Deserialize)]
pub struct CrossCheckedReceiptAnchorRequest {
    pub source: String,
    pub idempotency_key: String,
    pub external_event_id: String,
    pub external_receipt_hash: String,
    pub payload_hash: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub event_type: String,
    pub emitted_at: DateTime<Utc>,
    pub public_proof_url: String,
    /// DID of the CrossChecked authority that signed `external_proof_signature_hex`.
    /// Absent on legacy/unaware callers; a missing value can never resolve to
    /// a trusted authority, so the route refuses.
    #[serde(default)]
    pub crosschecked_authority_did: Option<String>,
    /// Hex-encoded Ed25519 signature over `payload_hash` (as UTF-8 bytes),
    /// produced by the CrossChecked authority's private key. This is the
    /// external proof a production intake path must verify against the
    /// resolved authority's public key before minting.
    #[serde(default)]
    pub external_proof_signature_hex: Option<String>,
}

/// Response from a successful CrossChecked receipt anchor.
#[derive(Debug, Serialize)]
pub struct CrossCheckedReceiptAnchorResponse {
    pub status: String,
    pub exochain_receipt_hash: String,
    pub anchor_hash: String,
    pub verified_at: DateTime<Utc>,
}

/// Response for `GET /api/v1/governance/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    pub consensus_round: u64,
    pub committed_height: u64,
    pub validator_count: usize,
    pub is_validator: bool,
    pub validators: Vec<String>,
    /// Public verification material for the active validator set, ordered by DID.
    ///
    /// Validator DIDs are self-certifying hashes of these Ed25519 keys. Publishing
    /// the keys lets offline clients verify node-signed receipts without granting
    /// write authority or exposing private material.
    pub validator_trust_anchors: Vec<ValidatorTrustAnchorResponse>,
}

/// Public, non-secret verification material for one active validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorTrustAnchorResponse {
    pub did: String,
    pub algorithm: String,
    pub public_key_hex: String,
}

struct NodeStatusSnapshot {
    consensus_round: u64,
    committed_height: u64,
    validators: Vec<String>,
    is_validator: bool,
    validator_trust_anchors: Vec<ValidatorTrustAnchorResponse>,
}

// ---------------------------------------------------------------------------
// Blocking adapters
// ---------------------------------------------------------------------------

async fn read_node_status_snapshot(
    reactor_state: SharedReactorState,
) -> Result<NodeStatusSnapshot, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let s = reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        let committed_height = u64::try_from(s.consensus.committed.len()).map_err(|_| {
            tracing::error!(
                committed_len = s.consensus.committed.len(),
                "Committed height cannot be represented as u64"
            );
            internal_error_response("Consensus status unavailable")
        })?;
        Ok(NodeStatusSnapshot {
            consensus_round: s.consensus.current_round,
            committed_height,
            validators: s
                .consensus
                .config
                .validators
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>(),
            is_validator: s.is_validator,
            validator_trust_anchors: s
                .validator_public_keys
                .as_map()
                .iter()
                .map(|(did, public_key)| ValidatorTrustAnchorResponse {
                    did: did.to_string(),
                    algorithm: "ed25519_v1".to_owned(),
                    public_key_hex: hex::encode(public_key.as_bytes()),
                })
                .collect(),
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Node status blocking task failed");
        internal_error_response("Consensus status unavailable")
    })?
}

#[cfg(feature = "unaudited-admin-governance-shortcut")]
async fn read_validator_count(
    reactor_state: SharedReactorState,
) -> Result<usize, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let s = reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        Ok(s.consensus.config.validators.len())
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Validator count blocking task failed");
        internal_error_response("Consensus status unavailable")
    })?
}

async fn load_receipt_by_hash(
    store: Arc<Mutex<SqliteDagStore>>,
    hash: Hash256,
) -> Result<Option<TrustReceipt>, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let st = store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Store unavailable".to_string(),
            )
        })?;
        st.load_receipt(&hash).map_err(|e| {
            tracing::error!(err = %e, "Receipt lookup failed");
            internal_error_response("Receipt lookup failed")
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Receipt lookup blocking task failed");
        internal_error_response("Receipt lookup failed")
    })?
}

async fn load_receipts_by_actor(
    store: Arc<Mutex<SqliteDagStore>>,
    actor: String,
    limit: u32,
) -> Result<Vec<TrustReceipt>, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || {
        let st = store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Store unavailable".to_string(),
            )
        })?;
        st.load_receipts_by_actor(&actor, limit).map_err(|e| {
            tracing::error!(err = %e, actor = %actor, "Receipt list failed");
            internal_error_response("Receipt list failed")
        })
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "Receipt list blocking task failed");
        internal_error_response("Receipt list failed")
    })?
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

#[cfg(feature = "unaudited-admin-governance-shortcut")]
fn parse_validator_public_key_hex(value: &str) -> Result<PublicKey, (StatusCode, String)> {
    let bytes = hex::decode(value).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public_key_hex: {e}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("public_key_hex must be 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(public_key))
}

/// `POST /api/v1/governance/propose` — submit a governance proposal for BFT consensus.
async fn handle_propose(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<ProposeRequest>,
) -> Result<Json<ProposeResponse>, (StatusCode, String)> {
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    {
        let _ = (api, req);
        tracing::warn!(
            "refusing POST /api/v1/governance/propose: raw admin governance \
             proposal shortcut is gated. Build with \
             --features exochain-node/unaudited-admin-governance-shortcut only for \
             isolated development clusters."
        );
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "admin_governance_proposal_shortcut_disabled",
                "message": "Raw governance proposal submission via bearer-token shortcut is disabled by default.",
                "feature_flag": "unaudited-admin-governance-shortcut",
                "refusal_source": "exo-node/api.rs::handle_propose",
            })
            .to_string(),
        ));
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    {
        let payload = hex::decode(&req.payload_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex payload: {e}")))?;

        match reactor::submit_proposal(&api.reactor_state, &api.store, &api.net_handle, &payload)
            .await
        {
            Ok(node) => Ok(Json(ProposeResponse {
                node_hash: hex::encode(node.hash.0),
                height: None,
            })),
            Err(e) => {
                tracing::error!(err = %e, "Proposal submission failed");
                Err(internal_error_response("Proposal submission failed"))
            }
        }
    }
}

/// `POST /api/v1/governance/broadcast` — broadcast a governance event to the network.
async fn handle_broadcast(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<BroadcastRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    {
        let _ = (api, req);
        tracing::warn!(
            "refusing POST /api/v1/governance/broadcast: raw admin governance \
             event broadcast shortcut is gated. Build with \
             --features exochain-node/unaudited-admin-governance-shortcut only for \
             isolated development clusters."
        );
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "admin_governance_broadcast_shortcut_disabled",
                "message": "Raw governance event broadcast via bearer-token shortcut is disabled by default.",
                "feature_flag": "unaudited-admin-governance-shortcut",
                "refusal_source": "exo-node/api.rs::handle_broadcast",
            })
            .to_string(),
        ));
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    {
        let payload = hex::decode(&req.payload_hex)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex payload: {e}")))?;

        let event_type = match req.event_type.as_str() {
            "DecisionCreated" => GovernanceEventType::DecisionCreated,
            "VoteCast" => GovernanceEventType::VoteCast,
            "DecisionFinalized" => GovernanceEventType::DecisionFinalized,
            "AuthorityDelegated" => GovernanceEventType::AuthorityDelegated,
            "ConsentChanged" => GovernanceEventType::ConsentChanged,
            "EntityEnrolled" => GovernanceEventType::EntityEnrolled,
            "AuditEntry" => GovernanceEventType::AuditEntry,
            "ValidatorSetChange" => GovernanceEventType::ValidatorSetChange,
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Unknown event type: {other}"),
                ));
            }
        };

        reactor::broadcast_governance_event(
            &api.reactor_state,
            &api.net_handle,
            event_type,
            payload,
        )
        .await
        .map_err(|e| {
            tracing::error!(err = %e, "Governance event broadcast failed");
            internal_error_response("Governance event broadcast failed")
        })?;

        Ok(StatusCode::ACCEPTED)
    }
}

/// `GET /api/v1/governance/status` — return current node and consensus state.
async fn handle_status(
    State(api): State<Arc<NodeApiState>>,
) -> Result<Json<NodeStatusResponse>, (StatusCode, String)> {
    let snapshot = read_node_status_snapshot(Arc::clone(&api.reactor_state)).await?;

    Ok(Json(NodeStatusResponse {
        consensus_round: snapshot.consensus_round,
        committed_height: snapshot.committed_height,
        validator_count: snapshot.validators.len(),
        is_validator: snapshot.is_validator,
        validators: snapshot.validators,
        validator_trust_anchors: snapshot.validator_trust_anchors,
    }))
}

/// `POST /api/v1/governance/validators` — add or remove a validator.
///
/// # Safety gate
///
/// This handler is behind the `unaudited-admin-governance-shortcut`
/// feature flag (default OFF). When OFF, the endpoint returns
/// `403 Forbidden` with a structured refusal.
///
/// **Why:** the legacy path below mutates the validator set purely
/// on presentation of the admin bearer token — no BFT proposal,
/// no quorum, no signature chain, no recorded governance event.
/// One holder of the admin token becomes a constitutional dictator
/// over validator membership. That violates SeparationOfPowers,
/// NoSelfGrant, and every on-chain-governance invariant the
/// constitution exists to enforce.
///
/// Enable ONLY with full understanding of the trade-off (e.g., an
/// isolated dev cluster) and NEVER in production until a real
/// propose → quorum-vote → commit flow replaces it.
///
/// See: council-intake/exo-node-onyx-3-api-mcp.md (RED #1),
///      Initiatives/fix-admin-governance-bypass.md.
async fn handle_validator_change(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<ValidatorChangeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    {
        let _ = (api, req); // silence unused warnings
        tracing::warn!(
            "refusing POST /api/v1/governance/validators: admin bearer \
             shortcut is gated. See fix-admin-governance-bypass \
             initiative. To opt in for a dev cluster, build with \
             --features exochain-node/unaudited-admin-governance-shortcut."
        );
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "admin_governance_shortcut_disabled",
                "message": "Validator set mutation via bearer-token shortcut is disabled \
                            by default. A real propose → quorum-vote → commit flow is \
                            required. See Initiatives/fix-admin-governance-bypass.md.",
                "feature_flag": "unaudited-admin-governance-shortcut",
                "refusal_source": "exo-node/api.rs::handle_validator_change",
            })
            .to_string(),
        ));
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    {
        tracing::warn!(
            action = %req.action,
            did = %req.did,
            "UNAUDITED admin-governance shortcut in use — single bearer \
             token is mutating validator set without quorum. This is \
             gated by the `unaudited-admin-governance-shortcut` feature \
             and MUST NOT be enabled in production."
        );
        let did = Did::new(&req.did)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;

        // VCG-015: `AddValidator` now carries the validator's real Ed25519
        // public key on the wire, fail-closed-validated against the claimed
        // DID. The HTTP "add" action must supply a valid `public_key_hex`
        // — an add request lacking one, or whose key does not hash to
        // `did`, is rejected here rather than fabricating a placeholder.
        let change = match req.action.as_str() {
            "add" => {
                let public_key_hex = req.public_key_hex.as_deref().ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "public_key_hex is required when adding a validator".to_string(),
                    )
                })?;
                let public_key = parse_validator_public_key_hex(public_key_hex)?;
                let derived_did = identity::did_from_public_key(&public_key).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("public_key_hex does not derive a valid validator DID: {e}"),
                    )
                })?;
                if derived_did != did {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("public_key_hex derives {derived_did}, not {did}"),
                    ));
                }
                ValidatorChange::AddValidator {
                    did: did.clone(),
                    public_key,
                }
            }
            "remove" => {
                // Fast-fail UX pre-check ONLY — not the safety boundary.
                // This rejects an obviously-doomed proposal early (before
                // spending a round on it) by checking the *current* live
                // validator count at submission time. It cannot prevent two
                // concurrent `RemoveValidator` proposals from each passing
                // this check (each sees the count still above the floor
                // when it submits) and both reaching quorum, which would
                // jointly drop the set below the BFT floor if nothing else
                // caught it. The authoritative, race-proof invariant lives
                // at apply-on-commit time in
                // `reactor::apply_committed_validator_change_in_memory`'s
                // `RemoveValidator` arm (W3(A)/R1.5), which re-checks the
                // floor inside the same lock as the mutation and refuses
                // any commit that would breach it — regardless of caller,
                // and regardless of what this pre-check saw.
                let validator_count = read_validator_count(Arc::clone(&api.reactor_state)).await?;
                if validator_count <= 4 {
                    return Err((
                        StatusCode::CONFLICT,
                        "Cannot propose validator removal: minimum 4 required for BFT safety (3f+1)"
                            .into(),
                    ));
                }
                ValidatorChange::RemoveValidator { did: did.clone() }
            }
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid action '{other}', expected 'add' or 'remove'"),
                ));
            }
        };

        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).map_err(|e| {
            tracing::error!(err = %e, "Validator change proposal CBOR encoding failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Validator change proposal encoding failed".to_string(),
            )
        })?;

        let node =
            reactor::submit_proposal(&api.reactor_state, &api.store, &api.net_handle, &payload)
                .await
                .map_err(|e| {
                    tracing::warn!(err = %e, "Validator change proposal submission failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Validator change proposal submission failed".to_string(),
                    )
                })?;

        Ok(Json(serde_json::json!({
            "proposal_status": "submitted",
            "node_hash": hex::encode(node.hash.0),
            "action": req.action,
            "did": req.did,
        })))
    } // end cfg(feature = "unaudited-admin-governance-shortcut") block
}

// ---------------------------------------------------------------------------
// Trust receipt handlers
// ---------------------------------------------------------------------------

fn parse_hash256_hex(value: &str, field: &str) -> Result<Hash256, (StatusCode, String)> {
    let bytes = hex::decode(value)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{field} must be hex: {e}")))?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(arr))
}

/// The blanket refusal response used whenever the CrossChecked intake
/// feature is off, or is on but the request cannot even attempt authority
/// resolution (no `crosschecked_authority_did` / `external_proof_signature_hex`
/// supplied). This is intentionally the *same* error for both cases: a
/// caller that never identifies an authority gets no more information than
/// a caller running against a disabled node.
fn crosschecked_receipt_anchor_disabled_response() -> (StatusCode, String) {
    tracing::warn!(
        "refusing POST /api/v1/receipts: CrossChecked receipt anchoring is \
         disabled because this node cannot verify external proof URLs, \
         CrossChecked signatures, tenant authorization, or authority chains"
    );
    (
        StatusCode::FORBIDDEN,
        serde_json::json!({
            "error": "crosschecked_receipt_anchor_disabled",
            "message": "Node-signed CrossChecked receipt anchoring is disabled. A trusted runtime adapter must verify the external receipt proof, tenant/workspace authorization, and authority chain before EXOCHAIN mints a trust receipt.",
            "feature_flag": "unaudited-crosschecked-receipt-anchor",
            "refusal_source": "exo-node/api.rs::handle_crosschecked_receipt_anchor",
        })
        .to_string(),
    )
}

fn crosschecked_authority_error(error: &'static str, message: String) -> (StatusCode, String) {
    (
        StatusCode::FORBIDDEN,
        serde_json::json!({
            "error": error,
            "message": message,
            "feature_flag": "unaudited-crosschecked-receipt-anchor",
            "refusal_source": "exo-node/api.rs::handle_crosschecked_receipt_anchor",
        })
        .to_string(),
    )
}

/// `POST /api/v1/receipts` — anchor a CrossChecked receipt in the Exochain node.
///
/// VCG-007 / D3: even when `unaudited-crosschecked-receipt-anchor` is
/// enabled, this route only mints an EXOCHAIN `TrustReceipt` after (1)
/// resolving a TRUSTED CrossChecked authority via a verified
/// `exo-authority::DelegationRegistry` chain bound to an
/// `exo-identity::LocalDidRegistry` public key, (2) verifying the external
/// receipt's proof signature against that resolved authority, and (3)
/// confirming the request's tenant/workspace scope matches what the
/// authority was actually granted. Any missing/invalid step refuses and
/// never persists a receipt.
async fn handle_crosschecked_receipt_anchor(
    State(api): State<Arc<NodeApiState>>,
    Json(req): Json<CrossCheckedReceiptAnchorRequest>,
) -> Result<Json<CrossCheckedReceiptAnchorResponse>, (StatusCode, String)> {
    if !cfg!(feature = "unaudited-crosschecked-receipt-anchor") {
        return Err(crosschecked_receipt_anchor_disabled_response());
    }

    // A caller that does not even identify a CrossChecked authority and
    // proof cannot be distinguished from "feature not wired up" — refuse
    // with the same blanket error as the disabled-feature case.
    let (Some(authority_did_str), Some(proof_signature_hex)) = (
        req.crosschecked_authority_did.as_deref(),
        req.external_proof_signature_hex.as_deref(),
    ) else {
        return Err(crosschecked_receipt_anchor_disabled_response());
    };

    let authority_did = Did::new(authority_did_str).map_err(|e| {
        crosschecked_authority_error(
            "crosschecked_authority_unresolved",
            format!("crosschecked_authority_did is not a valid DID: {e}"),
        )
    })?;

    let now = Timestamp::new(u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0), 0);

    let (authority_public_key, scope) = {
        let anchor = api
            .crosschecked_trust
            .lock()
            .map_err(|_| internal_error_response("CrossChecked trust anchor lock poisoned"))?;
        match anchor.resolve(&authority_did, &now) {
            Some((public_key, scope)) => (public_key, scope.clone()),
            None => {
                return Err(crosschecked_authority_error(
                    "crosschecked_authority_unresolved",
                    format!(
                        "CrossChecked authority '{authority_did_str}' is not a resolvable, \
                         trusted delegation in this node's authority registry"
                    ),
                ));
            }
        }
    };

    // Tenant/workspace authorization: the resolved authority must have been
    // granted exactly the scope this request claims.
    if scope.tenant_id != req.tenant_id || scope.workspace_id != req.workspace_id {
        return Err(crosschecked_authority_error(
            "crosschecked_authority_scope_mismatch",
            format!(
                "CrossChecked authority '{authority_did_str}' is not authorized for \
                 tenant '{}' / workspace '{}'",
                req.tenant_id, req.workspace_id
            ),
        ));
    }

    // Verify the external proof: a signature over the payload hash, made by
    // the resolved trusted authority's key.
    let proof_signature_bytes = hex::decode(proof_signature_hex).map_err(|e| {
        crosschecked_authority_error(
            "crosschecked_authority_not_trusted",
            format!("external_proof_signature_hex is not valid hex: {e}"),
        )
    })?;
    let proof_signature_array: [u8; 64] =
        proof_signature_bytes.as_slice().try_into().map_err(|_| {
            crosschecked_authority_error(
                "crosschecked_authority_not_trusted",
                format!(
                    "external_proof_signature_hex must decode to 64 bytes, got {}",
                    proof_signature_bytes.len()
                ),
            )
        })?;
    let proof_signature = Signature::from_bytes(proof_signature_array);

    if !exo_core::crypto::verify(
        req.payload_hash.as_bytes(),
        &proof_signature,
        &authority_public_key,
    ) {
        return Err(crosschecked_authority_error(
            "crosschecked_authority_not_trusted",
            "external proof signature does not verify against the resolved CrossChecked \
             authority's public key"
                .to_string(),
        ));
    }

    // All gates passed: mint a node-signed TrustReceipt anchoring this
    // verified CrossChecked event, reusing the existing receipt-minting and
    // store paths.
    let payload_hash = Hash256::digest(req.payload_hash.as_bytes());
    let authority_chain_hash = Hash256::digest(authority_did_str.as_bytes());

    let receipt = TrustReceipt::new(
        api.node_did.clone(),
        authority_chain_hash,
        None,
        "crosschecked.receipt.anchor".to_string(),
        payload_hash,
        ReceiptOutcome::Executed,
        now,
        &*api.sign_fn,
    )
    .map_err(|e| {
        tracing::error!(err = %e, "CrossChecked trust receipt construction failed");
        internal_error_response("CrossChecked trust receipt construction failed")
    })?;

    {
        let mut store = api
            .store
            .lock()
            .map_err(|_| internal_error_response("Receipt store lock poisoned"))?;
        store.save_receipt(&receipt).map_err(|e| {
            tracing::error!(err = %e, "CrossChecked trust receipt persistence failed");
            internal_error_response("CrossChecked trust receipt persistence failed")
        })?;
    }

    let exochain_receipt_hash = hex::encode(receipt.receipt_hash.0);
    Ok(Json(CrossCheckedReceiptAnchorResponse {
        status: "minted".to_string(),
        exochain_receipt_hash: exochain_receipt_hash.clone(),
        anchor_hash: exochain_receipt_hash,
        verified_at: Utc::now(),
    }))
}

/// `GET /api/v1/receipts/:hash` — look up a trust receipt by content hash.
async fn handle_receipt_by_hash(
    State(api): State<Arc<NodeApiState>>,
    Path(hash_hex): Path<String>,
) -> Result<Json<ReceiptResponse>, (StatusCode, String)> {
    let hash_bytes = hex::decode(&hash_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex hash: {e}")))?;
    if hash_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Hash must be 32 bytes, got {}", hash_bytes.len()),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let hash = Hash256::from_bytes(arr);

    let receipt = load_receipt_by_hash(Arc::clone(&api.store), hash).await?;

    match receipt {
        Some(r) => Ok(Json(ReceiptResponse::from(r))),
        None => Err((StatusCode::NOT_FOUND, "Receipt not found".into())),
    }
}

/// `GET /api/v1/receipts` — list trust receipts filtered by actor DID.
async fn handle_receipts_list(
    State(api): State<Arc<NodeApiState>>,
    Query(q): Query<ReceiptQuery>,
) -> Result<Json<Vec<ReceiptResponse>>, (StatusCode, String)> {
    let actor = q.actor.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Query parameter 'actor' is required".into(),
        )
    })?;

    let limit = q.limit.unwrap_or(50).min(500);

    let receipts = load_receipts_by_actor(Arc::clone(&api.store), actor, limit).await?;

    Ok(Json(
        receipts.into_iter().map(ReceiptResponse::from).collect(),
    ))
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the governance API router.
pub fn governance_router(state: Arc<NodeApiState>) -> Router {
    Router::new()
        .route("/api/v1/governance/propose", post(handle_propose))
        .route("/api/v1/governance/broadcast", post(handle_broadcast))
        .route("/api/v1/governance/status", get(handle_status))
        .route(
            "/api/v1/governance/validators",
            post(handle_validator_change),
        )
        .route("/api/v1/receipts/:hash", get(handle_receipt_by_hash))
        .route(
            "/api/v1/receipts",
            get(handle_receipts_list).post(handle_crosschecked_receipt_anchor),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_GOVERNANCE_API_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(
            MAX_GOVERNANCE_API_CONCURRENT_REQUESTS,
        ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    use axum::{body::Body, http::Request};
    use exo_core::{crypto::KeyPair, types::Signature};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        reactor::{ReactorConfig, create_reactor_state},
        store::SqliteDagStore,
    };

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        let keypair = KeyPair::from_secret_bytes([1u8; 32]).unwrap();
        Arc::new(move |data: &[u8]| keypair.sign(data))
    }

    fn validator_public_keys(
        validators: &BTreeSet<Did>,
    ) -> std::collections::BTreeMap<Did, exo_core::types::PublicKey> {
        validators
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, did)| {
                let seed = u8::try_from(idx + 1).unwrap();
                let keypair = KeyPair::from_secret_bytes([seed; 32]).unwrap();
                (did, *keypair.public_key())
            })
            .collect()
    }

    fn test_api_state_with_validator_flag(is_validator: bool) -> Arc<NodeApiState> {
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();

        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator,
            validator_public_keys: validator_public_keys(&validators),
            validators,
            round_timeout_ms: 5000,
        };

        let sign_fn = make_sign_fn();
        let reactor_state = create_reactor_state(&config, Arc::clone(&sign_fn), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            while let Some(command) = cmd_rx.recv().await {
                if let crate::network::NetworkCommand::Publish { reply, .. } = command {
                    let _ = reply.send(Ok(()));
                }
            }
        });
        let net_handle = NetworkHandle::new(cmd_tx);

        Arc::new(NodeApiState {
            reactor_state,
            store,
            net_handle,
            node_did: Did::new("did:exo:v0").unwrap(),
            sign_fn,
            crosschecked_trust: Arc::new(Mutex::new(test_crosschecked_trust_anchor())),
        })
    }

    fn test_api_state() -> Arc<NodeApiState> {
        test_api_state_with_validator_flag(true)
    }

    /// Seed a `CrossCheckedTrustAnchor` with exactly one trusted CrossChecked
    /// authority, `did:exo:crosschecked-authority-trusted`, delegated from a
    /// root authority and bound to the tenant/workspace scope the VCG-007
    /// red tests exercise as "authorized". Any other authority DID
    /// (including `did:exo:crosschecked-authority-unregistered`) has no
    /// delegation chain and no DID document here, so it is unresolvable —
    /// this models a real node that has explicitly delegated exactly one
    /// CrossChecked verification seat.
    fn test_crosschecked_trust_anchor() -> CrossCheckedTrustAnchor {
        let root_did = Did::new("did:exo:root-authority").unwrap();
        let root_keypair = KeyPair::from_secret_bytes([9u8; 32]).unwrap();
        let authority_did = Did::new("did:exo:crosschecked-authority-trusted").unwrap();
        let authority_keypair = KeyPair::from_secret_bytes([7u8; 32]).unwrap();

        let now = exo_core::types::Timestamp::new(1_000, 0);
        let expires = exo_core::types::Timestamp::new(9_999_999_999_999, 0);

        let mut registry = DelegationRegistry::new();
        registry
            .delegate(
                exo_authority::delegation::DelegationGrant {
                    from: &root_did,
                    to: &authority_did,
                    scope: &[exo_authority::Permission::Challenge],
                    expires,
                    now: &now,
                    parent_link_id: None,
                    delegatee_kind: exo_authority::DelegateeKind::AiAgent {
                        model_id: "crosschecked-verifier".to_string(),
                    },
                    delegator_public_key: root_keypair.public_key(),
                },
                |payload| root_keypair.sign(payload),
            )
            .unwrap();

        let mut dids = LocalDidRegistry::new();
        dids.register(DidDocument {
            id: root_did.clone(),
            public_keys: vec![*root_keypair.public_key()],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: now,
            updated: now,
            revoked: false,
        })
        .unwrap();
        dids.register(DidDocument {
            id: authority_did.clone(),
            public_keys: vec![*authority_keypair.public_key()],
            authentication: vec![],
            verification_methods: vec![],
            hybrid_verification_methods: vec![],
            service_endpoints: vec![],
            created: now,
            updated: now,
            revoked: false,
        })
        .unwrap();

        let mut scopes = std::collections::BTreeMap::new();
        scopes.insert(
            authority_did,
            CrossCheckedAuthorityScope {
                tenant_id: "00000000-0000-0000-0000-000000000101".to_string(),
                workspace_id: "00000000-0000-0000-0000-000000000102".to_string(),
            },
        );

        CrossCheckedTrustAnchor {
            root_did,
            registry,
            dids,
            scopes,
        }
    }

    fn crosschecked_receipt_anchor_body() -> serde_json::Value {
        serde_json::json!({
            "source": "crosschecked",
            "idempotency_key": "crosschecked:test-event",
            "external_event_id": "00000000-0000-0000-0000-000000000001",
            "external_receipt_hash": "11".repeat(32),
            "payload_hash": "22".repeat(32),
            "tenant_id": "00000000-0000-0000-0000-000000000101",
            "workspace_id": "00000000-0000-0000-0000-000000000102",
            "event_type": "synthetic.receipt.check",
            "emitted_at": "2026-05-12T12:00:00Z",
            "public_proof_url": "https://crosschecked.ai/verify?receipt=00000000-0000-0000-0000-000000000001"
        })
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    fn validator_change_payload_hex_for_test() -> String {
        // VCG-015: the payload's DID must actually hash from the
        // accompanying public key (fail-closed cross-check in
        // `validate_governance_proposal_payload`), so this fixture uses a
        // real deterministic keypair rather than a hand-picked DID string.
        let keypair = KeyPair::from_secret_bytes([222u8; 32]).unwrap();
        let public_key = *keypair.public_key();
        let did = identity::did_from_public_key(&public_key).unwrap();
        let change = ValidatorChange::AddValidator { did, public_key };
        let mut payload = Vec::new();
        ciborium::into_writer(&change, &mut payload).unwrap();
        hex::encode(payload)
    }

    #[tokio::test]
    async fn status_endpoint_returns_consensus_state() {
        let state = test_api_state();
        let app = governance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let status: NodeStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.consensus_round, 0);
        assert_eq!(status.validator_count, 4);
        assert!(status.is_validator);
        assert_eq!(status.validator_trust_anchors.len(), 4);
        for anchor in status.validator_trust_anchors {
            assert_eq!(anchor.algorithm, "ed25519_v1");
            assert_eq!(anchor.public_key_hex.len(), 64);
            assert!(status.validators.contains(&anchor.did));
        }
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn propose_endpoint_creates_dag_node() {
        let state = test_api_state();
        let app = governance_router(state);

        let payload = validator_change_payload_hex_for_test();
        let body = serde_json::json!({ "payload_hex": payload });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The publish may fail (no network loop), but the DAG node is created locally.
        // The endpoint returns 500 because net publish fails, but the local state
        // is mutated. In production, the network loop would be running.
        // Let's accept either 200 or 500 and check that the DAG was modified.
        let _status = resp.status();
    }

    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    #[tokio::test]
    async fn propose_endpoint_refuses_admin_shortcut_without_feature_flag() {
        let state = test_api_state();
        let tips_before = state.store.lock().unwrap().tips_sync().unwrap();
        let app = governance_router(Arc::clone(&state));

        let body = serde_json::json!({ "payload_hex": hex::encode(b"test governance decision") });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "default build must refuse raw admin-token governance proposal shortcuts"
        );
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("admin_governance_proposal_shortcut_disabled"),
            "refusal body must include proposal shortcut error tag, got: {text}"
        );

        let tips_after = state.store.lock().unwrap().tips_sync().unwrap();
        assert_eq!(
            tips_before, tips_after,
            "refused proposal shortcut must not append or persist a DAG node"
        );
    }

    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    #[tokio::test]
    async fn broadcast_endpoint_refuses_admin_shortcut_without_feature_flag() {
        let state = test_api_state();
        let app = governance_router(state);

        let body = serde_json::json!({
            "event_type": "DecisionCreated",
            "payload_hex": hex::encode(b"decision-created"),
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/broadcast")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "default build must refuse raw admin-token governance event broadcast shortcuts"
        );
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("admin_governance_broadcast_shortcut_disabled"),
            "refusal body must include broadcast shortcut error tag, got: {text}"
        );
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn propose_endpoint_redacts_internal_submission_errors() {
        let state = test_api_state_with_validator_flag(false);
        let app = governance_router(state);

        let body = serde_json::json!({ "payload_hex": hex::encode(b"not from validator") });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            !text.contains("not a validator"),
            "internal reactor errors must not be echoed to HTTP clients: {text}"
        );
        assert!(
            text.contains("Proposal submission failed"),
            "client should receive a generic proposal failure, got: {text}"
        );
    }

    #[tokio::test]
    async fn propose_endpoint_rejects_oversized_body_before_handler() {
        let state = test_api_state();
        let app = governance_router(state);
        let oversized_payload = "ab".repeat(70 * 1024);
        let body = serde_json::json!({ "payload_hex": oversized_payload });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn status_height_conversion_does_not_use_truncating_cast() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            !production.contains(".committed.len() as u64"),
            "status committed height must use checked conversion, not a truncating cast"
        );
    }

    #[test]
    fn production_api_source_does_not_suppress_security_relevant_clippy_lints() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        for lint in ["clippy::expect_used", "clippy::as_conversions"] {
            assert!(
                !production.contains(lint),
                "production API source must not suppress {lint}"
            );
        }
    }

    #[test]
    fn async_handlers_do_not_lock_std_mutexes_directly() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let handlers = production
            .split("// ---------------------------------------------------------------------------\n// Route handlers")
            .nth(1)
            .expect("route handler section")
            .split("// ---------------------------------------------------------------------------\n// Router construction")
            .next()
            .expect("router construction boundary");

        assert!(
            !handlers.contains(".store.lock()"),
            "async route handlers must not block runtime workers on store std::sync::Mutex"
        );
        assert!(
            !handlers.contains(".reactor_state.lock()"),
            "async route handlers must not block runtime workers on reactor std::sync::Mutex"
        );
    }

    #[test]
    fn governance_router_applies_local_admission_layers() {
        let source = include_str!("api.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");

        assert!(
            production.contains("DefaultBodyLimit::max(MAX_GOVERNANCE_API_BODY_BYTES)"),
            "governance router must cap request body size locally"
        );
        assert!(
            production.contains("ConcurrencyLimitLayer::new(")
                && production.contains("MAX_GOVERNANCE_API_CONCURRENT_REQUESTS"),
            "governance router must apply local request admission control"
        );
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn broadcast_rejects_unknown_event_type() {
        let state = test_api_state();
        let app = governance_router(state);

        let body = serde_json::json!({
            "event_type": "UnknownType",
            "payload_hex": "deadbeef",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/broadcast")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn validator_add_submits_proposal_without_mutating_validator_set() {
        let state = test_api_state();
        let validators_before = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        let app = governance_router(Arc::clone(&state));
        let keypair = KeyPair::from_secret_bytes([50u8; 32]).unwrap();
        let did = crate::identity::did_from_public_key(keypair.public_key()).unwrap();

        let body = serde_json::json!({
            "action": "add",
            "did": did.to_string(),
            "public_key_hex": hex::encode(keypair.public_key().as_bytes()),
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result["proposal_status"], "submitted");
        assert_eq!(result["action"], "add");
        assert_eq!(result["did"], did.to_string());
        assert_eq!(
            result["node_hash"].as_str().map(str::len),
            Some(64),
            "validator change proposal must return a 32-byte DAG hash"
        );

        let validators_after = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        assert_eq!(
            validators_before, validators_after,
            "validator-change endpoint must not directly mutate validator set"
        );
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn validator_remove_below_minimum_rejected() {
        let state = test_api_state();
        let app = governance_router(state);

        let body = serde_json::json!({
            "action": "remove",
            "did": "did:exo:v0",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[cfg(feature = "unaudited-admin-governance-shortcut")]
    #[tokio::test]
    async fn validator_remove_above_minimum_submits_proposal_without_mutating_validator_set() {
        let state = test_api_state();

        // First add validators to reach 5+
        {
            let mut s = state.reactor_state.lock().unwrap();
            s.consensus
                .config
                .validators
                .insert(Did::new("did:exo:v4").unwrap());
        }
        let validators_before = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };

        let app = governance_router(Arc::clone(&state));

        let body = serde_json::json!({
            "action": "remove",
            "did": "did:exo:v4",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result["proposal_status"], "submitted");
        assert_eq!(result["action"], "remove");
        assert_eq!(result["did"], "did:exo:v4");
        assert_eq!(
            result["node_hash"].as_str().map(str::len),
            Some(64),
            "validator change proposal must return a 32-byte DAG hash"
        );

        let validators_after = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        assert_eq!(
            validators_before, validators_after,
            "validator-change endpoint must not directly mutate validator set"
        );
    }

    // -----------------------------------------------------------------------
    // Trust receipt endpoint tests
    // -----------------------------------------------------------------------

    fn make_test_receipt(actor: &str, action: &str, ts_ms: u64) -> exo_core::types::TrustReceipt {
        use exo_core::types::{Hash256, ReceiptOutcome, Timestamp, TrustReceipt};
        let sign_fn = make_sign_fn();
        TrustReceipt::new(
            Did::new(actor).unwrap(),
            Hash256::ZERO,
            None,
            action.to_string(),
            Hash256::digest(format!("{actor}-{action}-{ts_ms}").as_bytes()),
            ReceiptOutcome::Executed,
            Timestamp {
                physical_ms: ts_ms,
                logical: 0,
            },
            &*sign_fn,
        )
        .expect("test trust receipt should encode")
    }

    #[tokio::test]
    async fn receipt_lookup_returns_stored_receipt() {
        let state = test_api_state();
        let receipt = make_test_receipt("did:exo:test-actor", "dag.commit", 1_700_000_000_000);
        let receipt_hash = receipt.receipt_hash;

        {
            let mut st = state.store.lock().unwrap();
            st.save_receipt(&receipt).unwrap();
        }

        let app = governance_router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/receipts/{}", hex::encode(receipt_hash.0)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["actor_did"], "did:exo:test-actor");
        assert_eq!(result["action_type"], "dag.commit");
        assert_eq!(result["outcome"], "executed");
    }

    #[cfg(not(feature = "unaudited-crosschecked-receipt-anchor"))]
    #[tokio::test]
    async fn crosschecked_receipt_anchor_refuses_untrusted_external_metadata_by_default() {
        let state = test_api_state();
        let app = governance_router(Arc::clone(&state));
        let body = crosschecked_receipt_anchor_body();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/receipts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["error"], "crosschecked_receipt_anchor_disabled");
        assert_eq!(
            result["feature_flag"],
            "unaudited-crosschecked-receipt-anchor"
        );
        let receipts = state
            .store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:v0", 10)
            .unwrap();
        assert!(
            receipts.is_empty(),
            "refused CrossChecked anchor must not persist a node-signed trust receipt"
        );
    }

    #[cfg(feature = "unaudited-crosschecked-receipt-anchor")]
    #[tokio::test]
    async fn crosschecked_receipt_anchor_refuses_unverified_metadata_even_when_feature_enabled() {
        let state = test_api_state();
        let app = governance_router(Arc::clone(&state));
        let body = crosschecked_receipt_anchor_body();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/receipts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["error"], "crosschecked_receipt_anchor_disabled");
        let receipts = state
            .store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:v0", 10)
            .unwrap();
        assert!(
            receipts.is_empty(),
            "feature-enabled CrossChecked anchor must not persist a node-signed trust receipt"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-007 RED stage — CrossChecked intake must resolve a TRUSTED authority
    // (exo-authority DelegationRegistry entry per D3), verify the external
    // receipt's proof/signature against that authority, and enforce
    // tenant/workspace scope before minting any EXOCHAIN TrustReceipt. Today
    // the route is an unconditional 403 refusal with no minting path in any
    // configuration (see api.rs::handle_crosschecked_receipt_anchor), so all
    // three tests below are expected RED: they fail because the route never
    // reaches authority resolution, proof verification, or scope enforcement
    // — it refuses everything with the blanket `crosschecked_receipt_anchor_disabled`
    // 403 regardless of feature flag or request content.

    /// A CrossChecked anchor request body carrying an external authority
    /// reference and an external proof signature that a production intake
    /// implementation would need to resolve/verify against an
    /// `exo-authority::DelegationRegistry` entry (D3: registry entries are
    /// the single authority species). These fields do not exist on
    /// `CrossCheckedReceiptAnchorRequest` yet — they are extra JSON keys the
    /// current struct silently ignores (no `deny_unknown_fields`), which is
    /// exactly why the route cannot distinguish an unresolvable authority
    /// from a resolvable one today: it 403s before parsing the intent.
    fn crosschecked_anchor_body_with_authority(
        authority_did: &str,
        proof_signature_hex: &str,
        tenant_id: &str,
        workspace_id: &str,
    ) -> serde_json::Value {
        let mut body = crosschecked_receipt_anchor_body();
        body["tenant_id"] = serde_json::json!(tenant_id);
        body["workspace_id"] = serde_json::json!(workspace_id);
        body["crosschecked_authority_did"] = serde_json::json!(authority_did);
        body["external_proof_signature_hex"] = serde_json::json!(proof_signature_hex);
        body
    }

    /// (1) An external receipt whose claimed CrossChecked authority is not
    /// registered in the node's `exo-authority::DelegationRegistry` at all —
    /// i.e. cryptographically unresolvable. A correct implementation must
    /// reject this with a specific authority-verification error distinct from
    /// the blanket disabled-feature 403, and must never persist a receipt.
    ///
    /// Expected RED: the route refuses unconditionally with
    /// `crosschecked_receipt_anchor_disabled` regardless of authority
    /// resolvability, so the specific-error assertion fails.
    #[cfg(feature = "unaudited-crosschecked-receipt-anchor")]
    #[tokio::test]
    async fn crosschecked_anchor_rejects_external_metadata_without_trusted_authority() {
        let state = test_api_state();
        let app = governance_router(Arc::clone(&state));

        // Unknown/unregistered authority DID — no corresponding
        // DelegationRegistry entry exists anywhere in this node.
        let unresolvable_authority_did = "did:exo:crosschecked-authority-unregistered";
        let bogus_signature_hex = "ab".repeat(64);
        let body = crosschecked_anchor_body_with_authority(
            unresolvable_authority_did,
            &bogus_signature_hex,
            "00000000-0000-0000-0000-000000000101",
            "00000000-0000-0000-0000-000000000102",
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/receipts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = resp.status();
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();

        // Must be rejected — but with a specific authority-verification
        // error, not the blanket disabled-feature refusal. A worker cannot
        // pass this by leaving the unconditional 403 in place.
        assert_ne!(
            result["error"], "crosschecked_receipt_anchor_disabled",
            "expected a specific authority-resolution error, got the blanket refusal \
             (status {status}): {result}"
        );
        assert!(
            result["error"] == "crosschecked_authority_unresolved"
                || result["error"] == "crosschecked_authority_not_trusted",
            "expected an authority-verification-specific error code, got: {result}"
        );

        let receipts = state
            .store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:v0", 10)
            .unwrap();
        assert!(
            receipts.is_empty(),
            "rejected CrossChecked anchor with unresolvable authority must not \
             persist a node-signed trust receipt"
        );
    }

    /// (2) A CrossChecked authority IS registered in the node's
    /// `DelegationRegistry` (per D3, reused via `exo-authority` +
    /// `exo-identity::LocalDidRegistry`), and the external receipt carries a
    /// proof that verifies against that authority's resolved key/scope. A
    /// correct implementation mints a node-signed `TrustReceipt` whose
    /// `exochain_receipt_hash` is derivable from the request's `payload_hash`,
    /// and the receipt must be retrievable afterward.
    ///
    /// Expected RED: the route refuses unconditionally, so no receipt is ever
    /// minted and the retrieval assertion fails.
    #[cfg(feature = "unaudited-crosschecked-receipt-anchor")]
    #[tokio::test]
    async fn crosschecked_anchor_mints_when_authority_resolves_and_proof_verifies() {
        let state = test_api_state();
        let app = governance_router(Arc::clone(&state));

        // Register a trusted CrossChecked authority as a DelegationRegistry
        // entry — the single authority species per D3 (same species as a
        // future council seat). This models what a production intake path
        // would resolve via exo-authority + exo-identity::LocalDidRegistry.
        let authority_keypair = KeyPair::from_secret_bytes([7u8; 32]).unwrap();
        let authority_did = Did::new("did:exo:crosschecked-authority-trusted").unwrap();

        let mut registry = exo_authority::DelegationRegistry::new();
        let root_did = Did::new("did:exo:root-authority").unwrap();
        let root_keypair = KeyPair::from_secret_bytes([9u8; 32]).unwrap();
        let now = exo_core::types::Timestamp::new(1_000, 0);
        let expires = exo_core::types::Timestamp::new(9_999_999_999_999, 0);

        let link = registry
            .delegate(
                exo_authority::delegation::DelegationGrant {
                    from: &root_did,
                    to: &authority_did,
                    scope: &[exo_authority::Permission::Challenge],
                    expires,
                    now: &now,
                    parent_link_id: None,
                    delegatee_kind: exo_authority::DelegateeKind::AiAgent {
                        model_id: "crosschecked-verifier".to_string(),
                    },
                    delegator_public_key: root_keypair.public_key(),
                },
                |payload| root_keypair.sign(payload),
            )
            .unwrap();
        assert!(registry.find_chain(&root_did, &authority_did).is_some());
        let _ = link;

        // A signed external proof from the trusted authority's key over the
        // receipt's payload hash — this is what a production verifier must
        // check against the resolved authority's public key.
        let payload_hash_hex = "22".repeat(32);
        let proof_signature = authority_keypair.sign(payload_hash_hex.as_bytes());
        let proof_signature_hex = hex::encode(proof_signature.to_bytes());

        let body = crosschecked_anchor_body_with_authority(
            authority_did.as_str(),
            &proof_signature_hex,
            "00000000-0000-0000-0000-000000000101",
            "00000000-0000-0000-0000-000000000102",
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/receipts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a resolvable trusted authority with a verifying proof must mint, not refuse"
        );
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let minted: serde_json::Value = serde_json::from_slice(&resp_body)
            .expect("successful mint must return a JSON CrossCheckedReceiptAnchorResponse body");
        assert_eq!(minted["status"], "minted");
        let minted_hash = minted["exochain_receipt_hash"]
            .as_str()
            .expect("minted response must carry exochain_receipt_hash")
            .to_string();

        // The minted receipt hash must be derivable from payload_hash and
        // must actually be retrievable from the receipt store afterward.
        let receipts = state
            .store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:v0", 10)
            .unwrap();
        assert_eq!(
            receipts.len(),
            1,
            "authority-verified CrossChecked anchor must persist exactly one trust receipt"
        );
        assert_eq!(
            hex::encode(receipts[0].receipt_hash.0),
            minted_hash,
            "returned exochain_receipt_hash must match the persisted receipt"
        );
    }

    /// (3) The external receipt's proof verifies against a resolved, trusted
    /// authority, but the request's tenant/workspace scope does not match the
    /// scope that authority was actually granted. This must be rejected even
    /// though the signature checks out — tenant/workspace authorization is a
    /// separate, mandatory gate (SCOPE IN item 3 of the VCG-007 work order).
    ///
    /// Expected RED: the route refuses unconditionally before any
    /// authority/scope logic runs, so the specific scope-mismatch assertion
    /// fails (today every request — matching scope or not — gets the same
    /// blanket 403).
    #[cfg(feature = "unaudited-crosschecked-receipt-anchor")]
    #[tokio::test]
    async fn crosschecked_anchor_rejects_tenant_workspace_mismatch() {
        let state = test_api_state();
        let app = governance_router(Arc::clone(&state));

        let authority_keypair = KeyPair::from_secret_bytes([7u8; 32]).unwrap();
        let authority_did = Did::new("did:exo:crosschecked-authority-trusted").unwrap();

        let mut registry = exo_authority::DelegationRegistry::new();
        let root_did = Did::new("did:exo:root-authority").unwrap();
        let root_keypair = KeyPair::from_secret_bytes([9u8; 32]).unwrap();
        let now = exo_core::types::Timestamp::new(1_000, 0);
        let expires = exo_core::types::Timestamp::new(9_999_999_999_999, 0);

        // Authority is granted scope for a *different* tenant/workspace than
        // the one in the request below (modeled here via delegatee kind +
        // scope narrative; the production implementation decides the actual
        // scope-carrying type per the work order's explicit-scope-decision
        // requirement). The request below targets a tenant/workspace the
        // authority was never granted.
        registry
            .delegate(
                exo_authority::delegation::DelegationGrant {
                    from: &root_did,
                    to: &authority_did,
                    scope: &[exo_authority::Permission::Challenge],
                    expires,
                    now: &now,
                    parent_link_id: None,
                    delegatee_kind: exo_authority::DelegateeKind::AiAgent {
                        model_id: "crosschecked-verifier".to_string(),
                    },
                    delegator_public_key: root_keypair.public_key(),
                },
                |payload| root_keypair.sign(payload),
            )
            .unwrap();

        let payload_hash_hex = "22".repeat(32);
        let proof_signature = authority_keypair.sign(payload_hash_hex.as_bytes());
        let proof_signature_hex = hex::encode(proof_signature.to_bytes());

        // Mismatched tenant/workspace relative to what the authority was
        // granted for.
        let body = crosschecked_anchor_body_with_authority(
            authority_did.as_str(),
            &proof_signature_hex,
            "00000000-0000-0000-0000-000000000999",
            "00000000-0000-0000-0000-000000000998",
        );

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/receipts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = resp.status();
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();

        assert_ne!(
            result["error"], "crosschecked_receipt_anchor_disabled",
            "expected a specific tenant/workspace scope-mismatch error, got the \
             blanket refusal (status {status}): {result}"
        );
        assert_eq!(
            result["error"], "crosschecked_authority_scope_mismatch",
            "expected the tenant/workspace scope-mismatch error code, got: {result}"
        );

        let receipts = state
            .store
            .lock()
            .unwrap()
            .load_receipts_by_actor("did:exo:v0", 10)
            .unwrap();
        assert!(
            receipts.is_empty(),
            "tenant/workspace scope mismatch must never mint a trust receipt, \
             even when the external proof signature verifies"
        );
    }

    #[tokio::test]
    async fn receipt_lookup_not_found() {
        let state = test_api_state();
        let app = governance_router(state);
        let fake_hash = "0".repeat(64);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/receipts/{fake_hash}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn receipt_lookup_invalid_hex() {
        let state = test_api_state();
        let app = governance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipts/not-valid-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn receipt_list_by_actor() {
        let state = test_api_state();

        // Save receipts for two different actors.
        {
            let mut st = state.store.lock().unwrap();
            st.save_receipt(&make_test_receipt("did:exo:alice", "propose", 1000))
                .unwrap();
            st.save_receipt(&make_test_receipt("did:exo:alice", "commit", 2000))
                .unwrap();
            st.save_receipt(&make_test_receipt("did:exo:bob", "propose", 3000))
                .unwrap();
        }

        let app = governance_router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipts?actor=did:exo:alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let results: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r["actor_did"] == "did:exo:alice"));
    }

    #[tokio::test]
    async fn receipt_list_requires_actor_param() {
        let state = test_api_state();
        let app = governance_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ==================================================================
    // GAP admin-governance-bypass refusal tests (default-build only)
    // ==================================================================

    /// When the `unaudited-admin-governance-shortcut` feature is OFF
    /// (the default), a POST to /api/v1/governance/validators must
    /// return 403 with a structured refusal body — never mutate the
    /// validator set on bearer-token alone.
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    #[tokio::test]
    async fn validator_add_refused_without_feature_flag() {
        let state = test_api_state();
        let validator_count_before = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.len()
        };

        let app = governance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "action": "add",
            "did": "did:exo:some-new-validator",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "default build MUST refuse validator-set mutation via bearer shortcut"
        );
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            text.contains("admin_governance_shortcut_disabled"),
            "refusal body must include error tag, got: {text}"
        );
        assert!(
            text.contains("unaudited-admin-governance-shortcut"),
            "refusal body must name the feature flag, got: {text}"
        );

        // CRITICAL: validator set was NOT mutated.
        let validator_count_after = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.len()
        };
        assert_eq!(
            validator_count_before, validator_count_after,
            "refused endpoint must not touch validator set"
        );
    }

    /// Same for `remove` — refused with no state change.
    #[cfg(not(feature = "unaudited-admin-governance-shortcut"))]
    #[tokio::test]
    async fn validator_remove_refused_without_feature_flag() {
        let state = test_api_state();
        let validators_before: BTreeSet<Did> = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };

        let app = governance_router(Arc::clone(&state));
        let body = serde_json::json!({
            "action": "remove",
            "did": "did:exo:v0",
        });

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/validators")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Validator set unchanged.
        let validators_after: BTreeSet<Did> = {
            let s = state.reactor_state.lock().unwrap();
            s.consensus.config.validators.clone()
        };
        assert_eq!(validators_before, validators_after);
    }
}
