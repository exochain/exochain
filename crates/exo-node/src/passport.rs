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

//! Agent Passport — external resolution of agent identity, delegation,
//! consent, attestation, and trust standing via HTTP.
//!
//! The passport aggregates data from multiple trust crates into a single
//! JSON-serializable profile that a third party can use to verify:
//!
//! - **who** an agent is (identity)
//! - **who authorized** that agent (delegation chain)
//! - **what scope** the agent holds (permissions)
//! - **what consent** governs its actions (bailments)
//! - **what standing** it has (sanctions, revocation, risk)
//!
//! ## Endpoints
//!
//! - `GET /api/v1/agents/:did/passport` — full trust profile
//! - `GET /api/v1/agents/:did/delegations` — active authority chains
//! - `GET /api/v1/agents/:did/consent` — active bailments
//! - `GET /api/v1/agents/:did/standing` — sanctions and revocation status

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use serde::Serialize;

use crate::{
    reactor::{ReactorState, SharedReactorState},
    store::SqliteDagStore,
    zerodentity::store::{SharedZerodentityStore, ZerodentityStore},
};

type PassportError = (StatusCode, String);
type PassportResult<T> = Result<T, PassportError>;
const PASSPORT_CONCURRENCY_LIMIT: usize = 32;

fn parse_passport_did(did: &str) -> PassportResult<exo_core::types::Did> {
    exo_core::types::Did::new(did).map_err(|error| {
        tracing::warn!(%error, "invalid passport DID path parameter");
        (StatusCode::BAD_REQUEST, "Invalid DID".to_string())
    })
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for passport API handlers.
#[derive(Clone)]
pub struct PassportApiState {
    pub reactor_state: SharedReactorState,
    /// DAG store shared with the node API.
    #[allow(dead_code)]
    pub store: Arc<Mutex<SqliteDagStore>>,
    /// 0dentity store for sovereign identity score lookup.
    pub zerodentity_store: SharedZerodentityStore,
}

async fn with_reactor_state_blocking<T, F>(
    state: Arc<PassportApiState>,
    operation: F,
) -> PassportResult<T>
where
    T: Send + 'static,
    F: FnOnce(&ReactorState) -> PassportResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let reactor = state.reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        operation(&reactor)
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "passport reactor state task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Reactor state task failed".to_string(),
        )
    })?
}

async fn with_zerodentity_store_blocking<T, F>(
    state: Arc<PassportApiState>,
    operation: F,
) -> PassportResult<T>
where
    T: Send + 'static,
    F: FnOnce(&ZerodentityStore) -> PassportResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let zd = state.zerodentity_store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Zerodentity store unavailable".to_string(),
            )
        })?;
        operation(&zd)
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "passport 0dentity store task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Zerodentity store task failed".to_string(),
        )
    })?
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Full agent passport — aggregated trust profile.
#[derive(Debug, Serialize)]
pub struct AgentPassport {
    /// The agent's decentralized identifier.
    pub did: String,
    /// Whether this DID is known to this node.
    pub known: bool,
    /// Whether this agent is a validator in the consensus set.
    pub is_validator: bool,
    /// Identity details.
    pub identity: IdentityProfile,
    /// Active delegations (authority chains where this agent participates).
    pub delegations: DelegationProfile,
    /// Consent and bailment records.
    pub consent: ConsentProfile,
    /// Trust standing (sanctions, revocation, risk).
    pub standing: StandingProfile,
    /// Whether the backing 0dentity store is durable across node restarts.
    pub persistence_ready: bool,
    /// 0dentity sovereign identity score, if available for this DID.
    pub zerodentity: Option<ZerodentityProfile>,
}

/// Identity portion of the passport.
#[derive(Debug, Serialize)]
pub struct IdentityProfile {
    /// The agent's DID string.
    pub did: String,
    /// Whether this node can verify the DID's signatures.
    pub verification_capable: bool,
    /// Key lifecycle state.
    pub key_state: String,
    /// How long this identity has been known to the node (seconds), if applicable.
    pub known_since_seconds: Option<u64>,
}

/// Delegation portion of the passport.
#[derive(Debug, Serialize)]
pub struct DelegationProfile {
    /// Whether this passport can prove delegation state from a live source.
    pub source_status: String,
    /// Number of active delegations where this agent is the delegator.
    pub delegations_granted: Option<u64>,
    /// Number of active delegations where this agent is the delegate.
    pub delegations_received: Option<u64>,
    /// Permission scope summary (list of permission types held).
    pub active_permissions: Option<Vec<String>>,
}

/// Consent portion of the passport.
#[derive(Debug, Serialize)]
pub struct ConsentProfile {
    /// Whether this passport can prove consent state from a live source.
    pub source_status: String,
    /// Number of active bailments where this agent is bailor.
    pub bailments_as_bailor: Option<u64>,
    /// Number of active bailments where this agent is bailee.
    pub bailments_as_bailee: Option<u64>,
    /// Whether default-deny consent posture is enforced.
    pub default_deny_enforced: bool,
}

/// Trust standing portion of the passport.
#[derive(Debug, Serialize)]
pub struct StandingProfile {
    /// Current standing: "active", "suspended", "revoked", "quarantined", "unknown".
    pub status: String,
    /// Whether this DID has been revoked.
    pub revoked: bool,
    /// Whether this agent is under active sanctions.
    pub sanctioned: bool,
    /// Whether this agent is under a Sybil challenge hold.
    pub sybil_challenge_hold: bool,
    /// Risk level if attested: "minimal", "low", "medium", "high", "critical", or "unassessed".
    pub risk_level: String,
}

/// 0dentity sovereign identity score profile.
///
/// All scores are in **basis points** (0–10_000 = 0%–100.00%).
#[derive(Debug, Serialize)]
pub struct ZerodentityProfile {
    /// Composite score: unweighted mean of all 8 polar axes (basis points).
    pub composite_bp: u32,
    /// Per-axis polar scores (each in basis points).
    pub axes: ZerodentityAxes,
    /// Number of verified claims contributing to this score.
    pub claim_count: u32,
    /// Shape symmetry index (0–10_000 bp; 10_000 = perfect octagon).
    pub symmetry_bp: u32,
    /// When this score was last computed (epoch ms).
    pub computed_ms: u64,
}

/// Per-axis 0dentity polar graph scores (basis points, 0–10_000).
#[derive(Debug, Serialize)]
pub struct ZerodentityAxes {
    pub communication: u32,
    pub credential_depth: u32,
    pub device_trust: u32,
    pub behavioral_signature: u32,
    pub network_reputation: u32,
    pub temporal_stability: u32,
    pub cryptographic_strength: u32,
    pub constitutional_standing: u32,
}

/// Delegation list response.
#[derive(Debug, Serialize)]
pub struct DelegationListResponse {
    pub did: String,
    pub delegations_granted: u64,
    pub delegations_received: u64,
    pub active_permissions: Vec<String>,
}

/// Consent list response.
#[derive(Debug, Serialize)]
pub struct ConsentListResponse {
    pub did: String,
    pub bailments_as_bailor: u64,
    pub bailments_as_bailee: u64,
    pub default_deny_enforced: bool,
}

/// Standing response.
#[derive(Debug, Serialize)]
pub struct StandingResponse {
    pub did: String,
    pub status: String,
    pub revoked: bool,
    pub sanctioned: bool,
    pub sybil_challenge_hold: bool,
    pub risk_level: String,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/agents/:did/passport` — full agent trust profile.
async fn handle_passport(
    State(state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<AgentPassport>, (StatusCode, String)> {
    let did_obj = parse_passport_did(&did)?;
    let did_for_reactor = did.clone();
    let did_obj_for_reactor = did_obj.clone();
    let (known, is_validator) = with_reactor_state_blocking(state.clone(), move |s| {
        let is_val = s.consensus.config.validators.contains(&did_obj_for_reactor);
        // A DID is "known" if it's in the validator set or is this node's own DID.
        let known = is_val || s.node_did.to_string() == did_for_reactor;
        Ok((known, is_val))
    })
    .await?;

    // Look up 0dentity data: score and claims.
    let did_obj_for_store = did_obj;
    let (zerodentity, standing) = with_zerodentity_store_blocking(state.clone(), move |zd| {
        let score_profile = zd
            .get_score(&did_obj_for_store)
            .map(|s| ZerodentityProfile {
                composite_bp: s.composite,
                axes: ZerodentityAxes {
                    communication: s.axes.communication,
                    credential_depth: s.axes.credential_depth,
                    device_trust: s.axes.device_trust,
                    behavioral_signature: s.axes.behavioral_signature,
                    network_reputation: s.axes.network_reputation,
                    temporal_stability: s.axes.temporal_stability,
                    cryptographic_strength: s.axes.cryptographic_strength,
                    constitutional_standing: s.axes.constitutional_standing,
                },
                claim_count: s.claim_count,
                symmetry_bp: s.symmetry,
                computed_ms: s.computed_ms,
            });

        let standing = build_standing_profile(known, &did_obj_for_store, zd)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

        Ok((score_profile, standing))
    })
    .await?;

    let passport = AgentPassport {
        did: did.clone(),
        known,
        is_validator,
        identity: build_identity_profile(&did, known),
        delegations: build_delegation_profile(),
        consent: build_consent_profile(),
        standing,
        persistence_ready: crate::zerodentity::store::ZerodentityStore::persistence_ready(),
        zerodentity,
    };

    Ok(Json(passport))
}

/// `GET /api/v1/agents/:did/delegations` — active authority chains.
async fn handle_delegations(
    State(_state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<DelegationListResponse>, (StatusCode, String)> {
    parse_passport_did(&did)?;
    Err(delegation_source_unavailable())
}

/// `GET /api/v1/agents/:did/consent` — active bailments.
async fn handle_consent(
    State(_state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<ConsentListResponse>, (StatusCode, String)> {
    parse_passport_did(&did)?;
    Err(consent_source_unavailable())
}

/// `GET /api/v1/agents/:did/standing` — sanctions and revocation status.
async fn handle_standing(
    State(state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<StandingResponse>, (StatusCode, String)> {
    let did_obj = parse_passport_did(&did)?;

    let did_for_reactor = did.clone();
    let did_obj_for_reactor = did_obj.clone();
    let known = with_reactor_state_blocking(state.clone(), move |s| {
        Ok(s.consensus.config.validators.contains(&did_obj_for_reactor)
            || s.node_did.to_string() == did_for_reactor)
    })
    .await?;

    let did_obj_for_store = did_obj;
    let standing = with_zerodentity_store_blocking(state, move |zd| {
        build_standing_profile(known, &did_obj_for_store, zd)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
    })
    .await?;

    Ok(Json(StandingResponse {
        did,
        status: standing.status,
        revoked: standing.revoked,
        sanctioned: standing.sanctioned,
        sybil_challenge_hold: standing.sybil_challenge_hold,
        risk_level: standing.risk_level,
    }))
}

// ---------------------------------------------------------------------------
// Profile builders
// ---------------------------------------------------------------------------

fn build_identity_profile(did: &str, known: bool) -> IdentityProfile {
    IdentityProfile {
        did: did.to_string(),
        verification_capable: known,
        key_state: if known {
            "active".into()
        } else {
            "unknown".into()
        },
        known_since_seconds: None,
    }
}

fn build_delegation_profile() -> DelegationProfile {
    DelegationProfile {
        source_status: "unavailable".into(),
        delegations_granted: None,
        delegations_received: None,
        active_permissions: None,
    }
}

fn build_consent_profile() -> ConsentProfile {
    ConsentProfile {
        source_status: "unavailable".into(),
        bailments_as_bailor: None,
        bailments_as_bailee: None,
        default_deny_enforced: true,
    }
}

fn delegation_source_unavailable() -> PassportError {
    tracing::warn!("passport delegation source unavailable");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Delegation source unavailable".to_string(),
    )
}

fn consent_source_unavailable() -> PassportError {
    tracing::warn!("passport consent source unavailable");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Consent source unavailable".to_string(),
    )
}

fn build_standing_profile(
    known: bool,
    did: &exo_core::types::Did,
    zd_store: &crate::zerodentity::store::ZerodentityStore,
) -> Result<StandingProfile, String> {
    use crate::zerodentity::types::{ClaimStatus, ClaimType};

    let claims = zd_store.get_claims(did).map_err(|e| {
        format!(
            "Zerodentity claims unavailable for DID {}: {e}",
            did.as_str()
        )
    })?;

    // Check if all claims are revoked (identity erased).
    let all_revoked =
        !claims.is_empty() && claims.iter().all(|(_, c)| c.status == ClaimStatus::Revoked);

    // Check for any active sybil challenge.
    let sybil_hold = claims.iter().any(|(_, c)| {
        matches!(c.claim_type, ClaimType::SybilChallengeResolution { .. })
            && c.status == ClaimStatus::Challenged
    });

    // Derive risk level from composite score if available.
    let risk_level = match zd_store.get_score(did) {
        Some(s) => match s.composite {
            8000.. => "minimal",
            6000..=7999 => "low",
            4000..=5999 => "medium",
            2000..=3999 => "high",
            _ => "critical",
        },
        None => "unassessed",
    };

    // Determine overall status.
    let status = if all_revoked {
        "revoked"
    } else if sybil_hold {
        "quarantined"
    } else if known || !claims.is_empty() {
        "active"
    } else {
        "unknown"
    };

    Ok(StandingProfile {
        status: status.into(),
        revoked: all_revoked,
        sanctioned: false,
        sybil_challenge_hold: sybil_hold,
        risk_level: risk_level.into(),
    })
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

fn passport_routes(state: Arc<PassportApiState>) -> Router {
    Router::new()
        .route("/api/v1/agents/:did/passport", get(handle_passport))
        .route("/api/v1/agents/:did/delegations", get(handle_delegations))
        .route("/api/v1/agents/:did/consent", get(handle_consent))
        .route("/api/v1/agents/:did/standing", get(handle_standing))
        .with_state(state)
}

/// Build the agent passport API router.
pub fn passport_router(state: Arc<PassportApiState>, auth: crate::auth::BearerAuth) -> Router {
    passport_routes(state)
        .layer(axum::middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            crate::auth::require_bearer(auth, req, next)
        }))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            PASSPORT_CONCURRENCY_LIMIT,
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
    use exo_core::types::{Did, Signature};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        reactor::{ReactorConfig, create_reactor_state},
        store::SqliteDagStore,
        zerodentity::store::new_shared_store,
    };

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        Arc::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    #[test]
    fn passport_standing_does_not_discard_zerodentity_read_errors() {
        let source = include_str!("passport.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let standing_profile = production
            .split("fn build_standing_profile")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------\n// Router construction").next())
            .unwrap();

        assert!(!standing_profile.contains(".unwrap_or_default()"));
    }

    #[test]
    fn passport_async_handlers_use_blocking_state_access() {
        let source = include_str!("passport.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "passport handlers must isolate synchronous store access from Tokio workers"
        );

        let handlers = production
            .split("// Route handlers\n// ---------------------------------------------------------------------------")
            .nth(1)
            .and_then(|section| {
                section.split("// ---------------------------------------------------------------------------\n// Profile builders")
                    .next()
            })
            .unwrap();
        assert!(
            !handlers.contains(".lock()"),
            "passport async handlers must not lock std::sync::Mutex values directly"
        );
    }

    fn test_passport_state() -> Arc<PassportApiState> {
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();

        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            validator_public_keys: std::collections::BTreeMap::new(),
            round_timeout_ms: 5000,
        };

        let reactor_state = create_reactor_state(&config, make_sign_fn(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        Arc::new(PassportApiState {
            reactor_state,
            store,
            zerodentity_store: new_shared_store(),
        })
    }

    fn test_passport_auth() -> crate::auth::BearerAuth {
        crate::auth::BearerAuth {
            token: Arc::new(zeroize::Zeroizing::new("passport-test-token".to_string())),
        }
    }

    fn passport_test_routes(state: Arc<PassportApiState>) -> Router {
        passport_routes(state)
    }

    #[tokio::test]
    async fn passport_get_requires_bearer_token() {
        let state = test_passport_state();
        let app = passport_router(state, test_passport_auth());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn passport_get_with_bearer_token_passes() {
        let state = test_passport_state();
        let app = passport_router(state, test_passport_auth());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .header("authorization", "Bearer passport-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn standing_fails_closed_when_claim_read_fails() {
        let state = test_passport_state();
        {
            let mut zd = state.zerodentity_store.lock().unwrap();
            zd.inject_read_failure(crate::zerodentity::store::ZerodentityReadFailure::Claims);
        }

        let app = passport_test_routes(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/standing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert!(message.contains("Zerodentity claims unavailable"));
        assert!(message.contains("did:exo:v0"));
    }

    #[tokio::test]
    async fn passport_returns_profile_for_known_validator() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let passport: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(passport["did"], "did:exo:v0");
        assert_eq!(passport["known"], true);
        assert_eq!(passport["is_validator"], true);
        assert_eq!(passport["identity"]["key_state"], "active");
        assert_eq!(passport["standing"]["status"], "active");
        assert_eq!(passport["standing"]["revoked"], false);
        assert_eq!(passport["consent"]["default_deny_enforced"], true);
        assert_eq!(passport["persistence_ready"], false);
    }

    #[tokio::test]
    async fn passport_returns_unknown_for_unrecognized_did() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:stranger/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let passport: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(passport["known"], false);
        assert_eq!(passport["is_validator"], false);
        assert_eq!(passport["identity"]["key_state"], "unknown");
        assert_eq!(passport["standing"]["status"], "unknown");
    }

    #[tokio::test]
    async fn passport_invalid_did_errors_are_redacted() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        for route in [
            "/api/v1/agents/not-a-did/passport",
            "/api/v1/agents/not-a-did/delegations",
            "/api/v1/agents/not-a-did/consent",
            "/api/v1/agents/not-a-did/standing",
        ] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert_eq!(body, "Invalid DID");
        }
    }

    #[tokio::test]
    async fn delegations_endpoint_fails_closed_when_delegation_source_unavailable() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/delegations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(message, "Delegation source unavailable");
    }

    #[tokio::test]
    async fn consent_endpoint_fails_closed_when_consent_source_unavailable() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v1/consent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(message, "Consent source unavailable");
    }

    #[tokio::test]
    async fn passport_marks_unavailable_trust_sources_without_fabricated_counts() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let passport: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(passport["delegations"]["source_status"], "unavailable");
        assert!(passport["delegations"]["delegations_granted"].is_null());
        assert!(passport["delegations"]["delegations_received"].is_null());
        assert!(passport["delegations"]["active_permissions"].is_null());
        assert_eq!(passport["consent"]["source_status"], "unavailable");
        assert!(passport["consent"]["bailments_as_bailor"].is_null());
        assert!(passport["consent"]["bailments_as_bailee"].is_null());
        assert_eq!(passport["consent"]["default_deny_enforced"], true);
    }

    #[tokio::test]
    async fn delegations_endpoint_does_not_emit_synthetic_empty_counts() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/delegations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(message, "Delegation source unavailable");
    }

    #[tokio::test]
    async fn consent_endpoint_does_not_emit_synthetic_bailment_counts() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v1/consent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(message, "Consent source unavailable");
    }

    #[tokio::test]
    async fn standing_shows_active_for_validator() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v2/standing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["status"], "active");
        assert_eq!(result["revoked"], false);
        assert_eq!(result["sanctioned"], false);
        assert_eq!(result["sybil_challenge_hold"], false);
    }

    #[tokio::test]
    async fn standing_shows_unknown_for_unrecognized_did() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:nobody/standing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["status"], "unknown");
    }

    #[tokio::test]
    async fn passport_includes_all_trust_dimensions() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let passport: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify all top-level trust dimensions are present.
        assert!(passport.get("did").is_some());
        assert!(passport.get("identity").is_some());
        assert!(passport.get("delegations").is_some());
        assert!(passport.get("consent").is_some());
        assert!(passport.get("standing").is_some());
        assert!(passport.get("persistence_ready").is_some());
        // zerodentity is Optional — present as null when no score exists.
        assert!(passport.get("zerodentity").is_some());

        // Verify identity sub-fields.
        let id = &passport["identity"];
        assert!(id.get("did").is_some());
        assert!(id.get("verification_capable").is_some());
        assert!(id.get("key_state").is_some());

        // Verify standing sub-fields.
        let st = &passport["standing"];
        assert!(st.get("status").is_some());
        assert!(st.get("revoked").is_some());
        assert!(st.get("sanctioned").is_some());
        assert!(st.get("sybil_challenge_hold").is_some());
        assert!(st.get("risk_level").is_some());
    }

    #[tokio::test]
    async fn passport_returns_null_zerodentity_when_no_score() {
        let state = test_passport_state();
        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let passport: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(passport["zerodentity"].is_null());
    }

    #[tokio::test]
    async fn passport_includes_zerodentity_score_when_present() {
        use crate::zerodentity::types::{PolarAxes, ZerodentityScore};

        let state = test_passport_state();

        // Insert a score for validator v0.
        {
            let mut zd = state.zerodentity_store.lock().unwrap();
            let score = ZerodentityScore {
                subject_did: Did::new("did:exo:v0").unwrap(),
                axes: PolarAxes {
                    communication: 7500,
                    credential_depth: 6000,
                    device_trust: 8000,
                    behavioral_signature: 5500,
                    network_reputation: 4000,
                    temporal_stability: 9000,
                    cryptographic_strength: 7000,
                    constitutional_standing: 3000,
                },
                composite: 6250,
                computed_ms: 1_700_000_000_000,
                dag_state_hash: exo_core::types::Hash256::digest(b"test"),
                claim_count: 12,
                symmetry: 6800,
            };
            zd.put_score(score);
        }

        let app = passport_test_routes(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let passport: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let zd = &passport["zerodentity"];
        assert!(!zd.is_null(), "zerodentity should be present");
        assert_eq!(zd["composite_bp"], 6250);
        assert_eq!(zd["claim_count"], 12);
        assert_eq!(zd["symmetry_bp"], 6800);
        assert_eq!(zd["computed_ms"], 1_700_000_000_000_u64);

        // Verify all 8 polar axes.
        let axes = &zd["axes"];
        assert_eq!(axes["communication"], 7500);
        assert_eq!(axes["credential_depth"], 6000);
        assert_eq!(axes["device_trust"], 8000);
        assert_eq!(axes["behavioral_signature"], 5500);
        assert_eq!(axes["network_reputation"], 4000);
        assert_eq!(axes["temporal_stability"], 9000);
        assert_eq!(axes["cryptographic_strength"], 7000);
        assert_eq!(axes["constitutional_standing"], 3000);
    }

    #[tokio::test]
    async fn standing_shows_risk_level_from_score() {
        use crate::zerodentity::types::{PolarAxes, ZerodentityScore};

        let state = test_passport_state();

        // Insert a high composite score (8000+ = minimal risk).
        {
            let mut zd = state.zerodentity_store.lock().unwrap();
            zd.put_score(ZerodentityScore {
                subject_did: Did::new("did:exo:v1").unwrap(),
                axes: PolarAxes {
                    communication: 9000,
                    credential_depth: 9000,
                    device_trust: 9000,
                    behavioral_signature: 9000,
                    network_reputation: 9000,
                    temporal_stability: 9000,
                    cryptographic_strength: 9000,
                    constitutional_standing: 9000,
                },
                composite: 9000,
                computed_ms: 1_700_000_000_000,
                dag_state_hash: exo_core::types::Hash256::digest(b"test"),
                claim_count: 20,
                symmetry: 10_000,
            });
        }

        let app = passport_test_routes(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v1/standing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["risk_level"], "minimal");
    }

    #[tokio::test]
    async fn standing_shows_revoked_when_all_claims_revoked() {
        use crate::zerodentity::types::{ClaimStatus, ClaimType, IdentityClaim};

        let state = test_passport_state();

        // Insert revoked claims for a DID.
        {
            let mut zd = state.zerodentity_store.lock().unwrap();
            let did = Did::new("did:exo:v2").unwrap();
            let claim = IdentityClaim {
                claim_hash: exo_core::types::Hash256::digest(b"email"),
                subject_did: did.clone(),
                claim_type: ClaimType::Email,
                status: ClaimStatus::Revoked,
                created_ms: 1000,
                verified_ms: Some(2000),
                expires_ms: None,
                signature: exo_core::types::Signature::Empty,
                dag_node_hash: exo_core::types::Hash256::digest(b"dag"),
            };
            zd.insert_claim("claim-rev", &claim).unwrap();
        }

        let app = passport_test_routes(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v2/standing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["status"], "revoked");
        assert_eq!(result["revoked"], true);
    }
}
