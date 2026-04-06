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
    reactor::SharedReactorState, store::SqliteDagStore, zerodentity::store::SharedZerodentityStore,
};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for passport API handlers.
#[derive(Clone)]
pub struct PassportApiState {
    pub reactor_state: SharedReactorState,
    /// Store for future delegation/consent/attestation persistence queries.
    #[allow(dead_code)]
    pub store: Arc<Mutex<SqliteDagStore>>,
    /// 0dentity store for sovereign identity score lookup.
    pub zerodentity_store: SharedZerodentityStore,
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
    /// Number of active delegations where this agent is the delegator.
    pub delegations_granted: u64,
    /// Number of active delegations where this agent is the delegate.
    pub delegations_received: u64,
    /// Permission scope summary (list of permission types held).
    pub active_permissions: Vec<String>,
}

/// Consent portion of the passport.
#[derive(Debug, Serialize)]
pub struct ConsentProfile {
    /// Number of active bailments where this agent is bailor.
    pub bailments_as_bailor: u64,
    /// Number of active bailments where this agent is bailee.
    pub bailments_as_bailee: u64,
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
    let (known, is_validator) = {
        let s = state.reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        let did_obj = exo_core::types::Did::new(&did)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;
        let is_val = s.consensus.config.validators.contains(&did_obj);
        // A DID is "known" if it's in the validator set or is this node's own DID.
        let known = is_val || s.node_did.to_string() == did;
        (known, is_val)
    };

    // Look up 0dentity data: score and claims.
    let did_obj = exo_core::types::Did::new(&did)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;
    let (zerodentity, standing) = {
        let zd = state.zerodentity_store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Zerodentity store unavailable".to_string(),
            )
        })?;

        let score_profile = zd.get_score(&did_obj).map(|s| ZerodentityProfile {
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

        let standing = build_standing_profile(known, &did_obj, &zd);

        (score_profile, standing)
    };

    let passport = AgentPassport {
        did: did.clone(),
        known,
        is_validator,
        identity: build_identity_profile(&did, known),
        delegations: build_delegation_profile(),
        consent: build_consent_profile(),
        standing,
        zerodentity,
    };

    Ok(Json(passport))
}

/// `GET /api/v1/agents/:did/delegations` — active authority chains.
async fn handle_delegations(
    State(state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<DelegationListResponse>, (StatusCode, String)> {
    // Validate DID format.
    let _did_obj = exo_core::types::Did::new(&did)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;

    let _ = &state; // used for future delegation registry queries

    Ok(Json(DelegationListResponse {
        did,
        delegations_granted: 0,
        delegations_received: 0,
        active_permissions: Vec::new(),
    }))
}

/// `GET /api/v1/agents/:did/consent` — active bailments.
async fn handle_consent(
    State(state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<ConsentListResponse>, (StatusCode, String)> {
    let _did_obj = exo_core::types::Did::new(&did)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;

    let _ = &state;

    Ok(Json(ConsentListResponse {
        did,
        bailments_as_bailor: 0,
        bailments_as_bailee: 0,
        default_deny_enforced: true,
    }))
}

/// `GET /api/v1/agents/:did/standing` — sanctions and revocation status.
async fn handle_standing(
    State(state): State<Arc<PassportApiState>>,
    Path(did): Path<String>,
) -> Result<Json<StandingResponse>, (StatusCode, String)> {
    let did_obj = exo_core::types::Did::new(&did)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;

    let known = {
        let s = state.reactor_state.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Reactor state unavailable".to_string(),
            )
        })?;
        s.consensus.config.validators.contains(&did_obj) || s.node_did.to_string() == did
    };

    let zd = state.zerodentity_store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Zerodentity store unavailable".to_string(),
        )
    })?;
    let standing = build_standing_profile(known, &did_obj, &zd);

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
    // The DelegationRegistry in exo-authority and DelegatedAuthority in
    // decision-forum track live delegation chains. These are in-memory
    // per-crate structures; wiring them here requires a shared delegation
    // persistence layer (planned for the Phase 4 state-sync milestone).
    DelegationProfile {
        delegations_granted: 0,
        delegations_received: 0,
        active_permissions: Vec::new(),
    }
}

fn build_consent_profile() -> ConsentProfile {
    // Bailment lifecycle (propose → accept → terminate) is implemented in
    // exo-consent and gatekeeper.  Wiring requires a shared consent store
    // that persists bailment state across the node (planned for Phase 4).
    // Default-deny is always enforced by the constitutional kernel.
    ConsentProfile {
        bailments_as_bailor: 0,
        bailments_as_bailee: 0,
        default_deny_enforced: true,
    }
}

fn build_standing_profile(
    known: bool,
    did: &exo_core::types::Did,
    zd_store: &crate::zerodentity::store::ZerodentityStore,
) -> StandingProfile {
    use crate::zerodentity::types::{ClaimStatus, ClaimType};

    let claims = zd_store.get_claims(did).unwrap_or_default();

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

    StandingProfile {
        status: status.into(),
        revoked: all_revoked,
        sanctioned: false,
        sybil_challenge_hold: sybil_hold,
        risk_level: risk_level.into(),
    }
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the agent passport API router.
pub fn passport_router(state: Arc<PassportApiState>) -> Router {
    Router::new()
        .route("/api/v1/agents/:did/passport", get(handle_passport))
        .route("/api/v1/agents/:did/delegations", get(handle_delegations))
        .route("/api/v1/agents/:did/consent", get(handle_consent))
        .route("/api/v1/agents/:did/standing", get(handle_standing))
        .with_state(state)
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

    fn test_passport_state() -> Arc<PassportApiState> {
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();

        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
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

    #[tokio::test]
    async fn passport_returns_profile_for_known_validator() {
        let state = test_passport_state();
        let app = passport_router(state);

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
    }

    #[tokio::test]
    async fn passport_returns_unknown_for_unrecognized_did() {
        let state = test_passport_state();
        let app = passport_router(state);

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
    async fn passport_rejects_invalid_did_format() {
        let state = test_passport_state();
        let app = passport_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/not-a-did/passport")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn delegations_endpoint_returns_empty_for_known_did() {
        let state = test_passport_state();
        let app = passport_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v0/delegations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["did"], "did:exo:v0");
        assert_eq!(result["delegations_granted"], 0);
    }

    #[tokio::test]
    async fn consent_endpoint_returns_default_deny() {
        let state = test_passport_state();
        let app = passport_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents/did:exo:v1/consent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["default_deny_enforced"], true);
    }

    #[tokio::test]
    async fn standing_shows_active_for_validator() {
        let state = test_passport_state();
        let app = passport_router(state);

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
        let app = passport_router(state);

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
        let app = passport_router(state);

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

        // Verify all 6 top-level trust dimensions are present.
        assert!(passport.get("did").is_some());
        assert!(passport.get("identity").is_some());
        assert!(passport.get("delegations").is_some());
        assert!(passport.get("consent").is_some());
        assert!(passport.get("standing").is_some());
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
        let app = passport_router(state);

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

        let app = passport_router(state);

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

        let app = passport_router(state);
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

        let app = passport_router(state);
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
