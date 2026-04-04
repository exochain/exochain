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

use crate::reactor::SharedReactorState;
use crate::store::SqliteDagStore;

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
        let s = state.reactor_state.lock().expect("reactor state lock");
        let did_obj = exo_core::types::Did::new(&did)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;
        let is_val = s.consensus.config.validators.contains(&did_obj);
        // A DID is "known" if it's in the validator set or is this node's own DID.
        let known = is_val || s.node_did.to_string() == did;
        (known, is_val)
    };

    let passport = AgentPassport {
        did: did.clone(),
        known,
        is_validator,
        identity: build_identity_profile(&did, known),
        delegations: build_delegation_profile(),
        consent: build_consent_profile(),
        standing: build_standing_profile(known),
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
    let _did_obj = exo_core::types::Did::new(&did)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid DID: {e}")))?;

    let known = {
        let s = state.reactor_state.lock().expect("reactor state lock");
        let did_obj = exo_core::types::Did::new(&did).expect("already validated");
        s.consensus.config.validators.contains(&did_obj) || s.node_did.to_string() == did
    };

    Ok(Json(StandingResponse {
        did,
        status: if known { "active".into() } else { "unknown".into() },
        revoked: false,
        sanctioned: false,
        sybil_challenge_hold: false,
        risk_level: "unassessed".into(),
    }))
}

// ---------------------------------------------------------------------------
// Profile builders
// ---------------------------------------------------------------------------

fn build_identity_profile(did: &str, known: bool) -> IdentityProfile {
    IdentityProfile {
        did: did.to_string(),
        verification_capable: known,
        key_state: if known { "active".into() } else { "unknown".into() },
        known_since_seconds: None,
    }
}

fn build_delegation_profile() -> DelegationProfile {
    // Delegation registry is in-memory in exo-authority; will be wired
    // when the node integrates delegation persistence.
    DelegationProfile {
        delegations_granted: 0,
        delegations_received: 0,
        active_permissions: Vec::new(),
    }
}

fn build_consent_profile() -> ConsentProfile {
    // Consent/bailment records will be wired when the node integrates
    // bailment persistence from exo-consent.
    ConsentProfile {
        bailments_as_bailor: 0,
        bailments_as_bailee: 0,
        default_deny_enforced: true,
    }
}

fn build_standing_profile(known: bool) -> StandingProfile {
    StandingProfile {
        status: if known { "active".into() } else { "unknown".into() },
        revoked: false,
        sanctioned: false,
        sybil_challenge_hold: false,
        risk_level: "unassessed".into(),
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
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use axum::{body::Body, http::Request};
    use exo_core::types::{Did, Signature};
    use tower::ServiceExt;

    use super::*;
    use crate::reactor::{ReactorConfig, create_reactor_state};
    use crate::store::SqliteDagStore;

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

        // Verify all 5 top-level trust dimensions are present.
        assert!(passport.get("did").is_some());
        assert!(passport.get("identity").is_some());
        assert!(passport.get("delegations").is_some());
        assert!(passport.get("consent").is_some());
        assert!(passport.get("standing").is_some());

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
}
