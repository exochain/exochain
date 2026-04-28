//! 0dentity onboarding API routes.
//!
//! Implements: `POST /api/v1/0dentity/claims`, `POST /api/v1/0dentity/verify`,
//! `POST /api/v1/0dentity/verify/resend`.
//!
//! Spec reference: §7.1.

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use exo_core::types::{Did, Hash256};
use exo_core::{
    crypto,
    hlc::HybridClock,
    types::{PublicKey, Signature},
};
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use getrandom::getrandom;
use hmac::{Hmac, Mac};
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use super::session_auth::claim_submission_signing_payload;
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use super::types::{ClaimStatus, IdentityClaim, OtpChannel};
use super::{
    otp::OtpResult,
    session_auth::{
        bootstrap_signing_payload, did_from_public_key, public_key_from_hex,
        session_token_from_bootstrap, signature_from_hex,
    },
    store::ZerodentityStore,
    types::{ClaimType, IdentitySession, OtpChallenge, OtpState, ZerodentityScore},
};

type HmacSha256 = Hmac<Sha256>;

const OTP_RESEND_DERIVATION_DOMAIN: &[u8] = b"exo.zerodentity.otp.resend.v1";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for the onboarding router.
#[derive(Clone)]
pub struct OnboardingState {
    pub store: Arc<Mutex<ZerodentityStore>>,
    clock: Arc<Mutex<HybridClock>>,
}

impl OnboardingState {
    #[must_use]
    pub fn new(store: Arc<Mutex<ZerodentityStore>>) -> Self {
        Self::new_with_clock(store, HybridClock::new())
    }

    #[must_use]
    pub fn new_with_clock(store: Arc<Mutex<ZerodentityStore>>, clock: HybridClock) -> Self {
        Self {
            store,
            clock: Arc::new(Mutex::new(clock)),
        }
    }

    fn now_ms(&self) -> Result<u64, (StatusCode, Json<serde_json::Value>)> {
        let mut clock = self
            .clock
            .lock()
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Clock lock error"))?;
        Ok(clock.now().physical_ms)
    }
}

// ---------------------------------------------------------------------------
// Score summary helper (re-used by api.rs)
// ---------------------------------------------------------------------------

/// A compact score summary for API responses.
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct ScoreSummary {
    pub composite: u32,
    pub symmetry: u32,
    pub claim_count: u32,
}

/// Build a `ScoreSummary` from a full score.
#[must_use]
#[allow(dead_code)]
pub fn score_summary_from(score: &ZerodentityScore) -> ScoreSummary {
    ScoreSummary {
        composite: score.composite,
        symmetry: score.symmetry,
        claim_count: score.claim_count,
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(
    not(feature = "unaudited-zerodentity-first-touch-onboarding"),
    allow(dead_code)
)]
pub struct SubmitClaimRequest {
    pub subject_did: String,
    pub claim_type: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub created_ms: Option<u64>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    pub verification_channel: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitClaimResponse {
    pub claim_id: String,
    pub status: String,
    pub challenge_id: Option<String>,
    pub challenge_ttl_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyOtpRequest {
    pub challenge_id: String,
    pub code: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub bootstrap_signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyOtpResponse {
    pub verified: bool,
    pub session_token: Option<String>,
    pub attempts_remaining: Option<u32>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ResendOtpRequest {
    pub challenge_id: String,
}

#[derive(Debug, Serialize)]
pub struct ResendOtpResponse {
    pub challenge_id: String,
    pub ttl_ms: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
const FIRST_TOUCH_ONBOARDING_FEATURE: &str = "unaudited-zerodentity-first-touch-onboarding";
#[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
const FIRST_TOUCH_ONBOARDING_INITIATIVE: &str = "fix-onyx-4-r1-onboarding-auth.md";

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
fn build_rng() -> StdRng {
    let mut seed = [0u8; 32];
    let _ = getrandom(&mut seed);
    StdRng::from_seed(seed)
}

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
fn parse_did(s: &str) -> Result<Did, (StatusCode, Json<serde_json::Value>)> {
    Did::new(s).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid DID format"})),
        )
    })
}

fn json_error(
    status: StatusCode,
    error: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": error.into() })))
}

fn lock_store(
    state: &OnboardingState,
) -> Result<std::sync::MutexGuard<'_, ZerodentityStore>, (StatusCode, Json<serde_json::Value>)> {
    state
        .store
        .lock()
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Store lock error"))
}

fn derive_resend_secret(
    challenge: &OtpChallenge,
    now_ms: u64,
) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    let mut mac = HmacSha256::new_from_slice(&challenge.hmac_secret).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "OTP resend secret derivation failed",
        )
    })?;
    mac.update(OTP_RESEND_DERIVATION_DOMAIN);
    mac.update(challenge.challenge_id.as_bytes());
    mac.update(challenge.subject_did.as_str().as_bytes());
    mac.update(match challenge.channel {
        super::types::OtpChannel::Email => b"email",
        super::types::OtpChannel::Sms => b"sms",
    });
    mac.update(&now_ms.to_le_bytes());

    let bytes = mac.finalize().into_bytes();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

struct VerifiedBootstrap {
    public_key: PublicKey,
    signature: Signature,
}

fn verify_bootstrap_signature(
    req: &VerifyOtpRequest,
    challenge: &OtpChallenge,
) -> Result<VerifiedBootstrap, (StatusCode, Json<serde_json::Value>)> {
    let public_key_hex = req
        .public_key
        .as_deref()
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "public_key is required"))?;
    let signature_hex = req
        .bootstrap_signature
        .as_deref()
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "bootstrap_signature is required"))?;

    let public_key =
        public_key_from_hex(public_key_hex).map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;
    let derived_did = did_from_public_key(&public_key)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if derived_did != challenge.subject_did {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "public_key does not derive the challenged subject_did",
        ));
    }
    let signature =
        signature_from_hex(signature_hex).map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;
    if signature.is_empty() {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "bootstrap_signature must not be empty",
        ));
    }

    let payload =
        bootstrap_signing_payload(&challenge.challenge_id, &challenge.subject_did, &public_key)
            .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if !crypto::verify(&payload, &signature, &public_key) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "bootstrap_signature verification failed",
        ));
    }

    Ok(VerifiedBootstrap {
        public_key,
        signature,
    })
}

#[cfg_attr(
    not(feature = "unaudited-zerodentity-first-touch-onboarding"),
    allow(dead_code)
)]
fn parse_claim_type(ct: &str, provider: Option<&str>) -> Option<ClaimType> {
    match ct {
        "Email" => Some(ClaimType::Email),
        "Phone" => Some(ClaimType::Phone),
        "DisplayName" => Some(ClaimType::DisplayName),
        "GovernmentId" => Some(ClaimType::GovernmentId),
        "BiometricLiveness" => Some(ClaimType::BiometricLiveness),
        "EntropyAttestation" => Some(ClaimType::EntropyAttestation),
        "ProfessionalCredential" => Some(ClaimType::ProfessionalCredential {
            provider: provider.unwrap_or("").to_owned(),
        }),
        _ => None,
    }
}

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
fn parse_otp_channel(channel: &str) -> Result<OtpChannel, (StatusCode, Json<serde_json::Value>)> {
    OtpChannel::from_str(channel)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "Invalid OTP channel"))
}

#[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
fn first_touch_onboarding_refusal() -> (StatusCode, Json<serde_json::Value>) {
    tracing::warn!(
        "refusing POST /api/v1/0dentity/claims: first-touch onboarding \
         is gated. See fix-onyx-4-r1-onboarding-auth initiative. To opt \
         in for a dev cluster, build with \
         --features exo-node/unaudited-zerodentity-first-touch-onboarding."
    );
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "zerodentity_first_touch_onboarding_disabled",
            "message": "First-touch 0dentity claim creation is disabled by default. \
                        The approved onboarding proof-of-possession design must land \
                        before this path is exposed. See \
                        Initiatives/fix-onyx-4-r1-onboarding-auth.md.",
            "feature_flag": FIRST_TOUCH_ONBOARDING_FEATURE,
            "initiative": FIRST_TOUCH_ONBOARDING_INITIATIVE,
            "refusal_source": "exo-node/zerodentity/onboarding.rs::submit_claim",
        })),
    )
}

// ---------------------------------------------------------------------------
// POST /api/v1/0dentity/claims
// ---------------------------------------------------------------------------

/// `POST /api/v1/0dentity/claims` — submit a new identity claim for verification.
#[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
pub async fn submit_claim(
    State(state): State<OnboardingState>,
    Json(req): Json<SubmitClaimRequest>,
) -> Result<Json<SubmitClaimResponse>, (StatusCode, Json<serde_json::Value>)> {
    let _ = (state, req);
    Err(first_touch_onboarding_refusal())
}

/// `POST /api/v1/0dentity/claims` — submit a new identity claim for verification.
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
pub async fn submit_claim(
    State(state): State<OnboardingState>,
    Json(req): Json<SubmitClaimRequest>,
) -> Result<Json<SubmitClaimResponse>, (StatusCode, Json<serde_json::Value>)> {
    let subject_did = parse_did(&req.subject_did)?;

    let claim_type =
        parse_claim_type(&req.claim_type, req.provider.as_deref()).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Unrecognised claim_type"})),
            )
        })?;
    let created_ms = req
        .created_ms
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "created_ms is required"))?;
    if created_ms == 0 {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "created_ms must be non-zero",
        ));
    }

    let public_key_hex = req
        .public_key
        .as_deref()
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "public_key is required"))?;
    let public_key =
        public_key_from_hex(public_key_hex).map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;
    let derived_did = did_from_public_key(&public_key)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if derived_did != subject_did {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "subject_did must equal did:exo:<bs58(blake3(public_key))>",
        ));
    }

    let signature_hex = req
        .signature
        .as_deref()
        .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "signature is required"))?;
    let signature =
        signature_from_hex(signature_hex).map_err(|e| json_error(StatusCode::BAD_REQUEST, e))?;
    if signature.is_empty() {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "signature must not be empty",
        ));
    }

    let payload = claim_submission_signing_payload(
        &subject_did,
        &req.claim_type,
        req.provider.as_deref(),
        req.verification_channel.as_deref(),
        created_ms,
        &public_key,
    )
    .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if !crypto::verify(&payload, &signature, &public_key) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "signature verification failed",
        ));
    }

    let claim_hash = Hash256::digest(&payload);
    let mut claim_id_input = payload.clone();
    claim_id_input.extend_from_slice(&signature.to_bytes());
    let claim_id = hex::encode(Hash256::digest(&claim_id_input).as_bytes());

    let claim = IdentityClaim {
        claim_hash,
        subject_did: subject_did.clone(),
        claim_type,
        status: ClaimStatus::Pending,
        created_ms,
        verified_ms: None,
        expires_ms: None,
        signature: signature.clone(),
        dag_node_hash: Hash256::digest(claim_id.as_bytes()),
    };

    {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Store lock error"})),
            )
        })?;
        if store
            .get_claims(&subject_did)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Store error: {e}")})),
                )
            })?
            .iter()
            .any(|(existing_id, _)| existing_id == &claim_id)
        {
            return Err(json_error(
                StatusCode::CONFLICT,
                "claim submission has already been accepted",
            ));
        }
        store.insert_claim(&claim_id, &claim).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?;
    }

    // Optionally create OTP challenge for email/phone claims
    let (challenge_id, challenge_ttl_ms) = if let Some(channel_str) = &req.verification_channel {
        let channel = parse_otp_channel(channel_str)?;
        let ttl = channel.ttl_ms();

        let mut rng = build_rng();
        let (challenge, _code) = OtpChallenge::new(&subject_did, channel, created_ms, &mut rng)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "OTP generation failed"})),
                )
            })?;

        let cid = challenge.challenge_id.clone();
        {
            let mut store = state.store.lock().map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Store lock error"})),
                )
            })?;
            let _ = store.insert_otp_challenge(&challenge);
        }
        (Some(cid), Some(ttl))
    } else {
        (None, None)
    };

    Ok(Json(SubmitClaimResponse {
        claim_id,
        status: "Pending".into(),
        challenge_id,
        challenge_ttl_ms,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/v1/0dentity/verify
// ---------------------------------------------------------------------------

/// `POST /api/v1/0dentity/verify` — verify an OTP code against a challenge.
pub async fn verify_otp(
    State(state): State<OnboardingState>,
    Json(req): Json<VerifyOtpRequest>,
) -> Result<Json<VerifyOtpResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = state.now_ms()?;
    let mut store = lock_store(&state)?;
    let mut challenge = store
        .get_otp_challenge(&req.challenge_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Challenge not found"})),
            )
        })?;

    let result = challenge.verify(&req.code, now);

    match result {
        OtpResult::Success => {
            let bootstrap = verify_bootstrap_signature(&req, &challenge)?;
            let session_token = session_token_from_bootstrap(
                &challenge.challenge_id,
                &challenge.subject_did,
                &bootstrap.public_key,
                &bootstrap.signature,
                &challenge.hmac_secret,
            )
            .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let session = IdentitySession {
                session_token: session_token.clone(),
                subject_did: challenge.subject_did.clone(),
                public_key: bootstrap.public_key.as_bytes().to_vec(),
                created_ms: now,
                last_active_ms: now,
                revoked: false,
            };
            store.update_otp_challenge(&challenge).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Store error: {e}")})),
                )
            })?;
            store.insert_session(&session).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Store error: {e}")})),
                )
            })?;
            Ok(Json(VerifyOtpResponse {
                verified: true,
                session_token: Some(session_token),
                attempts_remaining: None,
                message: "Verification successful".into(),
            }))
        }
        OtpResult::AlreadyVerified => Err(json_error(
            StatusCode::CONFLICT,
            "Challenge has already been verified",
        )),
        OtpResult::WrongCode { attempts_remaining } => {
            store.update_otp_challenge(&challenge).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Store error: {e}")})),
                )
            })?;
            Ok(Json(VerifyOtpResponse {
                verified: false,
                session_token: None,
                attempts_remaining: Some(attempts_remaining),
                message: "Incorrect code".into(),
            }))
        }
        OtpResult::Expired => {
            store.update_otp_challenge(&challenge).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Store error: {e}")})),
                )
            })?;
            Err(json_error(StatusCode::GONE, "Challenge has expired"))
        }
        OtpResult::Locked { .. } => {
            store.update_otp_challenge(&challenge).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Store error: {e}")})),
                )
            })?;
            Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many failed attempts — locked",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/0dentity/verify/resend
// ---------------------------------------------------------------------------

/// `POST /api/v1/0dentity/verify/resend` — resend an OTP code for an existing challenge.
pub async fn resend_otp(
    State(state): State<OnboardingState>,
    Json(req): Json<ResendOtpRequest>,
) -> Result<Json<ResendOtpResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = state.now_ms()?;
    let mut store = lock_store(&state)?;
    let mut challenge = store
        .get_otp_challenge(&req.challenge_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Challenge not found"})),
            )
        })?;

    if !challenge.can_resend(now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Resend cooldown not elapsed"})),
        ));
    }

    let resend_secret = derive_resend_secret(&challenge, now)?;
    let (new_challenge, _code) = OtpChallenge::from_secret(
        &challenge.subject_did,
        challenge.channel.clone(),
        now,
        resend_secret,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "OTP generation failed"})),
        )
    })?;

    let ttl = new_challenge.ttl_ms;
    let new_id = new_challenge.challenge_id.clone();
    challenge.state = OtpState::Expired;
    store.update_otp_challenge(&challenge).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Store error: {e}")})),
        )
    })?;
    store.insert_otp_challenge(&new_challenge).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Store error: {e}")})),
        )
    })?;

    Ok(Json(ResendOtpResponse {
        challenge_id: new_id,
        ttl_ms: ttl,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the onboarding Axum router.
pub fn onboarding_router(state: OnboardingState) -> Router {
    Router::new()
        .route("/api/v1/0dentity/claims", post(submit_claim))
        .route("/api/v1/0dentity/verify", post(verify_otp))
        .route("/api/v1/0dentity/verify/resend", post(resend_otp))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use exo_core::types::{Did, Hash256};

    use super::*;
    use crate::zerodentity::types::{ClaimType, PolarAxes, ZerodentityScore};

    #[test]
    fn parse_claim_type_biometric_liveness() {
        assert_eq!(
            parse_claim_type("BiometricLiveness", None),
            Some(ClaimType::BiometricLiveness)
        );
    }

    #[test]
    #[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
    fn default_submit_claim_handler_compiles_out_legacy_claim_creation() {
        let source = include_str!("onboarding.rs");
        let default_handler = source
            .split(
                "#[cfg(not(feature = \"unaudited-zerodentity-first-touch-onboarding\"))]\n\
                 pub async fn submit_claim",
            )
            .nth(1)
            .and_then(|section| {
                section
                    .split("#[cfg(feature = \"unaudited-zerodentity-first-touch-onboarding\")]")
                    .next()
            })
            .expect("default submit_claim handler must have an explicit cfg boundary");

        assert!(default_handler.contains("first_touch_onboarding_refusal"));
        assert!(!default_handler.contains("now_ms()"));
        assert!(!default_handler.contains("Uuid::new_v4()"));
        assert!(!default_handler.contains("Signature::Empty"));
        assert!(!default_handler.contains("insert_claim"));
    }

    #[test]
    fn verify_bootstrap_signature_binds_public_key_to_challenged_did() {
        let source = include_str!("onboarding.rs");
        let verifier = source
            .split("fn verify_bootstrap_signature")
            .nth(1)
            .and_then(|section| section.split("Ok(public_key)").next())
            .expect("verify_bootstrap_signature must have an explicit function body");

        assert!(verifier.contains("did_from_public_key(&public_key)"));
        assert!(verifier.contains("derived_did != challenge.subject_did"));
    }

    #[test]
    fn verify_otp_does_not_mint_uuid_session_tokens() {
        let source = include_str!("onboarding.rs");
        let verifier = source
            .split("pub async fn verify_otp")
            .nth(1)
            .and_then(|section| {
                section
                    .split("// POST /api/v1/0dentity/verify/resend")
                    .next()
            })
            .expect("verify_otp must have an explicit function body");

        assert!(
            !verifier.contains("Uuid::new_v4()"),
            "session tokens must be derived from verified bootstrap material, not UUID v4"
        );
    }

    #[test]
    fn verify_otp_consumes_challenge_and_session_in_one_store_lock() {
        let source = include_str!("onboarding.rs");
        let verifier = source
            .split("pub async fn verify_otp")
            .nth(1)
            .and_then(|section| {
                section
                    .split("// POST /api/v1/0dentity/verify/resend")
                    .next()
            })
            .expect("verify_otp must have an explicit function body");
        let lock_count = verifier.matches("lock_store(&state)").count();

        assert_eq!(
            lock_count, 1,
            "OTP verification, challenge consumption, and session insertion must be one critical section"
        );
    }

    #[test]
    fn resend_otp_does_not_generate_runtime_rng_or_global_clock() {
        let source = include_str!("onboarding.rs");
        let resend = source
            .split("pub async fn resend_otp")
            .nth(1)
            .and_then(|section| section.split("// Router").next())
            .expect("resend_otp must have an explicit function body");

        assert!(
            !resend.contains("build_rng()"),
            "resend must derive replacement challenge material from existing challenge evidence"
        );
        assert!(
            !resend.contains("OtpChallenge::new("),
            "resend must not depend on runtime RNG challenge construction"
        );
        assert!(
            !resend.contains("let now = now_ms()"),
            "resend must read time through OnboardingState's injected HLC"
        );
    }

    #[test]
    fn parse_claim_type_entropy_attestation() {
        assert_eq!(
            parse_claim_type("EntropyAttestation", None),
            Some(ClaimType::EntropyAttestation)
        );
    }

    #[test]
    fn parse_claim_type_professional_credential_with_provider() {
        assert_eq!(
            parse_claim_type("ProfessionalCredential", Some("Acme")),
            Some(ClaimType::ProfessionalCredential {
                provider: "Acme".to_owned()
            })
        );
    }

    #[test]
    fn parse_claim_type_professional_credential_no_provider() {
        assert_eq!(
            parse_claim_type("ProfessionalCredential", None),
            Some(ClaimType::ProfessionalCredential {
                provider: "".to_owned()
            })
        );
    }

    #[test]
    fn parse_claim_type_unknown_returns_none() {
        assert_eq!(parse_claim_type("Foobar", None), None);
    }

    #[test]
    fn score_summary_from_extracts_fields() {
        let did = Did::new("did:exo:test").unwrap();
        let score = ZerodentityScore {
            subject_did: did,
            axes: PolarAxes {
                communication: 100,
                credential_depth: 200,
                device_trust: 300,
                behavioral_signature: 400,
                network_reputation: 500,
                temporal_stability: 600,
                cryptographic_strength: 700,
                constitutional_standing: 800,
            },
            composite: 5000,
            computed_ms: 1_000_000,
            dag_state_hash: Hash256::digest(b"test"),
            claim_count: 3,
            symmetry: 9000,
        };
        let summary = score_summary_from(&score);
        assert_eq!(summary.composite, 5000);
        assert_eq!(summary.symmetry, 9000);
        assert_eq!(summary.claim_count, 3);
    }
}
