//! 0dentity onboarding API routes.
//!
//! Implements: `POST /api/v1/0dentity/claims`, `POST /api/v1/0dentity/verify`,
//! `POST /api/v1/0dentity/verify/resend`.
//!
//! Spec reference: §7.1.

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use exo_core::types::{Did, Hash256, Signature};
use getrandom::getrandom;
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    otp::OtpResult,
    store::ZerodentityStore,
    types::{
        ClaimStatus, ClaimType, IdentityClaim, IdentitySession, OtpChallenge, OtpChannel,
        ZerodentityScore,
    },
};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for the onboarding router.
#[derive(Clone)]
pub struct OnboardingState {
    pub store: Arc<Mutex<ZerodentityStore>>,
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
pub struct SubmitClaimRequest {
    pub subject_did: String,
    pub claim_type: String,
    #[serde(default)]
    pub provider: Option<String>,
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

fn now_ms() -> u64 {
    exo_core::hlc::HybridClock::new().now().physical_ms
}

fn build_rng() -> StdRng {
    let mut seed = [0u8; 32];
    let _ = getrandom(&mut seed);
    StdRng::from_seed(seed)
}

fn parse_did(s: &str) -> Result<Did, (StatusCode, Json<serde_json::Value>)> {
    Did::new(s).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid DID format"})),
        )
    })
}

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

// ---------------------------------------------------------------------------
// POST /api/v1/0dentity/claims
// ---------------------------------------------------------------------------

/// `POST /api/v1/0dentity/claims` — submit a new identity claim for verification.
pub async fn submit_claim(
    State(state): State<OnboardingState>,
    Json(req): Json<SubmitClaimRequest>,
) -> Result<Json<SubmitClaimResponse>, (StatusCode, Json<serde_json::Value>)> {
    let subject_did = parse_did(&req.subject_did)?;
    let now = now_ms();

    let claim_type =
        parse_claim_type(&req.claim_type, req.provider.as_deref()).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Unrecognised claim_type"})),
            )
        })?;

    // Build claim payload hash
    let payload = format!("{}:{}", req.subject_did, req.claim_type);
    let claim_hash = Hash256::digest(payload.as_bytes());

    let claim_id = Uuid::new_v4().to_string();

    let claim = IdentityClaim {
        claim_hash,
        subject_did: subject_did.clone(),
        claim_type,
        status: ClaimStatus::Pending,
        created_ms: now,
        verified_ms: None,
        expires_ms: None,
        signature: Signature::Empty,
        dag_node_hash: Hash256::digest(claim_id.as_bytes()),
    };

    {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Store lock error"})),
            )
        })?;
        store.insert_claim(&claim_id, &claim).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Store error: {e}")})),
            )
        })?;
    }

    // Optionally create OTP challenge for email/phone claims
    let (challenge_id, challenge_ttl_ms) = if let Some(channel_str) = &req.verification_channel {
        let channel = OtpChannel::from_str(channel_str).unwrap_or(OtpChannel::Email);
        let ttl = channel.ttl_ms();

        let mut rng = build_rng();
        let (challenge, _code) =
            OtpChallenge::new(&subject_did, channel, now, &mut rng).map_err(|_| {
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
    let now = now_ms();

    let mut challenge = {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Store lock error"})),
            )
        })?;
        store
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
            })?
    };

    let result = challenge.verify(&req.code, now);

    {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Store lock error"})),
            )
        })?;
        let _ = store.update_otp_challenge(&challenge);
    }

    match result {
        OtpResult::Success => {
            let session_token = Uuid::new_v4().to_string();
            let session = IdentitySession {
                session_token: session_token.clone(),
                subject_did: challenge.subject_did.clone(),
                public_key: vec![],
                created_ms: now,
                last_active_ms: now,
                revoked: false,
            };
            {
                let mut store = state.store.lock().map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Store lock error"})),
                    )
                })?;
                let _ = store.insert_session(&session);
            }
            Ok(Json(VerifyOtpResponse {
                verified: true,
                session_token: Some(session_token),
                attempts_remaining: None,
                message: "Verification successful".into(),
            }))
        }
        OtpResult::WrongCode { attempts_remaining } => Ok(Json(VerifyOtpResponse {
            verified: false,
            session_token: None,
            attempts_remaining: Some(attempts_remaining),
            message: "Incorrect code".into(),
        })),
        OtpResult::Expired => Err((
            StatusCode::GONE,
            Json(serde_json::json!({"error": "Challenge has expired"})),
        )),
        OtpResult::Locked { .. } => Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many failed attempts — locked"})),
        )),
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
    let now = now_ms();

    let challenge = {
        let store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Store lock error"})),
            )
        })?;
        store
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
            })?
    };

    if !challenge.can_resend(now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Resend cooldown not elapsed"})),
        ));
    }

    // Create a fresh challenge
    let mut rng = build_rng();
    let (new_challenge, _code) = OtpChallenge::new(
        &challenge.subject_did,
        challenge.channel.clone(),
        now,
        &mut rng,
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "OTP generation failed"})),
        )
    })?;

    let ttl = new_challenge.ttl_ms;
    let new_id = new_challenge.challenge_id.clone();

    {
        let mut store = state.store.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Store lock error"})),
            )
        })?;
        let _ = store.insert_otp_challenge(&new_challenge);
    }

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
