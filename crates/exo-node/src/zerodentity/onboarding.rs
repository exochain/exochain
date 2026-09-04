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
#[cfg(any(
    feature = "unaudited-zerodentity-first-touch-onboarding",
    feature = "unaudited-zerodentity-device-behavioral-axes"
))]
use exo_core::types::Did;
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use exo_core::types::Hash256;
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
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
use super::session_auth::device_behavioral_submission_signing_payload;
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
use super::types::{ClaimStatus, IdentityClaim, OtpChannel};
use super::{
    otp::OtpResult,
    session_auth::{
        bootstrap_signing_payload, did_from_public_key, public_key_from_hex,
        session_token_from_bootstrap, signature_from_hex,
    },
    session_clock::{SessionClock, SessionClockError, TRUSTED_SESSION_CLOCK_UNAVAILABLE},
    store::ZerodentityStore,
    types::{ClaimType, IdentitySession, OtpChallenge, OtpState, ZerodentityScore},
};

type HmacSha256 = Hmac<Sha256>;

const OTP_RESEND_DERIVATION_DOMAIN: &[u8] = b"exo.zerodentity.otp.resend.v1";
type OnboardingError = (StatusCode, Json<serde_json::Value>);
type OnboardingResult<T> = Result<T, OnboardingError>;

/// Maximum age, in milliseconds, that a signed first-touch claim's
/// `created_ms` may lag behind the trusted 0dentity session clock before it
/// is rejected as stale. Mirrors `ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS` in
/// `store.rs`, but bounds the past side of the window rather than the future
/// side: proof-of-possession signature/replay checks bind the payload bytes,
/// not the freshness of the claimed time, so an arbitrarily old — but
/// otherwise valid — signed payload would be accepted forever without this
/// bound.
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
const ZERODENTITY_CLAIM_MAX_PAST_SKEW_MS: u64 = 21 * 24 * 60 * 60 * 1_000;
/// Maximum distance, in milliseconds, that a signed first-touch claim's
/// `created_ms` may sit ahead of the trusted 0dentity session clock before it
/// is rejected as beyond the trusted clock's tolerance. Same rationale as
/// [`ZERODENTITY_CLAIM_MAX_PAST_SKEW_MS`], mirrored to the future side.
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
const ZERODENTITY_CLAIM_MAX_FUTURE_SKEW_MS: u64 = 21 * 24 * 60 * 60 * 1_000;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared state for the onboarding router.
#[derive(Clone)]
pub struct OnboardingState {
    pub store: Arc<Mutex<ZerodentityStore>>,
    session_clock: SessionClock,
}

impl OnboardingState {
    #[must_use]
    pub fn new(store: Arc<Mutex<ZerodentityStore>>) -> Self {
        Self {
            store,
            session_clock: SessionClock::unavailable(),
        }
    }

    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new_with_clock(store: Arc<Mutex<ZerodentityStore>>, clock: HybridClock) -> Self {
        Self {
            store,
            session_clock: SessionClock::trusted(clock),
        }
    }

    fn now_ms(&self) -> Result<u64, (StatusCode, Json<serde_json::Value>)> {
        self.session_clock.now_ms().map_err(|err| match err {
            SessionClockError::Unavailable => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                TRUSTED_SESSION_CLOCK_UNAVAILABLE,
            ),
            SessionClockError::LockPoisoned => {
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "Clock lock error")
            }
            SessionClockError::Exhausted(err) => {
                tracing::error!(error = %err, "0dentity onboarding HLC exhausted");
                json_error(StatusCode::INTERNAL_SERVER_ERROR, "Clock exhausted")
            }
        })
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

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(
    not(any(
        feature = "unaudited-zerodentity-first-touch-onboarding",
        feature = "unaudited-zerodentity-device-behavioral-axes"
    )),
    allow(dead_code)
)]
pub struct SubmitClaimRequest {
    pub subject_did: String,
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-first-touch-onboarding"),
        allow(dead_code)
    )]
    pub claim_type: String,
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-first-touch-onboarding"),
        allow(dead_code)
    )]
    pub provider: Option<String>,
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-first-touch-onboarding"),
        allow(dead_code)
    )]
    pub created_ms: Option<u64>,
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-first-touch-onboarding"),
        allow(dead_code)
    )]
    pub public_key: Option<String>,
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-first-touch-onboarding"),
        allow(dead_code)
    )]
    pub signature: Option<String>,
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-first-touch-onboarding"),
        allow(dead_code)
    )]
    pub verification_channel: Option<String>,
    /// Spec §7.1: hex-encoded composite device fingerprint hash. Gated on
    /// `unaudited-zerodentity-device-behavioral-axes`; ignored otherwise.
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-device-behavioral-axes"),
        allow(dead_code)
    )]
    pub device_fingerprint: Option<String>,
    /// Spec §7.1: hex-encoded BLAKE3 hash of the client's behavioral summary.
    /// Gated on `unaudited-zerodentity-device-behavioral-axes`.
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-device-behavioral-axes"),
        allow(dead_code)
    )]
    pub behavioral_hash: Option<String>,
    /// Spec §7.1: per-signal hashes (`FingerprintSignal` name -> hex hash).
    /// Bounded to `FINGERPRINT_SIGNAL_COUNT` entries; gated on
    /// `unaudited-zerodentity-device-behavioral-axes`.
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-device-behavioral-axes"),
        allow(dead_code)
    )]
    pub signal_hashes: std::collections::BTreeMap<String, String>,
    /// VCG-009: caller-supplied consent receipt reference. Persistence of
    /// `device_fingerprint`/`behavioral_hash`/`signal_hashes` requires a
    /// valid, in-scope consent grant looked up from this receipt id — see
    /// `store::ZerodentityStore::check_device_behavioral_consent`.
    #[serde(default)]
    #[cfg_attr(
        not(feature = "unaudited-zerodentity-device-behavioral-axes"),
        allow(dead_code)
    )]
    pub consent_receipt_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitClaimResponse {
    pub claim_id: String,
    pub status: String,
    pub challenge_id: Option<String>,
    pub challenge_ttl_ms: Option<u64>,
}

#[derive(Deserialize)]
pub struct VerifyOtpRequest {
    pub challenge_id: String,
    pub code: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub bootstrap_signature: Option<String>,
}

impl std::fmt::Debug for VerifyOtpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifyOtpRequest")
            .field("challenge_id", &self.challenge_id)
            .field("code", &"<redacted>")
            .field("public_key", &self.public_key.as_ref().map(|_| "<present>"))
            .field(
                "bootstrap_signature",
                &self.bootstrap_signature.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Serialize)]
pub struct VerifyOtpResponse {
    pub verified: bool,
    pub session_token: Option<String>,
    pub attempts_remaining: Option<u32>,
    pub message: String,
}

impl std::fmt::Debug for VerifyOtpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifyOtpResponse")
            .field("verified", &self.verified)
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("attempts_remaining", &self.attempts_remaining)
            .field("message", &self.message)
            .finish()
    }
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
fn build_rng() -> Result<StdRng, (StatusCode, Json<serde_json::Value>)> {
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(|e| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("OTP entropy unavailable: {e}"),
        )
    })?;
    Ok(StdRng::from_seed(seed))
}

#[cfg(any(
    feature = "unaudited-zerodentity-first-touch-onboarding",
    feature = "unaudited-zerodentity-device-behavioral-axes"
))]
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

fn store_error_response(operation: &'static str, error: impl std::fmt::Display) -> OnboardingError {
    tracing::error!(
        operation,
        err = %error,
        "0dentity onboarding store operation failed"
    );
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "Store operation failed")
}

async fn now_ms_blocking(state: OnboardingState) -> OnboardingResult<u64> {
    tokio::task::spawn_blocking(move || state.now_ms())
        .await
        .map_err(|e| {
            tracing::error!(err = %e, "0dentity onboarding clock task failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "Clock task failed")
        })?
}

async fn with_store_blocking<T, F>(state: OnboardingState, operation: F) -> OnboardingResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut ZerodentityStore) -> OnboardingResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut store = state
            .store
            .lock()
            .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "Store lock error"))?;
        operation(&mut store)
    })
    .await
    .map_err(|e| {
        tracing::error!(err = %e, "0dentity onboarding store task failed");
        json_error(StatusCode::INTERNAL_SERVER_ERROR, "Store task failed")
    })?
}

fn derive_resend_secret(
    challenge: &OtpChallenge,
    now_ms: u64,
) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    let mut mac =
        HmacSha256::new_from_slice(challenge.hmac_secret.expose_secret()).map_err(|_| {
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
         --features exochain-node/unaudited-zerodentity-first-touch-onboarding."
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
// Device / behavioral sample ingestion (VCG-009)
// ---------------------------------------------------------------------------

/// Maximum number of `signal_hashes` entries accepted in a single submit.
/// Bounded to the documented `FingerprintSignal` variant count (spec §3.1):
/// a real client can never legitimately report more distinct signal kinds
/// than exist, so anything larger is rejected outright (VCG-009 bounded
/// ingestion requirement), before any per-key parsing is attempted.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
const MAX_SIGNAL_HASHES: usize = super::types::FINGERPRINT_SIGNAL_COUNT;

/// Whether a submit request is carrying the spec §7.1 device/behavioral
/// sample fields at all. A request with none of these fields set is an
/// ordinary claim submission and must fall through to the existing
/// first-touch-onboarding path unchanged.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
fn carries_device_behavioral_fields(req: &SubmitClaimRequest) -> bool {
    req.device_fingerprint.is_some()
        || req.behavioral_hash.is_some()
        || !req.signal_hashes.is_empty()
}

/// Handle a submit that carries device/behavioral sample fields: consent-gate,
/// then persist via `put_fingerprint`/`put_behavioral`, replay-safe and
/// bounded, and never touch the claim/OTP tables. Returns `None` only when
/// the caller should fall through to ordinary claim handling (i.e. the
/// request carries no device/behavioral fields at all) — every other outcome
/// (success or refusal) is returned as `Some`.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
async fn try_handle_device_behavioral_ingestion(
    state: &OnboardingState,
    req: &SubmitClaimRequest,
) -> Option<Result<Json<SubmitClaimResponse>, (StatusCode, Json<serde_json::Value>)>> {
    if !carries_device_behavioral_fields(req) {
        return None;
    }
    Some(handle_device_behavioral_ingestion(state.clone(), req.clone()).await)
}

#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
async fn handle_device_behavioral_ingestion(
    state: OnboardingState,
    req: SubmitClaimRequest,
) -> Result<Json<SubmitClaimResponse>, (StatusCode, Json<serde_json::Value>)> {
    use std::collections::BTreeMap;

    use super::types::{
        BehavioralSample, BehavioralSignalType, ClaimStatus, DeviceFingerprint, FingerprintSignal,
        IdentityClaim,
    };

    let subject_did = parse_did(&req.subject_did)?;
    let now_ms = now_ms_blocking(state.clone()).await?;

    // Bounded ingestion: reject an oversized signal_hashes map before any
    // per-key parsing (VCG-009 (d)). Checked before the consent gate so an
    // attacker cannot use an oversized payload to probe consent state.
    if req.signal_hashes.len() > MAX_SIGNAL_HASHES {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "signal_hashes must not exceed {MAX_SIGNAL_HASHES} entries \
                 (documented FingerprintSignal variant count)"
            ),
        ));
    }

    // Proof of possession: the request's public_key must derive subject_did.
    // This binds the samples to a subject who actually controls this DID,
    // independent of whichever session/consent evidence follows.
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

    // Real proof-of-possession: the signature must cryptographically verify
    // against `public_key` over the canonical, sample-bound payload — not
    // merely be present. `derived_did == subject_did` above only proves the
    // DID/public_key pairing is well-formed (both are Public per spec §7.1);
    // this is what proves the caller actually holds the matching private
    // key over exactly these sample bytes, closing the cross-account
    // (attacker's key over a victim's DID/public_key) and sample-
    // substitution (subject's own valid signature over different sample
    // bytes) attacks regardless of session/consent state.
    let signing_payload = device_behavioral_submission_signing_payload(
        &subject_did,
        req.device_fingerprint.as_deref(),
        req.behavioral_hash.as_deref(),
        &req.signal_hashes,
        &public_key,
    )
    .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if !crypto::verify(&signing_payload, &signature, &public_key) {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "signature does not verify against the canonical device/behavioral \
             sample-bound payload — proof of possession failed",
        ));
    }

    // Consent gate: require a non-empty consent_receipt_id that resolves to
    // a valid, in-scope grant. Nothing is persisted unless this passes.
    let receipt_id = req.consent_receipt_id.clone().unwrap_or_default();
    let subject_for_consent = subject_did.clone();
    let receipt_for_consent = receipt_id.clone();
    let granted = with_store_blocking(state.clone(), move |store| {
        store
            .check_device_behavioral_consent(&subject_for_consent, &receipt_for_consent, now_ms)
            .map_err(|e| store_error_response("check_device_behavioral_consent", e))
    })
    .await?;
    if !granted {
        tracing::warn!(
            subject_did = %subject_did,
            "refusing 0dentity device/behavioral sample ingestion: no valid, in-scope consent record"
        );
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "device/behavioral sample ingestion requires a valid, in-scope consent record \
             (consent_receipt_id missing, empty, or not grantable — see \
             ZerodentityStore::check_device_behavioral_consent)",
        ));
    }

    // Parse the fingerprint composite + per-signal hashes, if present.
    let parsed_fingerprint =
        req.device_fingerprint
            .as_deref()
            .map(
                |hex_hash| -> Result<DeviceFingerprint, (StatusCode, Json<serde_json::Value>)> {
                    let composite_hash = parse_hash256(hex_hash, "device_fingerprint")?;
                    let mut signal_hashes = BTreeMap::new();
                    for (name, hash_hex) in &req.signal_hashes {
                        let signal = name.parse::<FingerprintSignal>().map_err(|()| {
                    json_error(
                        StatusCode::BAD_REQUEST,
                        format!("signal_hashes key '{name}' is not a recognised FingerprintSignal"),
                    )
                })?;
                        let hash = parse_hash256(hash_hex, "signal_hashes value")?;
                        signal_hashes.insert(signal, hash);
                    }
                    Ok(DeviceFingerprint {
                        composite_hash,
                        signal_hashes,
                        captured_ms: now_ms,
                        consistency_score_bp: None,
                    })
                },
            )
            .transpose()?;

    // Parse the behavioral sample, if present. The spec §7.1 wire format
    // carries a single composite `behavioral_hash` (no signal-type
    // discriminant), so the categorisation tag used for scoring diversity
    // defaults to `KeystrokeDynamics`; this does not affect the axis
    // computation's use of the hash itself.
    let parsed_behavioral = req
        .behavioral_hash
        .as_deref()
        .map(
            |hex_hash| -> Result<BehavioralSample, (StatusCode, Json<serde_json::Value>)> {
                let sample_hash = parse_hash256(hex_hash, "behavioral_hash")?;
                Ok(BehavioralSample {
                    sample_hash,
                    signal_type: BehavioralSignalType::KeystrokeDynamics,
                    captured_ms: now_ms,
                    baseline_similarity_bp: None,
                })
            },
        )
        .transpose()?;

    // A consented sample submission also asserts the accompanying claim (the
    // spec §7.1 wire format bundles `claim_type` with the sample fields in
    // one request) so the DID is discoverable through the ordinary claims
    // store — `GET /score` and `GET /claims` key off `get_claims` non-empty,
    // and a subject with samples but no claim would be otherwise invisible.
    // The claim id is content-derived from (subject_did, claim_type,
    // public_key) — NOT from created_ms/samples — so a replay with the same
    // logical claim is idempotent (VCG-009 (c)) regardless of created_ms
    // jitter or which sample payload accompanied it.
    let claim_type = parse_claim_type(&req.claim_type, req.provider.as_deref());
    let claim_to_persist = claim_type.map(|claim_type| {
        let mut claim_id_input = subject_did.as_str().as_bytes().to_vec();
        claim_id_input.extend_from_slice(req.claim_type.as_bytes());
        claim_id_input.extend_from_slice(public_key.as_bytes());
        let claim_hash = exo_core::types::Hash256::digest(&claim_id_input);
        let claim_id = hex::encode(claim_hash.as_bytes());
        let claim = IdentityClaim {
            claim_hash,
            subject_did: subject_did.clone(),
            claim_type,
            status: ClaimStatus::Pending,
            created_ms: now_ms,
            verified_ms: None,
            expires_ms: None,
            signature,
            dag_node_hash: exo_core::types::Hash256::digest(claim_id.as_bytes()),
        };
        (claim_id, claim)
    });

    let subject_for_store = subject_did.clone();
    with_store_blocking(state.clone(), move |store| {
        // Replay-safety: dedupe by content hash. A resubmission of the exact
        // same composite/sample hash for this DID is treated as an
        // idempotent success rather than appended again.
        if let Some(fp) = parsed_fingerprint {
            let already_stored = store
                .get_fingerprints(&subject_for_store)
                .map_err(|e| store_error_response("device_behavioral_get_fingerprints", e))?
                .iter()
                .any(|existing| existing.composite_hash == fp.composite_hash);
            if !already_stored {
                store
                    .put_fingerprint(&subject_for_store, fp)
                    .map_err(|e| store_error_response("device_behavioral_put_fingerprint", e))?;
            }
        }
        if let Some(sample) = parsed_behavioral {
            let already_stored = store
                .get_behavioral_samples(&subject_for_store)
                .map_err(|e| store_error_response("device_behavioral_get_behavioral_samples", e))?
                .iter()
                .any(|existing| existing.sample_hash == sample.sample_hash);
            if !already_stored {
                store
                    .put_behavioral(&subject_for_store, sample)
                    .map_err(|e| store_error_response("device_behavioral_put_behavioral", e))?;
            }
        }
        if let Some((claim_id, claim)) = claim_to_persist {
            let already_stored = store
                .get_claims(&subject_for_store)
                .map_err(|e| store_error_response("device_behavioral_get_claims", e))?
                .iter()
                .any(|(existing_id, _)| existing_id == &claim_id);
            if !already_stored {
                store
                    .insert_claim(&claim_id, &claim)
                    .map_err(|e| store_error_response("device_behavioral_insert_claim", e))?;
            }
        }
        Ok(())
    })
    .await?;

    Ok(Json(SubmitClaimResponse {
        claim_id: String::new(),
        status: "DeviceBehavioralSamplesAccepted".into(),
        challenge_id: None,
        challenge_ttl_ms: None,
    }))
}

#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
fn parse_hash256(
    hex_str: &str,
    field: &str,
) -> Result<exo_core::types::Hash256, (StatusCode, Json<serde_json::Value>)> {
    let bytes = hex::decode(hex_str).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("{field} must be hex-encoded"),
        )
    })?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("{field} must be exactly 32 bytes"),
        )
    })?;
    Ok(exo_core::types::Hash256::from_bytes(array))
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
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    if let Some(result) = try_handle_device_behavioral_ingestion(&state, &req).await {
        return result;
    }
    let _ = (state, req);
    Err(first_touch_onboarding_refusal())
}

/// `POST /api/v1/0dentity/claims` — submit a new identity claim for verification.
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
pub async fn submit_claim(
    State(state): State<OnboardingState>,
    Json(req): Json<SubmitClaimRequest>,
) -> Result<Json<SubmitClaimResponse>, (StatusCode, Json<serde_json::Value>)> {
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    if let Some(result) = try_handle_device_behavioral_ingestion(&state, &req).await {
        return result;
    }
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

    let trusted_now_ms = now_ms_blocking(state.clone()).await?;
    if created_ms < trusted_now_ms.saturating_sub(ZERODENTITY_CLAIM_MAX_PAST_SKEW_MS) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "created_ms is outside the trusted freshness window: too far in the past",
        ));
    }
    if created_ms > trusted_now_ms.saturating_add(ZERODENTITY_CLAIM_MAX_FUTURE_SKEW_MS) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "created_ms is outside the trusted freshness window: too far in the future",
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
        let claim_id_for_store = claim_id.clone();
        let claim_for_store = claim.clone();
        let subject_did_for_store = subject_did.clone();
        with_store_blocking(state.clone(), move |store| {
            if store
                .get_claims(&subject_did_for_store)
                .map_err(|e| store_error_response("submit_claim_get_claims", e))?
                .iter()
                .any(|(existing_id, _)| existing_id == &claim_id_for_store)
            {
                return Err(json_error(
                    StatusCode::CONFLICT,
                    "claim submission has already been accepted",
                ));
            }
            store
                .insert_claim(&claim_id_for_store, &claim_for_store)
                .map_err(|e| store_error_response("submit_claim_insert_claim", e))
        })
        .await?;
    }

    // Optionally create OTP challenge for email/phone claims
    let (challenge_id, challenge_ttl_ms) = if let Some(channel_str) = &req.verification_channel {
        let channel = parse_otp_channel(channel_str)?;
        let ttl = channel.ttl_ms();
        let dispatched_ms = now_ms_blocking(state.clone()).await?;

        let mut rng = build_rng()?;
        let (challenge, _code) = OtpChallenge::new(&subject_did, channel, dispatched_ms, &mut rng)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "OTP generation failed"})),
                )
            })?;

        let cid = challenge.challenge_id.clone();
        {
            with_store_blocking(state.clone(), move |store| {
                store
                    .insert_otp_challenge(&challenge)
                    .map_err(|e| store_error_response("submit_claim_insert_otp_challenge", e))
            })
            .await?;
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
    let now = now_ms_blocking(state.clone()).await?;
    let response = with_store_blocking(state.clone(), move |store| {
        let mut challenge = store
            .get_otp_challenge(&req.challenge_id)
            .map_err(|e| store_error_response("verify_otp_get_challenge", e))?
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
                    challenge.hmac_secret.expose_secret(),
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
                store
                    .update_otp_challenge(&challenge)
                    .map_err(|e| store_error_response("verify_otp_update_success", e))?;
                store
                    .insert_session(&session)
                    .map_err(|e| store_error_response("verify_otp_insert_session", e))?;
                Ok(VerifyOtpResponse {
                    verified: true,
                    session_token: Some(session_token),
                    attempts_remaining: None,
                    message: "Verification successful".into(),
                })
            }
            OtpResult::AlreadyVerified => Err(json_error(
                StatusCode::CONFLICT,
                "Challenge has already been verified",
            )),
            OtpResult::WrongCode { attempts_remaining } => {
                store
                    .update_otp_challenge(&challenge)
                    .map_err(|e| store_error_response("verify_otp_update_wrong_code", e))?;
                Ok(VerifyOtpResponse {
                    verified: false,
                    session_token: None,
                    attempts_remaining: Some(attempts_remaining),
                    message: "Incorrect code".into(),
                })
            }
            OtpResult::Expired => {
                store
                    .update_otp_challenge(&challenge)
                    .map_err(|e| store_error_response("verify_otp_update_expired", e))?;
                Err(json_error(StatusCode::GONE, "Challenge has expired"))
            }
            OtpResult::Locked { .. } => {
                store
                    .update_otp_challenge(&challenge)
                    .map_err(|e| store_error_response("verify_otp_update_locked", e))?;
                Err(json_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed attempts — locked",
                ))
            }
        }
    })
    .await?;

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// POST /api/v1/0dentity/verify/resend
// ---------------------------------------------------------------------------

/// `POST /api/v1/0dentity/verify/resend` — resend an OTP code for an existing challenge.
pub async fn resend_otp(
    State(state): State<OnboardingState>,
    Json(req): Json<ResendOtpRequest>,
) -> Result<Json<ResendOtpResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = now_ms_blocking(state.clone()).await?;
    let response = with_store_blocking(state, move |store| {
        let mut challenge = store
            .get_otp_challenge(&req.challenge_id)
            .map_err(|e| store_error_response("resend_otp_get_challenge", e))?
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
        store
            .update_otp_challenge(&challenge)
            .map_err(|e| store_error_response("resend_otp_expire_original", e))?;
        store
            .insert_otp_challenge(&new_challenge)
            .map_err(|e| store_error_response("resend_otp_insert_replacement", e))?;

        Ok(ResendOtpResponse {
            challenge_id: new_id,
            ttl_ms: ttl,
        })
    })
    .await?;

    Ok(Json(response))
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
    fn verify_otp_http_debug_redacts_code_signature_and_session_token() {
        let request = VerifyOtpRequest {
            challenge_id: "challenge-visible".to_owned(),
            code: "867530".to_owned(),
            public_key: Some("public-key-visible".to_owned()),
            bootstrap_signature: Some("bootstrap-signature-secret".to_owned()),
        };
        let request_debug = format!("{request:?}");
        assert!(request_debug.contains("challenge-visible"));
        assert!(!request_debug.contains("867530"));
        assert!(!request_debug.contains("bootstrap-signature-secret"));

        let response = VerifyOtpResponse {
            verified: true,
            session_token: Some("session-token-secret".to_owned()),
            attempts_remaining: Some(2),
            message: "verified".to_owned(),
        };
        let response_debug = format!("{response:?}");
        assert!(response_debug.contains("verified"));
        assert!(!response_debug.contains("session-token-secret"));
    }

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
        let critical_section_count = verifier
            .matches("with_store_blocking(state.clone()")
            .count();

        assert_eq!(
            critical_section_count, 1,
            "OTP verification, challenge consumption, and session insertion must be one blocking critical section"
        );
        assert!(
            !verifier.contains("lock_store(&state)"),
            "OTP verification must not directly lock the store mutex inside async context"
        );
    }

    #[test]
    fn onboarding_async_handlers_use_blocking_store_access() {
        let source = include_str!("onboarding.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "0dentity onboarding handlers must isolate synchronous store access from Tokio workers"
        );

        let handlers = production
            .split("// POST /api/v1/0dentity/verify\n// ---------------------------------------------------------------------------")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------\n// Router").next())
            .unwrap();
        assert!(
            !handlers.contains("lock_store(&state)"),
            "0dentity onboarding async handlers must not lock the store mutex directly"
        );
        assert!(
            !handlers.contains("state.store.lock()"),
            "0dentity onboarding async handlers must route store locks through blocking helpers"
        );
    }

    #[test]
    fn production_onboarding_state_fails_closed_without_trusted_session_clock() {
        let state = OnboardingState::new(Arc::new(Mutex::new(ZerodentityStore::new())));
        let err = state
            .now_ms()
            .expect_err("production onboarding state must require a trusted session clock");

        assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.1["error"], "Trusted 0dentity session clock unavailable");
    }

    #[test]
    fn production_onboarding_state_does_not_install_deterministic_session_clock() {
        let source = include_str!("onboarding.rs");
        let constructor = source
            .split("pub fn new(store: Arc<Mutex<ZerodentityStore>>) -> Self")
            .nth(1)
            .and_then(|section| section.split("pub fn new_with_clock").next())
            .expect("OnboardingState::new constructor present");

        assert!(!constructor.contains("HybridClock::new()"));
        assert!(constructor.contains("SessionClock::unavailable()"));
    }

    #[test]
    fn onboarding_store_errors_are_redacted_in_http_responses() {
        let source = include_str!("onboarding.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        assert!(
            production.contains("fn store_error_response"),
            "onboarding store failures must use a central redaction helper"
        );
        assert!(
            !production.contains("Store error: {e}"),
            "internal store error details must not be reflected to HTTP clients"
        );
        assert!(
            !production.contains("format!(\"Store error"),
            "store error formatting must not be embedded in HTTP responses"
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
    fn first_touch_rng_entropy_errors_are_propagated() {
        let source = include_str!("onboarding.rs");
        let rng_builder = source
            .split("fn build_rng")
            .nth(1)
            .and_then(|section| section.split("fn parse_did").next())
            .expect("build_rng must have an explicit function body");

        assert!(
            rng_builder.contains("-> Result<StdRng"),
            "feature-on RNG construction must return a Result"
        );
        assert!(
            !rng_builder.contains("let _ = getrandom"),
            "feature-on RNG construction must not ignore entropy failures"
        );
        assert!(
            rng_builder.contains("getrandom(&mut seed).map_err"),
            "feature-on RNG construction must convert entropy errors into closed failures"
        );
    }

    #[test]
    fn first_touch_submit_claim_propagates_otp_challenge_store_error() {
        let source = include_str!("onboarding.rs");
        let submit_claim = source
            .split(
                "#[cfg(feature = \"unaudited-zerodentity-first-touch-onboarding\")]\n\
                 pub async fn submit_claim",
            )
            .nth(1)
            .and_then(|section| section.split("// POST /api/v1/0dentity/verify").next())
            .expect("feature-on submit_claim must have an explicit function body");

        assert!(
            !submit_claim.contains("let _ = store.insert_otp_challenge"),
            "OTP challenge persistence failures must not be swallowed"
        );
        assert!(
            submit_claim.contains("store_error_response(\"submit_claim_insert_otp_challenge\""),
            "OTP challenge persistence failures must be returned as redacted closed errors"
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
