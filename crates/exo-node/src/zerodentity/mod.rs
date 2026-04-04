//! 0dentity — sovereign identity scoring application.
//!
//! This module implements the 0dentity system as specified in
//! `docs/0DENTITY-APP-SPEC.md`. It is split across several sub-modules:
//!
//! - **types**        — foundational types (claims, axes, scores, fingerprints)
//! - **scoring**      — `ZerodentityScore::compute()` + 8 axis functions
//! - **store**        — `ZerodentityStore` + `SharedZerodentityStore`
//! - **otp**          — HMAC-SHA256 OTP challenge state machine
//! - **fingerprint**  — Jaccard-similarity device consistency scoring
//! - **behavioral**   — histogram baseline similarity
//! - **attestation**  — peer attestation validation
//! - **onboarding**   — POST /api/v1/0dentity/claims, /verify, /verify/resend
//! - **api**          — GET /api/v1/0dentity/:did/score, /claims, /history
//! - **dashboard**    — GET /0dentity/dashboard/:did
//! - **onboarding_ui**— GET /0dentity (onboarding flow HTML)

// Core modules (APE-72)
pub mod otp;
pub mod scoring;
pub mod store;
pub mod types;

// Signal modules (APE-74)
pub mod attestation;
pub mod behavioral;
pub mod fingerprint;

// API + UI modules (APE-73)
pub mod api;
pub mod dashboard;
pub mod onboarding;
pub mod onboarding_ui;

// ---------------------------------------------------------------------------
// Re-exports — the public surface of the 0dentity module
// ---------------------------------------------------------------------------

pub use otp::{
    OtpError, OtpResult, OTP_LOCKOUT_MS, OTP_MAX_ATTEMPTS, OTP_RESEND_COOLDOWN_MS, OTP_TTL_MS,
};
pub use store::{SharedZerodentityStore, ZerodentityStore};
pub use types::{
    AttestationType, BehavioralSample, BehavioralSignalType, ClaimStatus, ClaimType,
    DeviceFingerprint, FingerprintSignal, IdentityClaim, IdentitySession, OtpChallenge,
    OtpChannel, OtpState, PeerAttestation, PolarAxes, Signature, ZerodentityScore,
};
