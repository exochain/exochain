//! 0dentity — sovereign identity scoring application.
//!
//! This module implements the foundational 0dentity system as specified in
//! `docs/0DENTITY-APP-SPEC.md`. It is split across several sub-modules:
//!
//! - **types**        — foundational types (claims, axes, scores, OTP)
//! - **scoring**      — `ZerodentityScore::compute()` + 8 axis functions
//! - **store**        — `ZerodentityStore` + `SharedZerodentityStore`
//! - **otp**          — HMAC-SHA256 OTP challenge state machine
//!
//! Downstream crates (APE-73, APE-74) extend this core with signal collection,
//! API handlers, and the onboarding UI.

// Core modules (APE-72)
pub mod otp;
pub mod scoring;
pub mod store;
pub mod types;

// ---------------------------------------------------------------------------
// Re-exports — the public surface of the 0dentity core
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
pub use otp::{
    OTP_LOCKOUT_MS, OTP_MAX_ATTEMPTS, OTP_RESEND_COOLDOWN_MS, OTP_TTL_MS, OtpError, OtpResult,
};
#[allow(unused_imports)]
pub use store::{SharedZerodentityStore, ZerodentityStore};
#[allow(unused_imports)]
pub use types::{
    AttestationType, BehavioralSample, BehavioralSignalType, ClaimStatus, ClaimType,
    DeviceFingerprint, FingerprintSignal, IdentityClaim, IdentitySession, OtpChallenge, OtpChannel,
    OtpState, PeerAttestation, PolarAxes, Signature, ZerodentityScore,
};
