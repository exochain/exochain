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
//!
//! # Audit status — Onyx-4 R3 (default-off axes)
//!
//! The device fingerprint and behavioral biometric modules are deterministic
//! and tested, and the score engine can consume stored samples. The public
//! onboarding write path does not persist those client-collected samples, so
//! `device_trust` and `behavioral_signature` are disabled by default behind
//! `unaudited-zerodentity-device-behavioral-axes`.
//!
//! The fingerprint timeline API is also disabled by default because it exposes
//! the same unaudited data surface. The R3 initiative is
//! `fix-onyx-4-r3-unwired-axes.md`.

// Core modules
pub mod otp;
pub mod scoring;
pub(crate) mod session_auth;
pub mod store;
pub mod types;

// Feature modules
pub mod api;
pub mod attestation;
pub mod behavioral;
pub mod dashboard;
pub mod fingerprint;
pub mod onboarding;
pub mod onboarding_ui;

/// Feature flag required to score device and behavioral 0dentity axes.
pub const DEVICE_BEHAVIORAL_AXES_FEATURE: &str = "unaudited-zerodentity-device-behavioral-axes";

/// Initiative documenting the R3 unwired-axis finding.
pub const DEVICE_BEHAVIORAL_AXES_INITIATIVE: &str = "fix-onyx-4-r3-unwired-axes.md";

/// Whether the unaudited device/behavioral axes are compiled in.
#[must_use]
pub const fn device_behavioral_axes_enabled() -> bool {
    cfg!(feature = "unaudited-zerodentity-device-behavioral-axes")
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Re-exports — the public surface of the 0dentity module
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
pub use otp::{OTP_LOCKOUT_MS, OTP_MAX_ATTEMPTS, OTP_RESEND_COOLDOWN_MS, OtpError, OtpResult};
#[allow(unused_imports)]
pub use store::{SharedZerodentityStore, ZerodentityStore};
#[allow(unused_imports)]
pub use types::{
    AttestationType, BehavioralSample, BehavioralSignalType, ClaimStatus, ClaimType,
    DeviceFingerprint, FingerprintSignal, IdentityClaim, IdentitySession, OtpChallenge, OtpChannel,
    OtpState, PeerAttestation, PolarAxes, Signature, ZerodentityScore,
};
