//! OTP challenge state machine for 0dentity verification.
//!
//! Implements HMAC-SHA256 based 6-digit OTP generation and verification
//! per §4.3–4.6 of the 0dentity spec.
//!
//! ## Properties
//! - TTL: channel-specific via `OtpChannel::ttl_ms()`
//! - Lockout: after 5 failed attempts, locked for 3_600_000ms (1 hour)
//! - Resend cooldown: 60_000ms (1 min)
//! - Code format: 6-digit decimal string (leading zeros preserved)

use exo_core::types::{Did, Hash256};
use hmac::{Hmac, Mac};
#[cfg(any(test, feature = "unaudited-zerodentity-first-touch-onboarding"))]
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

use super::types::{OtpChallenge, OtpChannel, OtpState};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of failed attempts before lockout.
pub const OTP_MAX_ATTEMPTS: u32 = 5;

/// Lockout duration in milliseconds (1 hour).
pub const OTP_LOCKOUT_MS: u64 = 3_600_000;

/// Resend cooldown in milliseconds (1 minute).
pub const OTP_RESEND_COOLDOWN_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// OtpResult
// ---------------------------------------------------------------------------

/// Result of an OTP verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpResult {
    /// Code was correct.
    Success,
    /// The challenge was already consumed by a successful verification.
    AlreadyVerified,
    /// Code was wrong; `attempts_remaining` indicates how many more tries before lockout.
    WrongCode { attempts_remaining: u32 },
    /// The challenge TTL has expired.
    Expired,
    /// Too many failed attempts; locked until `locked_until_ms`.
    Locked { locked_until_ms: u64 },
}

// ---------------------------------------------------------------------------
// OtpError
// ---------------------------------------------------------------------------

/// Errors that can arise during OTP operations.
#[derive(Debug, Error)]
pub enum OtpError {
    #[error("HMAC key length invalid")]
    InvalidKeyLength,
    #[error("OTP HMAC secret must not be all zero")]
    InvalidSecret,
}

// ---------------------------------------------------------------------------
// OtpChallenge implementation
// ---------------------------------------------------------------------------

impl OtpChallenge {
    /// Create a new OTP challenge and generate the 6-digit code.
    ///
    /// Returns `(challenge, code_string)`.
    ///
    /// # Arguments
    /// - `subject_did`: the DID being verified
    /// - `channel`: delivery channel (email or SMS)
    /// - `now_ms`: current epoch time in milliseconds (from HLC)
    /// - `rng`: caller-provided RNG (must not be `SystemRng` in test contexts)
    #[cfg(any(test, feature = "unaudited-zerodentity-first-touch-onboarding"))]
    pub fn new(
        subject_did: &Did,
        channel: OtpChannel,
        now_ms: u64,
        rng: &mut dyn RngCore,
    ) -> Result<(Self, String), OtpError> {
        // Generate 32-byte HMAC secret
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        Self::from_secret(subject_did, channel, now_ms, secret)
    }

    /// Create an OTP challenge from caller-supplied HMAC secret material.
    ///
    /// This is the deterministic constructor for trust-boundary callers that
    /// derive challenge entropy from already verified evidence.
    pub fn from_secret(
        subject_did: &Did,
        channel: OtpChannel,
        now_ms: u64,
        hmac_secret: [u8; 32],
    ) -> Result<(Self, String), OtpError> {
        if hmac_secret == [0u8; 32] {
            return Err(OtpError::InvalidSecret);
        }

        let code = derive_code(&hmac_secret, subject_did.as_str(), now_ms)?;
        let code_str = format!("{code:06}");

        // Derive challenge_id from BLAKE3 of (subject_did || now_ms || secret)
        let mut id_input = Vec::with_capacity(100);
        id_input.extend_from_slice(subject_did.as_str().as_bytes());
        id_input.extend_from_slice(&now_ms.to_le_bytes());
        id_input.extend_from_slice(&hmac_secret);
        let id_hash = Hash256::digest(&id_input);
        let challenge_id = hex::encode(id_hash.as_bytes());
        let ttl_ms = channel.ttl_ms();

        let challenge = OtpChallenge {
            challenge_id,
            subject_did: subject_did.clone(),
            channel,
            hmac_secret,
            dispatched_ms: now_ms,
            ttl_ms,
            attempts: 0,
            max_attempts: OTP_MAX_ATTEMPTS,
            state: OtpState::Pending,
        };

        Ok((challenge, code_str))
    }

    /// Verify a user-provided code.
    ///
    /// Mutates `attempts` and `state` in-place. Callers must persist the
    /// updated challenge to the store after calling this.
    ///
    /// # Arguments
    /// - `code`: the 6-digit string the user entered
    /// - `now_ms`: current epoch time in milliseconds
    pub fn verify(&mut self, code: &str, now_ms: u64) -> OtpResult {
        // Already in a terminal or locked state?
        match self.state {
            OtpState::Verified => return OtpResult::AlreadyVerified,
            OtpState::LockedOut => {
                // Compute when lock expires
                let locked_until = self.dispatched_ms + self.ttl_ms + OTP_LOCKOUT_MS;
                return OtpResult::Locked {
                    locked_until_ms: locked_until,
                };
            }
            OtpState::Expired => return OtpResult::Expired,
            OtpState::Pending => {}
        }

        // Check TTL
        if now_ms >= self.dispatched_ms + self.ttl_ms {
            self.state = OtpState::Expired;
            return OtpResult::Expired;
        }

        // Check lockout
        if self.is_locked(now_ms) {
            let locked_until = self.dispatched_ms + self.ttl_ms + OTP_LOCKOUT_MS;
            return OtpResult::Locked {
                locked_until_ms: locked_until,
            };
        }

        // Derive expected code
        let expected = match derive_code(
            &self.hmac_secret,
            self.subject_did.as_str(),
            self.dispatched_ms, // use dispatched_ms, not now_ms — code was derived at creation
        ) {
            Ok(c) => format!("{c:06}"),
            Err(_) => return OtpResult::Expired, // treat internal error as expired
        };

        self.attempts += 1;

        if code == expected {
            self.state = OtpState::Verified;
            OtpResult::Success
        } else if self.attempts >= self.max_attempts {
            self.state = OtpState::LockedOut;
            let locked_until = self.dispatched_ms + self.ttl_ms + OTP_LOCKOUT_MS;
            OtpResult::Locked {
                locked_until_ms: locked_until,
            }
        } else {
            OtpResult::WrongCode {
                attempts_remaining: self.max_attempts - self.attempts,
            }
        }
    }

    /// Returns `true` if the challenge is currently in lockout.
    #[must_use]
    pub fn is_locked(&self, now_ms: u64) -> bool {
        if self.state == OtpState::LockedOut {
            // Lockout persists until TTL + lockout window after dispatch
            let locked_until = self.dispatched_ms + self.ttl_ms + OTP_LOCKOUT_MS;
            return now_ms < locked_until;
        }
        false
    }

    /// Whether the challenge can be re-dispatched (resend cooldown has elapsed).
    #[must_use]
    pub fn can_resend(&self, now_ms: u64) -> bool {
        self.state == OtpState::Pending && now_ms >= self.dispatched_ms + OTP_RESEND_COOLDOWN_MS
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive a 6-digit OTP code from the HMAC secret.
///
/// HMAC-SHA256(secret, subject_did || dispatched_ms) → u32 mod 1_000_000.
fn derive_code(secret: &[u8; 32], subject_did: &str, dispatched_ms: u64) -> Result<u32, OtpError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| OtpError::InvalidKeyLength)?;

    // Message: subject_did bytes || dispatched_ms as little-endian u64
    mac.update(subject_did.as_bytes());
    mac.update(&dispatched_ms.to_le_bytes());

    let result = mac.finalize().into_bytes();
    // Take first 4 bytes as big-endian u32
    let n = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    Ok(n % 1_000_000)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn test_rng() -> impl RngCore {
        // Seeded RNG for reproducible tests
        StdRng::seed_from_u64(0xDEAD_BEEF)
    }

    fn test_did() -> Did {
        Did::new("did:exo:otp-test").expect("valid did")
    }

    // ---- derive_code determinism ----

    #[test]
    fn derive_code_is_deterministic() {
        let secret = [42u8; 32];
        let c1 = derive_code(&secret, "did:exo:test", 1_000_000).expect("ok");
        let c2 = derive_code(&secret, "did:exo:test", 1_000_000).expect("ok");
        assert_eq!(c1, c2);
    }

    #[test]
    fn derive_code_different_dispatched_ms() {
        let secret = [42u8; 32];
        let c1 = derive_code(&secret, "did:exo:test", 1_000).expect("ok");
        let c2 = derive_code(&secret, "did:exo:test", 2_000).expect("ok");
        // Different time → different code (with overwhelming probability)
        // This is not guaranteed but extremely unlikely to collide
        let _ = (c1, c2); // just confirm no panic
    }

    #[test]
    fn derive_code_range() {
        let secret = [99u8; 32];
        let code = derive_code(&secret, "did:exo:range", 0).expect("ok");
        assert!(code < 1_000_000, "code must be < 1_000_000, got {code}");
    }

    // ---- OtpChallenge::new ----

    #[test]
    fn new_creates_pending_challenge() {
        let mut rng = test_rng();
        let did = test_did();
        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, 0, &mut rng).expect("new ok");
        assert_eq!(challenge.state, OtpState::Pending);
        assert_eq!(challenge.attempts, 0);
        assert_eq!(challenge.ttl_ms, OtpChannel::Email.ttl_ms());
        assert_eq!(challenge.max_attempts, OTP_MAX_ATTEMPTS);
        assert_eq!(code.len(), 6, "code must be 6 digits");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "code must be digits"
        );
    }

    #[test]
    fn from_secret_is_deterministic_and_uses_supplied_secret() {
        let did = test_did();
        let secret = [7u8; 32];
        let (first, first_code) =
            OtpChallenge::from_secret(&did, OtpChannel::Email, 42_000, secret).expect("new ok");
        let (second, second_code) =
            OtpChallenge::from_secret(&did, OtpChannel::Email, 42_000, secret).expect("new ok");

        assert_eq!(first.challenge_id, second.challenge_id);
        assert_eq!(first_code, second_code);

        let (different, different_code) =
            OtpChallenge::from_secret(&did, OtpChannel::Email, 42_000, [8u8; 32]).expect("new ok");
        assert_ne!(first.challenge_id, different.challenge_id);
        assert_ne!(first_code, different_code);
    }

    #[test]
    fn from_secret_rejects_zero_secret() {
        let did = test_did();
        let err = OtpChallenge::from_secret(&did, OtpChannel::Email, 42_000, [0u8; 32])
            .expect_err("zero secret must fail");

        assert!(matches!(err, OtpError::InvalidSecret));
    }

    #[test]
    fn new_challenge_ttl_matches_delivery_channel() {
        let did = test_did();
        let (email, _) =
            OtpChallenge::new(&did, OtpChannel::Email, 0, &mut test_rng()).expect("email ok");
        let (sms, _) =
            OtpChallenge::new(&did, OtpChannel::Sms, 1, &mut test_rng()).expect("sms ok");

        assert_eq!(email.ttl_ms, OtpChannel::Email.ttl_ms());
        assert_eq!(sms.ttl_ms, OtpChannel::Sms.ttl_ms());
    }

    #[test]
    fn new_code_is_deterministic_for_same_rng() {
        let did = test_did();
        // Two challenges created with same seed → same code
        let (_, code1) = OtpChallenge::new(
            &did,
            OtpChannel::Email,
            1_000,
            &mut StdRng::seed_from_u64(0),
        )
        .expect("ok");
        let (_, code2) = OtpChallenge::new(
            &did,
            OtpChannel::Email,
            1_000,
            &mut StdRng::seed_from_u64(0),
        )
        .expect("ok");
        assert_eq!(code1, code2);
    }

    // ---- OtpChallenge::verify — success ----

    #[test]
    fn verify_correct_code_succeeds() {
        let mut rng = test_rng();
        let did = test_did();
        let now = 0u64;
        let (mut challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, now, &mut rng).expect("new ok");
        let result = challenge.verify(&code, now + 1_000);
        assert_eq!(result, OtpResult::Success);
        assert_eq!(challenge.state, OtpState::Verified);
    }

    // ---- OtpChallenge::verify — wrong code ----

    #[test]
    fn verify_wrong_code_decrements_attempts() {
        let mut rng = test_rng();
        let did = test_did();
        let (mut challenge, _code) =
            OtpChallenge::new(&did, OtpChannel::Email, 0, &mut rng).expect("new ok");
        let result = challenge.verify("000000", 1_000);
        assert_eq!(
            result,
            OtpResult::WrongCode {
                attempts_remaining: 4
            }
        );
        assert_eq!(challenge.attempts, 1);
    }

    // ---- OtpChallenge::verify — expiry ----

    #[test]
    fn verify_expired_challenge() {
        let mut rng = test_rng();
        let did = test_did();
        let now = 0u64;
        let (mut challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, now, &mut rng).expect("new ok");
        // Advance past TTL
        let result = challenge.verify(&code, now + OtpChannel::Email.ttl_ms() + 1);
        assert_eq!(result, OtpResult::Expired);
        assert_eq!(challenge.state, OtpState::Expired);
    }

    // ---- OtpChallenge::verify — lockout after 5 wrong codes ----

    #[test]
    fn verify_lockout_after_max_attempts() {
        let mut rng = test_rng();
        let did = test_did();
        let (mut challenge, _code) =
            OtpChallenge::new(&did, OtpChannel::Email, 0, &mut rng).expect("new ok");

        // Make max_attempts wrong guesses
        for i in 0..OTP_MAX_ATTEMPTS {
            let result = challenge.verify("999999", 1_000);
            if i < OTP_MAX_ATTEMPTS - 1 {
                assert!(matches!(result, OtpResult::WrongCode { .. }));
            } else {
                assert!(matches!(result, OtpResult::Locked { .. }));
            }
        }
        assert_eq!(challenge.state, OtpState::LockedOut);
    }

    // ---- is_locked ----

    #[test]
    fn is_locked_false_for_fresh_challenge() {
        let mut rng = test_rng();
        let did = test_did();
        let (challenge, _) =
            OtpChallenge::new(&did, OtpChannel::Email, 0, &mut rng).expect("new ok");
        assert!(!challenge.is_locked(1_000));
    }

    // ---- can_resend ----

    #[test]
    fn can_resend_false_before_cooldown() {
        let mut rng = test_rng();
        let did = test_did();
        let now = 1_000_000u64;
        let (challenge, _) =
            OtpChallenge::new(&did, OtpChannel::Email, now, &mut rng).expect("new ok");
        assert!(!challenge.can_resend(now + OTP_RESEND_COOLDOWN_MS - 1));
    }

    #[test]
    fn can_resend_true_after_cooldown() {
        let mut rng = test_rng();
        let did = test_did();
        let now = 1_000_000u64;
        let (challenge, _) =
            OtpChallenge::new(&did, OtpChannel::Email, now, &mut rng).expect("new ok");
        assert!(challenge.can_resend(now + OTP_RESEND_COOLDOWN_MS));
    }

    // ---- verify: early-return branches for terminal states ----

    #[test]
    fn verify_on_already_verified_returns_already_verified_without_incrementing_attempts() {
        let mut rng = test_rng();
        let did = test_did();
        let now = 0u64;
        let (mut ch, code) =
            OtpChallenge::new(&did, OtpChannel::Email, now, &mut rng).expect("new ok");
        // First verify transitions Pending → Verified
        assert_eq!(ch.verify(&code, now + 1_000), OtpResult::Success);
        assert_eq!(ch.state, OtpState::Verified);
        let attempts_before = ch.attempts;
        // Second verify hits the Verified early-return (line 127)
        assert_eq!(ch.verify("wrong", now + 2_000), OtpResult::AlreadyVerified);
        assert_eq!(
            ch.attempts, attempts_before,
            "attempts must not change on re-verify"
        );
    }

    #[test]
    fn verify_on_already_locked_out_returns_locked_without_incrementing_attempts() {
        let mut rng = test_rng();
        let did = test_did();
        let (mut ch, _) = OtpChallenge::new(&did, OtpChannel::Email, 0, &mut rng).expect("new ok");
        // Drive to lockout
        for _ in 0..OTP_MAX_ATTEMPTS {
            let _ = ch.verify("000000", 1_000);
        }
        assert_eq!(ch.state, OtpState::LockedOut);
        let attempts_at_lockout = ch.attempts;
        // Verify again — hits LockedOut early-return (lines 128-133)
        let result = ch.verify("000000", 2_000);
        assert!(
            matches!(result, OtpResult::Locked { .. }),
            "expected Locked from early-return"
        );
        assert_eq!(ch.attempts, attempts_at_lockout, "attempts must not change");
    }

    #[test]
    fn verify_on_already_expired_state_returns_expired_immediately() {
        let mut rng = test_rng();
        let did = test_did();
        let now = 0u64;
        let (mut ch, _) =
            OtpChallenge::new(&did, OtpChannel::Email, now, &mut rng).expect("new ok");
        // Expire via TTL (transitions state to Expired)
        let _ = ch.verify("wrong", now + OtpChannel::Email.ttl_ms() + 1);
        assert_eq!(ch.state, OtpState::Expired);
        let attempts_before = ch.attempts;
        // Verify again — hits Expired early-return (line 135)
        let result = ch.verify("wrong", now + OtpChannel::Email.ttl_ms() + 2);
        assert_eq!(result, OtpResult::Expired, "should be Expired early-return");
        assert_eq!(ch.attempts, attempts_before, "attempts must not change");
    }

    // ---- is_locked: LockedOut state ----

    #[test]
    fn is_locked_true_inside_window_false_after_window() {
        let mut rng = test_rng();
        let did = test_did();
        let dispatched = 0u64;
        let (mut ch, _) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched, &mut rng).expect("new ok");
        // Drive to lockout
        for _ in 0..OTP_MAX_ATTEMPTS {
            let _ = ch.verify("000000", 1_000);
        }
        assert_eq!(ch.state, OtpState::LockedOut);
        // locked_until = dispatched + challenge ttl + OTP_LOCKOUT_MS
        let locked_until = dispatched + ch.ttl_ms + OTP_LOCKOUT_MS;
        // Inside the lock window → true (hits lines 184-188)
        assert!(
            ch.is_locked(locked_until - 1),
            "should be locked before window expires"
        );
        // At and after locked_until → false (same lines, opposite return)
        assert!(
            !ch.is_locked(locked_until),
            "should not be locked at expiry"
        );
        assert!(
            !ch.is_locked(locked_until + 1),
            "should not be locked after expiry"
        );
    }
}
