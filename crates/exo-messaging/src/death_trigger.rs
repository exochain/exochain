//! Death trigger — afterlife message release state machine.
//!
//! Manages the lifecycle of death verification claims and the
//! conditional release of afterlife messages.

use std::collections::BTreeSet;

use exo_core::{Did, Timestamp, hlc::HybridClock};
use serde::{Deserialize, Serialize};

use crate::error::MessagingError;

/// Status of a death verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeathVerificationStatus {
    /// Claim initiated, awaiting trustee confirmations.
    Pending,
    /// Sufficient trustees confirmed — death verified.
    Verified,
    /// Claim rejected or expired.
    Rejected,
}

/// A single trustee confirmation of a death claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrusteeConfirmation {
    pub trustee_did: Did,
    pub confirmed_at: Timestamp,
}

/// A death verification request tracking trustee consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeathVerification {
    /// The DID of the person whose death is being claimed.
    pub subject_did: Did,
    /// The trustee who initiated the death claim.
    pub initiated_by: Did,
    /// Number of trustee confirmations required (default: 3 for 3-of-4 PACE).
    pub required_confirmations: u8,
    /// Collected trustee confirmations.
    pub confirmations: Vec<TrusteeConfirmation>,
    /// Current verification status.
    pub status: DeathVerificationStatus,
    /// When the claim was initiated.
    pub created: Timestamp,
    /// When the claim was resolved (verified or rejected).
    pub resolved_at: Option<Timestamp>,
}

impl DeathVerification {
    /// Create a new death verification request.
    pub fn new(subject_did: Did, initiated_by: Did, required_confirmations: u8) -> Self {
        let mut clock = HybridClock::new();
        let now = clock.now();

        Self {
            subject_did,
            initiated_by: initiated_by.clone(),
            required_confirmations,
            confirmations: vec![TrusteeConfirmation {
                trustee_did: initiated_by,
                confirmed_at: now,
            }],
            status: DeathVerificationStatus::Pending,
            created: now,
            resolved_at: None,
        }
    }

    /// Add a trustee confirmation. Returns `true` if the threshold is now met.
    pub fn confirm(&mut self, trustee_did: Did) -> Result<bool, MessagingError> {
        if self.status != DeathVerificationStatus::Pending {
            return Err(MessagingError::DeathTriggerAlreadyResolved);
        }

        // Check for duplicate
        let existing: BTreeSet<String> = self
            .confirmations
            .iter()
            .map(|c| c.trustee_did.as_str().to_owned())
            .collect();
        if existing.contains(trustee_did.as_str()) {
            return Err(MessagingError::DuplicateConfirmation(
                trustee_did.as_str().to_owned(),
            ));
        }

        let mut clock = HybridClock::new();
        let now = clock.now();

        self.confirmations.push(TrusteeConfirmation {
            trustee_did,
            confirmed_at: now,
        });

        // Check if threshold is met. `required_confirmations` is a
        // u8 (max 255); widening to usize is lossless.
        if self.confirmations.len() >= usize::from(self.required_confirmations) {
            self.status = DeathVerificationStatus::Verified;
            self.resolved_at = Some(now);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Reject the death claim.
    pub fn reject(&mut self) -> Result<(), MessagingError> {
        if self.status != DeathVerificationStatus::Pending {
            return Err(MessagingError::DeathTriggerAlreadyResolved);
        }
        let mut clock = HybridClock::new();
        self.status = DeathVerificationStatus::Rejected;
        self.resolved_at = Some(clock.now());
        Ok(())
    }

    /// Check if the verification is complete and afterlife messages should be released.
    #[must_use]
    pub fn should_release(&self) -> bool {
        self.status == DeathVerificationStatus::Verified
    }

    /// Number of confirmations still needed.
    #[must_use]
    pub fn confirmations_remaining(&self) -> u8 {
        // Confirmations count is bounded by required_confirmations
        // (a u8) in the normal path; saturating at u8::MAX is the
        // correct behavior if somehow it grows past 255.
        let current = u8::try_from(self.confirmations.len()).unwrap_or(u8::MAX);
        self.required_confirmations.saturating_sub(current)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).unwrap()
    }

    #[test]
    fn new_verification_has_initiator_confirmation() {
        let dv = DeathVerification::new(did("alice"), did("bob"), 3);
        assert_eq!(dv.confirmations.len(), 1);
        assert_eq!(dv.confirmations[0].trustee_did, did("bob"));
        assert_eq!(dv.status, DeathVerificationStatus::Pending);
        assert_eq!(dv.confirmations_remaining(), 2);
    }

    #[test]
    fn threshold_met_triggers_verified() {
        let mut dv = DeathVerification::new(did("alice"), did("bob"), 3);

        let met = dv.confirm(did("carol")).unwrap();
        assert!(!met);
        assert_eq!(dv.confirmations_remaining(), 1);

        let met = dv.confirm(did("dave")).unwrap();
        assert!(met);
        assert_eq!(dv.status, DeathVerificationStatus::Verified);
        assert!(dv.should_release());
        assert!(dv.resolved_at.is_some());
    }

    #[test]
    fn duplicate_confirmation_rejected() {
        let mut dv = DeathVerification::new(did("alice"), did("bob"), 3);
        let result = dv.confirm(did("bob"));
        assert!(matches!(
            result,
            Err(MessagingError::DuplicateConfirmation(_))
        ));
    }

    #[test]
    fn cannot_confirm_after_resolved() {
        let mut dv = DeathVerification::new(did("alice"), did("bob"), 2);
        dv.confirm(did("carol")).unwrap(); // threshold met
        let result = dv.confirm(did("dave"));
        assert!(matches!(
            result,
            Err(MessagingError::DeathTriggerAlreadyResolved)
        ));
    }

    #[test]
    fn reject_prevents_further_confirmations() {
        let mut dv = DeathVerification::new(did("alice"), did("bob"), 3);
        dv.reject().unwrap();
        assert_eq!(dv.status, DeathVerificationStatus::Rejected);
        assert!(!dv.should_release());

        let result = dv.confirm(did("carol"));
        assert!(matches!(
            result,
            Err(MessagingError::DeathTriggerAlreadyResolved)
        ));
    }

    #[test]
    fn full_pace_4_trustee_flow() {
        // Simulates the 3-of-4 PACE trustee death verification
        let mut dv = DeathVerification::new(did("subject"), did("primary"), 3);
        assert_eq!(dv.confirmations_remaining(), 2);

        dv.confirm(did("alternate")).unwrap();
        assert_eq!(dv.confirmations_remaining(), 1);

        let verified = dv.confirm(did("contingency")).unwrap();
        assert!(verified);
        assert!(dv.should_release());
        assert_eq!(dv.confirmations_remaining(), 0);
    }
}
