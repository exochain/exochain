//! Consent and bailment management.
//!
//! A **bailment** is scoped, time-bounded consent from one party (the bailor)
//! to another (the bailee). It is the EXOCHAIN primitive that answers "is this
//! agent allowed to touch this data, and for how long?". The constitutional
//! kernel refuses to permit actions that are not backed by an active bailment
//! (see the `ConsentRequired` invariant).
//!
//! [`BailmentBuilder`] constructs a [`BailmentProposal`] using the builder
//! pattern. The SDK performs basic validation (non-empty scope, non-zero
//! duration) and generates a **deterministic** content-addressed proposal ID
//! from the fields, so two parties independently building the same proposal
//! produce the same ID.
//!
//! ## Why use this module
//!
//! - You want consent to be an auditable, content-addressed object rather
//!   than a sticky note in a policy engine.
//! - You want the same proposal ID on both sides of a negotiation with no
//!   coordination.
//! - You want the SDK to reject obvious mistakes (empty scope, zero-hour
//!   duration) before the proposal ever hits the wire.
//!
//! ## Quick start
//!
//! ```
//! use exochain_sdk::consent::BailmentBuilder;
//! use exo_core::Did;
//!
//! let alice = Did::new("did:exo:alice").expect("valid");
//! let bob = Did::new("did:exo:bob").expect("valid");
//!
//! let proposal = BailmentBuilder::new(alice, bob)
//!     .scope("data:medical")
//!     .duration_hours(24)
//!     .build()?;
//!
//! assert_eq!(proposal.scope, "data:medical");
//! assert_eq!(proposal.duration_hours, 24);
//! # Ok::<(), exochain_sdk::error::ExoError>(())
//! ```

use exo_core::Did;
use serde::{Deserialize, Serialize};

use crate::error::{ExoError, ExoResult};

/// Builder for a [`BailmentProposal`].
///
/// Required fields are set at construction; optional fields are set via
/// chained `with`-style methods. The final [`BailmentProposal`] is produced
/// by [`BailmentBuilder::build`], which validates the inputs.
///
/// The builder is cheap and can be cloned; each `.build()` call re-validates
/// and returns an owned proposal.
///
/// # Examples
///
/// ```
/// use exochain_sdk::consent::BailmentBuilder;
/// use exo_core::Did;
///
/// let bailor = Did::new("did:exo:alice").expect("valid");
/// let bailee = Did::new("did:exo:bob").expect("valid");
///
/// let proposal = BailmentBuilder::new(bailor, bailee)
///     .scope("data:medical")
///     .duration_hours(24)
///     .build()?;
/// assert_eq!(proposal.proposal_id.len(), 16);
/// # Ok::<(), exochain_sdk::error::ExoError>(())
/// ```
#[derive(Debug, Clone)]
pub struct BailmentBuilder {
    bailor: Did,
    bailee: Did,
    scope: Option<String>,
    duration_hours: Option<u64>,
}

impl BailmentBuilder {
    /// Start a new bailment proposal from `bailor` to `bailee`.
    ///
    /// Scope and duration are required and must be set via
    /// [`BailmentBuilder::scope`] and [`BailmentBuilder::duration_hours`]
    /// before calling [`BailmentBuilder::build`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::consent::BailmentBuilder;
    /// # use exo_core::Did;
    /// let alice = Did::new("did:exo:alice").expect("valid");
    /// let bob = Did::new("did:exo:bob").expect("valid");
    /// let builder = BailmentBuilder::new(alice, bob);
    /// # let _ = builder;
    /// ```
    #[must_use]
    pub fn new(bailor: Did, bailee: Did) -> Self {
        Self {
            bailor,
            bailee,
            scope: None,
            duration_hours: None,
        }
    }

    /// Set the scope of the bailment.
    ///
    /// Scopes are opaque strings from the SDK's perspective. Conventionally
    /// they are colon-separated namespaces such as `"data:medical"`,
    /// `"compute:inference"`, or `"messaging:read"`. The kernel matches
    /// bailment scopes against action strings, so choose names your
    /// application will use consistently.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::consent::BailmentBuilder;
    /// # use exo_core::Did;
    /// # let a = Did::new("did:exo:a").unwrap();
    /// # let b = Did::new("did:exo:b").unwrap();
    /// let builder = BailmentBuilder::new(a, b).scope("data:medical");
    /// # let _ = builder;
    /// ```
    #[must_use]
    pub fn scope(mut self, scope: &str) -> Self {
        self.scope = Some(scope.to_owned());
        self
    }

    /// Set the duration of the bailment in hours.
    ///
    /// Must be strictly greater than zero; [`BailmentBuilder::build`] rejects
    /// a zero-hour duration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::consent::BailmentBuilder;
    /// # use exo_core::Did;
    /// # let a = Did::new("did:exo:a").unwrap();
    /// # let b = Did::new("did:exo:b").unwrap();
    /// let builder = BailmentBuilder::new(a, b).duration_hours(48);
    /// # let _ = builder;
    /// ```
    #[must_use]
    pub fn duration_hours(mut self, hours: u64) -> Self {
        self.duration_hours = Some(hours);
        self
    }

    /// Validate the inputs and produce a [`BailmentProposal`].
    ///
    /// The proposal's `proposal_id` is computed deterministically as the
    /// first 16 hex characters of `BLAKE3(bailor || 0 || bailee || 0 ||
    /// scope || 0 || duration_hours_le_bytes)`. Two builders with the same
    /// fields always produce the same `proposal_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ExoError::Consent`] if:
    /// - `scope` was never set or is an empty string, or
    /// - `duration_hours` was never set or is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::consent::BailmentBuilder;
    /// use exochain_sdk::error::ExoError;
    /// use exo_core::Did;
    ///
    /// let a = Did::new("did:exo:a").expect("valid");
    /// let b = Did::new("did:exo:b").expect("valid");
    ///
    /// // Missing scope → error.
    /// let err = BailmentBuilder::new(a.clone(), b.clone())
    ///     .duration_hours(1)
    ///     .build()
    ///     .unwrap_err();
    /// assert!(matches!(err, ExoError::Consent(_)));
    ///
    /// // Valid inputs → proposal.
    /// let ok = BailmentBuilder::new(a, b)
    ///     .scope("data:medical")
    ///     .duration_hours(24)
    ///     .build()?;
    /// assert_eq!(ok.duration_hours, 24);
    /// # Ok::<(), ExoError>(())
    /// ```
    pub fn build(self) -> ExoResult<BailmentProposal> {
        let scope = self
            .scope
            .ok_or_else(|| ExoError::Consent("scope is required".into()))?;
        if scope.is_empty() {
            return Err(ExoError::Consent("scope must be non-empty".into()));
        }
        let duration_hours = self
            .duration_hours
            .ok_or_else(|| ExoError::Consent("duration_hours is required".into()))?;
        if duration_hours == 0 {
            return Err(ExoError::Consent("duration_hours must be > 0".into()));
        }

        // Deterministic proposal ID: BLAKE3 over canonical fields, first 16 hex chars.
        let proposal_id = proposal_id_for(&self.bailor, &self.bailee, &scope, duration_hours);

        Ok(BailmentProposal {
            proposal_id,
            bailor: self.bailor,
            bailee: self.bailee,
            scope,
            duration_hours,
        })
    }
}

/// A validated bailment proposal ready for downstream processing.
///
/// `BailmentProposal` is produced by [`BailmentBuilder::build`] and is the
/// canonical wire form for a consent object. It is `Serialize` /
/// `Deserialize`, `PartialEq`, and content-addressed: two proposals with
/// equal `proposal_id` are equivalent.
///
/// # Examples
///
/// Round-trip through JSON:
///
/// ```
/// use exochain_sdk::consent::{BailmentBuilder, BailmentProposal};
/// use exo_core::Did;
///
/// let a = Did::new("did:exo:a").expect("valid");
/// let b = Did::new("did:exo:b").expect("valid");
/// let proposal = BailmentBuilder::new(a, b)
///     .scope("data:medical")
///     .duration_hours(48)
///     .build()?;
///
/// let json = serde_json::to_string(&proposal).expect("serialize");
/// let decoded: BailmentProposal = serde_json::from_str(&json).expect("deserialize");
/// assert_eq!(proposal, decoded);
/// # Ok::<(), exochain_sdk::error::ExoError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BailmentProposal {
    /// Deterministic content-addressed identifier for this proposal.
    pub proposal_id: String,
    /// DID of the bailor (consent grantor).
    pub bailor: Did,
    /// DID of the bailee (consent grantee).
    pub bailee: Did,
    /// Scope string describing what the consent covers.
    pub scope: String,
    /// Duration of the bailment, in whole hours.
    pub duration_hours: u64,
}

/// Compute the deterministic proposal ID.
fn proposal_id_for(bailor: &Did, bailee: &Did, scope: &str, duration_hours: u64) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(bailor.as_str().as_bytes());
    payload.push(0);
    payload.extend_from_slice(bailee.as_str().as_bytes());
    payload.push(0);
    payload.extend_from_slice(scope.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&duration_hours.to_le_bytes());
    let digest = blake3::hash(&payload);
    let bytes = digest.as_bytes();
    let mut hex = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    #[test]
    fn builder_pattern_works() {
        let bailor = did("did:exo:alice");
        let bailee = did("did:exo:bob");
        let proposal = BailmentBuilder::new(bailor.clone(), bailee.clone())
            .scope("data:medical")
            .duration_hours(24)
            .build()
            .expect("valid proposal");
        assert_eq!(proposal.bailor, bailor);
        assert_eq!(proposal.bailee, bailee);
        assert_eq!(proposal.scope, "data:medical");
        assert_eq!(proposal.duration_hours, 24);
        assert_eq!(proposal.proposal_id.len(), 16);
        assert!(proposal.proposal_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn missing_scope_fails() {
        let err = BailmentBuilder::new(did("did:exo:a"), did("did:exo:b"))
            .duration_hours(1)
            .build()
            .unwrap_err();
        assert!(matches!(err, ExoError::Consent(_)));
    }

    #[test]
    fn empty_scope_fails() {
        let err = BailmentBuilder::new(did("did:exo:a"), did("did:exo:b"))
            .scope("")
            .duration_hours(1)
            .build()
            .unwrap_err();
        assert!(matches!(err, ExoError::Consent(_)));
    }

    #[test]
    fn missing_duration_fails() {
        let err = BailmentBuilder::new(did("did:exo:a"), did("did:exo:b"))
            .scope("data")
            .build()
            .unwrap_err();
        assert!(matches!(err, ExoError::Consent(_)));
    }

    #[test]
    fn zero_duration_fails() {
        let err = BailmentBuilder::new(did("did:exo:a"), did("did:exo:b"))
            .scope("data")
            .duration_hours(0)
            .build()
            .unwrap_err();
        assert!(matches!(err, ExoError::Consent(_)));
    }

    #[test]
    fn proposal_id_is_deterministic() {
        let bailor = did("did:exo:a");
        let bailee = did("did:exo:b");
        let p1 = BailmentBuilder::new(bailor.clone(), bailee.clone())
            .scope("s")
            .duration_hours(1)
            .build()
            .expect("ok");
        let p2 = BailmentBuilder::new(bailor, bailee)
            .scope("s")
            .duration_hours(1)
            .build()
            .expect("ok");
        assert_eq!(p1.proposal_id, p2.proposal_id);
    }

    #[test]
    fn proposal_id_differs_for_different_inputs() {
        let bailor = did("did:exo:a");
        let bailee = did("did:exo:b");
        let p1 = BailmentBuilder::new(bailor.clone(), bailee.clone())
            .scope("s1")
            .duration_hours(1)
            .build()
            .expect("ok");
        let p2 = BailmentBuilder::new(bailor, bailee)
            .scope("s2")
            .duration_hours(1)
            .build()
            .expect("ok");
        assert_ne!(p1.proposal_id, p2.proposal_id);
    }

    #[test]
    fn proposal_serde_roundtrip() {
        let proposal = BailmentBuilder::new(did("did:exo:a"), did("did:exo:b"))
            .scope("data:medical")
            .duration_hours(48)
            .build()
            .expect("ok");
        let json = serde_json::to_string(&proposal).expect("serialize");
        let decoded: BailmentProposal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proposal, decoded);
    }
}
