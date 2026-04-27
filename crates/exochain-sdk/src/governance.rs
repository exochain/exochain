//! Governance — decisions, voting, quorum.
//!
//! This module provides a simple, ergonomic interface for constructing a
//! [`Decision`], casting [`Vote`]s, and checking whether a quorum threshold
//! has been met. It is not a replacement for the full `exo-governance` crate —
//! it is a developer-facing facade useful for prototyping, testing, and
//! simple governance flows.
//!
//! ## Why use this module
//!
//! - You want a deterministic, content-addressed decision object that any
//!   party can independently construct and hash to the same ID.
//! - You want cheap, in-memory quorum checks before committing a decision to
//!   the fabric.
//! - You want the SDK to reject obvious mistakes (empty title, duplicate
//!   voter) before your governance flow ever hits the wire.
//!
//! ## Quick start
//!
//! ```
//! use exochain_sdk::governance::{DecisionBuilder, Vote, VoteChoice};
//! use exo_core::Did;
//!
//! let alice = Did::new("did:exo:alice").expect("valid");
//! let bob = Did::new("did:exo:bob").expect("valid");
//! let carol = Did::new("did:exo:carol").expect("valid");
//!
//! let mut decision = DecisionBuilder::new("Ratify v1", "Promote to prod", alice)
//!     .build()?;
//! decision.cast_vote(Vote::new(bob, VoteChoice::Approve))?;
//! decision.cast_vote(Vote::new(carol, VoteChoice::Approve))?;
//!
//! let quorum = decision.check_quorum(2);
//! assert!(quorum.met);
//! assert_eq!(quorum.approvals, 2);
//! # Ok::<(), exochain_sdk::error::ExoError>(())
//! ```

use exo_core::Did;
use serde::{Deserialize, Serialize};

use crate::error::{ExoError, ExoResult};

/// Lifecycle status of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionStatus {
    /// The decision has been proposed but not yet opened for deliberation.
    Proposed,
    /// The decision is under active deliberation.
    Deliberating,
    /// The decision has been approved by quorum.
    Approved,
    /// The decision has been rejected.
    Rejected,
    /// The decision is under challenge.
    Challenged,
}

/// Classification of a decision. Free-form label for downstream callers.
///
/// Downstream fabrics may interpret a decision's class to route it to
/// different forums, apply different quorum thresholds, or require different
/// escalation rules. The SDK itself does not interpret the value.
///
/// # Examples
///
/// ```
/// use exochain_sdk::governance::DecisionClass;
///
/// let ordinary = DecisionClass::new("ordinary");
/// let extraordinary = DecisionClass::new("extraordinary");
/// assert_ne!(ordinary, extraordinary);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecisionClass(pub String);

impl DecisionClass {
    /// Construct a new class from any string-like value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::governance::DecisionClass;
    /// let c = DecisionClass::new("ordinary");
    /// assert_eq!(c.0, "ordinary");
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// A vote choice cast on a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VoteChoice {
    /// Vote in favor of the decision.
    Approve,
    /// Vote against the decision.
    Reject,
    /// Explicitly abstain.
    Abstain,
}

/// A vote cast by a voter on a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// DID of the voter.
    pub voter: Did,
    /// The vote choice.
    pub choice: VoteChoice,
    /// Optional free-form rationale.
    pub rationale: Option<String>,
}

impl Vote {
    /// Construct a new vote without a rationale.
    ///
    /// Use [`Vote::with_rationale`] to attach a free-form rationale.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::governance::{Vote, VoteChoice};
    /// use exo_core::Did;
    ///
    /// let voter = Did::new("did:exo:v1").expect("valid");
    /// let vote = Vote::new(voter, VoteChoice::Approve);
    /// assert_eq!(vote.choice, VoteChoice::Approve);
    /// assert!(vote.rationale.is_none());
    /// ```
    #[must_use]
    pub fn new(voter: Did, choice: VoteChoice) -> Self {
        Self {
            voter,
            choice,
            rationale: None,
        }
    }

    /// Attach a rationale to this vote.
    ///
    /// Rationales are recommended whenever a vote rejects or abstains so that
    /// downstream consumers can audit the reasoning.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::governance::{Vote, VoteChoice};
    /// use exo_core::Did;
    ///
    /// let voter = Did::new("did:exo:v1").expect("valid");
    /// let vote = Vote::new(voter, VoteChoice::Reject)
    ///     .with_rationale("risk too high");
    /// assert_eq!(vote.rationale.as_deref(), Some("risk too high"));
    /// ```
    #[must_use]
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = Some(rationale.into());
        self
    }
}

/// Builder for a [`Decision`].
///
/// A decision starts life in [`DecisionStatus::Proposed`] with an empty vote
/// list. The `decision_id` is derived deterministically from the title,
/// description, and proposer, so independent builders producing the same
/// fields end up with the same ID.
///
/// # Examples
///
/// ```
/// use exochain_sdk::governance::{DecisionBuilder, DecisionClass, DecisionStatus};
/// use exo_core::Did;
///
/// let proposer = Did::new("did:exo:alice").expect("valid");
/// let decision = DecisionBuilder::new("Fund Q3", "Allocate 2%", proposer)
///     .decision_class(DecisionClass::new("ordinary"))
///     .build()?;
///
/// assert_eq!(decision.status, DecisionStatus::Proposed);
/// assert_eq!(decision.title, "Fund Q3");
/// assert!(decision.votes.is_empty());
/// # Ok::<(), exochain_sdk::error::ExoError>(())
/// ```
#[derive(Debug, Clone)]
pub struct DecisionBuilder {
    title: String,
    description: String,
    proposer: Did,
    decision_class: Option<DecisionClass>,
}

impl DecisionBuilder {
    /// Start building a decision with a title, description, and proposer DID.
    ///
    /// Title and description may be any strings; [`DecisionBuilder::build`]
    /// only rejects an empty title.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::governance::DecisionBuilder;
    /// # use exo_core::Did;
    /// let proposer = Did::new("did:exo:alice").expect("valid");
    /// let builder = DecisionBuilder::new("title", "desc", proposer);
    /// # let _ = builder;
    /// ```
    #[must_use]
    pub fn new(title: impl Into<String>, description: impl Into<String>, proposer: Did) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            proposer,
            decision_class: None,
        }
    }

    /// Attach an optional decision class.
    ///
    /// See [`DecisionClass`] for how downstream fabrics typically use this
    /// label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exochain_sdk::governance::{DecisionBuilder, DecisionClass};
    /// # use exo_core::Did;
    /// let proposer = Did::new("did:exo:alice").expect("valid");
    /// let decision = DecisionBuilder::new("t", "d", proposer)
    ///     .decision_class(DecisionClass::new("extraordinary"))
    ///     .build()?;
    /// assert_eq!(decision.class, Some(DecisionClass::new("extraordinary")));
    /// # Ok::<(), exochain_sdk::error::ExoError>(())
    /// ```
    #[must_use]
    pub fn decision_class(mut self, class: DecisionClass) -> Self {
        self.decision_class = Some(class);
        self
    }

    /// Validate and build the [`Decision`].
    ///
    /// On success, returns a decision in [`DecisionStatus::Proposed`] with an
    /// empty vote list. The `decision_id` is the first 16 hex chars of
    /// `BLAKE3(title || 0 || description || 0 || proposer_did)` and is
    /// therefore deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`ExoError::Governance`] if the title is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::governance::DecisionBuilder;
    /// use exochain_sdk::error::ExoError;
    /// use exo_core::Did;
    ///
    /// let proposer = Did::new("did:exo:alice").expect("valid");
    /// let err = DecisionBuilder::new("", "d", proposer).build().unwrap_err();
    /// assert!(matches!(err, ExoError::Governance(_)));
    /// ```
    pub fn build(self) -> ExoResult<Decision> {
        if self.title.is_empty() {
            return Err(ExoError::Governance("title must be non-empty".into()));
        }
        let decision_id = decision_id_for(&self.title, &self.description, &self.proposer);
        Ok(Decision {
            decision_id,
            title: self.title,
            description: self.description,
            proposer: self.proposer,
            status: DecisionStatus::Proposed,
            votes: Vec::new(),
            class: self.decision_class,
        })
    }
}

/// A governance decision — title, description, proposer, status, and cast votes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Deterministic content-addressed identifier for this decision.
    pub decision_id: String,
    /// Human-readable title.
    pub title: String,
    /// Human-readable description.
    pub description: String,
    /// The proposer's DID.
    pub proposer: Did,
    /// Current lifecycle status.
    pub status: DecisionStatus,
    /// Accumulated votes.
    pub votes: Vec<Vote>,
    /// Optional decision class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<DecisionClass>,
}

impl Decision {
    /// Cast a vote on this decision.
    ///
    /// The same voter may cast at most one vote per decision. Downstream
    /// flows that need to change a vote should first withdraw the original
    /// and re-cast, which is a policy decision the SDK leaves to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ExoError::Governance`] if the voter has already cast a vote
    /// on this decision.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::governance::{DecisionBuilder, Vote, VoteChoice};
    /// use exochain_sdk::error::ExoError;
    /// use exo_core::Did;
    ///
    /// let proposer = Did::new("did:exo:alice").expect("valid");
    /// let v1 = Did::new("did:exo:v1").expect("valid");
    /// let mut decision = DecisionBuilder::new("t", "d", proposer).build()?;
    /// decision.cast_vote(Vote::new(v1.clone(), VoteChoice::Approve))?;
    ///
    /// // A second vote from the same voter is rejected.
    /// let err = decision
    ///     .cast_vote(Vote::new(v1, VoteChoice::Reject))
    ///     .unwrap_err();
    /// assert!(matches!(err, ExoError::Governance(_)));
    /// # Ok::<(), ExoError>(())
    /// ```
    pub fn cast_vote(&mut self, vote: Vote) -> ExoResult<()> {
        if self.votes.iter().any(|v| v.voter == vote.voter) {
            return Err(ExoError::Governance(format!(
                "voter {} has already cast a vote",
                vote.voter
            )));
        }
        self.votes.push(vote);
        Ok(())
    }

    /// Check whether `threshold` approvals have been reached.
    ///
    /// `threshold` is the minimum number of `Approve` votes required for
    /// quorum. The returned [`QuorumResult`] also reports raw tallies for
    /// approvals, rejections, abstentions, and total votes, so callers can
    /// implement richer policies (e.g. "at least N approvals AND more
    /// approvals than rejections") without re-scanning the votes list.
    ///
    /// # Examples
    ///
    /// ```
    /// use exochain_sdk::governance::{DecisionBuilder, Vote, VoteChoice};
    /// use exo_core::Did;
    ///
    /// let proposer = Did::new("did:exo:alice").expect("valid");
    /// let mut decision = DecisionBuilder::new("t", "d", proposer).build()?;
    /// decision.cast_vote(Vote::new(Did::new("did:exo:v1").unwrap(), VoteChoice::Approve))?;
    /// decision.cast_vote(Vote::new(Did::new("did:exo:v2").unwrap(), VoteChoice::Approve))?;
    /// decision.cast_vote(Vote::new(Did::new("did:exo:v3").unwrap(), VoteChoice::Reject))?;
    ///
    /// let q = decision.check_quorum(2);
    /// assert!(q.met);
    /// assert_eq!(q.approvals, 2);
    /// assert_eq!(q.rejections, 1);
    /// assert_eq!(q.total_votes, 3);
    /// # Ok::<(), exochain_sdk::error::ExoError>(())
    /// ```
    #[must_use]
    pub fn check_quorum(&self, threshold: u32) -> QuorumResult {
        let total_votes = u32::try_from(self.votes.len()).unwrap_or(u32::MAX);
        let approvals = count_choice(&self.votes, VoteChoice::Approve);
        let rejections = count_choice(&self.votes, VoteChoice::Reject);
        let abstentions = count_choice(&self.votes, VoteChoice::Abstain);
        QuorumResult {
            met: approvals >= threshold,
            total_votes,
            approvals,
            rejections,
            abstentions,
        }
    }
}

/// Result of a quorum check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuorumResult {
    /// Whether the threshold has been met.
    pub met: bool,
    /// Total votes cast.
    pub total_votes: u32,
    /// Number of approval votes.
    pub approvals: u32,
    /// Number of rejection votes.
    pub rejections: u32,
    /// Number of abstention votes.
    pub abstentions: u32,
}

fn count_choice(votes: &[Vote], choice: VoteChoice) -> u32 {
    u32::try_from(votes.iter().filter(|v| v.choice == choice).count()).unwrap_or(u32::MAX)
}

fn decision_id_for(title: &str, description: &str, proposer: &Did) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(title.as_bytes());
    payload.push(0);
    payload.extend_from_slice(description.as_bytes());
    payload.push(0);
    payload.extend_from_slice(proposer.as_str().as_bytes());
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

    fn basic_decision() -> Decision {
        DecisionBuilder::new("Fund proposal", "Allocate budget", did("did:exo:alice"))
            .build()
            .expect("valid")
    }

    #[test]
    fn builder_creates_decision() {
        let d = basic_decision();
        assert_eq!(d.title, "Fund proposal");
        assert_eq!(d.description, "Allocate budget");
        assert_eq!(d.status, DecisionStatus::Proposed);
        assert!(d.votes.is_empty());
        assert_eq!(d.decision_id.len(), 16);
    }

    #[test]
    fn builder_with_class() {
        let d = DecisionBuilder::new("t", "d", did("did:exo:p"))
            .decision_class(DecisionClass::new("ordinary"))
            .build()
            .expect("ok");
        assert_eq!(d.class, Some(DecisionClass::new("ordinary")));
    }

    #[test]
    fn builder_rejects_empty_title() {
        let err = DecisionBuilder::new("", "d", did("did:exo:p"))
            .build()
            .unwrap_err();
        assert!(matches!(err, ExoError::Governance(_)));
    }

    #[test]
    fn cast_vote_adds_to_list() {
        let mut d = basic_decision();
        d.cast_vote(Vote::new(did("did:exo:v1"), VoteChoice::Approve))
            .expect("ok");
        assert_eq!(d.votes.len(), 1);
        assert_eq!(d.votes[0].choice, VoteChoice::Approve);
    }

    #[test]
    fn cast_vote_rejects_duplicate_voter() {
        let mut d = basic_decision();
        d.cast_vote(Vote::new(did("did:exo:v1"), VoteChoice::Approve))
            .expect("first ok");
        let err = d
            .cast_vote(Vote::new(did("did:exo:v1"), VoteChoice::Reject))
            .unwrap_err();
        assert!(matches!(err, ExoError::Governance(_)));
    }

    #[test]
    fn quorum_met_when_threshold_reached() {
        let mut d = basic_decision();
        d.cast_vote(Vote::new(did("did:exo:v1"), VoteChoice::Approve))
            .expect("ok");
        d.cast_vote(Vote::new(did("did:exo:v2"), VoteChoice::Approve))
            .expect("ok");
        d.cast_vote(Vote::new(did("did:exo:v3"), VoteChoice::Reject))
            .expect("ok");
        let q = d.check_quorum(2);
        assert!(q.met);
        assert_eq!(q.approvals, 2);
        assert_eq!(q.rejections, 1);
        assert_eq!(q.abstentions, 0);
        assert_eq!(q.total_votes, 3);
    }

    #[test]
    fn quorum_not_met_when_below_threshold() {
        let mut d = basic_decision();
        d.cast_vote(Vote::new(did("did:exo:v1"), VoteChoice::Approve))
            .expect("ok");
        d.cast_vote(Vote::new(did("did:exo:v2"), VoteChoice::Abstain))
            .expect("ok");
        let q = d.check_quorum(3);
        assert!(!q.met);
        assert_eq!(q.approvals, 1);
        assert_eq!(q.abstentions, 1);
        assert_eq!(q.total_votes, 2);
    }

    #[test]
    fn vote_with_rationale() {
        let v = Vote::new(did("did:exo:v"), VoteChoice::Reject).with_rationale("risk too high");
        assert_eq!(v.rationale.as_deref(), Some("risk too high"));
    }

    #[test]
    fn decision_id_is_deterministic() {
        let a = DecisionBuilder::new("t", "d", did("did:exo:p"))
            .build()
            .expect("ok");
        let b = DecisionBuilder::new("t", "d", did("did:exo:p"))
            .build()
            .expect("ok");
        assert_eq!(a.decision_id, b.decision_id);
    }

    #[test]
    fn decision_id_differs_for_different_inputs() {
        let a = DecisionBuilder::new("a", "d", did("did:exo:p"))
            .build()
            .expect("ok");
        let b = DecisionBuilder::new("b", "d", did("did:exo:p"))
            .build()
            .expect("ok");
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn decision_serde_roundtrip() {
        let mut d = basic_decision();
        d.cast_vote(Vote::new(did("did:exo:v1"), VoteChoice::Approve))
            .expect("ok");
        let json = serde_json::to_string(&d).expect("serialize");
        let decoded: Decision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, decoded);
    }
}
