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

//! DGCL Section 144 safe-harbor workflow (LEG-013).
//!
//! Delaware General Corporation Law §144 provides three safe-harbor paths
//! for interested-party transactions:
//! 1. **Board approval** — disinterested directors approve after full disclosure.
//! 2. **Shareholder approval** — disinterested shareholders approve after disclosure.
//! 3. **Fairness proof** — the transaction is proven fair as of the time authorized.
//!
//! This module tracks the workflow from disclosure through to verified safe-harbor.

use std::collections::BTreeSet;

use exo_core::{Did, Hash256, Timestamp};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};
use uuid::Uuid;

use crate::error::{LegalError, Result};

/// An interested transaction requiring safe-harbor analysis.
#[derive(Debug, Clone, Serialize)]
pub struct InterestedTransaction {
    id: Uuid,
    /// The interested party (director, officer, or entity with a conflict).
    interested_party: Did,
    /// Description of the material interest.
    interest_description: String,
    /// The counterparty to the transaction.
    counterparty: Did,
    /// Hash of the transaction terms for integrity.
    terms_hash: Hash256,
    /// When the transaction was initiated.
    initiated_at: Timestamp,
    /// Current status of the safe-harbor workflow.
    status: SafeHarborStatus,
    /// The safe-harbor path being pursued.
    path: Option<SafeHarborPath>,
    /// Full disclosure record.
    disclosure: Option<Disclosure>,
    /// Votes from disinterested parties (for Board/Shareholder paths).
    disinterested_votes: Vec<DisinterestedVote>,
    /// Fairness evidence (for FairnessProof path).
    fairness_evidence: Option<FairnessEvidence>,
}

/// Maximum number of unique disinterested voters accepted for one transaction.
pub const MAX_DISINTERESTED_VOTES: usize = 10_000;

/// Maximum UTF-8 byte length accepted for caller-controlled safe-harbor prose.
pub const MAX_SAFE_HARBOR_TEXT_BYTES: usize = 65_536;

/// The three safe-harbor paths under DGCL §144.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeHarborPath {
    /// §144(a)(1): approval by disinterested directors.
    BoardApproval,
    /// §144(a)(2): approval by disinterested shareholders.
    ShareholderApproval,
    /// §144(a)(3): the transaction is fair to the corporation.
    FairnessProof,
}

/// Workflow status for the safe-harbor process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeHarborStatus {
    /// Transaction identified as interested; awaiting disclosure.
    PendingDisclosure,
    /// Full disclosure made; awaiting approval or fairness proof.
    DisclosureMade,
    /// Voting in progress (Board or Shareholder path).
    VotingInProgress,
    /// Safe harbor verified — transaction is protected.
    Verified,
    /// Safe harbor failed — transaction is voidable.
    Failed { reason: String },
}

impl SafeHarborStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            SafeHarborStatus::PendingDisclosure => "PendingDisclosure",
            SafeHarborStatus::DisclosureMade => "DisclosureMade",
            SafeHarborStatus::VotingInProgress => "VotingInProgress",
            SafeHarborStatus::Verified => "Verified",
            SafeHarborStatus::Failed { .. } => "Failed",
        }
    }
}

/// A disclosure record documenting the material interest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    pub disclosed_by: Did,
    pub material_facts: String,
    pub disclosed_at: Timestamp,
    pub facts_hash: Hash256,
}

/// A vote by a disinterested party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisinterestedVote {
    pub voter: Did,
    pub approved: bool,
    pub timestamp: Timestamp,
    /// Attestation that the voter has no interest in the transaction.
    pub independence_attestation: bool,
}

/// Evidence of fairness for the FairnessProof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessEvidence {
    pub evaluator: Did,
    pub methodology: String,
    pub conclusion: String,
    pub evidence_hash: Hash256,
    pub evaluated_at: Timestamp,
}

#[derive(Deserialize)]
struct InterestedTransactionWire {
    id: Uuid,
    interested_party: Did,
    interest_description: String,
    counterparty: Did,
    terms_hash: Hash256,
    initiated_at: Timestamp,
    status: SafeHarborStatus,
    path: Option<SafeHarborPath>,
    disclosure: Option<Disclosure>,
    #[serde(deserialize_with = "deserialize_disinterested_votes")]
    disinterested_votes: Vec<DisinterestedVote>,
    fairness_evidence: Option<FairnessEvidence>,
}

fn deserialize_disinterested_votes<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<DisinterestedVote>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVotesVisitor;

    impl<'de> Visitor<'de> for BoundedVotesVisitor {
        type Value = Vec<DisinterestedVote>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_DISINTERESTED_VOTES} disinterested votes"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_DISINTERESTED_VOTES);
            let mut votes = Vec::with_capacity(capacity);
            while votes.len() < MAX_DISINTERESTED_VOTES {
                match sequence.next_element::<DisinterestedVote>()? {
                    Some(vote) => votes.push(vote),
                    None => return Ok(votes),
                }
            }

            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(format!(
                    "disinterested vote count exceeds {MAX_DISINTERESTED_VOTES}"
                )));
            }
            Ok(votes)
        }
    }

    deserializer.deserialize_seq(BoundedVotesVisitor)
}

fn validate_safe_harbor_text_length(label: &str, value: &str) -> std::result::Result<(), String> {
    if value.len() > MAX_SAFE_HARBOR_TEXT_BYTES {
        return Err(format!(
            "{label} may contain at most {MAX_SAFE_HARBOR_TEXT_BYTES} bytes"
        ));
    }
    Ok(())
}

fn validate_disclosure(disclosure: &Disclosure, initiated_at: Timestamp) -> Result<()> {
    validate_safe_harbor_text_length("material facts", &disclosure.material_facts)
        .map_err(|reason| LegalError::DisclosureVerificationInvalid { reason })?;
    if disclosure.material_facts.trim().is_empty() {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "safe-harbor material facts must not be blank".into(),
        });
    }
    if disclosure.disclosed_at == Timestamp::ZERO {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "safe-harbor disclosure requires a real timestamp".into(),
        });
    }
    if disclosure.disclosed_at < initiated_at {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: format!(
                "safe-harbor disclosure timestamp {} precedes initiation {}",
                disclosure.disclosed_at, initiated_at
            ),
        });
    }
    let expected_hash = Hash256::digest(disclosure.material_facts.as_bytes());
    if disclosure.facts_hash != expected_hash {
        return Err(LegalError::DisclosureVerificationInvalid {
            reason: "safe-harbor facts hash does not match material facts".into(),
        });
    }
    Ok(())
}

fn validate_fairness_evidence(
    evidence: &FairnessEvidence,
    interested_party: &Did,
    counterparty: &Did,
    disclosure: Option<&Disclosure>,
) -> Result<()> {
    if evidence.evaluator == *interested_party {
        return Err(LegalError::ConflictOfInterest {
            reason: format!(
                "{} is the interested party and cannot evaluate transaction fairness",
                evidence.evaluator
            ),
        });
    }
    if evidence.evaluator == *counterparty {
        return Err(LegalError::ConflictOfInterest {
            reason: format!(
                "{} is the counterparty and cannot evaluate transaction fairness",
                evidence.evaluator
            ),
        });
    }
    if evidence.methodology.trim().is_empty() {
        return Err(LegalError::NotAdmissible {
            reason: "fairness evidence methodology must not be blank".into(),
        });
    }
    validate_safe_harbor_text_length("methodology", &evidence.methodology)
        .map_err(|reason| LegalError::NotAdmissible { reason })?;
    if evidence.conclusion.trim().is_empty() {
        return Err(LegalError::NotAdmissible {
            reason: "fairness evidence conclusion must not be blank".into(),
        });
    }
    validate_safe_harbor_text_length("conclusion", &evidence.conclusion)
        .map_err(|reason| LegalError::NotAdmissible { reason })?;
    if evidence.evidence_hash == Hash256::ZERO {
        return Err(LegalError::NotAdmissible {
            reason: "fairness evidence hash must not be Hash256::ZERO".into(),
        });
    }
    if evidence.evaluated_at == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "fairness evidence requires a real evaluation timestamp".into(),
        });
    }
    let disclosed_at = disclosure
        .ok_or_else(|| LegalError::DisclosureRequired {
            action: "fairness evidence requires prior disclosure".into(),
        })?
        .disclosed_at;
    if evidence.evaluated_at < disclosed_at {
        return Err(LegalError::InvalidStateTransition {
            reason: format!(
                "fairness evaluation timestamp {} precedes disclosure {}",
                evidence.evaluated_at, disclosed_at
            ),
        });
    }
    Ok(())
}

impl InterestedTransaction {
    #[must_use]
    pub fn id(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub fn interested_party(&self) -> &Did {
        &self.interested_party
    }

    #[must_use]
    pub fn interest_description(&self) -> &str {
        &self.interest_description
    }

    #[must_use]
    pub fn counterparty(&self) -> &Did {
        &self.counterparty
    }

    #[must_use]
    pub fn terms_hash(&self) -> &Hash256 {
        &self.terms_hash
    }

    #[must_use]
    pub fn initiated_at(&self) -> &Timestamp {
        &self.initiated_at
    }

    #[must_use]
    pub fn status(&self) -> &SafeHarborStatus {
        &self.status
    }

    #[must_use]
    pub fn path(&self) -> Option<&SafeHarborPath> {
        self.path.as_ref()
    }

    #[must_use]
    pub fn disclosure(&self) -> Option<&Disclosure> {
        self.disclosure.as_ref()
    }

    #[must_use]
    pub fn disinterested_votes(&self) -> &[DisinterestedVote] {
        &self.disinterested_votes
    }

    #[must_use]
    pub fn fairness_evidence(&self) -> Option<&FairnessEvidence> {
        self.fairness_evidence.as_ref()
    }

    fn validate(&self) -> Result<()> {
        if self.id.is_nil() {
            return Err(LegalError::InvalidStateTransition {
                reason: "safe-harbor transaction ID must be caller-supplied and non-nil".into(),
            });
        }
        if self.interest_description.trim().is_empty() {
            return Err(LegalError::InvalidStateTransition {
                reason: "safe-harbor interest description must not be empty".into(),
            });
        }
        validate_safe_harbor_text_length("interest description", &self.interest_description)
            .map_err(|reason| LegalError::InvalidStateTransition { reason })?;
        if self.terms_hash == Hash256::ZERO {
            return Err(LegalError::InvalidStateTransition {
                reason: "safe-harbor terms hash must not be Hash256::ZERO".into(),
            });
        }
        if self.initiated_at == Timestamp::ZERO {
            return Err(LegalError::InvalidStateTransition {
                reason: "safe-harbor initiation requires a real timestamp".into(),
            });
        }

        let path = self
            .path
            .as_ref()
            .ok_or_else(|| LegalError::InvalidStateTransition {
                reason: "no safe-harbor path specified".into(),
            })?;

        if let Some(disclosure) = &self.disclosure {
            validate_disclosure(disclosure, self.initiated_at)?;
        }

        if let Some(evidence) = &self.fairness_evidence {
            validate_fairness_evidence(
                evidence,
                &self.interested_party,
                &self.counterparty,
                self.disclosure.as_ref(),
            )?;
        }

        if self.disinterested_votes.len() > MAX_DISINTERESTED_VOTES {
            return Err(LegalError::InvalidStateTransition {
                reason: format!("disinterested vote count exceeds {MAX_DISINTERESTED_VOTES}"),
            });
        }
        let mut unique_voters = BTreeSet::new();
        for vote in &self.disinterested_votes {
            if !unique_voters.insert(&vote.voter) {
                return Err(LegalError::InvalidStateTransition {
                    reason: format!("duplicate disinterested voter DID: {}", vote.voter),
                });
            }
            if vote.voter == self.interested_party {
                return Err(LegalError::ConflictOfInterest {
                    reason: format!("{} is the interested party and cannot vote", vote.voter),
                });
            }
            if vote.voter == self.counterparty {
                return Err(LegalError::ConflictOfInterest {
                    reason: format!("{} is the counterparty and cannot vote", vote.voter),
                });
            }
            if !vote.independence_attestation {
                return Err(LegalError::ConflictOfInterest {
                    reason: format!("{} did not attest independence", vote.voter),
                });
            }
            if vote.timestamp == Timestamp::ZERO {
                return Err(LegalError::InvalidStateTransition {
                    reason: format!("vote from {} requires a real timestamp", vote.voter),
                });
            }
            if let Some(disclosure) = &self.disclosure
                && vote.timestamp < disclosure.disclosed_at
            {
                return Err(LegalError::InvalidStateTransition {
                    reason: format!(
                        "vote timestamp {} from {} precedes disclosure {}",
                        vote.timestamp, vote.voter, disclosure.disclosed_at
                    ),
                });
            }
        }

        match path {
            SafeHarborPath::BoardApproval | SafeHarborPath::ShareholderApproval => {
                if self.fairness_evidence.is_some() {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "voting paths cannot contain fairness evidence".into(),
                    });
                }
            }
            SafeHarborPath::FairnessProof => {
                if !self.disinterested_votes.is_empty() {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "FairnessProof path cannot contain disinterested votes".into(),
                    });
                }
            }
        }

        match &self.status {
            SafeHarborStatus::PendingDisclosure => {
                if self.disclosure.is_some()
                    || !self.disinterested_votes.is_empty()
                    || self.fairness_evidence.is_some()
                {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "PendingDisclosure cannot contain disclosure, votes, or fairness evidence"
                            .into(),
                    });
                }
            }
            SafeHarborStatus::DisclosureMade => {
                if self.disclosure.is_none() {
                    return Err(LegalError::DisclosureRequired {
                        action: "DisclosureMade status requires disclosure".into(),
                    });
                }
                if !self.disinterested_votes.is_empty() {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "DisclosureMade cannot contain disinterested votes".into(),
                    });
                }
            }
            SafeHarborStatus::VotingInProgress => {
                if matches!(path, SafeHarborPath::FairnessProof) {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "FairnessProof path cannot enter VotingInProgress".into(),
                    });
                }
                if self.disclosure.is_none() || self.disinterested_votes.is_empty() {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "VotingInProgress requires disclosure and at least one vote".into(),
                    });
                }
            }
            SafeHarborStatus::Verified => match path {
                SafeHarborPath::BoardApproval | SafeHarborPath::ShareholderApproval => {
                    if self.disclosure.is_none() || self.disinterested_votes.is_empty() {
                        return Err(LegalError::InvalidStateTransition {
                            reason: "verified voting path requires disclosure and votes".into(),
                        });
                    }
                    let approvals = self
                        .disinterested_votes
                        .iter()
                        .filter(|vote| vote.approved)
                        .count();
                    if approvals * 2 <= self.disinterested_votes.len() {
                        return Err(LegalError::InvalidStateTransition {
                            reason: "verified voting path requires majority approval".into(),
                        });
                    }
                }
                SafeHarborPath::FairnessProof => {
                    if self.disclosure.is_none() || self.fairness_evidence.is_none() {
                        return Err(LegalError::InvalidStateTransition {
                            reason: "verified FairnessProof path requires disclosure and fairness evidence"
                                .into(),
                        });
                    }
                }
            },
            SafeHarborStatus::Failed { reason } => {
                if matches!(path, SafeHarborPath::FairnessProof)
                    || self.disclosure.is_none()
                    || self.disinterested_votes.is_empty()
                    || reason.trim().is_empty()
                {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "failed voting path requires disclosure, votes, and a reason"
                            .into(),
                    });
                }
                let approvals = self
                    .disinterested_votes
                    .iter()
                    .filter(|vote| vote.approved)
                    .count();
                if approvals * 2 > self.disinterested_votes.len() {
                    return Err(LegalError::InvalidStateTransition {
                        reason: "failed voting path cannot contain majority approval".into(),
                    });
                }
            }
        }

        Ok(())
    }
}

impl<'de> Deserialize<'de> for InterestedTransaction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = InterestedTransactionWire::deserialize(deserializer)?;
        let transaction = Self {
            id: wire.id,
            interested_party: wire.interested_party,
            interest_description: wire.interest_description,
            counterparty: wire.counterparty,
            terms_hash: wire.terms_hash,
            initiated_at: wire.initiated_at,
            status: wire.status,
            path: wire.path,
            disclosure: wire.disclosure,
            disinterested_votes: wire.disinterested_votes,
            fairness_evidence: wire.fairness_evidence,
        };
        transaction.validate().map_err(serde::de::Error::custom)?;
        Ok(transaction)
    }
}

/// Initiate a safe-harbor workflow for an interested transaction.
///
/// # Errors
/// Returns `LegalError::InvalidStateTransition` if the timestamp is zero.
pub fn initiate_safe_harbor(
    id: Uuid,
    interested_party: &Did,
    counterparty: &Did,
    interest_description: &str,
    terms_hash: Hash256,
    path: SafeHarborPath,
    now: Timestamp,
) -> Result<InterestedTransaction> {
    if id.is_nil() {
        return Err(LegalError::InvalidStateTransition {
            reason: "safe-harbor transaction ID must be caller-supplied and non-nil".into(),
        });
    }
    if interest_description.trim().is_empty() {
        return Err(LegalError::InvalidStateTransition {
            reason: "safe-harbor interest description must not be empty".into(),
        });
    }
    validate_safe_harbor_text_length("interest description", interest_description)
        .map_err(|reason| LegalError::InvalidStateTransition { reason })?;
    if terms_hash == Hash256::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "safe-harbor terms hash must not be Hash256::ZERO".into(),
        });
    }
    if now == Timestamp::ZERO {
        return Err(LegalError::InvalidStateTransition {
            reason: "safe-harbor initiation requires a real timestamp".into(),
        });
    }
    let transaction = InterestedTransaction {
        id,
        interested_party: interested_party.clone(),
        interest_description: interest_description.to_string(),
        counterparty: counterparty.clone(),
        terms_hash,
        initiated_at: now,
        status: SafeHarborStatus::PendingDisclosure,
        path: Some(path),
        disclosure: None,
        disinterested_votes: Vec::new(),
        fairness_evidence: None,
    };
    transaction.validate()?;
    Ok(transaction)
}

/// Complete the disclosure step — record the material facts.
///
/// # Errors
/// - `InvalidStateTransition` if not in `PendingDisclosure` status.
pub fn complete_disclosure(
    txn: &mut InterestedTransaction,
    disclosed_by: &Did,
    material_facts: &str,
    now: Timestamp,
) -> Result<()> {
    validate_safe_harbor_text_length("material facts", material_facts)
        .map_err(|reason| LegalError::DisclosureVerificationInvalid { reason })?;
    txn.validate()?;
    if txn.status != SafeHarborStatus::PendingDisclosure {
        return Err(LegalError::InvalidStateTransition {
            reason: format!("expected PendingDisclosure, got {}", txn.status.as_str()),
        });
    }
    let mut next = txn.clone();
    next.disclosure = Some(Disclosure {
        disclosed_by: disclosed_by.clone(),
        material_facts: material_facts.to_string(),
        disclosed_at: now,
        facts_hash: Hash256::digest(material_facts.as_bytes()),
    });
    next.status = SafeHarborStatus::DisclosureMade;
    next.validate()?;
    *txn = next;
    Ok(())
}

/// Record a vote from a disinterested party (Board or Shareholder path).
///
/// # Errors
/// - `InvalidStateTransition` if not in `DisclosureMade` or `VotingInProgress`.
/// - `ConflictOfInterest` if the voter is the interested party.
pub fn record_disinterested_vote(
    txn: &mut InterestedTransaction,
    voter: &Did,
    approved: bool,
    now: Timestamp,
) -> Result<()> {
    txn.validate()?;
    match &txn.status {
        SafeHarborStatus::DisclosureMade | SafeHarborStatus::VotingInProgress => {}
        other => {
            return Err(LegalError::InvalidStateTransition {
                reason: format!(
                    "expected DisclosureMade or VotingInProgress, got {}",
                    other.as_str()
                ),
            });
        }
    }

    if matches!(txn.path, Some(SafeHarborPath::FairnessProof)) {
        return Err(LegalError::InvalidStateTransition {
            reason: "FairnessProof path does not permit disinterested voting".into(),
        });
    }

    // Neither party to the transaction is disinterested.
    if *voter == txn.interested_party {
        return Err(LegalError::ConflictOfInterest {
            reason: format!("{voter} is the interested party and cannot vote"),
        });
    }
    if *voter == txn.counterparty {
        return Err(LegalError::ConflictOfInterest {
            reason: format!("{voter} is the counterparty and cannot vote"),
        });
    }

    if txn
        .disinterested_votes
        .iter()
        .any(|existing| existing.voter == *voter)
    {
        return Err(LegalError::InvalidStateTransition {
            reason: format!("duplicate disinterested voter DID: {voter}"),
        });
    }
    if txn.disinterested_votes.len() >= MAX_DISINTERESTED_VOTES {
        return Err(LegalError::InvalidStateTransition {
            reason: format!("disinterested vote count cannot exceed {MAX_DISINTERESTED_VOTES}"),
        });
    }

    let mut next = txn.clone();
    next.disinterested_votes.push(DisinterestedVote {
        voter: voter.clone(),
        approved,
        timestamp: now,
        independence_attestation: true,
    });
    next.status = SafeHarborStatus::VotingInProgress;
    next.validate()?;
    *txn = next;
    Ok(())
}

/// Record independent fairness evidence for the FairnessProof path.
///
/// # Errors
/// Returns `InvalidStateTransition` unless disclosure is complete and the
/// transaction is using the FairnessProof path.
pub fn record_fairness_evidence(
    txn: &mut InterestedTransaction,
    evaluator: &Did,
    methodology: &str,
    conclusion: &str,
    evidence_hash: Hash256,
    now: Timestamp,
) -> Result<()> {
    validate_safe_harbor_text_length("methodology", methodology)
        .map_err(|reason| LegalError::NotAdmissible { reason })?;
    validate_safe_harbor_text_length("conclusion", conclusion)
        .map_err(|reason| LegalError::NotAdmissible { reason })?;
    txn.validate()?;
    if txn.status != SafeHarborStatus::DisclosureMade {
        return Err(LegalError::InvalidStateTransition {
            reason: format!("expected DisclosureMade, got {}", txn.status.as_str()),
        });
    }
    if !matches!(txn.path, Some(SafeHarborPath::FairnessProof)) {
        return Err(LegalError::InvalidStateTransition {
            reason: "fairness evidence is only valid for the FairnessProof path".into(),
        });
    }
    if txn.fairness_evidence.is_some() {
        return Err(LegalError::InvalidStateTransition {
            reason: "fairness evidence has already been recorded".into(),
        });
    }

    let mut next = txn.clone();
    next.fairness_evidence = Some(FairnessEvidence {
        evaluator: evaluator.clone(),
        methodology: methodology.to_string(),
        conclusion: conclusion.to_string(),
        evidence_hash,
        evaluated_at: now,
    });
    next.validate()?;
    *txn = next;
    Ok(())
}

/// Verify the safe harbor — check that all requirements for the chosen path are met.
///
/// # Errors
/// - Various `LegalError` variants if requirements are not satisfied.
pub fn verify_safe_harbor(txn: &mut InterestedTransaction) -> Result<()> {
    txn.validate()?;
    // Disclosure must exist
    if txn.disclosure.is_none() {
        return Err(LegalError::DisclosureRequired {
            action: "safe-harbor verification requires prior disclosure".into(),
        });
    }

    let path = txn
        .path
        .as_ref()
        .ok_or_else(|| LegalError::InvalidStateTransition {
            reason: "no safe-harbor path specified".into(),
        })?;

    match path {
        SafeHarborPath::BoardApproval | SafeHarborPath::ShareholderApproval => {
            if txn.status != SafeHarborStatus::VotingInProgress {
                return Err(LegalError::InvalidStateTransition {
                    reason: format!("expected VotingInProgress, got {}", txn.status.as_str()),
                });
            }
            // Need at least one disinterested vote, majority must approve
            if txn.disinterested_votes.is_empty() {
                return Err(LegalError::InvalidStateTransition {
                    reason: "no disinterested votes recorded".into(),
                });
            }
            let approvals = txn
                .disinterested_votes
                .iter()
                .filter(|v| v.approved)
                .count();
            let total = txn.disinterested_votes.len();
            // Majority of disinterested voters must approve
            if approvals * 2 <= total {
                let mut next = txn.clone();
                next.status = SafeHarborStatus::Failed {
                    reason: format!("insufficient approval: {approvals}/{total}"),
                };
                next.validate()?;
                *txn = next;
                return Err(LegalError::FiduciaryViolation {
                    reason: format!(
                        "safe-harbor failed: only {approvals} of {total} disinterested votes approved"
                    ),
                });
            }
            let mut next = txn.clone();
            next.status = SafeHarborStatus::Verified;
            next.validate()?;
            *txn = next;
            Ok(())
        }
        SafeHarborPath::FairnessProof => {
            if txn.status != SafeHarborStatus::DisclosureMade {
                return Err(LegalError::InvalidStateTransition {
                    reason: format!("expected DisclosureMade, got {}", txn.status.as_str()),
                });
            }
            // Must have fairness evidence
            if txn.fairness_evidence.is_none() {
                return Err(LegalError::InvalidStateTransition {
                    reason: "FairnessProof path requires fairness evidence".into(),
                });
            }
            let mut next = txn.clone();
            next.status = SafeHarborStatus::Verified;
            next.validate()?;
            *txn = next;
            Ok(())
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn create_txn(path: SafeHarborPath) -> InterestedTransaction {
        initiate_safe_harbor(
            id(0x300),
            &did("director-alice"),
            &did("alice-corp"),
            "director has financial interest in counterparty",
            Hash256::digest(b"terms"),
            path,
            ts(1000),
        )
        .unwrap()
    }

    #[test]
    fn initiate_uses_caller_supplied_id() {
        let transaction_id = id(0x301);
        let txn = initiate_safe_harbor(
            transaction_id,
            &did("director-alice"),
            &did("alice-corp"),
            "director has financial interest in counterparty",
            Hash256::digest(b"terms"),
            SafeHarborPath::BoardApproval,
            ts(1000),
        )
        .unwrap();
        assert_eq!(txn.id, transaction_id);
    }

    #[test]
    fn initiate_rejects_placeholder_metadata() {
        assert!(
            initiate_safe_harbor(
                Uuid::nil(),
                &did("a"),
                &did("b"),
                "interest",
                Hash256::digest(b"terms"),
                SafeHarborPath::BoardApproval,
                ts(1000),
            )
            .is_err()
        );
        assert!(
            initiate_safe_harbor(
                id(0x302),
                &did("a"),
                &did("b"),
                "interest",
                Hash256::ZERO,
                SafeHarborPath::BoardApproval,
                ts(1000),
            )
            .is_err()
        );
        assert!(
            initiate_safe_harbor(
                id(0x303),
                &did("a"),
                &did("b"),
                " ",
                Hash256::digest(b"terms"),
                SafeHarborPath::BoardApproval,
                ts(1000),
            )
            .is_err()
        );
    }

    // -- Board Approval path --

    #[test]
    fn board_approval_full_workflow() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        assert_eq!(txn.status, SafeHarborStatus::PendingDisclosure);

        complete_disclosure(
            &mut txn,
            &did("director-alice"),
            "I own 30% of counterparty",
            ts(2000),
        )
        .unwrap();
        assert_eq!(txn.status, SafeHarborStatus::DisclosureMade);

        record_disinterested_vote(&mut txn, &did("director-bob"), true, ts(3000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-charlie"), true, ts(3001)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-diana"), false, ts(3002)).unwrap();
        assert_eq!(txn.status, SafeHarborStatus::VotingInProgress);

        verify_safe_harbor(&mut txn).unwrap();
        assert_eq!(txn.status, SafeHarborStatus::Verified);
    }

    #[test]
    fn board_approval_fails_insufficient_votes() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-bob"), false, ts(3000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-charlie"), false, ts(3001)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-diana"), true, ts(3002)).unwrap();
        assert!(verify_safe_harbor(&mut txn).is_err());
        assert!(matches!(txn.status, SafeHarborStatus::Failed { .. }));
    }

    #[test]
    fn duplicate_disinterested_voter_cannot_establish_quorum() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        let voter = did("director-bob");
        record_disinterested_vote(&mut txn, &voter, true, ts(3000)).unwrap();

        let err = record_disinterested_vote(&mut txn, &voter, true, ts(3001))
            .expect_err("a voter DID must be counted at most once");

        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
        assert_eq!(txn.disinterested_votes.len(), 1);
    }

    #[test]
    fn counterparty_cannot_vote_and_rejection_does_not_mutate() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        let original = serde_json::to_value(&txn).unwrap();

        let error = record_disinterested_vote(&mut txn, &did("alice-corp"), true, ts(3000))
            .expect_err("the transaction counterparty is not a disinterested voter");

        assert!(matches!(error, LegalError::ConflictOfInterest { .. }));
        assert_eq!(serde_json::to_value(&txn).unwrap(), original);
    }

    #[test]
    fn counterparty_vote_is_rejected_during_validated_deserialization() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-bob"), true, ts(3000)).unwrap();
        let mut snapshot = serde_json::to_value(txn).unwrap();
        snapshot["disinterested_votes"][0]["voter"] =
            serde_json::Value::String("did:exo:alice-corp".into());

        let error = serde_json::from_value::<InterestedTransaction>(snapshot)
            .expect_err("a serialized counterparty vote must fail validation");

        assert!(error.to_string().contains("counterparty"));
    }

    #[test]
    fn disinterested_vote_count_is_bounded() {
        let mut txn = create_txn(SafeHarborPath::ShareholderApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("shareholder-template"), true, ts(3000)).unwrap();
        let mut snapshot = serde_json::to_value(&txn).unwrap();
        let vote_template = snapshot["disinterested_votes"][0].clone();
        let votes = snapshot["disinterested_votes"]
            .as_array_mut()
            .expect("votes serialize as an array");
        votes.clear();
        for voter_number in 0_u64..10_000 {
            let mut vote = vote_template.clone();
            vote["voter"] =
                serde_json::Value::String(format!("did:exo:shareholder-{voter_number}"));
            votes.push(vote);
        }
        let mut txn: InterestedTransaction =
            serde_json::from_value(snapshot).expect("10,000 unique votes must be accepted");

        let err =
            record_disinterested_vote(&mut txn, &did("shareholder-over-limit"), true, ts(13_000))
                .expect_err("the 10,001st unique vote must be rejected");

        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
        assert_eq!(txn.disinterested_votes.len(), 10_000);
    }

    #[test]
    fn vote_deserializer_does_not_materialize_the_excess_vote() {
        let mut txn = create_txn(SafeHarborPath::ShareholderApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("shareholder-template"), true, ts(3000)).unwrap();
        let mut snapshot = serde_json::to_value(txn).unwrap();
        let vote_template = snapshot["disinterested_votes"][0].clone();
        let votes = snapshot["disinterested_votes"]
            .as_array_mut()
            .expect("votes serialize as an array");
        votes.clear();
        for voter_number in 0_u64..10_000 {
            let mut vote = vote_template.clone();
            vote["voter"] =
                serde_json::Value::String(format!("did:exo:shareholder-{voter_number}"));
            votes.push(vote);
        }
        votes.push(serde_json::json!({
            "sentinel": "this malformed excess item must be ignored rather than materialized"
        }));

        let serialized = serde_json::to_string(&snapshot).unwrap();
        let error = serde_json::from_str::<InterestedTransaction>(&serialized)
            .expect_err("the 10,001st streamed item must be rejected")
            .to_string();

        assert!(
            error.contains("disinterested vote count exceeds 10000"),
            "the excess item was materialized instead of consumed as IgnoredAny: {error}"
        );
    }

    #[test]
    fn safe_harbor_text_limit_is_enforced_before_transition_mutation() {
        let exact = "x".repeat(65_536);
        let over = "x".repeat(65_537);

        initiate_safe_harbor(
            id(0x304),
            &did("director-alice"),
            &did("alice-corp"),
            &exact,
            Hash256::digest(b"terms"),
            SafeHarborPath::BoardApproval,
            ts(1000),
        )
        .expect("an exact-limit interest description must be accepted");
        assert!(
            initiate_safe_harbor(
                id(0x305),
                &did("director-alice"),
                &did("alice-corp"),
                &over,
                Hash256::digest(b"terms"),
                SafeHarborPath::BoardApproval,
                ts(1000),
            )
            .is_err()
        );

        let mut disclosure_txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(
            &mut disclosure_txn,
            &did("director-alice"),
            &exact,
            ts(2000),
        )
        .expect("exact-limit material facts must be accepted");
        let mut disclosure_reject = create_txn(SafeHarborPath::BoardApproval);
        let original_disclosure = serde_json::to_value(&disclosure_reject).unwrap();
        assert!(
            complete_disclosure(
                &mut disclosure_reject,
                &did("director-alice"),
                &over,
                ts(2000),
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(&disclosure_reject).unwrap(),
            original_disclosure
        );

        for (name, methodology, conclusion) in [
            ("methodology", over.as_str(), "fair market range"),
            ("conclusion", "DCF analysis", over.as_str()),
        ] {
            let mut txn = create_txn(SafeHarborPath::FairnessProof);
            complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
            let original = serde_json::to_value(&txn).unwrap();
            let error = record_fairness_evidence(
                &mut txn,
                &did("independent-valuator"),
                methodology,
                conclusion,
                Hash256::digest(b"valuation-report"),
                ts(2500),
            );
            assert!(error.is_err(), "over-limit {name} must be rejected");
            assert_eq!(serde_json::to_value(&txn).unwrap(), original, "{name}");
        }

        for (name, methodology, conclusion) in [
            ("methodology", exact.as_str(), "fair market range"),
            ("conclusion", "DCF analysis", exact.as_str()),
        ] {
            let mut txn = create_txn(SafeHarborPath::FairnessProof);
            complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
            record_fairness_evidence(
                &mut txn,
                &did("independent-valuator"),
                methodology,
                conclusion,
                Hash256::digest(b"valuation-report"),
                ts(2500),
            )
            .unwrap_or_else(|error| panic!("exact-limit {name} must be accepted: {error}"));
        }
    }

    #[test]
    fn safe_harbor_snapshot_rejects_over_limit_prose_fields() {
        let over_text = "x".repeat(65_537);
        let over = serde_json::Value::String(over_text.clone());

        let pending = serde_json::to_value(create_txn(SafeHarborPath::BoardApproval)).unwrap();
        let mut interest = pending;
        interest["interest_description"] = over.clone();

        let mut disclosed_txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(
            &mut disclosed_txn,
            &did("director-alice"),
            "interest",
            ts(2000),
        )
        .unwrap();
        let mut material_facts = serde_json::to_value(disclosed_txn).unwrap();
        material_facts["disclosure"]["material_facts"] = over.clone();
        material_facts["disclosure"]["facts_hash"] =
            serde_json::to_value(Hash256::digest(over_text.as_bytes())).unwrap();

        let mut fairness_txn = create_txn(SafeHarborPath::FairnessProof);
        complete_disclosure(
            &mut fairness_txn,
            &did("director-alice"),
            "interest",
            ts(2000),
        )
        .unwrap();
        record_fairness_evidence(
            &mut fairness_txn,
            &did("independent-valuator"),
            "DCF analysis",
            "fair market range",
            Hash256::digest(b"valuation-report"),
            ts(2500),
        )
        .unwrap();
        let fairness = serde_json::to_value(fairness_txn).unwrap();
        let mut methodology = fairness.clone();
        methodology["fairness_evidence"]["methodology"] = over.clone();
        let mut conclusion = fairness;
        conclusion["fairness_evidence"]["conclusion"] = over;

        for (name, snapshot) in [
            ("interest_description", interest),
            ("material_facts", material_facts),
            ("methodology", methodology),
            ("conclusion", conclusion),
        ] {
            assert!(
                serde_json::from_value::<InterestedTransaction>(snapshot).is_err(),
                "over-limit {name} must be rejected during snapshot validation"
            );
        }
    }

    #[test]
    fn failed_transaction_cannot_transition_to_verified() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-bob"), false, ts(3000)).unwrap();
        assert!(verify_safe_harbor(&mut txn).is_err());
        assert!(matches!(txn.status, SafeHarborStatus::Failed { .. }));

        let err =
            verify_safe_harbor(&mut txn).expect_err("a failed transaction must remain terminal");

        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
        assert!(matches!(txn.status, SafeHarborStatus::Failed { .. }));
    }

    #[test]
    fn verified_transaction_cannot_reopen_voting() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-bob"), true, ts(3000)).unwrap();
        verify_safe_harbor(&mut txn).unwrap();
        let original_vote_count = txn.disinterested_votes.len();

        let err = record_disinterested_vote(&mut txn, &did("director-charlie"), true, ts(3001))
            .expect_err("a verified transaction must remain terminal");

        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
        assert_eq!(txn.disinterested_votes.len(), original_vote_count);
        assert_eq!(txn.status, SafeHarborStatus::Verified);
    }

    #[test]
    fn safe_harbor_snapshot_rejects_inconsistent_state() {
        let pending = create_txn(SafeHarborPath::BoardApproval);
        let mut disclosed = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut disclosed, &did("director-alice"), "interest", ts(2000)).unwrap();
        let mut voting = disclosed.clone();
        record_disinterested_vote(&mut voting, &did("director-bob"), true, ts(3000)).unwrap();

        let pending_snapshot = serde_json::to_value(&pending).unwrap();
        let disclosed_snapshot = serde_json::to_value(&disclosed).unwrap();
        let voting_snapshot = serde_json::to_value(&voting).unwrap();

        let mut disclosure_too_early = pending_snapshot.clone();
        disclosure_too_early["disclosure"] = disclosed_snapshot["disclosure"].clone();

        let mut voting_without_votes = disclosed_snapshot.clone();
        voting_without_votes["status"] = serde_json::Value::String("VotingInProgress".into());

        let mut duplicate_voters = voting_snapshot.clone();
        let duplicate_vote = duplicate_voters["disinterested_votes"][0].clone();
        duplicate_voters["disinterested_votes"]
            .as_array_mut()
            .expect("votes serialize as an array")
            .push(duplicate_vote);

        let mut too_many_voters = voting_snapshot.clone();
        let vote_template = too_many_voters["disinterested_votes"][0].clone();
        let votes = too_many_voters["disinterested_votes"]
            .as_array_mut()
            .expect("votes serialize as an array");
        votes.clear();
        for voter_number in 0_u64..=10_000 {
            let mut vote = vote_template.clone();
            vote["voter"] =
                serde_json::Value::String(format!("did:exo:shareholder-{voter_number}"));
            votes.push(vote);
        }

        let mut fairness_with_votes = voting_snapshot.clone();
        fairness_with_votes["path"] = serde_json::Value::String("FairnessProof".into());

        let fairness_evidence = FairnessEvidence {
            evaluator: did("independent-valuator"),
            methodology: "DCF analysis".into(),
            conclusion: "fair market range".into(),
            evidence_hash: Hash256::digest(b"valuation-report"),
            evaluated_at: ts(2500),
        };
        let mut voting_with_fairness = voting_snapshot.clone();
        voting_with_fairness["fairness_evidence"] =
            serde_json::to_value(fairness_evidence).unwrap();

        let mut terminal_without_prerequisites = disclosed_snapshot;
        terminal_without_prerequisites["status"] = serde_json::Value::String("Verified".into());

        let invalid_snapshots = [
            ("disclosure before DisclosureMade", disclosure_too_early),
            ("VotingInProgress without votes", voting_without_votes),
            ("duplicate voter DIDs", duplicate_voters),
            ("more than 10,000 voters", too_many_voters),
            ("votes on FairnessProof", fairness_with_votes),
            ("fairness evidence on a voting path", voting_with_fairness),
            (
                "terminal state without prerequisites",
                terminal_without_prerequisites,
            ),
        ];
        let accepted: Vec<&str> = invalid_snapshots
            .into_iter()
            .filter_map(|(name, snapshot)| {
                serde_json::from_value::<InterestedTransaction>(snapshot)
                    .ok()
                    .map(|_| name)
            })
            .collect();

        assert!(
            accepted.is_empty(),
            "invalid snapshots were accepted: {accepted:?}"
        );
    }

    #[test]
    fn safe_harbor_snapshot_valid_round_trip_preserves_wire_names() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-bob"), true, ts(3000)).unwrap();
        let serialized = serde_json::to_value(&txn).unwrap();

        assert!(serialized.get("status").is_some());
        assert!(serialized.get("path").is_some());
        assert!(serialized.get("disclosure").is_some());
        assert!(serialized.get("disinterested_votes").is_some());
        assert!(serialized.get("fairness_evidence").is_some());

        let round_trip: InterestedTransaction =
            serde_json::from_value(serialized.clone()).expect("valid snapshots must deserialize");
        assert_eq!(serde_json::to_value(round_trip).unwrap(), serialized);
    }

    #[test]
    fn disclosure_transition_rejects_invalid_content_or_time_without_mutation() {
        for (name, material_facts, disclosed_at) in [
            ("blank material facts", " \t", ts(2000)),
            ("zero disclosure time", "material interest", Timestamp::ZERO),
            ("disclosure before initiation", "material interest", ts(999)),
        ] {
            let mut txn = create_txn(SafeHarborPath::BoardApproval);
            let original = serde_json::to_value(&txn).expect("transaction serializes");

            let error = complete_disclosure(
                &mut txn,
                &did("director-alice"),
                material_facts,
                disclosed_at,
            )
            .expect_err(name);

            assert!(
                matches!(error, LegalError::DisclosureVerificationInvalid { .. }),
                "{name} returned the wrong error: {error}"
            );
            assert_eq!(serde_json::to_value(&txn).unwrap(), original, "{name}");
        }
    }

    #[test]
    fn disclosure_snapshot_rejects_invalid_content_time_and_hash_binding() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(
            &mut txn,
            &did("director-alice"),
            "director owns 30 percent of counterparty",
            ts(2000),
        )
        .unwrap();
        let valid = serde_json::to_value(&txn).unwrap();

        let mut blank_facts = valid.clone();
        blank_facts["disclosure"]["material_facts"] = serde_json::Value::String(" \n".into());

        let mut zero_time = valid.clone();
        zero_time["disclosure"]["disclosed_at"] = serde_json::to_value(Timestamp::ZERO).unwrap();

        let mut before_initiation = valid.clone();
        before_initiation["disclosure"]["disclosed_at"] = serde_json::to_value(ts(999)).unwrap();

        let mut tampered_facts = valid;
        tampered_facts["disclosure"]["material_facts"] =
            serde_json::Value::String("attacker-modified material facts".into());

        for (name, snapshot) in [
            ("blank material facts", blank_facts),
            ("zero disclosure time", zero_time),
            ("disclosure before initiation", before_initiation),
            ("material facts changed without rehashing", tampered_facts),
        ] {
            let error = serde_json::from_value::<InterestedTransaction>(snapshot)
                .expect_err(name)
                .to_string();
            assert!(
                error.contains("disclosure verification invalid"),
                "{name} returned the wrong error: {error}"
            );
        }
    }

    #[test]
    fn vote_transition_rejects_zero_or_predisclosure_time_without_mutation() {
        for (name, vote_time) in [
            ("zero vote timestamp", Timestamp::ZERO),
            ("vote before disclosure", ts(1999)),
        ] {
            let mut txn = create_txn(SafeHarborPath::BoardApproval);
            complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
            let original = serde_json::to_value(&txn).unwrap();

            let error = record_disinterested_vote(&mut txn, &did("director-bob"), true, vote_time)
                .expect_err(name);

            assert!(matches!(error, LegalError::InvalidStateTransition { .. }));
            assert_eq!(serde_json::to_value(&txn).unwrap(), original, "{name}");
        }
    }

    #[test]
    fn vote_snapshot_rejects_zero_or_predisclosure_time() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_disinterested_vote(&mut txn, &did("director-bob"), true, ts(3000)).unwrap();
        let valid = serde_json::to_value(&txn).unwrap();

        for (name, vote_time) in [
            ("zero vote timestamp", Timestamp::ZERO),
            ("vote before disclosure", ts(1999)),
        ] {
            let mut snapshot = valid.clone();
            snapshot["disinterested_votes"][0]["timestamp"] =
                serde_json::to_value(vote_time).unwrap();
            assert!(
                serde_json::from_value::<InterestedTransaction>(snapshot).is_err(),
                "{name} must be rejected during deserialization"
            );
        }
    }

    #[test]
    fn fairness_transition_rejects_invalid_evidence_without_mutation() {
        enum ExpectedError {
            NotAdmissible,
            InvalidStateTransition,
            ConflictOfInterest,
        }

        let interested_party = did("director-alice");
        let counterparty = did("alice-corp");
        let independent = did("independent-valuator");
        let cases = [
            (
                "blank methodology",
                independent.clone(),
                " \t",
                "fair market range",
                Hash256::digest(b"valuation-report"),
                ts(2500),
                ExpectedError::NotAdmissible,
            ),
            (
                "blank conclusion",
                independent.clone(),
                "DCF analysis",
                " \n",
                Hash256::digest(b"valuation-report"),
                ts(2500),
                ExpectedError::NotAdmissible,
            ),
            (
                "zero evidence hash",
                independent.clone(),
                "DCF analysis",
                "fair market range",
                Hash256::ZERO,
                ts(2500),
                ExpectedError::NotAdmissible,
            ),
            (
                "zero evaluation time",
                independent.clone(),
                "DCF analysis",
                "fair market range",
                Hash256::digest(b"valuation-report"),
                Timestamp::ZERO,
                ExpectedError::InvalidStateTransition,
            ),
            (
                "evaluation before disclosure",
                independent,
                "DCF analysis",
                "fair market range",
                Hash256::digest(b"valuation-report"),
                ts(1999),
                ExpectedError::InvalidStateTransition,
            ),
            (
                "interested party evaluator",
                interested_party,
                "DCF analysis",
                "fair market range",
                Hash256::digest(b"valuation-report"),
                ts(2500),
                ExpectedError::ConflictOfInterest,
            ),
            (
                "counterparty evaluator",
                counterparty,
                "DCF analysis",
                "fair market range",
                Hash256::digest(b"valuation-report"),
                ts(2500),
                ExpectedError::ConflictOfInterest,
            ),
        ];

        for (name, evaluator, methodology, conclusion, hash, evaluated_at, expected) in cases {
            let mut txn = create_txn(SafeHarborPath::FairnessProof);
            complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
            let original = serde_json::to_value(&txn).unwrap();

            let error = record_fairness_evidence(
                &mut txn,
                &evaluator,
                methodology,
                conclusion,
                hash,
                evaluated_at,
            )
            .expect_err(name);

            match expected {
                ExpectedError::NotAdmissible => {
                    assert!(
                        matches!(error, LegalError::NotAdmissible { .. }),
                        "{name}: {error}"
                    );
                }
                ExpectedError::InvalidStateTransition => assert!(
                    matches!(error, LegalError::InvalidStateTransition { .. }),
                    "{name}: {error}"
                ),
                ExpectedError::ConflictOfInterest => assert!(
                    matches!(error, LegalError::ConflictOfInterest { .. }),
                    "{name}: {error}"
                ),
            }
            assert_eq!(serde_json::to_value(&txn).unwrap(), original, "{name}");
        }
    }

    #[test]
    fn fairness_snapshot_rejects_invalid_evidence_and_valid_round_trip_survives() {
        let mut txn = create_txn(SafeHarborPath::FairnessProof);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        record_fairness_evidence(
            &mut txn,
            &did("independent-valuator"),
            "DCF analysis",
            "fair market range",
            Hash256::digest(b"valuation-report"),
            ts(2500),
        )
        .unwrap();
        let valid = serde_json::to_value(&txn).unwrap();
        let round_trip: InterestedTransaction =
            serde_json::from_value(valid.clone()).expect("valid fairness snapshot");
        assert_eq!(serde_json::to_value(round_trip).unwrap(), valid);

        let mut blank_methodology = valid.clone();
        blank_methodology["fairness_evidence"]["methodology"] = " \t".into();
        let mut blank_conclusion = valid.clone();
        blank_conclusion["fairness_evidence"]["conclusion"] = " \n".into();
        let mut zero_hash = valid.clone();
        zero_hash["fairness_evidence"]["evidence_hash"] =
            serde_json::to_value(Hash256::ZERO).unwrap();
        let mut zero_time = valid.clone();
        zero_time["fairness_evidence"]["evaluated_at"] =
            serde_json::to_value(Timestamp::ZERO).unwrap();
        let mut before_disclosure = valid.clone();
        before_disclosure["fairness_evidence"]["evaluated_at"] =
            serde_json::to_value(ts(1999)).unwrap();
        let mut interested_evaluator = valid.clone();
        interested_evaluator["fairness_evidence"]["evaluator"] =
            serde_json::Value::String("did:exo:director-alice".into());
        let mut counterparty_evaluator = valid;
        counterparty_evaluator["fairness_evidence"]["evaluator"] =
            serde_json::Value::String("did:exo:alice-corp".into());

        for (name, snapshot) in [
            ("blank methodology", blank_methodology),
            ("blank conclusion", blank_conclusion),
            ("zero evidence hash", zero_hash),
            ("zero evaluation time", zero_time),
            ("evaluation before disclosure", before_disclosure),
            ("interested party evaluator", interested_evaluator),
            ("counterparty evaluator", counterparty_evaluator),
        ] {
            assert!(
                serde_json::from_value::<InterestedTransaction>(snapshot).is_err(),
                "{name} must be rejected during deserialization"
            );
        }
    }

    #[test]
    fn fairness_evidence_transition_is_path_controlled() {
        let mut fairness_txn = create_txn(SafeHarborPath::FairnessProof);
        complete_disclosure(
            &mut fairness_txn,
            &did("director-alice"),
            "interest",
            ts(2000),
        )
        .unwrap();
        record_fairness_evidence(
            &mut fairness_txn,
            &did("independent-valuator"),
            "DCF analysis",
            "fair market range",
            Hash256::digest(b"valuation-report"),
            ts(2500),
        )
        .expect("FairnessProof path must accept controlled evidence");
        assert!(fairness_txn.fairness_evidence.is_some());

        let mut board_txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut board_txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        let err = record_fairness_evidence(
            &mut board_txn,
            &did("independent-valuator"),
            "DCF analysis",
            "fair market range",
            Hash256::digest(b"valuation-report"),
            ts(2500),
        )
        .expect_err("voting paths must reject fairness evidence");
        assert!(matches!(err, LegalError::InvalidStateTransition { .. }));
        assert!(board_txn.fairness_evidence.is_none());
    }

    // -- Shareholder Approval path --

    #[test]
    fn shareholder_approval_full_workflow() {
        let mut txn = create_txn(SafeHarborPath::ShareholderApproval);
        complete_disclosure(
            &mut txn,
            &did("director-alice"),
            "interest in deal",
            ts(2000),
        )
        .unwrap();
        record_disinterested_vote(&mut txn, &did("shareholder-1"), true, ts(3000)).unwrap();
        record_disinterested_vote(&mut txn, &did("shareholder-2"), true, ts(3001)).unwrap();
        verify_safe_harbor(&mut txn).unwrap();
        assert_eq!(txn.status, SafeHarborStatus::Verified);
    }

    // -- Fairness Proof path --

    #[test]
    fn fairness_proof_full_workflow() {
        let mut txn = create_txn(SafeHarborPath::FairnessProof);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();

        record_fairness_evidence(
            &mut txn,
            &did("independent-valuator"),
            "DCF analysis + comparable transactions",
            "Transaction price is within fair market range",
            Hash256::digest(b"valuation-report"),
            ts(2500),
        )
        .unwrap();

        verify_safe_harbor(&mut txn).unwrap();
        assert_eq!(txn.status, SafeHarborStatus::Verified);
    }

    #[test]
    fn fairness_proof_fails_without_evidence() {
        let mut txn = create_txn(SafeHarborPath::FairnessProof);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        assert!(verify_safe_harbor(&mut txn).is_err());
    }

    // -- Error cases --

    #[test]
    fn interested_party_cannot_vote() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("director-alice"), "interest", ts(2000)).unwrap();
        let err = record_disinterested_vote(&mut txn, &did("director-alice"), true, ts(3000));
        assert!(matches!(err, Err(LegalError::ConflictOfInterest { .. })));
    }

    #[test]
    fn vote_before_disclosure_fails() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        let err = record_disinterested_vote(&mut txn, &did("bob"), true, ts(3000));
        let err = err.expect_err("vote before disclosure must fail");
        assert_eq!(
            err.to_string(),
            "invalid state transition: expected DisclosureMade or VotingInProgress, got PendingDisclosure"
        );
    }

    #[test]
    fn disclosure_out_of_order_fails() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("alice"), "interest", ts(2000)).unwrap();
        // Second disclosure should fail
        let err = complete_disclosure(&mut txn, &did("alice"), "more", ts(2001));
        let err = err.expect_err("second disclosure must fail");
        assert_eq!(
            err.to_string(),
            "invalid state transition: expected PendingDisclosure, got DisclosureMade"
        );
    }

    #[test]
    fn verify_without_disclosure_fails() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        let err = verify_safe_harbor(&mut txn);
        assert!(matches!(err, Err(LegalError::DisclosureRequired { .. })));
    }

    #[test]
    fn initiate_rejects_zero_timestamp() {
        let err = initiate_safe_harbor(
            id(0x304),
            &did("a"),
            &did("b"),
            "interest",
            Hash256::digest(b"terms"),
            SafeHarborPath::BoardApproval,
            Timestamp::ZERO,
        );
        assert!(err.is_err());
    }

    #[test]
    fn status_serde() {
        let statuses: Vec<SafeHarborStatus> = vec![
            SafeHarborStatus::PendingDisclosure,
            SafeHarborStatus::DisclosureMade,
            SafeHarborStatus::VotingInProgress,
            SafeHarborStatus::Verified,
            SafeHarborStatus::Failed { reason: "x".into() },
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).unwrap();
            let s2: SafeHarborStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&s2, s);
        }
    }

    #[test]
    fn state_transition_errors_do_not_depend_on_debug_formatting() {
        let source = include_str!("dgcl144.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        for forbidden in [
            "expected PendingDisclosure, got {:?}",
            "expected DisclosureMade or VotingInProgress, got {other:?}",
        ] {
            assert!(
                !source.contains(forbidden),
                "DGCL safe-harbor state errors must use stable labels: {forbidden}"
            );
        }
    }

    #[test]
    fn path_serde() {
        for p in [
            SafeHarborPath::BoardApproval,
            SafeHarborPath::ShareholderApproval,
            SafeHarborPath::FairnessProof,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let p2: SafeHarborPath = serde_json::from_str(&json).unwrap();
            assert_eq!(p2, p);
        }
    }
}
