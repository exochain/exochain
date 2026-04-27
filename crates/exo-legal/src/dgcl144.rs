//! DGCL Section 144 safe-harbor workflow (LEG-013).
//!
//! Delaware General Corporation Law §144 provides three safe-harbor paths
//! for interested-party transactions:
//! 1. **Board approval** — disinterested directors approve after full disclosure.
//! 2. **Shareholder approval** — disinterested shareholders approve after disclosure.
//! 3. **Fairness proof** — the transaction is proven fair as of the time authorized.
//!
//! This module tracks the workflow from disclosure through to verified safe-harbor.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LegalError, Result};

/// An interested transaction requiring safe-harbor analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterestedTransaction {
    pub id: Uuid,
    /// The interested party (director, officer, or entity with a conflict).
    pub interested_party: Did,
    /// Description of the material interest.
    pub interest_description: String,
    /// The counterparty to the transaction.
    pub counterparty: Did,
    /// Hash of the transaction terms for integrity.
    pub terms_hash: Hash256,
    /// When the transaction was initiated.
    pub initiated_at: Timestamp,
    /// Current status of the safe-harbor workflow.
    pub status: SafeHarborStatus,
    /// The safe-harbor path being pursued.
    pub path: Option<SafeHarborPath>,
    /// Full disclosure record.
    pub disclosure: Option<Disclosure>,
    /// Votes from disinterested parties (for Board/Shareholder paths).
    pub disinterested_votes: Vec<DisinterestedVote>,
    /// Fairness evidence (for FairnessProof path).
    pub fairness_evidence: Option<FairnessEvidence>,
}

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
    Ok(InterestedTransaction {
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
    })
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
    if txn.status != SafeHarborStatus::PendingDisclosure {
        return Err(LegalError::InvalidStateTransition {
            reason: format!("expected PendingDisclosure, got {:?}", txn.status),
        });
    }
    txn.disclosure = Some(Disclosure {
        disclosed_by: disclosed_by.clone(),
        material_facts: material_facts.to_string(),
        disclosed_at: now,
        facts_hash: Hash256::digest(material_facts.as_bytes()),
    });
    txn.status = SafeHarborStatus::DisclosureMade;
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
    match &txn.status {
        SafeHarborStatus::DisclosureMade | SafeHarborStatus::VotingInProgress => {}
        other => {
            return Err(LegalError::InvalidStateTransition {
                reason: format!("expected DisclosureMade or VotingInProgress, got {other:?}"),
            });
        }
    }

    // The interested party cannot vote on their own transaction
    if *voter == txn.interested_party {
        return Err(LegalError::ConflictOfInterest {
            reason: format!("{voter} is the interested party and cannot vote"),
        });
    }

    txn.disinterested_votes.push(DisinterestedVote {
        voter: voter.clone(),
        approved,
        timestamp: now,
        independence_attestation: true,
    });
    txn.status = SafeHarborStatus::VotingInProgress;
    Ok(())
}

/// Verify the safe harbor — check that all requirements for the chosen path are met.
///
/// # Errors
/// - Various `LegalError` variants if requirements are not satisfied.
pub fn verify_safe_harbor(txn: &mut InterestedTransaction) -> Result<()> {
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
                txn.status = SafeHarborStatus::Failed {
                    reason: format!("insufficient approval: {approvals}/{total}"),
                };
                return Err(LegalError::FiduciaryViolation {
                    reason: format!(
                        "safe-harbor failed: only {approvals} of {total} disinterested votes approved"
                    ),
                });
            }
            txn.status = SafeHarborStatus::Verified;
            Ok(())
        }
        SafeHarborPath::FairnessProof => {
            // Must have fairness evidence
            if txn.fairness_evidence.is_none() {
                return Err(LegalError::InvalidStateTransition {
                    reason: "FairnessProof path requires fairness evidence".into(),
                });
            }
            txn.status = SafeHarborStatus::Verified;
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

        // Add fairness evidence
        txn.fairness_evidence = Some(FairnessEvidence {
            evaluator: did("independent-valuator"),
            methodology: "DCF analysis + comparable transactions".into(),
            conclusion: "Transaction price is within fair market range".into(),
            evidence_hash: Hash256::digest(b"valuation-report"),
            evaluated_at: ts(2500),
        });

        // Transition to VotingInProgress is not needed for fairness path
        txn.status = SafeHarborStatus::DisclosureMade;
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
        assert!(matches!(
            err,
            Err(LegalError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn disclosure_out_of_order_fails() {
        let mut txn = create_txn(SafeHarborPath::BoardApproval);
        complete_disclosure(&mut txn, &did("alice"), "interest", ts(2000)).unwrap();
        // Second disclosure should fail
        let err = complete_disclosure(&mut txn, &did("alice"), "more", ts(2001));
        assert!(matches!(
            err,
            Err(LegalError::InvalidStateTransition { .. })
        ));
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
