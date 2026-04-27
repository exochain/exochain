//! Accountability mechanisms (GOV-012).
//!
//! Actions: Censure, Suspension, Revocation, Recall. Each is itself a
//! Decision Object with due process. Suspension must be immediate (<60s).
//! Due process timelines are clocked by the system.

use exo_core::types::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ForumError, Result};

/// The type of accountability action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccountabilityActionType {
    Censure,
    Suspension,
    Revocation,
    Recall,
}

/// Status of an accountability action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountabilityStatus {
    Proposed,
    DueProcess,
    Enacted,
    Reversed,
}

/// An accountability action against an actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountabilityAction {
    pub id: Uuid,
    pub action_type: AccountabilityActionType,
    pub target_did: Did,
    pub proposer_did: Did,
    pub reason: String,
    pub evidence_hash: Hash256,
    pub status: AccountabilityStatus,
    pub decision_id: Option<Uuid>,
    pub proposed_at: Timestamp,
    pub enacted_at: Option<Timestamp>,
    pub due_process_deadline: Timestamp,
}

/// Due-process timeline limits in milliseconds.
pub const SUSPENSION_ENACT_LIMIT_MS: u64 = 60_000; // 60 seconds
pub const DUE_PROCESS_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 days

/// Caller-supplied metadata for proposing an accountability action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountabilityInput {
    pub id: Uuid,
    pub action_type: AccountabilityActionType,
    pub target: Did,
    pub proposer: Did,
    pub reason: String,
    pub evidence_hash: Hash256,
    pub proposed_at: Timestamp,
}

/// Propose an accountability action.
pub fn propose(input: AccountabilityInput) -> Result<AccountabilityAction> {
    validate_uuid(input.id, "accountability action id")?;
    validate_timestamp(input.proposed_at, "accountability proposed_at")?;
    validate_hash(input.evidence_hash, "accountability evidence hash")?;
    if input.reason.trim().is_empty() {
        return Err(ForumError::InvalidProvenance {
            reason: "accountability reason must be non-empty".into(),
        });
    }

    let due_process_deadline_ms = input
        .proposed_at
        .physical_ms
        .saturating_add(DUE_PROCESS_WINDOW_MS);
    Ok(AccountabilityAction {
        id: input.id,
        action_type: input.action_type,
        target_did: input.target,
        proposer_did: input.proposer,
        reason: input.reason,
        evidence_hash: input.evidence_hash,
        status: AccountabilityStatus::Proposed,
        decision_id: None,
        proposed_at: input.proposed_at,
        enacted_at: None,
        due_process_deadline: Timestamp::new(due_process_deadline_ms, 0),
    })
}

/// Move an action into due-process status.
pub fn begin_due_process(action: &mut AccountabilityAction) -> Result<()> {
    if action.status != AccountabilityStatus::Proposed {
        return Err(ForumError::AccountabilityFailed {
            reason: format!("cannot begin due process from {:?}", action.status),
        });
    }
    action.status = AccountabilityStatus::DueProcess;
    Ok(())
}

/// Enact an accountability action after due process (or immediately for suspension).
pub fn enact(
    action: &mut AccountabilityAction,
    decision_id: Uuid,
    timestamp: Timestamp,
) -> Result<()> {
    match action.status {
        AccountabilityStatus::Proposed | AccountabilityStatus::DueProcess => {}
        _ => {
            return Err(ForumError::AccountabilityFailed {
                reason: format!("cannot enact from {:?}", action.status),
            });
        }
    }

    // Suspension must be enacted within 60 seconds.
    if action.action_type == AccountabilityActionType::Suspension {
        let elapsed_ms = timestamp
            .physical_ms
            .saturating_sub(action.proposed_at.physical_ms);
        if elapsed_ms > SUSPENSION_ENACT_LIMIT_MS {
            return Err(ForumError::AccountabilityFailed {
                reason: format!(
                    "suspension enactment exceeded 60s limit: {}ms elapsed",
                    elapsed_ms
                ),
            });
        }
    }

    action.status = AccountabilityStatus::Enacted;
    action.decision_id = Some(decision_id);
    action.enacted_at = Some(timestamp);
    Ok(())
}

/// Reverse an enacted action.
pub fn reverse(action: &mut AccountabilityAction) -> Result<()> {
    if action.status != AccountabilityStatus::Enacted {
        return Err(ForumError::AccountabilityFailed {
            reason: "can only reverse enacted actions".into(),
        });
    }
    action.status = AccountabilityStatus::Reversed;
    Ok(())
}

/// Check if due process deadline has passed.
#[must_use]
pub fn is_due_process_expired(action: &AccountabilityAction, now: &Timestamp) -> bool {
    action.status == AccountabilityStatus::DueProcess && *now > action.due_process_deadline
}

fn validate_uuid(id: Uuid, label: &str) -> Result<()> {
    if id.is_nil() {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must not be nil"),
        });
    }
    Ok(())
}

fn validate_timestamp(timestamp: Timestamp, label: &str) -> Result<()> {
    if timestamp == Timestamp::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must be non-zero HLC"),
        });
    }
    Ok(())
}

fn validate_hash(hash: Hash256, label: &str) -> Result<()> {
    if hash == Hash256::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must be non-zero"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).expect("ok")
    }
    fn ts() -> Timestamp {
        Timestamp::new(1_000_000, 0)
    }

    fn action_input(id: Uuid, action_type: AccountabilityActionType) -> AccountabilityInput {
        AccountabilityInput {
            id,
            action_type,
            target: did("target"),
            proposer: did("proposer"),
            reason: "misconduct".into(),
            evidence_hash: Hash256::digest(b"evidence"),
            proposed_at: ts(),
        }
    }

    fn make_action(action_type: AccountabilityActionType) -> AccountabilityAction {
        propose(action_input(Uuid::from_u128(21), action_type)).expect("valid action")
    }

    #[test]
    fn propose_requires_caller_supplied_identity_and_hlc() {
        let action = propose(action_input(
            Uuid::from_u128(22),
            AccountabilityActionType::Censure,
        ))
        .expect("valid");
        assert_eq!(action.id, Uuid::from_u128(22));
        assert_eq!(action.proposed_at, ts());

        let nil =
            propose(action_input(Uuid::nil(), AccountabilityActionType::Censure)).unwrap_err();
        assert!(matches!(nil, ForumError::InvalidProvenance { .. }));

        let zero_time = propose(AccountabilityInput {
            proposed_at: Timestamp::ZERO,
            ..action_input(Uuid::from_u128(23), AccountabilityActionType::Censure)
        })
        .unwrap_err();
        assert!(matches!(zero_time, ForumError::InvalidProvenance { .. }));

        let zero_evidence = propose(AccountabilityInput {
            evidence_hash: Hash256::ZERO,
            ..action_input(Uuid::from_u128(24), AccountabilityActionType::Censure)
        })
        .unwrap_err();
        assert!(matches!(
            zero_evidence,
            ForumError::InvalidProvenance { .. }
        ));
    }

    #[test]
    fn propose_censure() {
        let a = make_action(AccountabilityActionType::Censure);
        assert_eq!(a.status, AccountabilityStatus::Proposed);
        assert_eq!(a.action_type, AccountabilityActionType::Censure);
    }

    #[test]
    fn due_process_flow() {
        let mut a = make_action(AccountabilityActionType::Recall);
        begin_due_process(&mut a).expect("ok");
        assert_eq!(a.status, AccountabilityStatus::DueProcess);
    }

    #[test]
    fn enact_after_due_process() {
        let mut a = make_action(AccountabilityActionType::Revocation);
        begin_due_process(&mut a).expect("ok");
        let enact_ts = Timestamp::new(ts().physical_ms + 1000, 0);
        enact(&mut a, Uuid::new_v4(), enact_ts).expect("ok");
        assert_eq!(a.status, AccountabilityStatus::Enacted);
        assert!(a.enacted_at.is_some());
    }

    #[test]
    fn suspension_must_be_immediate() {
        let mut a = make_action(AccountabilityActionType::Suspension);
        // Enact within 60s — should work
        let fast_ts = Timestamp::new(ts().physical_ms + 30_000, 0);
        enact(&mut a, Uuid::new_v4(), fast_ts).expect("ok");
    }

    #[test]
    fn suspension_too_slow_fails() {
        let mut a = make_action(AccountabilityActionType::Suspension);
        let slow_ts = Timestamp::new(ts().physical_ms + 120_000, 0);
        let err = enact(&mut a, Uuid::new_v4(), slow_ts).unwrap_err();
        assert!(err.to_string().contains("60s"));
    }

    #[test]
    fn reverse_enacted() {
        let mut a = make_action(AccountabilityActionType::Censure);
        let enact_ts = Timestamp::new(ts().physical_ms + 100, 0);
        enact(&mut a, Uuid::new_v4(), enact_ts).expect("ok");
        reverse(&mut a).expect("ok");
        assert_eq!(a.status, AccountabilityStatus::Reversed);
    }

    #[test]
    fn reverse_not_enacted_fails() {
        let mut a = make_action(AccountabilityActionType::Censure);
        assert!(reverse(&mut a).is_err());
    }

    #[test]
    fn due_process_expiry() {
        let mut a = make_action(AccountabilityActionType::Recall);
        begin_due_process(&mut a).expect("ok");
        let before = Timestamp::new(a.due_process_deadline.physical_ms - 1000, 0);
        assert!(!is_due_process_expired(&a, &before));
        let after = Timestamp::new(a.due_process_deadline.physical_ms + 1000, 0);
        assert!(is_due_process_expired(&a, &after));
    }

    #[test]
    fn double_due_process_fails() {
        let mut a = make_action(AccountabilityActionType::Censure);
        begin_due_process(&mut a).expect("ok");
        assert!(begin_due_process(&mut a).is_err());
    }
}
