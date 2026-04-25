//! Catapult-specific errors.
use thiserror::Error;
use uuid::Uuid;

use crate::{oda::OdaSlot, phase::OperationalPhase};

/// Errors returned by Catapult franchise operations.
#[derive(Debug, Error)]
pub enum CatapultError {
    #[error("franchise not found: {0}")]
    FranchiseNotFound(Uuid),
    #[error("newco not found: {0}")]
    NewcoNotFound(Uuid),
    #[error("invalid phase transition: {from:?} -> {to:?}")]
    InvalidPhaseTransition {
        from: OperationalPhase,
        to: OperationalPhase,
    },
    #[error("roster incomplete for phase {phase:?}: need {needed}, have {have}")]
    RosterIncomplete {
        phase: OperationalPhase,
        needed: usize,
        have: usize,
    },
    #[error("agent slot already filled: {0:?}")]
    SlotAlreadyFilled(OdaSlot),
    #[error("agent slot empty: {0:?}")]
    SlotEmpty(OdaSlot),
    #[error("budget exceeded: spent={spent_cents} limit={limit_cents}")]
    BudgetExceeded { spent_cents: u64, limit_cents: u64 },
    #[error("heartbeat timeout: agent {agent_did} last seen {elapsed_ms}ms ago")]
    HeartbeatTimeout { agent_did: String, elapsed_ms: u64 },
    #[error("goal not found: {0}")]
    GoalNotFound(Uuid),
    #[error("duplicate goal: {0}")]
    DuplicateGoal(Uuid),
    #[error("franchise already exists: {0}")]
    FranchiseAlreadyExists(Uuid),
    #[error("newco already exists: {0}")]
    NewcoAlreadyExists(Uuid),
}

/// Convenience alias for results with [`CatapultError`].
pub type Result<T> = std::result::Result<T, CatapultError>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_display() {
        let es: Vec<CatapultError> = vec![
            CatapultError::FranchiseNotFound(Uuid::nil()),
            CatapultError::NewcoNotFound(Uuid::nil()),
            CatapultError::InvalidPhaseTransition {
                from: OperationalPhase::Assessment,
                to: OperationalPhase::Execution,
            },
            CatapultError::RosterIncomplete {
                phase: OperationalPhase::Execution,
                needed: 12,
                have: 2,
            },
            CatapultError::SlotAlreadyFilled(OdaSlot::VentureCommander),
            CatapultError::SlotEmpty(OdaSlot::VentureCommander),
            CatapultError::BudgetExceeded {
                spent_cents: 100,
                limit_cents: 50,
            },
            CatapultError::HeartbeatTimeout {
                agent_did: "did:exo:test".into(),
                elapsed_ms: 600_000,
            },
            CatapultError::GoalNotFound(Uuid::nil()),
            CatapultError::DuplicateGoal(Uuid::nil()),
            CatapultError::FranchiseAlreadyExists(Uuid::nil()),
            CatapultError::NewcoAlreadyExists(Uuid::nil()),
        ];
        for e in &es {
            assert!(!e.to_string().is_empty());
        }
    }
}
