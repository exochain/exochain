//! Syntaxis workflow integration.
//!
//! Maps each decision lifecycle phase to a workflow stage with receipt
//! generation at each stage.

use exo_core::{
    bcts::BctsState,
    types::{Hash256, Timestamp},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ForumError, Result};

/// A workflow stage corresponding to a BCTS state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    pub state: BctsState,
    pub name: String,
    pub description: String,
    pub requires_receipt: bool,
}

/// A complete workflow definition for decision lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub id: Uuid,
    pub name: String,
    pub stages: Vec<WorkflowStage>,
}

impl WorkflowDefinition {
    /// Create the standard decision governance workflow.
    pub fn standard_governance(id: Uuid) -> Result<Self> {
        if id.is_nil() {
            return Err(ForumError::InvalidProvenance {
                reason: "workflow id must not be nil".into(),
            });
        }
        let stages = vec![
            WorkflowStage {
                state: BctsState::Draft,
                name: "Draft".into(),
                description: "Initial proposal creation".into(),
                requires_receipt: false,
            },
            WorkflowStage {
                state: BctsState::Submitted,
                name: "Submitted".into(),
                description: "Proposal submitted for review".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::IdentityResolved,
                name: "Identity Resolved".into(),
                description: "Actor identities verified".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::ConsentValidated,
                name: "Consent Validated".into(),
                description: "All required consents collected".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Deliberated,
                name: "Deliberated".into(),
                description: "Discussion and debate completed".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Verified,
                name: "Verified".into(),
                description: "Evidence and authority verified".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Governed,
                name: "Governed".into(),
                description: "Constitutional compliance confirmed".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Approved,
                name: "Approved".into(),
                description: "Decision approved by quorum".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Executed,
                name: "Executed".into(),
                description: "Decision enacted".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Recorded,
                name: "Recorded".into(),
                description: "Decision recorded in permanent ledger".into(),
                requires_receipt: true,
            },
            WorkflowStage {
                state: BctsState::Closed,
                name: "Closed".into(),
                description: "Decision lifecycle complete".into(),
                requires_receipt: true,
            },
        ];
        Ok(Self {
            id,
            name: "Standard Governance Workflow".into(),
            stages,
        })
    }

    /// Find the stage definition for a given BCTS state.
    #[must_use]
    pub fn stage_for(&self, state: BctsState) -> Option<&WorkflowStage> {
        self.stages.iter().find(|s| s.state == state)
    }

    /// Get the next stage after a given state in the workflow.
    #[must_use]
    pub fn next_stage(&self, current: BctsState) -> Option<&WorkflowStage> {
        let pos = self.stages.iter().position(|s| s.state == current)?;
        self.stages.get(pos + 1)
    }

    /// Check if a state requires a receipt in this workflow.
    #[must_use]
    pub fn requires_receipt(&self, state: BctsState) -> bool {
        self.stage_for(state).is_some_and(|s| s.requires_receipt)
    }

    /// Number of stages in this workflow.
    #[must_use]
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

/// A workflow receipt generated at a stage transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReceipt {
    pub workflow_id: Uuid,
    pub stage: BctsState,
    pub decision_id: Uuid,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash256,
}

/// Generate a receipt for a workflow stage.
#[must_use]
pub fn generate_receipt(
    workflow_id: Uuid,
    stage: BctsState,
    decision_id: Uuid,
    timestamp: Timestamp,
) -> WorkflowReceipt {
    let mut hasher = blake3::Hasher::new();
    hasher.update(workflow_id.as_bytes());
    hasher.update(decision_id.as_bytes());
    hasher.update(&timestamp.physical_ms.to_le_bytes());
    hasher.update(&u64::from(timestamp.logical).to_le_bytes());
    hasher.update(format!("{stage:?}").as_bytes());
    WorkflowReceipt {
        workflow_id,
        stage,
        decision_id,
        timestamp,
        receipt_hash: Hash256::from_bytes(*hasher.finalize().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_workflow_has_all_stages() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(80)).expect("valid");
        assert_eq!(wf.stage_count(), 11);
        assert!(wf.stage_for(BctsState::Draft).is_some());
        assert!(wf.stage_for(BctsState::Closed).is_some());
    }

    #[test]
    fn standard_workflow_requires_caller_supplied_identity() {
        let err = WorkflowDefinition::standard_governance(Uuid::nil()).unwrap_err();
        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
    }

    #[test]
    fn next_stage() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(81)).expect("valid");
        let next = wf.next_stage(BctsState::Draft).expect("should exist");
        assert_eq!(next.state, BctsState::Submitted);
    }

    #[test]
    fn next_stage_from_closed_is_none() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(82)).expect("valid");
        assert!(wf.next_stage(BctsState::Closed).is_none());
    }

    #[test]
    fn draft_no_receipt() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(83)).expect("valid");
        assert!(!wf.requires_receipt(BctsState::Draft));
    }

    #[test]
    fn submitted_requires_receipt() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(84)).expect("valid");
        assert!(wf.requires_receipt(BctsState::Submitted));
    }

    #[test]
    fn generate_receipt_deterministic() {
        let wf_id = Uuid::nil();
        let dec_id = Uuid::nil();
        let ts = Timestamp::new(1000, 0);
        let r1 = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts);
        let r2 = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_differs_per_stage() {
        let wf_id = Uuid::nil();
        let dec_id = Uuid::nil();
        let ts = Timestamp::new(1000, 0);
        let r1 = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts);
        let r2 = generate_receipt(wf_id, BctsState::Approved, dec_id, ts);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn unknown_state_not_found() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(85)).expect("valid");
        // Escalated is not in the standard workflow
        assert!(wf.stage_for(BctsState::Escalated).is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let wf = WorkflowDefinition::standard_governance(Uuid::from_u128(86)).expect("valid");
        let json = serde_json::to_string(&wf).expect("ser");
        let wf2: WorkflowDefinition = serde_json::from_str(&json).expect("de");
        assert_eq!(wf2.stage_count(), wf.stage_count());
    }
}
