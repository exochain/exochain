//! Syntaxis workflow integration.
//!
//! Maps each decision lifecycle phase to a workflow stage with receipt
//! generation at each stage.

use exo_core::{
    bcts::BctsState,
    hash::hash_structured,
    types::{Hash256, Timestamp},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ForumError, Result};

const WORKFLOW_RECEIPT_HASH_DOMAIN: &str = "decision.forum.workflow_receipt.v1";
const WORKFLOW_RECEIPT_HASH_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkflowReceiptHashPayload {
    domain: &'static str,
    schema_version: u16,
    workflow_id: Uuid,
    stage: BctsState,
    decision_id: Uuid,
    timestamp: Timestamp,
}

fn workflow_receipt_hash_payload(
    workflow_id: Uuid,
    stage: BctsState,
    decision_id: Uuid,
    timestamp: Timestamp,
) -> WorkflowReceiptHashPayload {
    WorkflowReceiptHashPayload {
        domain: WORKFLOW_RECEIPT_HASH_DOMAIN,
        schema_version: WORKFLOW_RECEIPT_HASH_SCHEMA_VERSION,
        workflow_id,
        stage,
        decision_id,
        timestamp,
    }
}

/// Generate a receipt for a workflow stage.
pub fn generate_receipt(
    workflow_id: Uuid,
    stage: BctsState,
    decision_id: Uuid,
    timestamp: Timestamp,
) -> Result<WorkflowReceipt> {
    if workflow_id.is_nil() {
        return Err(ForumError::InvalidProvenance {
            reason: "workflow receipt workflow_id must not be nil".into(),
        });
    }
    if decision_id.is_nil() {
        return Err(ForumError::InvalidProvenance {
            reason: "workflow receipt decision_id must not be nil".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: "workflow receipt timestamp must be non-zero HLC".into(),
        });
    }
    let payload = workflow_receipt_hash_payload(workflow_id, stage, decision_id, timestamp);
    let receipt_hash = hash_structured(&payload).map_err(ForumError::from)?;
    Ok(WorkflowReceipt {
        workflow_id,
        stage,
        decision_id,
        timestamp,
        receipt_hash,
    })
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
    fn workflow_receipt_hash_payload_is_domain_separated_cbor() {
        let wf_id = Uuid::from_u128(90);
        let dec_id = Uuid::from_u128(91);
        let ts = Timestamp::new(1000, 1);
        let payload = workflow_receipt_hash_payload(wf_id, BctsState::Submitted, dec_id, ts);
        assert_eq!(payload.domain, WORKFLOW_RECEIPT_HASH_DOMAIN);
        assert_eq!(payload.schema_version, WORKFLOW_RECEIPT_HASH_SCHEMA_VERSION);
        assert_eq!(payload.workflow_id, wf_id);
        assert_eq!(payload.decision_id, dec_id);
        assert_eq!(payload.stage, BctsState::Submitted);
        assert_eq!(payload.timestamp, ts);
    }

    #[test]
    fn workflow_receipt_rejects_legacy_raw_concat_hash() {
        let wf_id = Uuid::from_u128(92);
        let dec_id = Uuid::from_u128(93);
        let ts = Timestamp::new(1000, 1);
        let receipt = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts).expect("receipt");
        let mut hasher = blake3::Hasher::new();
        hasher.update(wf_id.as_bytes());
        hasher.update(dec_id.as_bytes());
        hasher.update(&ts.physical_ms.to_le_bytes());
        hasher.update(&u64::from(ts.logical).to_le_bytes());
        hasher.update(format!("{:?}", BctsState::Submitted).as_bytes());
        let legacy = Hash256::from_bytes(*hasher.finalize().as_bytes());
        assert_ne!(receipt.receipt_hash, legacy);
    }

    #[test]
    fn generate_receipt_rejects_placeholder_inputs() {
        let ts = Timestamp::new(1000, 1);
        let err = generate_receipt(Uuid::nil(), BctsState::Submitted, Uuid::from_u128(94), ts)
            .unwrap_err();
        assert!(matches!(err, ForumError::InvalidProvenance { .. }));

        let err = generate_receipt(Uuid::from_u128(95), BctsState::Submitted, Uuid::nil(), ts)
            .unwrap_err();
        assert!(matches!(err, ForumError::InvalidProvenance { .. }));

        let err = generate_receipt(
            Uuid::from_u128(96),
            BctsState::Submitted,
            Uuid::from_u128(97),
            Timestamp::ZERO,
        )
        .unwrap_err();
        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
    }

    #[test]
    fn workflow_production_source_has_no_raw_receipt_hashing() {
        let production = include_str!("workflow.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(!production.contains("blake3::Hasher"));
        assert!(!production.contains("hasher.update"));
        assert!(!production.contains("format!(\"{stage:?}\""));
    }

    #[test]
    fn generate_receipt_deterministic() {
        let wf_id = Uuid::from_u128(98);
        let dec_id = Uuid::from_u128(99);
        let ts = Timestamp::new(1000, 1);
        let r1 = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts).expect("receipt");
        let r2 = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts).expect("receipt");
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_differs_per_stage() {
        let wf_id = Uuid::from_u128(100);
        let dec_id = Uuid::from_u128(101);
        let ts = Timestamp::new(1000, 1);
        let r1 = generate_receipt(wf_id, BctsState::Submitted, dec_id, ts).expect("receipt");
        let r2 = generate_receipt(wf_id, BctsState::Approved, dec_id, ts).expect("receipt");
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
