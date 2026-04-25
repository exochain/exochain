//! Trust receipts for franchise operations.
//!
//! Every material Catapult operation produces a cryptographically chained
//! receipt anchored in the ExoChain DAG for immutable provenance.

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{oda::OdaSlot, phase::OperationalPhase};

/// A franchise operation that produces a trust receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FranchiseOperation {
    BlueprintPublished {
        blueprint_id: Uuid,
    },
    NewcoCreated {
        franchise_id: Uuid,
    },
    PhaseTransition {
        from: OperationalPhase,
        to: OperationalPhase,
    },
    AgentHired {
        slot: OdaSlot,
        agent_did: Did,
    },
    AgentReleased {
        slot: OdaSlot,
        agent_did: Did,
    },
    BudgetPolicyUpdated {
        policy_id: Uuid,
    },
    CostRecorded {
        event_id: Uuid,
        amount_cents: u64,
    },
    GoalCreated {
        goal_id: Uuid,
    },
    GoalCompleted {
        goal_id: Uuid,
    },
    HeartbeatRecorded {
        agent_did: Did,
    },
    PaceEscalation {
        from_level: String,
        to_level: String,
    },
    FranchiseReplicated {
        source_newco_id: Uuid,
        target_newco_id: Uuid,
    },
}

/// A cryptographically chained trust receipt for a franchise operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FranchiseReceipt {
    pub id: Uuid,
    pub newco_id: Uuid,
    pub operation: FranchiseOperation,
    pub actor_did: Did,
    pub timestamp: Timestamp,
    /// Hash of the newco state after this operation.
    pub state_hash: Hash256,
    /// Hash of the previous receipt — forms a hash chain.
    pub prev_receipt: Hash256,
    /// Cryptographic signature of this receipt.
    pub signature: Signature,
}

impl FranchiseReceipt {
    /// Create a new receipt (unsigned — signature is `Empty` until signed).
    #[must_use]
    pub fn new(
        newco_id: Uuid,
        operation: FranchiseOperation,
        actor_did: Did,
        timestamp: Timestamp,
        state_hash: Hash256,
        prev_receipt: Hash256,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            newco_id,
            operation,
            actor_did,
            timestamp,
            state_hash,
            prev_receipt,
            signature: Signature::empty(),
        }
    }

    /// Compute the content hash of this receipt (excluding the signature).
    #[must_use]
    pub fn content_hash(&self) -> Hash256 {
        // Serialize the content fields deterministically
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(self.newco_id.as_bytes());
        data.extend_from_slice(self.state_hash.as_bytes());
        data.extend_from_slice(self.prev_receipt.as_bytes());
        data.extend_from_slice(&self.timestamp.physical_ms.to_le_bytes());
        data.extend_from_slice(&self.timestamp.logical.to_le_bytes());
        Hash256::digest(&data)
    }

    /// Whether this receipt has been signed.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

/// An append-only chain of franchise receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReceiptChain {
    receipts: Vec<FranchiseReceipt>,
}

impl ReceiptChain {
    /// Create an empty receipt chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Append a receipt to the chain. The receipt's `prev_receipt` should
    /// match the last receipt's content hash (or `Hash256::ZERO` for the first).
    pub fn append(&mut self, receipt: FranchiseReceipt) {
        self.receipts.push(receipt);
    }

    /// The hash of the most recent receipt, or `Hash256::ZERO` if empty.
    #[must_use]
    pub fn tip_hash(&self) -> Hash256 {
        self.receipts
            .last()
            .map_or(Hash256::ZERO, |r| r.content_hash())
    }

    /// Number of receipts in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Verify the hash chain integrity.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = Hash256::ZERO;
        for receipt in &self.receipts {
            if receipt.prev_receipt != expected_prev {
                return false;
            }
            expected_prev = receipt.content_hash();
        }
        true
    }

    /// Iterate over all receipts in order.
    pub fn iter(&self) -> impl Iterator<Item = &FranchiseReceipt> {
        self.receipts.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-actor").unwrap()
    }

    fn make_receipt(newco_id: Uuid, op: FranchiseOperation, prev: Hash256) -> FranchiseReceipt {
        FranchiseReceipt::new(
            newco_id,
            op,
            test_did(),
            Timestamp::ZERO,
            Hash256::digest(b"state"),
            prev,
        )
    }

    #[test]
    fn receipt_creation() {
        let r = make_receipt(
            Uuid::nil(),
            FranchiseOperation::NewcoCreated {
                franchise_id: Uuid::nil(),
            },
            Hash256::ZERO,
        );
        assert!(!r.is_signed());
        assert_ne!(r.content_hash(), Hash256::ZERO);
    }

    #[test]
    fn chain_integrity() {
        let newco_id = Uuid::new_v4();
        let mut chain = ReceiptChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.tip_hash(), Hash256::ZERO);

        let r1 = make_receipt(
            newco_id,
            FranchiseOperation::NewcoCreated {
                franchise_id: Uuid::nil(),
            },
            Hash256::ZERO,
        );
        let r1_hash = r1.content_hash();
        chain.append(r1);

        let r2 = make_receipt(
            newco_id,
            FranchiseOperation::AgentHired {
                slot: OdaSlot::HrPeopleOps1,
                agent_did: test_did(),
            },
            r1_hash,
        );
        chain.append(r2);

        assert_eq!(chain.len(), 2);
        assert!(chain.verify_chain());
    }

    #[test]
    fn chain_broken() {
        let newco_id = Uuid::new_v4();
        let mut chain = ReceiptChain::new();

        let r1 = make_receipt(
            newco_id,
            FranchiseOperation::NewcoCreated {
                franchise_id: Uuid::nil(),
            },
            Hash256::ZERO,
        );
        chain.append(r1);

        // Wrong prev_receipt — should break chain
        let r2 = make_receipt(
            newco_id,
            FranchiseOperation::PhaseTransition {
                from: OperationalPhase::Assessment,
                to: OperationalPhase::Selection,
            },
            Hash256::ZERO, // Wrong — should be r1's hash
        );
        chain.append(r2);

        assert!(!chain.verify_chain());
    }

    #[test]
    fn operation_serde() {
        let ops = [
            FranchiseOperation::BlueprintPublished {
                blueprint_id: Uuid::nil(),
            },
            FranchiseOperation::NewcoCreated {
                franchise_id: Uuid::nil(),
            },
            FranchiseOperation::PhaseTransition {
                from: OperationalPhase::Assessment,
                to: OperationalPhase::Selection,
            },
            FranchiseOperation::AgentHired {
                slot: OdaSlot::VentureCommander,
                agent_did: test_did(),
            },
            FranchiseOperation::CostRecorded {
                event_id: Uuid::nil(),
                amount_cents: 5000,
            },
        ];
        for op in &ops {
            let j = serde_json::to_string(op).unwrap();
            let rt: FranchiseOperation = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, op);
        }
    }
}
