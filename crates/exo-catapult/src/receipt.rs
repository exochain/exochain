//! Trust receipts for franchise operations.
//!
//! Every material Catapult operation produces a cryptographically chained
//! receipt anchored in the ExoChain DAG for immutable provenance.

use exo_core::{Did, Hash256, PublicKey, SecretKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{CatapultError, Result},
    oda::OdaSlot,
    phase::OperationalPhase,
};

/// Domain tag for Catapult franchise receipt signatures.
pub const FRANCHISE_RECEIPT_SIGNATURE_DOMAIN: &str = "exo.catapult.franchise_receipt.v1";
const FRANCHISE_RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

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

/// Caller-supplied content for a signed franchise receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FranchiseReceiptInput {
    pub id: Uuid,
    pub newco_id: Uuid,
    pub operation: FranchiseOperation,
    pub actor_did: Did,
    pub timestamp: Timestamp,
    pub state_hash: Hash256,
    pub prev_receipt: Hash256,
}

impl FranchiseReceipt {
    /// Create a signed receipt from caller-supplied deterministic metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if the receipt contains placeholder metadata
    /// or if canonical CBOR serialization fails.
    pub fn signed(input: FranchiseReceiptInput, secret_key: &SecretKey) -> Result<Self> {
        validate_receipt_input(&input)?;
        let payload = franchise_receipt_signing_payload(&input)?;
        Ok(Self {
            id: input.id,
            newco_id: input.newco_id,
            operation: input.operation,
            actor_did: input.actor_did,
            timestamp: input.timestamp,
            state_hash: input.state_hash,
            prev_receipt: input.prev_receipt,
            signature: crypto::sign(&payload, secret_key),
        })
    }

    /// Compute the content hash of this receipt (excluding the signature).
    ///
    /// # Errors
    /// Returns [`CatapultError`] if canonical CBOR hashing fails.
    pub fn content_hash(&self) -> Result<Hash256> {
        receipt_content_hash(&self.input())
    }

    /// Whether this receipt has been signed.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Verify this receipt's Ed25519 signature against the actor public key.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if canonical CBOR serialization fails.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<bool> {
        if self.signature.is_empty() {
            return Ok(false);
        }
        let input = self.input();
        validate_receipt_input(&input)?;
        let payload = franchise_receipt_signing_payload(&input)?;
        Ok(crypto::verify(&payload, &self.signature, public_key))
    }

    fn input(&self) -> FranchiseReceiptInput {
        FranchiseReceiptInput {
            id: self.id,
            newco_id: self.newco_id,
            operation: self.operation.clone(),
            actor_did: self.actor_did.clone(),
            timestamp: self.timestamp,
            state_hash: self.state_hash,
            prev_receipt: self.prev_receipt,
        }
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

    /// Append a receipt after verifying its signature and hash-chain linkage.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if the signature is invalid or the previous
    /// receipt hash does not match the current tip.
    pub fn append(
        &mut self,
        receipt: FranchiseReceipt,
        actor_public_key: &PublicKey,
    ) -> Result<()> {
        if !receipt.verify_signature(actor_public_key)? {
            return Err(CatapultError::InvalidReceipt {
                reason: format!(
                    "receipt {} signature does not verify for actor {}",
                    receipt.id, receipt.actor_did
                ),
            });
        }
        let expected_prev = self.tip_hash()?;
        if receipt.prev_receipt != expected_prev {
            return Err(CatapultError::ReceiptChainBroken {
                index: self.receipts.len(),
            });
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// The hash of the most recent receipt, or `Hash256::ZERO` if empty.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if canonical CBOR hashing fails.
    pub fn tip_hash(&self) -> Result<Hash256> {
        self.receipts
            .last()
            .map_or(Ok(Hash256::ZERO), |r| r.content_hash())
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
    ///
    /// # Errors
    /// Returns [`CatapultError`] if canonical CBOR hashing fails.
    pub fn verify_chain(&self) -> Result<bool> {
        let mut expected_prev = Hash256::ZERO;
        for receipt in &self.receipts {
            if receipt.prev_receipt != expected_prev {
                return Ok(false);
            }
            expected_prev = receipt.content_hash()?;
        }
        Ok(true)
    }

    /// Iterate over all receipts in order.
    pub fn iter(&self) -> impl Iterator<Item = &FranchiseReceipt> {
        self.receipts.iter()
    }
}

/// Compute the canonical content hash for a receipt input.
///
/// # Errors
/// Returns [`CatapultError`] if canonical CBOR hashing fails.
pub fn receipt_content_hash(input: &FranchiseReceiptInput) -> Result<Hash256> {
    validate_receipt_input(input)?;
    exo_core::hash::hash_structured(&FranchiseReceiptHashPayload::from_input(input)).map_err(|e| {
        CatapultError::ReceiptSerializationFailed {
            reason: format!("franchise receipt hash CBOR serialization failed: {e}"),
        }
    })
}

/// Build the canonical CBOR signing payload for a franchise receipt.
///
/// # Errors
/// Returns [`CatapultError`] if canonical CBOR serialization fails.
pub fn franchise_receipt_signing_payload(input: &FranchiseReceiptInput) -> Result<Vec<u8>> {
    validate_receipt_input(input)?;
    let payload = FranchiseReceiptHashPayload::from_input(input);
    let mut encoded = Vec::new();
    ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
        CatapultError::ReceiptSerializationFailed {
            reason: format!("franchise receipt signing payload CBOR serialization failed: {e}"),
        }
    })?;
    Ok(encoded)
}

#[derive(Serialize)]
struct FranchiseReceiptHashPayload<'a> {
    domain: &'static str,
    schema_version: &'static str,
    id: Uuid,
    newco_id: Uuid,
    operation: &'a FranchiseOperation,
    actor_did: &'a Did,
    timestamp: Timestamp,
    state_hash: Hash256,
    prev_receipt: Hash256,
}

impl<'a> FranchiseReceiptHashPayload<'a> {
    fn from_input(input: &'a FranchiseReceiptInput) -> Self {
        Self {
            domain: FRANCHISE_RECEIPT_SIGNATURE_DOMAIN,
            schema_version: FRANCHISE_RECEIPT_SCHEMA_VERSION,
            id: input.id,
            newco_id: input.newco_id,
            operation: &input.operation,
            actor_did: &input.actor_did,
            timestamp: input.timestamp,
            state_hash: input.state_hash,
            prev_receipt: input.prev_receipt,
        }
    }
}

fn validate_receipt_input(input: &FranchiseReceiptInput) -> Result<()> {
    if input.id.is_nil() {
        return Err(CatapultError::InvalidReceipt {
            reason: "receipt id must be caller-supplied and non-nil".into(),
        });
    }
    if input.newco_id.is_nil() {
        return Err(CatapultError::InvalidReceipt {
            reason: "receipt newco id must be non-nil".into(),
        });
    }
    if input.timestamp == Timestamp::ZERO {
        return Err(CatapultError::InvalidReceipt {
            reason: "receipt timestamp must be caller-supplied HLC".into(),
        });
    }
    if input.state_hash == Hash256::ZERO {
        return Err(CatapultError::InvalidReceipt {
            reason: "receipt state hash must not be zero".into(),
        });
    }
    validate_operation(&input.operation)
}

fn validate_operation(operation: &FranchiseOperation) -> Result<()> {
    let invalid_uuid = |name: &str| CatapultError::InvalidReceipt {
        reason: format!("receipt operation {name} must be non-nil"),
    };
    match operation {
        FranchiseOperation::BlueprintPublished { blueprint_id } if blueprint_id.is_nil() => {
            Err(invalid_uuid("blueprint_id"))
        }
        FranchiseOperation::NewcoCreated { franchise_id } if franchise_id.is_nil() => {
            Err(invalid_uuid("franchise_id"))
        }
        FranchiseOperation::BudgetPolicyUpdated { policy_id } if policy_id.is_nil() => {
            Err(invalid_uuid("policy_id"))
        }
        FranchiseOperation::CostRecorded {
            event_id,
            amount_cents,
        } => {
            if event_id.is_nil() {
                return Err(invalid_uuid("event_id"));
            }
            if *amount_cents == 0 {
                return Err(CatapultError::InvalidReceipt {
                    reason: "receipt cost amount must be greater than zero".into(),
                });
            }
            Ok(())
        }
        FranchiseOperation::GoalCreated { goal_id }
        | FranchiseOperation::GoalCompleted { goal_id }
            if goal_id.is_nil() =>
        {
            Err(invalid_uuid("goal_id"))
        }
        FranchiseOperation::FranchiseReplicated {
            source_newco_id,
            target_newco_id,
        } => {
            if source_newco_id.is_nil() {
                return Err(invalid_uuid("source_newco_id"));
            }
            if target_newco_id.is_nil() {
                return Err(invalid_uuid("target_newco_id"));
            }
            if source_newco_id == target_newco_id {
                return Err(CatapultError::InvalidReceipt {
                    reason: "franchise replication source and target must differ".into(),
                });
            }
            Ok(())
        }
        FranchiseOperation::PaceEscalation {
            from_level,
            to_level,
        } => {
            if from_level.trim().is_empty() || to_level.trim().is_empty() {
                return Err(CatapultError::InvalidReceipt {
                    reason: "PACE escalation levels must not be empty".into(),
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-actor").unwrap()
    }

    fn uuid(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn keypair(seed: u8) -> exo_core::crypto::KeyPair {
        exo_core::crypto::KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }

    fn receipt_input(
        id: Uuid,
        newco_id: Uuid,
        op: FranchiseOperation,
        prev: Hash256,
    ) -> FranchiseReceiptInput {
        FranchiseReceiptInput {
            id,
            newco_id,
            operation: op,
            actor_did: test_did(),
            timestamp: ts(1000),
            state_hash: Hash256::digest(b"state"),
            prev_receipt: prev,
        }
    }

    #[test]
    fn signed_receipt_verifies_with_actor_key() {
        let signer = keypair(1);
        let receipt = FranchiseReceipt::signed(
            receipt_input(
                uuid(1),
                uuid(10),
                FranchiseOperation::NewcoCreated {
                    franchise_id: uuid(20),
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();

        assert!(receipt.is_signed());
        assert_ne!(receipt.content_hash().unwrap(), Hash256::ZERO);
        assert!(receipt.verify_signature(signer.public_key()).unwrap());
    }

    #[test]
    fn signed_receipt_rejects_wrong_key_and_tamper() {
        let signer = keypair(2);
        let wrong = keypair(3);
        let mut receipt = FranchiseReceipt::signed(
            receipt_input(
                uuid(2),
                uuid(10),
                FranchiseOperation::AgentHired {
                    slot: OdaSlot::HrPeopleOps1,
                    agent_did: test_did(),
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();

        assert!(!receipt.verify_signature(wrong.public_key()).unwrap());

        receipt.operation = FranchiseOperation::AgentReleased {
            slot: OdaSlot::HrPeopleOps1,
            agent_did: test_did(),
        };
        assert!(!receipt.verify_signature(signer.public_key()).unwrap());
    }

    #[test]
    fn receipt_content_hash_covers_actor_and_operation() {
        let base = receipt_input(
            uuid(3),
            uuid(10),
            FranchiseOperation::NewcoCreated {
                franchise_id: uuid(20),
            },
            Hash256::ZERO,
        );
        let actor_changed = FranchiseReceiptInput {
            actor_did: Did::new("did:exo:other-actor").unwrap(),
            ..base.clone()
        };
        let operation_changed = FranchiseReceiptInput {
            operation: FranchiseOperation::GoalCompleted { goal_id: uuid(30) },
            ..base.clone()
        };

        assert_ne!(
            receipt_content_hash(&base).unwrap(),
            receipt_content_hash(&actor_changed).unwrap()
        );
        assert_ne!(
            receipt_content_hash(&base).unwrap(),
            receipt_content_hash(&operation_changed).unwrap()
        );
    }

    #[test]
    fn receipt_rejects_placeholder_metadata() {
        let signer = keypair(4);
        assert!(
            FranchiseReceipt::signed(
                receipt_input(
                    Uuid::nil(),
                    uuid(10),
                    FranchiseOperation::NewcoCreated {
                        franchise_id: uuid(20),
                    },
                    Hash256::ZERO,
                ),
                signer.secret_key(),
            )
            .is_err()
        );
        assert!(
            FranchiseReceipt::signed(
                receipt_input(
                    uuid(4),
                    Uuid::nil(),
                    FranchiseOperation::NewcoCreated {
                        franchise_id: uuid(20),
                    },
                    Hash256::ZERO,
                ),
                signer.secret_key(),
            )
            .is_err()
        );
        assert!(
            FranchiseReceipt::signed(
                receipt_input(
                    uuid(5),
                    uuid(10),
                    FranchiseOperation::NewcoCreated {
                        franchise_id: Uuid::nil(),
                    },
                    Hash256::ZERO,
                ),
                signer.secret_key(),
            )
            .is_err()
        );
        let mut input = receipt_input(
            uuid(6),
            uuid(10),
            FranchiseOperation::NewcoCreated {
                franchise_id: uuid(20),
            },
            Hash256::ZERO,
        );
        input.timestamp = Timestamp::ZERO;
        assert!(FranchiseReceipt::signed(input, signer.secret_key()).is_err());
    }

    #[test]
    fn receipt_rejects_invalid_operation_payloads() {
        let signer = keypair(9);
        let invalid_operations = [
            FranchiseOperation::BlueprintPublished {
                blueprint_id: Uuid::nil(),
            },
            FranchiseOperation::BudgetPolicyUpdated {
                policy_id: Uuid::nil(),
            },
            FranchiseOperation::CostRecorded {
                event_id: Uuid::nil(),
                amount_cents: 1,
            },
            FranchiseOperation::CostRecorded {
                event_id: uuid(30),
                amount_cents: 0,
            },
            FranchiseOperation::GoalCreated {
                goal_id: Uuid::nil(),
            },
            FranchiseOperation::GoalCompleted {
                goal_id: Uuid::nil(),
            },
            FranchiseOperation::FranchiseReplicated {
                source_newco_id: Uuid::nil(),
                target_newco_id: uuid(31),
            },
            FranchiseOperation::FranchiseReplicated {
                source_newco_id: uuid(31),
                target_newco_id: Uuid::nil(),
            },
            FranchiseOperation::FranchiseReplicated {
                source_newco_id: uuid(31),
                target_newco_id: uuid(31),
            },
            FranchiseOperation::PaceEscalation {
                from_level: " ".into(),
                to_level: "incident command".into(),
            },
        ];

        for (index, operation) in invalid_operations.into_iter().enumerate() {
            let id = uuid(100 + u128::try_from(index).unwrap());
            assert!(
                FranchiseReceipt::signed(
                    receipt_input(id, uuid(10), operation, Hash256::ZERO),
                    signer.secret_key(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn unsigned_receipt_fails_signature_verification() {
        let signer = keypair(10);
        let mut receipt = FranchiseReceipt::signed(
            receipt_input(
                uuid(90),
                uuid(10),
                FranchiseOperation::HeartbeatRecorded {
                    agent_did: test_did(),
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();
        receipt.signature = Signature::Empty;

        assert!(!receipt.is_signed());
        assert!(!receipt.verify_signature(signer.public_key()).unwrap());
    }

    #[test]
    fn chain_append_requires_valid_signature_and_prev_hash() {
        let signer = keypair(5);
        let wrong = keypair(6);
        let newco_id = uuid(10);
        let mut chain = ReceiptChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.tip_hash().unwrap(), Hash256::ZERO);

        let r1 = FranchiseReceipt::signed(
            receipt_input(
                uuid(7),
                newco_id,
                FranchiseOperation::NewcoCreated {
                    franchise_id: uuid(20),
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();
        let r1_hash = r1.content_hash().unwrap();
        chain.append(r1, signer.public_key()).unwrap();

        let r2 = FranchiseReceipt::signed(
            receipt_input(
                uuid(8),
                newco_id,
                FranchiseOperation::AgentHired {
                    slot: OdaSlot::HrPeopleOps1,
                    agent_did: test_did(),
                },
                r1_hash,
            ),
            signer.secret_key(),
        )
        .unwrap();
        assert!(chain.append(r2.clone(), wrong.public_key()).is_err());
        chain.append(r2, signer.public_key()).unwrap();

        assert_eq!(chain.len(), 2);
        assert!(chain.verify_chain().unwrap());
    }

    #[test]
    fn chain_append_rejects_replayed_receipt() {
        let signer = keypair(7);
        let newco_id = uuid(10);
        let mut chain = ReceiptChain::new();
        let r1 = FranchiseReceipt::signed(
            receipt_input(
                uuid(9),
                newco_id,
                FranchiseOperation::NewcoCreated {
                    franchise_id: uuid(20),
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();
        chain.append(r1.clone(), signer.public_key()).unwrap();
        assert!(chain.append(r1, signer.public_key()).is_err());
    }

    #[test]
    fn chain_verify_detects_broken_prev_hash() {
        let signer = keypair(8);
        let newco_id = uuid(10);
        let mut chain = ReceiptChain::new();
        let r1 = FranchiseReceipt::signed(
            receipt_input(
                uuid(11),
                newco_id,
                FranchiseOperation::NewcoCreated {
                    franchise_id: uuid(20),
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();
        let r2 = FranchiseReceipt::signed(
            receipt_input(
                uuid(12),
                newco_id,
                FranchiseOperation::PhaseTransition {
                    from: OperationalPhase::Assessment,
                    to: OperationalPhase::Selection,
                },
                Hash256::ZERO,
            ),
            signer.secret_key(),
        )
        .unwrap();
        chain.receipts.push(r1);
        chain.receipts.push(r2);

        assert!(!chain.verify_chain().unwrap());
    }

    #[test]
    fn signing_payload_is_domain_separated_and_deterministic() {
        let input = receipt_input(
            uuid(13),
            uuid(10),
            FranchiseOperation::NewcoCreated {
                franchise_id: uuid(20),
            },
            Hash256::ZERO,
        );
        let first = franchise_receipt_signing_payload(&input).unwrap();
        let second = franchise_receipt_signing_payload(&input).unwrap();
        assert_eq!(first, second);
        assert!(
            first
                .windows(FRANCHISE_RECEIPT_SIGNATURE_DOMAIN.len())
                .any(|window| window == FRANCHISE_RECEIPT_SIGNATURE_DOMAIN.as_bytes())
        );
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
