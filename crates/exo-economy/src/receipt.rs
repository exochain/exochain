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

//! Settlement receipts — signed, hash-chained records of a settled
//! quote. Receipts exist for zero-priced settlements as well so trust
//! is never paywalled.

use exo_core::{Did, Hash256, Signature, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    error::EconomyError,
    revenue_share::RevenueShareLine,
    types::{EventClass, MicroExo, ZeroFeeReason},
};

/// Domain tag used when computing the canonical settlement-receipt hash.
pub const SETTLEMENT_RECEIPT_HASH_DOMAIN: &str = "exo.economy.settlement_receipt.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub id: String,
    pub quote_hash: Hash256,
    pub actor_did: Did,
    pub event_class: EventClass,
    pub charged_amount_micro_exo: MicroExo,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub revenue_shares: Vec<RevenueShareLine>,
    pub custody_transaction_hash: Hash256,
    pub prev_settlement_receipt: Hash256,
    pub timestamp: Timestamp,
    pub content_hash: Hash256,
    pub signature: Signature,
}

#[derive(Serialize)]
struct ReceiptHashPayload<'a> {
    domain: &'static str,
    id: &'a str,
    quote_hash: &'a Hash256,
    actor_did: &'a Did,
    event_class: &'a EventClass,
    charged_amount_micro_exo: MicroExo,
    zero_fee_reason: Option<&'a ZeroFeeReason>,
    revenue_shares: &'a [RevenueShareLine],
    custody_transaction_hash: &'a Hash256,
    prev_settlement_receipt: &'a Hash256,
    timestamp: &'a Timestamp,
}

impl SettlementReceipt {
    /// Recompute the canonical content hash for this receipt and check
    /// that it matches `content_hash`.
    ///
    /// # Errors
    /// Returns [`EconomyError::Serialization`] when CBOR encoding fails.
    pub fn verify_content_hash(&self) -> Result<bool, EconomyError> {
        Ok(canonical_content_hash(self)? == self.content_hash)
    }
}

pub(crate) fn canonical_content_hash(receipt: &SettlementReceipt) -> Result<Hash256, EconomyError> {
    let payload = ReceiptHashPayload {
        domain: SETTLEMENT_RECEIPT_HASH_DOMAIN,
        id: &receipt.id,
        quote_hash: &receipt.quote_hash,
        actor_did: &receipt.actor_did,
        event_class: &receipt.event_class,
        charged_amount_micro_exo: receipt.charged_amount_micro_exo,
        zero_fee_reason: receipt.zero_fee_reason.as_ref(),
        revenue_shares: &receipt.revenue_shares,
        custody_transaction_hash: &receipt.custody_transaction_hash,
        prev_settlement_receipt: &receipt.prev_settlement_receipt,
        timestamp: &receipt.timestamp,
    };
    hash_structured(&payload).map_err(EconomyError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EventClass;

    fn sample_receipt() -> SettlementReceipt {
        SettlementReceipt {
            id: "rec-1".into(),
            quote_hash: Hash256::from_bytes([0x11; 32]),
            actor_did: Did::new("did:exo:agent").unwrap(),
            event_class: EventClass::AvcValidate,
            charged_amount_micro_exo: 0,
            zero_fee_reason: Some(ZeroFeeReason::AgentValidation),
            revenue_shares: vec![],
            custody_transaction_hash: Hash256::from_bytes([0x22; 32]),
            prev_settlement_receipt: Hash256::ZERO,
            timestamp: Timestamp::new(1_000, 0),
            content_hash: Hash256::ZERO,
            signature: Signature::empty(),
        }
    }

    #[test]
    fn canonical_content_hash_is_deterministic() {
        let r = sample_receipt();
        let h1 = canonical_content_hash(&r).unwrap();
        let h2 = canonical_content_hash(&r).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, Hash256::ZERO);
    }

    #[test]
    fn canonical_content_hash_changes_when_field_changes() {
        let r1 = sample_receipt();
        let mut r2 = r1.clone();
        r2.id = "rec-2".into();
        assert_ne!(
            canonical_content_hash(&r1).unwrap(),
            canonical_content_hash(&r2).unwrap()
        );
    }

    #[test]
    fn verify_content_hash_returns_true_after_set() {
        let mut r = sample_receipt();
        r.content_hash = canonical_content_hash(&r).unwrap();
        assert!(r.verify_content_hash().unwrap());
    }

    #[test]
    fn verify_content_hash_returns_false_when_field_tampered() {
        let mut r = sample_receipt();
        r.content_hash = canonical_content_hash(&r).unwrap();
        r.charged_amount_micro_exo = 1;
        assert!(!r.verify_content_hash().unwrap());
    }
}
