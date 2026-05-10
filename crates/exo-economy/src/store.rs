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

//! Deterministic in-memory store for quotes, receipts, and the active
//! pricing policy.
//!
//! This MVP store is designed to support the node API and unit tests.
//! Persistence is deferred to a follow-up PR.

use std::collections::BTreeMap;

use exo_core::Hash256;

use crate::{
    error::EconomyError, policy::PricingPolicy, quote::SettlementQuote, receipt::SettlementReceipt,
};

pub trait EconomyStore {
    fn put_quote(&mut self, quote: SettlementQuote) -> Result<(), EconomyError>;
    fn get_quote(&self, quote_hash: &Hash256) -> Result<Option<SettlementQuote>, EconomyError>;
    fn put_receipt(&mut self, receipt: SettlementReceipt) -> Result<(), EconomyError>;
    fn get_receipt(&self, id: &str) -> Result<Option<SettlementReceipt>, EconomyError>;
    fn get_active_policy(&self) -> Result<PricingPolicy, EconomyError>;
    fn set_active_policy(&mut self, policy: PricingPolicy) -> Result<(), EconomyError>;
    /// Returns the latest receipt's content hash, or `Hash256::ZERO`
    /// when no settlements have occurred.
    fn latest_receipt_hash(&self) -> Hash256;
}

#[derive(Debug, Clone)]
pub struct InMemoryEconomyStore {
    quotes: BTreeMap<Hash256, SettlementQuote>,
    receipts: BTreeMap<String, SettlementReceipt>,
    receipt_by_hash: BTreeMap<Hash256, String>,
    active_policy: PricingPolicy,
    latest_receipt_hash: Hash256,
}

impl InMemoryEconomyStore {
    /// Construct a store seeded with the zero-launch policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            quotes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            receipt_by_hash: BTreeMap::new(),
            active_policy: PricingPolicy::zero_launch_default(),
            latest_receipt_hash: Hash256::ZERO,
        }
    }

    /// Number of stored quotes.
    #[must_use]
    pub fn quote_count(&self) -> usize {
        self.quotes.len()
    }

    /// Number of stored receipts.
    #[must_use]
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }
}

impl Default for InMemoryEconomyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EconomyStore for InMemoryEconomyStore {
    fn put_quote(&mut self, quote: SettlementQuote) -> Result<(), EconomyError> {
        if self.quotes.contains_key(&quote.quote_hash) {
            return Err(EconomyError::InvalidInput {
                reason: format!("duplicate quote hash {}", quote.quote_hash),
            });
        }
        self.quotes.insert(quote.quote_hash, quote);
        Ok(())
    }

    fn get_quote(&self, quote_hash: &Hash256) -> Result<Option<SettlementQuote>, EconomyError> {
        Ok(self.quotes.get(quote_hash).cloned())
    }

    fn put_receipt(&mut self, receipt: SettlementReceipt) -> Result<(), EconomyError> {
        if self.receipts.contains_key(&receipt.id) {
            return Err(EconomyError::InvalidInput {
                reason: format!("duplicate settlement receipt {}", receipt.id),
            });
        }
        self.receipt_by_hash
            .insert(receipt.content_hash, receipt.id.clone());
        self.latest_receipt_hash = receipt.content_hash;
        self.receipts.insert(receipt.id.clone(), receipt);
        Ok(())
    }

    fn get_receipt(&self, id: &str) -> Result<Option<SettlementReceipt>, EconomyError> {
        Ok(self.receipts.get(id).cloned())
    }

    fn get_active_policy(&self) -> Result<PricingPolicy, EconomyError> {
        Ok(self.active_policy.clone())
    }

    fn set_active_policy(&mut self, policy: PricingPolicy) -> Result<(), EconomyError> {
        policy.validate()?;
        self.active_policy = policy;
        Ok(())
    }

    fn latest_receipt_hash(&self) -> Hash256 {
        self.latest_receipt_hash
    }
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Signature, Timestamp};

    use super::*;
    use crate::{
        policy::PricingPolicy,
        price::PricingInputs,
        quote::quote,
        settlement::{SettlementContext, settle},
        types::{ActorClass, AssuranceClass, EventClass},
    };

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    fn baseline_inputs() -> PricingInputs {
        PricingInputs {
            actor_did: Did::new("did:exo:agent").unwrap(),
            actor_class: ActorClass::Holon,
            event_class: EventClass::HolonCommercialAction,
            assurance_class: AssuranceClass::Standard,
            declared_value_micro_exo: Some(1_000_000),
            realized_value_micro_exo: None,
            compute_units: 100,
            storage_bytes: 4_096,
            verification_ops: 5,
            network_load_bp: 10_000,
            risk_bp: 1_500,
            market_domain: None,
            timestamp: Timestamp::new(1_000_000, 0),
        }
    }

    #[test]
    fn put_and_get_quote_round_trips() {
        let mut store = InMemoryEconomyStore::new();
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        store.put_quote(q.clone()).unwrap();
        let fetched = store.get_quote(&q.quote_hash).unwrap();
        assert_eq!(fetched.unwrap(), q);
        assert_eq!(store.quote_count(), 1);
    }

    #[test]
    fn put_quote_rejects_duplicate_hash() {
        let mut store = InMemoryEconomyStore::new();
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        store.put_quote(q.clone()).unwrap();
        assert!(store.put_quote(q).is_err());
    }

    #[test]
    fn missing_quote_returns_none() {
        let store = InMemoryEconomyStore::new();
        assert!(
            store
                .get_quote(&Hash256::from_bytes([0x99; 32]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn put_and_get_receipt_round_trips_and_advances_chain() {
        let mut store = InMemoryEconomyStore::new();
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let ctx = SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
            prev_settlement_receipt: store.latest_receipt_hash(),
            now: Timestamp::new(1_010_000, 0),
        };
        let receipt = settle(&q, &ctx, |_| fixed_signature()).unwrap();
        store.put_receipt(receipt.clone()).unwrap();
        let fetched = store.get_receipt("rec-1").unwrap();
        assert_eq!(fetched.unwrap(), receipt);
        assert_eq!(store.latest_receipt_hash(), receipt.content_hash);
    }

    #[test]
    fn duplicate_receipt_rejected() {
        let mut store = InMemoryEconomyStore::new();
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let ctx = SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
            prev_settlement_receipt: Hash256::ZERO,
            now: Timestamp::new(1_010_000, 0),
        };
        let receipt = settle(&q, &ctx, |_| fixed_signature()).unwrap();
        store.put_receipt(receipt.clone()).unwrap();
        assert!(store.put_receipt(receipt).is_err());
    }

    #[test]
    fn missing_receipt_returns_none() {
        let store = InMemoryEconomyStore::new();
        assert!(store.get_receipt("missing").unwrap().is_none());
    }

    #[test]
    fn active_policy_is_zero_launch_default() {
        let store = InMemoryEconomyStore::new();
        let policy = store.get_active_policy().unwrap();
        assert_eq!(policy.id, "exo.economy.zero-launch");
        assert_eq!(policy.compute_unit_price_micro_exo, 0);
    }

    #[test]
    fn set_active_policy_validates() {
        let mut store = InMemoryEconomyStore::new();
        let mut policy = PricingPolicy::zero_launch_default();
        policy.id = "".into();
        assert!(store.set_active_policy(policy).is_err());
    }

    #[test]
    fn set_active_policy_persists_when_valid() {
        let mut store = InMemoryEconomyStore::new();
        let mut policy = PricingPolicy::zero_launch_default();
        policy.version = "v2".into();
        store.set_active_policy(policy.clone()).unwrap();
        assert_eq!(store.get_active_policy().unwrap(), policy);
    }

    #[test]
    fn quote_and_receipt_counts_increment() {
        let mut store = InMemoryEconomyStore::new();
        let policy = PricingPolicy::zero_launch_default();
        assert_eq!(store.quote_count(), 0);
        assert_eq!(store.receipt_count(), 0);
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        store.put_quote(q.clone()).unwrap();
        assert_eq!(store.quote_count(), 1);
        let ctx = SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::ZERO,
            prev_settlement_receipt: Hash256::ZERO,
            now: Timestamp::new(1_010_000, 0),
        };
        let receipt = settle(&q, &ctx, |_| fixed_signature()).unwrap();
        store.put_receipt(receipt).unwrap();
        assert_eq!(store.receipt_count(), 1);
    }

    #[test]
    fn default_constructor_matches_new() {
        let a = InMemoryEconomyStore::new();
        let b = InMemoryEconomyStore::default();
        assert_eq!(a.quote_count(), b.quote_count());
        assert_eq!(a.receipt_count(), b.receipt_count());
    }

    #[test]
    fn latest_receipt_hash_chain_advances_per_settlement() {
        let mut store = InMemoryEconomyStore::new();
        assert_eq!(store.latest_receipt_hash(), Hash256::ZERO);

        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let ctx = SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
            prev_settlement_receipt: store.latest_receipt_hash(),
            now: Timestamp::new(1_010_000, 0),
        };
        let r1 = settle(&q, &ctx, |_| fixed_signature()).unwrap();
        store.put_receipt(r1.clone()).unwrap();

        let mut inputs2 = baseline_inputs();
        inputs2.compute_units = 200;
        let q2 = quote(&policy, &inputs2, "q-2".into()).unwrap();
        let ctx2 = SettlementContext {
            receipt_id: "rec-2".into(),
            custody_transaction_hash: Hash256::from_bytes([0x44; 32]),
            prev_settlement_receipt: store.latest_receipt_hash(),
            now: Timestamp::new(1_020_000, 0),
        };
        let r2 = settle(&q2, &ctx2, |_| fixed_signature()).unwrap();
        store.put_receipt(r2.clone()).unwrap();

        assert_ne!(r1.content_hash, r2.content_hash);
        assert_eq!(r2.prev_settlement_receipt, r1.content_hash);
        assert_eq!(store.latest_receipt_hash(), r2.content_hash);
    }
}
