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

//! Deterministic store for quotes, receipts, mission economics, and
//! HonorGood value-contribution records.
//!
//! The in-memory implementation is the reference core store used by tests
//! and node adapters. Every HonorGood object is validated, canonical-hash
//! checked, and appended to a deterministic hash-linked economy anchor chain
//! before it is accepted.

use std::collections::BTreeMap;

use exo_core::Hash256;
use serde::{Deserialize, Serialize};

use crate::{
    adoption::{AdoptionEvent, UseEvent, ValueEvent},
    bailment::{BailmentTerms, BailmentWrapper},
    contribution_acceptance::ContributionAcceptance,
    contribution_offer::ContributionOffer,
    contribution_receipt::ContributionReceipt,
    error::EconomyError,
    legacy::LegacyReceipt,
    mission::Mission,
    policy::PricingPolicy,
    quote::SettlementQuote,
    receipt::SettlementReceipt,
    ruleset::HonorGoodRuleset,
    settlement::{AutomatedSettlementEvent, MissionSettlement},
    value_contribution::{ValueContributionNode, require_nonzero_hash, require_nonzero_timestamp},
};

pub const ECONOMY_RECORD_ANCHOR_HASH_DOMAIN: &str = "exo.economy.record_anchor.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomyObjectKind {
    Mission,
    ContributionReceipt,
    LegacyReceipt,
    #[serde(rename = "honorgood_ruleset")]
    HonorGoodRuleset,
    ValueContributionNode,
    ContributionOffer,
    ContributionAcceptance,
    BailmentTerms,
    BailmentWrapper,
    AdoptionEvent,
    UseEvent,
    ValueEvent,
    MissionSettlement,
    AutomatedSettlementEvent,
}

impl EconomyObjectKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Mission => "mission",
            Self::ContributionReceipt => "contribution_receipt",
            Self::LegacyReceipt => "legacy_receipt",
            Self::HonorGoodRuleset => "honorgood_ruleset",
            Self::ValueContributionNode => "value_contribution_node",
            Self::ContributionOffer => "contribution_offer",
            Self::ContributionAcceptance => "contribution_acceptance",
            Self::BailmentTerms => "bailment_terms",
            Self::BailmentWrapper => "bailment_wrapper",
            Self::AdoptionEvent => "adoption_event",
            Self::UseEvent => "use_event",
            Self::ValueEvent => "value_event",
            Self::MissionSettlement => "mission_settlement",
            Self::AutomatedSettlementEvent => "automated_settlement_event",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomyRecordAnchor {
    pub anchor_hash: Hash256,
    pub previous_anchor_hash: Hash256,
    pub object_kind: EconomyObjectKind,
    pub object_id: Hash256,
    pub object_hash: Hash256,
    pub created_at: exo_core::Timestamp,
}

#[derive(Serialize)]
struct EconomyRecordAnchorHashPayload<'a> {
    domain: &'static str,
    previous_anchor_hash: &'a Hash256,
    object_kind: EconomyObjectKind,
    object_id: &'a Hash256,
    object_hash: &'a Hash256,
    created_at: &'a exo_core::Timestamp,
}

impl EconomyRecordAnchor {
    pub fn validate(&self) -> Result<(), EconomyError> {
        require_nonzero_hash(self.object_id, "economy_anchor.object_id")?;
        require_nonzero_hash(self.object_hash, "economy_anchor.object_hash")?;
        require_nonzero_timestamp(self.created_at, "economy_anchor.created_at")
    }

    pub fn recompute_anchor_hash(&self) -> Result<Hash256, EconomyError> {
        exo_core::hash::hash_structured(&EconomyRecordAnchorHashPayload {
            domain: ECONOMY_RECORD_ANCHOR_HASH_DOMAIN,
            previous_anchor_hash: &self.previous_anchor_hash,
            object_kind: self.object_kind,
            object_id: &self.object_id,
            object_hash: &self.object_hash,
            created_at: &self.created_at,
        })
        .map_err(EconomyError::from)
    }

    pub fn anchor(mut self) -> Result<Self, EconomyError> {
        self.validate()?;
        self.anchor_hash = self.recompute_anchor_hash()?;
        Ok(self)
    }
}

pub trait EconomyStore {
    fn put_quote(&mut self, quote: SettlementQuote) -> Result<(), EconomyError>;
    fn get_quote(&self, quote_hash: &Hash256) -> Result<Option<SettlementQuote>, EconomyError>;
    fn put_receipt(&mut self, receipt: SettlementReceipt) -> Result<(), EconomyError>;
    fn get_receipt(&self, id: &str) -> Result<Option<SettlementReceipt>, EconomyError>;
    fn put_mission(&mut self, mission: Mission) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_mission(&self, id: &Hash256) -> Result<Option<Mission>, EconomyError>;
    fn put_contribution_receipt(
        &mut self,
        receipt: ContributionReceipt,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_contribution_receipt(
        &self,
        id: &Hash256,
    ) -> Result<Option<ContributionReceipt>, EconomyError>;
    fn put_legacy_receipt(
        &mut self,
        receipt: LegacyReceipt,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_legacy_receipt(&self, id: &Hash256) -> Result<Option<LegacyReceipt>, EconomyError>;
    fn put_ruleset(
        &mut self,
        ruleset: HonorGoodRuleset,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_ruleset(&self, id: &Hash256) -> Result<Option<HonorGoodRuleset>, EconomyError>;
    fn put_value_contribution_node(
        &mut self,
        node: ValueContributionNode,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_value_contribution_node(
        &self,
        id: &Hash256,
    ) -> Result<Option<ValueContributionNode>, EconomyError>;
    fn put_contribution_offer(
        &mut self,
        offer: ContributionOffer,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_contribution_offer(
        &self,
        id: &Hash256,
    ) -> Result<Option<ContributionOffer>, EconomyError>;
    fn put_contribution_acceptance(
        &mut self,
        acceptance: ContributionAcceptance,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_contribution_acceptance(
        &self,
        id: &Hash256,
    ) -> Result<Option<ContributionAcceptance>, EconomyError>;
    fn put_bailment_terms(
        &mut self,
        terms: BailmentTerms,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_bailment_terms(&self, id: &Hash256) -> Result<Option<BailmentTerms>, EconomyError>;
    fn put_bailment_wrapper(
        &mut self,
        wrapper: BailmentWrapper,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_bailment_wrapper(&self, id: &Hash256) -> Result<Option<BailmentWrapper>, EconomyError>;
    fn put_adoption_event(
        &mut self,
        event: AdoptionEvent,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_adoption_event(&self, id: &Hash256) -> Result<Option<AdoptionEvent>, EconomyError>;
    fn put_use_event(&mut self, event: UseEvent) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_use_event(&self, id: &Hash256) -> Result<Option<UseEvent>, EconomyError>;
    fn put_value_event(&mut self, event: ValueEvent) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_value_event(&self, id: &Hash256) -> Result<Option<ValueEvent>, EconomyError>;
    fn put_mission_settlement(
        &mut self,
        settlement: MissionSettlement,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_mission_settlement(
        &self,
        id: &Hash256,
    ) -> Result<Option<MissionSettlement>, EconomyError>;
    fn put_automated_settlement_event(
        &mut self,
        event: AutomatedSettlementEvent,
    ) -> Result<EconomyRecordAnchor, EconomyError>;
    fn get_automated_settlement_event(
        &self,
        id: &Hash256,
    ) -> Result<Option<AutomatedSettlementEvent>, EconomyError>;
    fn get_economy_anchor(
        &self,
        anchor_hash: &Hash256,
    ) -> Result<Option<EconomyRecordAnchor>, EconomyError>;
    fn latest_economy_anchor_hash(&self) -> Hash256;
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
    missions: BTreeMap<Hash256, Mission>,
    contribution_receipts: BTreeMap<Hash256, ContributionReceipt>,
    legacy_receipts: BTreeMap<Hash256, LegacyReceipt>,
    rulesets: BTreeMap<Hash256, HonorGoodRuleset>,
    value_contribution_nodes: BTreeMap<Hash256, ValueContributionNode>,
    contribution_offers: BTreeMap<Hash256, ContributionOffer>,
    contribution_acceptances: BTreeMap<Hash256, ContributionAcceptance>,
    bailment_terms: BTreeMap<Hash256, BailmentTerms>,
    bailment_wrappers: BTreeMap<Hash256, BailmentWrapper>,
    adoption_events: BTreeMap<Hash256, AdoptionEvent>,
    use_events: BTreeMap<Hash256, UseEvent>,
    value_events: BTreeMap<Hash256, ValueEvent>,
    mission_settlements: BTreeMap<Hash256, MissionSettlement>,
    automated_settlement_events: BTreeMap<Hash256, AutomatedSettlementEvent>,
    economy_anchors: BTreeMap<Hash256, EconomyRecordAnchor>,
    active_policy: PricingPolicy,
    latest_receipt_hash: Hash256,
    latest_economy_anchor_hash: Hash256,
}

impl InMemoryEconomyStore {
    /// Construct a store seeded with the zero-launch policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            quotes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            receipt_by_hash: BTreeMap::new(),
            missions: BTreeMap::new(),
            contribution_receipts: BTreeMap::new(),
            legacy_receipts: BTreeMap::new(),
            rulesets: BTreeMap::new(),
            value_contribution_nodes: BTreeMap::new(),
            contribution_offers: BTreeMap::new(),
            contribution_acceptances: BTreeMap::new(),
            bailment_terms: BTreeMap::new(),
            bailment_wrappers: BTreeMap::new(),
            adoption_events: BTreeMap::new(),
            use_events: BTreeMap::new(),
            value_events: BTreeMap::new(),
            mission_settlements: BTreeMap::new(),
            automated_settlement_events: BTreeMap::new(),
            economy_anchors: BTreeMap::new(),
            active_policy: PricingPolicy::zero_launch_default(),
            latest_receipt_hash: Hash256::ZERO,
            latest_economy_anchor_hash: Hash256::ZERO,
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

    /// Number of hash-linked HonorGood/economy object anchors.
    #[must_use]
    pub fn economy_anchor_count(&self) -> usize {
        self.economy_anchors.len()
    }

    fn append_economy_anchor(
        &mut self,
        object_kind: EconomyObjectKind,
        object_id: Hash256,
        object_hash: Hash256,
        created_at: exo_core::Timestamp,
    ) -> Result<EconomyRecordAnchor, EconomyError> {
        let anchor = EconomyRecordAnchor {
            anchor_hash: Hash256::ZERO,
            previous_anchor_hash: self.latest_economy_anchor_hash,
            object_kind,
            object_id,
            object_hash,
            created_at,
        }
        .anchor()?;
        if self.economy_anchors.contains_key(&anchor.anchor_hash) {
            return Err(EconomyError::InvalidInput {
                reason: format!("duplicate economy anchor {}", anchor.anchor_hash),
            });
        }
        self.latest_economy_anchor_hash = anchor.anchor_hash;
        self.economy_anchors
            .insert(anchor.anchor_hash, anchor.clone());
        Ok(anchor)
    }
}

macro_rules! impl_economy_object_store {
    (
        $put:ident,
        $get:ident,
        $field:ident,
        $ty:ty,
        $kind:ident,
        $id_field:ident,
        $created_field:ident,
        $duplicate_label:literal,
        $hash_field_label:literal
    ) => {
        fn $put(&mut self, object: $ty) -> Result<EconomyRecordAnchor, EconomyError> {
            object.validate()?;
            let recomputed = object.recompute_content_hash()?;
            if object.$id_field != recomputed || object.content_hash != recomputed {
                return Err(EconomyError::HashMismatch {
                    field: $hash_field_label,
                });
            }
            if self.$field.contains_key(&object.$id_field) {
                return Err(EconomyError::InvalidInput {
                    reason: format!("duplicate {} {}", $duplicate_label, object.$id_field),
                });
            }
            let anchor = self.append_economy_anchor(
                EconomyObjectKind::$kind,
                object.$id_field,
                object.content_hash,
                object.$created_field,
            )?;
            self.$field.insert(object.$id_field, object);
            Ok(anchor)
        }

        fn $get(&self, id: &Hash256) -> Result<Option<$ty>, EconomyError> {
            Ok(self.$field.get(id).cloned())
        }
    };
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
        if receipt.prev_settlement_receipt != self.latest_receipt_hash {
            return Err(EconomyError::InvalidInput {
                reason: format!(
                    "settlement receipt prev_settlement_receipt {} does not match latest receipt hash {}",
                    receipt.prev_settlement_receipt, self.latest_receipt_hash
                ),
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

    impl_economy_object_store!(
        put_mission,
        get_mission,
        missions,
        Mission,
        Mission,
        mission_id,
        created_at,
        "mission",
        "mission.content_hash"
    );

    impl_economy_object_store!(
        put_contribution_receipt,
        get_contribution_receipt,
        contribution_receipts,
        ContributionReceipt,
        ContributionReceipt,
        receipt_id,
        created_at,
        "contribution receipt",
        "contribution_receipt.content_hash"
    );

    impl_economy_object_store!(
        put_legacy_receipt,
        get_legacy_receipt,
        legacy_receipts,
        LegacyReceipt,
        LegacyReceipt,
        legacy_receipt_id,
        created_at,
        "legacy receipt",
        "legacy_receipt.content_hash"
    );

    impl_economy_object_store!(
        put_ruleset,
        get_ruleset,
        rulesets,
        HonorGoodRuleset,
        HonorGoodRuleset,
        ruleset_id,
        created_at,
        "HonorGood ruleset",
        "ruleset.content_hash"
    );

    impl_economy_object_store!(
        put_value_contribution_node,
        get_value_contribution_node,
        value_contribution_nodes,
        ValueContributionNode,
        ValueContributionNode,
        contribution_node_id,
        created_at_hlc,
        "value contribution node",
        "value_contribution.content_hash"
    );

    impl_economy_object_store!(
        put_contribution_offer,
        get_contribution_offer,
        contribution_offers,
        ContributionOffer,
        ContributionOffer,
        offer_id,
        created_at_hlc,
        "contribution offer",
        "contribution_offer.content_hash"
    );

    impl_economy_object_store!(
        put_contribution_acceptance,
        get_contribution_acceptance,
        contribution_acceptances,
        ContributionAcceptance,
        ContributionAcceptance,
        acceptance_id,
        accepted_at_hlc,
        "contribution acceptance",
        "contribution_acceptance.content_hash"
    );

    impl_economy_object_store!(
        put_bailment_terms,
        get_bailment_terms,
        bailment_terms,
        BailmentTerms,
        BailmentTerms,
        terms_id,
        created_at_hlc,
        "bailment terms",
        "bailment_terms.content_hash"
    );

    impl_economy_object_store!(
        put_bailment_wrapper,
        get_bailment_wrapper,
        bailment_wrappers,
        BailmentWrapper,
        BailmentWrapper,
        wrapper_id,
        created_at_hlc,
        "bailment wrapper",
        "bailment_wrapper.content_hash"
    );

    impl_economy_object_store!(
        put_adoption_event,
        get_adoption_event,
        adoption_events,
        AdoptionEvent,
        AdoptionEvent,
        adoption_id,
        created_at_hlc,
        "adoption event",
        "adoption_event.content_hash"
    );

    impl_economy_object_store!(
        put_use_event,
        get_use_event,
        use_events,
        UseEvent,
        UseEvent,
        use_event_id,
        created_at_hlc,
        "use event",
        "use_event.content_hash"
    );

    impl_economy_object_store!(
        put_value_event,
        get_value_event,
        value_events,
        ValueEvent,
        ValueEvent,
        value_event_id,
        created_at_hlc,
        "value event",
        "value_event.content_hash"
    );

    impl_economy_object_store!(
        put_mission_settlement,
        get_mission_settlement,
        mission_settlements,
        MissionSettlement,
        MissionSettlement,
        settlement_id,
        created_at,
        "mission settlement",
        "mission_settlement.content_hash"
    );

    impl_economy_object_store!(
        put_automated_settlement_event,
        get_automated_settlement_event,
        automated_settlement_events,
        AutomatedSettlementEvent,
        AutomatedSettlementEvent,
        automated_settlement_id,
        created_at_hlc,
        "automated settlement event",
        "automated_settlement.content_hash"
    );

    fn get_economy_anchor(
        &self,
        anchor_hash: &Hash256,
    ) -> Result<Option<EconomyRecordAnchor>, EconomyError> {
        Ok(self.economy_anchors.get(anchor_hash).cloned())
    }

    fn latest_economy_anchor_hash(&self) -> Hash256 {
        self.latest_economy_anchor_hash
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
        adoption::test_support::{sample_adoption, sample_use_event, sample_value_event},
        bailment::test_support::{sample_terms, sample_wrapper},
        contribution_acceptance::test_support::sample_acceptance,
        contribution_offer::test_support::sample_offer,
        contribution_receipt::test_support::sample_contribution_receipt,
        honorgood::{archon_exoforge_legacy_receipt, archon_exoforge_ruleset},
        legacy::test_support::sample_legacy_receipt,
        mission::test_support::sample_mission,
        policy::PricingPolicy,
        price::PricingInputs,
        quote::quote,
        ruleset::test_support::sample_ruleset,
        settlement::{SettlementContext, settle},
        types::{ActorClass, AssuranceClass, EventClass, ZeroFeeReason},
        value_contribution::test_support::{authority, h, sample_node, ts},
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
    fn put_receipt_rejects_receipt_not_chained_to_latest_hash() {
        let mut store = InMemoryEconomyStore::new();
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let first_context = SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
            prev_settlement_receipt: store.latest_receipt_hash(),
            now: Timestamp::new(1_010_000, 0),
        };
        let first_receipt = settle(&q, &first_context, |_| fixed_signature()).unwrap();
        store.put_receipt(first_receipt.clone()).unwrap();

        let mut inputs2 = baseline_inputs();
        inputs2.compute_units = 200;
        let q2 = quote(&policy, &inputs2, "q-2".into()).unwrap();
        let fork_context = SettlementContext {
            receipt_id: "rec-2".into(),
            custody_transaction_hash: Hash256::from_bytes([0x44; 32]),
            prev_settlement_receipt: Hash256::from_bytes([0xFA; 32]),
            now: Timestamp::new(1_020_000, 0),
        };
        let forked_receipt = settle(&q2, &fork_context, |_| fixed_signature()).unwrap();

        let err = store.put_receipt(forked_receipt).unwrap_err();
        assert!(matches!(
            err,
            EconomyError::InvalidInput { reason }
                if reason.contains("prev_settlement_receipt")
                    && reason.contains("latest receipt hash")
        ));
        assert_eq!(store.latest_receipt_hash(), first_receipt.content_hash);
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

    fn sample_automated_settlement_event() -> AutomatedSettlementEvent {
        let ruleset = sample_ruleset().anchor().unwrap();
        let lines = vec![crate::settlement::SettlementLine {
            recipient: ruleset.share_lines[0].recipient.clone(),
            recipient_type: ruleset.share_lines[0].recipient_type,
            basis: ruleset.share_lines[0].basis.clone(),
            share_bp: 100,
            amount_micro_exo: 0,
            zero_fee_reason: Some(ZeroFeeReason::PublicGood),
            source_receipt_id: None,
            legacy_receipt_id: None,
        }];
        AutomatedSettlementEvent {
            automated_settlement_id: Hash256::ZERO,
            value_event_id: h(0xB1),
            contribution_node_id: h(0xB2),
            adoption_id: h(0xB3),
            ruleset_id: ruleset.ruleset_id,
            settlement_lines: lines,
            automation_authority_ref: authority("settlement-agent"),
            preapproved_terms_hash: h(0xB4),
            bailment_wrapper_id: h(0xB5),
            human_approval_required: false,
            fail_closed_checks: vec!["accepted_offer".into(), "delegated_authority".into()],
            created_at_hlc: ts(9_000),
            content_hash: Hash256::ZERO,
        }
        .anchor()
        .unwrap()
    }

    #[test]
    fn put_mission_records_hash_linked_anchor_and_gets_by_id() {
        let mut store = InMemoryEconomyStore::new();
        let mission = sample_mission().anchor().unwrap();
        let anchor = store.put_mission(mission.clone()).unwrap();

        assert_eq!(anchor.object_kind, EconomyObjectKind::Mission);
        assert_eq!(anchor.object_id, mission.mission_id);
        assert_eq!(anchor.object_hash, mission.content_hash);
        assert_eq!(anchor.previous_anchor_hash, Hash256::ZERO);
        assert_eq!(store.latest_economy_anchor_hash(), anchor.anchor_hash);
        assert_eq!(store.economy_anchor_count(), 1);
        assert_eq!(
            store.get_mission(&mission.mission_id).unwrap(),
            Some(mission)
        );
        assert_eq!(
            store.get_economy_anchor(&anchor.anchor_hash).unwrap(),
            Some(anchor)
        );
    }

    #[test]
    fn economy_store_rejects_duplicate_and_tampered_hashes() {
        let mut store = InMemoryEconomyStore::new();
        let mission = sample_mission().anchor().unwrap();
        store.put_mission(mission.clone()).unwrap();
        assert!(store.put_mission(mission.clone()).is_err());

        let mut tampered = mission;
        tampered.name = "tampered after hash".into();
        assert!(matches!(
            store.put_mission(tampered),
            Err(EconomyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn put_core_honorgood_objects_appends_deterministic_anchor_chain() {
        let mut store = InMemoryEconomyStore::new();

        let mission_anchor = store
            .put_mission(sample_mission().anchor().unwrap())
            .unwrap();
        let receipt_anchor = store
            .put_contribution_receipt(sample_contribution_receipt().anchor().unwrap())
            .unwrap();
        let legacy_anchor = store
            .put_legacy_receipt(sample_legacy_receipt().anchor().unwrap())
            .unwrap();
        let ruleset_anchor = store
            .put_ruleset(sample_ruleset().anchor().unwrap())
            .unwrap();
        let node_anchor = store
            .put_value_contribution_node(sample_node().anchor().unwrap())
            .unwrap();
        let terms_anchor = store
            .put_bailment_terms(sample_terms().anchor().unwrap())
            .unwrap();
        let offer_anchor = store
            .put_contribution_offer(sample_offer().anchor().unwrap())
            .unwrap();
        let acceptance_anchor = store
            .put_contribution_acceptance(sample_acceptance().anchor().unwrap())
            .unwrap();
        let wrapper_anchor = store
            .put_bailment_wrapper(sample_wrapper().anchor().unwrap())
            .unwrap();
        let adoption_anchor = store
            .put_adoption_event(sample_adoption().anchor().unwrap())
            .unwrap();
        let use_anchor = store
            .put_use_event(sample_use_event().anchor().unwrap())
            .unwrap();
        let value_anchor = store
            .put_value_event(sample_value_event().anchor().unwrap())
            .unwrap();
        let mission_settlement = MissionSettlement::from_ruleset(
            h(0xC1),
            &archon_exoforge_ruleset().unwrap(),
            0,
            0,
            Some(ZeroFeeReason::PublicGood),
            None,
            ts(9_100),
        )
        .unwrap();
        let mission_settlement_anchor = store
            .put_mission_settlement(mission_settlement.clone())
            .unwrap();
        let automated_anchor = store
            .put_automated_settlement_event(sample_automated_settlement_event())
            .unwrap();

        assert_eq!(
            receipt_anchor.previous_anchor_hash,
            mission_anchor.anchor_hash
        );
        assert_eq!(
            legacy_anchor.previous_anchor_hash,
            receipt_anchor.anchor_hash
        );
        assert_eq!(
            ruleset_anchor.previous_anchor_hash,
            legacy_anchor.anchor_hash
        );
        assert_eq!(node_anchor.previous_anchor_hash, ruleset_anchor.anchor_hash);
        assert_eq!(terms_anchor.previous_anchor_hash, node_anchor.anchor_hash);
        assert_eq!(offer_anchor.previous_anchor_hash, terms_anchor.anchor_hash);
        assert_eq!(
            acceptance_anchor.previous_anchor_hash,
            offer_anchor.anchor_hash
        );
        assert_eq!(
            wrapper_anchor.previous_anchor_hash,
            acceptance_anchor.anchor_hash
        );
        assert_eq!(
            adoption_anchor.previous_anchor_hash,
            wrapper_anchor.anchor_hash
        );
        assert_eq!(use_anchor.previous_anchor_hash, adoption_anchor.anchor_hash);
        assert_eq!(value_anchor.previous_anchor_hash, use_anchor.anchor_hash);
        assert_eq!(
            mission_settlement_anchor.previous_anchor_hash,
            value_anchor.anchor_hash
        );
        assert_eq!(
            automated_anchor.previous_anchor_hash,
            mission_settlement_anchor.anchor_hash
        );
        assert_eq!(store.economy_anchor_count(), 14);
        assert_eq!(
            store
                .get_mission_settlement(&mission_settlement.settlement_id)
                .unwrap(),
            Some(mission_settlement)
        );
    }

    #[test]
    fn seed_legacy_receipt_can_be_stored_but_remains_non_ratified() {
        let mut store = InMemoryEconomyStore::new();
        let seed = archon_exoforge_legacy_receipt().unwrap();
        let anchor = store.put_legacy_receipt(seed.clone()).unwrap();
        assert_eq!(anchor.object_kind, EconomyObjectKind::LegacyReceipt);
        assert_ne!(
            seed.status,
            crate::legacy::LegacyReceiptStatus::Ratified,
            "seed upstream recognition must not enter the store as ratified"
        );
        assert_eq!(
            store.get_legacy_receipt(&seed.legacy_receipt_id).unwrap(),
            Some(seed)
        );
    }

    #[test]
    fn economy_object_kind_serializes_as_stable_snake_case() {
        let mut serialized = Vec::new();
        ciborium::into_writer(&EconomyObjectKind::Mission, &mut serialized).unwrap();
        assert_eq!(serialized, b"\x67mission");

        let mut ruleset = Vec::new();
        ciborium::into_writer(&EconomyObjectKind::HonorGoodRuleset, &mut ruleset).unwrap();
        assert_eq!(ruleset, b"\x71honorgood_ruleset");
    }

    #[test]
    fn economy_object_kind_labels_cover_all_variants() {
        let cases = [
            (EconomyObjectKind::Mission, "mission"),
            (
                EconomyObjectKind::ContributionReceipt,
                "contribution_receipt",
            ),
            (EconomyObjectKind::LegacyReceipt, "legacy_receipt"),
            (EconomyObjectKind::HonorGoodRuleset, "honorgood_ruleset"),
            (
                EconomyObjectKind::ValueContributionNode,
                "value_contribution_node",
            ),
            (EconomyObjectKind::ContributionOffer, "contribution_offer"),
            (
                EconomyObjectKind::ContributionAcceptance,
                "contribution_acceptance",
            ),
            (EconomyObjectKind::BailmentTerms, "bailment_terms"),
            (EconomyObjectKind::BailmentWrapper, "bailment_wrapper"),
            (EconomyObjectKind::AdoptionEvent, "adoption_event"),
            (EconomyObjectKind::UseEvent, "use_event"),
            (EconomyObjectKind::ValueEvent, "value_event"),
            (EconomyObjectKind::MissionSettlement, "mission_settlement"),
            (
                EconomyObjectKind::AutomatedSettlementEvent,
                "automated_settlement_event",
            ),
        ];

        for (kind, label) in cases {
            assert_eq!(kind.label(), label);
        }
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

    #[test]
    fn receipt_store_checks_chain_head_before_advancing_latest_hash() {
        let source = include_str!("store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let guard_index = production
            .find("receipt.prev_settlement_receipt != self.latest_receipt_hash")
            .expect("receipt store must compare receipt chain head to latest hash");
        let update_index = production
            .find("self.latest_receipt_hash = receipt.content_hash")
            .expect("receipt store must advance latest receipt hash after validation");
        assert!(
            guard_index < update_index,
            "receipt store must reject forked receipts before advancing the latest hash"
        );
    }
}
