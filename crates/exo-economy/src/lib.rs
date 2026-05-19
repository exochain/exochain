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

//! # exo-economy — custody-native transaction economy
//!
//! This crate provides the deterministic, integer-only quote/settle/
//! receipt scaffold for EXOCHAIN's custody-native economy. The launch
//! phase resolves every active fee, vigorish, multiplier, share, and
//! settlement amount to **zero**, so trust is never paywalled. The full
//! economic mechanism still runs end-to-end so that future governance
//! amendments can flip pricing on without reshaping the type system.
//!
//! ## Determinism contract
//!
//! - Integer-only (`MicroExo = u128`, `BasisPoints = u32`).
//! - All hashing is BLAKE3 over canonical CBOR.
//! - Checked arithmetic fails closed on overflow or underflow.
//! - Only deterministic ordered collections (`BTreeMap`, `BTreeSet`),
//!   never the unordered standard-library variants. No floating-point
//!   arithmetic anywhere in the price path.
//! - Quote and receipt hashes are deterministic and tamper-evident.
//!
//! ## Zero-launch guarantee
//!
//! [`PricingPolicy::zero_launch_default`] is the canonical launch
//! policy. Every active price field is `0`, every multiplier is the
//! neutral `10_000` basis points, and the global ceiling is `0`. The
//! deterministic pricing formula therefore clamps `charged_amount` to
//! `0` for any inputs.
//!
//! ## High-level API
//!
//! ```
//! use exo_economy::{
//!     ActorClass, AssuranceClass, EventClass, InMemoryEconomyStore,
//!     EconomyStore, PricingInputs, PricingPolicy, quote, settle,
//!     SettlementContext, ZeroFeeReason,
//! };
//! use exo_core::{Did, Hash256, Signature, Timestamp};
//!
//! let mut store = InMemoryEconomyStore::new();
//! let policy = store.get_active_policy().unwrap();
//!
//! let inputs = PricingInputs {
//!     actor_did: Did::new("did:exo:agent").unwrap(),
//!     actor_class: ActorClass::Holon,
//!     event_class: EventClass::HolonCommercialAction,
//!     assurance_class: AssuranceClass::Standard,
//!     declared_value_micro_exo: Some(1_000_000),
//!     realized_value_micro_exo: None,
//!     compute_units: 100,
//!     storage_bytes: 4_096,
//!     verification_ops: 5,
//!     network_load_bp: 10_000,
//!     risk_bp: 1_500,
//!     market_domain: None,
//!     timestamp: Timestamp::new(1_000_000, 0),
//! };
//!
//! let quote_record = quote(&policy, &inputs, "quote-1".into()).unwrap();
//! assert_eq!(quote_record.charged_amount_micro_exo, 0);
//! assert!(quote_record.zero_fee_reason.is_some());
//!
//! let context = SettlementContext {
//!     receipt_id: "rec-1".into(),
//!     custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
//!     prev_settlement_receipt: store.latest_receipt_hash(),
//!     now: Timestamp::new(1_010_000, 0),
//! };
//! let receipt = settle(&quote_record, &context, |_| Signature::from_bytes([7; 64])).unwrap();
//! assert_eq!(receipt.charged_amount_micro_exo, 0);
//! ```

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod adoption;
pub mod bailment;
pub mod contribution_acceptance;
pub mod contribution_offer;
pub mod contribution_receipt;
pub mod error;
pub mod honorgood;
pub mod legacy;
pub mod mission;
pub mod policy;
pub mod price;
pub mod quote;
pub mod receipt;
pub mod revenue_share;
pub mod ruleset;
pub mod settlement;
pub mod store;
pub mod types;
pub mod value_contribution;

pub use adoption::{
    ADOPTION_EVENT_HASH_DOMAIN, AdoptionEvent, USE_EVENT_HASH_DOMAIN, UseEvent, UseType,
    VALUE_EVENT_HASH_DOMAIN, ValueBasis, ValueEvent,
};
pub use bailment::{
    BAILMENT_TERMS_HASH_DOMAIN, BAILMENT_WRAPPER_HASH_DOMAIN, BailmentTerms, BailmentWrapper,
    BailmentWrapperStatus,
};
pub use contribution_acceptance::{
    AdopterType, CONTRIBUTION_ACCEPTANCE_HASH_DOMAIN, ContributionAcceptance,
};
pub use contribution_offer::{
    CONTRIBUTION_OFFER_HASH_DOMAIN, ContributionOffer, ContributionOfferStatus, ExpirationOrReview,
    RequiredAuthorityLevel,
};
pub use contribution_receipt::{
    ApprovalStatus, CONTRIBUTION_RECEIPT_HASH_DOMAIN, ContributionCategory,
    ContributionContributorType, ContributionReceipt,
};
pub use error::EconomyError;
pub use honorgood::{
    apex_velocity_catalyst_client_services_mission, apex_velocity_catalyst_client_services_ruleset,
    apex_velocity_catalyst_software_channel_ruleset, archon_exoforge_legacy_receipt,
    archon_exoforge_ruleset, paperclip_commandbase_legacy_receipt, paperclip_commandbase_ruleset,
    zero_launch_mission_settlement_reason,
};
pub use legacy::{
    BeneficiaryRef, BeneficiaryType, LEGACY_RECEIPT_HASH_DOMAIN, LegacyReceipt,
    LegacyReceiptStatus, LegalEffect, MaterialityReview, MaterialityReviewStatus, MaterialityTier,
};
pub use mission::{MISSION_HASH_DOMAIN, Mission, MissionPurpose, MissionStatus, MissionType};
pub use policy::{
    ActorMultiplier, AssuranceMultiplier, ECONOMY_POLICY_HASH_DOMAIN, EventMultiplier,
    PricingPolicy,
};
pub use price::{PriceBreakdown, PricingInputs, apply_bp, apply_multiplier, compute_breakdown};
pub use quote::{ECONOMY_QUOTE_HASH_DOMAIN, SettlementQuote, quote};
pub use receipt::{SETTLEMENT_RECEIPT_HASH_DOMAIN, SettlementReceipt};
pub use revenue_share::{
    RevenueShareLine, RevenueShareTemplate, TemplateAllocation, distribute_revenue,
};
pub use ruleset::{
    DurationPolicy, HONOR_GOOD_RULESET_HASH_DOMAIN, HonorGoodRuleset, ReviewFrequency,
    RulesetRecipientType, RulesetScope, RulesetShareLine, RulesetStatus, SettlementBasis,
    validate_basis_allocations,
};
pub use settlement::{
    AUTOMATED_SETTLEMENT_EVENT_HASH_DOMAIN, AutomatedSettlementEvent, AutomatedSettlementInputs,
    AutomatedSettlementRiskState, MISSION_SETTLEMENT_HASH_DOMAIN, MissionSettlement,
    SettlementContext, SettlementLine, checked_basis_point_amount, settle,
    settlement_lines_from_ruleset,
};
pub use store::{
    ECONOMY_RECORD_ANCHOR_HASH_DOMAIN, EconomyObjectKind, EconomyRecordAnchor, EconomyStore,
    InMemoryEconomyStore,
};
pub use types::{
    ActorClass, AssuranceClass, BasisPoints, DEFAULT_QUOTE_TTL_MS, EventClass, MAX_BASIS_POINTS,
    MAX_MULTIPLIER_BP, MicroExo, NEUTRAL_MULTIPLIER_BP, PricingMode, RevenueRecipient,
    ZeroFeeReason,
};
pub use value_contribution::{
    AuthorityEnvelopeRef, ContributionType, ContributorType, ParticipantRef,
    VALUE_CONTRIBUTION_NODE_HASH_DOMAIN, ValueContributionNode, ValueContributionStatus,
};

/// All economy hashing/signing domains. Used by hygiene tests and
/// external auditors.
pub const ECONOMY_DOMAINS: &[&str] = &[
    ADOPTION_EVENT_HASH_DOMAIN,
    AUTOMATED_SETTLEMENT_EVENT_HASH_DOMAIN,
    BAILMENT_TERMS_HASH_DOMAIN,
    BAILMENT_WRAPPER_HASH_DOMAIN,
    CONTRIBUTION_ACCEPTANCE_HASH_DOMAIN,
    CONTRIBUTION_OFFER_HASH_DOMAIN,
    CONTRIBUTION_RECEIPT_HASH_DOMAIN,
    ECONOMY_QUOTE_HASH_DOMAIN,
    ECONOMY_RECORD_ANCHOR_HASH_DOMAIN,
    ECONOMY_POLICY_HASH_DOMAIN,
    HONOR_GOOD_RULESET_HASH_DOMAIN,
    LEGACY_RECEIPT_HASH_DOMAIN,
    MISSION_HASH_DOMAIN,
    MISSION_SETTLEMENT_HASH_DOMAIN,
    SETTLEMENT_RECEIPT_HASH_DOMAIN,
    USE_EVENT_HASH_DOMAIN,
    VALUE_CONTRIBUTION_NODE_HASH_DOMAIN,
    VALUE_EVENT_HASH_DOMAIN,
];

#[cfg(test)]
mod hygiene_tests {
    use super::*;

    #[test]
    fn economy_domains_distinct_and_versioned() {
        let mut sorted = ECONOMY_DOMAINS.to_vec();
        sorted.sort_unstable();
        let original = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), original, "economy domains must be unique");
        for d in ECONOMY_DOMAINS {
            assert!(
                d.contains(".v1"),
                "economy domain {d} must be version-tagged"
            );
        }
    }

    #[test]
    fn no_hashmap_or_hashset_in_production_sources() {
        let sources = [
            include_str!("adoption.rs"),
            include_str!("bailment.rs"),
            include_str!("contribution_acceptance.rs"),
            include_str!("contribution_offer.rs"),
            include_str!("contribution_receipt.rs"),
            include_str!("error.rs"),
            include_str!("honorgood.rs"),
            include_str!("legacy.rs"),
            include_str!("lib.rs"),
            include_str!("mission.rs"),
            include_str!("policy.rs"),
            include_str!("price.rs"),
            include_str!("quote.rs"),
            include_str!("receipt.rs"),
            include_str!("revenue_share.rs"),
            include_str!("ruleset.rs"),
            include_str!("settlement.rs"),
            include_str!("store.rs"),
            include_str!("types.rs"),
            include_str!("value_contribution.rs"),
        ];
        let banned_map = ["Hash", "Map"].concat();
        let banned_set = ["Hash", "Set"].concat();
        for src in sources {
            let production = src.split("#[cfg(test)]").next().unwrap();
            assert!(
                !production.contains(&banned_map),
                "economy production sources must not use HashMap"
            );
            assert!(
                !production.contains(&banned_set),
                "economy production sources must not use HashSet"
            );
        }
    }

    #[test]
    fn no_floating_point_in_production_sources() {
        let sources = [
            include_str!("adoption.rs"),
            include_str!("bailment.rs"),
            include_str!("contribution_acceptance.rs"),
            include_str!("contribution_offer.rs"),
            include_str!("contribution_receipt.rs"),
            include_str!("error.rs"),
            include_str!("honorgood.rs"),
            include_str!("legacy.rs"),
            include_str!("lib.rs"),
            include_str!("mission.rs"),
            include_str!("policy.rs"),
            include_str!("price.rs"),
            include_str!("quote.rs"),
            include_str!("receipt.rs"),
            include_str!("revenue_share.rs"),
            include_str!("ruleset.rs"),
            include_str!("settlement.rs"),
            include_str!("store.rs"),
            include_str!("types.rs"),
            include_str!("value_contribution.rs"),
        ];
        for src in sources {
            let production = src.split("#[cfg(test)]").next().unwrap();
            for token in [": f32", ": f64", "as f32", "as f64", "f32::", "f64::"] {
                assert!(
                    !production.contains(token),
                    "economy production sources must not contain `{token}`"
                );
            }
        }
    }

    #[test]
    fn zero_launch_policy_is_active_and_zero_priced() {
        let policy = PricingPolicy::zero_launch_default();
        assert!(policy.is_active);
        assert_eq!(policy.compute_unit_price_micro_exo, 0);
        assert_eq!(policy.storage_byte_price_micro_exo, 0);
        assert_eq!(policy.verification_op_price_micro_exo, 0);
        assert_eq!(policy.protocol_vig_bp, 0);
        assert_eq!(policy.global_ceiling_micro_exo, 0);
        assert_eq!(policy.global_floor_micro_exo, 0);
        assert_eq!(policy.value_share_bp, 0);
        assert_eq!(policy.risk_share_bp, 0);
    }
}
