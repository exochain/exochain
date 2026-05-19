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

//! SDK re-exports for the custody-native economy layer.
//!
//! The launch policy is zero-priced: every quote and every settlement
//! resolves to `charged_amount_micro_exo == 0`. The settlement
//! mechanism still runs end-to-end so future governance amendments can
//! flip nonzero pricing on without changing this surface.
//!
//! ```
//! use exochain_sdk::economy::{
//!     ActorClass, AssuranceClass, EconomyStore, EventClass, InMemoryEconomyStore,
//!     PricingInputs, SettlementContext, ZeroFeeReason, quote, settle,
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
//! let q = quote(&policy, &inputs, "q-1".into()).unwrap();
//! assert_eq!(q.charged_amount_micro_exo, 0);
//! assert!(q.zero_fee_reason.is_some());
//!
//! let context = SettlementContext {
//!     receipt_id: "rec-1".into(),
//!     custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
//!     prev_settlement_receipt: store.latest_receipt_hash(),
//!     now: Timestamp::new(1_010_000, 0),
//! };
//! let receipt = settle(&q, &context, |_| Signature::from_bytes([7; 64])).unwrap();
//! assert_eq!(receipt.charged_amount_micro_exo, 0);
//! ```

pub use exo_economy::{
    ADOPTION_EVENT_HASH_DOMAIN, AUTOMATED_SETTLEMENT_EVENT_HASH_DOMAIN, ActorClass,
    ActorMultiplier, AdopterType, AdoptionEvent, ApprovalStatus, AssuranceClass,
    AssuranceMultiplier, AuthorityEnvelopeRef, AutomatedSettlementEvent, AutomatedSettlementInputs,
    AutomatedSettlementRiskState, BAILMENT_TERMS_HASH_DOMAIN, BAILMENT_WRAPPER_HASH_DOMAIN,
    BailmentTerms, BailmentWrapper, BailmentWrapperStatus, BasisPoints, BeneficiaryRef,
    BeneficiaryType, CONTRIBUTION_ACCEPTANCE_HASH_DOMAIN, CONTRIBUTION_OFFER_HASH_DOMAIN,
    CONTRIBUTION_RECEIPT_HASH_DOMAIN, ContributionAcceptance, ContributionCategory,
    ContributionContributorType, ContributionOffer, ContributionOfferStatus, ContributionReceipt,
    ContributionType, ContributorType, DEFAULT_QUOTE_TTL_MS, DurationPolicy, ECONOMY_DOMAINS,
    ECONOMY_POLICY_HASH_DOMAIN, ECONOMY_QUOTE_HASH_DOMAIN, ECONOMY_RECORD_ANCHOR_HASH_DOMAIN,
    EconomyError, EconomyObjectKind, EconomyRecordAnchor, EconomyStore, EventClass,
    EventMultiplier, ExpirationOrReview, HONOR_GOOD_RULESET_HASH_DOMAIN, HonorGoodRuleset,
    InMemoryEconomyStore, LEGACY_RECEIPT_HASH_DOMAIN, LegacyReceipt, LegacyReceiptStatus,
    LegalEffect, MAX_BASIS_POINTS, MAX_MULTIPLIER_BP, MISSION_HASH_DOMAIN,
    MISSION_SETTLEMENT_HASH_DOMAIN, MaterialityReview, MaterialityReviewStatus, MaterialityTier,
    MicroExo, Mission, MissionPurpose, MissionSettlement, MissionStatus, MissionType,
    NEUTRAL_MULTIPLIER_BP, ParticipantRef, PriceBreakdown, PricingInputs, PricingMode,
    PricingPolicy, RequiredAuthorityLevel, RevenueRecipient, RevenueShareLine,
    RevenueShareTemplate, RulesetRecipientType, RulesetScope, RulesetShareLine, RulesetStatus,
    SETTLEMENT_RECEIPT_HASH_DOMAIN, SettlementBasis, SettlementContext, SettlementLine,
    SettlementQuote, SettlementReceipt, TemplateAllocation, USE_EVENT_HASH_DOMAIN, UseEvent,
    UseType, VALUE_CONTRIBUTION_NODE_HASH_DOMAIN, VALUE_EVENT_HASH_DOMAIN, ValueBasis,
    ValueContributionNode, ValueContributionStatus, ValueEvent, ZeroFeeReason,
    apex_velocity_catalyst_client_services_mission, apex_velocity_catalyst_client_services_ruleset,
    apex_velocity_catalyst_software_channel_ruleset, apply_bp, apply_multiplier,
    archon_exoforge_legacy_receipt, archon_exoforge_ruleset, checked_basis_point_amount,
    compute_breakdown, distribute_revenue, paperclip_commandbase_legacy_receipt,
    paperclip_commandbase_ruleset, quote, settle, settlement_lines_from_ruleset,
    validate_basis_allocations, zero_launch_mission_settlement_reason,
};
