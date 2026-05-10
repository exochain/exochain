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

//! Settlement quotes — the bridge between pricing inputs and a
//! settlement receipt. Every quote carries a deterministic hash so
//! later settlement can prove the quote was unmodified.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    error::EconomyError,
    policy::PricingPolicy,
    price::{PriceBreakdown, PricingInputs, compute_breakdown},
    revenue_share::{RevenueShareLine, distribute_revenue},
    types::{ActorClass, AssuranceClass, EventClass, MicroExo, PricingMode, ZeroFeeReason},
};

/// Domain tag used when computing the canonical quote hash.
pub const ECONOMY_QUOTE_HASH_DOMAIN: &str = "exo.economy.quote.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementQuote {
    pub id: String,
    pub policy_id: String,
    pub policy_version: String,
    pub actor_did: Did,
    pub actor_class: ActorClass,
    pub event_class: EventClass,
    pub assurance_class: AssuranceClass,

    pub pricing_mode: PricingMode,
    pub zero_fee_reason: Option<ZeroFeeReason>,

    pub gross_amount_micro_exo: MicroExo,
    pub discount_amount_micro_exo: MicroExo,
    pub subsidy_amount_micro_exo: MicroExo,
    pub charged_amount_micro_exo: MicroExo,

    pub breakdown: PriceBreakdown,
    pub revenue_shares: Vec<RevenueShareLine>,

    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub quote_hash: Hash256,
}

#[derive(Serialize)]
struct QuoteHashPayload<'a> {
    domain: &'static str,
    id: &'a str,
    policy_id: &'a str,
    policy_version: &'a str,
    actor_did: &'a Did,
    actor_class: &'a ActorClass,
    event_class: &'a EventClass,
    assurance_class: &'a AssuranceClass,
    pricing_mode: &'a PricingMode,
    zero_fee_reason: Option<&'a ZeroFeeReason>,
    gross_amount_micro_exo: MicroExo,
    discount_amount_micro_exo: MicroExo,
    subsidy_amount_micro_exo: MicroExo,
    charged_amount_micro_exo: MicroExo,
    breakdown: &'a PriceBreakdown,
    revenue_shares: &'a [RevenueShareLine],
    issued_at: &'a Timestamp,
    expires_at: &'a Timestamp,
}

impl SettlementQuote {
    /// Recompute the canonical quote hash and compare it with the one
    /// recorded inside the quote. Used by settlement to detect
    /// tampering.
    ///
    /// # Errors
    /// Returns [`EconomyError::Serialization`] when CBOR encoding fails.
    pub fn verify_hash(&self) -> Result<bool, EconomyError> {
        Ok(canonical_hash(self)? == self.quote_hash)
    }

    /// Returns true when `now` is at or after `expires_at`.
    #[must_use]
    pub fn is_expired(&self, now: &Timestamp) -> bool {
        now >= &self.expires_at
    }
}

fn canonical_hash(quote: &SettlementQuote) -> Result<Hash256, EconomyError> {
    let payload = QuoteHashPayload {
        domain: ECONOMY_QUOTE_HASH_DOMAIN,
        id: &quote.id,
        policy_id: &quote.policy_id,
        policy_version: &quote.policy_version,
        actor_did: &quote.actor_did,
        actor_class: &quote.actor_class,
        event_class: &quote.event_class,
        assurance_class: &quote.assurance_class,
        pricing_mode: &quote.pricing_mode,
        zero_fee_reason: quote.zero_fee_reason.as_ref(),
        gross_amount_micro_exo: quote.gross_amount_micro_exo,
        discount_amount_micro_exo: quote.discount_amount_micro_exo,
        subsidy_amount_micro_exo: quote.subsidy_amount_micro_exo,
        charged_amount_micro_exo: quote.charged_amount_micro_exo,
        breakdown: &quote.breakdown,
        revenue_shares: &quote.revenue_shares,
        issued_at: &quote.issued_at,
        expires_at: &quote.expires_at,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf)?;
    Ok(Hash256::digest(&buf))
}

/// Build a deterministic `SettlementQuote` from `inputs` under `policy`.
///
/// During the zero-launch phase, `charged_amount_micro_exo` is always
/// `0` and `zero_fee_reason` is always populated. Future governance
/// amendments can flip the policy to a non-zero shape without changing
/// this function.
///
/// # Errors
/// Returns [`EconomyError`] for structural input failures, invalid
/// policy state, or CBOR encoding errors.
pub fn quote(
    policy: &PricingPolicy,
    inputs: &PricingInputs,
    quote_id: String,
) -> Result<SettlementQuote, EconomyError> {
    policy.validate()?;
    if quote_id.trim().is_empty() {
        return Err(EconomyError::EmptyField { field: "quote.id" });
    }

    let breakdown = compute_breakdown(policy, inputs)?;
    let pricing_mode = if breakdown.charged_amount_micro_exo == 0 {
        PricingMode::Zero
    } else {
        PricingMode::Hybrid
    };
    let zero_fee_reason = if breakdown.charged_amount_micro_exo == 0 {
        Some(infer_zero_fee_reason(inputs))
    } else {
        None
    };

    let revenue_shares = match policy.revenue_share_template_for(inputs.event_class) {
        Some(template) => distribute_revenue(template, breakdown.charged_amount_micro_exo)?,
        None => Vec::new(),
    };

    let expires_at = compute_expiry(inputs.timestamp, policy.quote_ttl_ms);

    let mut quote = SettlementQuote {
        id: quote_id,
        policy_id: policy.id.clone(),
        policy_version: policy.version.clone(),
        actor_did: inputs.actor_did.clone(),
        actor_class: inputs.actor_class,
        event_class: inputs.event_class,
        assurance_class: inputs.assurance_class,
        pricing_mode,
        zero_fee_reason,
        gross_amount_micro_exo: breakdown.gross_amount_micro_exo,
        discount_amount_micro_exo: 0,
        subsidy_amount_micro_exo: 0,
        charged_amount_micro_exo: breakdown.charged_amount_micro_exo,
        breakdown,
        revenue_shares,
        issued_at: inputs.timestamp,
        expires_at,
        quote_hash: Hash256::ZERO,
    };
    quote.quote_hash = canonical_hash(&quote)?;
    Ok(quote)
}

fn infer_zero_fee_reason(inputs: &PricingInputs) -> ZeroFeeReason {
    match inputs.event_class {
        EventClass::IdentityResolution | EventClass::AgentPassportLookup => {
            ZeroFeeReason::IdentityLookup
        }
        EventClass::AvcValidate => ZeroFeeReason::AgentValidation,
        EventClass::ConsentRevoke => ZeroFeeReason::ConsentRevocation,
        _ => match inputs.actor_class {
            ActorClass::Human | ActorClass::HumanSponsoredAgent => ZeroFeeReason::HumanBaseline,
            ActorClass::PublicGood => ZeroFeeReason::PublicGood,
            _ => ZeroFeeReason::PolicyConfiguredZero,
        },
    }
}

fn compute_expiry(issued_at: Timestamp, ttl_ms: u64) -> Timestamp {
    let physical = issued_at.physical_ms.saturating_add(ttl_ms);
    Timestamp::new(physical, issued_at.logical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActorClass, AssuranceClass, EventClass};

    fn did() -> Did {
        Did::new("did:exo:agent").unwrap()
    }

    fn baseline_inputs(actor: ActorClass, event: EventClass) -> PricingInputs {
        PricingInputs {
            actor_did: did(),
            actor_class: actor,
            event_class: event,
            assurance_class: AssuranceClass::Standard,
            declared_value_micro_exo: Some(1_000_000),
            realized_value_micro_exo: None,
            compute_units: 100,
            storage_bytes: 4_096,
            verification_ops: 5,
            network_load_bp: 10_000,
            risk_bp: 1_500,
            market_domain: Some("commandbase".into()),
            timestamp: Timestamp::new(1_000_000, 0),
        }
    }

    #[test]
    fn human_baseline_quotes_zero() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::Human, EventClass::AvcValidate),
            "q1".into(),
        )
        .unwrap();
        assert_eq!(q.charged_amount_micro_exo, 0);
        assert_eq!(q.zero_fee_reason, Some(ZeroFeeReason::AgentValidation));
        assert_eq!(q.pricing_mode, PricingMode::Zero);
    }

    #[test]
    fn quote_hash_is_deterministic_for_same_inputs() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q1 = quote(&policy, &inputs, "q-id".into()).unwrap();
        let q2 = quote(&policy, &inputs, "q-id".into()).unwrap();
        assert_eq!(q1.quote_hash, q2.quote_hash);
        assert_ne!(q1.quote_hash, Hash256::ZERO);
    }

    #[test]
    fn quote_hash_changes_with_canonical_input_change() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        // Varying actor_did is part of the canonical hash payload even
        // when the zero-launch breakdown is identical.
        let mut other = inputs.clone();
        other.actor_did = Did::new("did:exo:other-agent").unwrap();
        let q1 = quote(&policy, &inputs, "q-id".into()).unwrap();
        let q2 = quote(&policy, &other, "q-id".into()).unwrap();
        assert_ne!(q1.quote_hash, q2.quote_hash);
    }

    #[test]
    fn quote_hash_changes_with_event_class() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs1 = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let inputs2 = baseline_inputs(ActorClass::Holon, EventClass::AvcValidate);
        let q1 = quote(&policy, &inputs1, "q-id".into()).unwrap();
        let q2 = quote(&policy, &inputs2, "q-id".into()).unwrap();
        assert_ne!(q1.quote_hash, q2.quote_hash);
    }

    #[test]
    fn quote_hash_changes_with_actor_class() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs1 = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let inputs2 = baseline_inputs(ActorClass::Human, EventClass::HolonCommercialAction);
        let q1 = quote(&policy, &inputs1, "q-id".into()).unwrap();
        let q2 = quote(&policy, &inputs2, "q-id".into()).unwrap();
        assert_ne!(q1.quote_hash, q2.quote_hash);
    }

    #[test]
    fn quote_hash_changes_with_timestamp() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs1 = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let mut inputs2 = inputs1.clone();
        inputs2.timestamp = Timestamp::new(2_000_000, 0);
        let q1 = quote(&policy, &inputs1, "q-id".into()).unwrap();
        let q2 = quote(&policy, &inputs2, "q-id".into()).unwrap();
        assert_ne!(q1.quote_hash, q2.quote_hash);
    }

    #[test]
    fn quote_hash_includes_id() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q1 = quote(&policy, &inputs, "id-a".into()).unwrap();
        let q2 = quote(&policy, &inputs, "id-b".into()).unwrap();
        assert_ne!(q1.quote_hash, q2.quote_hash);
    }

    #[test]
    fn verify_hash_succeeds_for_unmodified_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction),
            "q1".into(),
        )
        .unwrap();
        assert!(q.verify_hash().unwrap());
    }

    #[test]
    fn verify_hash_fails_when_field_tampered() {
        let policy = PricingPolicy::zero_launch_default();
        let mut q = quote(
            &policy,
            &baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction),
            "q1".into(),
        )
        .unwrap();
        q.charged_amount_micro_exo = 999;
        assert!(!q.verify_hash().unwrap());
    }

    #[test]
    fn every_actor_event_assurance_combination_quotes_zero_under_zero_launch() {
        let policy = PricingPolicy::zero_launch_default();
        for actor in ActorClass::ALL {
            for event in EventClass::ALL {
                let mut inputs = baseline_inputs(actor, event);
                for assurance in AssuranceClass::ALL {
                    inputs.assurance_class = assurance;
                    let q = quote(&policy, &inputs, "q".into()).unwrap();
                    assert_eq!(q.charged_amount_micro_exo, 0);
                    assert!(q.zero_fee_reason.is_some());
                    assert_eq!(q.pricing_mode, PricingMode::Zero);
                    let breakdown = q.breakdown;
                    assert_eq!(breakdown.compute_component_micro_exo, 0);
                    assert_eq!(breakdown.storage_component_micro_exo, 0);
                    assert_eq!(breakdown.verification_component_micro_exo, 0);
                    assert_eq!(breakdown.value_component_micro_exo, 0);
                    assert_eq!(breakdown.risk_component_micro_exo, 0);
                    assert_eq!(breakdown.assurance_component_micro_exo, 0);
                    assert_eq!(breakdown.network_load_component_micro_exo, 0);
                    assert_eq!(breakdown.protocol_vig_micro_exo, 0);
                    for line in &q.revenue_shares {
                        assert_eq!(line.amount_micro_exo, 0);
                    }
                }
            }
        }
    }

    #[test]
    fn zero_fee_reason_for_identity_resolution_is_identity_lookup() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::Human, EventClass::IdentityResolution),
            "q".into(),
        )
        .unwrap();
        assert_eq!(q.zero_fee_reason, Some(ZeroFeeReason::IdentityLookup));
    }

    #[test]
    fn zero_fee_reason_for_consent_revoke_is_consent_revocation() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::AutonomousAgent, EventClass::ConsentRevoke),
            "q".into(),
        )
        .unwrap();
        assert_eq!(q.zero_fee_reason, Some(ZeroFeeReason::ConsentRevocation));
    }

    #[test]
    fn zero_fee_reason_for_holon_other_event_is_policy_configured_zero() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction),
            "q".into(),
        )
        .unwrap();
        assert_eq!(q.zero_fee_reason, Some(ZeroFeeReason::PolicyConfiguredZero));
    }

    #[test]
    fn zero_fee_reason_for_public_good_is_public_good() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::PublicGood, EventClass::GovernanceVote),
            "q".into(),
        )
        .unwrap();
        assert_eq!(q.zero_fee_reason, Some(ZeroFeeReason::PublicGood));
    }

    #[test]
    fn zero_fee_reason_for_human_sponsored_agent_is_human_baseline() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(
            &policy,
            &baseline_inputs(ActorClass::HumanSponsoredAgent, EventClass::Escalation),
            "q".into(),
        )
        .unwrap();
        assert_eq!(q.zero_fee_reason, Some(ZeroFeeReason::HumanBaseline));
    }

    #[test]
    fn rejects_blank_quote_id() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        assert!(quote(&policy, &inputs, "   ".into()).is_err());
    }

    #[test]
    fn rejects_invalid_policy() {
        let mut policy = PricingPolicy::zero_launch_default();
        policy.id = "".into();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        assert!(quote(&policy, &inputs, "q".into()).is_err());
    }

    #[test]
    fn quote_expires_at_issued_at_plus_ttl() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q = quote(&policy, &inputs, "q".into()).unwrap();
        assert_eq!(
            q.expires_at.physical_ms,
            inputs.timestamp.physical_ms + policy.quote_ttl_ms
        );
    }

    #[test]
    fn is_expired_at_or_after_expires_at() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q = quote(&policy, &inputs, "q".into()).unwrap();
        let just_inside = Timestamp::new(q.expires_at.physical_ms - 1, q.expires_at.logical);
        let at_expiry = q.expires_at;
        assert!(!q.is_expired(&just_inside));
        assert!(q.is_expired(&at_expiry));
    }

    #[test]
    fn revenue_shares_present_for_seeded_template() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q = quote(&policy, &inputs, "q".into()).unwrap();
        assert!(!q.revenue_shares.is_empty());
        for line in &q.revenue_shares {
            assert_eq!(line.amount_micro_exo, 0);
        }
    }

    #[test]
    fn revenue_shares_empty_when_no_template() {
        let mut policy = PricingPolicy::zero_launch_default();
        policy.revenue_share_templates.clear();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q = quote(&policy, &inputs, "q".into()).unwrap();
        assert!(q.revenue_shares.is_empty());
    }

    #[test]
    fn nonzero_policy_quote_returns_none_zero_fee_reason_and_hybrid_mode() {
        // Validates the structural Hybrid / no-zero-fee-reason branches
        // of `quote()` while keeping the launch policy exclusively zero.
        let mut policy = PricingPolicy::zero_launch_default();
        policy.compute_unit_price_micro_exo = 1;
        policy.global_ceiling_micro_exo = u128::MAX;
        let mut inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        inputs.compute_units = 1_000;
        let q = quote(&policy, &inputs, "q-nonzero".into()).unwrap();
        assert!(q.charged_amount_micro_exo > 0);
        assert!(q.zero_fee_reason.is_none());
        assert_eq!(q.pricing_mode, PricingMode::Hybrid);
    }

    #[test]
    fn round_trip_serialization() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs(ActorClass::Holon, EventClass::HolonCommercialAction);
        let q = quote(&policy, &inputs, "q".into()).unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&q, &mut buf).unwrap();
        let decoded: SettlementQuote = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, q);
    }
}
