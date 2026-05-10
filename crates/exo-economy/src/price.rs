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

//! Pricing inputs and the deterministic, integer-only price formula.
//!
//! Under [`crate::policy::PricingPolicy::zero_launch_default`], every
//! component of the formula resolves to `0` because:
//!
//! - all unit prices are `0`
//! - `value_share_bp` and `risk_share_bp` are `0`
//! - `protocol_vig_bp` is `0`
//! - `global_floor_micro_exo` and `global_ceiling_micro_exo` are `0`,
//!   so the final clamp pins `charged` at `0`
//!
//! Multipliers are still respected so a future governance amendment can
//! set them away from neutral without changing this code.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    error::EconomyError,
    policy::PricingPolicy,
    types::{
        ActorClass, AssuranceClass, BasisPoints, EventClass, MAX_BASIS_POINTS, MicroExo,
        NEUTRAL_MULTIPLIER_BP,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingInputs {
    pub actor_did: Did,
    pub actor_class: ActorClass,
    pub event_class: EventClass,
    pub assurance_class: AssuranceClass,

    pub declared_value_micro_exo: Option<MicroExo>,
    pub realized_value_micro_exo: Option<MicroExo>,

    pub compute_units: u64,
    pub storage_bytes: u64,
    pub verification_ops: u64,

    pub network_load_bp: BasisPoints,
    pub risk_bp: BasisPoints,
    pub market_domain: Option<String>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceBreakdown {
    pub compute_component_micro_exo: MicroExo,
    pub storage_component_micro_exo: MicroExo,
    pub verification_component_micro_exo: MicroExo,
    pub value_component_micro_exo: MicroExo,
    pub risk_component_micro_exo: MicroExo,
    pub assurance_component_micro_exo: MicroExo,
    pub network_load_component_micro_exo: MicroExo,
    pub protocol_vig_micro_exo: MicroExo,
    pub gross_amount_micro_exo: MicroExo,
    pub charged_amount_micro_exo: MicroExo,
}

impl PricingInputs {
    /// Validate structural inputs.
    ///
    /// # Errors
    /// Returns [`EconomyError`] when basis-point values are out of
    /// range or when a non-empty `market_domain` field is whitespace.
    pub fn validate(&self) -> Result<(), EconomyError> {
        require_bp("network_load_bp", self.network_load_bp)?;
        require_bp("risk_bp", self.risk_bp)?;
        if let Some(domain) = &self.market_domain {
            if domain.trim().is_empty() {
                return Err(EconomyError::EmptyField {
                    field: "pricing_inputs.market_domain",
                });
            }
        }
        Ok(())
    }
}

/// Compute the deterministic price breakdown for `inputs` under
/// `policy`. Every component is integer arithmetic with saturating
/// fall-back at `u128::MAX`.
///
/// # Errors
/// Returns [`EconomyError`] if the inputs or policy are structurally
/// invalid.
pub fn compute_breakdown(
    policy: &PricingPolicy,
    inputs: &PricingInputs,
) -> Result<PriceBreakdown, EconomyError> {
    inputs.validate()?;

    let compute =
        u128::from(inputs.compute_units).saturating_mul(policy.compute_unit_price_micro_exo);
    let storage =
        u128::from(inputs.storage_bytes).saturating_mul(policy.storage_byte_price_micro_exo);
    let verification =
        u128::from(inputs.verification_ops).saturating_mul(policy.verification_op_price_micro_exo);

    let value_component = match inputs
        .realized_value_micro_exo
        .or(inputs.declared_value_micro_exo)
    {
        Some(value) => apply_bp(value, policy.value_share_bp),
        None => 0,
    };

    let risk_component = match inputs.declared_value_micro_exo {
        Some(value) => apply_bp(value, policy.risk_share_bp)
            .saturating_mul(u128::from(inputs.risk_bp))
            .saturating_div(u128::from(MAX_BASIS_POINTS)),
        None => 0,
    };

    let cost_base = compute.saturating_add(storage).saturating_add(verification);

    let mut gross = cost_base
        .saturating_add(value_component)
        .saturating_add(risk_component);

    let actor_mult = policy.actor_multiplier_bp(inputs.actor_class);
    let event_mult = policy.event_multiplier_bp(inputs.event_class);
    let assurance_mult = policy.assurance_multiplier_bp(inputs.assurance_class);

    // Apply multipliers in order, recording the incremental contribution
    // of each one. Under the zero-launch policy `gross == 0` throughout
    // and every component is `0`. The accounting is structurally
    // correct under any future nonzero policy.
    gross = apply_multiplier(gross, actor_mult);
    gross = apply_multiplier(gross, event_mult);
    let pre_assurance = gross;
    gross = apply_multiplier(gross, assurance_mult);
    let assurance_component = gross.saturating_sub(pre_assurance);
    let pre_network = gross;
    gross = apply_multiplier(gross, inputs.network_load_bp);
    let network_load_component = gross.saturating_sub(pre_network);

    let protocol_vig = apply_bp(gross, policy.protocol_vig_bp);
    gross = gross.saturating_add(protocol_vig);

    let charged = gross
        .max(policy.global_floor_micro_exo)
        .min(policy.global_ceiling_micro_exo);

    Ok(PriceBreakdown {
        compute_component_micro_exo: compute,
        storage_component_micro_exo: storage,
        verification_component_micro_exo: verification,
        value_component_micro_exo: value_component,
        risk_component_micro_exo: risk_component,
        assurance_component_micro_exo: assurance_component,
        network_load_component_micro_exo: network_load_component,
        protocol_vig_micro_exo: protocol_vig,
        gross_amount_micro_exo: gross,
        charged_amount_micro_exo: charged,
    })
}

fn require_bp(field: &'static str, value: BasisPoints) -> Result<(), EconomyError> {
    if value > MAX_BASIS_POINTS {
        Err(EconomyError::BasisPointOutOfRange {
            field,
            value,
            max: MAX_BASIS_POINTS,
        })
    } else {
        Ok(())
    }
}

#[must_use]
pub fn apply_bp(amount: MicroExo, bp: BasisPoints) -> MicroExo {
    amount
        .saturating_mul(u128::from(bp))
        .saturating_div(u128::from(MAX_BASIS_POINTS))
}

#[must_use]
pub fn apply_multiplier(amount: MicroExo, multiplier_bp: BasisPoints) -> MicroExo {
    amount
        .saturating_mul(u128::from(multiplier_bp))
        .saturating_div(u128::from(NEUTRAL_MULTIPLIER_BP))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::new("did:exo:agent").unwrap()
    }

    fn baseline_inputs() -> PricingInputs {
        PricingInputs {
            actor_did: did(),
            actor_class: ActorClass::Human,
            event_class: EventClass::AvcValidate,
            assurance_class: AssuranceClass::Standard,
            declared_value_micro_exo: Some(1_000_000),
            realized_value_micro_exo: None,
            compute_units: 100,
            storage_bytes: 4_096,
            verification_ops: 5,
            network_load_bp: NEUTRAL_MULTIPLIER_BP,
            risk_bp: 1_500,
            market_domain: Some("commandbase".into()),
            timestamp: Timestamp::new(1_000, 0),
        }
    }

    #[test]
    fn zero_launch_breakdown_is_zero_for_human_baseline() {
        let policy = PricingPolicy::zero_launch_default();
        let breakdown = compute_breakdown(&policy, &baseline_inputs()).unwrap();
        assert_eq!(breakdown.compute_component_micro_exo, 0);
        assert_eq!(breakdown.storage_component_micro_exo, 0);
        assert_eq!(breakdown.verification_component_micro_exo, 0);
        assert_eq!(breakdown.value_component_micro_exo, 0);
        assert_eq!(breakdown.risk_component_micro_exo, 0);
        assert_eq!(breakdown.protocol_vig_micro_exo, 0);
        assert_eq!(breakdown.gross_amount_micro_exo, 0);
        assert_eq!(breakdown.charged_amount_micro_exo, 0);
    }

    #[test]
    fn zero_launch_breakdown_is_zero_for_every_actor_event_assurance_combination() {
        let policy = PricingPolicy::zero_launch_default();
        for actor in ActorClass::ALL {
            for event in EventClass::ALL {
                for assurance in AssuranceClass::ALL {
                    let mut inputs = baseline_inputs();
                    inputs.actor_class = actor;
                    inputs.event_class = event;
                    inputs.assurance_class = assurance;
                    let b = compute_breakdown(&policy, &inputs).unwrap();
                    assert_eq!(
                        b.charged_amount_micro_exo, 0,
                        "expected zero for {actor:?}/{event:?}/{assurance:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn zero_launch_breakdown_is_zero_even_with_max_inputs() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = PricingInputs {
            actor_did: did(),
            actor_class: ActorClass::Holon,
            event_class: EventClass::HolonCommercialAction,
            assurance_class: AssuranceClass::LegalGrade,
            declared_value_micro_exo: Some(u128::MAX),
            realized_value_micro_exo: Some(u128::MAX),
            compute_units: u64::MAX,
            storage_bytes: u64::MAX,
            verification_ops: u64::MAX,
            network_load_bp: MAX_BASIS_POINTS,
            risk_bp: MAX_BASIS_POINTS,
            market_domain: None,
            timestamp: Timestamp::new(1, 0),
        };
        let b = compute_breakdown(&policy, &inputs).unwrap();
        assert_eq!(b.charged_amount_micro_exo, 0);
    }

    #[test]
    fn rejects_invalid_basis_points() {
        let policy = PricingPolicy::zero_launch_default();
        let mut inputs = baseline_inputs();
        inputs.risk_bp = MAX_BASIS_POINTS + 1;
        assert!(compute_breakdown(&policy, &inputs).is_err());
        let mut inputs = baseline_inputs();
        inputs.network_load_bp = MAX_BASIS_POINTS + 1;
        assert!(compute_breakdown(&policy, &inputs).is_err());
    }

    #[test]
    fn rejects_blank_market_domain() {
        let policy = PricingPolicy::zero_launch_default();
        let mut inputs = baseline_inputs();
        inputs.market_domain = Some("   ".into());
        assert!(compute_breakdown(&policy, &inputs).is_err());
    }

    #[test]
    fn deterministic_repeated_call() {
        let policy = PricingPolicy::zero_launch_default();
        let inputs = baseline_inputs();
        let b1 = compute_breakdown(&policy, &inputs).unwrap();
        let b2 = compute_breakdown(&policy, &inputs).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn apply_bp_at_max_saturates_without_panic() {
        // u128::MAX * 10_000 saturates to u128::MAX, then / 10_000
        // returns u128::MAX / 10_000. The point of this test is that the
        // helper never panics under adversarial inputs.
        let result = apply_bp(u128::MAX, MAX_BASIS_POINTS);
        assert_eq!(
            result,
            u128::MAX.saturating_div(u128::from(MAX_BASIS_POINTS))
        );
        assert!(result > 0);
    }

    #[test]
    fn apply_bp_at_value_one_basis_point() {
        // 10_000 * 1 / 10_000 == 1
        assert_eq!(apply_bp(10_000, 1), 1);
    }

    #[test]
    fn apply_multiplier_neutral_returns_input() {
        assert_eq!(apply_multiplier(1_000, NEUTRAL_MULTIPLIER_BP), 1_000);
    }

    #[test]
    fn apply_multiplier_zero_returns_zero() {
        assert_eq!(apply_multiplier(1_000, 0), 0);
    }

    #[test]
    fn apply_multiplier_doubles_amount_at_20000_bp() {
        assert_eq!(apply_multiplier(1_000, 20_000), 2_000);
    }

    #[test]
    fn breakdown_with_no_value_inputs_zero_components() {
        let policy = PricingPolicy::zero_launch_default();
        let mut inputs = baseline_inputs();
        inputs.declared_value_micro_exo = None;
        inputs.realized_value_micro_exo = None;
        let breakdown = compute_breakdown(&policy, &inputs).unwrap();
        assert_eq!(breakdown.value_component_micro_exo, 0);
        assert_eq!(breakdown.risk_component_micro_exo, 0);
    }

    #[test]
    fn breakdown_with_realized_value_but_no_declared_uses_realized() {
        // Custom policy with nonzero value share so we can observe the
        // realized-vs-declared selection without changing other gates.
        let mut policy = PricingPolicy::zero_launch_default();
        policy.value_share_bp = 1_000;
        policy.global_ceiling_micro_exo = u128::MAX;
        let mut inputs = baseline_inputs();
        inputs.declared_value_micro_exo = None;
        inputs.realized_value_micro_exo = Some(1_000_000);
        let breakdown = compute_breakdown(&policy, &inputs).unwrap();
        assert_eq!(breakdown.value_component_micro_exo, 100_000);
    }

    #[test]
    fn breakdown_under_nonzero_policy_produces_positive_charged() {
        // Custom policy with a small compute price so we can observe
        // a nonzero charged amount. This validates the structural
        // correctness of the formula under future activation while
        // keeping the launch policy exclusively zero.
        let mut policy = PricingPolicy::zero_launch_default();
        policy.compute_unit_price_micro_exo = 1;
        policy.global_ceiling_micro_exo = u128::MAX;
        let mut inputs = baseline_inputs();
        inputs.compute_units = 1_000;
        let breakdown = compute_breakdown(&policy, &inputs).unwrap();
        assert!(breakdown.charged_amount_micro_exo > 0);
    }
}
