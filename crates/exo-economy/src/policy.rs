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

//! Pricing policy — bounded, integer-only, governance-versioned.
//!
//! `PricingPolicy::zero_launch_default()` defines the launch policy: every
//! active rate, multiplier, fee, vigorish, floor, and ceiling is zero.
//! The policy is structurally complete so that a future governance
//! amendment can flip nonzero pricing on without rewriting the type
//! system.

use serde::{Deserialize, Serialize};

use crate::{
    error::EconomyError,
    revenue_share::RevenueShareTemplate,
    types::{
        ActorClass, AssuranceClass, BasisPoints, EventClass, MAX_BASIS_POINTS, MAX_MULTIPLIER_BP,
        MicroExo, NEUTRAL_MULTIPLIER_BP,
    },
};

/// Domain tag for canonical policy hashes.
pub const ECONOMY_POLICY_HASH_DOMAIN: &str = "exo.economy.policy.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorMultiplier {
    pub actor_class: ActorClass,
    pub multiplier_bp: BasisPoints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMultiplier {
    pub event_class: EventClass,
    pub multiplier_bp: BasisPoints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceMultiplier {
    pub assurance_class: AssuranceClass,
    pub multiplier_bp: BasisPoints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingPolicy {
    pub id: String,
    pub version: String,
    pub is_active: bool,

    // Unit rates (MicroExo per unit).
    pub compute_unit_price_micro_exo: MicroExo,
    pub storage_byte_price_micro_exo: MicroExo,
    pub verification_op_price_micro_exo: MicroExo,

    // Global protocol vigorish.
    pub protocol_vig_bp: BasisPoints,

    // Human baseline rules.
    pub human_zero_fee_enabled: bool,
    pub human_max_charge_micro_exo: MicroExo,

    // Floors and ceilings.
    pub global_floor_micro_exo: MicroExo,
    pub global_ceiling_micro_exo: MicroExo,

    // Value-share defaults.
    pub value_share_bp: BasisPoints,
    pub risk_share_bp: BasisPoints,

    // Bounded multipliers.
    pub actor_multipliers: Vec<ActorMultiplier>,
    pub event_multipliers: Vec<EventMultiplier>,
    pub assurance_multipliers: Vec<AssuranceMultiplier>,

    // Revenue share templates indexed by event class.
    pub revenue_share_templates: Vec<RevenueShareTemplate>,

    // Quote validity window in milliseconds.
    pub quote_ttl_ms: u64,
}

impl PricingPolicy {
    /// The launch-phase policy: every active price is zero, every
    /// multiplier is the neutral 1.0× (10_000 bp), and the ceiling is
    /// also zero so the deterministic pricing formula clamps to zero
    /// regardless of inputs.
    #[must_use]
    pub fn zero_launch_default() -> Self {
        Self {
            id: "exo.economy.zero-launch".into(),
            version: "v1".into(),
            is_active: true,
            compute_unit_price_micro_exo: 0,
            storage_byte_price_micro_exo: 0,
            verification_op_price_micro_exo: 0,
            protocol_vig_bp: 0,
            human_zero_fee_enabled: true,
            human_max_charge_micro_exo: 0,
            global_floor_micro_exo: 0,
            global_ceiling_micro_exo: 0,
            value_share_bp: 0,
            risk_share_bp: 0,
            actor_multipliers: ActorClass::ALL
                .iter()
                .map(|c| ActorMultiplier {
                    actor_class: *c,
                    multiplier_bp: NEUTRAL_MULTIPLIER_BP,
                })
                .collect(),
            event_multipliers: EventClass::ALL
                .iter()
                .map(|c| EventMultiplier {
                    event_class: *c,
                    multiplier_bp: NEUTRAL_MULTIPLIER_BP,
                })
                .collect(),
            assurance_multipliers: AssuranceClass::ALL
                .iter()
                .map(|c| AssuranceMultiplier {
                    assurance_class: *c,
                    multiplier_bp: NEUTRAL_MULTIPLIER_BP,
                })
                .collect(),
            revenue_share_templates: RevenueShareTemplate::zero_launch_templates(),
            quote_ttl_ms: crate::types::DEFAULT_QUOTE_TTL_MS,
        }
    }

    /// Validate every structural and bounded invariant.
    ///
    /// # Errors
    /// Returns [`EconomyError`] when any field is outside the legal range
    /// or the floor exceeds the ceiling.
    pub fn validate(&self) -> Result<(), EconomyError> {
        if self.id.trim().is_empty() {
            return Err(EconomyError::EmptyField { field: "policy.id" });
        }
        if self.version.trim().is_empty() {
            return Err(EconomyError::EmptyField {
                field: "policy.version",
            });
        }
        Self::require_bp("protocol_vig_bp", self.protocol_vig_bp)?;
        Self::require_bp("value_share_bp", self.value_share_bp)?;
        Self::require_bp("risk_share_bp", self.risk_share_bp)?;
        for m in &self.actor_multipliers {
            Self::require_multiplier("actor_multipliers", m.multiplier_bp)?;
        }
        for m in &self.event_multipliers {
            Self::require_multiplier("event_multipliers", m.multiplier_bp)?;
        }
        for m in &self.assurance_multipliers {
            Self::require_multiplier("assurance_multipliers", m.multiplier_bp)?;
        }
        for template in &self.revenue_share_templates {
            template.validate()?;
        }
        if self.global_floor_micro_exo > self.global_ceiling_micro_exo {
            return Err(EconomyError::FloorAboveCeiling {
                floor: self.global_floor_micro_exo,
                ceiling: self.global_ceiling_micro_exo,
            });
        }
        if self.quote_ttl_ms == 0 {
            return Err(EconomyError::InvalidInput {
                reason: "quote_ttl_ms must be nonzero".into(),
            });
        }
        Ok(())
    }

    /// Returns the actor multiplier in basis points or the neutral
    /// multiplier when the actor class is not listed.
    #[must_use]
    pub fn actor_multiplier_bp(&self, actor_class: ActorClass) -> BasisPoints {
        self.actor_multipliers
            .iter()
            .find(|m| m.actor_class == actor_class)
            .map(|m| m.multiplier_bp)
            .unwrap_or(NEUTRAL_MULTIPLIER_BP)
    }

    /// Returns the event multiplier in basis points.
    #[must_use]
    pub fn event_multiplier_bp(&self, event_class: EventClass) -> BasisPoints {
        self.event_multipliers
            .iter()
            .find(|m| m.event_class == event_class)
            .map(|m| m.multiplier_bp)
            .unwrap_or(NEUTRAL_MULTIPLIER_BP)
    }

    /// Returns the assurance multiplier in basis points.
    #[must_use]
    pub fn assurance_multiplier_bp(&self, assurance_class: AssuranceClass) -> BasisPoints {
        self.assurance_multipliers
            .iter()
            .find(|m| m.assurance_class == assurance_class)
            .map(|m| m.multiplier_bp)
            .unwrap_or(NEUTRAL_MULTIPLIER_BP)
    }

    /// Returns the revenue share template registered for an event class
    /// or `None` if no template applies.
    #[must_use]
    pub fn revenue_share_template_for(
        &self,
        event_class: EventClass,
    ) -> Option<&RevenueShareTemplate> {
        self.revenue_share_templates
            .iter()
            .find(|t| t.event_class == event_class)
    }

    fn require_bp(field: &'static str, value: BasisPoints) -> Result<(), EconomyError> {
        if value > MAX_BASIS_POINTS {
            return Err(EconomyError::BasisPointOutOfRange {
                field,
                value,
                max: MAX_BASIS_POINTS,
            });
        }
        Ok(())
    }

    fn require_multiplier(field: &'static str, value: BasisPoints) -> Result<(), EconomyError> {
        if value > MAX_MULTIPLIER_BP {
            return Err(EconomyError::BasisPointOutOfRange {
                field,
                value,
                max: MAX_MULTIPLIER_BP,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZeroFeeReason;

    #[test]
    fn zero_launch_default_validates() {
        let p = PricingPolicy::zero_launch_default();
        p.validate().unwrap();
    }

    #[test]
    fn zero_launch_default_is_active() {
        let p = PricingPolicy::zero_launch_default();
        assert!(p.is_active);
    }

    #[test]
    fn zero_launch_default_zero_rate_invariants() {
        let p = PricingPolicy::zero_launch_default();
        assert_eq!(p.compute_unit_price_micro_exo, 0);
        assert_eq!(p.storage_byte_price_micro_exo, 0);
        assert_eq!(p.verification_op_price_micro_exo, 0);
        assert_eq!(p.protocol_vig_bp, 0);
        assert_eq!(p.human_max_charge_micro_exo, 0);
        assert_eq!(p.global_floor_micro_exo, 0);
        assert_eq!(p.global_ceiling_micro_exo, 0);
        assert_eq!(p.value_share_bp, 0);
        assert_eq!(p.risk_share_bp, 0);
    }

    #[test]
    fn zero_launch_default_multipliers_are_neutral_for_every_class() {
        let p = PricingPolicy::zero_launch_default();
        for c in ActorClass::ALL {
            assert_eq!(p.actor_multiplier_bp(c), NEUTRAL_MULTIPLIER_BP);
        }
        for c in EventClass::ALL {
            assert_eq!(p.event_multiplier_bp(c), NEUTRAL_MULTIPLIER_BP);
        }
        for c in AssuranceClass::ALL {
            assert_eq!(p.assurance_multiplier_bp(c), NEUTRAL_MULTIPLIER_BP);
        }
    }

    #[test]
    fn validate_rejects_empty_id() {
        let mut p = PricingPolicy::zero_launch_default();
        p.id = "   ".into();
        let err = p.validate().unwrap_err();
        assert!(matches!(err, EconomyError::EmptyField { field } if field == "policy.id"));
    }

    #[test]
    fn validate_rejects_empty_version() {
        let mut p = PricingPolicy::zero_launch_default();
        p.version = "".into();
        let err = p.validate().unwrap_err();
        assert!(matches!(err, EconomyError::EmptyField { field } if field == "policy.version"));
    }

    #[test]
    fn validate_rejects_protocol_vig_out_of_range() {
        let mut p = PricingPolicy::zero_launch_default();
        p.protocol_vig_bp = 99_999;
        let err = p.validate().unwrap_err();
        assert!(matches!(err, EconomyError::BasisPointOutOfRange { .. }));
    }

    #[test]
    fn validate_rejects_floor_above_ceiling() {
        let mut p = PricingPolicy::zero_launch_default();
        p.global_floor_micro_exo = 10;
        p.global_ceiling_micro_exo = 5;
        let err = p.validate().unwrap_err();
        assert!(matches!(err, EconomyError::FloorAboveCeiling { .. }));
    }

    #[test]
    fn validate_rejects_zero_quote_ttl() {
        let mut p = PricingPolicy::zero_launch_default();
        p.quote_ttl_ms = 0;
        let err = p.validate().unwrap_err();
        assert!(matches!(err, EconomyError::InvalidInput { .. }));
    }

    #[test]
    fn validate_rejects_value_share_out_of_range() {
        let mut p = PricingPolicy::zero_launch_default();
        p.value_share_bp = 11_000;
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_risk_share_out_of_range() {
        let mut p = PricingPolicy::zero_launch_default();
        p.risk_share_bp = 11_000;
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_actor_multiplier_out_of_range() {
        let mut p = PricingPolicy::zero_launch_default();
        p.actor_multipliers.push(ActorMultiplier {
            actor_class: ActorClass::Holon,
            multiplier_bp: MAX_MULTIPLIER_BP + 1,
        });
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_event_multiplier_out_of_range() {
        let mut p = PricingPolicy::zero_launch_default();
        p.event_multipliers.push(EventMultiplier {
            event_class: EventClass::AvcIssue,
            multiplier_bp: MAX_MULTIPLIER_BP + 1,
        });
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_rejects_assurance_multiplier_out_of_range() {
        let mut p = PricingPolicy::zero_launch_default();
        p.assurance_multipliers.push(AssuranceMultiplier {
            assurance_class: AssuranceClass::LegalGrade,
            multiplier_bp: MAX_MULTIPLIER_BP + 1,
        });
        assert!(p.validate().is_err());
    }

    #[test]
    fn lookup_default_for_unlisted_actor_class() {
        let mut p = PricingPolicy::zero_launch_default();
        p.actor_multipliers.clear();
        assert_eq!(
            p.actor_multiplier_bp(ActorClass::Holon),
            NEUTRAL_MULTIPLIER_BP
        );
    }

    #[test]
    fn lookup_default_for_unlisted_event_class() {
        let mut p = PricingPolicy::zero_launch_default();
        p.event_multipliers.clear();
        assert_eq!(
            p.event_multiplier_bp(EventClass::AvcIssue),
            NEUTRAL_MULTIPLIER_BP
        );
    }

    #[test]
    fn lookup_default_for_unlisted_assurance_class() {
        let mut p = PricingPolicy::zero_launch_default();
        p.assurance_multipliers.clear();
        assert_eq!(
            p.assurance_multiplier_bp(AssuranceClass::Anchored),
            NEUTRAL_MULTIPLIER_BP
        );
    }

    #[test]
    fn revenue_share_template_lookup_returns_some_for_seeded_event() {
        let p = PricingPolicy::zero_launch_default();
        let t = p.revenue_share_template_for(EventClass::HolonCommercialAction);
        assert!(t.is_some());
    }

    #[test]
    fn validate_rejects_invalid_template_basis_points() {
        let mut p = PricingPolicy::zero_launch_default();
        p.revenue_share_templates
            .push(RevenueShareTemplate::overallocated_for_test());
        assert!(p.validate().is_err());
    }

    #[test]
    fn round_trip_serialization() {
        let p = PricingPolicy::zero_launch_default();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&p, &mut buf).unwrap();
        let decoded: PricingPolicy = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn zero_fee_reason_can_be_described_for_zero_policy() {
        // Sanity: every variant of ZeroFeeReason is wire-stable.
        for r in ZeroFeeReason::ALL {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&r, &mut buf).unwrap();
            let decoded: ZeroFeeReason = ciborium::de::from_reader(buf.as_slice()).unwrap();
            assert_eq!(decoded, r);
        }
    }
}
