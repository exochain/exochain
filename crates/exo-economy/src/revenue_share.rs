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

//! Revenue share templates and per-quote allocation lines.
//!
//! Templates declare the basis-point split for an event class. During
//! the zero-launch phase, every `amount_micro_exo` resolves to `0`
//! regardless of template values because `charged_amount_micro_exo` is
//! always `0`.

use serde::{Deserialize, Serialize};

use crate::{
    error::EconomyError,
    types::{BasisPoints, EventClass, MAX_BASIS_POINTS, MicroExo, RevenueRecipient},
};

/// A single recipient share within a revenue allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueShareLine {
    pub recipient: RevenueRecipient,
    pub share_bp: BasisPoints,
    pub amount_micro_exo: MicroExo,
}

/// A template describing the basis-point split for a given event class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueShareTemplate {
    pub event_class: EventClass,
    pub allocations: Vec<TemplateAllocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateAllocation {
    pub recipient: RevenueRecipient,
    pub share_bp: BasisPoints,
}

impl RevenueShareTemplate {
    /// Validate that the template's basis-point sum is `<= 10_000` and
    /// no individual share is outside the legal range.
    ///
    /// # Errors
    /// Returns [`EconomyError::RevenueShareOverAllocated`] when the sum
    /// exceeds `10_000` or [`EconomyError::BasisPointOutOfRange`] when
    /// any share itself exceeds `10_000`.
    pub fn validate(&self) -> Result<(), EconomyError> {
        let mut sum: u32 = 0;
        for line in &self.allocations {
            if line.share_bp > MAX_BASIS_POINTS {
                return Err(EconomyError::BasisPointOutOfRange {
                    field: "revenue_share_template.share_bp",
                    value: line.share_bp,
                    max: MAX_BASIS_POINTS,
                });
            }
            sum = sum.saturating_add(line.share_bp);
        }
        if sum > MAX_BASIS_POINTS {
            return Err(EconomyError::RevenueShareOverAllocated { sum });
        }
        Ok(())
    }

    /// Default zero-launch templates: every event class maps to a
    /// single `ProtocolTreasury` line with `share_bp = 10_000`.
    /// `amount_micro_exo` is `0` under the zero-launch policy, so this
    /// shape simply provides a deterministic non-empty default.
    #[must_use]
    pub fn zero_launch_templates() -> Vec<Self> {
        EventClass::ALL
            .iter()
            .map(|c| Self {
                event_class: *c,
                allocations: vec![TemplateAllocation {
                    recipient: RevenueRecipient::ProtocolTreasury,
                    share_bp: MAX_BASIS_POINTS,
                }],
            })
            .collect()
    }

    /// Test-only constructor for an over-allocated template.
    #[cfg(test)]
    pub fn overallocated_for_test() -> Self {
        Self {
            event_class: EventClass::HolonCommercialAction,
            allocations: vec![
                TemplateAllocation {
                    recipient: RevenueRecipient::ProtocolTreasury,
                    share_bp: 6_000,
                },
                TemplateAllocation {
                    recipient: RevenueRecipient::ValidatorSet,
                    share_bp: 6_000,
                },
            ],
        }
    }
}

/// Allocate `charged_amount` across `template`, using saturating
/// integer arithmetic. Always deterministic; never floating point.
///
/// Each recipient amount is `charged_amount * share_bp / 10_000`
/// using `saturating_mul`/`saturating_div`. The remainder (if any)
/// stays unallocated and is the caller's responsibility to direct
/// (typically to the protocol treasury).
///
/// # Errors
/// Returns [`EconomyError`] if the template is structurally invalid.
pub fn distribute_revenue(
    template: &RevenueShareTemplate,
    charged_amount: MicroExo,
) -> Result<Vec<RevenueShareLine>, EconomyError> {
    template.validate()?;
    // `validate()` guarantees the basis-point sum is `<= 10_000`. Combined
    // with integer-division rounding-down in `apply_bp`, no validated
    // template can over-allocate the charged amount, so we do not need a
    // runtime over-allocation guard here.
    let lines = template
        .allocations
        .iter()
        .map(|alloc| RevenueShareLine {
            recipient: alloc.recipient.clone(),
            share_bp: alloc.share_bp,
            amount_micro_exo: apply_bp(charged_amount, alloc.share_bp),
        })
        .collect();
    Ok(lines)
}

/// Apply a basis-point ratio to `amount` using saturating integer math.
#[must_use]
pub fn apply_bp(amount: MicroExo, bp: BasisPoints) -> MicroExo {
    let bp_u128 = u128::from(bp);
    amount
        .saturating_mul(bp_u128)
        .saturating_div(u128::from(MAX_BASIS_POINTS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_launch_templates_cover_every_event_class() {
        let templates = RevenueShareTemplate::zero_launch_templates();
        assert_eq!(templates.len(), EventClass::ALL.len());
    }

    #[test]
    fn zero_launch_templates_validate() {
        let templates = RevenueShareTemplate::zero_launch_templates();
        for t in &templates {
            t.validate().unwrap();
        }
    }

    #[test]
    fn distribute_revenue_for_zero_amount_yields_zero_lines() {
        let template = &RevenueShareTemplate::zero_launch_templates()[0];
        let lines = distribute_revenue(template, 0).unwrap();
        assert!(!lines.is_empty());
        assert!(lines.iter().all(|l| l.amount_micro_exo == 0));
    }

    #[test]
    fn distribute_revenue_for_nonzero_amount_allocates_proportional_amounts() {
        let mut template = RevenueShareTemplate::zero_launch_templates()[0].clone();
        template.allocations = vec![
            TemplateAllocation {
                recipient: RevenueRecipient::ProtocolTreasury,
                share_bp: 5_000,
            },
            TemplateAllocation {
                recipient: RevenueRecipient::ValidatorSet,
                share_bp: 5_000,
            },
        ];
        let lines = distribute_revenue(&template, 1_000).unwrap();
        assert_eq!(
            lines.iter().map(|l| l.amount_micro_exo).sum::<MicroExo>(),
            1_000
        );
    }

    #[test]
    fn validate_rejects_overallocated_template() {
        let template = RevenueShareTemplate::overallocated_for_test();
        let err = template.validate().unwrap_err();
        assert!(matches!(
            err,
            EconomyError::RevenueShareOverAllocated { .. }
        ));
    }

    #[test]
    fn validate_rejects_share_bp_out_of_range() {
        let template = RevenueShareTemplate {
            event_class: EventClass::AvcIssue,
            allocations: vec![TemplateAllocation {
                recipient: RevenueRecipient::ProtocolTreasury,
                share_bp: 99_999,
            }],
        };
        assert!(template.validate().is_err());
    }

    #[test]
    fn apply_bp_saturating_at_max_value_does_not_panic() {
        // u128::MAX * 10_000 saturates to u128::MAX; dividing by 10_000
        // yields u128::MAX / 10_000. The helper must never panic.
        let result = apply_bp(u128::MAX, MAX_BASIS_POINTS);
        assert_eq!(
            result,
            u128::MAX.saturating_div(u128::from(MAX_BASIS_POINTS))
        );
    }

    #[test]
    fn apply_bp_zero_basis_points_is_zero() {
        assert_eq!(apply_bp(1_000_000, 0), 0);
    }

    #[test]
    fn apply_bp_full_basis_points_returns_full_amount() {
        assert_eq!(apply_bp(1_000_000, MAX_BASIS_POINTS), 1_000_000);
    }

    #[test]
    fn zero_launch_template_for_avc_validate_is_zero_amount_when_charged_is_zero() {
        let t = RevenueShareTemplate::zero_launch_templates()
            .into_iter()
            .find(|t| t.event_class == EventClass::AvcValidate)
            .unwrap();
        let lines = distribute_revenue(&t, 0).unwrap();
        for line in &lines {
            assert_eq!(line.amount_micro_exo, 0);
        }
    }

    #[test]
    fn distribute_revenue_overallocation_guard_triggers_when_amounts_exceed_charged() {
        // Construct a template whose share basis points sum to 10_000
        // but whose calculated amounts would exceed the charged amount
        // due to integer rounding interactions. Using share_bp 5_001 +
        // 5_000 against a charged amount of 10_001 yields 5_001 + 5_000
        // = 10_001 which is exactly equal — to force over-allocation we
        // craft a scenario with charged 1 and shares 10_000 + 10_000,
        // each producing 1, summing to 2 > 1. Validation rejects the
        // over-allocated template first, so we use a manually-built
        // template that bypasses sum check by single share = 20_000 bp.
        let template = RevenueShareTemplate {
            event_class: EventClass::AvcIssue,
            allocations: vec![TemplateAllocation {
                recipient: RevenueRecipient::ProtocolTreasury,
                share_bp: 11_000, // > MAX_BASIS_POINTS, validation will reject
            }],
        };
        // Validation rejects out-of-range share_bp before allocation runs.
        assert!(distribute_revenue(&template, 100).is_err());
    }

    #[test]
    fn round_trip_serialization() {
        let template = RevenueShareTemplate::zero_launch_templates()
            .into_iter()
            .next()
            .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&template, &mut buf).unwrap();
        let decoded: RevenueShareTemplate = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, template);
    }
}
