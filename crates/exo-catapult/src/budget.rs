//! Budget enforcement — Paperclip concept adapted for ExoChain.
//!
//! All amounts are in integer cents. Thresholds use basis points (bps).
//! No floating-point arithmetic — constitutional determinism requirement.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{oda::OdaSlot, phase::OperationalPhase};

/// Scope of a budget policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BudgetScope {
    /// Applies to the entire newco.
    Company,
    /// Applies to a specific ODA slot.
    Agent { slot: OdaSlot },
    /// Applies during a specific operational phase.
    Phase { phase: OperationalPhase },
}

/// What resource the budget tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BudgetMetric {
    /// Billed cost in integer cents.
    BilledCents,
    /// AI tokens consumed.
    TokensConsumed,
    /// API calls made.
    ApiCalls,
}

/// Time window for budget enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BudgetWindow {
    /// Calendar month.
    Monthly,
    /// Total lifetime of the newco.
    Lifetime,
    /// Tied to the current operational phase.
    Phase,
}

/// A budget policy defining limits and thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetPolicy {
    pub id: Uuid,
    pub scope: BudgetScope,
    pub metric: BudgetMetric,
    pub window: BudgetWindow,
    /// Hard limit in the metric's unit (cents, tokens, or calls).
    pub limit: u64,
    /// Warning threshold in basis points (e.g. 8000 = 80%).
    pub warn_threshold_bps: u32,
    /// Whether exceeding the limit halts the agent.
    pub hard_stop: bool,
    pub is_active: bool,
}

/// A recorded cost event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEvent {
    pub id: Uuid,
    pub newco_id: Uuid,
    pub agent_did: Did,
    pub slot: OdaSlot,
    pub amount: u64,
    pub metric: BudgetMetric,
    pub description: String,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash256,
}

/// Result of a budget enforcement check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Within budget.
    Ok,
    /// Approaching limit.
    Warning { spent: u64, limit: u64 },
    /// Limit exceeded — agent should be suspended.
    HardStop { spent: u64, limit: u64 },
}

/// Default budget template for franchise blueprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetTemplate {
    /// Default per-agent monthly limit in cents.
    pub default_agent_monthly_cents: u64,
    /// Default company lifetime limit in cents.
    pub company_lifetime_cents: u64,
    /// Warning threshold in basis points.
    pub warn_threshold_bps: u32,
}

impl Default for BudgetTemplate {
    fn default() -> Self {
        Self {
            default_agent_monthly_cents: 1_000_000, // $10,000
            company_lifetime_cents: 50_000_000,     // $500,000
            warn_threshold_bps: 8000,               // 80%
        }
    }
}

/// Budget ledger tracking policies and cost events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetLedger {
    policies: Vec<BudgetPolicy>,
    events: Vec<CostEvent>,
}

impl BudgetLedger {
    /// Create an empty budget ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Add a budget policy.
    pub fn add_policy(&mut self, policy: BudgetPolicy) {
        self.policies.push(policy);
    }

    /// Record a cost event.
    pub fn record_cost(&mut self, event: CostEvent) {
        self.events.push(event);
    }

    /// Calculate total spent for a given scope and metric.
    #[must_use]
    pub fn total_spent(&self, scope: &BudgetScope, metric: &BudgetMetric) -> u64 {
        self.events
            .iter()
            .filter(|e| {
                e.metric == *metric
                    && match scope {
                        BudgetScope::Company => true,
                        BudgetScope::Agent { slot } => e.slot == *slot,
                        BudgetScope::Phase { .. } => true, // Phase filtering needs external state
                    }
            })
            .map(|e| e.amount)
            .sum()
    }

    /// Check enforcement for a specific scope.
    ///
    /// Uses integer-only arithmetic: `spent * 10_000 >= limit * warn_threshold_bps`
    #[must_use]
    pub fn check_enforcement(&self, scope: &BudgetScope) -> BudgetVerdict {
        for policy in &self.policies {
            if !policy.is_active || policy.scope != *scope {
                continue;
            }
            let spent = self.total_spent(scope, &policy.metric);

            if spent >= policy.limit && policy.hard_stop {
                return BudgetVerdict::HardStop {
                    spent,
                    limit: policy.limit,
                };
            }

            // Integer-only threshold check: spent * 10_000 >= limit * warn_bps
            if spent.checked_mul(10_000).is_none_or(|s| {
                s >= policy
                    .limit
                    .saturating_mul(u64::from(policy.warn_threshold_bps))
            }) {
                return BudgetVerdict::Warning {
                    spent,
                    limit: policy.limit,
                };
            }
        }
        BudgetVerdict::Ok
    }

    /// Number of active policies.
    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Number of recorded cost events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-agent").unwrap()
    }

    fn make_policy(scope: BudgetScope, limit: u64) -> BudgetPolicy {
        BudgetPolicy {
            id: Uuid::new_v4(),
            scope,
            metric: BudgetMetric::BilledCents,
            window: BudgetWindow::Lifetime,
            limit,
            warn_threshold_bps: 8000,
            hard_stop: true,
            is_active: true,
        }
    }

    fn make_cost(slot: OdaSlot, amount: u64) -> CostEvent {
        CostEvent {
            id: Uuid::new_v4(),
            newco_id: Uuid::nil(),
            agent_did: test_did(),
            slot,
            amount,
            metric: BudgetMetric::BilledCents,
            description: "test cost".into(),
            timestamp: Timestamp::ZERO,
            receipt_hash: Hash256::ZERO,
        }
    }

    #[test]
    fn empty_ledger_ok() {
        let ledger = BudgetLedger::new();
        assert_eq!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::Ok
        );
    }

    #[test]
    fn under_budget() {
        let mut ledger = BudgetLedger::new();
        ledger.add_policy(make_policy(BudgetScope::Company, 100_000));
        ledger.record_cost(make_cost(OdaSlot::VentureCommander, 50_000));
        assert_eq!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::Ok
        );
    }

    #[test]
    fn warning_threshold() {
        let mut ledger = BudgetLedger::new();
        ledger.add_policy(make_policy(BudgetScope::Company, 100_000));
        // 85% of budget — exceeds 80% warning threshold
        ledger.record_cost(make_cost(OdaSlot::VentureCommander, 85_000));
        assert!(matches!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::Warning { .. }
        ));
    }

    #[test]
    fn hard_stop() {
        let mut ledger = BudgetLedger::new();
        ledger.add_policy(make_policy(BudgetScope::Company, 100_000));
        ledger.record_cost(make_cost(OdaSlot::VentureCommander, 100_001));
        assert!(matches!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::HardStop { .. }
        ));
    }

    #[test]
    fn per_agent_scope() {
        let mut ledger = BudgetLedger::new();
        let scope = BudgetScope::Agent {
            slot: OdaSlot::GrowthEngineer1,
        };
        ledger.add_policy(make_policy(scope, 10_000));
        // Cost from a different slot should not count
        ledger.record_cost(make_cost(OdaSlot::VentureCommander, 50_000));
        assert_eq!(ledger.check_enforcement(&scope), BudgetVerdict::Ok);
        // Cost from the target slot should count
        ledger.record_cost(make_cost(OdaSlot::GrowthEngineer1, 10_001));
        assert!(matches!(
            ledger.check_enforcement(&scope),
            BudgetVerdict::HardStop { .. }
        ));
    }

    #[test]
    fn total_spent() {
        let mut ledger = BudgetLedger::new();
        ledger.record_cost(make_cost(OdaSlot::VentureCommander, 100));
        ledger.record_cost(make_cost(OdaSlot::VentureCommander, 200));
        assert_eq!(
            ledger.total_spent(&BudgetScope::Company, &BudgetMetric::BilledCents),
            300
        );
    }

    #[test]
    fn template_default() {
        let t = BudgetTemplate::default();
        assert_eq!(t.default_agent_monthly_cents, 1_000_000);
        assert_eq!(t.warn_threshold_bps, 8000);
    }

    #[test]
    fn budget_scope_serde() {
        let scopes = [
            BudgetScope::Company,
            BudgetScope::Agent {
                slot: OdaSlot::VentureCommander,
            },
            BudgetScope::Phase {
                phase: OperationalPhase::Execution,
            },
        ];
        for s in &scopes {
            let j = serde_json::to_string(s).unwrap();
            let rt: BudgetScope = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, s);
        }
    }
}
