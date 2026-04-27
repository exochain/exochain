//! Budget enforcement — Paperclip concept adapted for ExoChain.
//!
//! All amounts are in integer cents. Thresholds use basis points (bps).
//! No floating-point arithmetic — constitutional determinism requirement.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{CatapultError, Result},
    oda::OdaSlot,
    phase::OperationalPhase,
};

/// Domain tag for canonical cost-event receipt hashes.
pub const COST_EVENT_HASH_DOMAIN: &str = "exo.catapult.cost_event.v1";
const COST_EVENT_HASH_SCHEMA_VERSION: &str = "1.0.0";

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

impl BudgetPolicy {
    /// Validate externally supplied or deserialized budget policy metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] when placeholder IDs, zero limits, or invalid
    /// thresholds are present.
    pub fn validate(&self) -> Result<()> {
        validate_budget_policy(self)
    }
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

/// Caller-supplied deterministic metadata for creating a cost event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEventInput {
    pub id: Uuid,
    pub newco_id: Uuid,
    pub agent_did: Did,
    pub slot: OdaSlot,
    pub amount: u64,
    pub metric: BudgetMetric,
    pub description: String,
    pub timestamp: Timestamp,
}

impl CostEvent {
    /// Create a cost event with a deterministic canonical receipt hash.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if the input contains placeholder metadata
    /// or canonical hashing fails.
    pub fn new(input: CostEventInput) -> Result<Self> {
        validate_cost_event_input(&input)?;
        let receipt_hash = cost_event_receipt_hash(&input)?;
        Ok(Self {
            id: input.id,
            newco_id: input.newco_id,
            agent_did: input.agent_did,
            slot: input.slot,
            amount: input.amount,
            metric: input.metric,
            description: input.description,
            timestamp: input.timestamp,
            receipt_hash,
        })
    }

    /// Validate externally supplied or deserialized cost event metadata.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if placeholders are present or the stored
    /// receipt hash does not match the canonical event payload.
    pub fn validate(&self) -> Result<()> {
        let input = self.input();
        validate_cost_event_input(&input)?;
        if self.receipt_hash == Hash256::ZERO {
            return Err(CatapultError::InvalidCostEvent {
                reason: "cost event receipt hash must not be zero".into(),
            });
        }
        if !self.verify_receipt_hash()? {
            return Err(CatapultError::InvalidCostEvent {
                reason: "cost event receipt hash does not match canonical payload".into(),
            });
        }
        Ok(())
    }

    /// Verify the stored receipt hash against the canonical payload.
    ///
    /// # Errors
    /// Returns [`CatapultError`] if canonical hashing fails.
    pub fn verify_receipt_hash(&self) -> Result<bool> {
        Ok(cost_event_receipt_hash(&self.input())? == self.receipt_hash)
    }

    fn input(&self) -> CostEventInput {
        CostEventInput {
            id: self.id,
            newco_id: self.newco_id,
            agent_did: self.agent_did.clone(),
            slot: self.slot,
            amount: self.amount,
            metric: self.metric,
            description: self.description.clone(),
            timestamp: self.timestamp,
        }
    }
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
    pub fn add_policy(&mut self, policy: BudgetPolicy) -> Result<()> {
        validate_budget_policy(&policy)?;
        if self
            .policies
            .iter()
            .any(|existing| existing.id == policy.id)
        {
            return Err(CatapultError::InvalidBudgetPolicy {
                reason: format!("duplicate budget policy id {}", policy.id),
            });
        }
        self.policies.push(policy);
        Ok(())
    }

    /// Record a cost event.
    pub fn record_cost(&mut self, event: CostEvent) -> Result<()> {
        event.validate()?;
        if self.events.iter().any(|existing| existing.id == event.id) {
            return Err(CatapultError::InvalidCostEvent {
                reason: format!("duplicate cost event id {}", event.id),
            });
        }
        self.events.push(event);
        Ok(())
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

    /// Validate every policy and event in a deserialized ledger.
    ///
    /// # Errors
    /// Returns [`CatapultError`] when placeholder metadata or duplicate IDs
    /// are present.
    pub fn validate(&self) -> Result<()> {
        let mut policy_ids = std::collections::BTreeSet::new();
        for policy in &self.policies {
            validate_budget_policy(policy)?;
            if !policy_ids.insert(policy.id) {
                return Err(CatapultError::InvalidBudgetPolicy {
                    reason: format!("duplicate budget policy id {}", policy.id),
                });
            }
        }

        let mut event_ids = std::collections::BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if !event_ids.insert(event.id) {
                return Err(CatapultError::InvalidCostEvent {
                    reason: format!("duplicate cost event id {}", event.id),
                });
            }
        }

        Ok(())
    }
}

/// Compute the canonical receipt hash for a cost event.
///
/// # Errors
/// Returns [`CatapultError`] if canonical CBOR hashing fails.
pub fn cost_event_receipt_hash(input: &CostEventInput) -> Result<Hash256> {
    validate_cost_event_input(input)?;
    exo_core::hash::hash_structured(&CostEventHashPayload::from_input(input)).map_err(|e| {
        CatapultError::InvalidCostEvent {
            reason: format!("cost event canonical hash failed: {e}"),
        }
    })
}

#[derive(Serialize)]
struct CostEventHashPayload<'a> {
    domain: &'static str,
    schema_version: &'static str,
    id: Uuid,
    newco_id: Uuid,
    agent_did: &'a Did,
    slot: OdaSlot,
    amount: u64,
    metric: BudgetMetric,
    description: &'a str,
    timestamp: Timestamp,
}

impl<'a> CostEventHashPayload<'a> {
    fn from_input(input: &'a CostEventInput) -> Self {
        Self {
            domain: COST_EVENT_HASH_DOMAIN,
            schema_version: COST_EVENT_HASH_SCHEMA_VERSION,
            id: input.id,
            newco_id: input.newco_id,
            agent_did: &input.agent_did,
            slot: input.slot,
            amount: input.amount,
            metric: input.metric,
            description: &input.description,
            timestamp: input.timestamp,
        }
    }
}

fn validate_budget_policy(policy: &BudgetPolicy) -> Result<()> {
    if policy.id.is_nil() {
        return Err(CatapultError::InvalidBudgetPolicy {
            reason: "budget policy id must be caller-supplied and non-nil".into(),
        });
    }
    if policy.limit == 0 {
        return Err(CatapultError::InvalidBudgetPolicy {
            reason: "budget policy limit must be nonzero".into(),
        });
    }
    if policy.warn_threshold_bps == 0 || policy.warn_threshold_bps > 10_000 {
        return Err(CatapultError::InvalidBudgetPolicy {
            reason: "budget policy warning threshold must be 1..=10000 basis points".into(),
        });
    }
    Ok(())
}

fn validate_cost_event_input(input: &CostEventInput) -> Result<()> {
    if input.id.is_nil() {
        return Err(CatapultError::InvalidCostEvent {
            reason: "cost event id must be caller-supplied and non-nil".into(),
        });
    }
    if input.newco_id.is_nil() {
        return Err(CatapultError::InvalidCostEvent {
            reason: "cost event newco id must be non-nil".into(),
        });
    }
    if input.amount == 0 {
        return Err(CatapultError::InvalidCostEvent {
            reason: "cost event amount must be nonzero".into(),
        });
    }
    if input.description.trim().is_empty() {
        return Err(CatapultError::InvalidCostEvent {
            reason: "cost event description must not be empty".into(),
        });
    }
    if input.timestamp == Timestamp::ZERO {
        return Err(CatapultError::InvalidCostEvent {
            reason: "cost event timestamp must be caller-supplied HLC".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-agent").unwrap()
    }

    fn test_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn uuid_from_u64(value: u64) -> Uuid {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Uuid::from_bytes(bytes)
    }

    fn test_timestamp() -> Timestamp {
        Timestamp::new(1_765_000_000_000, 0)
    }

    fn make_policy(scope: BudgetScope, limit: u64) -> BudgetPolicy {
        BudgetPolicy {
            id: uuid_from_u64(limit),
            scope,
            metric: BudgetMetric::BilledCents,
            window: BudgetWindow::Lifetime,
            limit,
            warn_threshold_bps: 8000,
            hard_stop: true,
            is_active: true,
        }
    }

    fn valid_policy(scope: BudgetScope, limit: u64) -> BudgetPolicy {
        BudgetPolicy {
            id: test_uuid(1),
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
        CostEvent::new(CostEventInput {
            id: uuid_from_u64(amount),
            newco_id: test_uuid(4),
            agent_did: test_did(),
            slot,
            amount,
            metric: BudgetMetric::BilledCents,
            description: "test cost".into(),
            timestamp: test_timestamp(),
        })
        .unwrap()
    }

    fn valid_cost_input(slot: OdaSlot, amount: u64) -> CostEventInput {
        CostEventInput {
            id: test_uuid(2),
            newco_id: test_uuid(3),
            agent_did: test_did(),
            slot,
            amount,
            metric: BudgetMetric::BilledCents,
            description: "valid cost".into(),
            timestamp: test_timestamp(),
        }
    }

    #[test]
    fn ledger_rejects_placeholder_budget_policy_and_cost_event() {
        let mut ledger = BudgetLedger::new();

        let mut policy = valid_policy(BudgetScope::Company, 100_000);
        policy.id = Uuid::nil();
        assert!(ledger.add_policy(policy).is_err());

        let mut policy = valid_policy(BudgetScope::Company, 0);
        policy.limit = 0;
        assert!(ledger.add_policy(policy).is_err());

        let mut cost = CostEvent::new(valid_cost_input(OdaSlot::VentureCommander, 100)).unwrap();
        cost.receipt_hash = Hash256::ZERO;
        assert!(ledger.record_cost(cost).is_err());
    }

    #[test]
    fn cost_event_receipt_hash_covers_canonical_payload() {
        let mut ledger = BudgetLedger::new();
        let event = CostEvent::new(valid_cost_input(OdaSlot::VentureCommander, 100)).unwrap();

        assert_ne!(event.receipt_hash, Hash256::ZERO);
        assert!(event.verify_receipt_hash().unwrap());
        ledger.record_cost(event.clone()).unwrap();

        let mut tampered = event;
        tampered.amount += 1;
        assert!(!tampered.verify_receipt_hash().unwrap());
        assert!(ledger.record_cost(tampered).is_err());
    }

    #[test]
    fn policy_and_cost_input_validation_rejects_boundary_placeholders() {
        let mut policy = valid_policy(BudgetScope::Company, 100_000);
        policy.warn_threshold_bps = 0;
        assert!(policy.validate().is_err());

        let mut policy = valid_policy(BudgetScope::Company, 100_000);
        policy.warn_threshold_bps = 10_001;
        assert!(policy.validate().is_err());

        let mut input = valid_cost_input(OdaSlot::VentureCommander, 100);
        input.id = Uuid::nil();
        assert!(CostEvent::new(input).is_err());

        let mut input = valid_cost_input(OdaSlot::VentureCommander, 100);
        input.newco_id = Uuid::nil();
        assert!(CostEvent::new(input).is_err());

        let mut input = valid_cost_input(OdaSlot::VentureCommander, 100);
        input.amount = 0;
        assert!(CostEvent::new(input).is_err());

        let mut input = valid_cost_input(OdaSlot::VentureCommander, 100);
        input.description = "   ".into();
        assert!(CostEvent::new(input).is_err());

        let mut input = valid_cost_input(OdaSlot::VentureCommander, 100);
        input.timestamp = Timestamp::ZERO;
        assert!(CostEvent::new(input).is_err());
    }

    #[test]
    fn ledger_rejects_duplicate_ids_from_api_and_deserialized_state() {
        let mut ledger = BudgetLedger::new();
        let policy = valid_policy(BudgetScope::Company, 100_000);
        ledger.add_policy(policy.clone()).unwrap();
        assert!(ledger.add_policy(policy.clone()).is_err());

        let duplicate_policy_ledger = BudgetLedger {
            policies: vec![policy.clone(), policy],
            events: Vec::new(),
        };
        assert!(duplicate_policy_ledger.validate().is_err());

        let event = CostEvent::new(valid_cost_input(OdaSlot::VentureCommander, 100)).unwrap();
        let duplicate_event_ledger = BudgetLedger {
            policies: Vec::new(),
            events: vec![event.clone(), event],
        };
        assert!(duplicate_event_ledger.validate().is_err());
    }

    #[test]
    fn inactive_policy_is_ignored_by_enforcement() {
        let mut ledger = BudgetLedger::new();
        let mut policy = make_policy(BudgetScope::Company, 1);
        policy.is_active = false;
        ledger.add_policy(policy).unwrap();
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 10))
            .unwrap();

        assert_eq!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::Ok
        );
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
        ledger
            .add_policy(make_policy(BudgetScope::Company, 100_000))
            .unwrap();
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 50_000))
            .unwrap();
        assert_eq!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::Ok
        );
    }

    #[test]
    fn warning_threshold() {
        let mut ledger = BudgetLedger::new();
        ledger
            .add_policy(make_policy(BudgetScope::Company, 100_000))
            .unwrap();
        // 85% of budget — exceeds 80% warning threshold
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 85_000))
            .unwrap();
        assert!(matches!(
            ledger.check_enforcement(&BudgetScope::Company),
            BudgetVerdict::Warning { .. }
        ));
    }

    #[test]
    fn hard_stop() {
        let mut ledger = BudgetLedger::new();
        ledger
            .add_policy(make_policy(BudgetScope::Company, 100_000))
            .unwrap();
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 100_001))
            .unwrap();
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
        ledger.add_policy(make_policy(scope, 10_000)).unwrap();
        // Cost from a different slot should not count
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 50_000))
            .unwrap();
        assert_eq!(ledger.check_enforcement(&scope), BudgetVerdict::Ok);
        // Cost from the target slot should count
        ledger
            .record_cost(make_cost(OdaSlot::GrowthEngineer1, 10_001))
            .unwrap();
        assert!(matches!(
            ledger.check_enforcement(&scope),
            BudgetVerdict::HardStop { .. }
        ));
    }

    #[test]
    fn total_spent() {
        let mut ledger = BudgetLedger::new();
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 100))
            .unwrap();
        ledger
            .record_cost(make_cost(OdaSlot::VentureCommander, 200))
            .unwrap();
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
