//! Newco — an instantiated franchise company governed by ExoChain.

use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    agent::{AgentRoster, CatapultAgent},
    budget::BudgetLedger,
    error::{CatapultError, Result},
    goal::GoalTree,
    oda::OdaSlot,
    phase::OperationalPhase,
    receipt::ReceiptChain,
};

/// Operational status of a newco.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NewcoStatus {
    /// Being set up — tenant provisioning in progress.
    Provisioning,
    /// Fully operational.
    Active,
    /// Temporarily suspended (governance action or budget halt).
    Suspended,
    /// Transitioning — scaling, pivoting, or closing.
    Transitioning,
    /// Orderly close completed.
    Closed,
}

/// A newco — a franchised company instantiated from a blueprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Newco {
    pub id: Uuid,
    pub name: String,
    /// Back-reference to the franchise blueprint.
    pub franchise_id: Uuid,
    /// Tenant isolation boundary (exo-tenant).
    pub tenant_id: Uuid,
    /// Snapshot of the constitution at creation.
    pub constitution_hash: Hash256,
    /// Current FM 3-05 operational phase.
    pub phase: OperationalPhase,
    /// The ODA roster.
    pub roster: AgentRoster,
    /// Budget tracking.
    pub budget: BudgetLedger,
    /// Goal hierarchy.
    pub goals: GoalTree,
    /// Root of the ODA authority chain.
    pub authority_chain_root: Did,
    /// Anchor into the exo-dag provenance layer.
    pub dag_anchor: Hash256,
    /// When this newco was created.
    pub created: Timestamp,
    /// Last heartbeat from any agent.
    pub last_heartbeat: Timestamp,
    /// Current operational status.
    pub status: NewcoStatus,
}

impl Newco {
    /// Create a new newco in Assessment phase.
    #[must_use]
    pub fn new(
        name: String,
        franchise_id: Uuid,
        tenant_id: Uuid,
        constitution_hash: Hash256,
        authority_chain_root: Did,
        created: Timestamp,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            franchise_id,
            tenant_id,
            constitution_hash,
            phase: OperationalPhase::Assessment,
            roster: AgentRoster::new(),
            budget: BudgetLedger::new(),
            goals: GoalTree::new(),
            authority_chain_root,
            dag_anchor: Hash256::ZERO,
            created,
            last_heartbeat: created,
            status: NewcoStatus::Provisioning,
        }
    }

    /// Advance to the next operational phase.
    ///
    /// Validates both the phase transition and roster sufficiency.
    pub fn advance_phase(&mut self, target: OperationalPhase) -> Result<()> {
        // Validate the phase transition
        if !self.phase.can_transition_to(target) {
            return Err(CatapultError::InvalidPhaseTransition {
                from: self.phase,
                to: target,
            });
        }

        // Validate roster sufficiency for the target phase
        let required = target.min_roster();
        if !self.roster.has_slots(required) {
            return Err(CatapultError::RosterIncomplete {
                phase: target,
                needed: required.len(),
                have: self.roster.filled_count(),
            });
        }

        self.phase = target;

        // Update status based on phase
        self.status = match target {
            OperationalPhase::Assessment | OperationalPhase::Selection => NewcoStatus::Provisioning,
            OperationalPhase::Preparation
            | OperationalPhase::Execution
            | OperationalPhase::Sustainment => NewcoStatus::Active,
            OperationalPhase::Transition => NewcoStatus::Transitioning,
        };

        Ok(())
    }

    /// Hire an agent into an ODA slot.
    pub fn hire_agent(&mut self, agent: CatapultAgent) -> Result<()> {
        self.roster.fill_slot(agent)
    }

    /// Release an agent from an ODA slot.
    pub fn release_agent(&mut self, slot: &OdaSlot) -> Result<CatapultAgent> {
        self.roster.release_slot(slot)
    }

    /// Suspend the newco (governance or budget action).
    pub fn suspend(&mut self) {
        self.status = NewcoStatus::Suspended;
    }

    /// Reactivate a suspended newco.
    pub fn reactivate(&mut self) {
        if self.status == NewcoStatus::Suspended {
            self.status = NewcoStatus::Active;
        }
    }

    /// Close the newco.
    pub fn close(&mut self) {
        self.status = NewcoStatus::Closed;
    }

    /// Whether the ODA roster is fully staffed.
    #[must_use]
    pub fn is_fully_staffed(&self) -> bool {
        self.roster.is_complete()
    }

    /// Whether the newco has its founding agents.
    #[must_use]
    pub fn has_founders(&self) -> bool {
        self.roster.has_slots(&OdaSlot::FOUNDERS)
    }
}

/// Registry of all newcos managed by Catapult.
#[derive(Debug, Clone, Default)]
pub struct NewcoRegistry {
    pub newcos: std::collections::BTreeMap<Uuid, Newco>,
    pub receipt_chains: std::collections::BTreeMap<Uuid, ReceiptChain>,
}

impl NewcoRegistry {
    /// Create an empty newco registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            newcos: std::collections::BTreeMap::new(),
            receipt_chains: std::collections::BTreeMap::new(),
        }
    }

    /// Register a new newco.
    pub fn register(&mut self, newco: Newco) -> Result<Uuid> {
        let id = newco.id;
        if self.newcos.contains_key(&id) {
            return Err(CatapultError::NewcoAlreadyExists(id));
        }
        self.newcos.insert(id, newco);
        self.receipt_chains.insert(id, ReceiptChain::new());
        Ok(id)
    }

    /// Look up a newco by ID.
    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<&Newco> {
        self.newcos.get(id)
    }

    /// Look up a newco by ID (mutable).
    #[must_use]
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut Newco> {
        self.newcos.get_mut(id)
    }

    /// Get the receipt chain for a newco.
    #[must_use]
    pub fn receipts(&self, id: &Uuid) -> Option<&ReceiptChain> {
        self.receipt_chains.get(id)
    }

    /// Get the receipt chain for a newco (mutable).
    #[must_use]
    pub fn receipts_mut(&mut self, id: &Uuid) -> Option<&mut ReceiptChain> {
        self.receipt_chains.get_mut(id)
    }

    /// List all newcos.
    #[must_use]
    pub fn list(&self) -> Vec<&Newco> {
        self.newcos.values().collect()
    }

    /// Number of registered newcos.
    #[must_use]
    pub fn len(&self) -> usize {
        self.newcos.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.newcos.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentStatus;

    fn test_did() -> Did {
        Did::new("did:exo:test-root").unwrap()
    }

    fn make_newco() -> Newco {
        Newco::new(
            "Test Co".into(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Hash256::ZERO,
            test_did(),
            Timestamp::ZERO,
        )
    }

    fn make_agent(slot: OdaSlot) -> CatapultAgent {
        CatapultAgent {
            did: Did::new(&format!("did:exo:test-{slot:?}").to_ascii_lowercase()).unwrap(),
            slot,
            display_name: slot.display_name().into(),
            capabilities: vec![],
            status: AgentStatus::Active,
            last_heartbeat: Timestamp::ZERO,
            budget_spent_cents: 0,
            budget_limit_cents: 100_000,
            hired_at: Timestamp::ZERO,
            hired_by: test_did(),
            commandbase_profile: None,
        }
    }

    #[test]
    fn new_newco_starts_in_assessment() {
        let n = make_newco();
        assert_eq!(n.phase, OperationalPhase::Assessment);
        assert_eq!(n.status, NewcoStatus::Provisioning);
        assert!(!n.has_founders());
    }

    #[test]
    fn advance_to_selection_with_founders() {
        let mut n = make_newco();
        // Assessment → Selection requires founders
        n.hire_agent(make_agent(OdaSlot::HrPeopleOps1)).unwrap();
        n.hire_agent(make_agent(OdaSlot::DeepResearcher)).unwrap();
        n.advance_phase(OperationalPhase::Selection).unwrap();
        assert_eq!(n.phase, OperationalPhase::Selection);
    }

    #[test]
    fn cannot_skip_to_execution() {
        let mut n = make_newco();
        assert!(n.advance_phase(OperationalPhase::Execution).is_err());
    }

    #[test]
    fn roster_insufficient_for_phase() {
        let mut n = make_newco();
        // Try to enter Selection without founders
        assert!(n.advance_phase(OperationalPhase::Selection).is_err());
    }

    #[test]
    fn full_lifecycle() {
        let mut n = make_newco();

        // Hire founders
        n.hire_agent(make_agent(OdaSlot::HrPeopleOps1)).unwrap();
        n.hire_agent(make_agent(OdaSlot::DeepResearcher)).unwrap();
        n.advance_phase(OperationalPhase::Selection).unwrap();

        // Hire leadership
        n.hire_agent(make_agent(OdaSlot::VentureCommander)).unwrap();
        n.hire_agent(make_agent(OdaSlot::ProcessArchitect)).unwrap();
        n.advance_phase(OperationalPhase::Preparation).unwrap();

        // Fill remaining ODA
        n.hire_agent(make_agent(OdaSlot::OperationsDeputy)).unwrap();
        n.hire_agent(make_agent(OdaSlot::GrowthEngineer1)).unwrap();
        n.hire_agent(make_agent(OdaSlot::GrowthEngineer2)).unwrap();
        n.hire_agent(make_agent(OdaSlot::Communications1)).unwrap();
        n.hire_agent(make_agent(OdaSlot::Communications2)).unwrap();
        n.hire_agent(make_agent(OdaSlot::HrPeopleOps2)).unwrap();
        n.hire_agent(make_agent(OdaSlot::PlatformEngineer1))
            .unwrap();
        n.hire_agent(make_agent(OdaSlot::PlatformEngineer2))
            .unwrap();

        assert!(n.is_fully_staffed());
        n.advance_phase(OperationalPhase::Execution).unwrap();
        assert_eq!(n.status, NewcoStatus::Active);

        n.advance_phase(OperationalPhase::Sustainment).unwrap();
        n.advance_phase(OperationalPhase::Transition).unwrap();
        assert_eq!(n.status, NewcoStatus::Transitioning);

        // Can restart the cycle
        n.advance_phase(OperationalPhase::Assessment).unwrap();
    }

    #[test]
    fn suspend_and_reactivate() {
        let mut n = make_newco();
        n.status = NewcoStatus::Active;
        n.suspend();
        assert_eq!(n.status, NewcoStatus::Suspended);
        n.reactivate();
        assert_eq!(n.status, NewcoStatus::Active);
    }

    #[test]
    fn registry_crud() {
        let mut reg = NewcoRegistry::new();
        assert!(reg.is_empty());

        let n = make_newco();
        let id = n.id;
        reg.register(n).unwrap();

        assert_eq!(reg.len(), 1);
        assert!(reg.get(&id).is_some());
        assert!(reg.receipts(&id).is_some());
    }

    #[test]
    fn registry_duplicate_rejected() {
        let mut reg = NewcoRegistry::new();
        let n = make_newco();
        let n2 = n.clone();
        reg.register(n).unwrap();
        assert!(reg.register(n2).is_err());
    }

    #[test]
    fn status_serde() {
        let statuses = [
            NewcoStatus::Provisioning,
            NewcoStatus::Active,
            NewcoStatus::Suspended,
            NewcoStatus::Transitioning,
            NewcoStatus::Closed,
        ];
        for s in &statuses {
            let j = serde_json::to_string(s).unwrap();
            let rt: NewcoStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, s);
        }
    }
}
