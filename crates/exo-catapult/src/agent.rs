//! Catapult agent definitions and roster management.

use exo_core::{DeterministicMap, Did, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::{CatapultError, Result},
    oda::OdaSlot,
};

/// Operational status of an agent within the ODA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Slot open, candidate being evaluated.
    Recruiting,
    /// Selected, undergoing preparation.
    Onboarding,
    /// Fully operational.
    Active,
    /// Temporarily stood down (budget, heartbeat, or governance action).
    Suspended,
    /// Honorably released from the ODA.
    Released,
}

/// An agent assigned to an ODA slot within a newco.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatapultAgent {
    /// Agent's decentralized identifier.
    pub did: Did,
    /// ODA slot this agent fills.
    pub slot: OdaSlot,
    /// Human-readable display name.
    pub display_name: String,
    /// Agent capabilities / specializations.
    pub capabilities: Vec<String>,
    /// Current operational status.
    pub status: AgentStatus,
    /// Last heartbeat timestamp.
    pub last_heartbeat: Timestamp,
    /// Budget spent in integer cents.
    pub budget_spent_cents: u64,
    /// Budget limit in integer cents.
    pub budget_limit_cents: u64,
    /// When this agent was hired.
    pub hired_at: Timestamp,
    /// DID of the agent that recruited this one.
    pub hired_by: Did,
    /// Optional link to CommandBase.ai profile name.
    pub commandbase_profile: Option<String>,
}

/// The ODA roster — a governed map of slots to agents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentRoster {
    agents: DeterministicMap<OdaSlot, CatapultAgent>,
}

impl AgentRoster {
    /// Create an empty roster.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agents: DeterministicMap::new(),
        }
    }

    /// Fill an ODA slot with an agent. Returns an error if the slot is already occupied.
    pub fn fill_slot(&mut self, agent: CatapultAgent) -> Result<()> {
        let slot = agent.slot;
        if self.agents.contains_key(&slot) {
            return Err(CatapultError::SlotAlreadyFilled(slot));
        }
        self.agents.insert(slot, agent);
        Ok(())
    }

    /// Release an agent from a slot, returning the agent.
    pub fn release_slot(&mut self, slot: &OdaSlot) -> Result<CatapultAgent> {
        self.agents
            .remove(slot)
            .ok_or(CatapultError::SlotEmpty(*slot))
    }

    /// Look up an agent by slot.
    #[must_use]
    pub fn get(&self, slot: &OdaSlot) -> Option<&CatapultAgent> {
        self.agents.get(slot)
    }

    /// Look up an agent by DID.
    #[must_use]
    pub fn get_by_did(&self, did: &Did) -> Option<&CatapultAgent> {
        self.agents.values().find(|a| a.did == *did)
    }

    /// Return the founding agents (HR + Deep Researcher).
    #[must_use]
    pub fn founding_agents(&self) -> Vec<&CatapultAgent> {
        OdaSlot::FOUNDERS
            .iter()
            .filter_map(|slot| self.agents.get(slot))
            .collect()
    }

    /// Whether all 12 ODA slots are filled.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        OdaSlot::ALL
            .iter()
            .all(|slot| self.agents.contains_key(slot))
    }

    /// Number of filled slots.
    #[must_use]
    pub fn filled_count(&self) -> usize {
        self.agents.len()
    }

    /// Number of vacant slots.
    #[must_use]
    pub fn vacancy_count(&self) -> usize {
        12_usize.saturating_sub(self.agents.len())
    }

    /// Number of agents currently in Active status.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.agents
            .values()
            .filter(|a| a.status == AgentStatus::Active)
            .count()
    }

    /// Check whether a specific set of slots are filled.
    #[must_use]
    pub fn has_slots(&self, required: &[OdaSlot]) -> bool {
        required.iter().all(|slot| self.agents.contains_key(slot))
    }

    /// Iterate over all filled slots.
    pub fn iter(&self) -> impl Iterator<Item = (&OdaSlot, &CatapultAgent)> {
        self.agents.iter()
    }

    /// Generate a unique DID for an agent in this newco.
    ///
    /// Format: `did:exo:catapult:<newco_id>:<slot_name>`
    pub fn generate_did(newco_id: &Uuid, slot: &OdaSlot) -> exo_core::Result<Did> {
        let slot_name = format!("{slot:?}").to_ascii_lowercase();
        Did::new(&format!("did:exo:catapult:{newco_id}:{slot_name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_did(name: &str) -> Did {
        Did::new(&format!("did:exo:test-{name}")).unwrap()
    }

    fn make_agent(slot: OdaSlot, name: &str) -> CatapultAgent {
        CatapultAgent {
            did: test_did(name),
            slot,
            display_name: name.into(),
            capabilities: vec!["test".into()],
            status: AgentStatus::Active,
            last_heartbeat: Timestamp::ZERO,
            budget_spent_cents: 0,
            budget_limit_cents: 100_000,
            hired_at: Timestamp::ZERO,
            hired_by: test_did("hr"),
            commandbase_profile: None,
        }
    }

    #[test]
    fn fill_and_get() {
        let mut roster = AgentRoster::new();
        let agent = make_agent(OdaSlot::HrPeopleOps1, "hr1");
        roster.fill_slot(agent).unwrap();
        assert_eq!(roster.filled_count(), 1);
        assert_eq!(roster.vacancy_count(), 11);
        assert!(roster.get(&OdaSlot::HrPeopleOps1).is_some());
    }

    #[test]
    fn duplicate_slot_rejected() {
        let mut roster = AgentRoster::new();
        roster
            .fill_slot(make_agent(OdaSlot::DeepResearcher, "dr1"))
            .unwrap();
        let result = roster.fill_slot(make_agent(OdaSlot::DeepResearcher, "dr2"));
        assert!(result.is_err());
    }

    #[test]
    fn release_slot() {
        let mut roster = AgentRoster::new();
        roster
            .fill_slot(make_agent(OdaSlot::VentureCommander, "vc"))
            .unwrap();
        let released = roster.release_slot(&OdaSlot::VentureCommander).unwrap();
        assert_eq!(released.display_name, "vc");
        assert_eq!(roster.filled_count(), 0);
    }

    #[test]
    fn release_empty_slot() {
        let mut roster = AgentRoster::new();
        assert!(roster.release_slot(&OdaSlot::VentureCommander).is_err());
    }

    #[test]
    fn founding_agents() {
        let mut roster = AgentRoster::new();
        roster
            .fill_slot(make_agent(OdaSlot::HrPeopleOps1, "hr"))
            .unwrap();
        roster
            .fill_slot(make_agent(OdaSlot::DeepResearcher, "dr"))
            .unwrap();
        assert_eq!(roster.founding_agents().len(), 2);
    }

    #[test]
    fn complete_roster() {
        let mut roster = AgentRoster::new();
        for (i, slot) in OdaSlot::ALL.iter().enumerate() {
            roster
                .fill_slot(make_agent(*slot, &format!("agent-{i}")))
                .unwrap();
        }
        assert!(roster.is_complete());
        assert_eq!(roster.filled_count(), 12);
        assert_eq!(roster.vacancy_count(), 0);
        assert_eq!(roster.active_count(), 12);
    }

    #[test]
    fn has_slots() {
        let mut roster = AgentRoster::new();
        roster
            .fill_slot(make_agent(OdaSlot::HrPeopleOps1, "hr"))
            .unwrap();
        roster
            .fill_slot(make_agent(OdaSlot::DeepResearcher, "dr"))
            .unwrap();
        assert!(roster.has_slots(&OdaSlot::FOUNDERS));
        assert!(!roster.has_slots(&[OdaSlot::VentureCommander]));
    }

    #[test]
    fn get_by_did() {
        let mut roster = AgentRoster::new();
        let agent = make_agent(OdaSlot::VentureCommander, "vc");
        let did = agent.did.clone();
        roster.fill_slot(agent).unwrap();
        assert!(roster.get_by_did(&did).is_some());
        assert!(roster.get_by_did(&test_did("nonexistent")).is_none());
    }

    #[test]
    fn generate_did_format() {
        let id = Uuid::nil();
        let did = AgentRoster::generate_did(&id, &OdaSlot::VentureCommander).unwrap();
        assert!(did.as_str().starts_with("did:exo:catapult:"));
        assert!(did.as_str().contains("venturecommander"));
    }

    #[test]
    fn agent_status_serde() {
        let statuses = [
            AgentStatus::Recruiting,
            AgentStatus::Onboarding,
            AgentStatus::Active,
            AgentStatus::Suspended,
            AgentStatus::Released,
        ];
        for s in &statuses {
            let j = serde_json::to_string(s).unwrap();
            let rt: AgentStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, s);
        }
    }
}
