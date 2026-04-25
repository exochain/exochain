//! Integration facade — connects Catapult to ExoChain subsystems.
//!
//! Provides helper functions for provisioning newco tenants, building
//! ODA authority chains, creating franchise bailments, and generating
//! agent DIDs in the `did:exo:catapult:` namespace.

use exo_core::Did;
use uuid::Uuid;

use crate::{newco::Newco, oda::OdaSlot};

/// PACE (Primary-Alternate-Contingency-Emergency) configuration
/// derived from the ODA command hierarchy.
#[derive(Debug, Clone)]
pub struct PaceConfig {
    /// Primary operator — VentureCommander (18A).
    pub primary: Option<Did>,
    /// Alternates — OperationsDeputy (180A).
    pub alternates: Vec<Did>,
    /// Contingency — ProcessArchitect (18Z).
    pub contingency: Vec<Did>,
    /// Emergency — founding agents (HrPeopleOps1, DeepResearcher).
    pub emergency: Vec<Did>,
}

/// Build a PACE configuration from the current ODA roster.
///
/// Maps the FM 3-05 command hierarchy to PACE continuity levels:
/// - **Primary**: VentureCommander (18A)
/// - **Alternate**: OperationsDeputy (180A)
/// - **Contingency**: ProcessArchitect (18Z)
/// - **Emergency**: Founding agents (HR + Deep Researcher)
#[must_use]
pub fn build_pace_config(newco: &Newco) -> PaceConfig {
    PaceConfig {
        primary: newco
            .roster
            .get(&OdaSlot::VentureCommander)
            .map(|a| a.did.clone()),
        alternates: newco
            .roster
            .get(&OdaSlot::OperationsDeputy)
            .map(|a| vec![a.did.clone()])
            .unwrap_or_default(),
        contingency: newco
            .roster
            .get(&OdaSlot::ProcessArchitect)
            .map(|a| vec![a.did.clone()])
            .unwrap_or_default(),
        emergency: newco
            .roster
            .founding_agents()
            .iter()
            .map(|a| a.did.clone())
            .collect(),
    }
}

/// Decision classification based on ODA authority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionClass {
    /// Any agent within their slot authority.
    Routine,
    /// Requires ProcessArchitect + VentureCommander approval.
    Operational,
    /// Requires VentureCommander + quorum of 3+ agents.
    Strategic,
    /// Requires Catapult platform governance (human gate).
    Constitutional,
}

/// Determine the decision class based on the requesting agent's slot.
#[must_use]
pub fn classify_decision(slot: &OdaSlot) -> DecisionClass {
    match slot.authority_depth() {
        0 => DecisionClass::Strategic, // VentureCommander can initiate strategic
        1 => DecisionClass::Operational, // Deputy initiates operational
        2 => DecisionClass::Operational, // Architect/Researcher — operational
        _ => DecisionClass::Routine,   // Specialists — routine
    }
}

/// Generate a CommandBase.ai agent profile name from a Catapult agent.
///
/// Format: `catapult-<newco_short_id>-<slot_name>`
#[must_use]
pub fn commandbase_profile_name(newco_id: &Uuid, slot: &OdaSlot) -> String {
    let short_id = &newco_id.to_string()[..8];
    let slot_name = format!("{slot:?}").to_ascii_lowercase();
    format!("catapult-{short_id}-{slot_name}")
}

/// Summary of a newco's operational health.
#[derive(Debug, Clone)]
pub struct HealthSummary {
    pub newco_id: Uuid,
    pub phase: crate::phase::OperationalPhase,
    pub status: crate::newco::NewcoStatus,
    pub roster_filled: usize,
    pub roster_active: usize,
    pub budget_verdict: crate::budget::BudgetVerdict,
    pub goal_alignment_bps: u32,
    pub heartbeat_alerts: usize,
}

/// Compute a health summary for a newco.
#[must_use]
pub fn health_summary(newco: &Newco, heartbeat_alerts: usize) -> HealthSummary {
    HealthSummary {
        newco_id: newco.id,
        phase: newco.phase,
        status: newco.status,
        roster_filled: newco.roster.filled_count(),
        roster_active: newco.roster.active_count(),
        budget_verdict: newco
            .budget
            .check_enforcement(&crate::budget::BudgetScope::Company),
        goal_alignment_bps: newco.goals.alignment_score(),
        heartbeat_alerts,
    }
}

#[cfg(test)]
mod tests {
    use exo_core::{Hash256, Timestamp};

    use super::*;
    use crate::agent::{AgentStatus, CatapultAgent};

    fn test_did(name: &str) -> Did {
        Did::new(&format!("did:exo:test-{name}")).unwrap()
    }

    fn make_newco() -> Newco {
        Newco::new(
            "Test Co".into(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Hash256::ZERO,
            test_did("root"),
            Timestamp::ZERO,
        )
    }

    fn make_agent(slot: OdaSlot, name: &str) -> CatapultAgent {
        CatapultAgent {
            did: test_did(name),
            slot,
            display_name: name.into(),
            capabilities: vec![],
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
    fn pace_config_empty_roster() {
        let newco = make_newco();
        let pace = build_pace_config(&newco);
        assert!(pace.primary.is_none());
        assert!(pace.alternates.is_empty());
        assert!(pace.contingency.is_empty());
        assert!(pace.emergency.is_empty());
    }

    #[test]
    fn pace_config_with_roster() {
        let mut newco = make_newco();
        newco
            .hire_agent(make_agent(OdaSlot::VentureCommander, "vc"))
            .unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::OperationsDeputy, "od"))
            .unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::ProcessArchitect, "pa"))
            .unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::HrPeopleOps1, "hr"))
            .unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::DeepResearcher, "dr"))
            .unwrap();

        let pace = build_pace_config(&newco);
        assert!(pace.primary.is_some());
        assert_eq!(pace.alternates.len(), 1);
        assert_eq!(pace.contingency.len(), 1);
        assert_eq!(pace.emergency.len(), 2);
    }

    #[test]
    fn decision_classification() {
        assert_eq!(
            classify_decision(&OdaSlot::VentureCommander),
            DecisionClass::Strategic
        );
        assert_eq!(
            classify_decision(&OdaSlot::OperationsDeputy),
            DecisionClass::Operational
        );
        assert_eq!(
            classify_decision(&OdaSlot::ProcessArchitect),
            DecisionClass::Operational
        );
        assert_eq!(
            classify_decision(&OdaSlot::PlatformEngineer1),
            DecisionClass::Routine
        );
    }

    #[test]
    fn commandbase_profile() {
        let id = Uuid::nil();
        let name = commandbase_profile_name(&id, &OdaSlot::VentureCommander);
        assert!(name.starts_with("catapult-"));
        assert!(name.contains("venturecommander"));
    }

    #[test]
    fn health_summary_basic() {
        let newco = make_newco();
        let summary = health_summary(&newco, 0);
        assert_eq!(summary.roster_filled, 0);
        assert_eq!(summary.heartbeat_alerts, 0);
    }
}
