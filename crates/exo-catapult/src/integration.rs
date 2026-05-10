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

//! Integration facade — connects Catapult to ExoChain subsystems.
//!
//! Provides helper functions for provisioning newco tenants, building
//! ODA authority chains, creating franchise bailments, and generating
//! agent DIDs in the `did:exo:catapult:` namespace.

use exo_core::Did;
use uuid::Uuid;

use crate::{
    agent::AgentStatus,
    error::{CatapultError, Result},
    newco::Newco,
    oda::OdaSlot,
};

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
        primary: slot_did(newco, OdaSlot::VentureCommander),
        alternates: slot_did_vec(newco, OdaSlot::OperationsDeputy),
        contingency: slot_did_vec(newco, OdaSlot::ProcessArchitect),
        emergency: newco
            .roster
            .founding_agents()
            .iter()
            .map(|a| a.did.clone())
            .collect(),
    }
}

/// Build an operational PACE configuration for authority-chain use.
///
/// Unlike [`build_pace_config`], this function is fail-closed: all command
/// continuity levels must be staffed by active agents before the config can be
/// exported as an operational authority chain.
///
/// # Errors
/// Returns [`CatapultError`] when the newco is invalid, required PACE slots are
/// missing, or any required operator is not active.
pub fn build_operational_pace_config(newco: &Newco) -> Result<PaceConfig> {
    newco.validate()?;

    Ok(PaceConfig {
        primary: Some(require_active_slot(
            newco,
            OdaSlot::VentureCommander,
            "primary",
        )?),
        alternates: vec![require_active_slot(
            newco,
            OdaSlot::OperationsDeputy,
            "alternate",
        )?],
        contingency: vec![require_active_slot(
            newco,
            OdaSlot::ProcessArchitect,
            "contingency",
        )?],
        emergency: vec![
            require_active_slot(newco, OdaSlot::HrPeopleOps1, "emergency")?,
            require_active_slot(newco, OdaSlot::DeepResearcher, "emergency")?,
        ],
    })
}

fn slot_did(newco: &Newco, slot: OdaSlot) -> Option<Did> {
    newco.roster.get(&slot).map(|agent| agent.did.clone())
}

fn slot_did_vec(newco: &Newco, slot: OdaSlot) -> Vec<Did> {
    slot_did(newco, slot).map_or_else(Vec::new, |did| vec![did])
}

fn require_active_slot(newco: &Newco, slot: OdaSlot, level: &str) -> Result<Did> {
    let agent = newco
        .roster
        .get(&slot)
        .ok_or_else(|| CatapultError::InvalidNewco {
            reason: format!(
                "operational PACE {level} slot {} must be staffed",
                slot.slug()
            ),
        })?;

    if agent.status != AgentStatus::Active {
        return Err(CatapultError::InvalidNewco {
            reason: format!(
                "operational PACE {level} slot {} must be active",
                slot.slug()
            ),
        });
    }

    Ok(agent.did.clone())
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
    let short_id = uuid_short_id(newco_id);
    format!("catapult-{short_id}-{}", slot.slug())
}

fn uuid_short_id(id: &Uuid) -> String {
    id.to_string().chars().take(8).collect()
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
    use crate::{
        agent::{AgentStatus, CatapultAgent},
        newco::NewcoInput,
    };

    fn test_did(name: &str) -> Did {
        Did::new(&format!("did:exo:test-{name}")).unwrap()
    }

    fn make_newco() -> Newco {
        Newco::new(NewcoInput {
            id: Uuid::from_bytes([1; 16]),
            name: "Test Co".into(),
            franchise_id: Uuid::from_bytes([2; 16]),
            tenant_id: Uuid::from_bytes([3; 16]),
            constitution_hash: Hash256::digest(b"constitution"),
            authority_chain_root: test_did("root"),
            dag_anchor: Hash256::digest(b"dag-anchor"),
            created: Timestamp {
                physical_ms: 1_765_000_000_000,
                logical: 1,
            },
        })
        .unwrap()
    }

    fn make_agent(slot: OdaSlot, name: &str) -> CatapultAgent {
        CatapultAgent {
            did: test_did(name),
            slot,
            display_name: name.into(),
            capabilities: vec![],
            status: AgentStatus::Active,
            last_heartbeat: Timestamp::new(1_765_000_000_100, 0),
            budget_spent_cents: 0,
            budget_limit_cents: 100_000,
            hired_at: Timestamp::new(1_765_000_000_000, 0),
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
    fn operational_pace_config_rejects_missing_command_slot() {
        let mut newco = make_newco();
        newco
            .hire_agent(make_agent(OdaSlot::VentureCommander, "vc"))
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

        let err = build_operational_pace_config(&newco)
            .expect_err("missing OperationsDeputy must fail closed")
            .to_string();
        assert!(err.contains("operationsdeputy"));
        assert!(err.contains("must be staffed"));
    }

    #[test]
    fn operational_pace_config_rejects_inactive_operator() {
        let mut newco = make_newco();
        newco
            .hire_agent(make_agent(OdaSlot::VentureCommander, "vc"))
            .unwrap();
        let mut deputy = make_agent(OdaSlot::OperationsDeputy, "od");
        deputy.status = AgentStatus::Suspended;
        newco.hire_agent(deputy).unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::ProcessArchitect, "pa"))
            .unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::HrPeopleOps1, "hr"))
            .unwrap();
        newco
            .hire_agent(make_agent(OdaSlot::DeepResearcher, "dr"))
            .unwrap();

        let err = build_operational_pace_config(&newco)
            .expect_err("inactive OperationsDeputy must fail closed")
            .to_string();
        assert!(err.contains("operationsdeputy"));
        assert!(err.contains("must be active"));
    }

    #[test]
    fn operational_pace_config_requires_all_active_levels() {
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

        let pace = build_operational_pace_config(&newco).expect("complete active PACE");
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
        assert!(name.starts_with("catapult-00000000-"));
        assert!(name.contains("venturecommander"));
    }

    #[test]
    fn commandbase_profile_short_id_avoids_byte_slicing() {
        let source = include_str!("integration.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);

        assert!(
            !production.contains("to_string()[..8]"),
            "CommandBase profile short IDs must not byte-slice UUID strings"
        );
        assert!(
            !production.contains("format!(\"{slot:?}\")"),
            "CommandBase profile names must use explicit slot labels"
        );
    }

    #[test]
    fn health_summary_basic() {
        let newco = make_newco();
        let summary = health_summary(&newco, 0);
        assert_eq!(summary.roster_filled, 0);
        assert_eq!(summary.heartbeat_alerts, 0);
    }
}
