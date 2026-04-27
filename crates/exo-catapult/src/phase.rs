//! FM 3-05 operational phases adapted for newco lifecycle.
//!
//! The six phases mirror Army Special Operations doctrine:
//! Assessment → Selection → Preparation → Execution → Sustainment → Transition.

use serde::{Deserialize, Serialize};

use crate::{
    error::{CatapultError, Result},
    oda::OdaSlot,
};

/// Operational phase of a newco, aligned with FM 3-05 doctrine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OperationalPhase {
    /// Phase 1: Market opportunity validation, resource survey.
    Assessment,
    /// Phase 2: Agent team composition, capability matching, vetting.
    Selection,
    /// Phase 3: Agent specialization, workflow calibration, business plan.
    Preparation,
    /// Phase 4: Newco launch, tenant provisioning, active operations.
    Execution,
    /// Phase 5: Heartbeat monitoring, budget enforcement, performance.
    Sustainment,
    /// Phase 6: Scale, pivot, franchise replication, or orderly close.
    Transition,
}

impl OperationalPhase {
    /// Valid forward and backward transitions from this phase.
    #[must_use]
    pub fn valid_transitions(self) -> &'static [OperationalPhase] {
        use OperationalPhase::*;
        match self {
            Assessment => &[Selection],
            Selection => &[Preparation, Assessment],
            Preparation => &[Execution, Selection],
            Execution => &[Sustainment],
            Sustainment => &[Transition, Execution],
            Transition => &[Assessment],
        }
    }

    /// Check whether a transition to `target` is permitted.
    #[must_use]
    pub fn can_transition_to(self, target: OperationalPhase) -> bool {
        self.valid_transitions().contains(&target)
    }

    /// Attempt a phase transition, returning an error if invalid.
    pub fn transition(self, target: OperationalPhase) -> Result<OperationalPhase> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(CatapultError::InvalidPhaseTransition {
                from: self,
                to: target,
            })
        }
    }

    /// Minimum ODA slots required to enter this phase.
    #[must_use]
    pub fn min_roster(self) -> &'static [OdaSlot] {
        use OperationalPhase::*;
        match self {
            Assessment => &[],
            Selection => &OdaSlot::FOUNDERS,
            Preparation => &[
                OdaSlot::HrPeopleOps1,
                OdaSlot::DeepResearcher,
                OdaSlot::VentureCommander,
                OdaSlot::ProcessArchitect,
            ],
            Execution | Sustainment => &OdaSlot::ALL,
            Transition => &[OdaSlot::VentureCommander, OdaSlot::OperationsDeputy],
        }
    }

    /// All six phases in lifecycle order.
    pub const ALL: [OperationalPhase; 6] = [
        Self::Assessment,
        Self::Selection,
        Self::Preparation,
        Self::Execution,
        Self::Sustainment,
        Self::Transition,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_forward() {
        use OperationalPhase::*;
        let path = [
            Assessment,
            Selection,
            Preparation,
            Execution,
            Sustainment,
            Transition,
        ];
        for w in path.windows(2) {
            assert!(
                w[0].can_transition_to(w[1]),
                "{:?} should transition to {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn backward_transitions() {
        use OperationalPhase::*;
        // Selection can loop back to Assessment
        assert!(Selection.can_transition_to(Assessment));
        // Preparation can loop back to Selection
        assert!(Preparation.can_transition_to(Selection));
        // Sustainment can re-enter Execution
        assert!(Sustainment.can_transition_to(Execution));
        // Transition can restart the cycle
        assert!(Transition.can_transition_to(Assessment));
    }

    #[test]
    fn invalid_transitions() {
        use OperationalPhase::*;
        assert!(!Assessment.can_transition_to(Execution));
        assert!(!Assessment.can_transition_to(Transition));
        assert!(!Execution.can_transition_to(Assessment));
        assert!(!Sustainment.can_transition_to(Selection));
    }

    #[test]
    fn transition_result() {
        use OperationalPhase::*;
        assert_eq!(Assessment.transition(Selection).unwrap(), Selection);
        assert!(Assessment.transition(Execution).is_err());
    }

    #[test]
    fn min_roster_assessment_empty() {
        assert!(OperationalPhase::Assessment.min_roster().is_empty());
    }

    #[test]
    fn min_roster_selection_founders() {
        let roster = OperationalPhase::Selection.min_roster();
        assert_eq!(roster.len(), 2);
        assert!(roster.contains(&OdaSlot::HrPeopleOps1));
        assert!(roster.contains(&OdaSlot::DeepResearcher));
    }

    #[test]
    fn min_roster_execution_full() {
        assert_eq!(OperationalPhase::Execution.min_roster().len(), 12);
    }

    #[test]
    fn min_roster_transition_minimal() {
        let roster = OperationalPhase::Transition.min_roster();
        assert_eq!(roster.len(), 2);
        assert!(roster.contains(&OdaSlot::VentureCommander));
        assert!(roster.contains(&OdaSlot::OperationsDeputy));
    }

    #[test]
    fn all_phases_count() {
        assert_eq!(OperationalPhase::ALL.len(), 6);
    }

    #[test]
    fn serde_roundtrip() {
        for phase in &OperationalPhase::ALL {
            let j = serde_json::to_string(phase).unwrap();
            let rt: OperationalPhase = serde_json::from_str(&j).unwrap();
            assert_eq!(&rt, phase);
        }
    }
}
