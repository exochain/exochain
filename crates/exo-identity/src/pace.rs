//! PACE — Primary / Alternate / Contingency / Emergency operator continuity.

use std::collections::BTreeSet;

use exo_core::Did;
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;

/// Configuration defining the operator hierarchy for PACE continuity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaceConfig {
    pub primary: Did,
    pub alternates: Vec<Did>,
    pub contingency: Vec<Did>,
    pub emergency: Vec<Did>,
}

impl PaceConfig {
    /// Validate that all PACE levels are non-empty and contain no duplicate DIDs.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.alternates.is_empty() {
            return Err(IdentityError::InvalidPaceConfig(
                "alternates must not be empty".into(),
            ));
        }
        if self.contingency.is_empty() {
            return Err(IdentityError::InvalidPaceConfig(
                "contingency must not be empty".into(),
            ));
        }
        if self.emergency.is_empty() {
            return Err(IdentityError::InvalidPaceConfig(
                "emergency must not be empty".into(),
            ));
        }

        let mut all = BTreeSet::new();
        let all_dids = std::iter::once(&self.primary)
            .chain(self.alternates.iter())
            .chain(self.contingency.iter())
            .chain(self.emergency.iter());

        for did in all_dids {
            if !all.insert(did.as_str().to_owned()) {
                return Err(IdentityError::DuplicatePaceDid(did.clone()));
            }
        }

        Ok(())
    }
}

/// Current operational state in the PACE escalation hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaceState {
    Normal,
    AlternateActive,
    ContingencyActive,
    EmergencyActive,
}

/// Resolve the currently active operator DID for the given PACE state.
#[must_use]
pub fn resolve_operator<'a>(config: &'a PaceConfig, state: &PaceState) -> &'a Did {
    match state {
        PaceState::Normal => &config.primary,
        PaceState::AlternateActive => &config.alternates[0],
        PaceState::ContingencyActive => &config.contingency[0],
        PaceState::EmergencyActive => &config.emergency[0],
    }
}

/// Escalate the PACE state to the next higher level, returning the new state.
pub fn escalate(state: &mut PaceState) -> Result<PaceState, IdentityError> {
    let new_state = match *state {
        PaceState::Normal => PaceState::AlternateActive,
        PaceState::AlternateActive => PaceState::ContingencyActive,
        PaceState::ContingencyActive => PaceState::EmergencyActive,
        PaceState::EmergencyActive => return Err(IdentityError::CannotEscalate),
    };
    *state = new_state;
    Ok(new_state)
}

/// De-escalate the PACE state to the next lower level, returning the new state.
pub fn deescalate(state: &mut PaceState) -> Result<PaceState, IdentityError> {
    let new_state = match *state {
        PaceState::EmergencyActive => PaceState::ContingencyActive,
        PaceState::ContingencyActive => PaceState::AlternateActive,
        PaceState::AlternateActive => PaceState::Normal,
        PaceState::Normal => return Err(IdentityError::CannotDeescalate),
    };
    *state = new_state;
    Ok(new_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_did(label: &str) -> Did {
        Did::new(&format!("did:exo:{label}")).expect("valid did")
    }

    fn make_config() -> PaceConfig {
        PaceConfig {
            primary: make_did("primary"),
            alternates: vec![make_did("alt1"), make_did("alt2")],
            contingency: vec![make_did("cont1")],
            emergency: vec![make_did("emerg1")],
        }
    }

    #[test]
    fn validate_valid_config() {
        make_config().validate().unwrap();
    }

    #[test]
    fn validate_empty_alternates() {
        let mut config = make_config();
        config.alternates.clear();
        assert!(matches!(
            config.validate().unwrap_err(),
            IdentityError::InvalidPaceConfig(_)
        ));
    }

    #[test]
    fn validate_empty_contingency() {
        let mut config = make_config();
        config.contingency.clear();
        assert!(matches!(
            config.validate().unwrap_err(),
            IdentityError::InvalidPaceConfig(_)
        ));
    }

    #[test]
    fn validate_empty_emergency() {
        let mut config = make_config();
        config.emergency.clear();
        assert!(matches!(
            config.validate().unwrap_err(),
            IdentityError::InvalidPaceConfig(_)
        ));
    }

    #[test]
    fn validate_duplicate_across_levels() {
        let config = PaceConfig {
            primary: make_did("primary"),
            alternates: vec![make_did("alt1")],
            contingency: vec![make_did("primary")],
            emergency: vec![make_did("emerg1")],
        };
        assert!(matches!(
            config.validate().unwrap_err(),
            IdentityError::DuplicatePaceDid(_)
        ));
    }

    #[test]
    fn validate_duplicate_within_level() {
        let config = PaceConfig {
            primary: make_did("primary"),
            alternates: vec![make_did("alt1"), make_did("alt1")],
            contingency: vec![make_did("cont1")],
            emergency: vec![make_did("emerg1")],
        };
        assert!(matches!(
            config.validate().unwrap_err(),
            IdentityError::DuplicatePaceDid(_)
        ));
    }

    #[test]
    fn resolve_operator_normal() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::Normal),
            &config.primary
        );
    }

    #[test]
    fn resolve_operator_alternate() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::AlternateActive),
            &config.alternates[0]
        );
    }

    #[test]
    fn resolve_operator_contingency() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::ContingencyActive),
            &config.contingency[0]
        );
    }

    #[test]
    fn resolve_operator_emergency() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::EmergencyActive),
            &config.emergency[0]
        );
    }

    #[test]
    fn escalate_full_path() {
        let mut state = PaceState::Normal;
        assert_eq!(escalate(&mut state).unwrap(), PaceState::AlternateActive);
        assert_eq!(escalate(&mut state).unwrap(), PaceState::ContingencyActive);
        assert_eq!(escalate(&mut state).unwrap(), PaceState::EmergencyActive);
        assert!(matches!(
            escalate(&mut state).unwrap_err(),
            IdentityError::CannotEscalate
        ));
    }

    #[test]
    fn deescalate_full_path() {
        let mut state = PaceState::EmergencyActive;
        assert_eq!(
            deescalate(&mut state).unwrap(),
            PaceState::ContingencyActive
        );
        assert_eq!(deescalate(&mut state).unwrap(), PaceState::AlternateActive);
        assert_eq!(deescalate(&mut state).unwrap(), PaceState::Normal);
        assert!(matches!(
            deescalate(&mut state).unwrap_err(),
            IdentityError::CannotDeescalate
        ));
    }

    #[test]
    fn escalate_and_deescalate_roundtrip() {
        let mut state = PaceState::Normal;
        escalate(&mut state).unwrap();
        escalate(&mut state).unwrap();
        assert_eq!(state, PaceState::ContingencyActive);
        deescalate(&mut state).unwrap();
        assert_eq!(state, PaceState::AlternateActive);
        deescalate(&mut state).unwrap();
        assert_eq!(state, PaceState::Normal);
    }

    #[test]
    fn resolve_changes_with_escalation() {
        let config = make_config();
        let mut state = PaceState::Normal;

        assert_eq!(
            resolve_operator(&config, &state).as_str(),
            "did:exo:primary"
        );
        escalate(&mut state).unwrap();
        assert_eq!(resolve_operator(&config, &state).as_str(), "did:exo:alt1");
        escalate(&mut state).unwrap();
        assert_eq!(resolve_operator(&config, &state).as_str(), "did:exo:cont1");
        escalate(&mut state).unwrap();
        assert_eq!(resolve_operator(&config, &state).as_str(), "did:exo:emerg1");
    }
}
