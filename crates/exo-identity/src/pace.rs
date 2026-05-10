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

//! PACE — Primary / Alternate / Contingency / Emergency operator continuity.

use std::{collections::BTreeSet, fmt};

use exo_core::Did;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use crate::error::IdentityError;

/// Maximum DIDs accepted in any non-primary PACE level.
pub const MAX_PACE_LEVEL_DIDS: usize = 32;

/// Configuration defining the operator hierarchy for PACE continuity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaceConfig {
    pub primary: Did,
    #[serde(deserialize_with = "deserialize_pace_alternates")]
    pub alternates: Vec<Did>,
    #[serde(deserialize_with = "deserialize_pace_contingency")]
    pub contingency: Vec<Did>,
    #[serde(deserialize_with = "deserialize_pace_emergency")]
    pub emergency: Vec<Did>,
}

impl fmt::Debug for PaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaceConfig")
            .field("primary", &"<redacted>")
            .field("alternate_count", &self.alternates.len())
            .field("contingency_count", &self.contingency.len())
            .field("emergency_count", &self.emergency.len())
            .finish()
    }
}

fn deserialize_pace_alternates<'de, D>(deserializer: D) -> Result<Vec<Did>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_did_vec(deserializer, "alternates")
}

fn deserialize_pace_contingency<'de, D>(deserializer: D) -> Result<Vec<Did>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_did_vec(deserializer, "contingency")
}

fn deserialize_pace_emergency<'de, D>(deserializer: D) -> Result<Vec<Did>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_did_vec(deserializer, "emergency")
}

fn deserialize_bounded_did_vec<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<Vec<Did>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedDidVecVisitor {
        field: &'static str,
    }

    impl<'de> Visitor<'de> for BoundedDidVecVisitor {
        type Value = Vec<Did>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_PACE_LEVEL_DIDS} DID values in {}",
                self.field
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut dids = Vec::new();
            while let Some(did) = seq.next_element::<Did>()? {
                if dids.len() >= MAX_PACE_LEVEL_DIDS {
                    return Err(de::Error::custom(format!(
                        "{} must not contain more than {} DIDs",
                        self.field, MAX_PACE_LEVEL_DIDS
                    )));
                }
                dids.push(did);
            }
            Ok(dids)
        }
    }

    deserializer.deserialize_seq(BoundedDidVecVisitor { field })
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
pub fn resolve_operator<'a>(
    config: &'a PaceConfig,
    state: &PaceState,
) -> Result<&'a Did, IdentityError> {
    match state {
        PaceState::Normal => Ok(&config.primary),
        PaceState::AlternateActive => config
            .alternates
            .first()
            .ok_or_else(|| IdentityError::InvalidPaceConfig("alternates must not be empty".into())),
        PaceState::ContingencyActive => config.contingency.first().ok_or_else(|| {
            IdentityError::InvalidPaceConfig("contingency must not be empty".into())
        }),
        PaceState::EmergencyActive => config
            .emergency
            .first()
            .ok_or_else(|| IdentityError::InvalidPaceConfig("emergency must not be empty".into())),
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
    fn deserialize_rejects_oversized_pace_levels() {
        let alternates: Vec<String> = (0..=MAX_PACE_LEVEL_DIDS)
            .map(|idx| format!("did:exo:alt-{idx}"))
            .collect();
        let payload = serde_json::json!({
            "primary": "did:exo:primary",
            "alternates": alternates,
            "contingency": ["did:exo:contingency"],
            "emergency": ["did:exo:emergency"]
        });
        let json = serde_json::to_string(&payload).expect("PACE JSON encodes");

        let err = serde_json::from_str::<PaceConfig>(&json)
            .expect_err("oversized PACE level must be rejected during deserialization");

        assert!(
            err.to_string().contains("alternates"),
            "error should identify the oversized PACE level: {err}"
        );
    }

    #[test]
    fn deserialize_accepts_pace_levels_at_bound() {
        let alternates: Vec<String> = (0..MAX_PACE_LEVEL_DIDS)
            .map(|idx| format!("did:exo:alt-{idx}"))
            .collect();
        let payload = serde_json::json!({
            "primary": "did:exo:primary",
            "alternates": alternates,
            "contingency": ["did:exo:contingency"],
            "emergency": ["did:exo:emergency"]
        });
        let json = serde_json::to_string(&payload).expect("PACE JSON encodes");

        let config = serde_json::from_str::<PaceConfig>(&json)
            .expect("PACE levels at the configured bound must deserialize");

        assert_eq!(config.alternates.len(), MAX_PACE_LEVEL_DIDS);
        config
            .validate()
            .expect("bounded non-duplicated PACE config validates");
    }

    #[test]
    fn pace_config_debug_summarizes_operator_lists() {
        let config = make_config();

        let debug = format!("{config:?}");

        assert!(!debug.contains("did:exo:primary"));
        assert!(!debug.contains("did:exo:alt1"));
        assert!(debug.contains("alternate_count"));
        assert!(debug.contains("contingency_count"));
        assert!(debug.contains("emergency_count"));
    }

    #[test]
    fn resolve_operator_normal() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::Normal).expect("valid PACE config"),
            &config.primary
        );
    }

    #[test]
    fn resolve_operator_alternate() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::AlternateActive).expect("valid PACE config"),
            &config.alternates[0]
        );
    }

    #[test]
    fn resolve_operator_contingency() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::ContingencyActive).expect("valid PACE config"),
            &config.contingency[0]
        );
    }

    #[test]
    fn resolve_operator_emergency() {
        let config = make_config();
        assert_eq!(
            resolve_operator(&config, &PaceState::EmergencyActive).expect("valid PACE config"),
            &config.emergency[0]
        );
    }

    #[test]
    fn resolve_operator_rejects_empty_pace_level_without_panicking() {
        let mut config = make_config();
        config.alternates.clear();

        let result =
            std::panic::catch_unwind(|| resolve_operator(&config, &PaceState::AlternateActive));

        assert!(
            result.is_ok(),
            "operator resolution must return a typed error for invalid PACE configs instead of panicking"
        );
        assert!(matches!(
            result.expect("operator resolution must not panic"),
            Err(IdentityError::InvalidPaceConfig(reason)) if reason.contains("alternates")
        ));
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
            resolve_operator(&config, &state)
                .expect("valid PACE config")
                .as_str(),
            "did:exo:primary"
        );
        escalate(&mut state).unwrap();
        assert_eq!(
            resolve_operator(&config, &state)
                .expect("valid PACE config")
                .as_str(),
            "did:exo:alt1"
        );
        escalate(&mut state).unwrap();
        assert_eq!(
            resolve_operator(&config, &state)
                .expect("valid PACE config")
                .as_str(),
            "did:exo:cont1"
        );
        escalate(&mut state).unwrap();
        assert_eq!(
            resolve_operator(&config, &state)
                .expect("valid PACE config")
                .as_str(),
            "did:exo:emerg1"
        );
    }
}
