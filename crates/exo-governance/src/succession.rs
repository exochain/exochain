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

//! Succession protocol (GOV-011) — orderly transfer of authority
//! when a role-holder becomes unable or unwilling to serve.
//!
//! Supports three trigger types:
//! - **Declaration**: voluntary step-down by the current holder.
//! - **Unresponsiveness**: automatic activation after a timeout.
//! - **DesignatedActivator**: a specific DID triggers the succession.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::errors::GovernanceError;

/// A named role in the governance structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleName(pub String);

impl RoleName {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// An ordered list of successors for a specific role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionPlan {
    pub role: RoleName,
    /// Current holder of the role.
    pub current_holder: Did,
    /// Ordered list of successors — first available takes over.
    pub successors: Vec<Did>,
    /// When the plan was last updated.
    pub updated_at: Timestamp,
}

impl SuccessionPlan {
    /// The next successor in line, if any.
    #[must_use]
    pub fn next_successor(&self) -> Option<&Did> {
        self.successors.first()
    }

    /// Whether the plan has any successors defined.
    #[must_use]
    pub fn has_successors(&self) -> bool {
        !self.successors.is_empty()
    }
}

/// What triggers a succession activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuccessionTrigger {
    /// Voluntary declaration by the current holder.
    Declaration,
    /// Automatic trigger after the holder is unresponsive for `duration_ms`.
    Unresponsiveness {
        /// How many milliseconds of unresponsiveness before activation.
        duration_ms: u64,
        /// The last known activity timestamp of the holder.
        last_active: Timestamp,
    },
    /// A designated DID (e.g., board chair) triggers the succession.
    DesignatedActivator { activator: Did },
}

/// The result of activating a succession.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionResult {
    pub role: RoleName,
    pub previous_holder: Did,
    pub new_holder: Did,
    pub trigger: SuccessionTrigger,
    pub activated_at: Timestamp,
}

/// Activate a succession plan for the given role.
///
/// # Errors
/// - `GovernanceError::ActionNotFound` if the plan has no successors.
/// - `GovernanceError::InvalidTransition` if the trigger conditions are not met.
pub fn activate_succession(
    plan: &SuccessionPlan,
    trigger: SuccessionTrigger,
    now: &Timestamp,
) -> Result<SuccessionResult, GovernanceError> {
    // Verify the plan has successors
    let new_holder = plan.next_successor().ok_or_else(|| {
        GovernanceError::ActionNotFound(format!("no successors defined for role {}", plan.role.0))
    })?;

    // Validate trigger conditions
    match &trigger {
        SuccessionTrigger::Declaration => {
            // Voluntary — always valid
        }
        SuccessionTrigger::Unresponsiveness {
            duration_ms,
            last_active,
        } => {
            // Check that enough time has elapsed
            let elapsed = now.physical_ms.saturating_sub(last_active.physical_ms);
            if elapsed < *duration_ms {
                return Err(GovernanceError::InvalidTransition {
                    from: "active".into(),
                    to: format!(
                        "succession (need {}ms unresponsive, only {}ms elapsed)",
                        duration_ms, elapsed
                    ),
                });
            }
        }
        SuccessionTrigger::DesignatedActivator { activator } => {
            // The activator must not be the current holder (they should use Declaration)
            if *activator == plan.current_holder {
                return Err(GovernanceError::InvalidTransition {
                    from: "self-activation".into(),
                    to: "use Declaration trigger for voluntary step-down".into(),
                });
            }
        }
    }

    Ok(SuccessionResult {
        role: plan.role.clone(),
        previous_holder: plan.current_holder.clone(),
        new_holder: new_holder.clone(),
        trigger,
        activated_at: *now,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn sample_plan() -> SuccessionPlan {
        SuccessionPlan {
            role: RoleName::new("ceo"),
            current_holder: did("alice"),
            successors: vec![did("bob"), did("charlie")],
            updated_at: ts(1000),
        }
    }

    // -- Declaration trigger --

    #[test]
    fn declaration_succeeds() {
        let plan = sample_plan();
        let result = activate_succession(&plan, SuccessionTrigger::Declaration, &ts(5000)).unwrap();
        assert_eq!(result.previous_holder, did("alice"));
        assert_eq!(result.new_holder, did("bob"));
        assert_eq!(result.role, RoleName::new("ceo"));
        assert_eq!(result.activated_at, ts(5000));
    }

    // -- Unresponsiveness trigger --

    #[test]
    fn unresponsiveness_triggers_after_timeout() {
        let plan = sample_plan();
        let trigger = SuccessionTrigger::Unresponsiveness {
            duration_ms: 3_600_000, // 1 hour
            last_active: ts(1000),
        };
        // 2 hours later — should succeed
        let result = activate_succession(&plan, trigger, &ts(7_201_000)).unwrap();
        assert_eq!(result.new_holder, did("bob"));
    }

    #[test]
    fn unresponsiveness_rejects_too_early() {
        let plan = sample_plan();
        let trigger = SuccessionTrigger::Unresponsiveness {
            duration_ms: 3_600_000,
            last_active: ts(1000),
        };
        // Only 30 minutes later — should fail
        let err = activate_succession(&plan, trigger, &ts(1_801_000));
        assert!(matches!(
            err,
            Err(GovernanceError::InvalidTransition { .. })
        ));
    }

    // -- DesignatedActivator trigger --

    #[test]
    fn designated_activator_succeeds() {
        let plan = sample_plan();
        let trigger = SuccessionTrigger::DesignatedActivator {
            activator: did("board-chair"),
        };
        let result = activate_succession(&plan, trigger, &ts(5000)).unwrap();
        assert_eq!(result.new_holder, did("bob"));
    }

    #[test]
    fn designated_activator_rejects_self_activation() {
        let plan = sample_plan();
        // Current holder trying to use DesignatedActivator on themselves
        let trigger = SuccessionTrigger::DesignatedActivator {
            activator: did("alice"),
        };
        let err = activate_succession(&plan, trigger, &ts(5000));
        assert!(matches!(
            err,
            Err(GovernanceError::InvalidTransition { .. })
        ));
    }

    // -- No successors --

    #[test]
    fn no_successors_fails() {
        let plan = SuccessionPlan {
            role: RoleName::new("treasurer"),
            current_holder: did("alice"),
            successors: vec![],
            updated_at: ts(1000),
        };
        let err = activate_succession(&plan, SuccessionTrigger::Declaration, &ts(5000));
        assert!(matches!(err, Err(GovernanceError::ActionNotFound(_))));
    }

    // -- Plan utilities --

    #[test]
    fn plan_next_successor() {
        let plan = sample_plan();
        assert_eq!(plan.next_successor(), Some(&did("bob")));
    }

    #[test]
    fn plan_has_successors() {
        assert!(sample_plan().has_successors());
        let empty = SuccessionPlan {
            role: RoleName::new("r"),
            current_holder: did("a"),
            successors: vec![],
            updated_at: ts(0),
        };
        assert!(!empty.has_successors());
    }

    #[test]
    fn role_name_eq() {
        assert_eq!(RoleName::new("ceo"), RoleName::new("ceo"));
        assert_ne!(RoleName::new("ceo"), RoleName::new("cto"));
    }

    #[test]
    fn succession_trigger_serde() {
        let triggers = vec![
            SuccessionTrigger::Declaration,
            SuccessionTrigger::Unresponsiveness {
                duration_ms: 3_600_000,
                last_active: ts(1000),
            },
            SuccessionTrigger::DesignatedActivator {
                activator: did("board"),
            },
        ];
        for t in &triggers {
            let json = serde_json::to_string(t).unwrap();
            let t2: SuccessionTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(&t2, t);
        }
    }
}
