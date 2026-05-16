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

//! Quorum management (GOV-010, TNC-07).
//!
//! Per-decision-class quorum policies, verification BEFORE vote initiation,
//! graceful degradation on quorum failure, and independence-aware counting
//! via exo_governance::quorum.

use std::collections::BTreeSet;

use exo_core::types::{DeterministicMap, Did};
use serde::{Deserialize, Serialize};

use crate::{
    decision_object::{DecisionClass, DecisionObject, VoteChoice},
    error::{ForumError, Result},
    human_gate::is_verified_human_vote,
};

/// Quorum policy for a specific decision class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumRequirement {
    pub min_votes: usize,
    pub min_approve_pct: usize,
    pub min_human_votes: usize,
}

/// Registry of quorum policies per decision class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumRegistry {
    pub policies: DeterministicMap<String, QuorumRequirement>,
}

impl QuorumRegistry {
    /// Create a registry with default policies.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut policies = DeterministicMap::new();
        policies.insert(
            "Routine".into(),
            QuorumRequirement {
                min_votes: 1,
                min_approve_pct: 51,
                min_human_votes: 0,
            },
        );
        policies.insert(
            "Operational".into(),
            QuorumRequirement {
                min_votes: 3,
                min_approve_pct: 51,
                min_human_votes: 1,
            },
        );
        policies.insert(
            "Strategic".into(),
            QuorumRequirement {
                min_votes: 5,
                min_approve_pct: 67,
                min_human_votes: 3,
            },
        );
        policies.insert(
            "Constitutional".into(),
            QuorumRequirement {
                min_votes: 7,
                min_approve_pct: 75,
                min_human_votes: 5,
            },
        );
        Self { policies }
    }

    /// Look up the quorum requirement for a decision class.
    #[must_use]
    pub fn requirement_for(&self, class: DecisionClass) -> Option<&QuorumRequirement> {
        self.policies.get(&class.quorum_policy_key().to_owned())
    }
}

/// Result of a quorum check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumCheckResult {
    /// Quorum met with the given counts.
    Met {
        total_votes: usize,
        approve_count: usize,
        approve_pct: usize,
    },
    /// Quorum not met.
    NotMet { reason: String },
    /// Graceful degradation: partial quorum available.
    Degraded {
        reason: String,
        available: usize,
        required: usize,
    },
}

/// Check if quorum is met for a decision based on its class and votes.
pub fn check_quorum(
    registry: &QuorumRegistry,
    decision: &DecisionObject,
) -> Result<QuorumCheckResult> {
    check_quorum_with_verified_humans(registry, decision, &BTreeSet::new())
}

/// Check if quorum is met using a trusted set of externally verified human
/// voter DIDs. Human vote floors are satisfied only when the vote is declared
/// human and the voter DID appears in this set.
pub fn check_quorum_with_verified_humans(
    registry: &QuorumRegistry,
    decision: &DecisionObject,
    verified_human_voters: &BTreeSet<Did>,
) -> Result<QuorumCheckResult> {
    let req = registry
        .requirement_for(decision.class)
        .ok_or(ForumError::QuorumPolicyMissing)?;
    validate_requirement(req)?;

    let total_votes = decision.votes.len();
    let approve_count = decision
        .votes
        .iter()
        .filter(|v| v.choice == VoteChoice::Approve)
        .count();
    let human_count = decision
        .votes
        .iter()
        .filter(|vote| is_verified_human_vote(vote, verified_human_voters))
        .count();

    if total_votes < req.min_votes {
        return Ok(QuorumCheckResult::Degraded {
            reason: format!("insufficient votes: {} < {}", total_votes, req.min_votes),
            available: total_votes,
            required: req.min_votes,
        });
    }

    if human_count < req.min_human_votes {
        return Ok(QuorumCheckResult::NotMet {
            reason: format!(
                "insufficient human votes: {} < {}",
                human_count, req.min_human_votes
            ),
        });
    }

    let approve_pct = approve_count
        .checked_mul(100)
        .and_then(|n| n.checked_div(total_votes))
        .unwrap_or(0);

    if approve_pct < req.min_approve_pct {
        return Ok(QuorumCheckResult::NotMet {
            reason: format!(
                "approval percentage {}% < required {}%",
                approve_pct, req.min_approve_pct
            ),
        });
    }

    Ok(QuorumCheckResult::Met {
        total_votes,
        approve_count,
        approve_pct,
    })
}

/// Verify quorum preconditions BEFORE a vote is initiated (TNC-07).
/// Returns true if enough eligible voters and eligible human voters exist to
/// potentially meet quorum.
pub fn verify_quorum_precondition(
    registry: &QuorumRegistry,
    class: DecisionClass,
    eligible_voters: usize,
    eligible_human_voters: usize,
) -> Result<bool> {
    let req = registry
        .requirement_for(class)
        .ok_or(ForumError::QuorumPolicyMissing)?;
    validate_requirement(req)?;
    Ok(eligible_voters >= req.min_votes && eligible_human_voters >= req.min_human_votes)
}

fn validate_requirement(req: &QuorumRequirement) -> Result<()> {
    if !(1..=100).contains(&req.min_approve_pct) {
        return Err(ForumError::QuorumPolicyInvalid {
            reason: format!(
                "min_approve_pct must be in 1..=100; got {}",
                req.min_approve_pct
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use exo_core::{
        hlc::HybridClock,
        types::{Did, Hash256},
    };
    use uuid::Uuid;

    use super::*;
    use crate::decision_object::*;

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn human_approve_vote(name: &str, clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new(&format!("did:exo:{name}")).expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::Human,
            timestamp: clock.now().expect("HLC timestamp"),
            signature_hash: Hash256::digest(name.as_bytes()),
        }
    }

    fn ai_approve_vote(name: &str, clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new(&format!("did:exo:{name}")).expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "d1".into(),
                ceiling_class: DecisionClass::Operational,
            },
            timestamp: clock.now().expect("HLC timestamp"),
            signature_hash: Hash256::digest(name.as_bytes()),
        }
    }

    fn reject_vote(name: &str, clock: &mut HybridClock) -> Vote {
        Vote {
            voter_did: Did::new(&format!("did:exo:{name}")).expect("ok"),
            choice: VoteChoice::Reject,
            actor_kind: ActorKind::Human,
            timestamp: clock.now().expect("HLC timestamp"),
            signature_hash: Hash256::digest(name.as_bytes()),
        }
    }

    fn make_decision(title: &str, class: DecisionClass, clock: &mut HybridClock) -> DecisionObject {
        DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(200),
            title: title.into(),
            class,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: clock.now().expect("HLC timestamp"),
        })
        .expect("valid decision")
    }

    fn verified_human_voters(decision: &DecisionObject) -> BTreeSet<Did> {
        decision
            .votes
            .iter()
            .filter(|vote| matches!(vote.actor_kind, ActorKind::Human))
            .map(|vote| vote.voter_did.clone())
            .collect()
    }

    #[test]
    fn routine_quorum_met() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = make_decision("test", DecisionClass::Routine, &mut clock);
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        match check_quorum_with_verified_humans(&reg, &d, &verified_human_voters(&d)).expect("ok") {
            QuorumCheckResult::Met { total_votes, .. } => assert_eq!(total_votes, 1),
            other => panic!("expected Met, got {other:?}"),
        }
    }

    #[test]
    fn operational_needs_three_votes() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = make_decision("test", DecisionClass::Operational, &mut clock);
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        match check_quorum_with_verified_humans(&reg, &d, &verified_human_voters(&d)).expect("ok") {
            QuorumCheckResult::Degraded {
                available,
                required,
                ..
            } => {
                assert_eq!(available, 1);
                assert_eq!(required, 3);
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn operational_quorum_met() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = make_decision("test", DecisionClass::Operational, &mut clock);
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        d.add_vote(ai_approve_vote("bot1", &mut clock)).expect("ok");
        d.add_vote(ai_approve_vote("bot2", &mut clock)).expect("ok");
        match check_quorum_with_verified_humans(&reg, &d, &verified_human_voters(&d)).expect("ok") {
            QuorumCheckResult::Met {
                total_votes,
                approve_count,
                ..
            } => {
                assert_eq!(total_votes, 3);
                assert_eq!(approve_count, 3);
            }
            other => panic!("expected Met, got {other:?}"),
        }
    }

    #[test]
    fn insufficient_approval_pct() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = make_decision("test", DecisionClass::Operational, &mut clock);
        d.add_vote(human_approve_vote("alice", &mut clock))
            .expect("ok");
        d.add_vote(reject_vote("bob", &mut clock)).expect("ok");
        d.add_vote(reject_vote("carol", &mut clock)).expect("ok");
        match check_quorum_with_verified_humans(&reg, &d, &verified_human_voters(&d)).expect("ok") {
            QuorumCheckResult::NotMet { reason } => {
                assert!(reason.contains("approval percentage"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn strategic_needs_human_votes() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = make_decision("test", DecisionClass::Strategic, &mut clock);
        for i in 0..5 {
            d.add_vote(ai_approve_vote(&format!("bot{i}"), &mut clock))
                .expect("ok");
        }
        match check_quorum(&reg, &d).expect("ok") {
            QuorumCheckResult::NotMet { reason } => {
                assert!(reason.contains("human"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn check_quorum_rejects_unverified_human_actor_kind() {
        let mut clock = test_clock();
        let reg = QuorumRegistry::with_defaults();
        let mut d = make_decision(
            "declared humans are not verified humans",
            DecisionClass::Strategic,
            &mut clock,
        );
        for name in ["alice", "bob", "carol", "dave", "erin"] {
            d.add_vote(human_approve_vote(name, &mut clock))
                .expect("declared human vote accepted into decision object");
        }

        match check_quorum(&reg, &d).expect("quorum check ok") {
            QuorumCheckResult::NotMet { reason } => {
                assert!(
                    reason.contains("human"),
                    "unverified declared-human votes must not satisfy human quorum: {reason}"
                );
            }
            other => panic!("expected NotMet for unverified human actor_kind, got {other:?}"),
        }
    }

    #[test]
    fn verify_precondition() {
        let reg = QuorumRegistry::with_defaults();
        assert!(verify_quorum_precondition(&reg, DecisionClass::Routine, 1, 0).expect("ok"));
        assert!(!verify_quorum_precondition(&reg, DecisionClass::Operational, 2, 1).expect("ok"));
        assert!(!verify_quorum_precondition(&reg, DecisionClass::Operational, 3, 0).expect("ok"));
        assert!(verify_quorum_precondition(&reg, DecisionClass::Operational, 3, 1).expect("ok"));
    }

    #[test]
    fn strategic_precondition_rejects_when_human_floor_is_impossible() {
        let reg = QuorumRegistry::with_defaults();

        assert!(
            !verify_quorum_precondition(&reg, DecisionClass::Strategic, 5, 0).expect("ok"),
            "strategic class requires three eligible human voters"
        );
    }

    #[test]
    fn constitutional_precondition_rejects_when_human_floor_is_impossible() {
        let reg = QuorumRegistry::with_defaults();

        assert!(
            !verify_quorum_precondition(&reg, DecisionClass::Constitutional, 7, 4).expect("ok"),
            "constitutional class requires five eligible human voters"
        );
    }

    fn registry_with_routine_requirement(requirement: QuorumRequirement) -> QuorumRegistry {
        let mut policies = DeterministicMap::new();
        policies.insert(
            DecisionClass::Routine.quorum_policy_key().to_owned(),
            requirement,
        );
        QuorumRegistry { policies }
    }

    #[test]
    fn check_quorum_rejects_invalid_approval_thresholds() {
        for threshold in [0, 101] {
            let mut clock = test_clock();
            let reg = registry_with_routine_requirement(QuorumRequirement {
                min_votes: 1,
                min_approve_pct: threshold,
                min_human_votes: 0,
            });
            let mut decision =
                make_decision("invalid threshold", DecisionClass::Routine, &mut clock);
            decision
                .add_vote(human_approve_vote("alice", &mut clock))
                .expect("vote accepted");

            let err = check_quorum(&reg, &decision).expect_err("invalid threshold must fail");
            assert!(matches!(
                err,
                ForumError::QuorumPolicyInvalid { reason }
                    if reason.contains("min_approve_pct")
                        && reason.contains(&threshold.to_string())
            ));
        }
    }

    #[test]
    fn precondition_rejects_invalid_approval_threshold() {
        let reg = registry_with_routine_requirement(QuorumRequirement {
            min_votes: 1,
            min_approve_pct: 101,
            min_human_votes: 0,
        });

        let err = verify_quorum_precondition(&reg, DecisionClass::Routine, 1, 0)
            .expect_err("invalid threshold must fail before vote initiation");
        assert!(matches!(err, ForumError::QuorumPolicyInvalid { .. }));
    }

    #[test]
    fn default_registry_has_all_classes() {
        let reg = QuorumRegistry::with_defaults();
        assert!(reg.requirement_for(DecisionClass::Routine).is_some());
        assert!(reg.requirement_for(DecisionClass::Operational).is_some());
        assert!(reg.requirement_for(DecisionClass::Strategic).is_some());
        assert!(reg.requirement_for(DecisionClass::Constitutional).is_some());
    }

    #[test]
    fn requirement_lookup_does_not_depend_on_debug_format() {
        let source = include_str!("quorum.rs");
        let Some(after_lookup) = source.split("pub fn requirement_for").nth(1) else {
            panic!("requirement_for exists");
        };
        let Some(lookup_body) = after_lookup.split("/// Result of a quorum check").next() else {
            panic!("lookup body exists");
        };

        assert!(
            !lookup_body.contains("format!(\"{class:?}\")"),
            "quorum policy lookup must use an explicit stable key, not Debug output"
        );
    }
}
