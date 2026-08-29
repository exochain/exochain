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

//! Independence verification (anti-Sybil).

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

/// Maximum accepted actors for independence verification.
pub const MAX_INDEPENDENCE_ACTORS: usize = 1_024;
/// Maximum suspicious-pair output produced by independence verification.
pub const MAX_INDEPENDENCE_SUSPICIOUS_PAIRS: usize = 4_096;
/// Maximum accepted coordination actions before the pair-work budget is applied.
pub const MAX_COORDINATION_ACTIONS: usize = 4_096;
/// Maximum pair comparisons performed by coordination detection.
pub const MAX_COORDINATION_PAIR_CHECKS: usize = 65_341;
/// Maximum coordination signals returned by one detection pass.
pub const MAX_COORDINATION_SIGNALS: usize = 4_096;

/// Registry of identity attributes used for Sybil detection and independence verification.
#[derive(Debug, Clone, Default)]
pub struct IdentityRegistry {
    pub signing_keys: BTreeMap<Did, String>,
    pub attestation_roots: BTreeMap<Did, Did>,
    pub control_metadata: BTreeMap<Did, String>,
}

/// A group of DIDs that share a common identity attribute, indicating potential Sybil collusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cluster {
    pub reason: String,
    pub members: Vec<Did>,
}

/// Result of an independence verification: independent count, clusters, and suspicious pairs.
#[derive(Debug, Clone)]
pub struct IndependenceResult {
    pub independent_count: usize,
    pub clusters: Vec<Cluster>,
    pub suspicious_pairs: Vec<(Did, Did)>,
}

/// An actor's action with its timestamp, used for coordination detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedAction {
    pub actor: Did,
    pub action_hash: [u8; 32],
    pub timestamp: Timestamp,
}

/// Signal indicating potential coordination between actors based on timing analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationSignal {
    pub actors: Vec<Did>,
    pub reason: String,
    pub confidence: u8,
}

/// Typed denial returned when crosscheck work or output exceeds a finite budget.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "Crosscheck resource limit exceeded for {resource}: at least {observed} units, maximum {maximum}"
)]
pub struct CrosscheckResourceLimitError {
    pub resource: String,
    pub observed: usize,
    pub maximum: usize,
}

fn resource_limit_error(
    resource: &str,
    observed: usize,
    maximum: usize,
) -> CrosscheckResourceLimitError {
    CrosscheckResourceLimitError {
        resource: resource.to_owned(),
        observed,
        maximum,
    }
}

fn ensure_resource_limit(
    resource: &str,
    observed: usize,
    maximum: usize,
) -> Result<(), CrosscheckResourceLimitError> {
    if observed > maximum {
        return Err(resource_limit_error(resource, observed, maximum));
    }
    Ok(())
}

fn checked_pair_count(
    item_count: usize,
    resource: &str,
    maximum: usize,
) -> Result<usize, CrosscheckResourceLimitError> {
    let preceding = item_count.saturating_sub(1);
    let (left, right) = if item_count & 1 == 0 {
        (item_count / 2, preceding)
    } else {
        (item_count, preceding / 2)
    };
    left.checked_mul(right)
        .ok_or_else(|| resource_limit_error(resource, usize::MAX, maximum))
}

fn coordination_pair_checks(action_count: usize) -> Result<usize, CrosscheckResourceLimitError> {
    ensure_resource_limit(
        "coordination actions",
        action_count,
        MAX_COORDINATION_ACTIONS,
    )?;
    let pair_checks = checked_pair_count(
        action_count,
        "coordination pair checks",
        MAX_COORDINATION_PAIR_CHECKS,
    )?;
    ensure_resource_limit(
        "coordination pair checks",
        pair_checks,
        MAX_COORDINATION_PAIR_CHECKS,
    )?;
    Ok(pair_checks)
}

fn independence_suspicious_pair_capacity(
    control_groups: &BTreeMap<&str, Vec<Did>>,
    already_clustered: &BTreeSet<Did>,
) -> Result<usize, CrosscheckResourceLimitError> {
    let mut total = 0_usize;
    for members in control_groups.values() {
        let all_pairs = checked_pair_count(
            members.len(),
            "independence suspicious pairs",
            MAX_INDEPENDENCE_SUSPICIOUS_PAIRS,
        )?;
        let clustered_members = members
            .iter()
            .filter(|member| already_clustered.contains(*member))
            .count();
        let already_explained_pairs = checked_pair_count(
            clustered_members,
            "independence suspicious pairs",
            MAX_INDEPENDENCE_SUSPICIOUS_PAIRS,
        )?;
        let group_pairs = all_pairs
            .checked_sub(already_explained_pairs)
            .ok_or_else(|| {
                resource_limit_error(
                    "independence suspicious pairs",
                    usize::MAX,
                    MAX_INDEPENDENCE_SUSPICIOUS_PAIRS,
                )
            })?;
        total = total.checked_add(group_pairs).ok_or_else(|| {
            resource_limit_error(
                "independence suspicious pairs",
                usize::MAX,
                MAX_INDEPENDENCE_SUSPICIOUS_PAIRS,
            )
        })?;
        ensure_resource_limit(
            "independence suspicious pairs",
            total,
            MAX_INDEPENDENCE_SUSPICIOUS_PAIRS,
        )?;
    }
    Ok(total)
}

/// Verify independence of actors by checking for shared keys, attestation roots, and control metadata.
///
/// This compatibility entry point fails closed with zero independent actors if
/// a resource budget is exceeded. Call [`try_verify_independence`] when the
/// caller can propagate a typed error.
#[must_use]
pub fn verify_independence(actors: &[Did], registry: &IdentityRegistry) -> IndependenceResult {
    match try_verify_independence(actors, registry) {
        Ok(result) => result,
        Err(error) => IndependenceResult {
            independent_count: 0,
            clusters: vec![Cluster {
                reason: format!("independence verification denied by resource limit: {error}"),
                members: Vec::new(),
            }],
            suspicious_pairs: Vec::new(),
        },
    }
}

/// Verify independence while returning typed resource-limit failures.
///
/// # Errors
///
/// Returns [`CrosscheckResourceLimitError`] before
/// unbounded work or output when an actor or suspicious-pair budget is exceeded.
pub fn try_verify_independence(
    actors: &[Did],
    registry: &IdentityRegistry,
) -> Result<IndependenceResult, CrosscheckResourceLimitError> {
    ensure_resource_limit("independence actors", actors.len(), MAX_INDEPENDENCE_ACTORS)?;
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut clustered_dids: BTreeSet<Did> = BTreeSet::new();

    // Check 1: Same signing keys
    let mut key_groups: BTreeMap<&str, Vec<Did>> = BTreeMap::new();
    for actor in actors {
        if let Some(key) = registry.signing_keys.get(actor) {
            key_groups
                .entry(key.as_str())
                .or_default()
                .push(actor.clone());
        }
    }
    for (key, members) in &key_groups {
        if members.len() > 1 {
            clusters.push(Cluster {
                reason: format!("shared signing key: {key}"),
                members: members.clone(),
            });
            for m in members {
                clustered_dids.insert(m.clone());
            }
        }
    }

    // Check 2: Same attestation chain root
    let mut root_groups: BTreeMap<Did, Vec<Did>> = BTreeMap::new();
    for actor in actors {
        if let Some(root) = registry.attestation_roots.get(actor) {
            root_groups
                .entry(root.clone())
                .or_default()
                .push(actor.clone());
        }
    }
    for (_root, members) in &root_groups {
        if members.len() > 1 {
            clusters.push(Cluster {
                reason: format!("shared attestation root: {_root}"),
                members: members.clone(),
            });
            for m in members {
                clustered_dids.insert(m.clone());
            }
        }
    }

    // Check 3: Shared control metadata
    let mut control_groups: BTreeMap<&str, Vec<Did>> = BTreeMap::new();
    for actor in actors {
        if let Some(meta) = registry.control_metadata.get(actor) {
            control_groups
                .entry(meta.as_str())
                .or_default()
                .push(actor.clone());
        }
    }

    let suspicious_pair_capacity =
        independence_suspicious_pair_capacity(&control_groups, &clustered_dids)?;
    let mut suspicious_pairs: Vec<(Did, Did)> = Vec::with_capacity(suspicious_pair_capacity);
    for (meta, members) in &control_groups {
        if members.len() > 1 {
            for i in 0..members.len() {
                for j in (i + 1)..members.len() {
                    if !clustered_dids.contains(&members[i])
                        || !clustered_dids.contains(&members[j])
                    {
                        suspicious_pairs.push((members[i].clone(), members[j].clone()));
                    }
                }
            }
            clusters.push(Cluster {
                reason: format!("shared control metadata: {meta}"),
                members: members.clone(),
            });
            for m in members {
                clustered_dids.insert(m.clone());
            }
        }
    }

    let actor_set: BTreeSet<Did> = actors.iter().cloned().collect();
    let independent_count = actor_set.difference(&clustered_dids).count();

    Ok(IndependenceResult {
        independent_count,
        clusters,
        suspicious_pairs,
    })
}

/// Detect near-simultaneous identical actions by different actors as a coordination signal.
///
/// This compatibility entry point returns an explicit resource-denial signal
/// rather than an empty result when a finite budget is exceeded. Call
/// [`try_detect_coordination`] when the caller can propagate a typed error.
#[must_use]
pub fn detect_coordination(actions: &[TimestampedAction]) -> Vec<CoordinationSignal> {
    match try_detect_coordination(actions) {
        Ok(signals) => signals,
        Err(error) => vec![CoordinationSignal {
            actors: Vec::new(),
            reason: format!("coordination detection denied by resource limit: {error}"),
            confidence: 0,
        }],
    }
}

/// Detect coordination while returning typed resource-limit failures.
///
/// # Errors
///
/// Returns [`CrosscheckResourceLimitError`] before pair comparison or signal
/// insertion when a work or output budget is exceeded.
pub fn try_detect_coordination(
    actions: &[TimestampedAction],
) -> Result<Vec<CoordinationSignal>, CrosscheckResourceLimitError> {
    let pair_checks = coordination_pair_checks(actions.len())?;
    let mut signals = Vec::with_capacity(pair_checks.min(MAX_COORDINATION_SIGNALS));
    let threshold_ms: u64 = 100;

    for i in 0..actions.len() {
        for j in (i + 1)..actions.len() {
            if actions[i].actor == actions[j].actor {
                continue;
            }
            let t1 = actions[i].timestamp.physical_ms;
            let t2 = actions[j].timestamp.physical_ms;
            let diff = t1.abs_diff(t2);
            if diff <= threshold_ms && actions[i].action_hash == actions[j].action_hash {
                let next_signal_count = signals.len().checked_add(1).ok_or_else(|| {
                    resource_limit_error(
                        "coordination signals",
                        usize::MAX,
                        MAX_COORDINATION_SIGNALS,
                    )
                })?;
                ensure_resource_limit(
                    "coordination signals",
                    next_signal_count,
                    MAX_COORDINATION_SIGNALS,
                )?;
                signals.push(CoordinationSignal {
                    actors: vec![actions[i].actor.clone(), actions[j].actor.clone()],
                    reason: format!("near-simultaneous identical actions ({diff}ms apart)"),
                    confidence: 80,
                });
            }
        }
    }
    Ok(signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("valid test DID")
    }

    fn distinct_actions(count: usize) -> Vec<TimestampedAction> {
        (0..count)
            .map(|index| {
                let mut action_hash = [0_u8; 32];
                action_hash[..8].copy_from_slice(
                    &u64::try_from(index)
                        .expect("test index fits u64")
                        .to_be_bytes(),
                );
                TimestampedAction {
                    actor: did(&format!("actor-{index}")),
                    action_hash,
                    timestamp: Timestamp::new(1_000, 0),
                }
            })
            .collect()
    }

    fn matching_action_group(prefix: &str, count: usize, hash_byte: u8) -> Vec<TimestampedAction> {
        (0..count)
            .map(|index| TimestampedAction {
                actor: did(&format!("{prefix}-{index}")),
                action_hash: [hash_byte; 32],
                timestamp: Timestamp::new(1_000, 0),
            })
            .collect()
    }

    fn shared_control_group(
        prefix: &str,
        count: usize,
        metadata: &str,
    ) -> (Vec<Did>, IdentityRegistry) {
        let actors: Vec<Did> = (0..count)
            .map(|index| did(&format!("{prefix}-{index}")))
            .collect();
        let mut registry = IdentityRegistry::default();
        for actor in &actors {
            registry
                .control_metadata
                .insert(actor.clone(), metadata.to_owned());
        }
        (actors, registry)
    }

    #[test]
    fn truly_independent_actors_pass() {
        let mut reg = IdentityRegistry::default();
        reg.signing_keys.insert(did("alice"), "key_a".into());
        reg.signing_keys.insert(did("bob"), "key_b".into());
        reg.signing_keys.insert(did("carol"), "key_c".into());
        let r = verify_independence(&[did("alice"), did("bob"), did("carol")], &reg);
        assert_eq!(r.independent_count, 3);
        assert!(r.clusters.is_empty());
    }

    #[test]
    fn same_key_actors_fail() {
        let mut reg = IdentityRegistry::default();
        reg.signing_keys.insert(did("alice"), "shared".into());
        reg.signing_keys.insert(did("bob"), "shared".into());
        reg.signing_keys.insert(did("carol"), "key_c".into());
        let r = verify_independence(&[did("alice"), did("bob"), did("carol")], &reg);
        assert_eq!(r.independent_count, 1);
        assert!(
            r.clusters
                .iter()
                .any(|c| c.reason.contains("shared signing key"))
        );
    }

    #[test]
    fn coordinated_actors_fail_attestation_check() {
        let mut reg = IdentityRegistry::default();
        reg.signing_keys.insert(did("alice"), "key_a".into());
        reg.signing_keys.insert(did("bob"), "key_b".into());
        reg.attestation_roots.insert(did("alice"), did("mallory"));
        reg.attestation_roots.insert(did("bob"), did("mallory"));
        let r = verify_independence(&[did("alice"), did("bob")], &reg);
        assert_eq!(r.independent_count, 0);
    }

    #[test]
    fn shared_control_metadata_detected() {
        let mut reg = IdentityRegistry::default();
        reg.signing_keys.insert(did("alice"), "key_a".into());
        reg.signing_keys.insert(did("bob"), "key_b".into());
        reg.control_metadata.insert(did("alice"), "org:acme".into());
        reg.control_metadata.insert(did("bob"), "org:acme".into());
        let r = verify_independence(&[did("alice"), did("bob")], &reg);
        assert!(
            r.clusters
                .iter()
                .any(|c| c.reason.contains("shared control metadata"))
        );
    }

    #[test]
    fn detect_coordination_near_simultaneous() {
        let hash = [0u8; 32];
        let actions = vec![
            TimestampedAction {
                actor: did("alice"),
                action_hash: hash,
                timestamp: Timestamp::new(1000, 0),
            },
            TimestampedAction {
                actor: did("bob"),
                action_hash: hash,
                timestamp: Timestamp::new(1050, 0),
            },
        ];
        let signals = detect_coordination(&actions);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].reason.contains("near-simultaneous"));
    }

    #[test]
    fn detect_coordination_no_signal_for_distant_actions() {
        let hash = [0u8; 32];
        let actions = vec![
            TimestampedAction {
                actor: did("alice"),
                action_hash: hash,
                timestamp: Timestamp::new(1000, 0),
            },
            TimestampedAction {
                actor: did("bob"),
                action_hash: hash,
                timestamp: Timestamp::new(5000, 0),
            },
        ];
        assert!(detect_coordination(&actions).is_empty());
    }

    #[test]
    fn detect_coordination_ignores_same_actor() {
        let hash = [0u8; 32];
        let actions = vec![
            TimestampedAction {
                actor: did("alice"),
                action_hash: hash,
                timestamp: Timestamp::new(1000, 0),
            },
            TimestampedAction {
                actor: did("alice"),
                action_hash: hash,
                timestamp: Timestamp::new(1010, 0),
            },
        ];
        assert!(detect_coordination(&actions).is_empty());
    }

    #[test]
    fn detect_coordination_different_actions_no_signal() {
        let actions = vec![
            TimestampedAction {
                actor: did("alice"),
                action_hash: [0u8; 32],
                timestamp: Timestamp::new(1000, 0),
            },
            TimestampedAction {
                actor: did("bob"),
                action_hash: [1u8; 32],
                timestamp: Timestamp::new(1010, 0),
            },
        ];
        assert!(detect_coordination(&actions).is_empty());
    }

    #[test]
    fn empty_actors_returns_zero() {
        let r = verify_independence(&[], &IdentityRegistry::default());
        assert_eq!(r.independent_count, 0);
    }

    #[test]
    fn single_actor_is_independent() {
        let mut reg = IdentityRegistry::default();
        reg.signing_keys.insert(did("alice"), "key_a".into());
        assert_eq!(
            verify_independence(&[did("alice")], &reg).independent_count,
            1
        );
    }

    #[test]
    fn empty_actions() {
        assert!(detect_coordination(&[]).is_empty());
    }

    #[test]
    fn coordination_pair_budget_accepts_exact_limit_and_rejects_limit_plus_one() {
        let at_limit = distinct_actions(362);
        assert_eq!(
            coordination_pair_checks(at_limit.len()).expect("checked exact pair count"),
            MAX_COORDINATION_PAIR_CHECKS
        );
        assert!(
            try_detect_coordination(&at_limit)
                .expect("65,341 pair checks are accepted")
                .is_empty()
        );

        let over_limit = distinct_actions(363);
        let error = try_detect_coordination(&over_limit)
            .expect_err("65,341 pair checks plus the next action must fail before comparison");
        let CrosscheckResourceLimitError {
            resource,
            observed,
            maximum,
        } = error;
        assert_eq!(resource, "coordination pair checks");
        assert_eq!(observed, 65_703);
        assert_eq!(maximum, MAX_COORDINATION_PAIR_CHECKS);

        let legacy_result = detect_coordination(&over_limit);
        assert_eq!(legacy_result.len(), 1);
        assert!(legacy_result[0].actors.is_empty());
        assert!(legacy_result[0].reason.contains("resource limit"));
        assert_eq!(legacy_result[0].confidence, 0);
    }

    #[test]
    fn coordination_legacy_and_fallible_signatures_are_stable() {
        let legacy: fn(&[TimestampedAction]) -> Vec<CoordinationSignal> = detect_coordination;
        let fallible: fn(
            &[TimestampedAction],
        ) -> Result<Vec<CoordinationSignal>, CrosscheckResourceLimitError> =
            try_detect_coordination;
        let _ = (legacy, fallible);
    }

    #[test]
    fn coordination_signal_budget_accepts_exact_limit_and_rejects_next_signal() {
        let mut exact = matching_action_group("exact-large", 91, 0x11);
        exact.extend(matching_action_group("exact-pair", 2, 0x22));
        assert_eq!(
            try_detect_coordination(&exact)
                .expect("4,096 signals are accepted")
                .len(),
            MAX_COORDINATION_SIGNALS
        );

        let mut over = matching_action_group("over-large", 91, 0x33);
        over.extend(matching_action_group("over-triple", 3, 0x44));
        let error = try_detect_coordination(&over)
            .expect_err("the 4,097th signal must fail before allocation or push");
        let CrosscheckResourceLimitError {
            resource,
            observed,
            maximum,
        } = error;
        assert_eq!(resource, "coordination signals");
        assert_eq!(observed, 4_097);
        assert_eq!(maximum, MAX_COORDINATION_SIGNALS);
    }

    #[test]
    fn independence_suspicious_pair_output_is_bounded_and_legacy_api_fails_closed() {
        let (mut exact_actors, mut exact_registry) =
            shared_control_group("exact-large", 91, "group-a");
        let (exact_pair, pair_registry) = shared_control_group("exact-pair", 2, "group-b");
        exact_actors.extend(exact_pair);
        exact_registry
            .control_metadata
            .extend(pair_registry.control_metadata);
        assert_eq!(
            try_verify_independence(&exact_actors, &exact_registry)
                .expect("4,096 suspicious pairs are accepted")
                .suspicious_pairs
                .len(),
            MAX_INDEPENDENCE_SUSPICIOUS_PAIRS
        );

        let (mut over_actors, mut over_registry) =
            shared_control_group("over-large", 91, "group-a");
        let (over_pair_a, pair_a_registry) = shared_control_group("over-pair-a", 2, "group-b");
        let (over_pair_b, pair_b_registry) = shared_control_group("over-pair-b", 2, "group-c");
        over_actors.extend(over_pair_a);
        over_actors.extend(over_pair_b);
        over_registry
            .control_metadata
            .extend(pair_a_registry.control_metadata);
        over_registry
            .control_metadata
            .extend(pair_b_registry.control_metadata);
        let error = try_verify_independence(&over_actors, &over_registry)
            .expect_err("the 4,097th suspicious pair exceeds the output budget");
        let CrosscheckResourceLimitError {
            resource,
            observed,
            maximum,
        } = error;
        assert_eq!(resource, "independence suspicious pairs");
        assert_eq!(observed, 4_097);
        assert_eq!(maximum, MAX_INDEPENDENCE_SUSPICIOUS_PAIRS);

        let legacy_result = verify_independence(&over_actors, &over_registry);
        assert_eq!(legacy_result.independent_count, 0);
        assert!(legacy_result.suspicious_pairs.is_empty());
        assert!(
            legacy_result
                .clusters
                .iter()
                .any(|cluster| cluster.reason.contains("resource limit"))
        );
    }

    #[test]
    fn independence_actor_work_is_bounded_before_group_construction() {
        let at_limit: Vec<Did> = (0..MAX_INDEPENDENCE_ACTORS)
            .map(|index| did(&format!("bounded-{index}")))
            .collect();
        assert_eq!(
            try_verify_independence(&at_limit, &IdentityRegistry::default())
                .expect("actor limit is accepted")
                .independent_count,
            MAX_INDEPENDENCE_ACTORS
        );

        let mut over_limit = at_limit;
        over_limit.push(did("bounded-over"));
        let error = try_verify_independence(&over_limit, &IdentityRegistry::default())
            .expect_err("actor limit plus one must fail before group allocation");
        let CrosscheckResourceLimitError {
            resource,
            observed,
            maximum,
        } = error;
        assert_eq!(resource, "independence actors");
        assert_eq!(observed, MAX_INDEPENDENCE_ACTORS + 1);
        assert_eq!(maximum, MAX_INDEPENDENCE_ACTORS);
    }
}
