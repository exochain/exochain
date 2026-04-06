//! Independence verification (anti-Sybil).

use std::collections::{HashMap, HashSet};

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

/// Registry of identity attributes used for Sybil detection and independence verification.
#[derive(Debug, Clone, Default)]
pub struct IdentityRegistry {
    pub signing_keys: HashMap<Did, String>,
    pub attestation_roots: HashMap<Did, Did>,
    pub control_metadata: HashMap<Did, String>,
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

/// Verify independence of actors by checking for shared keys, attestation roots, and control metadata.
#[must_use]
pub fn verify_independence(actors: &[Did], registry: &IdentityRegistry) -> IndependenceResult {
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut clustered_dids: HashSet<Did> = HashSet::new();
    let mut suspicious_pairs: Vec<(Did, Did)> = Vec::new();

    // Check 1: Same signing keys
    let mut key_groups: HashMap<&str, Vec<Did>> = HashMap::new();
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
    let mut root_groups: HashMap<Did, Vec<Did>> = HashMap::new();
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
    let mut control_groups: HashMap<&str, Vec<Did>> = HashMap::new();
    for actor in actors {
        if let Some(meta) = registry.control_metadata.get(actor) {
            control_groups
                .entry(meta.as_str())
                .or_default()
                .push(actor.clone());
        }
    }
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

    let actor_set: HashSet<Did> = actors.iter().cloned().collect();
    let independent_count = actor_set.difference(&clustered_dids).count();

    IndependenceResult {
        independent_count,
        clusters,
        suspicious_pairs,
    }
}

/// Detect near-simultaneous identical actions by different actors as a coordination signal.
#[must_use]
pub fn detect_coordination(actions: &[TimestampedAction]) -> Vec<CoordinationSignal> {
    let mut signals = Vec::new();
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
                signals.push(CoordinationSignal {
                    actors: vec![actions[i].actor.clone(), actions[j].actor.clone()],
                    reason: format!("near-simultaneous identical actions ({diff}ms apart)"),
                    confidence: 80,
                });
            }
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("valid test DID")
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
}
