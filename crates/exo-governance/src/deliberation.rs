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

//! Deliberation process — structured decision-making with quorum-backed closure.

use exo_core::{Did, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::GovernanceError,
    quorum::{
        Approval, ApprovalScope, IndependenceAttestation, PublicKeyResolver, QuorumPolicy,
        QuorumResult, Role, compute_quorum_verified,
    },
};

/// A participant's stance on a deliberation proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Position {
    For,
    Against,
    Abstain,
}

impl Position {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Position::For => "For",
            Position::Against => "Against",
            Position::Abstain => "Abstain",
        }
    }
}

/// A signed vote cast by a participant in a deliberation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter_did: Did,
    pub position: Position,
    #[serde(default = "default_vote_role")]
    pub role: Role,
    pub reasoning_hash: [u8; 32],
    pub signature: Signature,
    #[serde(default)]
    pub independence_attestation: Option<IndependenceAttestation>,
}

fn default_vote_role() -> Role {
    Role::Contributor
}

/// Lifecycle state of a deliberation: Open, Closed, or Cancelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliberationStatus {
    Open,
    Closed,
    Cancelled,
}

impl DeliberationStatus {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            DeliberationStatus::Open => "Open",
            DeliberationStatus::Closed => "Closed",
            DeliberationStatus::Cancelled => "Cancelled",
        }
    }
}

/// A structured governance deliberation over a hashed proposal with tracked votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deliberation {
    pub id: Uuid,
    pub proposal_hash: [u8; 32],
    pub participants: Vec<Did>,
    pub votes: Vec<Vote>,
    pub status: DeliberationStatus,
    pub created: Timestamp,
}

/// Outcome of closing a deliberation: approved, rejected, or quorum not met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliberationResult {
    Approved {
        votes_for: usize,
        votes_against: usize,
        abstentions: usize,
    },
    Rejected {
        votes_for: usize,
        votes_against: usize,
        abstentions: usize,
    },
    NoQuorum {
        reason: String,
    },
}

/// Open a new deliberation for the given proposal bytes and participant list.
pub fn open_deliberation(
    id: Uuid,
    created: Timestamp,
    proposal: &[u8],
    participants: &[Did],
) -> Result<Deliberation, GovernanceError> {
    if id.is_nil() {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "deliberation.id".into(),
            reason: "must be caller-supplied and non-nil".into(),
        });
    }
    if created == Timestamp::ZERO {
        return Err(GovernanceError::InvalidGovernanceMetadata {
            field: "deliberation.created".into(),
            reason: "must be caller-supplied and non-zero".into(),
        });
    }

    Ok(Deliberation {
        id,
        proposal_hash: *blake3::hash(proposal).as_bytes(),
        participants: participants.to_vec(),
        votes: Vec::new(),
        status: DeliberationStatus::Open,
        created,
    })
}

/// Record a vote in an open deliberation, rejecting duplicates and closed sessions.
pub fn cast_vote(delib: &mut Deliberation, vote: Vote) -> Result<(), GovernanceError> {
    if delib.status != DeliberationStatus::Open {
        return Err(GovernanceError::DeliberationNotOpen);
    }
    if !delib
        .participants
        .iter()
        .any(|participant| participant == &vote.voter_did)
    {
        return Err(GovernanceError::ConstitutionalViolation {
            constraint_id: "deliberation.participant_membership".into(),
            reason: format!("{} is not a deliberation participant", vote.voter_did),
        });
    }
    if delib.votes.iter().any(|v| v.voter_did == vote.voter_did) {
        return Err(GovernanceError::DuplicateVote(vote.voter_did.to_string()));
    }
    delib.votes.push(vote);
    Ok(())
}

fn not_open_result(delib: &Deliberation) -> Option<DeliberationResult> {
    if delib.status == DeliberationStatus::Open {
        None
    } else {
        Some(DeliberationResult::NoQuorum {
            reason: format!("deliberation not open: {}", delib.status.as_str()),
        })
    }
}

fn tally_votes(delib: &Deliberation) -> (usize, usize, usize) {
    let votes_for = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::For)
        .count();
    let votes_against = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::Against)
        .count();
    let abstentions = delib
        .votes
        .iter()
        .filter(|v| v.position == Position::Abstain)
        .count();
    (votes_for, votes_against, abstentions)
}

fn approvals_from_for_votes(delib: &Deliberation) -> Vec<Approval> {
    delib
        .votes
        .iter()
        .filter(|v| v.position == Position::For)
        .map(|v| Approval {
            approver_did: v.voter_did.clone(),
            role: v.role.clone(),
            timestamp: delib.created,
            signature: v.signature.clone(),
            independence_attestation: v.independence_attestation.clone(),
            scope: Some(ApprovalScope::DeliberationVote {
                deliberation_id: delib.id,
                proposal_hash: delib.proposal_hash,
                position: v.position.as_str().to_string(),
                reasoning_hash: v.reasoning_hash,
            }),
        })
        .collect()
}

fn result_from_quorum(
    quorum_result: QuorumResult,
    votes_for: usize,
    votes_against: usize,
    abstentions: usize,
) -> DeliberationResult {
    match quorum_result {
        QuorumResult::Met { .. } => {
            if votes_for > votes_against {
                DeliberationResult::Approved {
                    votes_for,
                    votes_against,
                    abstentions,
                }
            } else {
                DeliberationResult::Rejected {
                    votes_for,
                    votes_against,
                    abstentions,
                }
            }
        }
        QuorumResult::NotMet { reason } => DeliberationResult::NoQuorum { reason },
        QuorumResult::Contested { challenge } => DeliberationResult::NoQuorum {
            reason: format!("contested: {challenge}"),
        },
    }
}

/// Close a deliberation with structural quorum checks for legacy unit tests.
#[cfg(test)]
fn close(delib: &mut Deliberation, quorum_policy: &QuorumPolicy) -> DeliberationResult {
    use crate::quorum::compute_quorum;

    if let Some(result) = not_open_result(delib) {
        return result;
    }

    let (votes_for, votes_against, abstentions) = tally_votes(delib);
    let approvals = approvals_from_for_votes(delib);
    let quorum_result = compute_quorum(&approvals, quorum_policy);
    delib.status = DeliberationStatus::Closed;
    result_from_quorum(quorum_result, votes_for, votes_against, abstentions)
}

/// Close a deliberation using cryptographically verified approval and independence evidence.
///
/// `Vote.signature` must be a signature over the canonical quorum
/// [`Approval::signing_payload`] produced from the vote's DID, role, created
/// timestamp, and independence attestation. This keeps deliberation closure on
/// the same verified quorum path as direct quorum computation.
pub fn close_verified<R: PublicKeyResolver>(
    delib: &mut Deliberation,
    quorum_policy: &QuorumPolicy,
    resolver: &R,
) -> DeliberationResult {
    if let Some(result) = not_open_result(delib) {
        return result;
    }

    let (votes_for, votes_against, abstentions) = tally_votes(delib);
    let approvals = approvals_from_for_votes(delib);
    let quorum_result = compute_quorum_verified(&approvals, quorum_policy, resolver);
    delib.status = DeliberationStatus::Closed;
    result_from_quorum(quorum_result, votes_for, votes_against, abstentions)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::crypto;

    use super::*;

    fn test_sig() -> Signature {
        let (_, sk) = crypto::generate_keypair();
        crypto::sign(b"vote", &sk)
    }
    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("ok")
    }

    fn delib_id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn open(proposal: &[u8], participants: &[Did]) -> Deliberation {
        open_with_id(0xD001, proposal, participants)
    }

    fn open_with_id(id: u128, proposal: &[u8], participants: &[Did]) -> Deliberation {
        open_deliberation(delib_id(id), ts(10_000), proposal, participants)
            .expect("deterministic deliberation")
    }

    #[test]
    fn production_deliberation_closure_uses_verified_quorum_only() {
        let source = include_str!("deliberation.rs");
        let before_tests = source
            .split("#[cfg(test)]\n#[allow")
            .next()
            .expect("non-test source section");
        let close_verified = before_tests
            .split("pub fn close_verified")
            .nth(1)
            .expect("close_verified source")
            .split("#[cfg(test)]")
            .next()
            .expect("close_verified source end");

        assert!(
            before_tests.contains("pub fn close_verified"),
            "production deliberation closure must expose the verified quorum path"
        );
        assert!(
            !before_tests.contains("pub fn close("),
            "structural deliberation close must not be exposed in production builds"
        );
        assert!(
            before_tests.contains("#[cfg(test)]\nfn close("),
            "structural deliberation close may exist only as a test-only helper"
        );
        assert!(
            !close_verified.contains("compute_quorum(&approvals"),
            "production deliberation closure must not call structural quorum"
        );
        assert!(
            before_tests.contains("ApprovalScope::DeliberationVote"),
            "production deliberation approvals must bind signatures to deliberation context"
        );
    }

    fn vote(name: &str, pos: Position) -> Vote {
        Vote {
            voter_did: did(name),
            position: pos,
            role: Role::Contributor,
            reasoning_hash: [0u8; 32],
            signature: test_sig(),
            independence_attestation: Some(IndependenceAttestation {
                attester_did: did(name),
                no_common_control: true,
                no_coordination: true,
                identity_verified: true,
                signature: test_sig(),
            }),
        }
    }

    fn keypair(seed: u8) -> crypto::KeyPair {
        crypto::KeyPair::from_secret_bytes([seed; 32]).expect("deterministic test key")
    }

    struct TestDeliberationResolver {
        keys: BTreeMap<Did, exo_core::PublicKey>,
        roles: BTreeMap<Did, Role>,
    }

    impl PublicKeyResolver for TestDeliberationResolver {
        fn resolve(&self, did: &Did) -> Option<exo_core::PublicKey> {
            self.keys.get(did).copied()
        }

        fn resolve_trusted_role(&self, did: &Did) -> Option<Role> {
            self.roles.get(did).cloned()
        }
    }

    fn resolver(keys: &BTreeMap<Did, exo_core::PublicKey>) -> TestDeliberationResolver {
        let roles = keys
            .keys()
            .map(|did| (did.clone(), Role::Contributor))
            .collect();
        TestDeliberationResolver {
            keys: keys.clone(),
            roles,
        }
    }

    fn resolver_with_roles(
        keys: &BTreeMap<Did, exo_core::PublicKey>,
        roles: Vec<(Did, Role)>,
    ) -> TestDeliberationResolver {
        TestDeliberationResolver {
            keys: keys.clone(),
            roles: roles.into_iter().collect(),
        }
    }

    fn signed_attestation(name: &str, keypair: &crypto::KeyPair) -> IndependenceAttestation {
        let mut attestation = IndependenceAttestation {
            attester_did: did(name),
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: Signature::Empty,
        };
        let payload = attestation
            .signing_payload()
            .expect("attestation payload encodes");
        attestation.signature = keypair.sign(&payload);
        attestation
    }

    fn signed_vote_for_deliberation(
        delib: &Deliberation,
        name: &str,
        pos: Position,
        role: Role,
        keypair: &crypto::KeyPair,
    ) -> Vote {
        let attestation = signed_attestation(name, keypair);
        let mut approval = Approval {
            approver_did: did(name),
            role: role.clone(),
            timestamp: delib.created,
            signature: Signature::Empty,
            independence_attestation: Some(attestation.clone()),
            scope: Some(ApprovalScope::DeliberationVote {
                deliberation_id: delib.id,
                proposal_hash: delib.proposal_hash,
                position: pos.as_str().to_string(),
                reasoning_hash: [0u8; 32],
            }),
        };
        let payload = approval
            .signing_payload()
            .expect("approval payload encodes");
        approval.signature = keypair.sign(&payload);

        Vote {
            voter_did: did(name),
            position: pos,
            role,
            reasoning_hash: [0u8; 32],
            signature: approval.signature,
            independence_attestation: Some(attestation),
        }
    }

    #[test]
    fn deliberation_status_messages_do_not_depend_on_debug_formatting() {
        let source = include_str!("deliberation.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(
            !source.contains("deliberation not open: {:?}"),
            "deliberation status messages must use stable labels"
        );
    }

    fn policy(min: usize) -> QuorumPolicy {
        QuorumPolicy {
            min_approvals: min,
            min_independent: min,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        }
    }

    fn open_deliberation_source() -> &'static str {
        let source = include_str!("deliberation.rs");
        let start = source
            .find("pub fn open_deliberation(")
            .expect("open_deliberation source must exist");
        let end = source[start..]
            .find("/// Record a vote")
            .expect("cast vote marker must exist");
        &source[start..start + end]
    }

    #[test]
    fn open_deliberation_has_no_internal_entropy_or_wall_clock() {
        let source = open_deliberation_source();
        assert!(
            !source.contains("Uuid::new_v4"),
            "governance deliberations must not fabricate UUIDs internally"
        );
        let forbidden_timestamp = ["Timestamp::", "now_utc"].concat();
        assert!(
            !source.contains(&forbidden_timestamp),
            "governance deliberations must not read wall-clock time internally"
        );
    }

    #[test]
    fn open_creates_open_status() {
        let id = delib_id(0xD010);
        let created = ts(10_010);
        let d = open_deliberation(id, created, b"proposal", &[did("alice"), did("bob")])
            .expect("deterministic deliberation");
        assert_eq!(d.id, id);
        assert_eq!(d.created, created);
        assert_eq!(d.status, DeliberationStatus::Open);
        assert_eq!(d.participants.len(), 2);
        assert!(d.votes.is_empty());
    }
    #[test]
    fn open_rejects_nil_id() {
        let err = open_deliberation(Uuid::nil(), ts(10_011), b"proposal", &[did("alice")])
            .expect_err("nil deliberation id must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }
    #[test]
    fn open_rejects_zero_created_timestamp() {
        let err = open_deliberation(
            delib_id(0xD011),
            Timestamp::ZERO,
            b"proposal",
            &[did("alice")],
        )
        .expect_err("zero deliberation timestamp must be rejected");

        assert!(matches!(
            err,
            GovernanceError::InvalidGovernanceMetadata { .. }
        ));
    }
    #[test]
    fn cast_vote_succeeds() {
        let mut d = open(b"p", &[did("alice")]);
        assert!(cast_vote(&mut d, vote("alice", Position::For)).is_ok());
        assert_eq!(d.votes.len(), 1);
    }
    #[test]
    fn cast_vote_rejects_non_participant() {
        let mut d = open(b"p", &[did("alice")]);
        assert!(
            cast_vote(&mut d, vote("mallory", Position::For)).is_err(),
            "only declared deliberation participants may vote"
        );
        assert!(d.votes.is_empty());
    }
    #[test]
    fn duplicate_vote_rejected() {
        let mut d = open(b"p", &[did("alice")]);
        cast_vote(&mut d, vote("alice", Position::For)).unwrap();
        assert!(matches!(
            cast_vote(&mut d, vote("alice", Position::Against)).unwrap_err(),
            GovernanceError::DuplicateVote(_)
        ));
    }
    #[test]
    fn vote_on_closed_rejected() {
        let mut d = open(b"p", &[did("alice")]);
        d.status = DeliberationStatus::Closed;
        assert!(matches!(
            cast_vote(&mut d, vote("alice", Position::For)).unwrap_err(),
            GovernanceError::DeliberationNotOpen
        ));
    }
    #[test]
    fn close_approved() {
        let key_a = keypair(1);
        let key_b = keypair(2);
        let mut keys = BTreeMap::new();
        keys.insert(did("a"), *key_a.public_key());
        keys.insert(did("b"), *key_b.public_key());

        let mut d = open(b"p", &[did("a"), did("b"), did("c")]);
        let vote_a =
            signed_vote_for_deliberation(&d, "a", Position::For, Role::Contributor, &key_a);
        let vote_b =
            signed_vote_for_deliberation(&d, "b", Position::For, Role::Contributor, &key_b);
        cast_vote(&mut d, vote_a).unwrap();
        cast_vote(&mut d, vote_b).unwrap();
        cast_vote(&mut d, vote("c", Position::Against)).unwrap();
        assert!(matches!(
            close_verified(&mut d, &policy(2), &resolver(&keys)),
            DeliberationResult::Approved {
                votes_for: 2,
                votes_against: 1,
                abstentions: 0
            }
        ));
    }
    #[test]
    fn close_rejected() {
        let key_a = keypair(1);
        let mut keys = BTreeMap::new();
        keys.insert(did("a"), *key_a.public_key());

        let mut d = open(b"p", &[did("a"), did("b"), did("c")]);
        let vote_a =
            signed_vote_for_deliberation(&d, "a", Position::For, Role::Contributor, &key_a);
        cast_vote(&mut d, vote_a).unwrap();
        cast_vote(&mut d, vote("b", Position::Against)).unwrap();
        cast_vote(&mut d, vote("c", Position::Against)).unwrap();
        assert!(matches!(
            close_verified(&mut d, &policy(1), &resolver(&keys)),
            DeliberationResult::Rejected { .. }
        ));
    }
    #[test]
    fn close_no_quorum() {
        let mut d = open(b"p", &[did("a")]);
        cast_vote(&mut d, vote("a", Position::For)).unwrap();
        assert!(matches!(
            close(&mut d, &policy(3)),
            DeliberationResult::NoQuorum { .. }
        ));
    }
    #[test]
    fn abstentions_counted() {
        let key_a = keypair(1);
        let key_b = keypair(2);
        let mut keys = BTreeMap::new();
        keys.insert(did("a"), *key_a.public_key());
        keys.insert(did("b"), *key_b.public_key());

        let mut d = open(b"p", &[did("a"), did("b"), did("c")]);
        let vote_a =
            signed_vote_for_deliberation(&d, "a", Position::For, Role::Contributor, &key_a);
        let vote_b =
            signed_vote_for_deliberation(&d, "b", Position::For, Role::Contributor, &key_b);
        cast_vote(&mut d, vote_a).unwrap();
        cast_vote(&mut d, vote_b).unwrap();
        cast_vote(&mut d, vote("c", Position::Abstain)).unwrap();
        assert!(matches!(
            close_verified(&mut d, &policy(2), &resolver(&keys)),
            DeliberationResult::Approved {
                votes_for: 2,
                votes_against: 0,
                abstentions: 1
            }
        ));
    }
    #[test]
    fn close_uses_vote_role_for_required_roles() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let mut d = open(b"p", &[did("alice")]);
        let vote_alice =
            signed_vote_for_deliberation(&d, "alice", Position::For, Role::Steward, &alice_key);
        cast_vote(&mut d, vote_alice).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        assert!(matches!(
            close_verified(
                &mut d,
                &quorum_policy,
                &resolver_with_roles(&keys, vec![(did("alice"), Role::Steward)])
            ),
            DeliberationResult::Approved {
                votes_for: 1,
                votes_against: 0,
                abstentions: 0
            }
        ));
    }

    #[test]
    fn close_verified_rejects_required_role_without_trusted_role_resolution() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let mut d = open(b"p", &[did("alice")]);
        let vote_alice =
            signed_vote_for_deliberation(&d, "alice", Position::For, Role::Steward, &alice_key);
        cast_vote(&mut d, vote_alice).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        let key_only_resolver = |did: &Did| keys.get(did).copied();
        match close_verified(&mut d, &quorum_policy, &key_only_resolver) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(
                    reason.contains("trusted role"),
                    "deliberation required roles must fail closed without trusted role resolution: {reason}"
                );
            }
            other => panic!(
                "self-asserted deliberation role must not satisfy verified quorum: {other:?}"
            ),
        }
    }

    #[test]
    fn close_verified_rejects_forged_vote_signature() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let mut d = open(b"p", &[did("alice")]);
        let mut forged =
            signed_vote_for_deliberation(&d, "alice", Position::For, Role::Steward, &alice_key);
        forged.signature = test_sig();
        cast_vote(&mut d, forged).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match close_verified(
            &mut d,
            &quorum_policy,
            &resolver_with_roles(&keys, vec![(did("alice"), Role::Steward)]),
        ) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(reason.contains("verified"));
            }
            other => panic!("forged vote must not close deliberation: {other:?}"),
        }
    }

    #[test]
    fn close_without_resolver_fails_closed_for_unverified_quorum() {
        let alice_key = keypair(1);
        let mut d = open(b"p", &[did("alice")]);
        let mut forged =
            signed_vote_for_deliberation(&d, "alice", Position::For, Role::Steward, &alice_key);
        forged.signature = test_sig();
        cast_vote(&mut d, forged).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match close(&mut d, &quorum_policy) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(reason.contains("verified quorum"));
            }
            other => panic!("structural close must not approve without verification: {other:?}"),
        }
    }

    #[test]
    fn close_verified_accepts_distinct_valid_steward_vote() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let mut d = open(b"p", &[did("alice")]);
        let vote_alice =
            signed_vote_for_deliberation(&d, "alice", Position::For, Role::Steward, &alice_key);
        cast_vote(&mut d, vote_alice).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        assert!(matches!(
            close_verified(
                &mut d,
                &quorum_policy,
                &resolver_with_roles(&keys, vec![(did("alice"), Role::Steward)])
            ),
            DeliberationResult::Approved {
                votes_for: 1,
                votes_against: 0,
                abstentions: 0
            }
        ));
    }

    #[test]
    fn close_verified_rejects_vote_signature_replayed_to_other_deliberation() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let source = open_with_id(0xD210, b"proposal-a", &[did("alice")]);
        let mut replay_target = open_deliberation(
            delib_id(0xD211),
            source.created,
            b"proposal-b",
            &[did("alice")],
        )
        .expect("deterministic target deliberation");
        let vote_signed_for_source = signed_vote_for_deliberation(
            &source,
            "alice",
            Position::For,
            Role::Steward,
            &alice_key,
        );

        cast_vote(&mut replay_target, vote_signed_for_source).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match close_verified(
            &mut replay_target,
            &quorum_policy,
            &resolver_with_roles(&keys, vec![(did("alice"), Role::Steward)]),
        ) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(
                    reason.contains("verified"),
                    "replayed deliberation vote signatures must fail verified quorum"
                );
            }
            other => panic!("replayed vote must not close another deliberation: {other:?}"),
        }
    }

    #[test]
    fn close_verified_rejects_vote_signature_replayed_to_other_position() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let mut d = open(b"p", &[did("alice")]);
        let mut vote_alice =
            signed_vote_for_deliberation(&d, "alice", Position::Against, Role::Steward, &alice_key);
        vote_alice.position = Position::For;
        cast_vote(&mut d, vote_alice).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match close_verified(
            &mut d,
            &quorum_policy,
            &resolver_with_roles(&keys, vec![(did("alice"), Role::Steward)]),
        ) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(
                    reason.contains("verified"),
                    "vote position changes must invalidate scoped signatures"
                );
            }
            other => panic!("position-replayed vote must not close deliberation: {other:?}"),
        }
    }

    #[test]
    fn close_verified_rejects_vote_signature_replayed_to_other_reasoning_hash() {
        let alice_key = keypair(1);
        let alice = did("alice");
        let mut keys = BTreeMap::new();
        keys.insert(alice, *alice_key.public_key());

        let mut d = open(b"p", &[did("alice")]);
        let mut vote_alice =
            signed_vote_for_deliberation(&d, "alice", Position::For, Role::Steward, &alice_key);
        vote_alice.reasoning_hash = [7u8; 32];
        cast_vote(&mut d, vote_alice).unwrap();

        let quorum_policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match close_verified(
            &mut d,
            &quorum_policy,
            &resolver_with_roles(&keys, vec![(did("alice"), Role::Steward)]),
        ) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(
                    reason.contains("verified"),
                    "reasoning-hash changes must invalidate scoped signatures"
                );
            }
            other => panic!("reasoning-replayed vote must not close deliberation: {other:?}"),
        }
    }
    #[test]
    fn close_does_not_overwrite_cancelled_deliberation() {
        let mut d = open(b"p", &[did("a")]);
        d.status = DeliberationStatus::Cancelled;

        match close(&mut d, &policy(0)) {
            DeliberationResult::NoQuorum { reason } => {
                assert!(reason.contains("not open"));
            }
            other => panic!("cancelled deliberation must not close: {other:?}"),
        }
        assert_eq!(d.status, DeliberationStatus::Cancelled);
    }
    #[test]
    fn cancelled_rejects_votes() {
        let mut d = open(b"p", &[did("a")]);
        d.status = DeliberationStatus::Cancelled;
        assert!(cast_vote(&mut d, vote("a", Position::For)).is_err());
    }
    #[test]
    fn proposal_hash_deterministic() {
        let d1 = open_with_id(0xD101, b"same", &[]);
        let d2 = open_with_id(0xD102, b"same", &[]);
        assert_eq!(d1.proposal_hash, d2.proposal_hash);
        assert_ne!(
            d1.proposal_hash,
            open_with_id(0xD103, b"diff", &[]).proposal_hash
        );
    }
}
