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

//! Quorum computation with independence-aware counting.
//!
//! Constitutional principle: "Numerical multiplicity without attributable
//! independence is theater, not legitimacy."

use std::collections::BTreeSet;

use exo_core::{Did, PublicKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    challenge::{Challenge, ChallengeStatus},
    errors::GovernanceError,
};

/// Roles that can participate in governance actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Steward,
    Governor,
    Reviewer,
    Contributor,
    /// Read-only participant; may observe governance but cannot satisfy quorum.
    Observer,
}

impl Role {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Role::Steward => "Steward",
            Role::Governor => "Governor",
            Role::Reviewer => "Reviewer",
            Role::Contributor => "Contributor",
            Role::Observer => "Observer",
        }
    }
}

/// A signed declaration of independence — no common control, no coordination,
/// identity verified through independent channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceAttestation {
    pub attester_did: Did,
    pub no_common_control: bool,
    pub no_coordination: bool,
    pub identity_verified: bool,
    pub signature: Signature,
}

impl IndependenceAttestation {
    /// Structural check: all three independence declarations must be true.
    ///
    /// **Caveat:** this does NOT verify the attester's signature. Use
    /// [`Self::verify_signature`] for that, and prefer
    /// [`Self::is_fully_valid`] at call sites that need both structural
    /// truth *and* cryptographic proof of authorship.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.no_common_control && self.no_coordination && self.identity_verified
    }

    /// Canonical CBOR payload that the attester signs.
    ///
    /// Order is fixed: `attester_did` then the three booleans in
    /// declaration order. Any future field additions must append to this
    /// payload, not reorder it, to avoid breaking existing signatures.
    pub fn signing_payload(&self) -> Result<Vec<u8>, GovernanceError> {
        // We use explicit CBOR encoding of a tuple to stay canonical.
        // ciborium preserves struct/tuple ordering on serialize.
        let tuple = (
            &self.attester_did,
            self.no_common_control,
            self.no_coordination,
            self.identity_verified,
        );
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
            GovernanceError::Serialization(format!(
                "independence attestation canonical encoding failed: {e}"
            ))
        })?;
        Ok(buf)
    }

    /// Verify the attester's signature over the canonical payload.
    ///
    /// Returns `true` only if the signature on `signing_payload()` is
    /// valid under `public_key`. An empty or malformed signature returns
    /// `false`.
    #[must_use]
    pub fn verify_signature(&self, public_key: &PublicKey) -> bool {
        let Ok(payload) = self.signing_payload() else {
            return false;
        };
        // Empty signatures are an explicit "unsigned" sentinel and must not verify.
        if self.signature.is_empty() || self.signature.ed25519_component_is_zero() {
            return false;
        }
        crypto::verify(&payload, &self.signature, public_key)
    }

    /// Structural check **and** cryptographic signature verification.
    ///
    /// This is the method governance call sites should use. It requires
    /// the caller to supply the attester's public key so the signature
    /// can be bound to a real identity.
    #[must_use]
    pub fn is_fully_valid(&self, public_key: &PublicKey) -> bool {
        self.is_valid() && self.verify_signature(public_key)
    }
}

/// A single approval cast toward a quorum decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver_did: Did,
    pub role: Role,
    pub timestamp: Timestamp,
    pub signature: Signature,
    pub independence_attestation: Option<IndependenceAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ApprovalScope>,
}

/// Optional context that binds a quorum approval to one governed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalScope {
    DeliberationVote {
        deliberation_id: Uuid,
        proposal_hash: [u8; 32],
        position: String,
        reasoning_hash: [u8; 32],
    },
}

impl Approval {
    /// Canonical CBOR payload that the approver signs.
    ///
    /// The approval signature binds the approver, role, timestamp, attached
    /// independence attestation, and optional action scope. The `signature`
    /// field itself is excluded. Unscoped approvals retain the v1 payload for
    /// compatibility; scoped approvals use v2 so signatures cannot be replayed
    /// into a different governed action.
    pub fn signing_payload(&self) -> Result<Vec<u8>, GovernanceError> {
        let mut buf = Vec::new();
        if let Some(scope) = &self.scope {
            let tuple = (
                "exo.governance.quorum.approval.v2",
                &self.approver_did,
                &self.role,
                &self.timestamp,
                &self.independence_attestation,
                scope,
            );
            ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
                GovernanceError::Serialization(format!("approval canonical encoding failed: {e}"))
            })?;
        } else {
            let tuple = (
                "exo.governance.quorum.approval.v1",
                &self.approver_did,
                &self.role,
                &self.timestamp,
                &self.independence_attestation,
            );
            ciborium::ser::into_writer(&tuple, &mut buf).map_err(|e| {
                GovernanceError::Serialization(format!("approval canonical encoding failed: {e}"))
            })?;
        }
        Ok(buf)
    }

    /// Verify the approval signature over its canonical payload.
    #[must_use]
    pub fn verify_signature(&self, public_key: &PublicKey) -> bool {
        if self.signature.is_empty() || self.signature.ed25519_component_is_zero() {
            return false;
        }
        let Ok(payload) = self.signing_payload() else {
            return false;
        };
        crypto::verify(&payload, &self.signature, public_key)
    }
}

/// Policy defining what constitutes a valid quorum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumPolicy {
    pub min_approvals: usize,
    pub min_independent: usize,
    pub required_roles: Vec<Role>,
    pub timeout: Timestamp,
}

/// The result of a quorum computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumResult {
    Met {
        independent_count: usize,
        total_count: usize,
    },
    NotMet {
        reason: String,
    },
    Contested {
        challenge: String,
    },
}

fn duplicate_approver(approvals: &[Approval]) -> Option<Did> {
    let mut seen = BTreeSet::new();
    for approval in approvals {
        if !seen.insert(approval.approver_did.clone()) {
            return Some(approval.approver_did.clone());
        }
    }
    None
}

fn verified_quorum_required() -> QuorumResult {
    QuorumResult::NotMet {
        reason: "verified quorum required: use compute_quorum_verified with a PublicKeyResolver"
            .into(),
    }
}

fn invalid_quorum_policy(reason: impl Into<String>) -> QuorumResult {
    QuorumResult::NotMet {
        reason: format!("invalid quorum policy: {}", reason.into()),
    }
}

#[must_use]
fn role_counts_toward_quorum(role: &Role) -> bool {
    !matches!(role, Role::Observer)
}

fn validate_policy(policy: &QuorumPolicy) -> Option<QuorumResult> {
    if policy.min_approvals == 0 {
        return Some(invalid_quorum_policy(
            "min_approvals must be greater than zero",
        ));
    }
    if policy.min_independent > policy.min_approvals {
        return Some(invalid_quorum_policy(
            "min_independent must not exceed min_approvals",
        ));
    }
    if policy
        .required_roles
        .iter()
        .any(|role| !role_counts_toward_quorum(role))
    {
        return Some(invalid_quorum_policy(
            "Observer cannot be a required quorum role",
        ));
    }
    None
}

/// Perform only fail-closed structural quorum checks.
///
/// This legacy API can prove rejection conditions such as duplicates,
/// insufficient approval count, or missing required roles. It cannot prove
/// quorum success because it has no public-key resolver and therefore cannot
/// verify approval signatures or independence-attestation signatures. Use
/// [`compute_quorum_verified`] for any path that may approve a quorum.
#[must_use]
pub fn compute_quorum(approvals: &[Approval], policy: &QuorumPolicy) -> QuorumResult {
    if let Some(invalid) = validate_policy(policy) {
        return invalid;
    }

    if let Some(duplicate) = duplicate_approver(approvals) {
        return QuorumResult::NotMet {
            reason: format!("duplicate approver DID: {duplicate}"),
        };
    }

    let quorum_eligible_approvals: Vec<&Approval> = approvals
        .iter()
        .filter(|approval| role_counts_toward_quorum(&approval.role))
        .collect();

    let total_count = quorum_eligible_approvals.len();

    if total_count < policy.min_approvals {
        let has_non_quorum_role = approvals
            .iter()
            .any(|approval| !role_counts_toward_quorum(&approval.role));
        let reason = if has_non_quorum_role {
            format!(
                "insufficient approvals: {total_count} < {} quorum-eligible required (Observer cannot satisfy quorum)",
                policy.min_approvals
            )
        } else {
            format!(
                "insufficient approvals: {total_count} < {}",
                policy.min_approvals
            )
        };
        return QuorumResult::NotMet { reason };
    }

    for required_role in &policy.required_roles {
        if !quorum_eligible_approvals
            .iter()
            .any(|a| &a.role == required_role)
        {
            return QuorumResult::NotMet {
                reason: format!("missing required role: {}", required_role.as_str()),
            };
        }
    }

    if !approvals.is_empty() || policy.min_approvals > 0 || policy.min_independent > 0 {
        return verified_quorum_required();
    }

    let independent_count = quorum_eligible_approvals
        .iter()
        .filter(|a| {
            a.independence_attestation
                .as_ref()
                .is_some_and(|att| att.attester_did == a.approver_did && att.is_valid())
        })
        .count();

    if independent_count < policy.min_independent {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient independence: {independent_count} independent of {} required \
                 (numerical multiplicity without attributable independence is theater, not legitimacy)",
                policy.min_independent
            ),
        };
    }

    QuorumResult::Met {
        independent_count,
        total_count,
    }
}

/// Compute quorum with active-challenge guard.
///
/// If any challenge in `open_challenges` is still `Filed` or `UnderReview`,
/// the result is `Contested` — the unresolved independence challenge blocks
/// quorum achievement per CR-001 §8.4.  Only when all challenges are
/// resolved (Sustained, Overruled, or Withdrawn) does this delegate to the
/// standard `compute_quorum`.
#[must_use]
pub fn compute_quorum_with_challenges(
    approvals: &[Approval],
    policy: &QuorumPolicy,
    open_challenges: &[&Challenge],
) -> QuorumResult {
    if let Some(blocking) = open_challenges.iter().find(|c| {
        matches!(
            c.status,
            ChallengeStatus::Filed | ChallengeStatus::UnderReview
        )
    }) {
        return QuorumResult::Contested {
            challenge: format!(
                "unresolved independence challenge {} on ground {}",
                blocking.id,
                blocking.ground.as_str()
            ),
        };
    }
    compute_quorum(approvals, policy)
}

/// Resolve governance identity facts for quorum verification.
///
/// Governance call sites supply an implementation of this trait backed by
/// the authority chain or identity registry. A resolver that returns
/// `None` for a given DID causes `compute_quorum_verified` to treat any
/// approval, required role, or independence attestation from that DID as
/// unverifiable.
pub trait PublicKeyResolver {
    fn resolve(&self, did: &Did) -> Option<PublicKey>;

    fn resolve_trusted_role(&self, did: &Did) -> Option<Role> {
        let _ = did;
        None
    }
}

impl<F> PublicKeyResolver for F
where
    F: Fn(&Did) -> Option<PublicKey>,
{
    fn resolve(&self, did: &Did) -> Option<PublicKey> {
        (self)(did)
    }
}

/// Compute quorum with **full cryptographic** independence verification.
///
/// Unlike [`compute_quorum`], which only inspects the three boolean
/// declarations inside each `IndependenceAttestation`, this variant
/// additionally requires a valid signature over the canonical payload
/// under the attester's public key (as resolved by `resolver`).
///
/// This closes GAP-013: the structural-only check allowed an attacker
/// with a forged or missing signature to be counted toward
/// `min_independent`, defeating CR-001 §8.3's intent that "numerical
/// multiplicity without attributable independence is theater."
///
/// Prefer this function over `compute_quorum` in all production paths.
#[must_use]
pub fn compute_quorum_verified<R: PublicKeyResolver>(
    approvals: &[Approval],
    policy: &QuorumPolicy,
    resolver: &R,
) -> QuorumResult {
    if let Some(invalid) = validate_policy(policy) {
        return invalid;
    }

    if let Some(duplicate) = duplicate_approver(approvals) {
        return QuorumResult::NotMet {
            reason: format!("duplicate approver DID: {duplicate}"),
        };
    }

    if approvals.len() < policy.min_approvals {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient approvals: {} < {}",
                approvals.len(),
                policy.min_approvals
            ),
        };
    }

    let verified_approvals: Vec<(&Approval, Role)> = approvals
        .iter()
        .filter_map(|approval| {
            let public_key = resolver.resolve(&approval.approver_did)?;
            let trusted_role = resolver.resolve_trusted_role(&approval.approver_did)?;
            if approval.role != trusted_role || !approval.verify_signature(&public_key) {
                return None;
            }
            Some((approval, trusted_role))
        })
        .collect();

    let quorum_eligible_approvals: Vec<(&Approval, Role)> = verified_approvals
        .iter()
        .filter(|(_, role)| role_counts_toward_quorum(role))
        .map(|(approval, role)| (*approval, role.clone()))
        .collect();

    let total_count = quorum_eligible_approvals.len();

    if total_count < policy.min_approvals {
        let has_verified_non_quorum_role = verified_approvals
            .iter()
            .any(|(_, role)| !role_counts_toward_quorum(role));
        let reason = if has_verified_non_quorum_role {
            format!(
                "insufficient verified trusted role approvals: {total_count} quorum-eligible verified of {} required (Observer cannot satisfy quorum)",
                policy.min_approvals
            )
        } else {
            format!(
                "insufficient verified trusted role approvals: {total_count} verified of {} required",
                policy.min_approvals
            )
        };
        return QuorumResult::NotMet { reason };
    }

    for required_role in &policy.required_roles {
        if !quorum_eligible_approvals
            .iter()
            .any(|(_, trusted_role)| trusted_role == required_role)
        {
            return QuorumResult::NotMet {
                reason: format!(
                    "missing required role: {} (trusted role unresolved or mismatched)",
                    required_role.as_str()
                ),
            };
        }
    }

    let independent_count = quorum_eligible_approvals
        .iter()
        .filter(|(approval, _)| {
            approval
                .independence_attestation
                .as_ref()
                .is_some_and(|att| {
                    att.attester_did == approval.approver_did
                        && resolver
                            .resolve(&att.attester_did)
                            .is_some_and(|key| att.is_fully_valid(&key))
                })
        })
        .count();

    if independent_count < policy.min_independent {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient verified independence: {independent_count} verified-independent of {} required \
                 (numerical multiplicity without attributable independence is theater, not legitimacy)",
                policy.min_independent
            ),
        };
    }

    QuorumResult::Met {
        independent_count,
        total_count,
    }
}

/// Same as [`compute_quorum_verified`] but with the active-challenge guard
/// from [`compute_quorum_with_challenges`].
#[must_use]
pub fn compute_quorum_with_challenges_verified<R: PublicKeyResolver>(
    approvals: &[Approval],
    policy: &QuorumPolicy,
    open_challenges: &[&Challenge],
    resolver: &R,
) -> QuorumResult {
    if let Some(blocking) = open_challenges.iter().find(|c| {
        matches!(
            c.status,
            ChallengeStatus::Filed | ChallengeStatus::UnderReview
        )
    }) {
        return QuorumResult::Contested {
            challenge: format!(
                "unresolved independence challenge {} on ground {}",
                blocking.id,
                blocking.ground.as_str()
            ),
        };
    }
    compute_quorum_verified(approvals, policy, resolver)
}

/// Validate a single approval's basic structure.
pub fn validate_approval(approval: &Approval) -> Result<(), GovernanceError> {
    if approval.approver_did.as_str().is_empty() {
        return Err(GovernanceError::QuorumNotMet {
            required: 1,
            present: 0,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::crypto;

    use super::*;

    fn test_sig() -> Signature {
        let (_pk, sk) = crypto::generate_keypair();
        crypto::sign(b"test", &sk)
    }

    fn valid_attestation(did: &Did) -> IndependenceAttestation {
        IndependenceAttestation {
            attester_did: did.clone(),
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: test_sig(),
        }
    }

    fn invalid_attestation(did: &Did) -> IndependenceAttestation {
        IndependenceAttestation {
            attester_did: did.clone(),
            no_common_control: false,
            no_coordination: true,
            identity_verified: true,
            signature: test_sig(),
        }
    }

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).expect("valid test DID")
    }

    #[derive(Default)]
    struct TestQuorumResolver {
        keys: BTreeMap<Did, PublicKey>,
        roles: BTreeMap<Did, Role>,
    }

    impl TestQuorumResolver {
        fn from_entries(entries: Vec<(Did, PublicKey, Role)>) -> Self {
            let mut resolver = Self::default();
            for (did, public_key, role) in entries {
                resolver.keys.insert(did.clone(), public_key);
                resolver.roles.insert(did, role);
            }
            resolver
        }
    }

    impl PublicKeyResolver for TestQuorumResolver {
        fn resolve(&self, did: &Did) -> Option<PublicKey> {
            self.keys.get(did).copied()
        }

        fn resolve_trusted_role(&self, did: &Did) -> Option<Role> {
            self.roles.get(did).cloned()
        }
    }

    fn make_approval(name: &str, role: Role, independent: bool) -> Approval {
        let d = did(name);
        Approval {
            approver_did: d.clone(),
            role,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: if independent {
                Some(valid_attestation(&d))
            } else {
                None
            },
            scope: None,
        }
    }

    fn default_policy() -> QuorumPolicy {
        QuorumPolicy {
            min_approvals: 3,
            min_independent: 2,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        }
    }

    fn assert_verified_quorum_required(result: QuorumResult) {
        match result {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("verified quorum"));
            }
            other => panic!("expected verified quorum fail-closed result, got {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_without_resolver_rejects_sufficient_structural_approvals() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        assert_verified_quorum_required(compute_quorum(&approvals, &default_policy()));
    }

    #[test]
    fn compute_quorum_without_resolver_rejects_sufficient_unverified_approvals() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, false),
            make_approval("carol", Role::Contributor, false),
        ];
        assert_verified_quorum_required(compute_quorum(&approvals, &default_policy()));
    }

    #[test]
    fn quorum_fails_with_insufficient_total_approvals() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
        ];
        match compute_quorum(&approvals, &default_policy()) {
            QuorumResult::NotMet { reason } => assert!(reason.contains("insufficient approvals")),
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn quorum_fails_with_missing_required_role() {
        let approvals = vec![
            make_approval("alice", Role::Reviewer, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        match compute_quorum(&approvals, &default_policy()) {
            QuorumResult::NotMet { reason } => assert!(reason.contains("missing required role")),
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn quorum_fails_with_no_approvals() {
        assert!(matches!(
            compute_quorum(&[], &default_policy()),
            QuorumResult::NotMet { .. }
        ));
    }

    #[test]
    fn compute_quorum_without_resolver_rejects_invalid_structural_attestation_set() {
        let d = did("dave");
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            Approval {
                approver_did: d.clone(),
                role: Role::Contributor,
                timestamp: Timestamp::new(1000, 0),
                signature: test_sig(),
                independence_attestation: Some(invalid_attestation(&d)),
                scope: None,
            },
        ];
        assert_verified_quorum_required(compute_quorum(&approvals, &default_policy()));
    }

    #[test]
    fn independence_attestation_validity() {
        let d = did("test");
        assert!(valid_attestation(&d).is_valid());
        assert!(!invalid_attestation(&d).is_valid());
        let partial = IndependenceAttestation {
            attester_did: d.clone(),
            no_common_control: true,
            no_coordination: true,
            identity_verified: false,
            signature: test_sig(),
        };
        assert!(!partial.is_valid());
    }

    #[test]
    fn validate_approval_accepts_valid() {
        let approval = make_approval("alice", Role::Steward, true);
        assert!(validate_approval(&approval).is_ok());
    }

    #[test]
    fn quorum_policy_with_no_required_roles() {
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let approvals = vec![make_approval("alice", Role::Contributor, true)];
        assert_verified_quorum_required(compute_quorum(&approvals, &policy));
    }

    #[test]
    fn contested_variant_exists() {
        let contested = QuorumResult::Contested {
            challenge: "test".to_string(),
        };
        assert!(matches!(contested, QuorumResult::Contested { .. }));
    }

    // ── WO-004: challenge-blocked quorum ──────────────────────────────────────

    use crate::challenge::{
        ChallengeGround, ChallengeStatus, ChallengeVerdict, adjudicate, file_challenge,
    };

    fn target() -> [u8; 32] {
        [1u8; 32]
    }
    fn challenger_did() -> Did {
        did("challenger")
    }

    fn challenge_id(n: u128) -> uuid::Uuid {
        uuid::Uuid::from_u128(n)
    }

    fn challenge_ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn make_challenge(
        id: u128,
        ground: ChallengeGround,
        evidence: &[u8],
    ) -> crate::challenge::Challenge {
        file_challenge(
            challenge_id(id),
            challenge_ts(20_000),
            &challenger_did(),
            &target(),
            ground,
            evidence,
        )
        .expect("deterministic challenge")
    }

    #[test]
    fn open_challenge_blocks_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let ch = make_challenge(
            0x9001,
            ChallengeGround::SybilAllegation,
            b"coordinated approvers suspected",
        );
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));
    }

    #[test]
    fn under_review_challenge_blocks_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = make_challenge(0x9002, ChallengeGround::QuorumViolation, b"");
        ch.status = ChallengeStatus::UnderReview;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));
    }

    #[test]
    fn resolved_challenge_delegates_to_fail_closed_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = make_challenge(0x9003, ChallengeGround::SybilAllegation, b"");
        ch.status = ChallengeStatus::Overruled;
        assert_verified_quorum_required(compute_quorum_with_challenges(
            &approvals,
            &default_policy(),
            &[&ch],
        ));
    }

    #[test]
    fn no_challenges_delegates_to_compute_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        assert_eq!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[]),
            compute_quorum(&approvals, &default_policy())
        );
    }

    #[test]
    fn withdrawn_challenge_delegates_to_fail_closed_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = make_challenge(0x9004, ChallengeGround::SybilAllegation, b"");
        ch.status = ChallengeStatus::Withdrawn;
        assert_verified_quorum_required(compute_quorum_with_challenges(
            &approvals,
            &default_policy(),
            &[&ch],
        ));
    }

    // ── SPR2-04: quorum hardening edge cases ─────────────────────────────────

    /// Challenge filed mid-vote → Contested; moves to UnderReview → still
    /// Contested; then resolved (Overruled) → quorum proceeds to the
    /// fail-closed structural quorum result.
    #[test]
    fn challenge_filed_mid_vote_resolved_then_quorum_requires_verification() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = make_challenge(
            0x9005,
            ChallengeGround::SybilAllegation,
            b"coordinated approvers suspected",
        );

        // Phase 1: Filed → Contested
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));

        // Phase 2: UnderReview → still Contested
        ch.status = ChallengeStatus::UnderReview;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));

        // Phase 3: Overruled → quorum re-runs and still cannot approve
        // without cryptographic verification.
        adjudicate(&mut ch, ChallengeVerdict::Overrule).expect("adjudicate ok");
        assert_eq!(ch.status, ChallengeStatus::Overruled);
        assert_verified_quorum_required(compute_quorum_with_challenges(
            &approvals,
            &default_policy(),
            &[&ch],
        ));
    }

    /// A Sustained challenge (upheld) is a terminal state; it is no longer
    /// Filed/UnderReview, so it must delegate to the fail-closed quorum gate.
    #[test]
    fn sustained_challenge_delegates_to_fail_closed_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = make_challenge(0x9006, ChallengeGround::QuorumViolation, b"");
        adjudicate(&mut ch, ChallengeVerdict::Sustain).expect("adjudicate ok");
        assert_eq!(ch.status, ChallengeStatus::Sustained);
        assert_verified_quorum_required(compute_quorum_with_challenges(
            &approvals,
            &default_policy(),
            &[&ch],
        ));
    }

    /// Two Filed challenges from different grounds must both produce Contested —
    /// numerical multiplicity of challenges mirrors multiplicity of approvals.
    #[test]
    fn simultaneous_challenges_different_grounds_both_contested() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let ch1 = make_challenge(0x9007, ChallengeGround::SybilAllegation, b"sybil evidence");
        let ch2 = make_challenge(0x9008, ChallengeGround::QuorumViolation, b"quorum evidence");
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch1, &ch2]),
            QuorumResult::Contested { .. }
        ));
    }

    /// One resolved challenge plus one still-Filed challenge must remain Contested.
    #[test]
    fn mixed_resolved_and_open_challenge_stays_contested() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut resolved = make_challenge(0x9009, ChallengeGround::SybilAllegation, b"");
        adjudicate(&mut resolved, ChallengeVerdict::Overrule).expect("adjudicate ok");

        let open = make_challenge(0x9010, ChallengeGround::ProceduralError, b"");

        // resolved first in slice — open challenge must still block
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&resolved, &open]),
            QuorumResult::Contested { .. }
        ));
    }

    // ---------------------------------------------------------------
    // GAP-013 fix: signature verification on independence attestations
    // ---------------------------------------------------------------

    /// Build an attestation whose signature IS a real signature over the
    /// canonical payload under `sk`.
    fn properly_signed_attestation(
        did: &Did,
        sk: &exo_core::types::SecretKey,
    ) -> IndependenceAttestation {
        let mut att = IndependenceAttestation {
            attester_did: did.clone(),
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: Signature::Empty,
        };
        let payload = att.signing_payload().expect("canonical payload");
        att.signature = crypto::sign(&payload, sk);
        att
    }

    #[test]
    fn properly_signed_attestation_verifies() {
        let (pk, sk) = crypto::generate_keypair();
        let d = did("alice");
        let att = properly_signed_attestation(&d, &sk);
        assert!(att.is_valid(), "structural must hold");
        assert!(
            att.verify_signature(&pk),
            "signature over canonical payload must verify"
        );
        assert!(att.is_fully_valid(&pk));
    }

    #[test]
    fn zero_signature_fails_verification() {
        let (pk, _sk) = crypto::generate_keypair();
        let d = did("alice");
        let att = IndependenceAttestation {
            attester_did: d,
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: Signature::Ed25519([0u8; 64]),
        };
        // Structural is true, but verification must fail because the
        // signature is a zero sentinel, not a real signature.
        assert!(att.is_valid());
        assert!(!att.verify_signature(&pk));
        assert!(!att.is_fully_valid(&pk));
    }

    #[test]
    fn signature_by_wrong_key_fails_verification() {
        let (_pk_a, sk_a) = crypto::generate_keypair();
        let (pk_b, _sk_b) = crypto::generate_keypair();
        let d = did("alice");
        // Signed by key A, verified against key B.
        let att = properly_signed_attestation(&d, &sk_a);
        assert!(!att.verify_signature(&pk_b));
        assert!(!att.is_fully_valid(&pk_b));
    }

    #[test]
    fn signature_over_tampered_booleans_fails_verification() {
        let (pk, sk) = crypto::generate_keypair();
        let d = did("alice");
        let mut att = properly_signed_attestation(&d, &sk);
        // Tamper after signing.
        att.no_common_control = false;
        assert!(!att.verify_signature(&pk));
    }

    #[test]
    fn compute_quorum_verified_counts_only_signed_attestations() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let (pk_bob, sk_bob) = crypto::generate_keypair();
        let d_alice = did("alice");
        let d_bob = did("bob");

        // Alice signs properly.
        let alice_att = properly_signed_attestation(&d_alice, &sk_alice);
        // Bob has a structurally-valid attestation but a zero signature —
        // this is the attack the old code allowed through.
        let bob_att = IndependenceAttestation {
            attester_did: d_bob.clone(),
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: Signature::Ed25519([0u8; 64]),
        };

        let approvals = vec![
            signed_approval_with_attestation(
                &d_alice,
                Role::Steward,
                Timestamp::new(10_000, 0),
                &sk_alice,
                Some(alice_att),
            ),
            signed_approval_with_attestation(
                &d_bob,
                Role::Governor,
                Timestamp::new(10_001, 0),
                &sk_bob,
                Some(bob_att),
            ),
        ];

        let policy = QuorumPolicy {
            min_approvals: 2,
            min_independent: 2,
            required_roles: vec![],
            timeout: Timestamp::new(20_000, 0),
        };

        // Structural-only cannot prove either signature, so it must fail closed.
        assert_verified_quorum_required(compute_quorum(&approvals, &policy));

        // Verified variant counts ONLY Alice.
        let resolver = TestQuorumResolver::from_entries(vec![
            (d_alice.clone(), pk_alice, Role::Steward),
            (d_bob.clone(), pk_bob, Role::Governor),
        ]);
        match compute_quorum_verified(&approvals, &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("insufficient verified independence"));
                assert!(reason.contains("1 verified-independent of 2"));
            }
            other => panic!("expected NotMet (only Alice verified) but got {other:?}"),
        }
    }

    fn approval_signing_payload_for_test(approval: &Approval) -> Vec<u8> {
        approval.signing_payload().expect("approval payload")
    }

    fn properly_signed_approval(
        did: &Did,
        role: Role,
        timestamp: Timestamp,
        sk: &exo_core::types::SecretKey,
    ) -> Approval {
        let att = properly_signed_attestation(did, sk);
        signed_approval_with_attestation(did, role, timestamp, sk, Some(att))
    }

    fn signed_approval_with_attestation(
        did: &Did,
        role: Role,
        timestamp: Timestamp,
        sk: &exo_core::types::SecretKey,
        attestation: Option<IndependenceAttestation>,
    ) -> Approval {
        let mut approval = Approval {
            approver_did: did.clone(),
            role,
            timestamp,
            signature: Signature::Empty,
            independence_attestation: attestation,
            scope: None,
        };
        let payload = approval_signing_payload_for_test(&approval);
        approval.signature = crypto::sign(&payload, sk);
        approval
    }

    #[test]
    fn compute_quorum_rejects_duplicate_approver_dids() {
        let alice = make_approval("alice", Role::Steward, true);
        let duplicate = Approval {
            timestamp: Timestamp::new(1001, 0),
            ..alice.clone()
        };
        let policy = QuorumPolicy {
            min_approvals: 2,
            min_independent: 2,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum(&[alice, duplicate], &policy) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("duplicate approver"));
            }
            other => panic!("duplicate approver must not inflate quorum, got {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_without_resolver_fails_closed_for_signed_approvals() {
        let approvals = vec![make_approval("alice", Role::Steward, true)];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum(&approvals, &policy) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("verified quorum"));
            }
            other => panic!("structural quorum must not approve without verification: {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_rejects_zero_min_approvals_policy() {
        let policy = QuorumPolicy {
            min_approvals: 0,
            min_independent: 0,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum(&[], &policy) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("invalid quorum policy"));
                assert!(reason.contains("min_approvals"));
            }
            other => panic!("zero-approval policy must not meet quorum: {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_verified_rejects_zero_min_approvals_policy() {
        let policy = QuorumPolicy {
            min_approvals: 0,
            min_independent: 0,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = |_did: &Did| -> Option<PublicKey> { None };

        match compute_quorum_verified(&[], &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("invalid quorum policy"));
                assert!(reason.contains("min_approvals"));
            }
            other => panic!("zero-approval verified policy must not meet quorum: {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_verified_rejects_impossible_independence_policy() {
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 2,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = |_did: &Did| -> Option<PublicKey> { None };

        match compute_quorum_verified(&[], &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("invalid quorum policy"));
                assert!(reason.contains("min_independent"));
            }
            other => panic!("impossible independence policy must not reach quorum: {other:?}"),
        }
    }

    #[test]
    fn quorum_policy_rejects_observer_as_required_role() {
        let resolver = |_did: &Did| -> Option<PublicKey> { None };
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Observer],
            timeout: Timestamp::new(999_999, 0),
        };

        for result in [
            compute_quorum(&[], &policy),
            compute_quorum_verified(&[], &policy, &resolver),
        ] {
            match result {
                QuorumResult::NotMet { reason } => {
                    assert!(reason.contains("invalid quorum policy"));
                    assert!(reason.contains("Observer cannot be a required quorum role"));
                }
                other => panic!("Observer must not be a required quorum role, got {other:?}"),
            }
        }
    }

    #[test]
    fn compute_quorum_verified_rejects_duplicate_approver_dids() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let alice = did("alice");
        let first =
            properly_signed_approval(&alice, Role::Steward, Timestamp::new(1000, 0), &sk_alice);
        let second =
            properly_signed_approval(&alice, Role::Reviewer, Timestamp::new(1001, 0), &sk_alice);
        let resolver =
            |d: &Did| -> Option<PublicKey> { if *d == alice { Some(pk_alice) } else { None } };
        let policy = QuorumPolicy {
            min_approvals: 2,
            min_independent: 2,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum_verified(&[first, second], &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("duplicate approver"));
            }
            other => panic!("duplicate approver must not inflate verified quorum, got {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_verified_rejects_observer_approvals() {
        let (pk_observer, sk_observer) = crypto::generate_keypair();
        let observer = did("observer");
        let approval = signed_approval_with_attestation(
            &observer,
            Role::Observer,
            Timestamp::new(1000, 0),
            &sk_observer,
            None,
        );
        let resolver =
            TestQuorumResolver::from_entries(vec![(observer.clone(), pk_observer, Role::Observer)]);
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum_verified(&[approval], &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("Observer") || reason.contains("observer"));
            }
            other => panic!("observer approval must not satisfy verified quorum, got {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_verified_excludes_observers_from_total_count() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let (pk_observer, sk_observer) = crypto::generate_keypair();
        let alice = did("alice");
        let observer = did("observer");
        let approvals = vec![
            signed_approval_with_attestation(
                &alice,
                Role::Steward,
                Timestamp::new(1000, 0),
                &sk_alice,
                None,
            ),
            signed_approval_with_attestation(
                &observer,
                Role::Observer,
                Timestamp::new(1001, 0),
                &sk_observer,
                None,
            ),
        ];
        let resolver = TestQuorumResolver::from_entries(vec![
            (alice.clone(), pk_alice, Role::Steward),
            (observer.clone(), pk_observer, Role::Observer),
        ]);
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        assert_eq!(
            compute_quorum_verified(&approvals, &policy, &resolver),
            QuorumResult::Met {
                independent_count: 0,
                total_count: 1,
            }
        );
    }

    #[test]
    fn compute_quorum_verified_requires_valid_approval_signature() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let alice = did("alice");
        let att = properly_signed_attestation(&alice, &sk_alice);
        let approval = Approval {
            approver_did: alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: Signature::Ed25519([9u8; 64]),
            independence_attestation: Some(att),
            scope: None,
        };
        let resolver =
            TestQuorumResolver::from_entries(vec![(alice.clone(), pk_alice, Role::Steward)]);
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum_verified(&[approval], &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("verified"));
            }
            other => panic!("forged approval signature must not count, got {other:?}"),
        }
    }

    #[test]
    fn approval_signing_payload_binds_optional_scope() {
        let alice = did("alice");
        let base = Approval {
            approver_did: alice,
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: Signature::Empty,
            independence_attestation: None,
            scope: None,
        };
        let unscoped = base.signing_payload().expect("unscoped payload");
        let mut scoped_a = base.clone();
        scoped_a.scope = Some(ApprovalScope::DeliberationVote {
            deliberation_id: Uuid::from_u128(0xA001),
            proposal_hash: [1u8; 32],
            position: "For".to_string(),
            reasoning_hash: [2u8; 32],
        });
        let mut scoped_b = scoped_a.clone();
        scoped_b.scope = Some(ApprovalScope::DeliberationVote {
            deliberation_id: Uuid::from_u128(0xA002),
            proposal_hash: [1u8; 32],
            position: "For".to_string(),
            reasoning_hash: [2u8; 32],
        });

        assert_ne!(
            unscoped,
            scoped_a.signing_payload().expect("scoped payload"),
            "scoped quorum approvals must not share the legacy unscoped signature payload"
        );
        assert_ne!(
            scoped_a.signing_payload().expect("scoped payload"),
            scoped_b.signing_payload().expect("changed scoped payload"),
            "changing approval scope must change the canonical signature payload"
        );
    }

    #[test]
    fn compute_quorum_verified_requires_attestation_from_approver() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let (pk_bob, sk_bob) = crypto::generate_keypair();
        let alice = did("alice");
        let bob = did("bob");
        let alice_att = properly_signed_attestation(&alice, &sk_alice);
        let mut bob_approval = Approval {
            approver_did: bob.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: Signature::Empty,
            independence_attestation: Some(alice_att),
            scope: None,
        };
        let payload = approval_signing_payload_for_test(&bob_approval);
        bob_approval.signature = crypto::sign(&payload, &sk_bob);
        let resolver = TestQuorumResolver::from_entries(vec![
            (alice.clone(), pk_alice, Role::Steward),
            (bob.clone(), pk_bob, Role::Steward),
        ]);
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum_verified(&[bob_approval], &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("verified"));
            }
            other => panic!(
                "borrowed attestation must not count for a different approver, got {other:?}"
            ),
        }
    }

    #[test]
    fn compute_quorum_verified_unresolved_did_not_counted() {
        let (_pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let att = properly_signed_attestation(&d_alice, &sk_alice);

        let approvals = vec![Approval {
            approver_did: d_alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(10_000, 0),
            signature: test_sig(),
            independence_attestation: Some(att),
            scope: None,
        }];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(20_000, 0),
        };

        // Resolver that returns None for everything — attestation cannot
        // be verified, so independent_count is 0.
        let null_resolver = |_did: &Did| None;
        assert!(matches!(
            compute_quorum_verified(&approvals, &policy, &null_resolver),
            QuorumResult::NotMet { .. }
        ));
    }

    // ── Coverage completion: previously-untested branches ────────────────────

    // Covers validate_approval Err branch when approver_did is empty.
    #[test]
    fn validate_approval_rejects_empty_did() {
        let approval = Approval {
            approver_did: Did::new("did:exo:placeholder").expect("valid did"),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: None,
            scope: None,
        };
        // Replace DID with one whose as_str() is empty via a direct constructor.
        // Did::new rejects empties, so fabricate one by cloning and mutating
        // through serde round-trip of a hand-built JSON value.
        let empty_did: Did =
            serde_json::from_str("\"\"").expect("empty-string DID deserializes for test");
        let bad_approval = Approval {
            approver_did: empty_did,
            ..approval
        };
        match validate_approval(&bad_approval) {
            Err(GovernanceError::QuorumNotMet { required, present }) => {
                assert_eq!(required, 1);
                assert_eq!(present, 0);
            }
            other => panic!("expected QuorumNotMet error, got {other:?}"),
        }
    }

    // Covers compute_quorum_verified's `insufficient approvals` NotMet branch.
    #[test]
    fn compute_quorum_verified_insufficient_approvals_branch() {
        let resolver = |_d: &Did| -> Option<PublicKey> { None };
        let policy = QuorumPolicy {
            min_approvals: 3,
            min_independent: 0,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let approvals = vec![make_approval("alice", Role::Steward, false)];
        match compute_quorum_verified(&approvals, &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(
                    reason.contains("insufficient approvals"),
                    "reason was {reason}"
                );
                assert!(reason.contains("1 < 3"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn quorum_reasons_do_not_depend_on_debug_formatting() {
        let source = include_str!("quorum.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        for forbidden in ["missing required role: {required_role:?}", "on ground {:?}"] {
            assert!(
                !source.contains(forbidden),
                "quorum reasons must use explicit stable labels: {forbidden}"
            );
        }
    }

    // Covers compute_quorum_verified's `missing required role` NotMet branch.
    #[test]
    fn compute_quorum_verified_missing_required_role_branch() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let (pk_bob, sk_bob) = crypto::generate_keypair();
        let (pk_carol, sk_carol) = crypto::generate_keypair();
        let d_alice = did("alice");
        let d_bob = did("bob");
        let d_carol = did("carol");
        let resolver = TestQuorumResolver::from_entries(vec![
            (d_alice.clone(), pk_alice, Role::Reviewer),
            (d_bob.clone(), pk_bob, Role::Reviewer),
            (d_carol.clone(), pk_carol, Role::Reviewer),
        ]);
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Governor],
            timeout: Timestamp::new(999_999, 0),
        };
        // Three Reviewer approvals — no Governor.
        let approvals = vec![
            signed_approval_with_attestation(
                &d_alice,
                Role::Reviewer,
                Timestamp::new(1000, 0),
                &sk_alice,
                None,
            ),
            signed_approval_with_attestation(
                &d_bob,
                Role::Reviewer,
                Timestamp::new(1001, 0),
                &sk_bob,
                None,
            ),
            signed_approval_with_attestation(
                &d_carol,
                Role::Reviewer,
                Timestamp::new(1002, 0),
                &sk_carol,
                None,
            ),
        ];
        match compute_quorum_verified(&approvals, &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("missing required role: Governor"));
                assert!(reason.contains("trusted role"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    #[test]
    fn compute_quorum_verified_rejects_required_role_without_trusted_role_resolution() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let approval = signed_approval_with_attestation(
            &d_alice,
            Role::Steward,
            Timestamp::new(1000, 0),
            &sk_alice,
            None,
        );
        let key_only_resolver =
            |d: &Did| -> Option<PublicKey> { if *d == d_alice { Some(pk_alice) } else { None } };
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };

        match compute_quorum_verified(&[approval], &policy, &key_only_resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(
                    reason.contains("trusted role"),
                    "required roles must fail closed without trusted role resolution: {reason}"
                );
            }
            other => {
                panic!("self-asserted required role must not satisfy verified quorum: {other:?}")
            }
        }
    }

    // Covers compute_quorum_verified's Met success branch with a signed attestation.
    #[test]
    fn compute_quorum_verified_met_branch_for_signed_attestation() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let (pk_bob, sk_bob) = crypto::generate_keypair();
        let d_alice = did("alice");
        let d_bob = did("bob");
        let approvals = vec![
            properly_signed_approval(&d_alice, Role::Steward, Timestamp::new(1000, 0), &sk_alice),
            properly_signed_approval(&d_bob, Role::Reviewer, Timestamp::new(1001, 0), &sk_bob),
        ];
        let policy = QuorumPolicy {
            min_approvals: 2,
            min_independent: 2,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = TestQuorumResolver::from_entries(vec![
            (d_alice.clone(), pk_alice, Role::Steward),
            (d_bob.clone(), pk_bob, Role::Reviewer),
        ]);
        assert_eq!(
            compute_quorum_verified(&approvals, &policy, &resolver),
            QuorumResult::Met {
                independent_count: 2,
                total_count: 2,
            }
        );
    }

    // Covers compute_quorum_verified's None-from-resolver path (approval not counted).
    #[test]
    fn compute_quorum_verified_none_resolver_excludes_but_totals_pass() {
        let (_pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let approvals = vec![properly_signed_approval(
            &d_alice,
            Role::Steward,
            Timestamp::new(1000, 0),
            &sk_alice,
        )];
        // Even with min_independent=0, unresolved approvers cannot count
        // toward verified approval quorum.
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let null_resolver = |_d: &Did| -> Option<PublicKey> { None };
        match compute_quorum_verified(&approvals, &policy, &null_resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("insufficient verified trusted role approvals"));
            }
            other => panic!("expected NotMet for unresolved approver, got {other:?}"),
        }
    }

    // Covers compute_quorum_with_challenges_verified: open Filed challenge short-circuits to Contested.
    #[test]
    fn compute_quorum_with_challenges_verified_filed_blocks() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let approvals = vec![properly_signed_approval(
            &d_alice,
            Role::Steward,
            Timestamp::new(1000, 0),
            &sk_alice,
        )];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver =
            TestQuorumResolver::from_entries(vec![(d_alice.clone(), pk_alice, Role::Steward)]);
        let ch = make_challenge(0x9011, ChallengeGround::SybilAllegation, b"evidence");
        match compute_quorum_with_challenges_verified(&approvals, &policy, &[&ch], &resolver) {
            QuorumResult::Contested { challenge } => {
                assert!(challenge.contains("unresolved independence challenge"));
                assert!(challenge.contains("SybilAllegation"));
            }
            other => panic!("expected Contested, got {other:?}"),
        }
    }

    // Covers compute_quorum_with_challenges_verified: UnderReview challenge also blocks.
    #[test]
    fn compute_quorum_with_challenges_verified_under_review_blocks() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let approvals = vec![properly_signed_approval(
            &d_alice,
            Role::Steward,
            Timestamp::new(1000, 0),
            &sk_alice,
        )];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver =
            TestQuorumResolver::from_entries(vec![(d_alice.clone(), pk_alice, Role::Steward)]);
        let mut ch = make_challenge(0x9012, ChallengeGround::QuorumViolation, b"");
        ch.status = ChallengeStatus::UnderReview;
        assert!(matches!(
            compute_quorum_with_challenges_verified(&approvals, &policy, &[&ch], &resolver),
            QuorumResult::Contested { .. }
        ));
    }

    // Covers compute_quorum_with_challenges_verified: no open challenges → delegates and returns Met.
    #[test]
    fn compute_quorum_with_challenges_verified_delegates_to_verified_on_clean() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let approvals = vec![properly_signed_approval(
            &d_alice,
            Role::Steward,
            Timestamp::new(1000, 0),
            &sk_alice,
        )];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver =
            TestQuorumResolver::from_entries(vec![(d_alice.clone(), pk_alice, Role::Steward)]);
        assert_eq!(
            compute_quorum_with_challenges_verified(&approvals, &policy, &[], &resolver),
            QuorumResult::Met {
                independent_count: 1,
                total_count: 1,
            }
        );
    }

    // Covers compute_quorum_with_challenges_verified: only resolved challenges pass through to verified delegate.
    #[test]
    fn compute_quorum_with_challenges_verified_resolved_challenge_passes_through() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let approvals = vec![properly_signed_approval(
            &d_alice,
            Role::Steward,
            Timestamp::new(1000, 0),
            &sk_alice,
        )];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver =
            TestQuorumResolver::from_entries(vec![(d_alice.clone(), pk_alice, Role::Steward)]);
        let mut ch = make_challenge(0x9013, ChallengeGround::SybilAllegation, b"");
        ch.status = ChallengeStatus::Overruled;
        assert!(matches!(
            compute_quorum_with_challenges_verified(&approvals, &policy, &[&ch], &resolver),
            QuorumResult::Met { .. }
        ));
    }

    // Covers PublicKeyResolver trait's closure adapter — resolve() invokes the Fn.
    #[test]
    fn public_key_resolver_closure_adapter_invokes_fn() {
        let (pk, _sk) = crypto::generate_keypair();
        let d = did("adapter");
        let pk_clone = pk;
        let d_clone = d.clone();
        let resolver = move |q: &Did| -> Option<PublicKey> {
            if *q == d_clone { Some(pk_clone) } else { None }
        };
        // Trait-dispatched call path.
        let resolved: Option<PublicKey> = PublicKeyResolver::resolve(&resolver, &d);
        assert!(resolved.is_some());
        assert_eq!(resolved.expect("just checked some"), pk);
        // Unrecognized DID maps to None via the same adapter.
        assert!(PublicKeyResolver::resolve(&resolver, &did("other")).is_none());
    }

    // Covers verify_signature's empty-signature early reject.
    #[test]
    fn verify_signature_rejects_empty_variant() {
        let (pk, _sk) = crypto::generate_keypair();
        let d = did("empty-sig");
        let att = IndependenceAttestation {
            attester_did: d,
            no_common_control: true,
            no_coordination: true,
            identity_verified: true,
            signature: Signature::Empty,
        };
        // Empty sentinel must not verify even though the structural flags hold.
        assert!(att.is_valid());
        assert!(!att.verify_signature(&pk));
        assert!(!att.is_fully_valid(&pk));
    }

    // Covers Role equality & hashing across all five variants (exhaustive Role coverage incl. Observer).
    #[test]
    fn role_variants_distinct_and_serde_roundtrip() {
        let all = [
            Role::Steward,
            Role::Governor,
            Role::Reviewer,
            Role::Contributor,
            Role::Observer,
        ];
        // Pairwise inequality.
        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
        // Serde round-trip for each variant.
        for r in &all {
            let ser = serde_json::to_string(r).expect("serialize role");
            let back: Role = serde_json::from_str(&ser).expect("deserialize role");
            assert_eq!(&back, r);
        }
    }

    // Covers compute_quorum Met result's eq/debug surface (PartialEq + Debug on QuorumResult).
    #[test]
    fn quorum_result_debug_and_eq_surface() {
        let met = QuorumResult::Met {
            independent_count: 2,
            total_count: 3,
        };
        let met2 = QuorumResult::Met {
            independent_count: 2,
            total_count: 3,
        };
        let notmet = QuorumResult::NotMet { reason: "x".into() };
        assert_eq!(met, met2);
        assert_ne!(met, notmet);
        let dbg = format!("{met:?}");
        assert!(dbg.contains("Met"));
        assert!(dbg.contains("independent_count"));
    }
}
