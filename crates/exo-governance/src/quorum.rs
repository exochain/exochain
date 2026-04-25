//! Quorum computation with independence-aware counting.
//!
//! Constitutional principle: "Numerical multiplicity without attributable
//! independence is theater, not legitimacy."

use exo_core::{Did, PublicKey, Signature, Timestamp, crypto};
use serde::{Deserialize, Serialize};

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
    Observer,
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
        let raw = self.signature.as_bytes();
        if raw.is_empty() || raw.iter().all(|b| *b == 0) {
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

/// Compute whether a quorum is met given a set of approvals and a policy.
#[must_use]
pub fn compute_quorum(approvals: &[Approval], policy: &QuorumPolicy) -> QuorumResult {
    let total_count = approvals.len();

    if total_count < policy.min_approvals {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient approvals: {total_count} < {}",
                policy.min_approvals
            ),
        };
    }

    for required_role in &policy.required_roles {
        if !approvals.iter().any(|a| &a.role == required_role) {
            return QuorumResult::NotMet {
                reason: format!("missing required role: {required_role:?}"),
            };
        }
    }

    let independent_count = approvals
        .iter()
        .filter(|a| {
            a.independence_attestation
                .as_ref()
                .is_some_and(|att| att.is_valid())
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
                "unresolved independence challenge {} on ground {:?}",
                blocking.id, blocking.ground
            ),
        };
    }
    compute_quorum(approvals, policy)
}

/// Resolve an attester DID to a public key for signature verification.
///
/// Governance call sites supply an implementation of this trait backed by
/// the authority chain or identity registry. A resolver that returns
/// `None` for a given DID causes `compute_quorum_verified` to treat any
/// independence attestation from that DID as unverifiable (and therefore
/// not countable toward `min_independent`).
pub trait PublicKeyResolver {
    fn resolve(&self, did: &Did) -> Option<PublicKey>;
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
    let total_count = approvals.len();

    if total_count < policy.min_approvals {
        return QuorumResult::NotMet {
            reason: format!(
                "insufficient approvals: {total_count} < {}",
                policy.min_approvals
            ),
        };
    }

    for required_role in &policy.required_roles {
        if !approvals.iter().any(|a| &a.role == required_role) {
            return QuorumResult::NotMet {
                reason: format!("missing required role: {required_role:?}"),
            };
        }
    }

    let independent_count = approvals
        .iter()
        .filter(|a| {
            a.independence_attestation.as_ref().is_some_and(|att| {
                match resolver.resolve(&att.attester_did) {
                    Some(key) => att.is_fully_valid(&key),
                    None => false,
                }
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
                "unresolved independence challenge {} on ground {:?}",
                blocking.id, blocking.ground
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

    #[test]
    fn quorum_met_with_sufficient_independent_approvals() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        assert_eq!(
            compute_quorum(&approvals, &default_policy()),
            QuorumResult::Met {
                independent_count: 3,
                total_count: 3
            }
        );
    }

    #[test]
    fn quorum_fails_with_sufficient_approvals_but_insufficient_independence() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, false),
            make_approval("carol", Role::Contributor, false),
        ];
        match compute_quorum(&approvals, &default_policy()) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("insufficient independence"));
                assert!(reason.contains("theater, not legitimacy"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
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
    fn quorum_with_invalid_attestation_counts_as_non_independent() {
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
            },
        ];
        assert_eq!(
            compute_quorum(&approvals, &default_policy()),
            QuorumResult::Met {
                independent_count: 2,
                total_count: 3
            }
        );
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
        assert!(matches!(
            compute_quorum(&approvals, &policy),
            QuorumResult::Met { .. }
        ));
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

    #[test]
    fn open_challenge_blocks_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let ch = file_challenge(
            &challenger_did(),
            &target(),
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
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        ch.status = ChallengeStatus::UnderReview;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Contested { .. }
        ));
    }

    #[test]
    fn resolved_challenge_does_not_block_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        ch.status = ChallengeStatus::Overruled;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
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
    fn withdrawn_challenge_does_not_block_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        ch.status = ChallengeStatus::Withdrawn;
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
        ));
    }

    // ── SPR2-04: quorum hardening edge cases ─────────────────────────────────

    /// Challenge filed mid-vote → Contested; moves to UnderReview → still
    /// Contested; then resolved (Overruled) → quorum proceeds to Met.
    #[test]
    fn challenge_filed_mid_vote_resolved_then_quorum_proceeds() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
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

        // Phase 3: Overruled → quorum re-runs and succeeds
        adjudicate(&mut ch, ChallengeVerdict::Overrule).expect("adjudicate ok");
        assert_eq!(ch.status, ChallengeStatus::Overruled);
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
        ));
    }

    /// A Sustained challenge (upheld) is a terminal state; it is no longer
    /// Filed/UnderReview, so it must not block the quorum gate.
    #[test]
    fn sustained_challenge_does_not_block_quorum() {
        let approvals = vec![
            make_approval("alice", Role::Steward, true),
            make_approval("bob", Role::Reviewer, true),
            make_approval("carol", Role::Contributor, true),
        ];
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
        adjudicate(&mut ch, ChallengeVerdict::Sustain).expect("adjudicate ok");
        assert_eq!(ch.status, ChallengeStatus::Sustained);
        assert!(matches!(
            compute_quorum_with_challenges(&approvals, &default_policy(), &[&ch]),
            QuorumResult::Met { .. }
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
        let ch1 = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"sybil evidence",
        );
        let ch2 = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"quorum evidence",
        );
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
        let mut resolved = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
        adjudicate(&mut resolved, ChallengeVerdict::Overrule).expect("adjudicate ok");

        let open = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::ProceduralError,
            b"",
        );

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
        let (pk_bob, _sk_bob) = crypto::generate_keypair();
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
            Approval {
                approver_did: d_alice.clone(),
                role: Role::Steward,
                timestamp: Timestamp::now_utc(),
                signature: test_sig(),
                independence_attestation: Some(alice_att),
            },
            Approval {
                approver_did: d_bob.clone(),
                role: Role::Governor,
                timestamp: Timestamp::now_utc(),
                signature: test_sig(),
                independence_attestation: Some(bob_att),
            },
        ];

        let policy = QuorumPolicy {
            min_approvals: 2,
            min_independent: 2,
            required_roles: vec![],
            timeout: Timestamp::now_utc(),
        };

        // Structural-only counts both. (This is the bug.)
        assert!(matches!(
            compute_quorum(&approvals, &policy),
            QuorumResult::Met {
                independent_count: 2,
                ..
            }
        ));

        // Verified variant counts ONLY Alice.
        let resolver = |did: &Did| -> Option<exo_core::types::PublicKey> {
            if *did == d_alice {
                Some(pk_alice)
            } else if *did == d_bob {
                Some(pk_bob)
            } else {
                None
            }
        };
        match compute_quorum_verified(&approvals, &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("insufficient verified independence"));
                assert!(reason.contains("1 verified-independent of 2"));
            }
            other => panic!("expected NotMet (only Alice verified) but got {other:?}"),
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
            timestamp: Timestamp::now_utc(),
            signature: test_sig(),
            independence_attestation: Some(att),
        }];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::now_utc(),
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

    // Covers compute_quorum_verified's `missing required role` NotMet branch.
    #[test]
    fn compute_quorum_verified_missing_required_role_branch() {
        let resolver = |_d: &Did| -> Option<PublicKey> { None };
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![Role::Governor],
            timeout: Timestamp::new(999_999, 0),
        };
        // Three Reviewer approvals — no Governor.
        let approvals = vec![
            make_approval("alice", Role::Reviewer, false),
            make_approval("bob", Role::Reviewer, false),
            make_approval("carol", Role::Reviewer, false),
        ];
        match compute_quorum_verified(&approvals, &policy, &resolver) {
            QuorumResult::NotMet { reason } => {
                assert!(reason.contains("missing required role"));
                assert!(reason.contains("Governor"));
            }
            other => panic!("expected NotMet, got {other:?}"),
        }
    }

    // Covers compute_quorum_verified's Met success branch with a signed attestation.
    #[test]
    fn compute_quorum_verified_met_branch_for_signed_attestation() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let (pk_bob, sk_bob) = crypto::generate_keypair();
        let d_alice = did("alice");
        let d_bob = did("bob");
        let alice_att = properly_signed_attestation(&d_alice, &sk_alice);
        let bob_att = properly_signed_attestation(&d_bob, &sk_bob);

        let approvals = vec![
            Approval {
                approver_did: d_alice.clone(),
                role: Role::Steward,
                timestamp: Timestamp::new(1000, 0),
                signature: test_sig(),
                independence_attestation: Some(alice_att),
            },
            Approval {
                approver_did: d_bob.clone(),
                role: Role::Reviewer,
                timestamp: Timestamp::new(1000, 0),
                signature: test_sig(),
                independence_attestation: Some(bob_att),
            },
        ];
        let policy = QuorumPolicy {
            min_approvals: 2,
            min_independent: 2,
            required_roles: vec![Role::Steward],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = |d: &Did| -> Option<PublicKey> {
            if *d == d_alice {
                Some(pk_alice)
            } else if *d == d_bob {
                Some(pk_bob)
            } else {
                None
            }
        };
        assert_eq!(
            compute_quorum_verified(&approvals, &policy, &resolver),
            QuorumResult::Met {
                independent_count: 2,
                total_count: 2,
            }
        );
    }

    // Covers compute_quorum_verified's None-from-resolver match arm path (attestation not counted).
    #[test]
    fn compute_quorum_verified_none_resolver_excludes_but_totals_pass() {
        let (_pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let att = properly_signed_attestation(&d_alice, &sk_alice);
        let approvals = vec![Approval {
            approver_did: d_alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: Some(att),
        }];
        // min_independent=0 so Met is reached even with unresolvable DID.
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 0,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let null_resolver = |_d: &Did| -> Option<PublicKey> { None };
        assert_eq!(
            compute_quorum_verified(&approvals, &policy, &null_resolver),
            QuorumResult::Met {
                independent_count: 0,
                total_count: 1,
            }
        );
    }

    // Covers compute_quorum_with_challenges_verified: open Filed challenge short-circuits to Contested.
    #[test]
    fn compute_quorum_with_challenges_verified_filed_blocks() {
        let (pk_alice, sk_alice) = crypto::generate_keypair();
        let d_alice = did("alice");
        let att = properly_signed_attestation(&d_alice, &sk_alice);
        let approvals = vec![Approval {
            approver_did: d_alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: Some(att),
        }];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = move |d: &Did| -> Option<PublicKey> {
            if *d == d_alice { Some(pk_alice) } else { None }
        };
        let ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"evidence",
        );
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
        let att = properly_signed_attestation(&d_alice, &sk_alice);
        let approvals = vec![Approval {
            approver_did: d_alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: Some(att),
        }];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = move |d: &Did| -> Option<PublicKey> {
            if *d == d_alice { Some(pk_alice) } else { None }
        };
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::QuorumViolation,
            b"",
        );
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
        let att = properly_signed_attestation(&d_alice, &sk_alice);
        let approvals = vec![Approval {
            approver_did: d_alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: Some(att),
        }];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = move |d: &Did| -> Option<PublicKey> {
            if *d == d_alice { Some(pk_alice) } else { None }
        };
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
        let att = properly_signed_attestation(&d_alice, &sk_alice);
        let approvals = vec![Approval {
            approver_did: d_alice.clone(),
            role: Role::Steward,
            timestamp: Timestamp::new(1000, 0),
            signature: test_sig(),
            independence_attestation: Some(att),
        }];
        let policy = QuorumPolicy {
            min_approvals: 1,
            min_independent: 1,
            required_roles: vec![],
            timeout: Timestamp::new(999_999, 0),
        };
        let resolver = move |d: &Did| -> Option<PublicKey> {
            if *d == d_alice { Some(pk_alice) } else { None }
        };
        let mut ch = file_challenge(
            &challenger_did(),
            &target(),
            ChallengeGround::SybilAllegation,
            b"",
        );
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

    // Covers verify_signature's empty-signature early reject (Signature::Empty → 64 zeros).
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
