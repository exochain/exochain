//! CGR (Constitutional Governance Runtime) Kernel.
//!
//! The kernel is immutable after initialization. It holds the invariant set
//! and constitution hash, and adjudicates every action request.

use exo_core::Did;
use serde::{Deserialize, Serialize};

use crate::{
    invariants::{
        ConstitutionalInvariant, InvariantContext, InvariantEngine, InvariantSet,
        InvariantViolation, enforce_all,
    },
    types::{
        AuthorityChain, BailmentState, ConsentRecord, PermissionSet, Provenance, QuorumEvidence,
        Role,
    },
};

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Result of kernel adjudication: permitted, denied with violations, or escalated for review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    Permitted,
    Denied { violations: Vec<InvariantViolation> },
    Escalated { reason: String },
}

impl Verdict {
    pub fn is_permitted(&self) -> bool {
        matches!(self, Verdict::Permitted)
    }
    pub fn is_denied(&self) -> bool {
        matches!(self, Verdict::Denied { .. })
    }
}

// ---------------------------------------------------------------------------
// Action request
// ---------------------------------------------------------------------------

/// A request submitted to the kernel for adjudication against constitutional invariants.
#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub actor: Did,
    pub action: String,
    pub required_permissions: PermissionSet,
    pub is_self_grant: bool,
    pub modifies_kernel: bool,
}

// ---------------------------------------------------------------------------
// Adjudication context
// ---------------------------------------------------------------------------

/// Contextual evidence (roles, authority chain, consent, etc.) supplied alongside an action request.
#[derive(Debug, Clone)]
pub struct AdjudicationContext {
    pub actor_roles: Vec<Role>,
    pub authority_chain: AuthorityChain,
    pub consent_records: Vec<ConsentRecord>,
    pub bailment_state: BailmentState,
    pub human_override_preserved: bool,
    pub actor_permissions: PermissionSet,
    pub provenance: Option<Provenance>,
    pub quorum_evidence: Option<QuorumEvidence>,
    /// When set, the action is under an active Sybil challenge hold.
    /// The kernel short-circuits to `Verdict::Escalated` before running
    /// invariant checks — the action is paused (not denied) pending review.
    /// Populate from `ContestHold::escalation_reason()` in exo-escalation.
    pub active_challenge_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Kernel
// ---------------------------------------------------------------------------

/// Immutable constitutional governance kernel that adjudicates actions against invariants.
#[derive(Debug, Clone)]
pub struct Kernel {
    constitution_hash: [u8; 32],
    invariant_engine: InvariantEngine,
}

impl Kernel {
    #[must_use]
    pub fn new(constitution: &[u8], invariants: InvariantSet) -> Self {
        let hash = blake3::hash(constitution);
        Self {
            constitution_hash: *hash.as_bytes(),
            invariant_engine: InvariantEngine::new(invariants),
        }
    }

    pub fn adjudicate(&self, action: &ActionRequest, context: &AdjudicationContext) -> Verdict {
        // Short-circuit: an active Sybil challenge hold pauses the action
        // (Escalated, not Denied) so it can be reviewed rather than blocked.
        if let Some(ref reason) = context.active_challenge_reason {
            return Verdict::Escalated {
                reason: reason.clone(),
            };
        }

        let inv_ctx = InvariantContext {
            actor: action.actor.clone(),
            actor_roles: context.actor_roles.clone(),
            bailment_state: context.bailment_state.clone(),
            consent_records: context.consent_records.clone(),
            authority_chain: context.authority_chain.clone(),
            is_self_grant: action.is_self_grant,
            human_override_preserved: context.human_override_preserved,
            kernel_modification_attempted: action.modifies_kernel,
            quorum_evidence: context.quorum_evidence.clone(),
            provenance: context.provenance.clone(),
            actor_permissions: context.actor_permissions.clone(),
            requested_permissions: action.required_permissions.clone(),
        };

        match enforce_all(&self.invariant_engine, &inv_ctx) {
            Ok(()) => Verdict::Permitted,
            Err(violations) => {
                let needs_escalation = violations.iter().any(|v| {
                    v.invariant == ConstitutionalInvariant::QuorumLegitimate
                        || v.invariant == ConstitutionalInvariant::AuthorityChainValid
                });
                if needs_escalation && violations.len() == 1 {
                    Verdict::Escalated {
                        reason: violations[0].description.clone(),
                    }
                } else {
                    Verdict::Denied { violations }
                }
            }
        }
    }

    pub fn verify_kernel_integrity(&self, constitution: &[u8]) -> bool {
        *blake3::hash(constitution).as_bytes() == self.constitution_hash
    }

    #[must_use]
    pub fn constitution_hash(&self) -> &[u8; 32] {
        &self.constitution_hash
    }

    #[must_use]
    pub fn invariant_engine(&self) -> &InvariantEngine {
        &self.invariant_engine
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        invariants::{authority_link_signature_message, provenance_signature_message},
        types::{AuthorityLink, GovernmentBranch, Permission, QuorumVote},
    };

    const CONSTITUTION: &[u8] = b"We the people of the EXOCHAIN...";

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    fn signed_link(grantor_str: &str, grantee: &Did) -> AuthorityLink {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = did(grantor_str);
        let permissions = PermissionSet::new(vec![Permission::new("read")]);
        let mut link = AuthorityLink {
            grantor,
            grantee: grantee.clone(),
            permissions,
            signature: Vec::new(),
            grantor_public_key: Some(pk.as_bytes().to_vec()),
        };
        let message = authority_link_signature_message(&link).expect("canonical link payload");
        let signature = exo_core::crypto::sign(message.as_bytes(), &sk);
        link.signature = signature.to_bytes().to_vec();
        link
    }

    fn signed_provenance(actor: &Did) -> Provenance {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let timestamp = "2025-01-01T00:00:00Z".to_owned();
        let action_hash = vec![1, 2, 3];
        let mut provenance = Provenance {
            actor: actor.clone(),
            timestamp,
            action_hash,
            signature: Vec::new(),
            public_key: Some(pk.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        };
        let message =
            provenance_signature_message(&provenance).expect("canonical provenance payload");
        let signature = exo_core::crypto::sign(message.as_bytes(), &sk);
        provenance.signature = signature.to_bytes().to_vec();
        provenance
    }

    fn test_kernel() -> Kernel {
        Kernel::new(CONSTITUTION, InvariantSet::all())
    }

    fn valid_action(actor: &Did) -> ActionRequest {
        ActionRequest {
            actor: actor.clone(),
            action: "read medical record".into(),
            required_permissions: PermissionSet::new(vec![Permission::new("read")]),
            is_self_grant: false,
            modifies_kernel: false,
        }
    }

    fn valid_context(actor: &Did) -> AdjudicationContext {
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "judge".into(),
                branch: GovernmentBranch::Judicial,
            }],
            authority_chain: AuthorityChain {
                links: vec![signed_link("did:exo:root", actor)],
            },
            consent_records: vec![ConsentRecord {
                subject: did("did:exo:bailor"),
                granted_to: actor.clone(),
                scope: "data:medical".into(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor: did("did:exo:bailor"),
                bailee: actor.clone(),
                scope: "data:medical".into(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
            provenance: Some(signed_provenance(actor)),
            quorum_evidence: None,
            active_challenge_reason: None,
        }
    }

    #[test]
    fn kernel_hashes_constitution() {
        let kernel = test_kernel();
        assert_eq!(
            kernel.constitution_hash(),
            blake3::hash(CONSTITUTION).as_bytes()
        );
    }

    #[test]
    fn verify_integrity_matches() {
        assert!(test_kernel().verify_kernel_integrity(CONSTITUTION));
    }

    #[test]
    fn verify_integrity_fails_tampered() {
        assert!(!test_kernel().verify_kernel_integrity(b"TAMPERED"));
    }

    #[test]
    fn cp1_separation_denies_multi_branch() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        let mut ctx = valid_context(&actor);
        ctx.actor_roles = vec![
            Role {
                name: "s".into(),
                branch: GovernmentBranch::Legislative,
            },
            Role {
                name: "j".into(),
                branch: GovernmentBranch::Judicial,
            },
        ];
        assert!(kernel.adjudicate(&valid_action(&actor), &ctx).is_denied());
    }

    #[test]
    fn cp1_separation_permits_single_branch() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        assert!(
            kernel
                .adjudicate(&valid_action(&actor), &valid_context(&actor))
                .is_permitted()
        );
    }

    #[test]
    fn cp2_consent_denies_no_bailment() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        let mut ctx = valid_context(&actor);
        ctx.bailment_state = BailmentState::None;
        assert!(kernel.adjudicate(&valid_action(&actor), &ctx).is_denied());
    }

    #[test]
    fn cp2_consent_permits_active() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        assert!(
            kernel
                .adjudicate(&valid_action(&actor), &valid_context(&actor))
                .is_permitted()
        );
    }

    #[test]
    fn cp3_no_self_grant_denies() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        let mut action = valid_action(&actor);
        action.is_self_grant = true;
        assert!(
            kernel
                .adjudicate(&action, &valid_context(&actor))
                .is_denied()
        );
    }

    #[test]
    fn cp3_no_self_grant_permits() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        assert!(
            kernel
                .adjudicate(&valid_action(&actor), &valid_context(&actor))
                .is_permitted()
        );
    }

    #[test]
    fn cp4_human_override_denies() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        let mut ctx = valid_context(&actor);
        ctx.human_override_preserved = false;
        assert!(kernel.adjudicate(&valid_action(&actor), &ctx).is_denied());
    }

    #[test]
    fn cp4_human_override_permits() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        assert!(
            kernel
                .adjudicate(&valid_action(&actor), &valid_context(&actor))
                .is_permitted()
        );
    }

    #[test]
    fn cp5_kernel_immutability_denies() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        let mut action = valid_action(&actor);
        action.modifies_kernel = true;
        assert!(
            kernel
                .adjudicate(&action, &valid_context(&actor))
                .is_denied()
        );
    }

    #[test]
    fn cp5_kernel_immutability_permits() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        assert!(
            kernel
                .adjudicate(&valid_action(&actor), &valid_context(&actor))
                .is_permitted()
        );
    }

    #[test]
    fn escalation_for_quorum_violation() {
        let kernel = test_kernel();
        let actor = did("did:exo:actor1");
        let mut ctx = valid_context(&actor);
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 3,
            votes: vec![
                QuorumVote {
                    voter: did("did:exo:v1"),
                    approved: true,
                    signature: vec![1],
                    provenance: None,
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: false,
                    signature: vec![2],
                    provenance: None,
                },
            ],
        });
        match kernel.adjudicate(&valid_action(&actor), &ctx) {
            Verdict::Escalated { reason } => assert!(reason.contains("Quorum")),
            other => panic!("Expected Escalated, got {:?}", other),
        }
    }

    #[test]
    fn verdict_helpers() {
        assert!(Verdict::Permitted.is_permitted());
        assert!(!Verdict::Permitted.is_denied());
        let denied = Verdict::Denied { violations: vec![] };
        assert!(denied.is_denied());
        assert!(!denied.is_permitted());
    }

    #[test]
    fn kernel_engine_accessor() {
        assert_eq!(
            test_kernel()
                .invariant_engine()
                .invariant_set
                .invariants
                .len(),
            8
        );
    }

    // -----------------------------------------------------------------------
    // WO-009: No-Admin Preservation
    //
    // CR-001 §8.9 — "No admins is ratified as a definitional guardrail."
    // Any implementation shortcut creating a de facto admin bypass of AEGIS
    // SHALL be prohibited.
    //
    // Audit finding (2026-03-30): no bypass paths found in any crate.
    // Kernel::adjudicate is the single adjudication codepath.  The tests
    // below explicitly verify that known escalation patterns — inflated
    // permissions, multi-branch roles, empty authority chains, suppressed
    // human oversight, and kernel modification attempts — are all denied.
    // -----------------------------------------------------------------------
    mod no_admin_bypass {
        use super::*;

        /// WO-009 §1: The gateway dev-scaffold context (BailmentState::None +
        /// empty AuthorityChain) MUST be denied.  It is NOT a bypass path.
        #[test]
        fn dev_scaffold_context_is_deny_all() {
            let kernel = test_kernel();
            let actor = did("did:exo:any-actor");
            let scaffold_ctx = AdjudicationContext {
                actor_roles: vec![],
                authority_chain: AuthorityChain::default(),
                consent_records: vec![],
                bailment_state: BailmentState::None,
                human_override_preserved: true,
                actor_permissions: PermissionSet::new(vec![Permission::new("vote")]),
                provenance: None,
                quorum_evidence: None,
                active_challenge_reason: None,
            };
            assert!(
                kernel
                    .adjudicate(&valid_action(&actor), &scaffold_ctx)
                    .is_denied(),
                "WO-009: dev-scaffold context must be denied — BailmentState::None \
                 fails ConsentRequired invariant"
            );
        }

        /// WO-009 §2: Holding all three constitutional branches simultaneously
        /// is denied by SeparationOfPowers.  No omnipotent admin role exists.
        #[test]
        fn all_government_branches_simultaneously_denied() {
            let kernel = test_kernel();
            let actor = did("did:exo:multi-branch-admin");
            let mut ctx = valid_context(&actor);
            ctx.actor_roles = vec![
                Role {
                    name: "executive-admin".into(),
                    branch: GovernmentBranch::Executive,
                },
                Role {
                    name: "legislator".into(),
                    branch: GovernmentBranch::Legislative,
                },
                Role {
                    name: "judge".into(),
                    branch: GovernmentBranch::Judicial,
                },
            ];
            assert!(
                kernel.adjudicate(&valid_action(&actor), &ctx).is_denied(),
                "WO-009: omnipotent multi-branch actor must be denied by SeparationOfPowers"
            );
        }

        /// WO-009 §3: Inflated permission sets cannot override ConsentRequired.
        /// No permission label — including "admin" or "override" — bypasses
        /// bailment enforcement.
        #[test]
        fn maximum_permissions_cannot_bypass_consent() {
            let kernel = test_kernel();
            let actor = did("did:exo:permission-inflated");
            let mut ctx = valid_context(&actor);
            ctx.actor_permissions = PermissionSet::new(vec![
                Permission::new("read"),
                Permission::new("write"),
                Permission::new("admin"),
                Permission::new("execute"),
                Permission::new("override"),
            ]);
            ctx.bailment_state = BailmentState::None;
            assert!(
                kernel.adjudicate(&valid_action(&actor), &ctx).is_denied(),
                "WO-009: inflated permission set must not bypass ConsentRequired invariant"
            );
        }

        /// WO-009 §4: An empty authority chain is never permitted, even when all
        /// other context fields are valid.  Per kernel escalation rules, an
        /// isolated AuthorityChainValid violation escalates (not denies) — the
        /// important WO-009 guarantee is that it is NOT `Permitted`.
        #[test]
        fn empty_authority_chain_not_permitted() {
            let kernel = test_kernel();
            let actor = did("did:exo:no-chain");
            let mut ctx = valid_context(&actor);
            ctx.authority_chain = AuthorityChain::default();
            let verdict = kernel.adjudicate(&valid_action(&actor), &ctx);
            assert!(
                !verdict.is_permitted(),
                "WO-009: empty authority chain must not be permitted \
                 (escalated or denied, never Permitted)"
            );
        }

        /// WO-009 §5: human_override_preserved = false is always denied.
        /// No admin path can suppress human oversight of AEGIS.
        #[test]
        fn human_override_suppression_is_non_bypassable() {
            let kernel = test_kernel();
            let actor = did("did:exo:override-suppressor");
            let mut ctx = valid_context(&actor);
            ctx.human_override_preserved = false;
            assert!(
                kernel.adjudicate(&valid_action(&actor), &ctx).is_denied(),
                "WO-009: human override suppression must always be denied by HumanOverride"
            );
        }

        /// WO-009 §6: modifies_kernel = true is always denied.
        /// Kernel immutability is unconditional — no escalation path exists.
        #[test]
        fn kernel_modification_always_denied() {
            let kernel = test_kernel();
            let actor = did("did:exo:kernel-patcher");
            let mut action = valid_action(&actor);
            action.modifies_kernel = true;
            assert!(
                kernel
                    .adjudicate(&action, &valid_context(&actor))
                    .is_denied(),
                "WO-009: modifies_kernel must always be denied by KernelImmutability"
            );
        }
    }

    // -----------------------------------------------------------------------
    // WO-005: Challenge paths — contested actions return Escalated, not Denied
    // CR-001 §8.5 — any active Sybil challenge hold pauses the action.
    // -----------------------------------------------------------------------
    mod challenge_paths {
        use super::*;

        /// WO-005: An action under an active Sybil challenge returns
        /// Verdict::Escalated so it is paused (not denied) pending review.
        #[test]
        fn active_challenge_escalates_not_denies() {
            let kernel = test_kernel();
            let actor = did("did:exo:actor1");
            let mut ctx = valid_context(&actor);
            ctx.active_challenge_reason =
                Some("SybilChallenge/CoordinatedManipulation: action under review".into());
            match kernel.adjudicate(&valid_action(&actor), &ctx) {
                Verdict::Escalated { reason } => {
                    assert!(
                        reason.contains("SybilChallenge"),
                        "escalation reason must identify the challenge"
                    );
                }
                other => panic!(
                    "WO-005: active challenge must produce Escalated, got {:?}",
                    other
                ),
            }
        }

        /// WO-005: Without a challenge, the same context produces Permitted.
        #[test]
        fn no_challenge_is_not_escalated() {
            let kernel = test_kernel();
            let actor = did("did:exo:actor1");
            let ctx = valid_context(&actor);
            assert!(
                kernel
                    .adjudicate(&valid_action(&actor), &ctx)
                    .is_permitted(),
                "WO-005: no active challenge must not cause escalation"
            );
        }

        /// WO-005: Challenge escalation takes priority over invariant checks —
        /// even an otherwise-denied action is escalated (not denied) while
        /// the challenge is pending.
        #[test]
        fn challenge_takes_priority_over_denial() {
            let kernel = test_kernel();
            let actor = did("did:exo:actor1");
            let mut ctx = valid_context(&actor);
            // Would normally be denied (ConsentRequired: BailmentState::None)
            ctx.bailment_state = BailmentState::None;
            ctx.active_challenge_reason =
                Some("SybilChallenge/QuorumContamination: pause-eligible".into());
            match kernel.adjudicate(&valid_action(&actor), &ctx) {
                Verdict::Escalated { .. } => {}
                other => panic!("WO-005: challenge must pre-empt denial, got {:?}", other),
            }
        }
    }
}
