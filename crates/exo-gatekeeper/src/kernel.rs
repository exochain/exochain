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

//! CGR (Constitutional Governance Runtime) Kernel.
//!
//! The kernel is immutable after initialization. It holds the invariant set
//! and constitution hash, and adjudicates every action request.

use exo_core::{
    Did, ExoError,
    bcts::{BctsTransitionAdjudicator, BctsTransitionRequest},
};
use serde::{Deserialize, Serialize};

use crate::{
    invariants::{
        ConstitutionalInvariant, InvariantContext, InvariantEngine, InvariantSet,
        InvariantViolation, enforce_all,
    },
    types::{
        AuthorityChain, BailmentState, ConsentRecord, PermissionSet, Provenance, QuorumEvidence,
        Role, TrustedAuthorityKeys, TrustedProvenanceKeys,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicationContext {
    pub actor_roles: Vec<Role>,
    pub authority_chain: AuthorityChain,
    pub consent_records: Vec<ConsentRecord>,
    pub bailment_state: BailmentState,
    pub human_override_preserved: bool,
    pub actor_permissions: PermissionSet,
    pub trusted_authority_keys: TrustedAuthorityKeys,
    pub trusted_provenance_keys: TrustedProvenanceKeys,
    pub provenance: Option<Provenance>,
    pub quorum_evidence: Option<QuorumEvidence>,
    /// When set, the action is under an active Sybil challenge hold.
    /// The kernel can pause otherwise valid or reviewable authority/quorum
    /// cases as `Verdict::Escalated`, but final constitutional denials still
    /// win after invariant checks run.
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
            trusted_authority_keys: context.trusted_authority_keys.clone(),
            trusted_provenance_keys: context.trusted_provenance_keys.clone(),
        };

        match enforce_all(&self.invariant_engine, &inv_ctx) {
            Ok(()) => match &context.active_challenge_reason {
                Some(reason) => Verdict::Escalated {
                    reason: reason.clone(),
                },
                None => Verdict::Permitted,
            },
            Err(violations) => {
                if let Some(reason) = &context.active_challenge_reason {
                    if violations.iter().all(is_challenge_pause_eligible) {
                        return Verdict::Escalated {
                            reason: reason.clone(),
                        };
                    }
                }
                verdict_for_violations(violations)
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

fn is_challenge_pause_eligible(violation: &InvariantViolation) -> bool {
    matches!(
        violation.invariant,
        ConstitutionalInvariant::QuorumLegitimate | ConstitutionalInvariant::AuthorityChainValid
    )
}

fn verdict_for_violations(violations: Vec<InvariantViolation>) -> Verdict {
    let needs_escalation = violations.iter().any(is_challenge_pause_eligible);
    if needs_escalation && violations.len() == 1 {
        Verdict::Escalated {
            reason: violations[0].description.clone(),
        }
    } else {
        Verdict::Denied { violations }
    }
}

/// Adapter that binds a BCTS transition boundary to a concrete kernel
/// adjudication request and context.
pub struct KernelBctsAdjudicator<'a> {
    kernel: &'a Kernel,
    action: &'a ActionRequest,
    context: &'a AdjudicationContext,
}

impl<'a> KernelBctsAdjudicator<'a> {
    #[must_use]
    pub fn new(
        kernel: &'a Kernel,
        action: &'a ActionRequest,
        context: &'a AdjudicationContext,
    ) -> Self {
        Self {
            kernel,
            action,
            context,
        }
    }
}

impl BctsTransitionAdjudicator for KernelBctsAdjudicator<'_> {
    fn adjudicate_transition(&self, request: &BctsTransitionRequest) -> exo_core::Result<()> {
        if self.action.actor != request.actor_did {
            return Err(ExoError::InvariantViolation {
                description: format!(
                    "BCTS transition actor {} does not match adjudicated action actor {}",
                    request.actor_did, self.action.actor
                ),
            });
        }

        match self.kernel.adjudicate(self.action, self.context) {
            Verdict::Permitted => Ok(()),
            Verdict::Denied { violations } => {
                let reason = violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant.id(), v.description))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(ExoError::InvariantViolation {
                    description: format!("BCTS transition denied by kernel: {reason}"),
                })
            }
            Verdict::Escalated { reason } => Err(ExoError::InvariantViolation {
                description: format!("BCTS transition escalated by kernel: {reason}"),
            }),
        }
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
        types::{
            AuthorityLink, GovernmentBranch, Permission, QuorumVote, TrustedAuthorityKeys,
            TrustedProvenanceKeys,
        },
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

    fn signed_provenance(actor: &Did) -> (Provenance, exo_core::PublicKey) {
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
        (provenance, pk)
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
        let authority_chain = AuthorityChain {
            links: vec![signed_link("did:exo:root", actor)],
        };
        let mut trusted_authority_keys = TrustedAuthorityKeys::default();
        for link in &authority_chain.links {
            if let Some(public_key) = &link.grantor_public_key {
                trusted_authority_keys.insert(link.grantor.clone(), vec![public_key.clone()]);
            }
        }
        let (provenance, provenance_public_key) = signed_provenance(actor);
        let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
        trusted_provenance_keys.insert(
            actor.clone(),
            vec![provenance_public_key.as_bytes().to_vec()],
        );
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "judge".into(),
                branch: GovernmentBranch::Judicial,
            }],
            authority_chain,
            consent_records: vec![ConsentRecord {
                subject: did("did:exo:bailor"),
                granted_to: actor.clone(),
                scope: "data:read".into(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor: did("did:exo:bailor"),
                bailee: actor.clone(),
                scope: "data:read".into(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
            trusted_authority_keys,
            trusted_provenance_keys,
            provenance: Some(provenance),
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
                name: "senator".into(),
                branch: GovernmentBranch::Legislative,
            },
            Role {
                name: "judge".into(),
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
                trusted_authority_keys: TrustedAuthorityKeys::default(),
                trusted_provenance_keys: TrustedProvenanceKeys::default(),
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

        /// F-010: required permissions must be backed by the actor context and
        /// by the signed authority chain, not merely supplied on the action.
        #[test]
        fn missing_required_permission_not_permitted() {
            let kernel = test_kernel();
            let actor = did("did:exo:scope-mismatch");
            let mut action = valid_action(&actor);
            action.required_permissions = PermissionSet::new(vec![Permission::new("advance_pace")]);
            let verdict = kernel.adjudicate(&action, &valid_context(&actor));
            assert!(
                !verdict.is_permitted(),
                "F-010: requested permission absent from authority evidence must not be permitted"
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
    // WO-005: Challenge paths — active Sybil holds pause reviewable actions
    // without suppressing final constitutional denials.
    // -----------------------------------------------------------------------
    mod challenge_paths {
        use super::*;

        /// WO-005: An otherwise valid action under an active Sybil challenge
        /// returns Verdict::Escalated so it is paused pending review.
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

        /// WO-005: Challenge escalation can pause reviewable authority-chain
        /// failures while the challenge is pending.
        #[test]
        fn challenge_can_pause_authority_chain_review() {
            let kernel = test_kernel();
            let actor = did("did:exo:actor1");
            let mut ctx = valid_context(&actor);
            ctx.authority_chain = AuthorityChain::default();
            ctx.active_challenge_reason =
                Some("SybilChallenge/QuorumContamination: pause-eligible".into());
            match kernel.adjudicate(&valid_action(&actor), &ctx) {
                Verdict::Escalated { .. } => {}
                other => panic!(
                    "WO-005: challenge must pause authority review, got {:?}",
                    other
                ),
            }
        }

        /// Challenge holds must not suppress final constitutional denials.
        #[test]
        fn challenge_does_not_override_kernel_modification_denial() {
            let kernel = test_kernel();
            let actor = did("did:exo:actor1");
            let mut action = valid_action(&actor);
            action.modifies_kernel = true;
            let mut ctx = valid_context(&actor);
            ctx.active_challenge_reason =
                Some("SybilChallenge/KernelPatch: action under review".into());
            match kernel.adjudicate(&action, &ctx) {
                Verdict::Denied { violations } => assert!(
                    violations
                        .iter()
                        .any(|v| v.invariant == ConstitutionalInvariant::KernelImmutability),
                    "kernel modification denial must be preserved: {violations:?}"
                ),
                other => panic!(
                    "WO-005: challenge must not suppress KernelImmutability denial, got {:?}",
                    other
                ),
            }
        }

        /// Human override suppression is a final denial even when another
        /// challenge is active.
        #[test]
        fn challenge_does_not_override_human_override_denial() {
            let kernel = test_kernel();
            let actor = did("did:exo:actor1");
            let mut ctx = valid_context(&actor);
            ctx.human_override_preserved = false;
            ctx.active_challenge_reason =
                Some("SybilChallenge/HumanOverride: action under review".into());
            match kernel.adjudicate(&valid_action(&actor), &ctx) {
                Verdict::Denied { violations } => assert!(
                    violations
                        .iter()
                        .any(|v| v.invariant == ConstitutionalInvariant::HumanOverride),
                    "human override denial must be preserved: {violations:?}"
                ),
                other => panic!(
                    "WO-005: challenge must not suppress HumanOverride denial, got {:?}",
                    other
                ),
            }
        }
    }
}
