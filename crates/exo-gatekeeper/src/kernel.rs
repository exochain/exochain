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
}

// ---------------------------------------------------------------------------
// Kernel
// ---------------------------------------------------------------------------

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
mod tests {
    use super::*;
    use crate::types::{AuthorityLink, GovernmentBranch, Permission, QuorumVote};

    const CONSTITUTION: &[u8] = b"We the people of the EXOCHAIN...";

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
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
                links: vec![AuthorityLink {
                    grantor: did("did:exo:root"),
                    grantee: actor.clone(),
                    permissions: PermissionSet::new(vec![Permission::new("read")]),
                    signature: vec![1, 2, 3],
                    grantor_public_key: None,
                }],
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
            provenance: Some(Provenance {
                actor: actor.clone(),
                timestamp: "2025-01-01T00:00:00Z".into(),
                action_hash: vec![1, 2, 3],
                signature: vec![4, 5, 6],
            }),
            quorum_evidence: None,
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
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: false,
                    signature: vec![2],
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
}
