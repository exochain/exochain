//! Invariant enforcement engine.
//!
//! Every action in the constitutional fabric must satisfy a set of invariants.
//! Failed invariants produce detailed violation reports with evidence.

use exo_core::{Did, Hash256};
use serde::{Deserialize, Serialize};

use crate::types::{
    AuthorityChain, BailmentState, ConsentRecord, GovernmentBranch, PermissionSet, Provenance,
    QuorumEvidence, Role,
};

// ---------------------------------------------------------------------------
// Constitutional invariant definitions
// ---------------------------------------------------------------------------

/// The set of constitutional invariants enforced by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstitutionalInvariant {
    /// No single actor may hold legislative + executive + judicial power.
    SeparationOfPowers,
    /// Action denied without active bailment consent.
    ConsentRequired,
    /// An actor cannot expand its own permissions.
    NoSelfGrant,
    /// Emergency human intervention must always be possible.
    HumanOverride,
    /// Kernel configuration cannot be modified after creation.
    KernelImmutability,
    /// Authority chain must be valid and unbroken.
    AuthorityChainValid,
    /// Quorum decisions must meet threshold requirements.
    QuorumLegitimate,
    /// All actions must have verifiable provenance.
    ProvenanceVerifiable,
}

/// Complete set of invariants to enforce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantSet {
    pub invariants: Vec<ConstitutionalInvariant>,
}

impl InvariantSet {
    #[must_use]
    pub fn all() -> Self {
        Self {
            invariants: vec![
                ConstitutionalInvariant::SeparationOfPowers,
                ConstitutionalInvariant::ConsentRequired,
                ConstitutionalInvariant::NoSelfGrant,
                ConstitutionalInvariant::HumanOverride,
                ConstitutionalInvariant::KernelImmutability,
                ConstitutionalInvariant::AuthorityChainValid,
                ConstitutionalInvariant::QuorumLegitimate,
                ConstitutionalInvariant::ProvenanceVerifiable,
            ],
        }
    }

    #[must_use]
    pub fn with(invariants: Vec<ConstitutionalInvariant>) -> Self {
        Self { invariants }
    }
}

// ---------------------------------------------------------------------------
// Invariant context
// ---------------------------------------------------------------------------

/// Context provided to the invariant engine for checking.
#[derive(Debug, Clone)]
pub struct InvariantContext {
    pub actor: Did,
    pub actor_roles: Vec<Role>,
    pub bailment_state: BailmentState,
    pub consent_records: Vec<ConsentRecord>,
    pub authority_chain: AuthorityChain,
    pub is_self_grant: bool,
    pub human_override_preserved: bool,
    pub kernel_modification_attempted: bool,
    pub quorum_evidence: Option<QuorumEvidence>,
    pub provenance: Option<Provenance>,
    pub actor_permissions: PermissionSet,
    pub requested_permissions: PermissionSet,
}

// ---------------------------------------------------------------------------
// Invariant violation
// ---------------------------------------------------------------------------

/// A detailed report of an invariant violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant: ConstitutionalInvariant,
    pub description: String,
    pub evidence: Vec<String>,
}

// ---------------------------------------------------------------------------
// Invariant engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InvariantEngine {
    pub invariant_set: InvariantSet,
}

impl InvariantEngine {
    #[must_use]
    pub fn new(invariant_set: InvariantSet) -> Self {
        Self { invariant_set }
    }

    #[must_use]
    pub fn all() -> Self {
        Self::new(InvariantSet::all())
    }
}

/// Enforce all invariants. Returns Ok(()) if all pass.
pub fn enforce_all(
    engine: &InvariantEngine,
    context: &InvariantContext,
) -> Result<(), Vec<InvariantViolation>> {
    let mut violations = Vec::new();
    for invariant in &engine.invariant_set.invariants {
        if let Err(v) = check_invariant(*invariant, context) {
            violations.push(v);
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn check_invariant(
    invariant: ConstitutionalInvariant,
    context: &InvariantContext,
) -> Result<(), InvariantViolation> {
    match invariant {
        ConstitutionalInvariant::SeparationOfPowers => check_separation_of_powers(context),
        ConstitutionalInvariant::ConsentRequired => check_consent_required(context),
        ConstitutionalInvariant::NoSelfGrant => check_no_self_grant(context),
        ConstitutionalInvariant::HumanOverride => check_human_override(context),
        ConstitutionalInvariant::KernelImmutability => check_kernel_immutability(context),
        ConstitutionalInvariant::AuthorityChainValid => check_authority_chain_valid(context),
        ConstitutionalInvariant::QuorumLegitimate => check_quorum_legitimate(context),
        ConstitutionalInvariant::ProvenanceVerifiable => check_provenance_verifiable(context),
    }
}

fn check_separation_of_powers(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    let mut branches = std::collections::HashSet::new();
    for role in &ctx.actor_roles {
        branches.insert(role.branch);
    }
    if branches.contains(&GovernmentBranch::Legislative)
        && branches.contains(&GovernmentBranch::Executive)
        && branches.contains(&GovernmentBranch::Judicial)
    {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::SeparationOfPowers,
            description: "Actor holds roles in all three branches of government".into(),
            evidence: vec![
                format!("actor: {}", ctx.actor),
                format!("roles: {:?}", ctx.actor_roles),
            ],
        });
    }
    if branches.len() > 1 {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::SeparationOfPowers,
            description: "Actor holds roles in multiple branches of government".into(),
            evidence: vec![
                format!("actor: {}", ctx.actor),
                format!("branches: {:?}", branches),
            ],
        });
    }
    Ok(())
}

fn check_consent_required(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    if !ctx.bailment_state.is_active() {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::ConsentRequired,
            description: "No active bailment for this action".into(),
            evidence: vec![format!("bailment_state: {:?}", ctx.bailment_state)],
        });
    }
    let has_active = ctx
        .consent_records
        .iter()
        .any(|c| c.granted_to == ctx.actor && c.active);
    if !has_active {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::ConsentRequired,
            description: "No active consent record for actor".into(),
            evidence: vec![
                format!("actor: {}", ctx.actor),
                format!("records: {}", ctx.consent_records.len()),
            ],
        });
    }
    Ok(())
}

fn check_no_self_grant(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    if ctx.is_self_grant {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::NoSelfGrant,
            description: "Actor attempted to expand own permissions".into(),
            evidence: vec![format!("actor: {}", ctx.actor)],
        });
    }
    Ok(())
}

fn check_human_override(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    if !ctx.human_override_preserved {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::HumanOverride,
            description: "Human override capability is not preserved".into(),
            evidence: vec!["human_override_preserved: false".into()],
        });
    }
    Ok(())
}

fn check_kernel_immutability(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    if ctx.kernel_modification_attempted {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::KernelImmutability,
            description: "Attempted to modify immutable kernel configuration".into(),
            evidence: vec!["kernel_modification_attempted: true".into()],
        });
    }
    Ok(())
}

fn check_authority_chain_valid(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    if ctx.authority_chain.is_empty() {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::AuthorityChainValid,
            description: "Authority chain is empty — no delegation path".into(),
            evidence: vec!["authority_chain: empty".into()],
        });
    }
    let links = &ctx.authority_chain.links;

    // Topology: each link's grantee must be the next link's grantor.
    for i in 0..links.len().saturating_sub(1) {
        if links[i].grantee != links[i + 1].grantor {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: "Authority chain is broken — delegation gap".into(),
                evidence: vec![
                    format!("link[{}].grantee: {}", i, links[i].grantee),
                    format!("link[{}].grantor: {}", i + 1, links[i + 1].grantor),
                ],
            });
        }
    }

    // Terminal link must end at the actor.
    if let Some(last) = links.last() {
        if last.grantee != ctx.actor {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: "Authority chain does not terminate at actor".into(),
                evidence: vec![
                    format!("terminal: {}", last.grantee),
                    format!("actor: {}", ctx.actor),
                ],
            });
        }
    }

    // TNC-01: Cryptographic signature verification (if grantor_public_key is provided).
    // For each link that carries a public key, verify the Ed25519 signature over the
    // canonical payload: Hash256(grantor_bytes || 0x00 || grantee_bytes || 0x00 ||
    // permission_bytes).  Links without a public key fall back to non-emptiness check.
    for (idx, link) in links.iter().enumerate() {
        match &link.grantor_public_key {
            Some(pk_bytes) => {
                // Validate key length.
                let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
                    InvariantViolation {
                        invariant: ConstitutionalInvariant::AuthorityChainValid,
                        description: format!(
                            "link[{idx}] grantor_public_key is not 32 bytes"
                        ),
                        evidence: vec![format!("key_len: {}", pk_bytes.len())],
                    }
                })?;

                // Validate signature length.
                let sig_arr: [u8; 64] = link.signature.as_slice().try_into().map_err(|_| {
                    InvariantViolation {
                        invariant: ConstitutionalInvariant::AuthorityChainValid,
                        description: format!(
                            "link[{idx}] signature is not 64 bytes (required for Ed25519)"
                        ),
                        evidence: vec![format!("sig_len: {}", link.signature.len())],
                    }
                })?;

                // Compute canonical payload.
                let mut payload = Vec::new();
                payload.extend_from_slice(link.grantor.as_str().as_bytes());
                payload.push(0x00);
                payload.extend_from_slice(link.grantee.as_str().as_bytes());
                payload.push(0x00);
                for perm in &link.permissions.permissions {
                    payload.extend_from_slice(perm.0.as_bytes());
                    payload.push(0x00);
                }
                let message = Hash256::digest(&payload);

                let pubkey = exo_core::PublicKey::from_bytes(pk_arr);
                let sig = exo_core::Signature::from_bytes(sig_arr);

                if !exo_core::crypto::verify(message.as_bytes(), &sig, &pubkey) {
                    return Err(InvariantViolation {
                        invariant: ConstitutionalInvariant::AuthorityChainValid,
                        description: format!(
                            "link[{idx}] Ed25519 signature is cryptographically invalid"
                        ),
                        evidence: vec![
                            format!("grantor: {}", link.grantor),
                            format!("grantee: {}", link.grantee),
                        ],
                    });
                }
            }
            None => {
                // Legacy: at minimum the signature must be non-empty.
                if link.signature.is_empty() {
                    return Err(InvariantViolation {
                        invariant: ConstitutionalInvariant::AuthorityChainValid,
                        description: format!("link[{idx}] has empty signature"),
                        evidence: vec![format!("grantor: {}", link.grantor)],
                    });
                }
            }
        }
    }

    Ok(())
}

fn check_quorum_legitimate(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    match &ctx.quorum_evidence {
        None => Ok(()),
        Some(evidence) => {
            if !evidence.is_met() {
                let approvals = evidence.votes.iter().filter(|v| v.approved).count();
                Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::QuorumLegitimate,
                    description: "Quorum threshold not met".into(),
                    evidence: vec![
                        format!("threshold: {}", evidence.threshold),
                        format!("approvals: {}", approvals),
                    ],
                })
            } else {
                Ok(())
            }
        }
    }
}

fn check_provenance_verifiable(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    match &ctx.provenance {
        None => Err(InvariantViolation {
            invariant: ConstitutionalInvariant::ProvenanceVerifiable,
            description: "No provenance metadata provided".into(),
            evidence: vec!["provenance: None".into()],
        }),
        Some(prov) => {
            if !prov.is_signed() {
                return Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                    description: "Provenance metadata is not signed".into(),
                    evidence: vec![format!("actor: {}", prov.actor)],
                });
            }
            if prov.actor != ctx.actor {
                return Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                    description: "Provenance actor does not match request actor".into(),
                    evidence: vec![
                        format!("provenance.actor: {}", prov.actor),
                        format!("context.actor: {}", ctx.actor),
                    ],
                });
            }
            Ok(())
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthorityLink, Permission, QuorumVote};
    use exo_core::Hash256;

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    fn passing_context() -> InvariantContext {
        let actor = did("did:exo:actor1");
        InvariantContext {
            actor: actor.clone(),
            actor_roles: vec![Role {
                name: "judge".into(),
                branch: GovernmentBranch::Judicial,
            }],
            bailment_state: BailmentState::Active {
                bailor: did("did:exo:bailor"),
                bailee: actor.clone(),
                scope: "data:medical".into(),
            },
            consent_records: vec![ConsentRecord {
                subject: did("did:exo:bailor"),
                granted_to: actor.clone(),
                scope: "data:medical".into(),
                active: true,
            }],
            authority_chain: AuthorityChain {
                links: vec![AuthorityLink {
                    grantor: did("did:exo:root"),
                    grantee: actor.clone(),
                    permissions: PermissionSet::new(vec![Permission::new("read")]),
                    signature: vec![1, 2, 3],
                }],
            },
            is_self_grant: false,
            human_override_preserved: true,
            kernel_modification_attempted: false,
            quorum_evidence: None,
            provenance: Some(Provenance {
                actor: actor.clone(),
                timestamp: "2025-01-01T00:00:00Z".into(),
                action_hash: vec![1, 2, 3],
                signature: vec![4, 5, 6],
            }),
            actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
            requested_permissions: PermissionSet::default(),
        }
    }

    #[test]
    fn all_invariants_pass() {
        let engine = InvariantEngine::all();
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn separation_fails_multi_branch() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::SeparationOfPowers,
        ]));
        let mut ctx = passing_context();
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
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn separation_fails_all_three() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::SeparationOfPowers,
        ]));
        let mut ctx = passing_context();
        ctx.actor_roles = vec![
            Role {
                name: "s".into(),
                branch: GovernmentBranch::Legislative,
            },
            Role {
                name: "g".into(),
                branch: GovernmentBranch::Executive,
            },
            Role {
                name: "j".into(),
                branch: GovernmentBranch::Judicial,
            },
        ];
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn separation_passes_single_branch() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::SeparationOfPowers,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn consent_fails_no_bailment() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.bailment_state = BailmentState::None;
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert_eq!(err[0].invariant, ConstitutionalInvariant::ConsentRequired);
    }

    #[test]
    fn consent_fails_inactive_record() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.consent_records[0].active = false;
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn consent_fails_wrong_grantee() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.consent_records[0].granted_to = did("did:exo:other");
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn consent_passes() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn consent_fails_suspended() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.bailment_state = BailmentState::Suspended {
            reason: "audit".into(),
        };
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn consent_fails_terminated() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.bailment_state = BailmentState::Terminated;
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn no_self_grant_fails() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::NoSelfGrant,
        ]));
        let mut ctx = passing_context();
        ctx.is_self_grant = true;
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn no_self_grant_passes() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::NoSelfGrant,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn human_override_fails() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::HumanOverride,
        ]));
        let mut ctx = passing_context();
        ctx.human_override_preserved = false;
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn human_override_passes() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::HumanOverride,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn kernel_immutability_fails() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::KernelImmutability,
        ]));
        let mut ctx = passing_context();
        ctx.kernel_modification_attempted = true;
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn kernel_immutability_passes() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::KernelImmutability,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn authority_chain_fails_empty() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.authority_chain = AuthorityChain::default();
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn authority_chain_fails_broken() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.authority_chain = AuthorityChain {
            links: vec![
                AuthorityLink {
                    grantor: did("did:exo:root"),
                    grantee: did("did:exo:mid"),
                    permissions: PermissionSet::default(),
                    signature: vec![1],
                },
                AuthorityLink {
                    grantor: did("did:exo:WRONG"),
                    grantee: ctx.actor.clone(),
                    permissions: PermissionSet::default(),
                    signature: vec![2],
                },
            ],
        };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("broken"));
    }

    #[test]
    fn authority_chain_fails_wrong_terminal() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.authority_chain = AuthorityChain {
            links: vec![AuthorityLink {
                grantor: did("did:exo:root"),
                grantee: did("did:exo:other"),
                permissions: PermissionSet::default(),
                signature: vec![1],
            }],
        };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("terminate"));
    }

    #[test]
    fn authority_chain_passes_valid() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn authority_chain_passes_multi_link() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.authority_chain = AuthorityChain {
            links: vec![
                AuthorityLink {
                    grantor: did("did:exo:root"),
                    grantee: did("did:exo:mid"),
                    permissions: PermissionSet::default(),
                    signature: vec![1],
                },
                AuthorityLink {
                    grantor: did("did:exo:mid"),
                    grantee: ctx.actor.clone(),
                    permissions: PermissionSet::default(),
                    signature: vec![2],
                },
            ],
        };
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn quorum_passes_none() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn quorum_fails_threshold() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        let mut ctx = passing_context();
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
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn quorum_passes_met() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        let mut ctx = passing_context();
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 2,
            votes: vec![
                QuorumVote {
                    voter: did("did:exo:v1"),
                    approved: true,
                    signature: vec![1],
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: true,
                    signature: vec![2],
                },
            ],
        });
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn provenance_fails_missing() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        ctx.provenance = None;
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn provenance_fails_unsigned() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        ctx.provenance = Some(Provenance {
            actor: ctx.actor.clone(),
            timestamp: "t".into(),
            action_hash: vec![1],
            signature: vec![],
        });
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn provenance_fails_actor_mismatch() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        ctx.provenance = Some(Provenance {
            actor: did("did:exo:wrong"),
            timestamp: "t".into(),
            action_hash: vec![1],
            signature: vec![1],
        });
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn provenance_passes() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        assert!(enforce_all(&engine, &passing_context()).is_ok());
    }

    #[test]
    fn multiple_violations_collected() {
        let engine = InvariantEngine::all();
        let mut ctx = passing_context();
        ctx.is_self_grant = true;
        ctx.human_override_preserved = false;
        ctx.kernel_modification_attempted = true;
        let violations = enforce_all(&engine, &ctx).unwrap_err();
        assert!(violations.len() >= 3);
    }

    #[test]
    fn invariant_set_all_count() {
        assert_eq!(InvariantSet::all().invariants.len(), 8);
    }

    #[test]
    fn invariant_set_with_custom() {
        assert_eq!(
            InvariantSet::with(vec![ConstitutionalInvariant::NoSelfGrant])
                .invariants
                .len(),
            1
        );
    }

    #[test]
    fn engine_all_constructor() {
        assert_eq!(InvariantEngine::all().invariant_set.invariants.len(), 8);
    }

    // ── TNC-01: Ed25519 signature verification ───────────────────────────

    /// Build a properly signed AuthorityLink for the given grantor→grantee.
    fn signed_link(grantor_str: &str, grantee_str: &str) -> (AuthorityLink, exo_core::PublicKey) {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = did(grantor_str);
        let grantee = did(grantee_str);
        let perms = PermissionSet::new(vec![Permission::new("read")]);

        // Canonical payload matches invariant engine computation.
        let mut payload = Vec::new();
        payload.extend_from_slice(grantor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(grantee.as_str().as_bytes());
        payload.push(0x00);
        for p in &perms.permissions {
            payload.extend_from_slice(p.0.as_bytes());
            payload.push(0x00);
        }
        let message = Hash256::digest(&payload);
        let sig = exo_core::crypto::sign(message.as_bytes(), &sk);

        let link = AuthorityLink {
            grantor,
            grantee,
            permissions: perms,
            signature: sig.to_bytes().to_vec(),
            grantor_public_key: Some(pk.as_bytes().to_vec()),
        };
        (link, pk)
    }

    #[test]
    fn authority_chain_passes_with_valid_ed25519_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (link, _pk) = signed_link("did:exo:root", "did:exo:actor1");
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn authority_chain_fails_with_tampered_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (mut link, _pk) = signed_link("did:exo:root", "did:exo:actor1");
        // Flip a byte in the signature to corrupt it.
        link.signature[0] ^= 0xFF;
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("cryptographically invalid"));
    }

    #[test]
    fn authority_chain_fails_with_wrong_public_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (mut link, _pk) = signed_link("did:exo:root", "did:exo:actor1");
        // Replace public key with a different one.
        let (other_pk, _other_sk) = exo_core::crypto::generate_keypair();
        link.grantor_public_key = Some(other_pk.as_bytes().to_vec());
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("cryptographically invalid"));
    }

    #[test]
    fn authority_chain_fails_with_malformed_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let mut link = AuthorityLink {
            grantor: did("did:exo:root"),
            grantee: did("did:exo:actor1"),
            permissions: PermissionSet::default(),
            signature: vec![0u8; 64],
            grantor_public_key: Some(vec![0u8; 16]), // wrong length
        };
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("not 32 bytes"));
    }

    #[test]
    fn authority_chain_fails_empty_signature_no_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.authority_chain = AuthorityChain {
            links: vec![AuthorityLink {
                grantor: did("did:exo:root"),
                grantee: did("did:exo:actor1"),
                permissions: PermissionSet::default(),
                signature: vec![], // empty — legacy check fails
                grantor_public_key: None,
            }],
        };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("empty signature"));
    }

    #[test]
    fn authority_chain_passes_multi_link_with_ed25519() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (link1, _) = signed_link("did:exo:root", "did:exo:mid");
        let (link2, _) = signed_link("did:exo:mid", "did:exo:actor1");
        ctx.authority_chain = AuthorityChain {
            links: vec![link1, link2],
        };
        assert!(enforce_all(&engine, &ctx).is_ok());
    }
}
