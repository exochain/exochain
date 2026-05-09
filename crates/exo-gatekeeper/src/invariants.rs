//! Invariant enforcement engine.
//!
//! Every action in the constitutional fabric must satisfy a set of invariants.
//! Failed invariants produce detailed violation reports with evidence.

use exo_core::{Did, Hash256, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::types::{
    AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, PermissionSet,
    Provenance, QuorumEvidence, Role, TrustedAuthorityKeys,
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

impl ConstitutionalInvariant {
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            ConstitutionalInvariant::SeparationOfPowers => "separation-of-powers",
            ConstitutionalInvariant::ConsentRequired => "consent-required",
            ConstitutionalInvariant::NoSelfGrant => "no-self-grant",
            ConstitutionalInvariant::HumanOverride => "human-override",
            ConstitutionalInvariant::KernelImmutability => "kernel-immutability",
            ConstitutionalInvariant::AuthorityChainValid => "authority-chain-valid",
            ConstitutionalInvariant::QuorumLegitimate => "quorum-legitimate",
            ConstitutionalInvariant::ProvenanceVerifiable => "provenance-verifiable",
        }
    }
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
    pub action: String,
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
    pub trusted_authority_keys: TrustedAuthorityKeys,
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

const AUTHORITY_LINK_SIGNATURE_DOMAIN: &str = "exo.gatekeeper.authority-link-signature";
const PROVENANCE_SIGNATURE_DOMAIN: &str = "exo.gatekeeper.provenance-signature";
const SIGNATURE_PAYLOAD_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct AuthorityLinkSignaturePayload<'a> {
    domain: &'static str,
    schema_version: u16,
    grantor: &'a Did,
    grantee: &'a Did,
    permissions: Vec<&'a str>,
}

#[derive(Serialize)]
struct ProvenanceSignaturePayload<'a> {
    domain: &'static str,
    schema_version: u16,
    actor: &'a Did,
    action_hash: &'a [u8],
    timestamp: &'a str,
}

// ---------------------------------------------------------------------------
// Invariant engine
// ---------------------------------------------------------------------------

/// Runtime engine that checks a configured set of constitutional invariants.
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

fn government_branch_label(branch: GovernmentBranch) -> &'static str {
    branch.as_str()
}

fn role_evidence_label(roles: &[Role]) -> String {
    roles
        .iter()
        .map(|role| format!("{}@{}", role.name, government_branch_label(role.branch)))
        .collect::<Vec<_>>()
        .join(",")
}

fn branch_evidence_label(branches: &std::collections::BTreeSet<GovernmentBranch>) -> String {
    branches
        .iter()
        .map(|branch| government_branch_label(*branch))
        .collect::<Vec<_>>()
        .join(",")
}

fn bailment_state_evidence(state: &BailmentState) -> Vec<String> {
    match state {
        BailmentState::None => vec!["bailment_state: none".into()],
        BailmentState::Active {
            bailor,
            bailee,
            scope,
        } => vec![
            "bailment_state: active".into(),
            format!("bailor: {bailor}"),
            format!("bailee: {bailee}"),
            format!("scope: {scope}"),
        ],
        BailmentState::Suspended { reason } => {
            vec![
                "bailment_state: suspended".into(),
                format!("reason: {reason}"),
            ]
        }
        BailmentState::Terminated => vec!["bailment_state: terminated".into()],
    }
}

fn check_separation_of_powers(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    let mut branches = std::collections::BTreeSet::new();
    for (index, role) in ctx.actor_roles.iter().enumerate() {
        if let Err(err) = role.validate_governed() {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::SeparationOfPowers,
                description: err.to_string(),
                evidence: vec![
                    format!("actor: {}", ctx.actor),
                    format!("role_index: {index}"),
                    format!("actual_branch: {}", government_branch_label(role.branch)),
                ],
            });
        }
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
                format!("roles: {}", role_evidence_label(&ctx.actor_roles)),
            ],
        });
    }
    if branches.len() > 1 {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::SeparationOfPowers,
            description: "Actor holds roles in multiple branches of government".into(),
            evidence: vec![
                format!("actor: {}", ctx.actor),
                format!("branches: {}", branch_evidence_label(&branches)),
            ],
        });
    }
    Ok(())
}

fn check_consent_required(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    let (bailor, bailee, bailment_scope) = match &ctx.bailment_state {
        BailmentState::Active {
            bailor,
            bailee,
            scope,
        } => (bailor, bailee, scope),
        _ => {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::ConsentRequired,
                description: "No active bailment for this action".into(),
                evidence: bailment_state_evidence(&ctx.bailment_state),
            });
        }
    };

    if bailee != &ctx.actor {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::ConsentRequired,
            description: "Active bailment bailee does not match action actor".into(),
            evidence: vec![format!("actor: {}", ctx.actor), format!("bailee: {bailee}")],
        });
    }

    if !scope_authorizes_request(bailment_scope, &ctx.action, &ctx.requested_permissions) {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::ConsentRequired,
            description: "Active bailment scope does not authorize requested action".into(),
            evidence: vec![
                format!("action: {}", ctx.action),
                format!("scope: {bailment_scope}"),
            ],
        });
    }

    let has_active = ctx.consent_records.iter().any(|c| {
        c.active && c.granted_to == ctx.actor && c.subject == *bailor && c.scope == *bailment_scope
    });
    if !has_active {
        return Err(InvariantViolation {
            invariant: ConstitutionalInvariant::ConsentRequired,
            description: "No active consent record matching actor, bailor, and scope".into(),
            evidence: vec![
                format!("actor: {}", ctx.actor),
                format!("bailor: {bailor}"),
                format!("scope: {bailment_scope}"),
                format!("records: {}", ctx.consent_records.len()),
            ],
        });
    }
    Ok(())
}

fn scope_authorizes_request(scope: &str, action: &str, requested: &PermissionSet) -> bool {
    let scope = scope.trim();
    if scope.is_empty() {
        return false;
    }

    let action = action.trim();
    if !action.is_empty()
        && (scope == action
            || action.starts_with(scope)
                && action
                    .as_bytes()
                    .get(scope.len())
                    .is_some_and(|separator| matches!(separator, b':' | b'/' | b'.')))
    {
        return true;
    }

    if requested.is_empty() {
        return action.is_empty();
    }

    requested
        .permissions
        .iter()
        .any(|permission| scope_authorizes_permission(scope, permission.0.trim()))
}

fn scope_authorizes_permission(scope: &str, permission: &str) -> bool {
    if permission.is_empty() {
        return false;
    }
    scope == permission
        || scope
            .strip_suffix(permission)
            .is_some_and(|prefix| matches!(prefix.as_bytes().last(), Some(b':' | b'/' | b'.')))
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

    // TNC-01: Cryptographic signature verification.
    // Every link must carry the grantor public key and verify the Ed25519
    // signature over the domain-separated canonical CBOR payload.
    for (idx, link) in links.iter().enumerate() {
        let pk_bytes = link
            .grantor_public_key
            .as_ref()
            .ok_or_else(|| InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: format!("link[{idx}] missing grantor_public_key"),
                evidence: vec![format!("grantor: {}", link.grantor)],
            })?;

        // Validate key length.
        let pk_arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: format!("link[{idx}] grantor_public_key is not 32 bytes"),
                evidence: vec![format!("key_len: {}", pk_bytes.len())],
            })?;

        let trusted_keys = ctx
            .trusted_authority_keys
            .get(&link.grantor)
            .ok_or_else(|| InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: format!(
                    "link[{idx}] grantor_public_key is unresolved for grantor DID"
                ),
                evidence: vec![format!("grantor: {}", link.grantor)],
            })?;

        if !trusted_keys
            .iter()
            .any(|trusted_key| trusted_key.as_slice() == pk_bytes.as_slice())
        {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: format!("link[{idx}] grantor_public_key is not bound to grantor DID"),
                evidence: vec![format!("grantor: {}", link.grantor)],
            });
        }

        // Validate signature length.
        let sig_arr: [u8; 64] =
            link.signature
                .as_slice()
                .try_into()
                .map_err(|_| InvariantViolation {
                    invariant: ConstitutionalInvariant::AuthorityChainValid,
                    description: format!(
                        "link[{idx}] signature is not 64 bytes (required for Ed25519)"
                    ),
                    evidence: vec![format!("sig_len: {}", link.signature.len())],
                })?;

        let message = authority_link_signature_message(link).map_err(|err| InvariantViolation {
            invariant: ConstitutionalInvariant::AuthorityChainValid,
            description: format!("link[{idx}] canonical signature payload could not be encoded"),
            evidence: vec![
                format!("grantor: {}", link.grantor),
                format!("grantee: {}", link.grantee),
                format!("error: {err}"),
            ],
        })?;

        let pubkey = exo_core::PublicKey::from_bytes(pk_arr);
        let sig = exo_core::Signature::from_bytes(sig_arr);

        if !exo_core::crypto::verify(message.as_bytes(), &sig, &pubkey) {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: format!("link[{idx}] Ed25519 signature is cryptographically invalid"),
                evidence: vec![
                    format!("grantor: {}", link.grantor),
                    format!("grantee: {}", link.grantee),
                ],
            });
        }
    }

    for permission in &ctx.requested_permissions.permissions {
        if !ctx.actor_permissions.contains(permission) {
            return Err(InvariantViolation {
                invariant: ConstitutionalInvariant::AuthorityChainValid,
                description: "Requested permission is absent from actor authority context".into(),
                evidence: vec![
                    format!("actor: {}", ctx.actor),
                    format!("requested_permission: {}", permission.0),
                ],
            });
        }

        for (idx, link) in links.iter().enumerate() {
            if !link.permissions.contains(permission) {
                return Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::AuthorityChainValid,
                    description: "Requested permission is absent from authority chain scope".into(),
                    evidence: vec![
                        format!("link_index: {idx}"),
                        format!("grantor: {}", link.grantor),
                        format!("grantee: {}", link.grantee),
                        format!("requested_permission: {}", permission.0),
                    ],
                });
            }
        }
    }

    Ok(())
}

fn check_quorum_legitimate(ctx: &InvariantContext) -> Result<(), InvariantViolation> {
    match &ctx.quorum_evidence {
        None => Ok(()),
        Some(evidence) => {
            let duplicate_voters = evidence.duplicate_voters();
            if !duplicate_voters.is_empty() {
                let duplicate_voters = duplicate_voters
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::QuorumLegitimate,
                    description: "Quorum evidence contains duplicate voter entries".into(),
                    evidence: vec![
                        format!("threshold: {}", evidence.threshold),
                        format!("duplicate_voters: {duplicate_voters}"),
                    ],
                });
            }

            // CR-001 §8.3: synthetic voices SHALL never be counted as distinct
            // humans. Use is_met_authentic() which excludes Synthetic-voiced
            // votes from the approval count.
            if !evidence.is_met_authentic() {
                let authentic_approvals = evidence.distinct_authentic_approved_voter_count();
                let synthetic_excluded = evidence.synthetic_vote_count();
                Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::QuorumLegitimate,
                    description: "Quorum threshold not met by authentic (non-synthetic) votes"
                        .into(),
                    evidence: vec![
                        format!("threshold: {}", evidence.threshold),
                        format!("authentic_approvals: {}", authentic_approvals),
                        format!("synthetic_votes_excluded: {}", synthetic_excluded),
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
            let pk_bytes = prov.public_key.as_ref().ok_or_else(|| InvariantViolation {
                invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                description: "Provenance public_key is required for Ed25519 verification".into(),
                evidence: vec![format!("actor: {}", prov.actor)],
            })?;
            let pk_arr: [u8; 32] =
                pk_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| InvariantViolation {
                        invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                        description: "Provenance public_key is not 32 bytes".into(),
                        evidence: vec![format!("key_len: {}", pk_bytes.len())],
                    })?;
            let sig_arr: [u8; 64] =
                prov.signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| InvariantViolation {
                        invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                        description: "Provenance signature is not 64 bytes (required for Ed25519)"
                            .into(),
                        evidence: vec![format!("sig_len: {}", prov.signature.len())],
                    })?;
            let message = provenance_signature_message(prov).map_err(|err| InvariantViolation {
                invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                description: "Provenance canonical signature payload could not be encoded".into(),
                evidence: vec![format!("actor: {}", prov.actor), format!("error: {err}")],
            })?;
            let pubkey = exo_core::PublicKey::from_bytes(pk_arr);
            let sig = exo_core::Signature::from_bytes(sig_arr);
            if !exo_core::crypto::verify(message.as_bytes(), &sig, &pubkey) {
                return Err(InvariantViolation {
                    invariant: ConstitutionalInvariant::ProvenanceVerifiable,
                    description: "Provenance Ed25519 signature is cryptographically invalid".into(),
                    evidence: vec![format!("actor: {}", prov.actor)],
                });
            }
            Ok(())
        }
    }
}

/// Compute the canonical Ed25519 message for an authority-chain link.
///
/// The message is the hash of a domain-separated CBOR payload. Signers and
/// verifiers must both use this helper so signatures cannot be replayed across
/// other gatekeeper payload types or legacy delimiter-framed encodings.
pub fn authority_link_signature_message(link: &AuthorityLink) -> exo_core::Result<Hash256> {
    let mut permissions = link
        .permissions
        .permissions
        .iter()
        .map(|permission| permission.0.as_str())
        .collect::<Vec<_>>();
    permissions.sort_unstable();

    hash_structured(&AuthorityLinkSignaturePayload {
        domain: AUTHORITY_LINK_SIGNATURE_DOMAIN,
        schema_version: SIGNATURE_PAYLOAD_SCHEMA_VERSION,
        grantor: &link.grantor,
        grantee: &link.grantee,
        permissions,
    })
}

/// Compute the canonical Ed25519 message for action provenance.
///
/// The message is the hash of a domain-separated CBOR payload that binds the
/// provenance actor, action hash, and timestamp.
pub fn provenance_signature_message(prov: &Provenance) -> exo_core::Result<Hash256> {
    hash_structured(&ProvenanceSignaturePayload {
        domain: PROVENANCE_SIGNATURE_DOMAIN,
        schema_version: SIGNATURE_PAYLOAD_SCHEMA_VERSION,
        actor: &prov.actor,
        action_hash: &prov.action_hash,
        timestamp: &prov.timestamp,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use exo_core::Hash256;

    use super::*;
    use crate::types::{
        AuthorityLink, IndependenceClaim, Permission, QuorumVote, ReviewOrder, VoiceKind,
    };

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }

    fn production_source() -> &'static str {
        let source = include_str!("invariants.rs");
        let end = source
            .find("// ===========================================================================")
            .expect("tests section marker must exist");
        &source[..end]
    }

    fn passing_context() -> InvariantContext {
        let actor = did("did:exo:actor1");
        let (authority_link, authority_public_key) = signed_link("did:exo:root", actor.as_str());
        let (provenance, _, _) = signed_provenance(actor.as_str());
        let mut trusted_authority_keys = TrustedAuthorityKeys::default();
        trusted_authority_keys.insert(
            authority_link.grantor.clone(),
            vec![authority_public_key.as_bytes().to_vec()],
        );
        InvariantContext {
            actor: actor.clone(),
            action: "data:medical".into(),
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
                links: vec![authority_link],
            },
            is_self_grant: false,
            human_override_preserved: true,
            kernel_modification_attempted: false,
            quorum_evidence: None,
            provenance: Some(provenance),
            actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
            requested_permissions: PermissionSet::default(),
            trusted_authority_keys,
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
    fn separation_evidence_uses_stable_role_labels() {
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

        let err = enforce_all(&engine, &ctx).expect_err("multi-branch role must fail");
        assert_eq!(
            err[0].evidence,
            vec![
                "actor: did:exo:actor1".to_string(),
                "branches: legislative,judicial".to_string(),
            ]
        );
        assert!(
            err[0]
                .evidence
                .iter()
                .all(|entry| !entry.contains("Role {") && !entry.contains("Legislative")),
            "public evidence must not expose Rust Debug labels"
        );
    }

    #[test]
    fn separation_fails_all_three() {
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
                name: "worker".into(),
                branch: GovernmentBranch::Executive,
            },
            Role {
                name: "judge".into(),
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
    fn separation_rejects_unknown_role_name() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::SeparationOfPowers,
        ]));
        let mut ctx = passing_context();
        ctx.actor_roles = vec![Role {
            name: "root".into(),
            branch: GovernmentBranch::Judicial,
        }];

        let err = enforce_all(&engine, &ctx).expect_err("unknown role name must fail closed");

        assert_eq!(
            err[0].invariant,
            ConstitutionalInvariant::SeparationOfPowers
        );
        assert!(
            err[0].description.contains("unknown governed role name"),
            "unexpected description: {}",
            err[0].description
        );
    }

    #[test]
    fn separation_rejects_role_name_branch_mismatch() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::SeparationOfPowers,
        ]));
        let mut ctx = passing_context();
        ctx.actor_roles = vec![Role {
            name: "judge".into(),
            branch: GovernmentBranch::Executive,
        }];

        let err = enforce_all(&engine, &ctx).expect_err("role name branch mismatch must fail");

        assert_eq!(
            err[0].invariant,
            ConstitutionalInvariant::SeparationOfPowers
        );
        assert!(
            err[0]
                .description
                .contains("does not match governed branch"),
            "unexpected description: {}",
            err[0].description
        );
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
    fn consent_evidence_uses_stable_bailment_state_labels() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.bailment_state = BailmentState::Suspended {
            reason: "audit hold".into(),
        };

        let err = enforce_all(&engine, &ctx).expect_err("suspended bailment must fail");
        assert_eq!(
            err[0].evidence,
            vec![
                "bailment_state: suspended".to_string(),
                "reason: audit hold".to_string(),
            ]
        );
        assert!(
            err[0]
                .evidence
                .iter()
                .all(|entry| !entry.contains("Suspended {")),
            "public evidence must not expose Rust Debug labels"
        );
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
    fn consent_fails_active_bailment_for_different_bailee() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.bailment_state = BailmentState::Active {
            bailor: did("did:exo:bailor"),
            bailee: did("did:exo:other-bailee"),
            scope: "data:medical".into(),
        };

        let err = enforce_all(&engine, &ctx).unwrap_err();

        assert_eq!(err[0].invariant, ConstitutionalInvariant::ConsentRequired);
        assert!(
            err[0].description.contains("bailee"),
            "ConsentRequired must bind active bailment to the action actor: {err:?}"
        );
    }

    #[test]
    fn consent_fails_unrelated_active_scope() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.requested_permissions = PermissionSet::new(vec![Permission::new("advance_pace")]);
        ctx.bailment_state = BailmentState::Active {
            bailor: did("did:exo:bailor"),
            bailee: ctx.actor.clone(),
            scope: "data:vote".into(),
        };
        ctx.consent_records = vec![ConsentRecord {
            subject: did("did:exo:bailor"),
            granted_to: ctx.actor.clone(),
            scope: "data:vote".into(),
            active: true,
        }];

        let err = enforce_all(&engine, &ctx).unwrap_err();

        assert_eq!(err[0].invariant, ConstitutionalInvariant::ConsentRequired);
        assert!(
            err[0].description.contains("scope"),
            "ConsentRequired must bind active consent scope to the requested action: {err:?}"
        );
    }

    #[test]
    fn consent_fails_unrelated_action_without_requested_permissions() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ConsentRequired,
        ]));
        let mut ctx = passing_context();
        ctx.action = "advance_pace".into();
        ctx.requested_permissions = PermissionSet::new(vec![]);

        let err = enforce_all(&engine, &ctx).unwrap_err();

        assert_eq!(err[0].invariant, ConstitutionalInvariant::ConsentRequired);
        assert!(
            err[0].description.contains("scope"),
            "ConsentRequired must bind a non-empty action even when no permission set is provided: {err:?}"
        );
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
                    grantor_public_key: None,
                },
                AuthorityLink {
                    grantor: did("did:exo:WRONG"),
                    grantee: ctx.actor.clone(),
                    permissions: PermissionSet::default(),
                    signature: vec![2],
                    grantor_public_key: None,
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
                grantor_public_key: None,
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
        let (link1, pk1) = signed_link("did:exo:root", "did:exo:mid");
        let (link2, pk2) = signed_link("did:exo:mid", "did:exo:actor1");
        ctx.trusted_authority_keys
            .insert(link1.grantor.clone(), vec![pk1.as_bytes().to_vec()]);
        ctx.trusted_authority_keys
            .insert(link2.grantor.clone(), vec![pk2.as_bytes().to_vec()]);
        ctx.authority_chain = AuthorityChain {
            links: vec![link1, link2],
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
                    provenance: None,
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: true,
                    signature: vec![2],
                    provenance: None,
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
        let (pk, _) = exo_core::crypto::generate_keypair();
        ctx.provenance = Some(Provenance {
            actor: ctx.actor.clone(),
            timestamp: "t".into(),
            action_hash: vec![1],
            signature: vec![],
            public_key: Some(pk.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        });
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    #[test]
    fn provenance_fails_without_public_key_even_with_non_empty_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        ctx.provenance = Some(Provenance {
            actor: ctx.actor.clone(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            action_hash: vec![1],
            signature: vec![7u8; 64],
            public_key: None,
            voice_kind: None,
            independence: None,
            review_order: None,
        });

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("public_key"));
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
            public_key: None,
            voice_kind: None,
            independence: None,
            review_order: None,
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
    fn invariant_ids_are_stable_and_non_debug() {
        let ids: Vec<&str> = InvariantSet::all()
            .invariants
            .iter()
            .map(ConstitutionalInvariant::id)
            .collect();

        assert_eq!(
            ids,
            vec![
                "separation-of-powers",
                "consent-required",
                "no-self-grant",
                "human-override",
                "kernel-immutability",
                "authority-chain-valid",
                "quorum-legitimate",
                "provenance-verifiable",
            ]
        );
        assert!(
            ids.iter()
                .all(|id| !id.contains("Of") && !id.contains("Required")),
            "stable invariant IDs must not mirror Rust Debug variant names"
        );
    }

    #[test]
    fn invariant_production_source_has_no_debug_evidence_formatting() {
        let production = production_source();
        for forbidden in [
            "format!(\"roles: {:?}\"",
            "format!(\"branches: {:?}\"",
            "format!(\"bailment_state: {:?}\"",
        ] {
            assert!(
                !production.contains(forbidden),
                "invariant evidence must use stable labels, not Debug formatting: {forbidden}"
            );
        }
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

    // ── CR-001 §8.3: quorum synthetic-voice exclusion ───────────────────────

    fn make_vote(voter: &str, approved: bool, sig: u8, voice: Option<VoiceKind>) -> QuorumVote {
        QuorumVote {
            voter: did(voter),
            approved,
            signature: vec![sig],
            provenance: voice.map(|vk| Provenance {
                actor: did(voter),
                timestamp: "t".into(),
                action_hash: vec![1],
                signature: vec![sig],
                public_key: None,
                voice_kind: Some(vk),
                independence: None,
                review_order: None,
            }),
        }
    }

    #[test]
    fn quorum_fails_when_synthetic_makes_up_threshold() {
        // 1 human + 2 synthetic approvals, threshold 3 → authentic count = 1 → fail
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        let mut ctx = passing_context();
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 3,
            votes: vec![
                make_vote("did:exo:human1", true, 1, Some(VoiceKind::Human)),
                make_vote("did:exo:ai1", true, 2, Some(VoiceKind::Synthetic)),
                make_vote("did:exo:ai2", true, 3, Some(VoiceKind::Synthetic)),
            ],
        });
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert_eq!(err[0].invariant, ConstitutionalInvariant::QuorumLegitimate);
        assert!(err[0].description.contains("authentic"));
        assert!(
            err[0]
                .evidence
                .iter()
                .any(|e| e.contains("synthetic_votes_excluded: 2"))
        );
    }

    #[test]
    fn quorum_passes_when_humans_meet_threshold_despite_synthetics() {
        // 3 humans approve, 2 synthetics also approve, threshold 3 → passes
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        let mut ctx = passing_context();
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 3,
            votes: vec![
                make_vote("did:exo:h1", true, 1, Some(VoiceKind::Human)),
                make_vote("did:exo:h2", true, 2, Some(VoiceKind::Human)),
                make_vote("did:exo:h3", true, 3, Some(VoiceKind::Human)),
                make_vote("did:exo:ai1", true, 4, Some(VoiceKind::Synthetic)),
                make_vote("did:exo:ai2", true, 5, Some(VoiceKind::Synthetic)),
            ],
        });
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn quorum_legitimate_rejects_duplicate_voter_evidence() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        let mut ctx = passing_context();
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 2,
            votes: vec![
                make_vote("did:exo:h1", true, 1, Some(VoiceKind::Human)),
                make_vote("did:exo:h1", true, 2, Some(VoiceKind::Human)),
                make_vote("did:exo:h2", true, 3, Some(VoiceKind::Human)),
            ],
        });

        let err = enforce_all(&engine, &ctx).unwrap_err();

        assert_eq!(err[0].invariant, ConstitutionalInvariant::QuorumLegitimate);
        assert!(
            err[0].description.contains("duplicate voter"),
            "duplicate voter evidence must be rejected explicitly"
        );
        assert!(
            err[0]
                .evidence
                .iter()
                .any(|entry| entry.contains("did:exo:h1")),
            "violation evidence must identify the duplicated voter"
        );
    }

    #[test]
    fn quorum_passes_legacy_votes_no_provenance() {
        // Legacy votes (provenance=None) are not excluded
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
                    provenance: None,
                },
                QuorumVote {
                    voter: did("did:exo:v2"),
                    approved: true,
                    signature: vec![2],
                    provenance: None,
                },
            ],
        });
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn quorum_fails_all_synthetic_votes() {
        // All approvals are synthetic — threshold 1 → authentic count = 0 → fail
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::QuorumLegitimate,
        ]));
        let mut ctx = passing_context();
        ctx.quorum_evidence = Some(QuorumEvidence {
            threshold: 1,
            votes: vec![
                make_vote("did:exo:ai1", true, 1, Some(VoiceKind::Synthetic)),
                make_vote("did:exo:ai2", true, 2, Some(VoiceKind::Synthetic)),
            ],
        });
        assert!(enforce_all(&engine, &ctx).is_err());
    }

    // ── CR-001 §8.3: Ed25519 provenance verification (WO-003 / GAP-02) ──────

    #[test]
    fn invariant_signature_payloads_do_not_use_raw_delimited_hashing() {
        let source = production_source();

        assert!(
            !source.contains("payload.push(0x00)"),
            "signature payloads must use structured canonical CBOR, not ad hoc null separators"
        );
        assert!(
            !source.contains("Hash256::digest(&payload)"),
            "signature payloads must be hashed through hash_structured"
        );
    }

    #[test]
    fn authority_chain_validation_requires_trusted_grantor_key_resolution() {
        let source = production_source();
        let checker = source
            .split("fn check_authority_chain_valid")
            .nth(1)
            .and_then(|rest| rest.split("fn check_quorum_legitimate").next())
            .expect("AuthorityChainValid checker source must be present");
        let compact_checker = checker
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();

        assert!(
            compact_checker.contains("ctx.trusted_authority_keys"),
            "AuthorityChainValid must consult runtime-resolved trusted grantor keys"
        );
        assert!(
            checker.contains("grantor_public_key is unresolved for grantor DID"),
            "AuthorityChainValid must fail closed when the grantor DID has no resolved key"
        );
        assert!(
            checker.contains("grantor_public_key is not bound to grantor DID"),
            "AuthorityChainValid must reject self-attested keys not bound to the grantor DID"
        );
        assert!(
            compact_checker.find("ctx.trusted_authority_keys").unwrap()
                < compact_checker.find("exo_core::crypto::verify").unwrap(),
            "grantor key binding must be checked before accepting the Ed25519 signature"
        );
    }

    fn signed_provenance(
        actor_str: &str,
    ) -> (Provenance, exo_core::PublicKey, exo_core::SecretKey) {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let actor = did(actor_str);
        let action_hash = vec![0xde, 0xad, 0xbe, 0xef];
        let timestamp = "2026-01-01T00:00:00Z".to_string();
        let mut prov = Provenance {
            actor,
            timestamp,
            action_hash,
            signature: Vec::new(),
            public_key: Some(pk.as_bytes().to_vec()),
            voice_kind: Some(VoiceKind::Human),
            independence: Some(IndependenceClaim::Independent),
            review_order: Some(ReviewOrder::FirstOrder),
        };
        let message = provenance_signature_message(&prov).expect("canonical provenance payload");
        let sig = exo_core::crypto::sign(message.as_bytes(), &sk);
        prov.signature = sig.to_bytes().to_vec();
        (prov, pk, sk)
    }

    #[test]
    fn provenance_passes_valid_ed25519_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        let (prov, _pk, _sk) = signed_provenance("did:exo:actor1");
        ctx.provenance = Some(prov);
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn provenance_fails_tampered_ed25519_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        let (mut prov, _pk, _sk) = signed_provenance("did:exo:actor1");
        prov.signature[0] ^= 0xFF; // corrupt
        ctx.provenance = Some(prov);
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("cryptographically invalid"));
    }

    #[test]
    fn provenance_fails_wrong_public_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        let (mut prov, _pk, _sk) = signed_provenance("did:exo:actor1");
        let (other_pk, _) = exo_core::crypto::generate_keypair();
        prov.public_key = Some(other_pk.as_bytes().to_vec());
        ctx.provenance = Some(prov);
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("cryptographically invalid"));
    }

    #[test]
    fn provenance_fails_malformed_public_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        ctx.provenance = Some(Provenance {
            actor: ctx.actor.clone(),
            timestamp: "t".into(),
            action_hash: vec![1],
            signature: vec![0u8; 64],
            public_key: Some(vec![0u8; 16]), // wrong length
            voice_kind: None,
            independence: None,
            review_order: None,
        });
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("not 32 bytes"));
    }

    #[test]
    fn provenance_fails_malformed_signature_with_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        let (pk, _sk) = exo_core::crypto::generate_keypair();
        ctx.provenance = Some(Provenance {
            actor: ctx.actor.clone(),
            timestamp: "t".into(),
            action_hash: vec![1],
            signature: vec![0u8; 32], // wrong length for Ed25519 (need 64)
            public_key: Some(pk.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        });
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("not 64 bytes"));
    }

    #[test]
    fn provenance_rejects_legacy_delimited_signature_payload() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::ProvenanceVerifiable,
        ]));
        let mut ctx = passing_context();
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let actor = ctx.actor.clone();
        let action_hash = vec![0xde, 0xad, 0xbe, 0xef];
        let timestamp = "2026-01-01T00:00:00Z".to_string();
        let mut payload = Vec::new();
        payload.extend_from_slice(actor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&action_hash);
        payload.push(0x00);
        payload.extend_from_slice(timestamp.as_bytes());
        let message = Hash256::digest(&payload);
        let sig = exo_core::crypto::sign(message.as_bytes(), &sk);

        ctx.provenance = Some(Provenance {
            actor,
            timestamp,
            action_hash,
            signature: sig.to_bytes().to_vec(),
            public_key: Some(pk.as_bytes().to_vec()),
            voice_kind: Some(VoiceKind::Human),
            independence: Some(IndependenceClaim::Independent),
            review_order: Some(ReviewOrder::FirstOrder),
        });

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("cryptographically invalid"));
    }

    // ── TNC-01: Ed25519 signature verification ───────────────────────────

    /// Build a properly signed AuthorityLink for the given grantor→grantee.
    fn signed_link(grantor_str: &str, grantee_str: &str) -> (AuthorityLink, exo_core::PublicKey) {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = did(grantor_str);
        let grantee = did(grantee_str);
        let perms = PermissionSet::new(vec![Permission::new("read")]);
        let mut link = AuthorityLink {
            grantor,
            grantee,
            permissions: perms,
            signature: Vec::new(),
            grantor_public_key: Some(pk.as_bytes().to_vec()),
        };
        let message = authority_link_signature_message(&link).expect("canonical link payload");
        let sig = exo_core::crypto::sign(message.as_bytes(), &sk);

        link.signature = sig.to_bytes().to_vec();
        (link, pk)
    }

    #[test]
    fn authority_chain_passes_with_valid_ed25519_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (link, pk) = signed_link("did:exo:root", "did:exo:actor1");
        ctx.trusted_authority_keys
            .insert(link.grantor.clone(), vec![pk.as_bytes().to_vec()]);
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        assert!(enforce_all(&engine, &ctx).is_ok());
    }

    #[test]
    fn authority_chain_rejects_unresolved_grantor_public_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (link, _pk) = signed_link("did:exo:unresolved-root", "did:exo:actor1");
        ctx.authority_chain = AuthorityChain { links: vec![link] };

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(
            err[0].description.contains("grantor_public_key")
                && err[0].description.contains("unresolved"),
            "self-attested grantor public keys must not satisfy AuthorityChainValid: {err:?}"
        );
    }

    #[test]
    fn authority_chain_fails_when_requested_permission_absent_from_actor_permissions() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.requested_permissions = PermissionSet::new(vec![Permission::new("advance_pace")]);

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(
            err[0].description.contains("Requested permission"),
            "requested permission missing from actor permissions must fail AuthorityChainValid"
        );
    }

    #[test]
    fn authority_chain_fails_when_requested_permission_absent_from_chain_scope() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.actor_permissions = PermissionSet::new(vec![Permission::new("advance_pace")]);
        ctx.requested_permissions = PermissionSet::new(vec![Permission::new("advance_pace")]);

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(
            err[0].description.contains("authority chain scope"),
            "requested permission missing from signed chain scope must fail AuthorityChainValid"
        );
    }

    #[test]
    fn authority_chain_fails_with_tampered_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (mut link, pk) = signed_link("did:exo:root", "did:exo:actor1");
        ctx.trusted_authority_keys
            .insert(link.grantor.clone(), vec![pk.as_bytes().to_vec()]);
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
        let (mut link, pk) = signed_link("did:exo:root", "did:exo:actor1");
        ctx.trusted_authority_keys
            .insert(link.grantor.clone(), vec![pk.as_bytes().to_vec()]);
        // Replace public key with a different one.
        let (other_pk, _other_sk) = exo_core::crypto::generate_keypair();
        link.grantor_public_key = Some(other_pk.as_bytes().to_vec());
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("not bound"));
    }

    #[test]
    fn authority_chain_fails_with_malformed_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let link = AuthorityLink {
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
    fn authority_chain_fails_empty_signature_with_public_key() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (mut link, pk) = signed_link("did:exo:root", "did:exo:actor1");
        ctx.trusted_authority_keys
            .insert(link.grantor.clone(), vec![pk.as_bytes().to_vec()]);
        link.signature.clear();
        ctx.authority_chain = AuthorityChain { links: vec![link] };
        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("not 64 bytes"));
    }

    #[test]
    fn authority_chain_fails_without_grantor_public_key_even_with_non_empty_signature() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        ctx.authority_chain = AuthorityChain {
            links: vec![AuthorityLink {
                grantor: did("did:exo:root"),
                grantee: did("did:exo:actor1"),
                permissions: PermissionSet::new(vec![Permission::new("read")]),
                signature: vec![7u8; 64],
                grantor_public_key: None,
            }],
        };

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("grantor_public_key"));
    }

    #[test]
    fn authority_chain_rejects_legacy_delimited_signature_payload() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = did("did:exo:root");
        let grantee = ctx.actor.clone();
        let permissions = PermissionSet::new(vec![Permission::new("read")]);
        let mut payload = Vec::new();
        payload.extend_from_slice(grantor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(grantee.as_str().as_bytes());
        payload.push(0x00);
        for permission in &permissions.permissions {
            payload.extend_from_slice(permission.0.as_bytes());
            payload.push(0x00);
        }
        let message = Hash256::digest(&payload);
        let sig = exo_core::crypto::sign(message.as_bytes(), &sk);
        ctx.trusted_authority_keys
            .insert(grantor.clone(), vec![pk.as_bytes().to_vec()]);

        ctx.authority_chain = AuthorityChain {
            links: vec![AuthorityLink {
                grantor,
                grantee,
                permissions,
                signature: sig.to_bytes().to_vec(),
                grantor_public_key: Some(pk.as_bytes().to_vec()),
            }],
        };

        let err = enforce_all(&engine, &ctx).unwrap_err();
        assert!(err[0].description.contains("cryptographically invalid"));
    }

    #[test]
    fn authority_chain_passes_multi_link_with_ed25519() {
        let engine = InvariantEngine::new(InvariantSet::with(vec![
            ConstitutionalInvariant::AuthorityChainValid,
        ]));
        let mut ctx = passing_context();
        let (link1, pk1) = signed_link("did:exo:root", "did:exo:mid");
        let (link2, pk2) = signed_link("did:exo:mid", "did:exo:actor1");
        ctx.trusted_authority_keys
            .insert(link1.grantor.clone(), vec![pk1.as_bytes().to_vec()]);
        ctx.trusted_authority_keys
            .insert(link2.grantor.clone(), vec![pk2.as_bytes().to_vec()]);
        ctx.authority_chain = AuthorityChain {
            links: vec![link1, link2],
        };
        assert!(enforce_all(&engine, &ctx).is_ok());
    }
}
