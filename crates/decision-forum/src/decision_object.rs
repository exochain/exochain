//! The Decision Object — core domain type of the decision.forum.
//!
//! A Decision Object is:
//! - Storable, diffable, transferable, auditable, contestable (Axiom 2)
//! - Bound to constitutional version at creation (GOV-002)
//! - 14-state lifecycle matching BCTS (`exo_core::bcts`)
//! - Immutable after terminal status (TNC-08)

use exo_core::{
    bcts::BctsState,
    crypto,
    hash::hash_structured,
    types::{DeterministicMap, Did, Hash256, PublicKey, Signature, Timestamp},
};
use exo_gatekeeper::{
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    types::{Permission, VoiceKind},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    constitution::PublicKeyResolver,
    error::{ForumError, Result},
};

/// Classification of a decision, determining quorum, authority, and gate requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DecisionClass {
    /// Day-to-day operational decisions.
    Routine,
    /// Decisions affecting operations or resources.
    Operational,
    /// Long-term or high-impact decisions.
    Strategic,
    /// Decisions that modify the constitutional corpus itself.
    Constitutional,
}

impl DecisionClass {
    /// Stable registry key for quorum, policy, and persistence lookups.
    ///
    /// This deliberately does not rely on `Debug` output, so refactoring
    /// developer-facing formatting cannot silently change governance policy
    /// resolution.
    #[must_use]
    pub const fn quorum_policy_key(self) -> &'static str {
        match self {
            Self::Routine => "Routine",
            Self::Operational => "Operational",
            Self::Strategic => "Strategic",
            Self::Constitutional => "Constitutional",
        }
    }
}

/// Distinguishes human vs AI actors for human-gate enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorKind {
    Human,
    AiAgent {
        delegation_id: String,
        ceiling_class: DecisionClass,
    },
}

/// Cryptographic evidence binding a vote to the voter and decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteProvenance {
    pub public_key: PublicKey,
    pub signature: Signature,
    pub voice_kind: VoiceKind,
}

/// A single vote cast on a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub voter_did: Did,
    pub choice: VoteChoice,
    pub actor_kind: ActorKind,
    pub timestamp: Timestamp,
    pub signature_hash: Hash256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<VoteProvenance>,
}

/// Vote choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

/// A link in the authority chain attesting to delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityLink {
    pub actor_did: Did,
    pub actor_kind: ActorKind,
    pub delegation_hash: Hash256,
    pub timestamp: Timestamp,
}

/// A piece of evidence attached to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub hash: Hash256,
    pub description: String,
    pub attached_at: Timestamp,
}

/// A receipt recording a lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleReceipt {
    pub from_state: BctsState,
    pub to_state: BctsState,
    pub actor_did: Did,
    pub timestamp: Timestamp,
    pub receipt_hash: Hash256,
}

const BCTS_TRANSITION_ACTION_PREFIX: &str = "bcts:transition";
const DECISION_VOTE_SIGNATURE_DOMAIN: &str = "decision.forum.vote_signature.v1";
const DECISION_VOTE_SIGNATURE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Serialize)]
struct VoteSignaturePayload<'a> {
    domain: &'static str,
    schema_version: u16,
    decision_id: &'a Uuid,
    decision_class: DecisionClass,
    constitutional_hash: &'a Hash256,
    voter_did: &'a Did,
    choice: VoteChoice,
    actor_kind: &'a ActorKind,
    timestamp: &'a Timestamp,
}

/// Stable action name used when submitting a BCTS state transition to the
/// constitutional kernel.
#[must_use]
pub fn bcts_transition_action_name(from: BctsState, to: BctsState) -> String {
    format!("{BCTS_TRANSITION_ACTION_PREFIX}:{from}->{to}")
}

/// Stable permission required for a BCTS state transition.
#[must_use]
pub fn bcts_transition_permission(from: BctsState, to: BctsState) -> Permission {
    Permission::new(bcts_transition_action_name(from, to))
}

/// Canonical domain-separated message bytes to sign for a decision vote.
pub fn vote_signature_message(decision: &DecisionObject, vote: &Vote) -> Result<Vec<u8>> {
    let digest = hash_structured(&VoteSignaturePayload {
        domain: DECISION_VOTE_SIGNATURE_DOMAIN,
        schema_version: DECISION_VOTE_SIGNATURE_SCHEMA_VERSION,
        decision_id: &decision.id,
        decision_class: decision.class,
        constitutional_hash: &decision.constitutional_hash,
        voter_did: &vote.voter_did,
        choice: vote.choice,
        actor_kind: &vote.actor_kind,
        timestamp: &vote.timestamp,
    })?;
    Ok(digest.as_ref().to_vec())
}

impl Vote {
    /// Returns true when the vote carries internally consistent human provenance
    /// evidence. Decision-bound signature verification still requires the
    /// surrounding [`DecisionObject`].
    #[must_use]
    pub fn has_human_provenance_evidence(&self) -> bool {
        matches!(self.actor_kind, ActorKind::Human)
            && self.choice == VoteChoice::Approve
            && self.has_consistent_signature_evidence_for_voice(VoiceKind::Human)
    }

    fn has_consistent_signature_evidence_for_voice(&self, expected_voice: VoiceKind) -> bool {
        self.timestamp != Timestamp::ZERO
            && self.signature_hash != Hash256::ZERO
            && self.provenance.as_ref().is_some_and(|provenance| {
                provenance.voice_kind == expected_voice
                    && !provenance.signature.is_empty()
                    && !provenance.signature.ed25519_component_is_zero()
                    && Hash256::digest(&provenance.signature.to_bytes()) == self.signature_hash
            })
    }

    fn expected_voice_kind(&self) -> VoiceKind {
        match self.actor_kind {
            ActorKind::Human => VoiceKind::Human,
            ActorKind::AiAgent { .. } => VoiceKind::Synthetic,
        }
    }
}

fn actor_kind_label(actor_kind: &ActorKind) -> &'static str {
    match actor_kind {
        ActorKind::Human => "Human",
        ActorKind::AiAgent { .. } => "AiAgent",
    }
}

fn voice_kind_label(voice_kind: VoiceKind) -> &'static str {
    match voice_kind {
        VoiceKind::Human => "Human",
        VoiceKind::Synthetic => "Synthetic",
        VoiceKind::System => "System",
    }
}

fn no_voter_public_key(_: &Did) -> Option<PublicKey> {
    None
}

/// The core Decision Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionObject {
    pub id: Uuid,
    pub title: String,
    pub class: DecisionClass,
    pub constitutional_hash: Hash256,
    pub state: BctsState,
    pub authority_chain: Vec<AuthorityLink>,
    pub votes: Vec<Vote>,
    pub evidence_bundle: Vec<EvidenceItem>,
    pub receipt_chain: Vec<LifecycleReceipt>,
    pub created_at: Timestamp,
    pub metadata: DeterministicMap<String, String>,
}

/// Caller-supplied metadata for constructing a [`DecisionObject`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionObjectInput {
    pub id: Uuid,
    pub title: String,
    pub class: DecisionClass,
    pub constitutional_hash: Hash256,
    pub created_at: Timestamp,
}

impl DecisionObject {
    /// Create a new Decision Object in the Draft state, bound to the given
    /// constitutional hash.
    pub fn new(input: DecisionObjectInput) -> Result<Self> {
        validate_uuid(input.id, "decision id")?;
        validate_timestamp(input.created_at, "decision created_at")?;
        if input.title.trim().is_empty() {
            return Err(ForumError::InvalidProvenance {
                reason: "decision title must be non-empty".into(),
            });
        }
        if input.constitutional_hash == Hash256::ZERO {
            return Err(ForumError::InvalidProvenance {
                reason: "constitutional hash must be non-zero".into(),
            });
        }

        Ok(Self {
            id: input.id,
            title: input.title,
            class: input.class,
            constitutional_hash: input.constitutional_hash,
            state: BctsState::Draft,
            authority_chain: Vec::new(),
            votes: Vec::new(),
            evidence_bundle: Vec::new(),
            receipt_chain: Vec::new(),
            created_at: input.created_at,
            metadata: DeterministicMap::new(),
        })
    }

    /// Returns true if this decision is in a terminal state (Closed or
    /// Denied with no remediation pending).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state == BctsState::Closed
    }

    /// Raw BCTS transitions are disabled in production. Use
    /// [`Self::transition_adjudicated_at`] so the constitutional kernel
    /// adjudicates the transition before state is mutated.
    pub fn transition_at(
        &mut self,
        _to: BctsState,
        _actor: &Did,
        _timestamp: Timestamp,
    ) -> Result<()> {
        Err(ForumError::ConstitutionalConflict {
            reason: "raw BCTS decision transition requires Kernel::adjudicate via transition_adjudicated_at".into(),
        })
    }

    /// Transition the decision to a new BCTS state after a permitted kernel
    /// adjudication, recording a receipt.
    pub fn transition_adjudicated_at(
        &mut self,
        to: BctsState,
        actor: &Did,
        timestamp: Timestamp,
        kernel: &Kernel,
        action: &ActionRequest,
        context: &AdjudicationContext,
    ) -> Result<()> {
        self.validate_transition_preconditions(to, timestamp)?;
        validate_transition_action_binding(self.state, to, actor, action)?;

        match kernel.adjudicate(action, context) {
            Verdict::Permitted => self.apply_transition_at(to, actor, timestamp),
            Verdict::Denied { violations } => {
                let reason = violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant.id(), v.description))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(ForumError::ConstitutionalConflict {
                    reason: format!("BCTS transition denied by kernel: {reason}"),
                })
            }
            Verdict::Escalated { reason } => Err(ForumError::ConstitutionalConflict {
                reason: format!("BCTS transition escalated by kernel: {reason}"),
            }),
        }
    }

    fn validate_transition_preconditions(&self, to: BctsState, timestamp: Timestamp) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        if !self.state.can_transition_to(to) {
            return Err(ForumError::InvalidTransition {
                from: self.state.to_string(),
                to: to.to_string(),
            });
        }
        self.validate_transition_timestamp(timestamp)?;
        Ok(())
    }

    fn apply_transition_at(
        &mut self,
        to: BctsState,
        actor: &Did,
        timestamp: Timestamp,
    ) -> Result<()> {
        let receipt_hash = self.compute_receipt_hash(self.state, to, &timestamp, actor)?;

        self.receipt_chain.push(LifecycleReceipt {
            from_state: self.state,
            to_state: to,
            actor_did: actor.clone(),
            timestamp,
            receipt_hash,
        });
        self.state = to;
        Ok(())
    }

    fn validate_transition_timestamp(&self, timestamp: Timestamp) -> Result<()> {
        validate_timestamp(timestamp, "transition timestamp")?;
        let floor = self
            .receipt_chain
            .last()
            .map(|r| r.timestamp)
            .unwrap_or(self.created_at);
        if timestamp <= floor {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "transition timestamp {} must be greater than prior timestamp {}",
                    timestamp, floor
                ),
            });
        }
        Ok(())
    }

    /// Add a vote to this decision.
    pub fn add_vote(&mut self, vote: Vote) -> Result<()> {
        self.add_vote_with_key_resolver(vote, &no_voter_public_key)
    }

    /// Add a vote after resolving the voter's public key from trusted identity
    /// state. Use this at runtime boundaries; [`Self::add_vote`] intentionally
    /// fails closed because a vote's embedded public key is not self-authenticating.
    pub fn add_vote_with_key_resolver<R: PublicKeyResolver>(
        &mut self,
        vote: Vote,
        resolve_voter_public_key: &R,
    ) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        // Prevent duplicate votes from the same DID.
        if self.votes.iter().any(|v| v.voter_did == vote.voter_did) {
            return Err(ForumError::EnactmentFailed {
                reason: format!("duplicate vote from {}", vote.voter_did),
            });
        }
        self.verify_vote_signature_with_key_resolver(&vote, resolve_voter_public_key)?;
        self.votes.push(vote);
        Ok(())
    }

    /// Verify a vote's decision-bound signature and provenance metadata.
    pub fn verify_vote_signature(&self, vote: &Vote) -> Result<()> {
        self.verify_vote_signature_with_key_resolver(vote, &no_voter_public_key)
    }

    /// Verify a vote's decision-bound signature and ensure its signing key is
    /// resolved from trusted voter identity state.
    pub fn verify_vote_signature_with_key_resolver<R: PublicKeyResolver>(
        &self,
        vote: &Vote,
        resolve_voter_public_key: &R,
    ) -> Result<()> {
        validate_timestamp(vote.timestamp, "vote timestamp")?;

        if vote.signature_hash == Hash256::ZERO {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} must include non-zero signature hash",
                    vote.voter_did
                ),
            });
        }

        let provenance = vote
            .provenance
            .as_ref()
            .ok_or_else(|| ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} must include signature provenance",
                    vote.voter_did
                ),
            })?;

        let expected_voice = vote.expected_voice_kind();
        if provenance.voice_kind != expected_voice {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} declares {} actor with {} voice provenance",
                    vote.voter_did,
                    actor_kind_label(&vote.actor_kind),
                    voice_kind_label(provenance.voice_kind)
                ),
            });
        }

        let resolved_public_key = resolve_voter_public_key
            .resolve(&vote.voter_did)
            .ok_or_else(|| ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} voter public key is unresolved",
                    vote.voter_did
                ),
            })?;
        if resolved_public_key != provenance.public_key {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} provenance public key does not match resolved voter public key",
                    vote.voter_did
                ),
            });
        }

        if provenance.signature.is_empty() || provenance.signature.ed25519_component_is_zero() {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} must include a non-empty signature",
                    vote.voter_did
                ),
            });
        }

        let actual_signature_hash = Hash256::digest(&provenance.signature.to_bytes());
        if vote.signature_hash != actual_signature_hash {
            return Err(ForumError::InvalidProvenance {
                reason: format!(
                    "vote from {} signature hash does not match provenance signature",
                    vote.voter_did
                ),
            });
        }

        let message = vote_signature_message(self, vote)?;
        if !crypto::verify(&message, &provenance.signature, &provenance.public_key) {
            return Err(ForumError::InvalidProvenance {
                reason: format!("vote from {} signature failed verification", vote.voter_did),
            });
        }

        Ok(())
    }

    /// Returns true if this vote is a verified human approval for this decision.
    #[must_use]
    pub fn is_verified_human_approval(&self, vote: &Vote) -> bool {
        vote.has_human_provenance_evidence() && self.verify_vote_signature(vote).is_ok()
    }

    /// Returns true if this vote is a verified human approval with voter key
    /// resolution against trusted identity state.
    pub fn is_verified_human_approval_with_key_resolver<R: PublicKeyResolver>(
        &self,
        vote: &Vote,
        resolve_voter_public_key: &R,
    ) -> bool {
        vote.has_human_provenance_evidence()
            && self
                .verify_vote_signature_with_key_resolver(vote, resolve_voter_public_key)
                .is_ok()
    }

    /// Add evidence to this decision.
    pub fn add_evidence(&mut self, item: EvidenceItem) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        self.evidence_bundle.push(item);
        Ok(())
    }

    /// Add an authority link to the chain.
    pub fn add_authority_link(&mut self, link: AuthorityLink) -> Result<()> {
        if self.is_terminal() {
            return Err(ForumError::DecisionImmutable);
        }
        self.authority_chain.push(link);
        Ok(())
    }

    /// Compute a content hash over the full decision object for auditing.
    pub fn content_hash(&self) -> Result<Hash256> {
        #[derive(Serialize)]
        struct HashInput<'a> {
            id: &'a Uuid,
            title: &'a str,
            class: &'a DecisionClass,
            constitutional_hash: &'a Hash256,
            state: &'a BctsState,
            vote_count: usize,
            evidence_count: usize,
            receipt_count: usize,
        }
        let input = HashInput {
            id: &self.id,
            title: &self.title,
            class: &self.class,
            constitutional_hash: &self.constitutional_hash,
            state: &self.state,
            vote_count: self.votes.len(),
            evidence_count: self.evidence_bundle.len(),
            receipt_count: self.receipt_chain.len(),
        };
        hash_structured(&input).map_err(ForumError::from)
    }

    /// Compute a chained receipt hash.
    fn compute_receipt_hash(
        &self,
        from: BctsState,
        to: BctsState,
        timestamp: &Timestamp,
        actor: &Did,
    ) -> Result<Hash256> {
        #[derive(Serialize)]
        struct ReceiptInput<'a> {
            from: BctsState,
            to: BctsState,
            timestamp: &'a Timestamp,
            actor: &'a str,
            prev_hash: Hash256,
        }
        let prev = self
            .receipt_chain
            .last()
            .map(|r| r.receipt_hash)
            .unwrap_or(Hash256::ZERO);
        let input = ReceiptInput {
            from,
            to,
            timestamp,
            actor: actor.as_str(),
            prev_hash: prev,
        };
        hash_structured(&input).map_err(ForumError::from)
    }
}

fn validate_transition_action_binding(
    from: BctsState,
    to: BctsState,
    actor: &Did,
    action: &ActionRequest,
) -> Result<()> {
    if &action.actor != actor {
        return Err(ForumError::ConstitutionalConflict {
            reason: format!(
                "BCTS transition actor {actor} does not match adjudicated action actor {}",
                action.actor
            ),
        });
    }

    let expected_action = bcts_transition_action_name(from, to);
    if action.action != expected_action {
        return Err(ForumError::ConstitutionalConflict {
            reason: format!(
                "BCTS transition requires action {expected_action}, got {}",
                action.action
            ),
        });
    }

    let required = bcts_transition_permission(from, to);
    if !action.required_permissions.contains(&required) {
        return Err(ForumError::ConstitutionalConflict {
            reason: format!(
                "BCTS transition action must require permission {}",
                required.0
            ),
        });
    }

    Ok(())
}

fn validate_uuid(id: Uuid, label: &str) -> Result<()> {
    if id.is_nil() {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must not be nil"),
        });
    }
    Ok(())
}

fn validate_timestamp(timestamp: Timestamp, label: &str) -> Result<()> {
    if timestamp == Timestamp::ZERO {
        return Err(ForumError::InvalidProvenance {
            reason: format!("{label} must be non-zero HLC"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use exo_core::hlc::HybridClock;
    use exo_gatekeeper::{
        authority_link_signature_message,
        invariants::InvariantSet,
        provenance_signature_message,
        types::{
            AuthorityChain, AuthorityLink as GatekeeperAuthorityLink, BailmentState, ConsentRecord,
            GovernmentBranch, PermissionSet, Provenance, Role, TrustedAuthorityKeys, VoiceKind,
        },
    };

    use super::*;

    const CONSTITUTION: &[u8] = b"EXOCHAIN decision object test constitution";

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn test_did() -> Did {
        Did::new("did:exo:test-actor").expect("valid")
    }

    fn signed_authority_link(actor: &Did, permission: Permission) -> GatekeeperAuthorityLink {
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let grantor = Did::new("did:exo:governance-root").expect("valid DID");
        let mut link = GatekeeperAuthorityLink {
            grantor,
            grantee: actor.clone(),
            permissions: PermissionSet::new(vec![permission]),
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
        let mut provenance = Provenance {
            actor: actor.clone(),
            timestamp: "2026-04-30T00:00:00Z".to_owned(),
            action_hash: vec![0xB7, 0xC5],
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

    fn transition_action(actor: &Did, from: BctsState, to: BctsState) -> ActionRequest {
        let required = bcts_transition_permission(from, to);
        ActionRequest {
            actor: actor.clone(),
            action: bcts_transition_action_name(from, to),
            required_permissions: PermissionSet::new(vec![required]),
            is_self_grant: false,
            modifies_kernel: false,
        }
    }

    fn transition_context(actor: &Did, from: BctsState, to: BctsState) -> AdjudicationContext {
        let permission = bcts_transition_permission(from, to);
        let authority_chain = AuthorityChain {
            links: vec![signed_authority_link(actor, permission.clone())],
        };
        let mut trusted_authority_keys = TrustedAuthorityKeys::default();
        for link in &authority_chain.links {
            if let Some(public_key) = &link.grantor_public_key {
                trusted_authority_keys.insert(link.grantor.clone(), vec![public_key.clone()]);
            }
        }
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "transition-judge".into(),
                branch: GovernmentBranch::Judicial,
            }],
            authority_chain,
            consent_records: vec![ConsentRecord {
                subject: Did::new("did:exo:bailor").expect("valid DID"),
                granted_to: actor.clone(),
                scope: "bcts:transition".into(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor: Did::new("did:exo:bailor").expect("valid DID"),
                bailee: actor.clone(),
                scope: "bcts:transition".into(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![permission]),
            trusted_authority_keys,
            provenance: Some(signed_provenance(actor)),
            quorum_evidence: None,
            active_challenge_reason: None,
        }
    }

    fn adjudicated_transition_result(
        decision: &mut DecisionObject,
        to: BctsState,
        actor: &Did,
        timestamp: Timestamp,
    ) -> Result<()> {
        let from = decision.state;
        let kernel = Kernel::new(CONSTITUTION, InvariantSet::all());
        let action = transition_action(actor, from, to);
        let context = transition_context(actor, from, to);
        decision.transition_adjudicated_at(to, actor, timestamp, &kernel, &action, &context)
    }

    fn transition_ok(
        decision: &mut DecisionObject,
        to: BctsState,
        actor: &Did,
        timestamp: Timestamp,
    ) {
        adjudicated_transition_result(decision, to, actor, timestamp).expect("transition ok");
    }

    fn make_decision(clock: &mut HybridClock) -> DecisionObject {
        DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(1),
            title: "Test Decision".into(),
            class: DecisionClass::Operational,
            constitutional_hash: Hash256::digest(b"const-v1"),
            created_at: clock.now().expect("HLC timestamp"),
        })
        .expect("valid decision")
    }

    fn signed_vote_for(
        decision: &DecisionObject,
        voter_did: Did,
        choice: VoteChoice,
        actor_kind: ActorKind,
        voice_kind: VoiceKind,
        timestamp: Timestamp,
    ) -> Vote {
        let (public_key, secret_key) = exo_core::crypto::generate_keypair();
        let mut vote = Vote {
            voter_did,
            choice,
            actor_kind,
            timestamp,
            signature_hash: Hash256::ZERO,
            provenance: None,
        };
        let message = vote_signature_message(decision, &vote).expect("vote signing payload");
        let signature = exo_core::crypto::sign(&message, &secret_key);
        vote.signature_hash = Hash256::digest(&signature.to_bytes());
        vote.provenance = Some(VoteProvenance {
            public_key,
            signature,
            voice_kind,
        });
        vote
    }

    fn resolver_for_vote(vote: &Vote) -> impl Fn(&Did) -> Option<PublicKey> + use<> {
        let voter_did = vote.voter_did.clone();
        let public_key = vote
            .provenance
            .as_ref()
            .map(|provenance| provenance.public_key);
        move |did| {
            if did == &voter_did { public_key } else { None }
        }
    }

    fn add_resolved_vote(decision: &mut DecisionObject, vote: Vote) -> Result<()> {
        let resolver = resolver_for_vote(&vote);
        decision.add_vote_with_key_resolver(vote, &resolver)
    }

    #[test]
    fn new_decision_requires_caller_supplied_identity_and_hlc() {
        let input = DecisionObjectInput {
            id: Uuid::from_u128(42),
            title: "Deterministic Decision".into(),
            class: DecisionClass::Strategic,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: Timestamp::new(10_000, 0),
        };
        let first = DecisionObject::new(input.clone()).expect("valid decision");
        let second = DecisionObject::new(input).expect("same metadata valid");

        assert_eq!(first.id, Uuid::from_u128(42));
        assert_eq!(first.created_at, Timestamp::new(10_000, 0));
        assert_eq!(
            first.content_hash().expect("hash"),
            second.content_hash().expect("hash")
        );

        let nil_id = DecisionObject::new(DecisionObjectInput {
            id: Uuid::nil(),
            title: "bad".into(),
            class: DecisionClass::Routine,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: Timestamp::new(10_000, 0),
        })
        .unwrap_err();
        assert!(matches!(nil_id, ForumError::InvalidProvenance { .. }));

        let zero_time = DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(43),
            title: "bad".into(),
            class: DecisionClass::Routine,
            constitutional_hash: Hash256::digest(b"constitution"),
            created_at: Timestamp::ZERO,
        })
        .unwrap_err();
        assert!(matches!(zero_time, ForumError::InvalidProvenance { .. }));
    }

    #[test]
    fn transition_requires_caller_supplied_monotonic_hlc() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);

        transition_ok(
            &mut d,
            BctsState::Submitted,
            &actor,
            Timestamp::new(10_001, 0),
        );

        let zero = adjudicated_transition_result(
            &mut d,
            BctsState::IdentityResolved,
            &actor,
            Timestamp::ZERO,
        )
        .unwrap_err();
        assert!(matches!(zero, ForumError::InvalidProvenance { .. }));

        let regressive = adjudicated_transition_result(
            &mut d,
            BctsState::IdentityResolved,
            &actor,
            Timestamp::new(10_000, 0),
        )
        .unwrap_err();
        assert!(matches!(regressive, ForumError::InvalidProvenance { .. }));
        assert_eq!(
            regressive.to_string(),
            "invalid provenance metadata: transition timestamp 10000:0 must be greater than prior timestamp 10001:0"
        );

        transition_ok(
            &mut d,
            BctsState::IdentityResolved,
            &actor,
            Timestamp::new(10_002, 0),
        );
    }

    #[test]
    fn new_decision_is_draft() {
        let mut clock = test_clock();
        let d = make_decision(&mut clock);
        assert_eq!(d.state, BctsState::Draft);
        assert_eq!(d.class, DecisionClass::Operational);
        assert!(d.votes.is_empty());
        assert!(d.evidence_bundle.is_empty());
        assert!(d.receipt_chain.is_empty());
        assert!(d.authority_chain.is_empty());
    }

    #[test]
    fn transition_draft_to_submitted() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");
        transition_ok(&mut d, BctsState::Submitted, &test_did(), ts);
        assert_eq!(d.state, BctsState::Submitted);
        assert_eq!(d.receipt_chain.len(), 1);
    }

    #[test]
    fn raw_transition_without_kernel_adjudication_fails_closed() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");

        let err = d
            .transition_at(BctsState::Submitted, &actor, ts)
            .expect_err("raw BCTS decision transition must require kernel adjudication");

        assert!(matches!(err, ForumError::ConstitutionalConflict { .. }));
        assert_eq!(d.state, BctsState::Draft);
        assert!(d.receipt_chain.is_empty());
    }

    #[test]
    fn adjudicated_transition_denies_kernel_denial_without_mutating() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let to = BctsState::Submitted;
        let ts = clock.now().expect("HLC timestamp");
        let kernel = Kernel::new(CONSTITUTION, InvariantSet::all());
        let action = transition_action(&actor, d.state, to);
        let mut context = transition_context(&actor, d.state, to);
        context.provenance = None;

        let err = d
            .transition_adjudicated_at(to, &actor, ts, &kernel, &action, &context)
            .expect_err("kernel denial must fail the transition");

        assert!(matches!(err, ForumError::ConstitutionalConflict { .. }));
        assert!(err.to_string().contains("provenance-verifiable"));
        assert_eq!(d.state, BctsState::Draft);
        assert!(d.receipt_chain.is_empty());
    }

    #[test]
    fn adjudicated_transition_rejects_unbound_action_without_mutating() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let to = BctsState::Submitted;
        let ts = clock.now().expect("HLC timestamp");
        let kernel = Kernel::new(CONSTITUTION, InvariantSet::all());
        let action = transition_action(&actor, BctsState::Submitted, BctsState::Denied);
        let context = transition_context(&actor, BctsState::Submitted, BctsState::Denied);

        let err = d
            .transition_adjudicated_at(to, &actor, ts, &kernel, &action, &context)
            .expect_err("mismatched kernel action must fail the transition");

        assert!(matches!(err, ForumError::ConstitutionalConflict { .. }));
        assert!(err.to_string().contains("requires action"));
        assert_eq!(d.state, BctsState::Draft);
        assert!(d.receipt_chain.is_empty());
    }

    #[test]
    fn transition_invalid_rejects() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");
        let err =
            adjudicated_transition_result(&mut d, BctsState::Closed, &test_did(), ts).unwrap_err();
        assert!(matches!(err, ForumError::InvalidTransition { .. }));
    }

    #[test]
    fn full_lifecycle() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let steps = [
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Verified,
            BctsState::Governed,
            BctsState::Approved,
            BctsState::Executed,
            BctsState::Recorded,
            BctsState::Closed,
        ];
        for s in steps {
            let ts = clock.now().expect("HLC timestamp");
            transition_ok(&mut d, s, &actor, ts);
        }
        assert!(d.is_terminal());
        assert_eq!(d.receipt_chain.len(), 10);
    }

    #[test]
    fn terminal_decision_is_immutable() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        for s in [
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Verified,
            BctsState::Governed,
            BctsState::Approved,
            BctsState::Executed,
            BctsState::Recorded,
            BctsState::Closed,
        ] {
            let ts = clock.now().expect("HLC timestamp");
            transition_ok(&mut d, s, &actor, ts);
        }
        let ts = clock.now().expect("HLC timestamp");
        assert!(adjudicated_transition_result(&mut d, BctsState::Draft, &actor, ts).is_err());
        assert!(
            d.add_vote(Vote {
                voter_did: actor.clone(),
                choice: VoteChoice::Approve,
                actor_kind: ActorKind::Human,
                timestamp: clock.now().expect("HLC timestamp"),
                signature_hash: Hash256::ZERO,
                provenance: None,
            })
            .is_err()
        );
        assert!(
            d.add_evidence(EvidenceItem {
                hash: Hash256::ZERO,
                description: "x".into(),
                attached_at: clock.now().expect("HLC timestamp"),
            })
            .is_err()
        );
    }

    #[test]
    fn invalid_transition_errors_use_stable_bcts_labels() {
        let source = include_str!("decision_object.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(
            !production.contains("format!(\"{:?}\", self.state)"),
            "decision transition errors must not depend on BCTS Debug labels"
        );
        assert!(
            !production.contains("format!(\"{to:?}\")"),
            "decision transition errors must not depend on BCTS Debug labels"
        );
        assert!(
            !production
                .contains("transition timestamp {:?} must be greater than prior timestamp {:?}"),
            "decision timestamp errors must use Timestamp Display labels"
        );
    }

    #[test]
    fn add_vote_prevents_duplicates() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");
        let first_vote = signed_vote_for(
            &d,
            actor.clone(),
            VoteChoice::Approve,
            ActorKind::Human,
            VoiceKind::Human,
            ts,
        );
        add_resolved_vote(&mut d, first_vote).expect("ok");
        let second_vote = signed_vote_for(
            &d,
            actor.clone(),
            VoteChoice::Reject,
            ActorKind::Human,
            VoiceKind::Human,
            ts,
        );
        let err = d.add_vote(second_vote).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn add_vote_rejects_missing_signature_evidence() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);

        let err = d
            .add_vote(Vote {
                voter_did: actor,
                choice: VoteChoice::Approve,
                actor_kind: ActorKind::Human,
                timestamp: clock.now().expect("HLC timestamp"),
                signature_hash: Hash256::ZERO,
                provenance: None,
            })
            .expect_err("votes without signature evidence must fail closed");

        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
        assert!(d.votes.is_empty());
    }

    #[test]
    fn add_vote_rejects_unresolved_voter_public_key() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");
        let vote = signed_vote_for(
            &d,
            test_did(),
            VoteChoice::Approve,
            ActorKind::Human,
            VoiceKind::Human,
            ts,
        );

        let err = d
            .add_vote(vote)
            .expect_err("votes with self-supplied but unresolved keys must fail closed");
        assert!(err.to_string().contains("voter public key is unresolved"));
        assert!(d.votes.is_empty());
    }

    #[test]
    fn add_vote_rejects_missing_hlc_timestamp() {
        let actor = test_did();
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);

        let err = d
            .add_vote(Vote {
                voter_did: actor,
                choice: VoteChoice::Approve,
                actor_kind: ActorKind::Human,
                timestamp: Timestamp::ZERO,
                signature_hash: Hash256::digest(b"vote-signature"),
                provenance: None,
            })
            .expect_err("votes without HLC provenance must fail closed");

        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
        assert!(d.votes.is_empty());
    }

    #[test]
    fn add_vote_rejects_signature_replayed_for_different_decision() {
        let mut clock = test_clock();
        let source = make_decision(&mut clock);
        let mut target = DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(2),
            title: "Different Decision".into(),
            class: DecisionClass::Operational,
            constitutional_hash: Hash256::digest(b"const-v1"),
            created_at: clock.now().expect("HLC timestamp"),
        })
        .expect("valid decision");

        let vote = signed_vote_for(
            &source,
            test_did(),
            VoteChoice::Approve,
            ActorKind::Human,
            VoiceKind::Human,
            clock.now().expect("HLC timestamp"),
        );
        let resolver = resolver_for_vote(&vote);

        let err = target
            .add_vote_with_key_resolver(vote, &resolver)
            .expect_err("vote signatures must be bound to one decision");

        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
        assert!(
            err.to_string().contains("signature failed verification"),
            "error should identify signature verification failure, got: {err}"
        );
        assert!(target.votes.is_empty());
    }

    #[test]
    fn add_vote_rejects_human_actor_with_synthetic_voice_provenance() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let vote = signed_vote_for(
            &d,
            test_did(),
            VoteChoice::Approve,
            ActorKind::Human,
            VoiceKind::Synthetic,
            clock.now().expect("HLC timestamp"),
        );

        let err = d
            .add_vote(vote)
            .expect_err("human actor votes must carry human voice provenance");

        assert!(matches!(err, ForumError::InvalidProvenance { .. }));
        assert!(
            err.to_string().contains("Synthetic voice provenance"),
            "error should identify voice-kind mismatch, got: {err}"
        );
        assert!(d.votes.is_empty());
    }

    #[test]
    fn content_hash_deterministic() {
        let mut clock = test_clock();
        let d = make_decision(&mut clock);
        let h1 = d.content_hash().expect("ok");
        let h2 = d.content_hash().expect("ok");
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_changes_with_state() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let h1 = d.content_hash().expect("ok");
        let ts = clock.now().expect("HLC timestamp");
        transition_ok(&mut d, BctsState::Submitted, &actor, ts);
        let h2 = d.content_hash().expect("ok");
        assert_ne!(h1, h2);
    }

    #[test]
    fn receipt_chain_hashes_differ() {
        let mut clock = test_clock();
        let actor = test_did();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");
        transition_ok(&mut d, BctsState::Submitted, &actor, ts);
        let ts = clock.now().expect("HLC timestamp");
        transition_ok(&mut d, BctsState::IdentityResolved, &actor, ts);
        assert_ne!(
            d.receipt_chain[0].receipt_hash,
            d.receipt_chain[1].receipt_hash
        );
    }

    #[test]
    fn decision_class_ordering() {
        assert!(DecisionClass::Routine < DecisionClass::Operational);
        assert!(DecisionClass::Operational < DecisionClass::Strategic);
        assert!(DecisionClass::Strategic < DecisionClass::Constitutional);
    }

    #[test]
    fn constitutional_hash_bound_at_creation() {
        let mut clock = test_clock();
        let hash = Hash256::digest(b"test-constitution");
        let d = DecisionObject::new(DecisionObjectInput {
            id: Uuid::from_u128(2),
            title: "test".into(),
            class: DecisionClass::Routine,
            constitutional_hash: hash,
            created_at: clock.now().expect("HLC timestamp"),
        })
        .expect("valid");
        assert_eq!(d.constitutional_hash, hash);
    }

    #[test]
    fn add_authority_link() {
        let mut clock = test_clock();
        let mut d = make_decision(&mut clock);
        let ts = clock.now().expect("HLC timestamp");
        d.add_authority_link(AuthorityLink {
            actor_did: test_did(),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: ts,
        })
        .expect("ok");
        assert_eq!(d.authority_chain.len(), 1);
    }

    #[test]
    fn serde_roundtrip() {
        let mut clock = test_clock();
        let d = make_decision(&mut clock);
        let json = serde_json::to_string(&d).expect("ser");
        let d2: DecisionObject = serde_json::from_str(&json).expect("de");
        assert_eq!(d.id, d2.id);
        assert_eq!(d.title, d2.title);
        assert_eq!(d.state, d2.state);
    }
}
