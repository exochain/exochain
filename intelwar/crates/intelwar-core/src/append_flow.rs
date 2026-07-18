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

//! Minimal Living Log append flow:
//! consent → authority → CGR → IntelWar overlays → provenance receipt → DAG append.

use exo_core::{
    Did, Hash256, SecretKey, Signature, Timestamp,
    crypto::{self, KeyPair},
    hash::hash_structured,
};
use exo_dag::dag::{Dag, DeterministicDagClock, append as dag_append, get as dag_get};
use exo_gatekeeper::{
    ActionRequest, AdjudicationContext, Kernel, Verdict,
    authority_link_signature_message, provenance_signature_message,
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch,
        IndependenceClaim as GkIndependence, Permission, PermissionSet, Provenance,
        ReviewOrder as GkReviewOrder, Role, TrustedAuthorityKeys, TrustedProvenanceKeys,
        VoiceKind as GkVoiceKind,
    },
};
use serde::Serialize;

use crate::consent_flow::{LOG_APPEND_PERMISSION, consent_allows_log_append};
use crate::crosscheck::{CrossCheckResult, crosschecks_satisfy};
use crate::debate_session::{DebateSession, require_approved_debate};
use crate::error::{IntelwarError, Result};
use crate::invariants::{IntelWarInvariant, IntelWarInvariantContext, enforce_all};
use crate::log_entry::{
    EntryKind, IndependenceClaim, LivingLogReceipt, LogEntry, LogEntryBody, ReviewOrder,
    VoiceKind,
};

/// Constitution bytes hashed into the CGR Kernel at construction.
pub const INTELWAR_CONSTITUTION_BYTES: &[u8] =
    br#"IntelWar Constitution v1 - Living Log on EXOCHAIN CGR"#;

/// Inputs required to append one Living Log entry.
pub struct AppendRequest {
    pub entry_body: LogEntryBody,
    pub actor_secret_key: SecretKey,
    pub actor_roles: Vec<Role>,
    pub bailment_state: BailmentState,
    pub consent_records: Vec<ConsentRecord>,
    pub authority_chain: AuthorityChain,
    pub trusted_authority_keys: TrustedAuthorityKeys,
    pub trusted_provenance_keys: TrustedProvenanceKeys,
    pub human_override_preserved: bool,
    pub previous_receipt_hash: Option<Hash256>,
    pub crosschecks: Vec<CrossCheckResult>,
    pub debate: Option<DebateSession>,
    pub provenance_timestamp: String,
}

/// Result of a successful append.
#[derive(Debug, Clone)]
pub struct AppendReceipt {
    pub entry: LogEntry,
    pub dag_node_hash: Hash256,
    pub living_receipt: LivingLogReceipt,
    pub living_receipt_hash: Hash256,
}

/// Build a CGR Kernel bound to the IntelWar constitution bytes.
#[must_use]
pub fn intelwar_kernel() -> Kernel {
    Kernel::new(
        INTELWAR_CONSTITUTION_BYTES,
        exo_gatekeeper::InvariantSet::all(),
    )
}

/// Consent → authority → CGR → IntelWar → provenance receipt → DAG append.
pub fn append_log_entry(
    dag: &mut Dag,
    clock: &mut DeterministicDagClock,
    request: AppendRequest,
) -> Result<AppendReceipt> {
    let actor = request.entry_body.author_did.clone();

    // 1. Seal entry + verify content hash
    let entry = request.entry_body.seal()?;
    entry.verify_content_hash()?;

    // 2. Consent gate (IW-2 / ConsentRequired substrate)
    consent_allows_log_append(&actor, &request.bailment_state, &request.consent_records)?;

    // 3. Authority pre-check (non-empty chain ending at actor)
    if request.authority_chain.is_empty() {
        return Err(IntelwarError::Authority {
            reason: "authority chain is empty".into(),
        });
    }
    if let Some(last) = request.authority_chain.links.last() {
        if last.grantee != actor {
            return Err(IntelwarError::Authority {
                reason: "authority chain does not terminate at actor".into(),
            });
        }
    }

    // 4. Parent validity for DAG
    let parents = entry.parent_hashes.clone();
    let dag_parents_valid = if parents.is_empty() {
        dag.is_empty()
    } else {
        parents.iter().all(|p| dag_get(dag, p).is_some())
    };
    if !dag_parents_valid {
        return Err(IntelwarError::Dag {
            reason: "invalid parent_hashes for current DAG state".into(),
        });
    }

    // 5. Crosscheck / debate preconditions
    let crosscheck_satisfied = if entry.requires_crosscheck {
        crosschecks_satisfy(&actor, &entry.content_hash, &request.crosschecks)?;
        true
    } else {
        true
    };
    let debate_satisfied = match entry.entry_kind {
        EntryKind::Doctrine | EntryKind::ConstitutionalAmendment => {
            require_approved_debate(request.debate.as_ref())?;
            true
        }
        _ => true,
    };

    // 6. Signed provenance for CGR ProvenanceVerifiable + IW-4
    let action_hash = hash_action(&entry)?;
    let provenance = sign_provenance(
        &actor,
        &request.provenance_timestamp,
        action_hash.as_bytes(),
        &request.actor_secret_key,
        &entry.voice_kind,
        entry.independence,
        entry.review_order,
    )?;

    let permissions = PermissionSet::new(vec![Permission::new(LOG_APPEND_PERMISSION)]);
    let action = ActionRequest {
        actor: actor.clone(),
        action: "intelwar.log.append".into(),
        required_permissions: permissions.clone(),
        is_self_grant: false,
        modifies_kernel: false,
    };
    let context = AdjudicationContext {
        actor_roles: request.actor_roles,
        authority_chain: request.authority_chain,
        consent_records: request.consent_records,
        bailment_state: request.bailment_state,
        human_override_preserved: request.human_override_preserved,
        actor_permissions: permissions,
        trusted_authority_keys: request.trusted_authority_keys,
        trusted_provenance_keys: request.trusted_provenance_keys,
        provenance: Some(provenance),
        quorum_evidence: None,
        active_challenge_reason: None,
    };

    let kernel = intelwar_kernel();
    match kernel.adjudicate(&action, &context) {
        Verdict::Permitted => {}
        Verdict::Denied { violations } => {
            let summary = violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant.id(), v.description))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(IntelwarError::KernelDenied { summary });
        }
        Verdict::Escalated { reason } => {
            return Err(IntelwarError::KernelDenied {
                summary: format!("escalated: {reason}"),
            });
        }
    }

    // 7. IntelWar overlays
    let iw_ctx = IntelWarInvariantContext {
        entry: &entry,
        human_override_preserved: request.human_override_preserved,
        consent_ok: true,
        authority_ok: true,
        dag_parents_valid,
        content_hash_valid: true,
        receipt_will_chain: true,
        crosscheck_satisfied,
        debate_satisfied,
    };
    enforce_all(&iw_ctx)?;

    // 8. DAG append
    let payload = entry.to_cbor()?;
    let sk = request.actor_secret_key;
    let sign_fn = |msg: &[u8]| -> Signature { crypto::sign(msg, &sk) };
    let node = dag_append(dag, &parents, &payload, &actor, &sign_fn, clock).map_err(|e| {
        IntelwarError::Dag {
            reason: e.to_string(),
        }
    })?;

    // 9. Living Log receipt (IW-8)
    let mut living_receipt = LivingLogReceipt {
        schema_version: 1,
        receipt_id: format!("receipt-{}", entry.entry_id),
        previous_receipt_hash: request.previous_receipt_hash,
        entry_content_hash: entry.content_hash,
        dag_node_hash: node.hash,
        action_hash,
        actor_did: actor,
        voice_kind: entry.voice_kind,
        kernel_verdict: "permitted".into(),
        intelwar_verdict: "permitted".into(),
        signature: Vec::new(),
    };
    let receipt_hash = living_receipt.unsigned_hash()?;
    living_receipt.signature = crypto::sign(receipt_hash.as_bytes(), &sk)
        .to_bytes()
        .to_vec();
    let living_receipt_hash = living_receipt.unsigned_hash()?;

    Ok(AppendReceipt {
        entry,
        dag_node_hash: node.hash,
        living_receipt,
        living_receipt_hash,
    })
}

fn hash_action(entry: &LogEntry) -> Result<Hash256> {
    #[derive(Serialize)]
    struct ActionPayload<'a> {
        domain: &'static str,
        action: &'static str,
        entry_content_hash: &'a Hash256,
    }
    hash_structured(&ActionPayload {
        domain: "intelwar.living-log.append.v1",
        action: "intelwar.log.append",
        entry_content_hash: &entry.content_hash,
    })
    .map_err(|e| IntelwarError::Serialization {
        reason: e.to_string(),
    })
}

fn sign_provenance(
    actor: &Did,
    timestamp: &str,
    action_hash: &[u8; 32],
    sk: &SecretKey,
    voice: &VoiceKind,
    independence: Option<IndependenceClaim>,
    review_order: Option<ReviewOrder>,
) -> Result<Provenance> {
    let pk = KeyPair::from_secret_bytes(*sk.as_bytes())
        .map_err(|e| IntelwarError::Provenance {
            reason: e.to_string(),
        })?
        .public;
    let mut prov = Provenance {
        actor: actor.clone(),
        timestamp: timestamp.to_string(),
        action_hash: action_hash.to_vec(),
        signature: Vec::new(),
        public_key: Some(pk.as_bytes().to_vec()),
        voice_kind: Some(map_voice(voice)),
        independence: independence.map(map_independence),
        review_order: review_order.map(map_review),
    };
    let message = provenance_signature_message(&prov).map_err(|e| IntelwarError::Provenance {
        reason: e.to_string(),
    })?;
    prov.signature = crypto::sign(message.as_bytes(), sk).to_bytes().to_vec();
    Ok(prov)
}

fn map_voice(v: &VoiceKind) -> GkVoiceKind {
    match v {
        VoiceKind::Human => GkVoiceKind::Human,
        VoiceKind::Synthetic => GkVoiceKind::Synthetic,
        VoiceKind::System => GkVoiceKind::System,
    }
}

fn map_independence(v: IndependenceClaim) -> GkIndependence {
    match v {
        IndependenceClaim::Independent => GkIndependence::Independent,
        IndependenceClaim::Coordinated => GkIndependence::Coordinated,
    }
}

fn map_review(v: ReviewOrder) -> GkReviewOrder {
    match v {
        ReviewOrder::FirstOrder => GkReviewOrder::FirstOrder,
        ReviewOrder::Derivative => GkReviewOrder::Derivative,
    }
}

/// Test / fixture helper: signed authority link grantor→grantee for `log:append`.
pub fn signed_authority_link(
    grantor: &Did,
    grantee: &Did,
    grantor_sk: &SecretKey,
) -> Result<AuthorityLink> {
    let pk = KeyPair::from_secret_bytes(*grantor_sk.as_bytes())
        .map_err(|e| IntelwarError::Authority {
            reason: e.to_string(),
        })?
        .public;
    let mut link = AuthorityLink {
        grantor: grantor.clone(),
        grantee: grantee.clone(),
        permissions: PermissionSet::new(vec![Permission::new(LOG_APPEND_PERMISSION)]),
        signature: Vec::new(),
        grantor_public_key: Some(pk.as_bytes().to_vec()),
    };
    let message =
        authority_link_signature_message(&link).map_err(|e| IntelwarError::Authority {
            reason: e.to_string(),
        })?;
    link.signature = crypto::sign(message.as_bytes(), grantor_sk)
        .to_bytes()
        .to_vec();
    Ok(link)
}

/// Default judicial-only role (satisfies SeparationOfPowers).
#[must_use]
pub fn judicial_role() -> Role {
    // Must use a governed role name recognized by SeparationOfPowers
    // (`Role::validate_governed` in exo-gatekeeper).
    Role {
        name: "judge".into(),
        branch: GovernmentBranch::Judicial,
    }
}

/// Default EXOCHAIN + IntelWar invariant id lists for sealed entries.
#[must_use]
pub fn default_invariant_id_lists() -> (Vec<String>, Vec<String>) {
    let exo = vec![
        "separation-of-powers".into(),
        "consent-required".into(),
        "no-self-grant".into(),
        "human-override".into(),
        "kernel-immutability".into(),
        "authority-chain-valid".into(),
        "quorum-legitimate".into(),
        "provenance-verifiable".into(),
    ];
    let iw = IntelWarInvariant::all()
        .iter()
        .map(|i| i.id().to_string())
        .collect();
    (exo, iw)
}

/// Convenience: build a development-decision entry body with HLC stamp.
#[must_use]
pub fn development_decision_body(
    entry_id: impl Into<String>,
    author: Did,
    hlc: Timestamp,
    summary: impl Into<String>,
    payload: Vec<u8>,
    parents: Vec<Hash256>,
) -> LogEntryBody {
    let (exochain_invariants, intelwar_invariants) = default_invariant_id_lists();
    LogEntryBody {
        schema_version: 1,
        entry_id: entry_id.into(),
        entry_kind: EntryKind::DevelopmentDecision,
        author_did: author,
        hlc_timestamp: hlc,
        parent_hashes: parents,
        summary: summary.into(),
        payload,
        voice_kind: VoiceKind::Human,
        independence: Some(IndependenceClaim::Independent),
        review_order: Some(ReviewOrder::FirstOrder),
        agent_attestation: None,
        requires_crosscheck: false,
        crosscheck_refs: Vec::new(),
        debate_ref: None,
        consent_scope: LOG_APPEND_PERMISSION.into(),
        intelwar_invariants,
        exochain_invariants,
    }
}
