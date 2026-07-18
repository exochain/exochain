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

//! PM-003: Doctrine append requires decision-forum DecisionObject evidence (IW-4).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use decision_forum::decision_object::{
    ActorKind, DecisionClass, DecisionObject, DecisionObjectInput, EvidenceItem, Vote, VoteChoice,
    bcts_transition_action_name, bcts_transition_permission,
};
use exo_core::{
    Did, Hash256, Timestamp, bcts::BctsState, crypto, hlc::HybridClock,
};
use exo_dag::dag::{Dag, DeterministicDagClock};
use exo_gatekeeper::{
    ActionRequest, AdjudicationContext, Kernel, authority_link_signature_message,
    provenance_signature_message,
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role, TrustedAuthorityKeys, TrustedProvenanceKeys,
    },
};
use intelwar_core::{
    AppendRequest, EntryKind, LOG_APPEND_PERMISSION, append_log_entry, debate_session_from_decision,
    development_decision_body, judicial_role, signed_authority_link,
};
use uuid::Uuid;

const CONSTITUTION: &[u8] = b"IntelWar doctrine debate test constitution";

fn did(s: &str) -> Did {
    Did::new(s).expect("valid did")
}

fn test_clock() -> HybridClock {
    let counter = AtomicU64::new(1_000);
    HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
}

fn signed_transition_link(grantee: &Did, permission: Permission) -> AuthorityLink {
    let (pk, sk) = crypto::generate_keypair();
    let grantor = did("did:exo:governance-root");
    let mut link = AuthorityLink {
        grantor,
        grantee: grantee.clone(),
        permissions: PermissionSet::new(vec![permission]),
        signature: Vec::new(),
        grantor_public_key: Some(pk.as_bytes().to_vec()),
    };
    let message = authority_link_signature_message(&link).expect("canonical");
    link.signature = crypto::sign(message.as_bytes(), &sk).to_bytes().to_vec();
    link
}

fn signed_provenance(actor: &Did) -> Provenance {
    let (pk, sk) = crypto::generate_keypair();
    let mut provenance = Provenance {
        actor: actor.clone(),
        timestamp: "2026-07-18T00:00:00Z".into(),
        action_hash: vec![0x01, 0x02, 0x03],
        signature: Vec::new(),
        public_key: Some(pk.as_bytes().to_vec()),
        voice_kind: None,
        independence: None,
        review_order: None,
    };
    let message = provenance_signature_message(&provenance).expect("canonical");
    provenance.signature = crypto::sign(message.as_bytes(), &sk).to_bytes().to_vec();
    provenance
}

fn transition_context(actor: &Did, from: BctsState, to: BctsState) -> AdjudicationContext {
    let permission = bcts_transition_permission(from, to);
    let authority_chain = AuthorityChain {
        links: vec![signed_transition_link(actor, permission.clone())],
    };
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    for link in &authority_chain.links {
        if let Some(public_key) = &link.grantor_public_key {
            trusted_authority_keys.insert(link.grantor.clone(), vec![public_key.clone()]);
        }
    }
    let provenance = signed_provenance(actor);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    if let Some(public_key) = &provenance.public_key {
        trusted_provenance_keys.insert(actor.clone(), vec![public_key.clone()]);
    }
    AdjudicationContext {
        actor_roles: vec![Role {
            name: "transition-judge".into(),
            branch: GovernmentBranch::Judicial,
        }],
        authority_chain,
        consent_records: vec![ConsentRecord {
            subject: did("did:exo:bailor"),
            granted_to: actor.clone(),
            scope: "bcts:transition".into(),
            active: true,
        }],
        bailment_state: BailmentState::Active {
            bailor: did("did:exo:bailor"),
            bailee: actor.clone(),
            scope: "bcts:transition".into(),
        },
        human_override_preserved: true,
        actor_permissions: PermissionSet::new(vec![permission]),
        trusted_authority_keys,
        trusted_provenance_keys,
        provenance: Some(provenance),
        quorum_evidence: None,
        active_challenge_reason: None,
    }
}

fn make_approved_decision(
    class: DecisionClass,
    id: u128,
    human_voter: &Did,
    clock: &mut HybridClock,
) -> DecisionObject {
    let actor = did("did:exo:governance-author");
    let mut d = DecisionObject::new(DecisionObjectInput {
        id: Uuid::from_u128(id),
        title: "IntelWar doctrine evidence decision".into(),
        class,
        constitutional_hash: Hash256::digest(CONSTITUTION),
        created_at: clock.now().expect("hlc"),
    })
    .expect("decision");

    d.add_evidence(EvidenceItem {
        hash: Hash256::digest(b"doctrine-evidence"),
        description: "Doctrine supporting materials".into(),
        attached_at: clock.now().expect("hlc"),
    })
    .expect("evidence");

    d.add_vote(Vote {
        voter_did: human_voter.clone(),
        choice: VoteChoice::Approve,
        actor_kind: ActorKind::Human,
        timestamp: clock.now().expect("hlc"),
        signature_hash: Hash256::digest(b"vote-sig"),
    })
    .expect("vote");

    let kernel = Kernel::new(CONSTITUTION, exo_gatekeeper::InvariantSet::all());
    for state in [
        BctsState::Submitted,
        BctsState::IdentityResolved,
        BctsState::ConsentValidated,
        BctsState::Deliberated,
        BctsState::Verified,
        BctsState::Governed,
        BctsState::Approved,
    ] {
        let from = d.state;
        let ts = clock.now().expect("hlc");
        let action = ActionRequest {
            actor: actor.clone(),
            action: bcts_transition_action_name(from, state),
            required_permissions: PermissionSet::new(vec![bcts_transition_permission(from, state)]),
            is_self_grant: false,
            modifies_kernel: false,
        };
        let context = transition_context(&actor, from, state);
        d.transition_adjudicated_at(state, &actor, ts, &kernel, &action, &context)
            .expect("lifecycle");
    }
    d
}

fn fixture_append_keys() -> (
    Did,
    exo_core::SecretKey,
    exo_core::PublicKey,
    Did,
    exo_core::SecretKey,
    exo_core::PublicKey,
) {
    let actor = did("did:exo:intelwar-actor");
    let (actor_pk, actor_sk) = crypto::generate_keypair();
    let root = did("did:exo:intelwar-root");
    let (root_pk, root_sk) = crypto::generate_keypair();
    (actor, actor_sk, actor_pk, root, root_sk, root_pk)
}

#[test]
fn doctrine_append_fails_without_decision_object() {
    let (actor, actor_sk, actor_pk, root, root_sk, root_pk) = fixture_append_keys();
    let bailor = did("did:exo:intelwar-bailor");
    let link = signed_authority_link(&root, &actor, &root_sk).expect("link");
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(root, vec![root_pk.as_bytes().to_vec()]);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(actor.clone(), vec![actor_pk.as_bytes().to_vec()]);

    let mut body = development_decision_body(
        "doctrine-missing-decision",
        actor.clone(),
        Timestamp::new(1_752_854_400_000, 0),
        "Doctrine without forum evidence",
        br#"{"kind":"doctrine"}"#.to_vec(),
        Vec::new(),
    );
    body.entry_kind = EntryKind::Doctrine;

    let request = AppendRequest {
        entry_body: body,
        actor_secret_key: actor_sk,
        actor_roles: vec![judicial_role()],
        bailment_state: BailmentState::Active {
            bailor: bailor.clone(),
            bailee: actor.clone(),
            scope: LOG_APPEND_PERMISSION.into(),
        },
        consent_records: vec![ConsentRecord {
            subject: bailor,
            granted_to: actor,
            scope: LOG_APPEND_PERMISSION.into(),
            active: true,
        }],
        authority_chain: AuthorityChain { links: vec![link] },
        trusted_authority_keys,
        trusted_provenance_keys,
        human_override_preserved: true,
        previous_receipt_hash: None,
        crosschecks: Vec::new(),
        debate: None,
        debate_decision: None,
        verified_human_voters: BTreeSet::new(),
        provenance_timestamp: "hlc:1752854400000:0".into(),
    };

    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::with_time(1_752_854_400_000);
    let err = append_log_entry(&mut dag, &mut clock, request).expect_err("must deny");
    assert!(
        err.to_string().contains("debate_decision"),
        "unexpected: {err}"
    );
    assert!(dag.is_empty());
}

#[test]
fn doctrine_append_succeeds_with_approved_strategic_decision() {
    let human = did("did:exo:intelwar-human-voter");
    let mut forum_clock = test_clock();
    let decision =
        make_approved_decision(DecisionClass::Strategic, 9001, &human, &mut forum_clock);
    let session = debate_session_from_decision(&decision).expect("session");

    let (actor, actor_sk, actor_pk, root, root_sk, root_pk) = fixture_append_keys();
    let bailor = did("did:exo:intelwar-bailor");
    let link = signed_authority_link(&root, &actor, &root_sk).expect("link");
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(root, vec![root_pk.as_bytes().to_vec()]);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(actor.clone(), vec![actor_pk.as_bytes().to_vec()]);

    let mut body = development_decision_body(
        "doctrine-with-forum",
        actor.clone(),
        Timestamp::new(1_752_854_400_000, 0),
        "Doctrine linked to decision-forum",
        br#"{"kind":"doctrine"}"#.to_vec(),
        Vec::new(),
    );
    body.entry_kind = EntryKind::Doctrine;

    let mut verified = BTreeSet::new();
    verified.insert(human);

    let request = AppendRequest {
        entry_body: body,
        actor_secret_key: actor_sk,
        actor_roles: vec![judicial_role()],
        bailment_state: BailmentState::Active {
            bailor: bailor.clone(),
            bailee: actor.clone(),
            scope: LOG_APPEND_PERMISSION.into(),
        },
        consent_records: vec![ConsentRecord {
            subject: bailor,
            granted_to: actor,
            scope: LOG_APPEND_PERMISSION.into(),
            active: true,
        }],
        authority_chain: AuthorityChain { links: vec![link] },
        trusted_authority_keys,
        trusted_provenance_keys,
        human_override_preserved: true,
        previous_receipt_hash: None,
        crosschecks: Vec::new(),
        debate: Some(session.clone()),
        debate_decision: Some(decision),
        verified_human_voters: verified,
        provenance_timestamp: "hlc:1752854400000:0".into(),
    };

    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::with_time(1_752_854_400_000);
    let receipt = append_log_entry(&mut dag, &mut clock, request).expect("append");
    assert_eq!(dag.len(), 1);
    assert_eq!(
        receipt.entry.debate_ref.as_deref(),
        Some(session.decision_id.as_str())
    );
    assert_eq!(receipt.living_receipt.kernel_verdict, "permitted");
}

#[test]
fn doctrine_append_fails_human_gate_without_verified_voters() {
    let human = did("did:exo:intelwar-human-voter");
    let mut forum_clock = test_clock();
    let decision =
        make_approved_decision(DecisionClass::Strategic, 9002, &human, &mut forum_clock);

    let (actor, actor_sk, actor_pk, root, root_sk, root_pk) = fixture_append_keys();
    let bailor = did("did:exo:intelwar-bailor");
    let link = signed_authority_link(&root, &actor, &root_sk).expect("link");
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(root, vec![root_pk.as_bytes().to_vec()]);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(actor.clone(), vec![actor_pk.as_bytes().to_vec()]);

    let mut body = development_decision_body(
        "doctrine-no-verified-human",
        actor.clone(),
        Timestamp::new(1_752_854_400_000, 0),
        "Doctrine missing verified human gate",
        br#"{"kind":"doctrine"}"#.to_vec(),
        Vec::new(),
    );
    body.entry_kind = EntryKind::Doctrine;

    let request = AppendRequest {
        entry_body: body,
        actor_secret_key: actor_sk,
        actor_roles: vec![judicial_role()],
        bailment_state: BailmentState::Active {
            bailor: bailor.clone(),
            bailee: actor.clone(),
            scope: LOG_APPEND_PERMISSION.into(),
        },
        consent_records: vec![ConsentRecord {
            subject: bailor,
            granted_to: actor,
            scope: LOG_APPEND_PERMISSION.into(),
            active: true,
        }],
        authority_chain: AuthorityChain { links: vec![link] },
        trusted_authority_keys,
        trusted_provenance_keys,
        human_override_preserved: true,
        previous_receipt_hash: None,
        crosschecks: Vec::new(),
        debate: None,
        debate_decision: Some(decision),
        verified_human_voters: BTreeSet::new(),
        provenance_timestamp: "hlc:1752854400000:0".into(),
    };

    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::with_time(1_752_854_400_000);
    let err = append_log_entry(&mut dag, &mut clock, request).expect_err("must deny");
    assert!(
        err.to_string().contains("human gate"),
        "unexpected: {err}"
    );
    assert!(dag.is_empty());
}
