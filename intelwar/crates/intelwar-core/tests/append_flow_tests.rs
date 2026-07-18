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

//! Integration tests for Living Log append flow.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use exo_core::{Did, Timestamp, crypto};
use exo_dag::dag::{Dag, DeterministicDagClock};
use exo_gatekeeper::types::{
    AuthorityChain, BailmentState, ConsentRecord, TrustedAuthorityKeys, TrustedProvenanceKeys,
};
use intelwar_core::{
    AppendRequest, LOG_APPEND_PERMISSION, append_log_entry, development_decision_body,
    judicial_role, signed_authority_link,
};

fn did(s: &str) -> Did {
    Did::new(s).expect("valid did")
}

fn fixture_keys() -> (
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
fn append_genesis_development_decision_succeeds() {
    let (actor, actor_sk, actor_pk, root, root_sk, root_pk) = fixture_keys();
    let bailor = did("did:exo:intelwar-bailor");

    let link = signed_authority_link(&root, &actor, &root_sk).expect("signed link");
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(root, vec![root_pk.as_bytes().to_vec()]);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(actor.clone(), vec![actor_pk.as_bytes().to_vec()]);

    let body = development_decision_body(
        "entry-genesis-001",
        actor.clone(),
        Timestamp::new(1_752_854_400_000, 0),
        "Bootstrap IntelWar Living Log on EXOCHAIN v0.2.3",
        br#"{"refs":["INTELWAR_CONSTITUTION.md"]}"#.to_vec(),
        Vec::new(),
    );

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
        provenance_timestamp: "2026-07-18T00:00:00Z".into(),
    };

    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::with_time(1_752_854_400_000);
    let receipt = append_log_entry(&mut dag, &mut clock, request).expect("append");

    assert_eq!(dag.len(), 1);
    assert_eq!(receipt.living_receipt.kernel_verdict, "permitted");
    assert_eq!(receipt.living_receipt.intelwar_verdict, "permitted");
    assert!(!receipt.living_receipt.signature.is_empty());
    assert_eq!(receipt.dag_node_hash, receipt.living_receipt.dag_node_hash);
}

#[test]
fn append_is_deterministic_for_same_logical_inputs() {
    let run = || {
        // Determinism of content hash for identical sealed bodies
        let author = did("did:exo:intelwar-actor");
        let body = development_decision_body(
            "entry-det-001",
            author,
            Timestamp::new(100, 1),
            "determinism check",
            b"payload".to_vec(),
            Vec::new(),
        );
        body.compute_content_hash().expect("hash")
    };
    assert_eq!(run(), run());
}

#[test]
fn append_fails_without_consent() {
    let (actor, actor_sk, actor_pk, root, root_sk, root_pk) = fixture_keys();
    let link = signed_authority_link(&root, &actor, &root_sk).expect("signed link");
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(root, vec![root_pk.as_bytes().to_vec()]);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(actor.clone(), vec![actor_pk.as_bytes().to_vec()]);

    let body = development_decision_body(
        "entry-noconnect",
        actor.clone(),
        Timestamp::new(1, 0),
        "should fail",
        Vec::new(),
        Vec::new(),
    );

    let request = AppendRequest {
        entry_body: body,
        actor_secret_key: actor_sk,
        actor_roles: vec![judicial_role()],
        bailment_state: BailmentState::None,
        consent_records: Vec::new(),
        authority_chain: AuthorityChain { links: vec![link] },
        trusted_authority_keys,
        trusted_provenance_keys,
        human_override_preserved: true,
        previous_receipt_hash: None,
        crosschecks: Vec::new(),
        debate: None,
        provenance_timestamp: "2026-07-18T00:00:00Z".into(),
    };

    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::new();
    let err = append_log_entry(&mut dag, &mut clock, request).expect_err("must deny");
    let msg = err.to_string();
    assert!(
        msg.contains("consent") || msg.contains("bailment"),
        "unexpected error: {msg}"
    );
    assert!(dag.is_empty());
}
