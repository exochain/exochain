// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/crosschecked_anchor_governance.rs"]
mod governance_support;

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use exo_api::crosschecked_anchor::{ANCHOR_PATH, CrossCheckedAnchorRequestV1};
use exo_authority::{AuthorityChain, AuthorityLink, DelegateeKind, Permission};
use exo_core::{
    crypto::KeyPair,
    types::{Did, Hash256, Signature, Timestamp},
};
use exo_identity::did::{DidDocument, VerificationMethod};
use exo_node::crosschecked_anchor_store::{
    AnchorConflictKind, AnchorNodeIdentity, AnchorRecordDisposition, AnchorStore,
    AnchorStoreConfig, AnchorStoreError, AuthorityLifecycleEventV1, AuthorityProvisioningV1,
    AuthorityRetirementV1, CrossCheckedScopeBindingV1, DurableAnchorSigner, SignOnceError,
    SubmissionContext, authority_chain_fingerprint,
};
use governance_support::{
    GOVERNANCE_KEY_EPOCH, configure_governance, governance_group_public_key,
    governance_group_public_key_for_seed, provisioning_authorization, resign_authorization,
    retirement_authorization,
};
use tempfile::TempDir;

const AUDIENCE: &str = "crosschecked.production";
const INTERMEDIATE_DID: &str = "did:exo:crosschecked-intermediate";
const INTERMEDIATE_KEY_ID: &str = "did:exo:crosschecked-intermediate#key-1";
const NODE_DID: &str = "did:exo:anchor-node";
const NODE_KEY_ID: &str = "did:exo:anchor-node#response-2026";
const ISSUED_AT: u64 = 1_800_000_000_000;

#[derive(Debug)]
struct CountingDurableSigner {
    identity: AnchorNodeIdentity,
    key: KeyPair,
    reservations: Mutex<BTreeMap<Hash256, Timestamp>>,
    operations: Mutex<BTreeMap<Hash256, (Hash256, Signature)>>,
    unique_calls: AtomicUsize,
    fail_next: AtomicUsize,
}

impl CountingDurableSigner {
    fn new(identity: AnchorNodeIdentity, secret: [u8; 32]) -> Self {
        Self {
            identity,
            key: KeyPair::from_secret_bytes(secret).expect("fixed signer key"),
            reservations: Mutex::new(BTreeMap::new()),
            operations: Mutex::new(BTreeMap::new()),
            unique_calls: AtomicUsize::new(0),
            fail_next: AtomicUsize::new(0),
        }
    }

    fn fail_next_operation(&self) {
        self.fail_next.store(1, Ordering::SeqCst);
    }

    fn unique_calls(&self) -> usize {
        self.unique_calls.load(Ordering::SeqCst)
    }
}

impl DurableAnchorSigner for CountingDurableSigner {
    fn identity(&self) -> AnchorNodeIdentity {
        self.identity.clone()
    }

    fn reserved_recorded_at(
        &self,
        request_hash: Hash256,
    ) -> Result<Option<Timestamp>, SignOnceError> {
        Ok(self
            .reservations
            .lock()
            .map_err(|_| SignOnceError::Unavailable("test reservation lock poisoned".into()))?
            .get(&request_hash)
            .copied())
    }

    fn reserve_recorded_at(
        &self,
        request_hash: Hash256,
        proposed: Timestamp,
    ) -> Result<Timestamp, SignOnceError> {
        Ok(*self
            .reservations
            .lock()
            .map_err(|_| SignOnceError::Unavailable("test reservation lock poisoned".into()))?
            .entry(request_hash)
            .or_insert(proposed))
    }

    fn sign_once(&self, operation_id: Hash256, payload: &[u8]) -> Result<Signature, SignOnceError> {
        if self
            .fail_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(SignOnceError::Unavailable(
                "injected pre-commit failure".into(),
            ));
        }

        let payload_hash = Hash256::digest(payload);
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| SignOnceError::Unavailable("test signer lock poisoned".into()))?;
        if let Some((stored_hash, signature)) = operations.get(&operation_id) {
            if stored_hash != &payload_hash {
                return Err(SignOnceError::OperationPayloadConflict);
            }
            return Ok(signature.clone());
        }

        let signature = self.key.sign(payload);
        operations.insert(operation_id, (payload_hash, signature.clone()));
        self.unique_calls.fetch_add(1, Ordering::SeqCst);
        Ok(signature)
    }
}

struct Harness {
    _temp: TempDir,
    path: std::path::PathBuf,
    store: AnchorStore,
    intermediate_key: KeyPair,
    authority_key: KeyPair,
    authority_did: String,
    authority_key_id: String,
    grant_id: [u8; 32],
    scope_alias: [u8; 32],
    signer: Arc<CountingDurableSigner>,
    config: AnchorStoreConfig,
    provisioning_authorization_hash: Hash256,
}

impl Harness {
    fn new() -> Self {
        let temp = TempDir::new().expect("temp directory");
        let path = temp.path().join("crosschecked-anchor.sqlite3");
        let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
        let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
        let node_identity = AnchorNodeIdentity {
            did: NODE_DID.to_owned(),
            key_id: NODE_KEY_ID.to_owned(),
            public_key: *node_key.public_key(),
        };
        let mut config = AnchorStoreConfig {
            expected_audience: AUDIENCE.to_owned(),
            crosschecked_intermediate_did: INTERMEDIATE_DID.to_owned(),
            crosschecked_intermediate_key_id: INTERMEDIATE_KEY_ID.to_owned(),
            crosschecked_intermediate_public_key: *intermediate_key.public_key(),
            governance_frost_group_public_key: governance_group_public_key(),
            governance_frost_key_epoch: GOVERNANCE_KEY_EPOCH,
            node_identity: node_identity.clone(),
        };
        configure_governance(&mut config);
        let store = AnchorStore::open(&path, config.clone()).expect("open store");
        let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
        let authority_did = "did:exo:crosschecked-workspace-a".to_owned();
        let authority_key_id = format!("{authority_did}#anchor-1");
        let grant_id = [0x31; 32];
        let scope_alias = [0x42; 32];
        let provisioning = provisioning(
            &intermediate_key,
            &authority_key,
            &authority_did,
            &authority_key_id,
            grant_id,
            scope_alias,
            Permission::AnchorReceiptCommitment,
            1,
        );
        let provisioning_authorization = provisioning_authorization(
            &config,
            &provisioning,
            1,
            Hash256::from_bytes([0; 32]),
            0x71,
            0x7001,
        );
        let provisioning_authorization_hash = provisioning_authorization
            .authorization_hash()
            .expect("provisioning authorization hash");
        store
            .provision_authority(
                &provisioning,
                &provisioning_authorization,
                provisioning.scope_binding.valid_from_ms,
            )
            .expect("provision authority");
        let signer = Arc::new(CountingDurableSigner::new(node_identity, [0x29; 32]));
        Self {
            _temp: temp,
            path,
            store,
            intermediate_key,
            authority_key,
            authority_did,
            authority_key_id,
            grant_id,
            scope_alias,
            signer,
            config,
            provisioning_authorization_hash,
        }
    }

    fn request(&self, action_byte: u8, nonce_byte: u8) -> Vec<u8> {
        signed_request(
            &self.authority_key,
            &self.authority_did,
            &self.authority_key_id,
            self.grant_id,
            self.scope_alias,
            [action_byte; 32],
            [nonce_byte; 32],
            ISSUED_AT,
            ISSUED_AT + 300_000,
        )
    }

    fn submission<'a>(&self, body: &'a [u8], now: Timestamp) -> SubmissionContext<'a> {
        SubmissionContext {
            method: "POST",
            path: ANCHOR_PATH,
            content_type: "application/cbor",
            body,
            now,
        }
    }

    fn retirement(&self, retired_at_ms: u64) -> AuthorityRetirementV1 {
        let mut retirement = AuthorityRetirementV1 {
            protocol_version: 1,
            authority_did: did(&self.authority_did),
            authority_key_id: self.authority_key_id.clone(),
            key_epoch: 1,
            retired_at_ms,
            signer_did: did(INTERMEDIATE_DID),
            signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
            signature: Signature::empty(),
        };
        retirement.signature = self
            .intermediate_key
            .sign(&retirement.signing_preimage().expect("retirement payload"));
        retirement
    }
}

fn did(value: &str) -> Did {
    Did::new(value).expect("valid did")
}

fn did_document(did_value: &str, key_id: &str, key: &KeyPair, version: u64) -> DidDocument {
    let did = did(did_value);
    DidDocument {
        id: did.clone(),
        public_keys: vec![*key.public_key()],
        authentication: vec![],
        verification_methods: vec![VerificationMethod {
            id: key_id.to_owned(),
            key_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did,
            public_key_multibase: format!(
                "z{}",
                bs58::encode(key.public_key().as_bytes()).into_string()
            ),
            version,
            active: true,
            valid_from: ISSUED_AT - 10_000,
            revoked_at: None,
        }],
        hybrid_verification_methods: vec![],
        service_endpoints: vec![],
        created: Timestamp::new(ISSUED_AT - 10_000, 0),
        updated: Timestamp::new(ISSUED_AT - 10_000, 0),
        revoked: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn provisioning(
    intermediate_key: &KeyPair,
    authority_key: &KeyPair,
    authority_did: &str,
    authority_key_id: &str,
    grant_id: [u8; 32],
    scope_alias: [u8; 32],
    permission: Permission,
    key_epoch: u64,
) -> AuthorityProvisioningV1 {
    let mut link = AuthorityLink {
        delegator_did: did(INTERMEDIATE_DID),
        delegate_did: did(authority_did),
        scope: vec![permission],
        created: Timestamp::new(ISSUED_AT - 10_000, 0),
        expires: Some(Timestamp::new(ISSUED_AT + 3_600_000, 0)),
        signature: Signature::empty(),
        depth: 0,
        delegatee_kind: DelegateeKind::Unknown,
    };
    link.signature = intermediate_key.sign(&link.signing_payload().expect("link payload"));
    let chain = AuthorityChain {
        links: vec![link],
        max_depth: 5,
    };
    let mut binding = CrossCheckedScopeBindingV1 {
        protocol_version: 1,
        authority_did: did(authority_did),
        authority_key_id: authority_key_id.to_owned(),
        grant_id,
        scope_alias,
        audience: AUDIENCE.to_owned(),
        permission: Permission::AnchorReceiptCommitment,
        key_epoch,
        valid_from_ms: ISSUED_AT - 5_000,
        valid_until_ms: ISSUED_AT + 3_000_000,
        chain_fingerprint: authority_chain_fingerprint(&chain).expect("chain fingerprint"),
        binding_signer_did: did(INTERMEDIATE_DID),
        binding_signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        signature: Signature::empty(),
    };
    binding.signature =
        intermediate_key.sign(&binding.signing_preimage().expect("binding payload"));
    AuthorityProvisioningV1 {
        protocol_version: 1,
        did_documents: vec![
            did_document(INTERMEDIATE_DID, INTERMEDIATE_KEY_ID, intermediate_key, 1),
            did_document(authority_did, authority_key_id, authority_key, key_epoch),
        ],
        authority_chain: chain,
        scope_binding: binding,
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_request(
    key: &KeyPair,
    authority_did: &str,
    authority_key_id: &str,
    grant_id: [u8; 32],
    scope_alias: [u8; 32],
    action_hash: [u8; 32],
    nonce: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Vec<u8> {
    let mut request = CrossCheckedAnchorRequestV1 {
        protocol_version: 1,
        source_code: "crosschecked".to_owned(),
        receipt_format: "action_receipt_v3".to_owned(),
        audience: AUDIENCE.to_owned(),
        authority_did: authority_did.to_owned(),
        authority_key_id: authority_key_id.to_owned(),
        grant_id,
        scope_alias,
        action_hash_algorithm: "blake3-256".to_owned(),
        action_hash,
        idempotency_key: [0; 32],
        nonce,
        issued_at_ms,
        expires_at_ms,
        signature_algorithm: "ed25519".to_owned(),
        signature: [0; 64],
    };
    request.idempotency_key = request.derive_idempotency_key().expect("idempotency");
    request.signature = *key
        .sign(&request.signing_preimage().expect("request payload"))
        .ed25519_bytes()
        .expect("Ed25519 signature");
    request.to_canonical_cbor().expect("request body")
}

fn count_rows(path: &Path, table: &str) -> i64 {
    let connection = rusqlite::Connection::open(path).expect("open sqlite");
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("row count")
}

#[test]
fn authority_provisioning_rejects_missing_permission_and_key_epoch_substitution() {
    let temp = TempDir::new().expect("temp");
    let path = temp.path().join("authority.sqlite3");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate");
    let config = AnchorStoreConfig {
        expected_audience: AUDIENCE.to_owned(),
        crosschecked_intermediate_did: INTERMEDIATE_DID.to_owned(),
        crosschecked_intermediate_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        crosschecked_intermediate_public_key: *intermediate.public_key(),
        governance_frost_group_public_key: governance_group_public_key(),
        governance_frost_key_epoch: GOVERNANCE_KEY_EPOCH,
        node_identity: AnchorNodeIdentity {
            did: NODE_DID.to_owned(),
            key_id: NODE_KEY_ID.to_owned(),
            public_key: *node_key.public_key(),
        },
    };
    let store = AnchorStore::open(&path, config.clone()).expect("store");
    let authority = KeyPair::from_secret_bytes([0x17; 32]).expect("authority");
    let authority_did = "did:exo:workspace-denied";
    let key_id = format!("{authority_did}#anchor-1");

    let missing_permission = provisioning(
        &intermediate,
        &authority,
        authority_did,
        &key_id,
        [0x31; 32],
        [0x42; 32],
        Permission::Write,
        1,
    );
    let missing_permission_authorization = provisioning_authorization(
        &config,
        &missing_permission,
        1,
        Hash256::from_bytes([0; 32]),
        0x72,
        0x7002,
    );
    assert!(matches!(
        store.provision_authority(
            &missing_permission,
            &missing_permission_authorization,
            missing_permission.scope_binding.valid_from_ms,
        ),
        Err(AnchorStoreError::AuthorityValidation(_))
    ));

    let mut wrong_epoch = provisioning(
        &intermediate,
        &authority,
        authority_did,
        &key_id,
        [0x31; 32],
        [0x42; 32],
        Permission::AnchorReceiptCommitment,
        1,
    );
    wrong_epoch.scope_binding.key_epoch = 2;
    wrong_epoch.scope_binding.signature = intermediate.sign(
        &wrong_epoch
            .scope_binding
            .signing_preimage()
            .expect("wrong-epoch binding payload"),
    );
    let wrong_epoch_authorization = provisioning_authorization(
        &config,
        &wrong_epoch,
        1,
        Hash256::from_bytes([0; 32]),
        0x73,
        0x7003,
    );
    assert!(matches!(
        store.provision_authority(
            &wrong_epoch,
            &wrong_epoch_authorization,
            wrong_epoch.scope_binding.valid_from_ms,
        ),
        Err(AnchorStoreError::AuthorityValidation(_))
    ));
    assert_eq!(count_rows(&path, "crosschecked_anchor_authorities"), 0);
}

#[test]
fn authority_provisioning_rejects_substituted_intermediate_key_for_pinned_did() {
    let temp = TempDir::new().expect("temp");
    let path = temp.path().join("intermediate-substitution.sqlite3");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let trusted_intermediate =
        KeyPair::from_secret_bytes([0x41; 32]).expect("trusted intermediate");
    let attacker_intermediate =
        KeyPair::from_secret_bytes([0x42; 32]).expect("attacker intermediate");
    let config = AnchorStoreConfig {
        expected_audience: AUDIENCE.to_owned(),
        crosschecked_intermediate_did: INTERMEDIATE_DID.to_owned(),
        crosschecked_intermediate_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        crosschecked_intermediate_public_key: *trusted_intermediate.public_key(),
        governance_frost_group_public_key: governance_group_public_key(),
        governance_frost_key_epoch: GOVERNANCE_KEY_EPOCH,
        node_identity: AnchorNodeIdentity {
            did: NODE_DID.to_owned(),
            key_id: NODE_KEY_ID.to_owned(),
            public_key: *node_key.public_key(),
        },
    };
    let store = AnchorStore::open(&path, config.clone()).expect("store");
    let authority = KeyPair::from_secret_bytes([0x17; 32]).expect("authority");
    let authority_did = "did:exo:attacker-workspace";
    let candidate = provisioning(
        &attacker_intermediate,
        &authority,
        authority_did,
        &format!("{authority_did}#anchor-1"),
        [0x31; 32],
        [0x42; 32],
        Permission::AnchorReceiptCommitment,
        1,
    );
    let candidate_authorization = provisioning_authorization(
        &config,
        &candidate,
        1,
        Hash256::from_bytes([0; 32]),
        0x74,
        0x7004,
    );

    assert!(matches!(
        store.provision_authority(
            &candidate,
            &candidate_authorization,
            candidate.scope_binding.valid_from_ms,
        ),
        Err(AnchorStoreError::AuthorityValidation(_))
    ));
    assert_eq!(count_rows(&path, "crosschecked_anchor_authorities"), 0);
}

#[test]
fn authority_chain_fingerprint_commits_to_complete_signed_links() {
    let intermediate = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate");
    let authority = KeyPair::from_secret_bytes([0x17; 32]).expect("authority");
    let authority_did = "did:exo:fingerprint-workspace";
    let provisioning = provisioning(
        &intermediate,
        &authority,
        authority_did,
        &format!("{authority_did}#anchor-1"),
        [0x31; 32],
        [0x42; 32],
        Permission::AnchorReceiptCommitment,
        1,
    );
    let original =
        authority_chain_fingerprint(&provisioning.authority_chain).expect("original fingerprint");
    let mut signature_substitution = provisioning.authority_chain;
    signature_substitution.links[0].signature = Signature::from_bytes([0xA5; 64]);

    assert_ne!(
        authority_chain_fingerprint(&signature_substitution).expect("substituted fingerprint"),
        original,
        "the full signed delegation artifact must be committed"
    );
}

#[test]
fn first_record_atomically_persists_every_component_and_authenticated_readback() {
    let harness = Harness::new();
    let body = harness.request(0x53, 0x64);
    let recorded = harness
        .store
        .record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 7)),
            harness.signer.as_ref(),
        )
        .expect("record");

    assert_eq!(recorded.disposition, AnchorRecordDisposition::Created);
    assert_eq!(recorded.request_hash, Hash256::digest(&body));
    assert_eq!(recorded.action_hash, Hash256::from_bytes([0x53; 32]));
    assert_eq!(harness.signer.unique_calls(), 2);
    for table in [
        "crosschecked_anchor_requests",
        "crosschecked_anchor_idempotency",
        "crosschecked_anchor_receipts",
        "crosschecked_anchor_responses",
    ] {
        assert_eq!(count_rows(&harness.path, table), 1, "table {table}");
    }
    assert_eq!(
        count_rows(&harness.path, "crosschecked_anchor_signatures"),
        2
    );

    let readback = harness
        .store
        .readback_action("crosschecked", &[0x53; 32])
        .expect("readback")
        .expect("stored record");
    assert_eq!(readback.response_body, recorded.response_body);
    assert_eq!(
        readback.response.exochain_receipt,
        recorded.response.exochain_receipt
    );
}

#[test]
fn one_hundred_concurrent_identical_requests_create_one_record_and_one_signature_pair() {
    let harness = Harness::new();
    let body = Arc::new(harness.request(0x53, 0x64));
    let store = Arc::new(harness.store);
    let signer = harness.signer.clone();
    let barrier = Arc::new(Barrier::new(100));
    let mut threads = Vec::new();

    for _ in 0..100 {
        let body = body.clone();
        let store = store.clone();
        let signer = signer.clone();
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            store
                .record(
                    SubmissionContext {
                        method: "POST",
                        path: ANCHOR_PATH,
                        content_type: "application/cbor",
                        body: body.as_slice(),
                        now: Timestamp::new(ISSUED_AT + 123, 7),
                    },
                    signer.as_ref(),
                )
                .expect("concurrent record")
        }));
    }

    let records: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("join"))
        .collect();
    let created = records
        .iter()
        .filter(|record| record.disposition == AnchorRecordDisposition::Created)
        .count();
    let expected = records[0].response_body.clone();
    assert_eq!(created, 1);
    assert!(
        records
            .iter()
            .all(|record| record.response_body == expected)
    );
    assert_eq!(signer.unique_calls(), 2);
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 1);
}

#[test]
fn idempotency_and_cross_scope_action_conflicts_are_typed_and_persist_nothing_extra() {
    let harness = Harness::new();
    let body = harness.request(0x53, 0x64);
    harness
        .store
        .record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref(),
        )
        .expect("first record");

    let same_idempotency_different_body = harness.request(0x53, 0x65);
    assert_eq!(
        harness.store.record(
            harness.submission(
                &same_idempotency_different_body,
                Timestamp::new(ISSUED_AT + 124, 0)
            ),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::Conflict(
            AnchorConflictKind::IdempotencyKey
        ))
    );

    let other_key = KeyPair::from_secret_bytes([0x18; 32]).expect("other authority");
    let other_did = "did:exo:crosschecked-workspace-b";
    let other_key_id = format!("{other_did}#anchor-1");
    let other_provisioning = provisioning(
        &harness.intermediate_key,
        &other_key,
        other_did,
        &other_key_id,
        [0x32; 32],
        [0x43; 32],
        Permission::AnchorReceiptCommitment,
        1,
    );
    let other_authorization = provisioning_authorization(
        &harness.config,
        &other_provisioning,
        1,
        Hash256::from_bytes([0; 32]),
        0x75,
        0x7005,
    );
    harness
        .store
        .provision_authority(
            &other_provisioning,
            &other_authorization,
            other_provisioning.scope_binding.valid_from_ms,
        )
        .expect("second scope");
    let cross_scope = signed_request(
        &other_key,
        other_did,
        &other_key_id,
        [0x32; 32],
        [0x43; 32],
        [0x53; 32],
        [0x66; 32],
        ISSUED_AT,
        ISSUED_AT + 300_000,
    );
    assert_eq!(
        harness.store.record(
            harness.submission(&cross_scope, Timestamp::new(ISSUED_AT + 125, 0)),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::Conflict(AnchorConflictKind::ActionHash))
    );
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 1);
    assert_eq!(harness.signer.unique_calls(), 2);
}

#[test]
fn storage_abort_after_signing_rolls_back_all_rows_and_retry_reuses_signatures() {
    let harness = Harness::new();
    let body = harness.request(0x53, 0x64);
    let connection = rusqlite::Connection::open(&harness.path).expect("sqlite");
    connection
        .execute_batch(
            "CREATE TRIGGER inject_precommit_abort
             BEFORE INSERT ON crosschecked_anchor_requests
             BEGIN
               SELECT RAISE(ABORT, 'injected after signing before commit');
             END;",
        )
        .expect("install failure trigger");

    assert!(matches!(
        harness.store.record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::Storage(_))
    ));
    assert_eq!(harness.signer.unique_calls(), 2);
    for table in [
        "crosschecked_anchor_requests",
        "crosschecked_anchor_idempotency",
        "crosschecked_anchor_receipts",
        "crosschecked_anchor_responses",
        "crosschecked_anchor_signatures",
    ] {
        assert_eq!(count_rows(&harness.path, table), 0, "table {table}");
    }

    connection
        .execute_batch("DROP TRIGGER inject_precommit_abort;")
        .expect("remove failure trigger");
    let retry = harness
        .store
        .record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref(),
        )
        .expect("retry");
    assert_eq!(retry.disposition, AnchorRecordDisposition::Created);
    assert_eq!(
        harness.signer.unique_calls(),
        2,
        "retry must retrieve both durable sign-once results"
    );
}

#[test]
fn signer_failure_before_commit_leaves_zero_records_and_retry_creates_once() {
    let harness = Harness::new();
    let body = harness.request(0x53, 0x64);
    harness.signer.fail_next_operation();

    assert!(matches!(
        harness.store.record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::Signer(_))
    ));
    for table in [
        "crosschecked_anchor_requests",
        "crosschecked_anchor_idempotency",
        "crosschecked_anchor_receipts",
        "crosschecked_anchor_responses",
        "crosschecked_anchor_signatures",
    ] {
        assert_eq!(count_rows(&harness.path, table), 0, "table {table}");
    }

    let retry = harness
        .store
        .record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 124, 0)),
            harness.signer.as_ref(),
        )
        .expect("retry");
    assert_eq!(retry.disposition, AnchorRecordDisposition::Created);
    assert_eq!(harness.signer.unique_calls(), 2);
}

#[test]
fn lifecycle_mutations_require_frost_and_fail_atomically_on_expiry_or_event_substitution() {
    for case in [
        "no-frost",
        "expired",
        "event-substitution",
        "clock-regression",
        "six-signer-roster",
    ] {
        let harness = Harness::new();
        let retirement = harness.retirement(ISSUED_AT + 200);
        let mut authorization = retirement_authorization(
            &harness.config,
            &retirement,
            harness.scope_alias,
            AuthorityLifecycleEventV1::Retire,
            2,
            harness.provisioning_authorization_hash,
            0x78,
            0x7008,
        );
        let mut applied_at_ms = retirement.retired_at_ms;
        match case {
            "no-frost" => authorization.signature.fill(0),
            "expired" => {
                authorization.valid_until_ms = retirement.retired_at_ms;
                resign_authorization(&mut authorization, 0x7009);
            }
            "event-substitution" => {
                authorization.lifecycle_event = AuthorityLifecycleEventV1::Revoke;
                resign_authorization(&mut authorization, 0x7010);
            }
            "clock-regression" => {
                authorization.valid_from_ms = ISSUED_AT - 10_000;
                applied_at_ms = ISSUED_AT - 5_001;
                resign_authorization(&mut authorization, 0x7018);
            }
            "six-signer-roster" => {
                authorization.signer_ids.pop();
            }
            _ => unreachable!(),
        }

        assert!(matches!(
            harness
                .store
                .retire_authority(&retirement, &authorization, applied_at_ms),
            Err(AnchorStoreError::GovernanceAuthorization(_))
        ));
        assert_eq!(
            count_rows(
                &harness.path,
                "crosschecked_anchor_governance_authorizations"
            ),
            1,
            "{case} must not persist a governance authorization"
        );
        let retired_at: Option<i64> = rusqlite::Connection::open(&harness.path)
            .expect("sqlite")
            .query_row(
                "SELECT retired_at_ms FROM crosschecked_anchor_authorities",
                [],
                |row| row.get(0),
            )
            .expect("authority lifecycle state");
        assert_eq!(retired_at, None, "{case} must not mutate authority state");
    }
}

#[test]
fn governance_authorization_restarts_replay_exactly_and_conflicts_fail_closed() {
    let harness = Harness::new();
    let retirement = harness.retirement(ISSUED_AT + 200);
    let authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x79,
        0x7011,
    );
    harness
        .store
        .retire_authority(&retirement, &authorization, retirement.retired_at_ms)
        .expect("initial retirement");
    let applied_at_ms: i64 = rusqlite::Connection::open(&harness.path)
        .expect("sqlite")
        .query_row(
            "SELECT applied_at_ms FROM crosschecked_anchor_governance_authorizations
             WHERE authorization_sequence = 2",
            [],
            |row| row.get(0),
        )
        .expect("persisted first-application time");
    assert_eq!(
        u64::try_from(applied_at_ms).expect("non-negative application time"),
        retirement.retired_at_ms
    );

    let restarted = AnchorStore::open(&harness.path, harness.config.clone()).expect("restart");
    restarted
        .retire_authority(
            &retirement,
            &authorization,
            authorization.valid_until_ms + 1,
        )
        .expect("exact authorization replay after restart");
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        2,
        "exact replay must not duplicate authorization"
    );

    let conflicting_retirement = harness.retirement(ISSUED_AT + 201);
    let conflicting_authorization = retirement_authorization(
        &harness.config,
        &conflicting_retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x79,
        0x7012,
    );
    assert_eq!(
        restarted.retire_authority(
            &conflicting_retirement,
            &conflicting_authorization,
            conflicting_retirement.retired_at_ms,
        ),
        Err(AnchorStoreError::GovernanceAuthorizationConflict)
    );
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        2
    );
}

#[test]
fn governance_ceremony_id_is_single_use_and_conflict_is_atomic() {
    let harness = Harness::new();
    let retirement = harness.retirement(ISSUED_AT + 200);
    let mut authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x7f,
        0x7019,
    );
    authorization.ceremony_id = [0x71_u8.wrapping_add(0x40); 32];
    resign_authorization(&mut authorization, 0x7020);

    assert_eq!(
        harness
            .store
            .retire_authority(&retirement, &authorization, retirement.retired_at_ms,),
        Err(AnchorStoreError::GovernanceAuthorizationConflict)
    );
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        1,
        "a reused ceremony must not persist another authorization"
    );
    let retired_at: Option<i64> = rusqlite::Connection::open(&harness.path)
        .expect("sqlite")
        .query_row(
            "SELECT retired_at_ms FROM crosschecked_anchor_authorities",
            [],
            |row| row.get(0),
        )
        .expect("authority lifecycle state");
    assert_eq!(
        retired_at, None,
        "a ceremony conflict must roll back the authority mutation"
    );
}

#[test]
fn authority_lifecycle_transaction_rolls_back_state_when_authorization_insert_aborts() {
    let harness = Harness::new();
    let retirement = harness.retirement(ISSUED_AT + 200);
    let authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x7d,
        0x7016,
    );
    let connection = rusqlite::Connection::open(&harness.path).expect("sqlite");
    connection
        .execute_batch(
            "CREATE TRIGGER abort_governance_authorization_insert
             BEFORE INSERT ON crosschecked_anchor_governance_authorizations
             WHEN NEW.authorization_sequence = 2
             BEGIN
                 SELECT RAISE(ABORT, 'injected lifecycle commit failure');
             END;",
        )
        .expect("install failure trigger");
    assert!(
        harness
            .store
            .retire_authority(&retirement, &authorization, retirement.retired_at_ms)
            .is_err()
    );
    let retired_at: Option<i64> = connection
        .query_row(
            "SELECT retired_at_ms FROM crosschecked_anchor_authorities",
            [],
            |row| row.get(0),
        )
        .expect("authority state after abort");
    assert_eq!(
        retired_at, None,
        "retirement update must roll back atomically"
    );
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        1
    );

    connection
        .execute_batch("DROP TRIGGER abort_governance_authorization_insert;")
        .expect("remove failure trigger");
    harness
        .store
        .retire_authority(&retirement, &authorization, retirement.retired_at_ms)
        .expect("retry after rollback");
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        2
    );
}

#[test]
fn first_provision_transaction_rolls_back_authority_when_authorization_insert_aborts() {
    let temp = TempDir::new().expect("temp directory");
    let path = temp.path().join("provision-atomic.sqlite3");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let config = AnchorStoreConfig {
        expected_audience: AUDIENCE.to_owned(),
        crosschecked_intermediate_did: INTERMEDIATE_DID.to_owned(),
        crosschecked_intermediate_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        crosschecked_intermediate_public_key: *intermediate.public_key(),
        governance_frost_group_public_key: governance_group_public_key(),
        governance_frost_key_epoch: GOVERNANCE_KEY_EPOCH,
        node_identity: AnchorNodeIdentity {
            did: NODE_DID.to_owned(),
            key_id: NODE_KEY_ID.to_owned(),
            public_key: *node_key.public_key(),
        },
    };
    let store = AnchorStore::open(&path, config.clone()).expect("store");
    let authority = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let candidate = provisioning(
        &intermediate,
        &authority,
        "did:exo:atomic-workspace",
        "did:exo:atomic-workspace#anchor-1",
        [0x34; 32],
        [0x45; 32],
        Permission::AnchorReceiptCommitment,
        1,
    );
    let authorization = provisioning_authorization(
        &config,
        &candidate,
        1,
        Hash256::from_bytes([0; 32]),
        0x7e,
        0x7017,
    );
    let connection = rusqlite::Connection::open(&path).expect("sqlite");
    connection
        .execute_batch(
            "CREATE TRIGGER abort_first_governance_authorization_insert
             BEFORE INSERT ON crosschecked_anchor_governance_authorizations
             BEGIN
                 SELECT RAISE(ABORT, 'injected provisioning commit failure');
             END;",
        )
        .expect("install failure trigger");
    assert!(
        store
            .provision_authority(
                &candidate,
                &authorization,
                candidate.scope_binding.valid_from_ms,
            )
            .is_err()
    );
    assert_eq!(count_rows(&path, "crosschecked_anchor_authorities"), 0);
    assert_eq!(
        count_rows(&path, "crosschecked_anchor_governance_authorizations"),
        0
    );
    connection
        .execute_batch("DROP TRIGGER abort_first_governance_authorization_insert;")
        .expect("remove failure trigger");
    store
        .provision_authority(
            &candidate,
            &authorization,
            candidate.scope_binding.valid_from_ms,
        )
        .expect("retry after rollback");
    assert_eq!(count_rows(&path, "crosschecked_anchor_authorities"), 1);
    assert_eq!(
        count_rows(&path, "crosschecked_anchor_governance_authorizations"),
        1
    );
}

#[test]
fn missing_governance_predecessor_fails_route_before_signing_or_persistence() {
    let harness = Harness::new();
    rusqlite::Connection::open(&harness.path)
        .expect("sqlite")
        .execute(
            "DELETE FROM crosschecked_anchor_governance_authorizations",
            [],
        )
        .expect("simulate missing governance authorization");
    let body = harness.request(0x53, 0x64);
    assert!(matches!(
        harness.store.record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref(),
        ),
        Err(AnchorStoreError::ReadbackValidation(_))
    ));
    assert_eq!(harness.signer.unique_calls(), 0);
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 0);
}

#[test]
fn authority_rotation_requires_prior_frost_retirement_and_increasing_epoch() {
    let harness = Harness::new();
    let retirement = harness.retirement(ISSUED_AT + 200);
    let retirement_authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Revoke,
        2,
        harness.provisioning_authorization_hash,
        0x7a,
        0x7013,
    );
    harness
        .store
        .revoke_authority(
            &retirement,
            &retirement_authorization,
            retirement.retired_at_ms,
        )
        .expect("governance-authorized revocation");
    let retirement_authorization_hash = retirement_authorization
        .authorization_hash()
        .expect("retirement authorization hash");

    let replacement_key = KeyPair::from_secret_bytes([0x18; 32]).expect("replacement key");
    let replacement_key_id = format!("{}#anchor-2", harness.authority_did);
    let replacement = provisioning(
        &harness.intermediate_key,
        &replacement_key,
        &harness.authority_did,
        &replacement_key_id,
        [0x32; 32],
        harness.scope_alias,
        Permission::AnchorReceiptCommitment,
        2,
    );
    let mut replacement_authorization = provisioning_authorization(
        &harness.config,
        &replacement,
        3,
        retirement_authorization_hash,
        0x7b,
        0x7014,
    );
    replacement_authorization.valid_from_ms = ISSUED_AT + 200;
    replacement_authorization.valid_until_ms = ISSUED_AT + 300_000;
    resign_authorization(&mut replacement_authorization, 0x7014);
    harness
        .store
        .provision_authority(&replacement, &replacement_authorization, ISSUED_AT + 201)
        .expect("governance-authorized increasing key epoch");

    let stale_key_id = format!("{}#anchor-stale", harness.authority_did);
    let stale = provisioning(
        &harness.intermediate_key,
        &replacement_key,
        &harness.authority_did,
        &stale_key_id,
        [0x33; 32],
        harness.scope_alias,
        Permission::AnchorReceiptCommitment,
        2,
    );
    let stale_authorization = provisioning_authorization(
        &harness.config,
        &stale,
        4,
        replacement_authorization
            .authorization_hash()
            .expect("replacement authorization hash"),
        0x7c,
        0x7015,
    );
    assert!(matches!(
        harness
            .store
            .provision_authority(&stale, &stale_authorization, ISSUED_AT + 202,),
        Err(AnchorStoreError::GovernanceAuthorization(_))
            | Err(AnchorStoreError::AuthorityValidation(_))
    ));
    assert_eq!(
        count_rows(&harness.path, "crosschecked_anchor_authorities"),
        2
    );
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        3
    );
}

#[test]
fn tampered_governance_predecessor_fails_route_before_signing_or_persistence() {
    let harness = Harness::new();
    let retirement = harness.retirement(ISSUED_AT + 200);
    let mut retirement_authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Revoke,
        2,
        harness.provisioning_authorization_hash,
        0x81,
        0x7021,
    );
    harness
        .store
        .revoke_authority(
            &retirement,
            &retirement_authorization,
            retirement.retired_at_ms,
        )
        .expect("governance-authorized revocation");
    let retirement_authorization_hash = retirement_authorization
        .authorization_hash()
        .expect("retirement authorization hash");

    let replacement_key = KeyPair::from_secret_bytes([0x18; 32]).expect("replacement key");
    let replacement_key_id = format!("{}#anchor-2", harness.authority_did);
    let replacement = provisioning(
        &harness.intermediate_key,
        &replacement_key,
        &harness.authority_did,
        &replacement_key_id,
        [0x35; 32],
        harness.scope_alias,
        Permission::AnchorReceiptCommitment,
        2,
    );
    let mut replacement_authorization = provisioning_authorization(
        &harness.config,
        &replacement,
        3,
        retirement_authorization_hash,
        0x82,
        0x7022,
    );
    replacement_authorization.valid_from_ms = ISSUED_AT + 200;
    replacement_authorization.valid_until_ms = ISSUED_AT + 300_000;
    resign_authorization(&mut replacement_authorization, 0x7022);
    harness
        .store
        .provision_authority(&replacement, &replacement_authorization, ISSUED_AT + 201)
        .expect("governance-authorized replacement");

    retirement_authorization.signature.fill(0);
    let mut tampered_record = Vec::new();
    ciborium::ser::into_writer(&retirement_authorization, &mut tampered_record)
        .expect("tampered authorization record");
    let tampered_cbor = retirement_authorization
        .to_cbor_bytes()
        .expect("tampered authorization CBOR");
    rusqlite::Connection::open(&harness.path)
        .expect("sqlite")
        .execute(
            "UPDATE crosschecked_anchor_governance_authorizations
             SET authorization_cbor = ?1, authorization_record_cbor = ?2
             WHERE authorization_sequence = 2",
            rusqlite::params![tampered_cbor, tampered_record],
        )
        .expect("simulate predecessor artifact tampering");

    let body = signed_request(
        &replacement_key,
        &harness.authority_did,
        &replacement_key_id,
        [0x35; 32],
        harness.scope_alias,
        [0x54; 32],
        [0x65; 32],
        ISSUED_AT + 202,
        ISSUED_AT + 300_000,
    );
    assert!(matches!(
        harness.store.record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 203, 0)),
            harness.signer.as_ref(),
        ),
        Err(AnchorStoreError::ReadbackValidation(_))
            | Err(AnchorStoreError::GovernanceAuthorization(_))
    ));
    assert_eq!(harness.signer.unique_calls(), 0);
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 0);
}

#[test]
fn persisted_frost_group_key_and_epoch_cannot_be_substituted_on_restart() {
    let harness = Harness::new();
    let mut wrong_epoch = harness.config.clone();
    wrong_epoch.governance_frost_key_epoch += 1;
    assert!(matches!(
        AnchorStore::open(&harness.path, wrong_epoch),
        Err(AnchorStoreError::Storage(_))
    ));

    let mut wrong_group = harness.config.clone();
    wrong_group.governance_frost_group_public_key =
        governance_group_public_key_for_seed(0x0BAD_5EED);
    assert!(matches!(
        AnchorStore::open(&harness.path, wrong_group),
        Err(AnchorStoreError::Storage(_))
    ));
    assert_eq!(
        count_rows(
            &harness.path,
            "crosschecked_anchor_governance_authorizations"
        ),
        1
    );
}

#[test]
fn lost_response_restart_expiry_and_key_retirement_replay_exact_committed_bytes() {
    let harness = Harness::new();
    let body = harness.request(0x53, 0x64);
    let committed_but_not_delivered = harness
        .store
        .record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref(),
        )
        .expect("commit before simulated delivery crash");
    let calls_after_commit = harness.signer.unique_calls();

    let restarted = AnchorStore::open(&harness.path, harness.config.clone()).expect("restart");
    let mut retirement = AuthorityRetirementV1 {
        protocol_version: 1,
        authority_did: did(&harness.authority_did),
        authority_key_id: harness.authority_key_id.clone(),
        key_epoch: 1,
        retired_at_ms: ISSUED_AT + 200,
        signer_did: did(INTERMEDIATE_DID),
        signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        signature: Signature::empty(),
    };
    retirement.signature = harness
        .intermediate_key
        .sign(&retirement.signing_preimage().expect("retirement payload"));
    let retirement_authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x76,
        0x7006,
    );
    restarted
        .retire_authority(
            &retirement,
            &retirement_authorization,
            retirement.retired_at_ms,
        )
        .expect("retire key");
    let replay = restarted
        .record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &body,
                now: Timestamp::new(ISSUED_AT + 600_000, 0),
            },
            harness.signer.as_ref(),
        )
        .expect("historical exact replay");

    assert_eq!(replay.disposition, AnchorRecordDisposition::Replayed);
    assert_eq!(
        replay.response_body,
        committed_but_not_delivered.response_body
    );
    assert_eq!(harness.signer.unique_calls(), calls_after_commit);

    let new_body = harness.request(0x54, 0x67);
    assert_eq!(
        restarted.record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &new_body,
                now: Timestamp::new(ISSUED_AT + 250, 0),
            },
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::AuthorityRetired)
    );
}

#[test]
fn scope_binding_audience_and_grant_substitution_fail_before_signing() {
    let harness = Harness::new();
    let substituted = signed_request(
        &harness.authority_key,
        &harness.authority_did,
        &harness.authority_key_id,
        [0x99; 32],
        harness.scope_alias,
        [0x53; 32],
        [0x64; 32],
        ISSUED_AT,
        ISSUED_AT + 300_000,
    );
    assert!(matches!(
        harness.store.record(
            harness.submission(&substituted, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::AuthorityValidation(_))
    ));
    assert_eq!(harness.signer.unique_calls(), 0);
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 0);

    let substituted_scope = signed_request(
        &harness.authority_key,
        &harness.authority_did,
        &harness.authority_key_id,
        harness.grant_id,
        [0x98; 32],
        [0x54; 32],
        [0x65; 32],
        ISSUED_AT,
        ISSUED_AT + 300_000,
    );
    assert!(matches!(
        harness.store.record(
            harness.submission(&substituted_scope, Timestamp::new(ISSUED_AT + 124, 0)),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::AuthorityValidation(_))
    ));
    assert_eq!(harness.signer.unique_calls(), 0);
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 0);
}

#[test]
fn incomplete_persisted_retirement_state_fails_closed() {
    let harness = Harness::new();
    let mut retirement = AuthorityRetirementV1 {
        protocol_version: 1,
        authority_did: did(&harness.authority_did),
        authority_key_id: harness.authority_key_id.clone(),
        key_epoch: 1,
        retired_at_ms: ISSUED_AT + 200,
        signer_did: did(INTERMEDIATE_DID),
        signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        signature: Signature::empty(),
    };
    retirement.signature = harness
        .intermediate_key
        .sign(&retirement.signing_preimage().expect("retirement payload"));
    let retirement_authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x77,
        0x7007,
    );
    harness
        .store
        .retire_authority(
            &retirement,
            &retirement_authorization,
            retirement.retired_at_ms,
        )
        .expect("retire");

    let connection = rusqlite::Connection::open(&harness.path).expect("sqlite");
    connection
        .execute(
            "UPDATE crosschecked_anchor_authorities SET retired_at_ms = NULL",
            [],
        )
        .expect("tamper retirement state");
    let body = harness.request(0x53, 0x64);
    assert!(matches!(
        harness.store.record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 250, 0)),
            harness.signer.as_ref()
        ),
        Err(AnchorStoreError::ReadbackValidation(_))
    ));
    assert_eq!(harness.signer.unique_calls(), 0);
    assert_eq!(count_rows(&harness.path, "crosschecked_anchor_requests"), 0);
}

#[test]
fn authenticated_readback_rejects_persisted_response_tampering() {
    let harness = Harness::new();
    let body = harness.request(0x53, 0x64);
    harness
        .store
        .record(
            harness.submission(&body, Timestamp::new(ISSUED_AT + 123, 0)),
            harness.signer.as_ref(),
        )
        .expect("record");

    let connection = rusqlite::Connection::open(&harness.path).expect("sqlite");
    let mut response: Vec<u8> = connection
        .query_row(
            "SELECT canonical_response_body FROM crosschecked_anchor_responses",
            [],
            |row| row.get(0),
        )
        .expect("response bytes");
    let last = response.last_mut().expect("non-empty response");
    *last ^= 1;
    connection
        .execute(
            "UPDATE crosschecked_anchor_responses SET canonical_response_body = ?1",
            [&response],
        )
        .expect("tamper row");

    assert!(matches!(
        harness.store.readback_action("crosschecked", &[0x53; 32]),
        Err(AnchorStoreError::ReadbackValidation(_))
    ));
}
