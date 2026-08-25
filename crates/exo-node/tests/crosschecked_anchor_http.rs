// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/crosschecked_anchor_governance.rs"]
mod governance_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use exo_api::crosschecked_anchor::{ANCHOR_PATH, CrossCheckedAnchorRequestV1};
use exo_authority::{AuthorityChain, AuthorityLink, DelegateeKind, Permission};
use exo_core::{
    crypto::KeyPair,
    types::{Did, Hash256, Signature, Timestamp},
};
use exo_identity::did::{DidDocument, VerificationMethod};
use exo_node::{
    crosschecked_anchor_http::{
        CROSSCHECKED_ANCHOR_BEARER_ENV, CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV,
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV,
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV, CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV, CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV,
        CrossCheckedAnchorHttpState, CrossCheckedAnchorStartupConfig, CrossCheckedBearerVerifier,
        SqliteDurableAnchorSigner, crosschecked_anchor_router,
    },
    crosschecked_anchor_store::{
        AnchorNodeIdentity, AnchorStore, AnchorStoreConfig, AnchorStoreError,
        AuthorityLifecycleEventV1, AuthorityProvisioningV1, AuthorityRetirementV1,
        CrossCheckedScopeBindingV1, DurableAnchorSigner, SignOnceError, SubmissionContext,
        authority_chain_fingerprint,
    },
};
use tempfile::TempDir;
use tower::ServiceExt;

use governance_support::{
    GOVERNANCE_KEY_EPOCH, governance_group_public_key, provisioning_authorization,
    retirement_authorization,
};

const AUDIENCE: &str = "crosschecked.production";
const INTERMEDIATE_DID: &str = "did:exo:crosschecked-intermediate";
const INTERMEDIATE_KEY_ID: &str = "did:exo:crosschecked-intermediate#key-1";
const NODE_DID: &str = "did:exo:anchor-node";
const NODE_KEY_ID: &str = "did:exo:anchor-node#response-2026";
const ISSUED_AT: u64 = 1_800_000_000_000;
const DEDICATED_BEARER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ADMIN_BEARER: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

static_assertions::assert_not_impl_any!(CrossCheckedAnchorHttpState: serde::Serialize);
static_assertions::assert_not_impl_any!(CrossCheckedAnchorStartupConfig: serde::Serialize);

fn anchor_store_config() -> AnchorStoreConfig {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    AnchorStoreConfig {
        expected_audience: AUDIENCE.to_owned(),
        crosschecked_intermediate_did: INTERMEDIATE_DID.to_owned(),
        crosschecked_intermediate_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        crosschecked_intermediate_public_key: *intermediate_key.public_key(),
        governance_frost_group_public_key: governance_group_public_key(),
        governance_frost_key_epoch: GOVERNANCE_KEY_EPOCH,
        node_identity: AnchorNodeIdentity {
            did: NODE_DID.to_owned(),
            key_id: NODE_KEY_ID.to_owned(),
            public_key: *node_key.public_key(),
        },
    }
}

#[derive(Debug)]
struct CountingSigner {
    identity: AnchorNodeIdentity,
    key: KeyPair,
    reservations: Mutex<BTreeMap<Hash256, Timestamp>>,
    operations: Mutex<BTreeMap<Hash256, (Hash256, Signature)>>,
}

impl CountingSigner {
    fn new(identity: AnchorNodeIdentity, secret: [u8; 32]) -> Self {
        Self {
            identity,
            key: KeyPair::from_secret_bytes(secret).expect("signer key"),
            reservations: Mutex::new(BTreeMap::new()),
            operations: Mutex::new(BTreeMap::new()),
        }
    }
}

impl DurableAnchorSigner for CountingSigner {
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
        Ok(signature)
    }
}

struct Harness {
    _temp: TempDir,
    store_path: std::path::PathBuf,
    store: AnchorStore,
    intermediate_key: KeyPair,
    authority_key: KeyPair,
    authority_did: String,
    authority_key_id: String,
    grant_id: [u8; 32],
    scope_alias: [u8; 32],
    signer: Arc<CountingSigner>,
    config: AnchorStoreConfig,
    provisioning_authorization_hash: Hash256,
}

impl Harness {
    fn new() -> Self {
        let temp = TempDir::new().expect("temp directory");
        let store_path = temp.path().join("crosschecked-anchor.sqlite3");
        let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
        let store_config = anchor_store_config();
        let node_identity = store_config.node_identity.clone();
        let store = AnchorStore::open(&store_path, store_config.clone()).expect("anchor store");
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
        );
        let authorization = provisioning_authorization(
            &store_config,
            &provisioning,
            1,
            Hash256::from_bytes([0; 32]),
            0x51,
            0x5101,
        );
        let provisioning_authorization_hash = authorization
            .authorization_hash()
            .expect("provisioning authorization hash");
        store
            .provision_authority(
                &provisioning,
                &authorization,
                provisioning.scope_binding.valid_from_ms,
            )
            .expect("provision authority");
        let signer = Arc::new(CountingSigner::new(node_identity, [0x29; 32]));
        Self {
            _temp: temp,
            store_path,
            store,
            intermediate_key,
            authority_key,
            authority_did,
            authority_key_id,
            grant_id,
            scope_alias,
            signer,
            config: store_config,
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
        )
    }

    fn app(&self) -> axum::Router {
        let signer: Arc<dyn DurableAnchorSigner> = self.signer.clone();
        let clock = Arc::new(|| Ok(Timestamp::new(ISSUED_AT + 1_000, 0)));
        let state = CrossCheckedAnchorHttpState::new(
            self.store.clone(),
            signer,
            CrossCheckedBearerVerifier::from_bearer(DEDICATED_BEARER)
                .expect("valid dedicated bearer"),
            clock,
        );
        crosschecked_anchor_router(state)
    }
}

fn signer_reservation_count(path: &std::path::Path) -> u64 {
    let connection = rusqlite::Connection::open(path).expect("signer journal");
    connection
        .query_row(
            "SELECT COUNT(*) FROM crosschecked_anchor_recorded_at_reservations",
            [],
            |row| row.get(0),
        )
        .expect("reservation count")
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
) -> AuthorityProvisioningV1 {
    let mut link = AuthorityLink {
        delegator_did: did(INTERMEDIATE_DID),
        delegate_did: did(authority_did),
        scope: vec![Permission::AnchorReceiptCommitment],
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
        key_epoch: 1,
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
            did_document(authority_did, authority_key_id, authority_key, 1),
        ],
        authority_chain: chain,
        scope_binding: binding,
    }
}

fn signed_request(
    key: &KeyPair,
    authority_did: &str,
    authority_key_id: &str,
    grant_id: [u8; 32],
    scope_alias: [u8; 32],
    action_hash: [u8; 32],
    nonce: [u8; 32],
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
        issued_at_ms: ISSUED_AT,
        expires_at_ms: ISSUED_AT + 300_000,
        signature_algorithm: "ed25519".to_owned(),
        signature: [0; 64],
    };
    request.idempotency_key = request.derive_idempotency_key().expect("idempotency");
    request.signature = *key
        .sign(&request.signing_preimage().expect("request payload"))
        .ed25519_bytes()
        .expect("Ed25519 signature");
    request.to_canonical_cbor().expect("canonical request")
}

async fn request(
    app: axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(bearer) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    app.oneshot(builder.body(Body::from(body)).expect("request"))
        .await
        .expect("response")
}

async fn body(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body")
        .to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_hundred_concurrent_identical_posts_create_once_and_replay_exactly() {
    let harness = Harness::new();
    let app = harness.app();
    let request_body = harness.request(0x53, 0x61);
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let app = app.clone();
        let request_body = request_body.clone();
        tasks.push(tokio::spawn(async move {
            let response = request(
                app,
                "POST",
                ANCHOR_PATH,
                Some(DEDICATED_BEARER),
                Some("application/cbor"),
                request_body,
            )
            .await;
            let status = response.status();
            let body = body(response).await;
            (status, body)
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("concurrent request task"));
    }
    assert_eq!(
        results
            .iter()
            .filter(|(status, _)| *status == StatusCode::CREATED)
            .count(),
        1
    );
    assert!(
        results
            .iter()
            .all(|(status, _)| matches!(*status, StatusCode::CREATED | StatusCode::OK))
    );
    let expected = &results[0].1;
    assert!(results.iter().all(|(_, body)| body == expected));
}

#[tokio::test]
async fn post_returns_201_then_200_with_byte_identical_canonical_body() {
    let harness = Harness::new();
    let request_body = harness.request(0x53, 0x61);

    let created = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        request_body.clone(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        created.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/cbor"
    );
    let created_body = body(created).await;

    let replayed = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        request_body,
    )
    .await;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(body(replayed).await, created_body);
}

#[tokio::test]
async fn dedicated_bearer_is_required_and_admin_bearer_is_rejected() {
    let harness = Harness::new();
    for (bearer, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("wrong"), StatusCode::FORBIDDEN),
        (Some(ADMIN_BEARER), StatusCode::FORBIDDEN),
    ] {
        let response = request(
            harness.app(),
            "POST",
            ANCHOR_PATH,
            bearer,
            Some("application/cbor"),
            harness.request(0x53, 0x61),
        )
        .await;
        assert_eq!(response.status(), expected);
    }
    let connection = rusqlite::Connection::open(&harness.store_path).expect("store");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM crosschecked_anchor_requests",
            [],
            |row| row.get(0),
        )
        .expect("row count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn duplicate_authorization_or_content_type_headers_are_rejected() {
    let harness = Harness::new();
    let mut duplicate_authorization = Request::builder()
        .method("POST")
        .uri(ANCHOR_PATH)
        .header(header::AUTHORIZATION, format!("Bearer {DEDICATED_BEARER}"))
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(harness.request(0x53, 0x61)))
        .expect("request");
    duplicate_authorization.headers_mut().append(
        header::AUTHORIZATION,
        "Bearer another-token".parse().expect("header value"),
    );
    let response = harness
        .app()
        .oneshot(duplicate_authorization)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let harness = Harness::new();
    let mut duplicate_content_type = Request::builder()
        .method("POST")
        .uri(ANCHOR_PATH)
        .header(header::AUTHORIZATION, format!("Bearer {DEDICATED_BEARER}"))
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(harness.request(0x53, 0x61)))
        .expect("request");
    duplicate_content_type.headers_mut().append(
        header::CONTENT_TYPE,
        "application/json".parse().expect("header value"),
    );
    let response = harness
        .app()
        .oneshot(duplicate_content_type)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn exact_content_type_body_limit_and_canonical_cbor_are_enforced_before_persistence() {
    let harness = Harness::new();
    let valid = harness.request(0x53, 0x61);
    let wrong_type = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor; charset=utf-8"),
        valid.clone(),
    )
    .await;
    assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let oversized = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        vec![0; 8 * 1024 + 1],
    )
    .await;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let at_transport_limit = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        vec![0; 8 * 1024],
    )
    .await;
    assert_eq!(at_transport_limit.status(), StatusCode::BAD_REQUEST);

    let mut trailing = valid;
    trailing.push(0);
    let noncanonical = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        trailing,
    )
    .await;
    assert_eq!(noncanonical.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn conflicts_are_typed_409_responses() {
    let harness = Harness::new();
    let original = harness.request(0x53, 0x61);
    assert_eq!(
        request(
            harness.app(),
            "POST",
            ANCHOR_PATH,
            Some(DEDICATED_BEARER),
            Some("application/cbor"),
            original.clone(),
        )
        .await
        .status(),
        StatusCode::CREATED
    );

    // Nonce is signed but deliberately not part of the derived idempotency
    // key, so this is a valid request that attempts to reuse the same key for
    // different exact bytes.
    let same_idempotency = harness.request(0x53, 0x62);
    let response = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        same_idempotency,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let conflict: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    assert_eq!(conflict["error_code"], "idempotency_key_conflict");

    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let other_key = KeyPair::from_secret_bytes([0x18; 32]).expect("other authority");
    let other_did = "did:exo:crosschecked-workspace-b";
    let other_key_id = format!("{other_did}#anchor-1");
    let other_provisioning = provisioning(
        &intermediate_key,
        &other_key,
        other_did,
        &other_key_id,
        [0x32; 32],
        [0x43; 32],
    );
    let other_authorization = provisioning_authorization(
        &harness.config,
        &other_provisioning,
        1,
        Hash256::from_bytes([0; 32]),
        0x52,
        0x5201,
    );
    harness
        .store
        .provision_authority(
            &other_provisioning,
            &other_authorization,
            other_provisioning.scope_binding.valid_from_ms,
        )
        .expect("second scope");
    let same_action = signed_request(
        &other_key,
        other_did,
        &other_key_id,
        [0x32; 32],
        [0x43; 32],
        [0x53; 32],
        [0x63; 32],
    );
    let response = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        same_action,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let conflict: serde_json::Value = serde_json::from_slice(&body(response).await).unwrap();
    assert_eq!(conflict["error_code"], "action_hash_conflict");
}

#[tokio::test]
async fn readback_requires_the_dedicated_bearer_and_returns_exact_stored_response() {
    let harness = Harness::new();
    let created = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        harness.request(0x53, 0x61),
    )
    .await;
    let created_body = body(created).await;
    let uri = format!("{ANCHOR_PATH}/{}", "53".repeat(32));

    let unauthorized = request(harness.app(), "GET", &uri, None, None, Vec::new()).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let admin = request(
        harness.app(),
        "GET",
        &uri,
        Some(ADMIN_BEARER),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(admin.status(), StatusCode::FORBIDDEN);
    let readback = request(
        harness.app(),
        "GET",
        &uri,
        Some(DEDICATED_BEARER),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(readback.status(), StatusCode::OK);
    assert_eq!(body(readback).await, created_body);
}

#[test]
fn startup_config_is_disabled_only_when_all_values_are_absent_and_rejects_partial_or_unsafe_values()
{
    let empty = BTreeMap::new();
    assert_eq!(
        CrossCheckedAnchorStartupConfig::from_values(ADMIN_BEARER, &empty).unwrap(),
        None
    );

    let mut values = BTreeMap::new();
    values.insert(
        CROSSCHECKED_ANCHOR_BEARER_ENV.to_owned(),
        DEDICATED_BEARER.to_owned(),
    );
    assert!(CrossCheckedAnchorStartupConfig::from_values(ADMIN_BEARER, &values).is_err());

    values.insert(
        CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV.to_owned(),
        AUDIENCE.to_owned(),
    );
    values.insert(
        CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV.to_owned(),
        INTERMEDIATE_DID.to_owned(),
    );
    values.insert(
        CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV.to_owned(),
        INTERMEDIATE_KEY_ID.to_owned(),
    );
    values.insert(
        CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV.to_owned(),
        "41".repeat(32),
    );
    values.insert(
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV.to_owned(),
        hex::encode(governance_group_public_key()),
    );
    values.insert(
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV.to_owned(),
        GOVERNANCE_KEY_EPOCH.to_string(),
    );
    values.insert(
        CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV.to_owned(),
        NODE_KEY_ID.to_owned(),
    );
    assert!(CrossCheckedAnchorStartupConfig::from_values(ADMIN_BEARER, &values).is_ok());

    values.insert(
        CROSSCHECKED_ANCHOR_BEARER_ENV.to_owned(),
        ADMIN_BEARER.to_owned(),
    );
    assert!(CrossCheckedAnchorStartupConfig::from_values(ADMIN_BEARER, &values).is_err());
    values.insert(
        CROSSCHECKED_ANCHOR_BEARER_ENV.to_owned(),
        "not-256-bit-hex".to_owned(),
    );
    assert!(CrossCheckedAnchorStartupConfig::from_values(ADMIN_BEARER, &values).is_err());
}

#[test]
fn sqlite_signer_replays_one_persisted_signature_after_restart_without_resigning() {
    let temp = TempDir::new().expect("temp");
    let path = temp.path().join("signer.sqlite3");
    let key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    let calls = Arc::new(AtomicUsize::new(0));
    let identity = AnchorNodeIdentity {
        did: NODE_DID.to_owned(),
        key_id: NODE_KEY_ID.to_owned(),
        public_key: *key.public_key(),
    };
    let signer_fn = {
        let key = Arc::clone(&key);
        let calls = Arc::clone(&calls);
        Arc::new(move |payload: &[u8]| {
            calls.fetch_add(1, Ordering::SeqCst);
            key.sign(payload)
        })
    };
    let signer = SqliteDurableAnchorSigner::open(&path, identity.clone(), signer_fn.clone())
        .expect("open signer");
    let first = signer
        .sign_once(Hash256::digest(b"operation"), b"payload")
        .expect("first signature");
    drop(signer);

    let reopened =
        SqliteDurableAnchorSigner::open(&path, identity, signer_fn).expect("reopen signer");
    let replay = reopened
        .sign_once(Hash256::digest(b"operation"), b"payload")
        .expect("replayed signature");
    assert_eq!(replay, first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        reopened.sign_once(Hash256::digest(b"operation"), b"changed"),
        Err(SignOnceError::OperationPayloadConflict)
    );
}

#[test]
fn signer_journal_commit_before_record_abort_restarts_into_one_exact_record() {
    let harness = Harness::new();
    let signer_path = harness._temp.path().join("signatures.sqlite3");
    let key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    let calls = Arc::new(AtomicUsize::new(0));
    let sign_fn = {
        let key = Arc::clone(&key);
        let calls = Arc::clone(&calls);
        Arc::new(move |payload: &[u8]| {
            calls.fetch_add(1, Ordering::SeqCst);
            key.sign(payload)
        })
    };
    let signer = SqliteDurableAnchorSigner::open(
        &signer_path,
        anchor_store_config().node_identity,
        sign_fn.clone(),
    )
    .expect("signer journal");
    let records_connection = rusqlite::Connection::open(&harness.store_path).expect("records DB");
    records_connection
        .execute_batch(
            "CREATE TRIGGER inject_record_abort
             BEFORE INSERT ON crosschecked_anchor_requests
             BEGIN
               SELECT RAISE(ABORT, 'injected after signer journal commit');
             END;",
        )
        .expect("install record abort");
    let request_body = harness.request(0x5a, 0x6b);
    let submission = |now| SubmissionContext {
        method: "POST",
        path: ANCHOR_PATH,
        content_type: "application/cbor",
        body: &request_body,
        now,
    };

    assert!(matches!(
        harness
            .store
            .record(submission(Timestamp::new(ISSUED_AT + 1_000, 0)), &signer),
        Err(AnchorStoreError::Storage(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    records_connection
        .execute_batch("DROP TRIGGER inject_record_abort;")
        .expect("remove record abort");
    drop(records_connection);
    drop(signer);

    let restarted_store =
        AnchorStore::open(&harness.store_path, anchor_store_config()).expect("restart records DB");
    let restarted_signer =
        SqliteDurableAnchorSigner::open(&signer_path, anchor_store_config().node_identity, sign_fn)
            .expect("restart signer journal");
    let created = restarted_store
        .record(
            submission(Timestamp::new(ISSUED_AT + 2_000, 7)),
            &restarted_signer,
        )
        .expect("changed-clock convergent retry");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let replay = restarted_store
        .record(
            submission(Timestamp::new(ISSUED_AT + 3_000, 9)),
            &restarted_signer,
        )
        .expect("exact replay");
    assert_eq!(replay.response_body, created.response_body);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let records = rusqlite::Connection::open(&harness.store_path).expect("records DB");
    for table in [
        "crosschecked_anchor_requests",
        "crosschecked_anchor_receipts",
        "crosschecked_anchor_responses",
    ] {
        let count: u64 = records
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("record count");
        assert_eq!(count, 1, "table {table}");
    }
    let journal = rusqlite::Connection::open(&signer_path).expect("signer journal");
    let signature_count: u64 = journal
        .query_row(
            "SELECT COUNT(*) FROM crosschecked_anchor_signatures",
            [],
            |row| row.get(0),
        )
        .expect("signature count");
    assert_eq!(signature_count, 2);
    assert_eq!(signer_reservation_count(&signer_path), 1);
}

#[test]
fn orphaned_signatures_retry_after_request_expiry_and_authority_retirement() {
    let harness = Harness::new();
    let signer_path = harness._temp.path().join("signatures-expiry.sqlite3");
    let key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    let calls = Arc::new(AtomicUsize::new(0));
    let sign_fn = {
        let key = Arc::clone(&key);
        let calls = Arc::clone(&calls);
        Arc::new(move |payload: &[u8]| {
            calls.fetch_add(1, Ordering::SeqCst);
            key.sign(payload)
        })
    };
    let signer = SqliteDurableAnchorSigner::open(
        &signer_path,
        anchor_store_config().node_identity,
        sign_fn.clone(),
    )
    .expect("signer journal");
    let records_connection = rusqlite::Connection::open(&harness.store_path).expect("records DB");
    records_connection
        .execute_batch(
            "CREATE TRIGGER inject_expiry_record_abort
             BEFORE INSERT ON crosschecked_anchor_requests
             BEGIN
               SELECT RAISE(ABORT, 'injected after signer journal commit');
             END;",
        )
        .expect("install record abort");
    let request_body = harness.request(0x5b, 0x6c);

    assert!(matches!(
        harness.store.record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &request_body,
                now: Timestamp::new(ISSUED_AT + 1_000, 0),
            },
            &signer
        ),
        Err(AnchorStoreError::Storage(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    records_connection
        .execute_batch("DROP TRIGGER inject_expiry_record_abort;")
        .expect("remove record abort");
    drop(records_connection);
    drop(signer);

    let mut retirement = AuthorityRetirementV1 {
        protocol_version: 1,
        authority_did: did(&harness.authority_did),
        authority_key_id: harness.authority_key_id.clone(),
        key_epoch: 1,
        retired_at_ms: ISSUED_AT + 2_000,
        signer_did: did(INTERMEDIATE_DID),
        signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        signature: Signature::empty(),
    };
    retirement.signature = harness
        .intermediate_key
        .sign(&retirement.signing_preimage().expect("retirement payload"));
    let authorization = retirement_authorization(
        &harness.config,
        &retirement,
        harness.scope_alias,
        AuthorityLifecycleEventV1::Retire,
        2,
        harness.provisioning_authorization_hash,
        0x53,
        0x5301,
    );
    harness
        .store
        .retire_authority(&retirement, &authorization, retirement.retired_at_ms)
        .expect("retire authority after reservation");

    let restarted_signer =
        SqliteDurableAnchorSigner::open(&signer_path, anchor_store_config().node_identity, sign_fn)
            .expect("restart signer journal");
    let created = harness
        .store
        .record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &request_body,
                now: Timestamp::new(ISSUED_AT + 600_000, 0),
            },
            &restarted_signer,
        )
        .expect("reserved-time retry after expiry and retirement");
    assert_eq!(
        created.response.node_recorded_at,
        Timestamp::new(ISSUED_AT + 1_000, 0)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(signer_reservation_count(&signer_path), 1);
}

#[test]
fn invalid_or_untrusted_requests_create_no_recorded_at_reservation() {
    let harness = Harness::new();
    let signer_path = harness._temp.path().join("signatures-invalid.sqlite3");
    let key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    let signer = SqliteDurableAnchorSigner::open(
        &signer_path,
        anchor_store_config().node_identity,
        Arc::new(move |payload: &[u8]| key.sign(payload)),
    )
    .expect("signer journal");

    let mut invalid_signature = harness.request(0x5c, 0x6d);
    let last = invalid_signature.last_mut().expect("signature byte");
    *last ^= 1;
    assert!(matches!(
        harness.store.record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &invalid_signature,
                now: Timestamp::new(ISSUED_AT + 1_000, 0),
            },
            &signer,
        ),
        Err(AnchorStoreError::Codec(_))
    ));

    let unknown_key = KeyPair::from_secret_bytes([0x55; 32]).expect("unknown authority key");
    let unknown_did = "did:exo:crosschecked-unknown-workspace";
    let unknown_key_id = format!("{unknown_did}#anchor-1");
    let untrusted = signed_request(
        &unknown_key,
        unknown_did,
        &unknown_key_id,
        [0x71; 32],
        [0x72; 32],
        [0x73; 32],
        [0x74; 32],
    );
    assert_eq!(
        harness.store.record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &untrusted,
                now: Timestamp::new(ISSUED_AT + 1_000, 0),
            },
            &signer,
        ),
        Err(AnchorStoreError::AuthorityNotFound)
    );
    assert_eq!(signer_reservation_count(&signer_path), 0);
}

#[test]
fn recorded_at_reservation_is_concurrent_restart_safe_and_identity_bound() {
    let temp = TempDir::new().expect("temp");
    let signer_path = temp.path().join("signatures-reservation.sqlite3");
    let identity = anchor_store_config().node_identity;
    let key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    let signer = Arc::new(
        SqliteDurableAnchorSigner::open(
            &signer_path,
            identity.clone(),
            Arc::new(move |payload: &[u8]| key.sign(payload)),
        )
        .expect("signer journal"),
    );
    let request_hash = Hash256::digest(b"concurrent-recorded-at-reservation");
    let mut threads = Vec::new();
    for index in 0_u32..100 {
        let signer = Arc::clone(&signer);
        threads.push(std::thread::spawn(move || {
            signer
                .reserve_recorded_at(
                    request_hash,
                    Timestamp::new(ISSUED_AT + u64::from(index), index),
                )
                .expect("reserve or read timestamp")
        }));
    }
    let reservations: Vec<Timestamp> = threads
        .into_iter()
        .map(|thread| thread.join().expect("reservation thread"))
        .collect();
    assert!(reservations.iter().all(|value| *value == reservations[0]));
    assert_eq!(signer_reservation_count(&signer_path), 1);
    drop(signer);

    let key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    let restarted = SqliteDurableAnchorSigner::open(
        &signer_path,
        identity.clone(),
        Arc::new(move |payload: &[u8]| key.sign(payload)),
    )
    .expect("restart signer");
    assert_eq!(
        restarted
            .reserved_recorded_at(request_hash)
            .expect("read reservation"),
        Some(reservations[0])
    );

    let mut other_identity = identity;
    other_identity.key_id = "did:exo:anchor-node#substituted".to_owned();
    let other_key = Arc::new(KeyPair::from_secret_bytes([0x29; 32]).expect("node key"));
    assert!(
        SqliteDurableAnchorSigner::open(
            &signer_path,
            other_identity,
            Arc::new(move |payload: &[u8]| other_key.sign(payload)),
        )
        .is_err()
    );
}

#[test]
fn route_state_debug_does_not_expose_transport_bearer() {
    let harness = Harness::new();
    let signer: Arc<dyn DurableAnchorSigner> = harness.signer.clone();
    let state = CrossCheckedAnchorHttpState::new(
        harness.store,
        signer,
        CrossCheckedBearerVerifier::from_bearer(DEDICATED_BEARER).expect("valid dedicated bearer"),
        Arc::new(|| Ok(Timestamp::new(ISSUED_AT + 1_000, 0))),
    );
    let debug = format!("{state:?}");
    assert!(!debug.contains(DEDICATED_BEARER));
}

#[test]
fn runtime_auth_retains_only_a_fixed_size_domain_separated_verifier() {
    let verifier =
        CrossCheckedBearerVerifier::from_bearer(DEDICATED_BEARER).expect("valid dedicated bearer");
    assert_eq!(std::mem::size_of_val(&verifier), 32);
    assert!(verifier.verifies(DEDICATED_BEARER));
    assert!(!verifier.verifies(ADMIN_BEARER));
    let debug = format!("{verifier:?}");
    assert!(!debug.contains(DEDICATED_BEARER));
    assert!(!debug.contains(&hex::encode(
        blake3::hash(DEDICATED_BEARER.as_bytes()).as_bytes()
    )));
}

#[tokio::test]
async fn raw_transport_bearer_never_enters_anchor_persistence() {
    let harness = Harness::new();
    let response = request(
        harness.app(),
        "POST",
        ANCHOR_PATH,
        Some(DEDICATED_BEARER),
        Some("application/cbor"),
        harness.request(0x7a, 0x7b),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let needle = DEDICATED_BEARER.as_bytes();
    for entry in std::fs::read_dir(harness._temp.path()).expect("persistence directory") {
        let path = entry.expect("directory entry").path();
        if path.is_file() {
            let bytes = std::fs::read(&path).expect("persistence file");
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "raw dedicated bearer leaked into {}",
                path.display()
            );
        }
    }
}

#[test]
fn startup_config_debug_does_not_expose_transport_bearer() {
    let values = BTreeMap::from([
        (
            CROSSCHECKED_ANCHOR_BEARER_ENV.to_owned(),
            DEDICATED_BEARER.to_owned(),
        ),
        (
            CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV.to_owned(),
            AUDIENCE.to_owned(),
        ),
        (
            CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV.to_owned(),
            INTERMEDIATE_DID.to_owned(),
        ),
        (
            CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV.to_owned(),
            INTERMEDIATE_KEY_ID.to_owned(),
        ),
        (
            CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV.to_owned(),
            "41".repeat(32),
        ),
        (
            CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV.to_owned(),
            hex::encode(governance_group_public_key()),
        ),
        (
            CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV.to_owned(),
            GOVERNANCE_KEY_EPOCH.to_string(),
        ),
        (
            CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV.to_owned(),
            NODE_KEY_ID.to_owned(),
        ),
    ]);
    let config = CrossCheckedAnchorStartupConfig::from_values(ADMIN_BEARER, &values)
        .expect("config")
        .expect("enabled");
    assert!(!format!("{config:?}").contains(DEDICATED_BEARER));
}

#[test]
fn required_startup_environment_names_are_unique() {
    let names = BTreeSet::from([
        CROSSCHECKED_ANCHOR_BEARER_ENV,
        CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV,
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV,
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV,
        CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV,
    ]);
    assert_eq!(names.len(), 8);
}
