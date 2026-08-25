// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Output},
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use exo_api::crosschecked_anchor::{ANCHOR_PATH, CrossCheckedAnchorRequestV1};
use exo_core::{
    crypto::KeyPair,
    types::{Hash256, Signature, Timestamp},
};
use exo_node::{
    crosschecked_anchor_http::{
        CrossCheckedAnchorHttpState, CrossCheckedBearerVerifier, crosschecked_anchor_router,
    },
    crosschecked_anchor_store::{
        AnchorNodeIdentity, AnchorStore, AnchorStoreConfig, AnchorStoreError,
        AuthorityProvisioningV1, AuthorityRetirementV1, DurableAnchorSigner, SignOnceError,
        SubmissionContext,
    },
};
use serde_json::json;
use tempfile::TempDir;
use tower::ServiceExt;

const AUDIENCE: &str = "crosschecked.production";
const INTERMEDIATE_DID: &str = "did:exo:crosschecked-intermediate";
const INTERMEDIATE_KEY_ID: &str = "did:exo:crosschecked-intermediate#key-1";
const NODE_DID: &str = "did:exo:anchor-node";
const NODE_KEY_ID: &str = "did:exo:anchor-node#response-2026";
const AUTHORITY_DID: &str = "did:exo:crosschecked-workspace-a";
const AUTHORITY_KEY_ID: &str = "did:exo:crosschecked-workspace-a#anchor-1";
const ISSUED_AT: u64 = 1_800_000_000_000;
const DEDICATED_BEARER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct TestSigner {
    identity: AnchorNodeIdentity,
    key: KeyPair,
    reservations: Mutex<BTreeMap<Hash256, Timestamp>>,
    operations: Mutex<BTreeMap<Hash256, (Hash256, Signature)>>,
}

impl TestSigner {
    fn new(identity: AnchorNodeIdentity, secret: [u8; 32]) -> Self {
        Self {
            identity,
            key: KeyPair::from_secret_bytes(secret).expect("test signer key"),
            reservations: Mutex::new(BTreeMap::new()),
            operations: Mutex::new(BTreeMap::new()),
        }
    }
}

impl DurableAnchorSigner for TestSigner {
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
        let mut reservations = self
            .reservations
            .lock()
            .map_err(|_| SignOnceError::Unavailable("test reservation lock poisoned".into()))?;
        Ok(*reservations.entry(request_hash).or_insert(proposed))
    }

    fn sign_once(&self, operation_id: Hash256, payload: &[u8]) -> Result<Signature, SignOnceError> {
        let payload_hash = Hash256::digest(payload);
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| SignOnceError::Unavailable("test operation lock poisoned".into()))?;
        if let Some((existing_hash, signature)) = operations.get(&operation_id) {
            if *existing_hash != payload_hash {
                return Err(SignOnceError::OperationPayloadConflict);
            }
            return Ok(signature.clone());
        }
        let signature = self.key.sign(payload);
        operations.insert(operation_id, (payload_hash, signature.clone()));
        Ok(signature)
    }
}

fn write_private(path: &Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize private test input");
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .expect("create private test input");
        file.write_all(&bytes).expect("write private test input");
    }
    #[cfg(not(unix))]
    fs::write(path, bytes).expect("write private test input");
}

fn run_admin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exochain"))
        .args(args)
        .output()
        .expect("execute exochain owner admin command")
}

fn store_config(node_key: &KeyPair, intermediate_key: &KeyPair) -> AnchorStoreConfig {
    AnchorStoreConfig {
        expected_audience: AUDIENCE.to_owned(),
        crosschecked_intermediate_did: INTERMEDIATE_DID.to_owned(),
        crosschecked_intermediate_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        crosschecked_intermediate_public_key: *intermediate_key.public_key(),
        node_identity: AnchorNodeIdentity {
            did: NODE_DID.to_owned(),
            key_id: NODE_KEY_ID.to_owned(),
            public_key: *node_key.public_key(),
        },
    }
}

fn command_policy(node_key: &KeyPair, intermediate_key: &KeyPair) -> serde_json::Value {
    json!({
        "protocol_version": 1,
        "expected_audience": AUDIENCE,
        "intermediate_did": INTERMEDIATE_DID,
        "intermediate_key_id": INTERMEDIATE_KEY_ID,
        "intermediate_public_key_hex": hex::encode(intermediate_key.public_key().as_bytes()),
        "node_did": NODE_DID,
        "node_key_id": NODE_KEY_ID,
        "node_public_key_hex": hex::encode(node_key.public_key().as_bytes()),
    })
}

fn signed_request(
    authority_key: &KeyPair,
    action_hash: [u8; 32],
    nonce: [u8; 32],
    issued_at_ms: u64,
) -> Vec<u8> {
    let mut request = CrossCheckedAnchorRequestV1 {
        protocol_version: 1,
        source_code: "crosschecked".to_owned(),
        receipt_format: "action_receipt_v3".to_owned(),
        audience: AUDIENCE.to_owned(),
        authority_did: AUTHORITY_DID.to_owned(),
        authority_key_id: AUTHORITY_KEY_ID.to_owned(),
        grant_id: [0x31; 32],
        scope_alias: [0x42; 32],
        action_hash_algorithm: "blake3-256".to_owned(),
        action_hash,
        idempotency_key: [0; 32],
        nonce,
        issued_at_ms,
        expires_at_ms: issued_at_ms + 300_000,
        signature_algorithm: "ed25519".to_owned(),
        signature: [0; 64],
    };
    request.idempotency_key = request
        .derive_idempotency_key()
        .expect("derive idempotency");
    request.signature = *authority_key
        .sign(&request.signing_preimage().expect("request preimage"))
        .ed25519_bytes()
        .expect("Ed25519 request signature");
    request.to_canonical_cbor().expect("canonical request")
}

fn assert_redacted(output: &Output, secret_hex: &str) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let prohibited = vec![
        secret_hex.to_owned(),
        INTERMEDIATE_DID.to_owned(),
        INTERMEDIATE_KEY_ID.to_owned(),
        NODE_DID.to_owned(),
        NODE_KEY_ID.to_owned(),
        AUTHORITY_DID.to_owned(),
        AUTHORITY_KEY_ID.to_owned(),
        hex::encode(intermediate_key.public_key().as_bytes()),
        hex::encode(node_key.public_key().as_bytes()),
        hex::encode(authority_key.public_key().as_bytes()),
        hex::encode([0x31; 32]),
        hex::encode([0x42; 32]),
    ];
    for prohibited in prohibited {
        assert!(
            !combined.contains(&prohibited),
            "owner command output disclosed prohibited material: {prohibited}"
        );
    }
}

async fn post_anchor(app: axum::Router, body: Vec<u8>) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(ANCHOR_PATH)
            .header(header::CONTENT_TYPE, "application/cbor")
            .header(header::AUTHORIZATION, format!("Bearer {DEDICATED_BEARER}"))
            .body(Body::from(body))
            .expect("anchor HTTP request"),
    )
    .await
    .expect("anchor route response")
}

#[tokio::test]
async fn owner_cli_provisions_fresh_registry_accepts_then_idempotently_retires_and_rejects() {
    let temp = TempDir::new().expect("temp directory");
    let data_dir = temp.path().join("node-data");
    fs::create_dir(&data_dir).expect("create node data directory");
    let provision_path = temp.path().join("provision.json");
    let retirement_path = temp.path().join("retire.json");
    let secret_path = temp.path().join("intermediate.secret.json");
    let provisioning_artifact = temp.path().join("provisioning.cbor");
    let retirement_artifact = temp.path().join("retirement.cbor");

    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let secret_hex = hex::encode([0x41; 32]);
    write_private(
        &secret_path,
        &json!({
            "protocol_version": 1,
            "intermediate_did": INTERMEDIATE_DID,
            "intermediate_key_id": INTERMEDIATE_KEY_ID,
            "signing_secret_hex": secret_hex,
        }),
    );

    let mut provision = command_policy(&node_key, &intermediate_key);
    provision.as_object_mut().expect("object").extend(
        json!({
            "authority_did": AUTHORITY_DID,
            "authority_key_id": AUTHORITY_KEY_ID,
            "authority_public_key_hex": hex::encode(authority_key.public_key().as_bytes()),
            "grant_id_hex": hex::encode([0x31; 32]),
            "scope_alias_hex": hex::encode([0x42; 32]),
            "key_epoch": 1,
            "valid_from_ms": ISSUED_AT - 1_000,
            "valid_until_ms": ISSUED_AT + 600_000,
        })
        .as_object()
        .expect("object")
        .clone(),
    );
    write_private(&provision_path, &provision);

    let provision_output = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        provision_path.to_str().expect("provision path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--signed-package-out",
        provisioning_artifact
            .to_str()
            .expect("provisioning artifact path"),
    ]);
    assert!(
        provision_output.status.success(),
        "provision failed: {}",
        String::from_utf8_lossy(&provision_output.stderr)
    );
    assert_redacted(&provision_output, &secret_hex);
    let provision_summary: serde_json::Value =
        serde_json::from_slice(&provision_output.stdout).expect("redacted provision summary");
    assert_eq!(provision_summary["operation"], "provision");
    assert_eq!(
        provision_summary["persistence_status"],
        "committed_or_exact_replay"
    );
    assert_eq!(
        provision_summary.as_object().expect("summary object").len(),
        4,
        "summary must remain a closed four-field object"
    );
    let provisioning_bytes = fs::read(&provisioning_artifact).expect("provision artifact");
    let signed_provisioning: AuthorityProvisioningV1 =
        ciborium::from_reader(provisioning_bytes.as_slice()).expect("signed provisioning CBOR");
    assert_eq!(
        signed_provisioning.scope_binding.authority_did.as_str(),
        AUTHORITY_DID
    );
    assert!(!signed_provisioning.scope_binding.signature.is_empty());
    assert!(
        !signed_provisioning.authority_chain.links[0]
            .signature
            .is_empty()
    );
    let records_path = data_dir.join("crosschecked_anchor").join("records.sqlite3");
    let persisted_provisioning: Vec<u8> = rusqlite::Connection::open(&records_path)
        .expect("open owner registry")
        .query_row(
            "SELECT provisioning_cbor FROM crosschecked_anchor_authorities",
            [],
            |row| row.get(0),
        )
        .expect("read exact persisted provisioning");
    assert_eq!(persisted_provisioning, provisioning_bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(data_dir.join("crosschecked_anchor"))
                .expect("registry directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&records_path)
                .expect("registry file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&provisioning_artifact)
                .expect("provision artifact metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let artifact_overwrite = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        provision_path.to_str().expect("provision path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--signed-package-out",
        provisioning_artifact
            .to_str()
            .expect("provisioning artifact path"),
    ]);
    assert!(
        !artifact_overwrite.status.success(),
        "signed package output must be create-new"
    );
    assert_redacted(&artifact_overwrite, &secret_hex);
    assert_eq!(
        fs::read(&provisioning_artifact).expect("unchanged provision artifact"),
        provisioning_bytes
    );

    let exact_replay = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        provision_path.to_str().expect("provision path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
    ]);
    assert!(
        exact_replay.status.success(),
        "exact provision replay failed"
    );
    assert_redacted(&exact_replay, &secret_hex);
    let replay_summary: serde_json::Value =
        serde_json::from_slice(&exact_replay.stdout).expect("redacted replay summary");
    assert_eq!(
        replay_summary["package_sha256"],
        provision_summary["package_sha256"]
    );
    let authority_rows: i64 = rusqlite::Connection::open(&records_path)
        .expect("open owner registry")
        .query_row(
            "SELECT COUNT(*) FROM crosschecked_anchor_authorities",
            [],
            |row| row.get(0),
        )
        .expect("count durable authorities");
    assert_eq!(
        authority_rows, 1,
        "exact provisioning replay must not duplicate"
    );
    let config = store_config(&node_key, &intermediate_key);
    let store = AnchorStore::open(&records_path, config.clone()).expect("open provisioned store");
    let signer = Arc::new(TestSigner::new(config.node_identity.clone(), [0x29; 32]));
    let durable_signer: Arc<dyn DurableAnchorSigner> = signer.clone();
    let route = crosschecked_anchor_router(CrossCheckedAnchorHttpState::new(
        store.clone(),
        durable_signer,
        CrossCheckedBearerVerifier::from_bearer(DEDICATED_BEARER).expect("dedicated route bearer"),
        Arc::new(|| Ok(Timestamp::new(ISSUED_AT + 100, 0))),
    ));
    let accepted_body = signed_request(&authority_key, [0x53; 32], [0x64; 32], ISSUED_AT);
    assert_eq!(
        post_anchor(route.clone(), accepted_body).await.status(),
        StatusCode::CREATED,
        "fresh node route must accept after owner provisioning"
    );

    let mut retirement = command_policy(&node_key, &intermediate_key);
    retirement.as_object_mut().expect("object").extend(
        json!({
            "authority_did": AUTHORITY_DID,
            "authority_key_id": AUTHORITY_KEY_ID,
            "key_epoch": 1,
            "retired_at_ms": ISSUED_AT + 200,
        })
        .as_object()
        .expect("object")
        .clone(),
    );
    write_private(&retirement_path, &retirement);
    let retire_output = run_admin(&[
        "crosschecked-anchor-authority",
        "retire",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        retirement_path.to_str().expect("retirement path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--signed-package-out",
        retirement_artifact
            .to_str()
            .expect("retirement artifact path"),
    ]);
    assert!(
        retire_output.status.success(),
        "retire failed: {}",
        String::from_utf8_lossy(&retire_output.stderr)
    );
    assert_redacted(&retire_output, &secret_hex);
    let retirement_bytes = fs::read(&retirement_artifact).expect("retirement artifact");
    let signed_retirement: AuthorityRetirementV1 =
        ciborium::from_reader(retirement_bytes.as_slice()).expect("signed retirement CBOR");
    assert_eq!(signed_retirement.retired_at_ms, ISSUED_AT + 200);
    assert!(!signed_retirement.signature.is_empty());
    let persisted_retirement: Vec<u8> = rusqlite::Connection::open(&records_path)
        .expect("open owner registry")
        .query_row(
            "SELECT retirement_cbor FROM crosschecked_anchor_authorities",
            [],
            |row| row.get(0),
        )
        .expect("read exact persisted retirement");
    assert_eq!(persisted_retirement, retirement_bytes);

    let retirement_replay = run_admin(&[
        "crosschecked-anchor-authority",
        "revoke",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        retirement_path.to_str().expect("retirement path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
    ]);
    assert!(
        retirement_replay.status.success(),
        "retirement replay failed"
    );
    assert_redacted(&retirement_replay, &secret_hex);

    let restarted = AnchorStore::open(&records_path, config).expect("reopen retired store");
    let rejected_body = signed_request(&authority_key, [0x54; 32], [0x65; 32], ISSUED_AT + 250);
    assert_eq!(
        post_anchor(route, rejected_body.clone()).await.status(),
        StatusCode::FORBIDDEN,
        "fresh node route must reject new records after retirement"
    );
    assert_eq!(
        restarted.record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &rejected_body,
                now: Timestamp::new(ISSUED_AT + 300, 0),
            },
            signer.as_ref(),
        ),
        Err(AnchorStoreError::AuthorityRetired)
    );
}

#[cfg(unix)]
#[test]
fn owner_cli_rejects_permissive_or_symlinked_secret_files_and_unknown_command_fields() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temp = TempDir::new().expect("temp directory");
    let data_dir = temp.path().join("node-data");
    fs::create_dir(&data_dir).expect("create node data directory");
    let command_path = temp.path().join("provision.json");
    let unknown_command_path = temp.path().join("provision-unknown.json");
    let secret_path = temp.path().join("intermediate.secret.json");
    let secret_link = temp.path().join("intermediate.secret.link.json");
    let wrong_secret_path = temp.path().join("wrong-intermediate.secret.json");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let secret_hex = hex::encode([0x41; 32]);

    let mut command = command_policy(&node_key, &intermediate_key);
    command.as_object_mut().expect("object").extend(
        json!({
            "authority_did": AUTHORITY_DID,
            "authority_key_id": AUTHORITY_KEY_ID,
            "authority_public_key_hex": hex::encode(authority_key.public_key().as_bytes()),
            "grant_id_hex": hex::encode([0x31; 32]),
            "scope_alias_hex": hex::encode([0x42; 32]),
            "key_epoch": 1,
            "valid_from_ms": ISSUED_AT - 1_000,
            "valid_until_ms": ISSUED_AT + 600_000,
        })
        .as_object()
        .expect("object")
        .clone(),
    );
    write_private(&command_path, &command);
    let mut unknown_command = command.clone();
    unknown_command
        .as_object_mut()
        .expect("object")
        .insert("unexpected_field".to_owned(), json!("must-fail-closed"));
    write_private(&unknown_command_path, &unknown_command);
    write_private(
        &secret_path,
        &json!({
            "protocol_version": 1,
            "intermediate_did": INTERMEDIATE_DID,
            "intermediate_key_id": INTERMEDIATE_KEY_ID,
            "signing_secret_hex": secret_hex,
        }),
    );
    write_private(
        &wrong_secret_path,
        &json!({
            "protocol_version": 1,
            "intermediate_did": INTERMEDIATE_DID,
            "intermediate_key_id": INTERMEDIATE_KEY_ID,
            "signing_secret_hex": hex::encode([0x43; 32]),
        }),
    );
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644))
        .expect("make secret permissive");

    let permissive = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        command_path.to_str().expect("command path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
    ]);
    assert!(!permissive.status.success());
    assert_redacted(&permissive, &secret_hex);

    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
        .expect("restore secret mode");
    symlink(&secret_path, &secret_link).expect("create secret symlink");
    let symlinked = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        command_path.to_str().expect("command path"),
        "--intermediate-secret-file",
        secret_link.to_str().expect("secret link"),
    ]);
    assert!(!symlinked.status.success());
    assert_redacted(&symlinked, &secret_hex);

    let unknown_field = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        unknown_command_path.to_str().expect("unknown command path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
    ]);
    assert!(!unknown_field.status.success());
    assert_redacted(&unknown_field, &secret_hex);

    let substituted_signer = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        command_path.to_str().expect("command path"),
        "--intermediate-secret-file",
        wrong_secret_path.to_str().expect("wrong secret path"),
    ]);
    assert!(!substituted_signer.status.success());
    assert_redacted(&substituted_signer, &secret_hex);
    assert!(
        !String::from_utf8_lossy(&substituted_signer.stderr).contains(&hex::encode([0x43; 32])),
        "substituted signing secret must remain redacted"
    );
    assert!(
        !data_dir
            .join("crosschecked_anchor/records.sqlite3")
            .exists(),
        "rejected owner commands must not create registry state"
    );
}
