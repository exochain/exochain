// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/crosschecked_anchor_governance.rs"]
mod governance_support;

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Output},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use ciborium::Value;
use exo_api::crosschecked_anchor::{ANCHOR_PATH, CrossCheckedAnchorRequestV1};
use exo_authority::{AuthorityChain, AuthorityLink, DelegateeKind, Permission};
use exo_core::{
    crypto::KeyPair,
    types::{Did, Hash256, PublicKey, Signature, Timestamp},
};
use exo_identity::did::{DidDocument, VerificationMethod};
use exo_node::{
    crosschecked_anchor_http::{
        CrossCheckedAnchorHttpState, CrossCheckedBearerVerifier, crosschecked_anchor_router,
    },
    crosschecked_anchor_store::{
        AnchorNodeIdentity, AnchorStore, AnchorStoreConfig, AnchorStoreError,
        AuthorityProvisioningV1, AuthorityRetirementV1, CrossCheckedScopeBindingV1,
        DurableAnchorSigner, SignOnceError, SubmissionContext, authority_chain_fingerprint,
    },
};
use frost_ed25519 as frost;
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

use governance_support::governance_group_public_key;

const AUDIENCE: &str = "crosschecked.production";
const INTERMEDIATE_DID: &str = "did:exo:crosschecked-intermediate";
const INTERMEDIATE_KEY_ID: &str = "did:exo:crosschecked-intermediate#key-1";
const NODE_DID: &str = "did:exo:anchor-node";
const NODE_KEY_ID: &str = "did:exo:anchor-node#response-2026";
const AUTHORITY_DID: &str = "did:exo:crosschecked-workspace-a";
const AUTHORITY_KEY_ID: &str = "did:exo:crosschecked-workspace-a#anchor-1";
const ISSUED_AT: u64 = 1_800_000_000_000;
const DEDICATED_BEARER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GOVERNANCE_KEY_EPOCH: u64 = 7;
const GOVERNANCE_THRESHOLD: u16 = 7;
const GOVERNANCE_PARTICIPANTS: u16 = 13;
const GOVERNANCE_SIGNATURE_ALGORITHM: &str = "frost-ed25519-sha512-rfc9591";

struct GovernanceTestKeys {
    key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: frost::keys::PublicKeyPackage,
}

fn frost_test_keys(seed: u64) -> GovernanceTestKeys {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut round1_secrets = BTreeMap::new();
    let mut round1_public = BTreeMap::new();
    for value in 1..=GOVERNANCE_PARTICIPANTS {
        let identifier = frost::Identifier::try_from(value).expect("FROST identifier");
        let (secret, package) = frost::keys::dkg::part1(
            identifier,
            GOVERNANCE_PARTICIPANTS,
            GOVERNANCE_THRESHOLD,
            &mut rng,
        )
        .expect("FROST DKG round one");
        round1_secrets.insert(identifier, secret);
        round1_public.insert(identifier, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut round2_by_recipient: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    > = BTreeMap::new();
    for (identifier, secret) in round1_secrets {
        let peers = round1_public
            .iter()
            .filter(|(peer, _)| **peer != identifier)
            .map(|(peer, package)| (*peer, package.clone()))
            .collect();
        let (round2_secret, outbound) =
            frost::keys::dkg::part2(secret, &peers).expect("FROST DKG round two");
        for (recipient, package) in outbound {
            round2_by_recipient
                .entry(recipient)
                .or_default()
                .insert(identifier, package);
        }
        round2_secrets.insert(identifier, round2_secret);
    }

    let mut key_packages = BTreeMap::new();
    let mut public_key_package = None;
    for (identifier, secret) in round2_secrets {
        let round1_peers = round1_public
            .iter()
            .filter(|(peer, _)| **peer != identifier)
            .map(|(peer, package)| (*peer, package.clone()))
            .collect();
        let round2_peers = round2_by_recipient
            .remove(&identifier)
            .expect("recipient round-two packages");
        let (key_package, candidate_public) =
            frost::keys::dkg::part3(&secret, &round1_peers, &round2_peers)
                .expect("FROST DKG round three");
        if let Some(expected) = &public_key_package {
            assert_eq!(expected, &candidate_public, "all DKG participants agree");
        } else {
            public_key_package = Some(candidate_public.clone());
        }
        key_packages.insert(identifier, key_package);
    }
    GovernanceTestKeys {
        key_packages,
        public_key_package: public_key_package.expect("FROST public key package"),
    }
}

fn frost_sign(
    keys: &GovernanceTestKeys,
    message: &[u8],
    signer_count: usize,
    seed: u64,
) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let selected: BTreeMap<_, _> = keys
        .key_packages
        .iter()
        .take(signer_count)
        .map(|(identifier, package)| (*identifier, package.clone()))
        .collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (identifier, package) in &selected {
        let (signing_nonces, signing_commitments) =
            frost::round1::commit(package.signing_share(), &mut rng);
        nonces.insert(*identifier, signing_nonces);
        commitments.insert(*identifier, signing_commitments);
    }
    let signing_package = frost::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for (identifier, package) in &selected {
        shares.insert(
            *identifier,
            frost::round2::sign(&signing_package, &nonces[identifier], package)
                .expect("FROST signature share"),
        );
    }
    frost::aggregate(&signing_package, &shares, &keys.public_key_package)
        .expect("FROST aggregate signature")
        .serialize()
        .expect("FROST signature bytes")
}

fn encoded_array(values: Vec<Value>) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&Value::Array(values), &mut bytes).expect("canonical CBOR array");
    bytes
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn unsigned(value: u64) -> Value {
    Value::Integer(value.into())
}

fn did(value: &str) -> Did {
    Did::new(value).expect("valid DID")
}

fn did_document(
    did_value: &str,
    key_id: &str,
    public_key: PublicKey,
    version: u64,
    valid_from_ms: u64,
) -> DidDocument {
    let controller = did(did_value);
    DidDocument {
        id: controller.clone(),
        public_keys: vec![public_key],
        authentication: vec![],
        verification_methods: vec![VerificationMethod {
            id: key_id.to_owned(),
            key_type: "Ed25519VerificationKey2020".to_owned(),
            controller,
            public_key_multibase: format!("z{}", bs58::encode(public_key.as_bytes()).into_string()),
            version,
            active: true,
            valid_from: valid_from_ms,
            revoked_at: None,
        }],
        hybrid_verification_methods: vec![],
        service_endpoints: vec![],
        created: Timestamp::new(valid_from_ms, 0),
        updated: Timestamp::new(valid_from_ms, 0),
        revoked: false,
    }
}

fn cli_provisioning(
    intermediate_key: &KeyPair,
    authority_key: &KeyPair,
    valid_from_ms: u64,
    valid_until_ms: u64,
) -> AuthorityProvisioningV1 {
    let intermediate_did = did(INTERMEDIATE_DID);
    let authority_did = did(AUTHORITY_DID);
    let mut link = AuthorityLink {
        delegator_did: intermediate_did.clone(),
        delegate_did: authority_did.clone(),
        scope: vec![Permission::AnchorReceiptCommitment],
        created: Timestamp::new(valid_from_ms, 0),
        expires: Some(Timestamp::new(valid_until_ms, 0)),
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
        authority_did: authority_did.clone(),
        authority_key_id: AUTHORITY_KEY_ID.to_owned(),
        grant_id: [0x31; 32],
        scope_alias: [0x42; 32],
        audience: AUDIENCE.to_owned(),
        permission: Permission::AnchorReceiptCommitment,
        key_epoch: 1,
        valid_from_ms,
        valid_until_ms,
        chain_fingerprint: authority_chain_fingerprint(&chain).expect("chain fingerprint"),
        binding_signer_did: intermediate_did.clone(),
        binding_signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        signature: Signature::empty(),
    };
    binding.signature = intermediate_key.sign(
        &binding
            .signing_preimage()
            .expect("scope binding signing preimage"),
    );
    AuthorityProvisioningV1 {
        protocol_version: 1,
        did_documents: vec![
            did_document(
                INTERMEDIATE_DID,
                INTERMEDIATE_KEY_ID,
                *intermediate_key.public_key(),
                1,
                0,
            ),
            did_document(
                AUTHORITY_DID,
                AUTHORITY_KEY_ID,
                *authority_key.public_key(),
                1,
                valid_from_ms,
            ),
        ],
        authority_chain: chain,
        scope_binding: binding,
    }
}

fn cli_retirement(intermediate_key: &KeyPair, retired_at_ms: u64) -> AuthorityRetirementV1 {
    let mut retirement = AuthorityRetirementV1 {
        protocol_version: 1,
        authority_did: did(AUTHORITY_DID),
        authority_key_id: AUTHORITY_KEY_ID.to_owned(),
        key_epoch: 1,
        retired_at_ms,
        signer_did: did(INTERMEDIATE_DID),
        signer_key_id: INTERMEDIATE_KEY_ID.to_owned(),
        signature: Signature::empty(),
    };
    retirement.signature = intermediate_key.sign(
        &retirement
            .signing_preimage()
            .expect("retirement signing preimage"),
    );
    retirement
}

fn governance_node_policy_hash(
    node_key: &KeyPair,
    intermediate_key: &KeyPair,
    governance_group_public_key: &[u8],
) -> Hash256 {
    Hash256::digest(&governance_node_policy_preimage(
        node_key,
        intermediate_key,
        governance_group_public_key,
    ))
}

fn governance_node_policy_preimage(
    node_key: &KeyPair,
    intermediate_key: &KeyPair,
    governance_group_public_key: &[u8],
) -> Vec<u8> {
    encoded_array(vec![
        text("exo.crosschecked.anchor_node_policy.v1"),
        text(AUDIENCE),
        text(INTERMEDIATE_DID),
        text(INTERMEDIATE_KEY_ID),
        bytes(intermediate_key.public_key().as_bytes()),
        text(NODE_DID),
        text(NODE_KEY_ID),
        bytes(node_key.public_key().as_bytes()),
        unsigned(GOVERNANCE_KEY_EPOCH),
        unsigned(u64::from(GOVERNANCE_THRESHOLD)),
        unsigned(u64::from(GOVERNANCE_PARTICIPANTS)),
        bytes(governance_group_public_key),
    ])
}

fn governance_authorization_preimage(
    package_hash: Hash256,
    node_policy_hash: Hash256,
    authorization_valid_from_ms: u64,
    authorization_valid_until_ms: u64,
) -> Vec<u8> {
    encoded_array(vec![
        text("exo.crosschecked.authority_governance.v1"),
        unsigned(1),
        bytes(&[0x71; 32]),
        bytes(&[0x72; 32]),
        unsigned(GOVERNANCE_KEY_EPOCH),
        unsigned(u64::from(GOVERNANCE_THRESHOLD)),
        unsigned(u64::from(GOVERNANCE_PARTICIPANTS)),
        Value::Array(
            (1..=GOVERNANCE_THRESHOLD)
                .map(|value| unsigned(u64::from(value)))
                .collect(),
        ),
        text("provision"),
        text(AUTHORITY_DID),
        text(AUTHORITY_KEY_ID),
        unsigned(1),
        bytes(&[0x42; 32]),
        bytes(package_hash.as_bytes()),
        bytes(node_policy_hash.as_bytes()),
        unsigned(1),
        bytes(&[0; 32]),
        unsigned(authorization_valid_from_ms),
        unsigned(authorization_valid_until_ms),
        text(GOVERNANCE_SIGNATURE_ALGORITHM),
    ])
}

fn governance_authorization_json(
    keys: &GovernanceTestKeys,
    package_hash: Hash256,
    node_policy_hash: Hash256,
    application_time_ms: u64,
) -> serde_json::Value {
    let preimage = governance_authorization_preimage(
        package_hash,
        node_policy_hash,
        application_time_ms - 1_000,
        application_time_ms + 300_000,
    );
    let signature = frost_sign(keys, &preimage, usize::from(GOVERNANCE_THRESHOLD), 9002);
    json!({
        "protocol_version": 1,
        "authorization_id_hex": hex::encode([0x71; 32]),
        "ceremony_id_hex": hex::encode([0x72; 32]),
        "governance_key_epoch": GOVERNANCE_KEY_EPOCH,
        "threshold": GOVERNANCE_THRESHOLD,
        "participant_count": GOVERNANCE_PARTICIPANTS,
        "signer_ids": [1, 2, 3, 4, 5, 6, 7],
        "lifecycle_event": "provision",
        "authority_did": AUTHORITY_DID,
        "authority_key_id": AUTHORITY_KEY_ID,
        "authority_key_epoch": 1,
        "scope_alias_hex": hex::encode([0x42; 32]),
        "package_hash_hex": hex::encode(package_hash.as_bytes()),
        "node_policy_hash_hex": hex::encode(node_policy_hash.as_bytes()),
        "authorization_sequence": 1,
        "prior_authorization_hash_hex": hex::encode([0; 32]),
        "valid_from_ms": application_time_ms - 1_000,
        "valid_until_ms": application_time_ms + 300_000,
        "signature_algorithm": GOVERNANCE_SIGNATURE_ALGORITHM,
        "signature_hex": hex::encode(signature),
    })
}

fn current_time_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock after Unix epoch")
            .as_millis(),
    )
    .expect("test clock fits u64")
}

fn governance_authorization_artifact_hash(
    authorization_json: &serde_json::Value,
    preimage: &[u8],
) -> Hash256 {
    let signature = hex::decode(
        authorization_json["signature_hex"]
            .as_str()
            .expect("signature hex"),
    )
    .expect("signature bytes");
    Hash256::digest(&encoded_array(vec![bytes(preimage), bytes(&signature)]))
}

#[allow(clippy::too_many_arguments)]
fn governance_retirement_authorization_json(
    keys: &GovernanceTestKeys,
    lifecycle_event: &str,
    package_hash: Hash256,
    node_policy_hash: Hash256,
    prior_authorization_hash: Hash256,
    application_time_ms: u64,
) -> serde_json::Value {
    let preimage = encoded_array(vec![
        text("exo.crosschecked.authority_governance.v1"),
        unsigned(1),
        bytes(&[0x73; 32]),
        bytes(&[0x74; 32]),
        unsigned(GOVERNANCE_KEY_EPOCH),
        unsigned(u64::from(GOVERNANCE_THRESHOLD)),
        unsigned(u64::from(GOVERNANCE_PARTICIPANTS)),
        Value::Array(
            (1..=GOVERNANCE_THRESHOLD)
                .map(|value| unsigned(u64::from(value)))
                .collect(),
        ),
        text(lifecycle_event),
        text(AUTHORITY_DID),
        text(AUTHORITY_KEY_ID),
        unsigned(1),
        bytes(&[0x42; 32]),
        bytes(package_hash.as_bytes()),
        bytes(node_policy_hash.as_bytes()),
        unsigned(2),
        bytes(prior_authorization_hash.as_bytes()),
        unsigned(application_time_ms - 1_000),
        unsigned(application_time_ms + 300_000),
        text(GOVERNANCE_SIGNATURE_ALGORITHM),
    ]);
    let signature = frost_sign(keys, &preimage, usize::from(GOVERNANCE_THRESHOLD), 9003);
    json!({
        "protocol_version": 1,
        "authorization_id_hex": hex::encode([0x73; 32]),
        "ceremony_id_hex": hex::encode([0x74; 32]),
        "governance_key_epoch": GOVERNANCE_KEY_EPOCH,
        "threshold": GOVERNANCE_THRESHOLD,
        "participant_count": GOVERNANCE_PARTICIPANTS,
        "signer_ids": [1, 2, 3, 4, 5, 6, 7],
        "lifecycle_event": lifecycle_event,
        "authority_did": AUTHORITY_DID,
        "authority_key_id": AUTHORITY_KEY_ID,
        "authority_key_epoch": 1,
        "scope_alias_hex": hex::encode([0x42; 32]),
        "package_hash_hex": hex::encode(package_hash.as_bytes()),
        "node_policy_hash_hex": hex::encode(node_policy_hash.as_bytes()),
        "authorization_sequence": 2,
        "prior_authorization_hash_hex": hex::encode(prior_authorization_hash.as_bytes()),
        "valid_from_ms": application_time_ms - 1_000,
        "valid_until_ms": application_time_ms + 300_000,
        "signature_algorithm": GOVERNANCE_SIGNATURE_ALGORITHM,
        "signature_hex": hex::encode(signature),
    })
}

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
        governance_frost_group_public_key: governance_group_public_key(),
        governance_frost_key_epoch: GOVERNANCE_KEY_EPOCH,
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
        "governance_group_public_key_hex": hex::encode(governance_group_public_key()),
        "governance_key_epoch": GOVERNANCE_KEY_EPOCH,
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
    let provision_authorization_path = temp.path().join("provision-governance.json");
    let retirement_authorization_path = temp.path().join("retire-governance.json");
    let secret_path = temp.path().join("intermediate.secret.json");
    let provisioning_artifact = temp.path().join("provisioning.cbor");
    let retirement_artifact = temp.path().join("retirement.cbor");

    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let governance_keys = frost_test_keys(9001);
    let governance_public_key = governance_keys
        .public_key_package
        .verifying_key()
        .serialize()
        .expect("FROST group public key");
    let mut pinned_config = store_config(&node_key, &intermediate_key);
    pinned_config.governance_frost_group_public_key = governance_public_key
        .as_slice()
        .try_into()
        .expect("32-byte governance group public key");
    let registry_dir = data_dir.join("crosschecked_anchor");
    fs::create_dir(&registry_dir).expect("create registry directory");
    let records_path = registry_dir.join("records.sqlite3");
    AnchorStore::open(&records_path, pinned_config.clone())
        .expect("initialize persistently pinned authority registry");
    let owner_command_time_ms = current_time_ms();
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
            "governance_group_public_key_hex": hex::encode(&governance_public_key),
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
    let provisioning_package = cli_provisioning(
        &intermediate_key,
        &authority_key,
        ISSUED_AT - 1_000,
        ISSUED_AT + 600_000,
    );
    let provisioning_package_hash = Hash256::digest(
        &provisioning_package
            .to_cbor_bytes()
            .expect("provisioning package CBOR"),
    );
    let node_policy_hash =
        governance_node_policy_hash(&node_key, &intermediate_key, &governance_public_key);
    let provisioning_authorization = governance_authorization_json(
        &governance_keys,
        provisioning_package_hash,
        node_policy_hash,
        owner_command_time_ms,
    );
    write_private(&provision_authorization_path, &provisioning_authorization);
    let provisioning_authorization_hash = governance_authorization_artifact_hash(
        &provisioning_authorization,
        &governance_authorization_preimage(
            provisioning_package_hash,
            node_policy_hash,
            owner_command_time_ms - 1_000,
            owner_command_time_ms + 300_000,
        ),
    );

    let provision_output = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        provision_path.to_str().expect("provision path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--governance-authorization",
        provision_authorization_path
            .to_str()
            .expect("provision authorization path"),
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
    let persisted_provisioning: Vec<u8> = rusqlite::Connection::open(&records_path)
        .expect("open owner registry")
        .query_row(
            "SELECT provisioning_cbor FROM crosschecked_anchor_authorities",
            [],
            |row| row.get(0),
        )
        .expect("read exact persisted provisioning");
    assert_eq!(persisted_provisioning, provisioning_bytes);
    let persisted_authorization_hash: Vec<u8> = rusqlite::Connection::open(&records_path)
        .expect("open owner registry")
        .query_row(
            "SELECT authorization_hash FROM crosschecked_anchor_governance_authorizations",
            [],
            |row| row.get(0),
        )
        .expect("read persisted governance authorization hash");
    assert_eq!(
        persisted_authorization_hash,
        provisioning_authorization_hash.as_bytes(),
        "independent canonical authorization commitment must match persisted bytes"
    );
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
        "--governance-authorization",
        provision_authorization_path
            .to_str()
            .expect("provision authorization path"),
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
        "--governance-authorization",
        provision_authorization_path
            .to_str()
            .expect("provision authorization path"),
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
    let config = pinned_config;
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
            "governance_group_public_key_hex": hex::encode(&governance_public_key),
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
    let retirement_package = cli_retirement(&intermediate_key, ISSUED_AT + 200);
    let retirement_package_hash = Hash256::digest(
        &retirement_package
            .to_cbor_bytes()
            .expect("retirement package CBOR"),
    );
    let retirement_authorization = governance_retirement_authorization_json(
        &governance_keys,
        "retire",
        retirement_package_hash,
        node_policy_hash,
        provisioning_authorization_hash,
        owner_command_time_ms,
    );
    write_private(&retirement_authorization_path, &retirement_authorization);
    let retire_output = run_admin(&[
        "crosschecked-anchor-authority",
        "retire",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        retirement_path.to_str().expect("retirement path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--governance-authorization",
        retirement_authorization_path
            .to_str()
            .expect("retirement authorization path"),
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
        "retire",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        retirement_path.to_str().expect("retirement path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--governance-authorization",
        retirement_authorization_path
            .to_str()
            .expect("retirement authorization path"),
    ]);
    assert!(
        retirement_replay.status.success(),
        "retirement replay failed"
    );
    assert_redacted(&retirement_replay, &secret_hex);
    let governance_rows: i64 = rusqlite::Connection::open(&records_path)
        .expect("open owner registry")
        .query_row(
            "SELECT COUNT(*) FROM crosschecked_anchor_governance_authorizations",
            [],
            |row| row.get(0),
        )
        .expect("count governance authorizations");
    assert_eq!(
        governance_rows, 2,
        "exact replays must not duplicate governance authorizations"
    );

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

#[test]
fn owner_cli_rejects_intermediate_only_provisioning_without_governance_authorization() {
    let temp = TempDir::new().expect("temp directory");
    let data_dir = temp.path().join("node-data");
    fs::create_dir(&data_dir).expect("create node data directory");
    let command_path = temp.path().join("provision.json");
    let secret_path = temp.path().join("intermediate.secret.json");
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
    write_private(
        &secret_path,
        &json!({
            "protocol_version": 1,
            "intermediate_did": INTERMEDIATE_DID,
            "intermediate_key_id": INTERMEDIATE_KEY_ID,
            "signing_secret_hex": secret_hex,
        }),
    );

    let output = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        command_path.to_str().expect("command path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
    ]);
    assert!(
        !output.status.success(),
        "intermediate signer possession without threshold authorization must fail closed"
    );
    assert_redacted(&output, &secret_hex);
    assert!(
        !data_dir
            .join("crosschecked_anchor/records.sqlite3")
            .exists(),
        "no-FROST provisioning must leave no registry state"
    );
}

#[test]
fn owner_cli_rejects_malformed_governance_authorization_before_registry_mutation() {
    let temp = TempDir::new().expect("temp directory");
    let data_dir = temp.path().join("node-data");
    fs::create_dir(&data_dir).expect("create node data directory");
    let command_path = temp.path().join("provision.json");
    let secret_path = temp.path().join("intermediate.secret.json");
    let authorization_path = temp.path().join("governance-authorization.json");
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
    write_private(
        &secret_path,
        &json!({
            "protocol_version": 1,
            "intermediate_did": INTERMEDIATE_DID,
            "intermediate_key_id": INTERMEDIATE_KEY_ID,
            "signing_secret_hex": secret_hex,
        }),
    );
    write_private(&authorization_path, &json!({"protocol_version": 1}));

    let output = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        command_path.to_str().expect("command path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--governance-authorization",
        authorization_path.to_str().expect("authorization path"),
    ]);
    assert!(
        !output.status.success(),
        "malformed threshold authorization must fail closed"
    );
    assert_redacted(&output, &secret_hex);
    assert!(
        !data_dir
            .join("crosschecked_anchor/records.sqlite3")
            .exists(),
        "malformed threshold authorization must leave no registry state"
    );
}

#[test]
fn owner_cli_accepts_exact_seven_of_thirteen_frost_authorization() {
    let temp = TempDir::new().expect("temp directory");
    let data_dir = temp.path().join("node-data");
    fs::create_dir(&data_dir).expect("create node data directory");
    let command_path = temp.path().join("provision.json");
    let secret_path = temp.path().join("intermediate.secret.json");
    let authorization_path = temp.path().join("governance-authorization.json");
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let governance_keys = frost_test_keys(9001);
    let governance_public_key = governance_keys
        .public_key_package
        .verifying_key()
        .serialize()
        .expect("FROST group public key");
    let valid_from_ms = ISSUED_AT - 1_000;
    let valid_until_ms = ISSUED_AT + 600_000;
    let provisioning = cli_provisioning(
        &intermediate_key,
        &authority_key,
        valid_from_ms,
        valid_until_ms,
    );
    let package_bytes = provisioning.to_cbor_bytes().expect("provisioning CBOR");
    let package_hash = Hash256::digest(&package_bytes);
    let node_policy_hash =
        governance_node_policy_hash(&node_key, &intermediate_key, &governance_public_key);
    let registry_dir = data_dir.join("crosschecked_anchor");
    fs::create_dir(&registry_dir).expect("create registry directory");
    let mut pinned_config = store_config(&node_key, &intermediate_key);
    pinned_config.governance_frost_group_public_key = governance_public_key
        .as_slice()
        .try_into()
        .expect("32-byte governance group public key");
    AnchorStore::open(registry_dir.join("records.sqlite3"), pinned_config)
        .expect("initialize pinned authority registry");

    let mut command = command_policy(&node_key, &intermediate_key);
    command.as_object_mut().expect("object").extend(
        json!({
            "governance_group_public_key_hex": hex::encode(&governance_public_key),
            "governance_key_epoch": GOVERNANCE_KEY_EPOCH,
            "authority_did": AUTHORITY_DID,
            "authority_key_id": AUTHORITY_KEY_ID,
            "authority_public_key_hex": hex::encode(authority_key.public_key().as_bytes()),
            "grant_id_hex": hex::encode([0x31; 32]),
            "scope_alias_hex": hex::encode([0x42; 32]),
            "key_epoch": 1,
            "valid_from_ms": valid_from_ms,
            "valid_until_ms": valid_until_ms,
        })
        .as_object()
        .expect("object")
        .clone(),
    );
    write_private(&command_path, &command);
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
    write_private(
        &authorization_path,
        &governance_authorization_json(
            &governance_keys,
            package_hash,
            node_policy_hash,
            current_time_ms(),
        ),
    );

    let output = run_admin(&[
        "crosschecked-anchor-authority",
        "provision",
        "--data-dir",
        data_dir.to_str().expect("data dir path"),
        "--command",
        command_path.to_str().expect("command path"),
        "--intermediate-secret-file",
        secret_path.to_str().expect("secret path"),
        "--governance-authorization",
        authorization_path.to_str().expect("authorization path"),
    ]);
    assert!(
        output.status.success(),
        "exact threshold-authorized provisioning failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_redacted(&output, &secret_hex);
    let records_path = data_dir.join("crosschecked_anchor/records.sqlite3");
    let connection = rusqlite::Connection::open(records_path).expect("open registry");
    let counts: (i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM crosschecked_anchor_authorities),
                (SELECT COUNT(*) FROM crosschecked_anchor_governance_authorizations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("count atomically persisted authority and authorization");
    assert_eq!(counts, (1, 1));
}

#[test]
fn cross_implementation_governance_fixture_is_exact_and_self_verifying() {
    let node_key = KeyPair::from_secret_bytes([0x29; 32]).expect("node key");
    let intermediate_key = KeyPair::from_secret_bytes([0x41; 32]).expect("intermediate key");
    let authority_key = KeyPair::from_secret_bytes([0x17; 32]).expect("authority key");
    let governance_keys = frost_test_keys(9001);
    let governance_public_key = governance_keys
        .public_key_package
        .verifying_key()
        .serialize()
        .expect("FROST group public key");
    let valid_from_ms = ISSUED_AT - 1_000;
    let provisioning = cli_provisioning(
        &intermediate_key,
        &authority_key,
        valid_from_ms,
        ISSUED_AT + 600_000,
    );
    let package_cbor = provisioning.to_cbor_bytes().expect("provisioning CBOR");
    let package_hash = Hash256::digest(&package_cbor);
    let node_policy_preimage =
        governance_node_policy_preimage(&node_key, &intermediate_key, &governance_public_key);
    let node_policy_hash = Hash256::digest(&node_policy_preimage);
    let authorization_preimage = governance_authorization_preimage(
        package_hash,
        node_policy_hash,
        valid_from_ms - 1_000,
        valid_from_ms + 300_000,
    );
    let authorization = governance_authorization_json(
        &governance_keys,
        package_hash,
        node_policy_hash,
        valid_from_ms,
    );
    let signature = hex::decode(
        authorization["signature_hex"]
            .as_str()
            .expect("signature hex"),
    )
    .expect("signature bytes");
    let authorization_artifact_cbor =
        encoded_array(vec![bytes(&authorization_preimage), bytes(&signature)]);
    let fixture = json!({
        "fixture_version": "crosschecked_anchor_authority_governance_v1",
        "protocol_version": 1,
        "signature_algorithm": GOVERNANCE_SIGNATURE_ALGORITHM,
        "governance_key_epoch": GOVERNANCE_KEY_EPOCH,
        "threshold": GOVERNANCE_THRESHOLD,
        "participant_count": GOVERNANCE_PARTICIPANTS,
        "signer_ids": [1, 2, 3, 4, 5, 6, 7],
        "governance_group_public_key_hex": hex::encode(&governance_public_key),
        "provisioning_package_cbor_hex": hex::encode(&package_cbor),
        "provisioning_package_blake3_hex": hex::encode(package_hash.as_bytes()),
        "node_policy_preimage_cbor_hex": hex::encode(&node_policy_preimage),
        "node_policy_blake3_hex": hex::encode(node_policy_hash.as_bytes()),
        "authorization_signing_preimage_cbor_hex": hex::encode(&authorization_preimage),
        "authorization_signature_hex": hex::encode(&signature),
        "authorization_artifact_cbor_hex": hex::encode(&authorization_artifact_cbor),
        "authorization_artifact_blake3_hex": hex::encode(Hash256::digest(&authorization_artifact_cbor).as_bytes()),
        "authorization_artifact_sha256_hex": hex::encode(Sha256::digest(&authorization_artifact_cbor)),
    });
    let locked: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tools/cross-impl-test/fixtures/crosschecked_anchor_authority_governance_v1.json"
    ))
    .expect("locked cross-implementation fixture JSON");
    assert_eq!(
        fixture, locked,
        "golden authority governance fixture drifted"
    );
    let verifying_key = frost::VerifyingKey::deserialize(&governance_public_key)
        .expect("fixture FROST group public key");
    let signature = frost::Signature::deserialize(&signature).expect("fixture FROST signature");
    verifying_key
        .verify(&authorization_preimage, &signature)
        .expect("fixture RFC 9591 FROST authorization verification");
}
