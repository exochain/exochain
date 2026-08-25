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

//! Owner-only, file-backed administration for the durable CrossChecked anchor registry.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use exo_authority::{AuthorityChain, AuthorityLink, DelegateeKind, Permission};
use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto::KeyPair};
use exo_identity::did::{DidDocument, VerificationMethod};
use exo_node::crosschecked_anchor_store::{
    AnchorNodeIdentity, AnchorStore, AnchorStoreConfig, AuthorityGovernanceAuthorizationV1,
    AuthorityLifecycleEventV1, AuthorityProvisioningV1, AuthorityRetirementV1,
    CrossCheckedScopeBindingV1, authority_chain_fingerprint,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{CrossCheckedAnchorAuthorityAdminArgs, CrossCheckedAnchorAuthorityCommand};

const OWNER_COMMAND_MAX_BYTES: u64 = 64 * 1024;
const SIGNER_SECRET_MAX_BYTES: u64 = 4 * 1024;
const GOVERNANCE_AUTHORIZATION_MAX_BYTES: u64 = 16 * 1024;
const PROTOCOL_VERSION: u16 = 1;
const PACKAGE_HASH_ALGORITHM: &str = "sha256";

#[derive(Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct IntermediateSigningMaterialV1 {
    protocol_version: u16,
    intermediate_did: String,
    intermediate_key_id: String,
    signing_secret_hex: String,
}

#[derive(Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct GovernanceAuthorizationInputV1 {
    protocol_version: u16,
    authorization_id_hex: String,
    ceremony_id_hex: String,
    governance_key_epoch: u64,
    threshold: u16,
    participant_count: u16,
    signer_ids: Vec<u16>,
    lifecycle_event: String,
    authority_did: String,
    authority_key_id: String,
    authority_key_epoch: u64,
    scope_alias_hex: String,
    package_hash_hex: String,
    node_policy_hash_hex: String,
    authorization_sequence: u64,
    prior_authorization_hash_hex: String,
    valid_from_ms: u64,
    valid_until_ms: u64,
    signature_algorithm: String,
    signature_hex: String,
}

#[derive(Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct ProvisionAuthorityCommandV1 {
    protocol_version: u16,
    expected_audience: String,
    intermediate_did: String,
    intermediate_key_id: String,
    intermediate_public_key_hex: String,
    node_did: String,
    node_key_id: String,
    node_public_key_hex: String,
    governance_group_public_key_hex: String,
    governance_key_epoch: u64,
    authority_did: String,
    authority_key_id: String,
    authority_public_key_hex: String,
    grant_id_hex: String,
    scope_alias_hex: String,
    key_epoch: u64,
    valid_from_ms: u64,
    valid_until_ms: u64,
}

#[derive(Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct RetireAuthorityCommandV1 {
    protocol_version: u16,
    expected_audience: String,
    intermediate_did: String,
    intermediate_key_id: String,
    intermediate_public_key_hex: String,
    node_did: String,
    node_key_id: String,
    node_public_key_hex: String,
    governance_group_public_key_hex: String,
    governance_key_epoch: u64,
    authority_did: String,
    authority_key_id: String,
    key_epoch: u64,
    retired_at_ms: u64,
}

struct OwnerStorePolicyRef<'a> {
    expected_audience: &'a str,
    intermediate_did: &'a str,
    intermediate_key_id: &'a str,
    intermediate_public_key_hex: &'a str,
    node_did: &'a str,
    node_key_id: &'a str,
    node_public_key_hex: &'a str,
    governance_group_public_key_hex: &'a str,
    governance_key_epoch: u64,
}

impl ProvisionAuthorityCommandV1 {
    fn store_policy(&self) -> OwnerStorePolicyRef<'_> {
        OwnerStorePolicyRef {
            expected_audience: &self.expected_audience,
            intermediate_did: &self.intermediate_did,
            intermediate_key_id: &self.intermediate_key_id,
            intermediate_public_key_hex: &self.intermediate_public_key_hex,
            node_did: &self.node_did,
            node_key_id: &self.node_key_id,
            node_public_key_hex: &self.node_public_key_hex,
            governance_group_public_key_hex: &self.governance_group_public_key_hex,
            governance_key_epoch: self.governance_key_epoch,
        }
    }
}

impl RetireAuthorityCommandV1 {
    fn store_policy(&self) -> OwnerStorePolicyRef<'_> {
        OwnerStorePolicyRef {
            expected_audience: &self.expected_audience,
            intermediate_did: &self.intermediate_did,
            intermediate_key_id: &self.intermediate_key_id,
            intermediate_public_key_hex: &self.intermediate_public_key_hex,
            node_did: &self.node_did,
            node_key_id: &self.node_key_id,
            node_public_key_hex: &self.node_public_key_hex,
            governance_group_public_key_hex: &self.governance_group_public_key_hex,
            governance_key_epoch: self.governance_key_epoch,
        }
    }
}

#[derive(Serialize)]
struct RedactedOwnerCommandOutput<'a> {
    protocol_version: u16,
    operation: &'a str,
    persistence_status: &'static str,
    package_sha256: String,
}

pub fn run(command: CrossCheckedAnchorAuthorityCommand) -> anyhow::Result<()> {
    match command {
        CrossCheckedAnchorAuthorityCommand::Provision(args) => provision(args),
        CrossCheckedAnchorAuthorityCommand::Retire(args) => {
            retire(args, AuthorityLifecycleEventV1::Retire)
        }
        CrossCheckedAnchorAuthorityCommand::Revoke(args) => {
            retire(args, AuthorityLifecycleEventV1::Revoke)
        }
    }
}

fn provision(args: CrossCheckedAnchorAuthorityAdminArgs) -> anyhow::Result<()> {
    ensure_distinct_inputs(&args)?;
    let command: ProvisionAuthorityCommandV1 = read_private_json(
        &args.command,
        OWNER_COMMAND_MAX_BYTES,
        "owner command input rejected",
    )?;
    let signing_material: IntermediateSigningMaterialV1 = read_private_json(
        &args.intermediate_secret_file,
        SIGNER_SECRET_MAX_BYTES,
        "intermediate signer input rejected",
    )?;
    let authorization: GovernanceAuthorizationInputV1 = read_private_json(
        &args.governance_authorization,
        GOVERNANCE_AUTHORIZATION_MAX_BYTES,
        "governance authorization input rejected",
    )?;
    require_protocol(command.protocol_version)?;
    let intermediate_key = intermediate_key(&signing_material)?;
    let store_config = store_config(command.store_policy(), &signing_material, &intermediate_key)?;
    let provisioning = signed_provisioning(&command, &signing_material, &intermediate_key)?;
    let authorization = governance_authorization(authorization)?;
    let package_bytes = Zeroizing::new(
        provisioning
            .to_cbor_bytes()
            .map_err(|_| anyhow::anyhow!("signed provisioning package encoding failed"))?,
    );

    let records_path = records_path(&args.data_dir, true)?;
    let store = AnchorStore::open(&records_path, store_config)
        .map_err(|_| anyhow::anyhow!("durable authority registry rejected store policy"))?;
    store
        .provision_authority(&provisioning, &authorization, current_time_ms()?)
        .map_err(|_| anyhow::anyhow!("signed authority provisioning rejected"))?;
    restrict_registry_file(&records_path)?;
    write_optional_package(args.signed_package_out.as_deref(), &package_bytes)?;
    write_redacted_summary("provision", &package_bytes)
}

fn retire(
    args: CrossCheckedAnchorAuthorityAdminArgs,
    lifecycle_event: AuthorityLifecycleEventV1,
) -> anyhow::Result<()> {
    ensure_distinct_inputs(&args)?;
    let command: RetireAuthorityCommandV1 = read_private_json(
        &args.command,
        OWNER_COMMAND_MAX_BYTES,
        "owner command input rejected",
    )?;
    let signing_material: IntermediateSigningMaterialV1 = read_private_json(
        &args.intermediate_secret_file,
        SIGNER_SECRET_MAX_BYTES,
        "intermediate signer input rejected",
    )?;
    let authorization: GovernanceAuthorizationInputV1 = read_private_json(
        &args.governance_authorization,
        GOVERNANCE_AUTHORIZATION_MAX_BYTES,
        "governance authorization input rejected",
    )?;
    require_protocol(command.protocol_version)?;
    let intermediate_key = intermediate_key(&signing_material)?;
    let store_config = store_config(command.store_policy(), &signing_material, &intermediate_key)?;
    let retirement = signed_retirement(&command, &signing_material, &intermediate_key)?;
    let authorization = governance_authorization(authorization)?;
    let package_bytes = Zeroizing::new(
        retirement
            .to_cbor_bytes()
            .map_err(|_| anyhow::anyhow!("signed retirement package encoding failed"))?,
    );

    let records_path = records_path(&args.data_dir, true)?;
    let store = AnchorStore::open(&records_path, store_config)
        .map_err(|_| anyhow::anyhow!("durable authority registry rejected store policy"))?;
    match lifecycle_event {
        AuthorityLifecycleEventV1::Retire => {
            store.retire_authority(&retirement, &authorization, current_time_ms()?)
        }
        AuthorityLifecycleEventV1::Revoke => {
            store.revoke_authority(&retirement, &authorization, current_time_ms()?)
        }
        AuthorityLifecycleEventV1::Provision => {
            anyhow::bail!("governance lifecycle event rejected")
        }
    }
    .map_err(|_| anyhow::anyhow!("signed authority retirement rejected"))?;
    restrict_registry_file(&records_path)?;
    write_optional_package(args.signed_package_out.as_deref(), &package_bytes)?;
    write_redacted_summary(lifecycle_event.code(), &package_bytes)
}

fn current_time_ms() -> anyhow::Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("trusted owner-command clock unavailable"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| anyhow::anyhow!("trusted owner-command clock unavailable"))
}

fn require_protocol(protocol_version: u16) -> anyhow::Result<()> {
    if protocol_version != PROTOCOL_VERSION {
        anyhow::bail!("owner command protocol version rejected");
    }
    Ok(())
}

fn governance_authorization(
    authorization: GovernanceAuthorizationInputV1,
) -> anyhow::Result<AuthorityGovernanceAuthorizationV1> {
    require_protocol(authorization.protocol_version)?;
    let lifecycle_event = match authorization.lifecycle_event.as_str() {
        "provision" => AuthorityLifecycleEventV1::Provision,
        "retire" => AuthorityLifecycleEventV1::Retire,
        "revoke" => AuthorityLifecycleEventV1::Revoke,
        _ => anyhow::bail!("governance authorization input rejected"),
    };
    Ok(AuthorityGovernanceAuthorizationV1 {
        protocol_version: authorization.protocol_version,
        authorization_id: decode_lower_hex(
            &authorization.authorization_id_hex,
            "governance authorization input rejected",
        )?,
        ceremony_id: decode_lower_hex(
            &authorization.ceremony_id_hex,
            "governance authorization input rejected",
        )?,
        governance_key_epoch: authorization.governance_key_epoch,
        threshold: authorization.threshold,
        participant_count: authorization.participant_count,
        signer_ids: authorization.signer_ids.clone(),
        lifecycle_event,
        authority_did: parse_did(&authorization.authority_did)?,
        authority_key_id: authorization.authority_key_id.clone(),
        authority_key_epoch: authorization.authority_key_epoch,
        scope_alias: decode_lower_hex(
            &authorization.scope_alias_hex,
            "governance authorization input rejected",
        )?,
        package_hash: Hash256::from_bytes(decode_lower_hex(
            &authorization.package_hash_hex,
            "governance authorization input rejected",
        )?),
        node_policy_hash: Hash256::from_bytes(decode_lower_hex(
            &authorization.node_policy_hash_hex,
            "governance authorization input rejected",
        )?),
        authorization_sequence: authorization.authorization_sequence,
        prior_authorization_hash: Hash256::from_bytes(decode_lower_hex(
            &authorization.prior_authorization_hash_hex,
            "governance authorization input rejected",
        )?),
        valid_from_ms: authorization.valid_from_ms,
        valid_until_ms: authorization.valid_until_ms,
        signature_algorithm: authorization.signature_algorithm.clone(),
        signature: decode_lower_hex::<64>(
            &authorization.signature_hex,
            "governance authorization input rejected",
        )?
        .to_vec(),
    })
}

fn intermediate_key(material: &IntermediateSigningMaterialV1) -> anyhow::Result<KeyPair> {
    require_protocol(material.protocol_version)?;
    let secret = decode_secret_hex(&material.signing_secret_hex)?;
    KeyPair::from_secret_bytes(*secret)
        .map_err(|_| anyhow::anyhow!("intermediate signing key rejected"))
}

fn store_config(
    policy: OwnerStorePolicyRef<'_>,
    signing_material: &IntermediateSigningMaterialV1,
    intermediate_key: &KeyPair,
) -> anyhow::Result<AnchorStoreConfig> {
    let configured_intermediate_public_key =
        PublicKey::from_bytes(decode_public_hex(policy.intermediate_public_key_hex)?);
    if policy.intermediate_did != signing_material.intermediate_did
        || policy.intermediate_key_id != signing_material.intermediate_key_id
        || configured_intermediate_public_key != *intermediate_key.public_key()
    {
        anyhow::bail!("intermediate signing material does not match pinned owner command policy");
    }
    Ok(AnchorStoreConfig {
        expected_audience: policy.expected_audience.to_owned(),
        crosschecked_intermediate_did: policy.intermediate_did.to_owned(),
        crosschecked_intermediate_key_id: policy.intermediate_key_id.to_owned(),
        crosschecked_intermediate_public_key: configured_intermediate_public_key,
        governance_frost_group_public_key: decode_public_hex(
            policy.governance_group_public_key_hex,
        )?,
        governance_frost_key_epoch: policy.governance_key_epoch,
        node_identity: AnchorNodeIdentity {
            did: policy.node_did.to_owned(),
            key_id: policy.node_key_id.to_owned(),
            public_key: PublicKey::from_bytes(decode_public_hex(policy.node_public_key_hex)?),
        },
    })
}

fn signed_provisioning(
    command: &ProvisionAuthorityCommandV1,
    signing_material: &IntermediateSigningMaterialV1,
    intermediate_key: &KeyPair,
) -> anyhow::Result<AuthorityProvisioningV1> {
    let intermediate_did = parse_did(&signing_material.intermediate_did)?;
    let authority_did = parse_did(&command.authority_did)?;
    let authority_public_key =
        PublicKey::from_bytes(decode_public_hex(&command.authority_public_key_hex)?);
    let mut link = AuthorityLink {
        delegator_did: intermediate_did.clone(),
        delegate_did: authority_did.clone(),
        scope: vec![Permission::AnchorReceiptCommitment],
        created: Timestamp::new(command.valid_from_ms, 0),
        expires: Some(Timestamp::new(command.valid_until_ms, 0)),
        signature: Signature::empty(),
        depth: 0,
        delegatee_kind: DelegateeKind::Unknown,
    };
    link.signature = intermediate_key.sign(
        &link
            .signing_payload()
            .map_err(|_| anyhow::anyhow!("authority delegation payload rejected"))?,
    );
    let chain = AuthorityChain {
        links: vec![link],
        max_depth: 5,
    };
    let mut binding = CrossCheckedScopeBindingV1 {
        protocol_version: PROTOCOL_VERSION,
        authority_did: authority_did.clone(),
        authority_key_id: command.authority_key_id.clone(),
        grant_id: decode_public_hex(&command.grant_id_hex)?,
        scope_alias: decode_public_hex(&command.scope_alias_hex)?,
        audience: command.expected_audience.clone(),
        permission: Permission::AnchorReceiptCommitment,
        key_epoch: command.key_epoch,
        valid_from_ms: command.valid_from_ms,
        valid_until_ms: command.valid_until_ms,
        chain_fingerprint: authority_chain_fingerprint(&chain)
            .map_err(|_| anyhow::anyhow!("authority chain fingerprint failed"))?,
        binding_signer_did: intermediate_did.clone(),
        binding_signer_key_id: signing_material.intermediate_key_id.clone(),
        signature: Signature::empty(),
    };
    binding.signature = intermediate_key.sign(
        &binding
            .signing_preimage()
            .map_err(|_| anyhow::anyhow!("scope binding payload rejected"))?,
    );

    Ok(AuthorityProvisioningV1 {
        protocol_version: PROTOCOL_VERSION,
        did_documents: vec![
            did_document(
                intermediate_did,
                &signing_material.intermediate_key_id,
                *intermediate_key.public_key(),
                1,
                0,
            ),
            did_document(
                authority_did,
                &command.authority_key_id,
                authority_public_key,
                command.key_epoch,
                command.valid_from_ms,
            ),
        ],
        authority_chain: chain,
        scope_binding: binding,
    })
}

fn signed_retirement(
    command: &RetireAuthorityCommandV1,
    signing_material: &IntermediateSigningMaterialV1,
    intermediate_key: &KeyPair,
) -> anyhow::Result<AuthorityRetirementV1> {
    let mut retirement = AuthorityRetirementV1 {
        protocol_version: PROTOCOL_VERSION,
        authority_did: parse_did(&command.authority_did)?,
        authority_key_id: command.authority_key_id.clone(),
        key_epoch: command.key_epoch,
        retired_at_ms: command.retired_at_ms,
        signer_did: parse_did(&signing_material.intermediate_did)?,
        signer_key_id: signing_material.intermediate_key_id.clone(),
        signature: Signature::empty(),
    };
    retirement.signature = intermediate_key.sign(
        &retirement
            .signing_preimage()
            .map_err(|_| anyhow::anyhow!("retirement signing payload rejected"))?,
    );
    Ok(retirement)
}

fn did_document(
    did: Did,
    key_id: &str,
    public_key: PublicKey,
    version: u64,
    valid_from_ms: u64,
) -> DidDocument {
    DidDocument {
        id: did.clone(),
        public_keys: vec![public_key],
        authentication: vec![],
        verification_methods: vec![VerificationMethod {
            id: key_id.to_owned(),
            key_type: "Ed25519VerificationKey2020".to_owned(),
            controller: did,
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

fn parse_did(value: &str) -> anyhow::Result<Did> {
    Did::new(value).map_err(|_| anyhow::anyhow!("owner command DID rejected"))
}

fn decode_public_hex(value: &str) -> anyhow::Result<[u8; 32]> {
    decode_lower_hex(value, "owner command 32-byte lowercase hex field rejected")
}

fn decode_lower_hex<const N: usize>(
    value: &str,
    error_message: &'static str,
) -> anyhow::Result<[u8; N]> {
    if value.len() != N.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!(error_message);
    }
    let bytes = hex::decode(value).map_err(|_| anyhow::anyhow!(error_message))?;
    bytes.try_into().map_err(|_| anyhow::anyhow!(error_message))
}

fn decode_secret_hex(value: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!("intermediate signing secret rejected");
    }
    let decoded = Zeroizing::new(
        hex::decode(value).map_err(|_| anyhow::anyhow!("intermediate signing secret rejected"))?,
    );
    if decoded.len() != 32 {
        anyhow::bail!("intermediate signing secret rejected");
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(decoded.as_slice());
    Ok(secret)
}

fn ensure_distinct_inputs(args: &CrossCheckedAnchorAuthorityAdminArgs) -> anyhow::Result<()> {
    if args.command == args.intermediate_secret_file
        || args.command == args.governance_authorization
        || args.intermediate_secret_file == args.governance_authorization
        || args.signed_package_out.as_ref().is_some_and(|output| {
            output == &args.command
                || output == &args.intermediate_secret_file
                || output == &args.governance_authorization
        })
    {
        anyhow::bail!("owner command input and output paths must be distinct");
    }
    Ok(())
}

fn read_private_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
    error_message: &'static str,
) -> anyhow::Result<T> {
    let bytes = read_owner_only_file(path, max_bytes, error_message)?;
    serde_json::from_slice(bytes.as_slice()).map_err(|_| anyhow::anyhow!(error_message))
}

#[cfg(unix)]
fn read_owner_only_file(
    path: &Path,
    max_bytes: u64,
    error_message: &'static str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::MetadataExt;

    let before = fs::symlink_metadata(path).map_err(|_| anyhow::anyhow!(error_message))?;
    let mode = before.mode() & 0o777;
    if before.file_type().is_symlink()
        || !before.is_file()
        || !matches!(mode, 0o400 | 0o600)
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > max_bytes
    {
        anyhow::bail!(error_message);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| anyhow::anyhow!(error_message))?;
    let opened = file
        .metadata()
        .map_err(|_| anyhow::anyhow!(error_message))?;
    if opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.mode() != before.mode()
        || opened.len() != before.len()
        || opened.nlink() != 1
        || !opened.is_file()
    {
        anyhow::bail!(error_message);
    }
    let capacity = usize::try_from(before.len()).map_err(|_| anyhow::anyhow!(error_message))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    let mut bounded_file = file.take(max_bytes + 1);
    bounded_file
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!(error_message))?;
    let after = bounded_file
        .get_ref()
        .metadata()
        .map_err(|_| anyhow::anyhow!(error_message))?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| anyhow::anyhow!(error_message))?;
    if bytes.is_empty()
        || bytes_len != before.len()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.mode() != before.mode()
        || after.len() != before.len()
        || after.nlink() != 1
    {
        anyhow::bail!(error_message);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_owner_only_file(
    _path: &Path,
    _max_bytes: u64,
    error_message: &'static str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    Err(anyhow::anyhow!(
        "{error_message}: owner-only permission verification unavailable"
    ))
}

fn records_path(data_dir: &Path, must_exist: bool) -> anyhow::Result<PathBuf> {
    let data_metadata = fs::symlink_metadata(data_dir)
        .map_err(|_| anyhow::anyhow!("node data directory rejected"))?;
    if data_metadata.file_type().is_symlink() || !data_metadata.is_dir() {
        anyhow::bail!("node data directory rejected");
    }
    let registry_dir = data_dir.join("crosschecked_anchor");
    if registry_dir.exists() {
        let metadata = fs::symlink_metadata(&registry_dir)
            .map_err(|_| anyhow::anyhow!("authority registry directory rejected"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("authority registry directory rejected");
        }
        restrict_directory(&registry_dir)?;
    } else if must_exist {
        anyhow::bail!("durable authority registry is unavailable");
    } else {
        create_private_directory(&registry_dir)?;
    }
    let records_path = registry_dir.join("records.sqlite3");
    if must_exist && !records_path.exists() {
        anyhow::bail!("durable authority registry is unavailable");
    }
    if records_path.exists() {
        let metadata = fs::symlink_metadata(&records_path)
            .map_err(|_| anyhow::anyhow!("durable authority registry file rejected"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!("durable authority registry file rejected");
        }
    }
    Ok(records_path)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|_| anyhow::anyhow!("authority registry directory creation failed"))?;
    restrict_directory(path)
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("authority registry directory permission enforcement unavailable")
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| anyhow::anyhow!("authority registry directory permission update failed"))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("authority registry directory permission enforcement unavailable")
}

#[cfg(unix)]
fn restrict_registry_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("durable authority registry file rejected"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("durable authority registry file rejected");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| anyhow::anyhow!("durable authority registry permission update failed"))
}

#[cfg(not(unix))]
fn restrict_registry_file(_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("durable authority registry permission enforcement unavailable")
}

fn write_optional_package(path: Option<&Path>, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(path) = path {
        write_private_create_new(path, bytes)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_create_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| anyhow::anyhow!("signed package output creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| anyhow::anyhow!("signed package output permission update failed"))?;
    file.write_all(bytes)
        .map_err(|_| anyhow::anyhow!("signed package output write failed"))?;
    file.sync_all()
        .map_err(|_| anyhow::anyhow!("signed package output sync failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| anyhow::anyhow!("signed package output permission update failed"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_create_new(_path: &Path, _bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("signed package output permission enforcement unavailable")
}

fn write_redacted_summary(operation: &str, package_bytes: &[u8]) -> anyhow::Result<()> {
    let package_hash = Sha256::digest(package_bytes);
    let output = RedactedOwnerCommandOutput {
        protocol_version: PROTOCOL_VERSION,
        operation,
        persistence_status: "committed_or_exact_replay",
        package_sha256: format!("{PACKAGE_HASH_ALGORITHM}:{}", hex::encode(package_hash)),
    };
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    serde_json::to_writer(&mut locked, &output)
        .map_err(|_| anyhow::anyhow!("redacted owner output serialization failed"))?;
    locked
        .write_all(b"\n")
        .map_err(|_| anyhow::anyhow!("redacted owner output write failed"))
}
