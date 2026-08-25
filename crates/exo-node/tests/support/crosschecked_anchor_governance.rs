// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, dead_code)]

use std::{collections::BTreeMap, sync::LazyLock};

use exo_core::{Did, Hash256};
use exo_node::crosschecked_anchor_store::{
    AnchorStoreConfig, AuthorityGovernanceAuthorizationV1, AuthorityLifecycleEventV1,
    AuthorityProvisioningV1, AuthorityRetirementV1, CROSSCHECKED_GOVERNANCE_PARTICIPANTS,
    CROSSCHECKED_GOVERNANCE_THRESHOLD, anchor_node_policy_hash,
};
use frost_ed25519 as frost;
use rand::{SeedableRng, rngs::StdRng};

pub const GOVERNANCE_KEY_EPOCH: u64 = 7;
pub const GOVERNANCE_SIGNATURE_ALGORITHM: &str = "frost-ed25519-sha512-rfc9591";

pub struct GovernanceTestKeys {
    key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: frost::keys::PublicKeyPackage,
}

static GOVERNANCE_KEYS: LazyLock<GovernanceTestKeys> =
    LazyLock::new(|| frost_test_keys(0x4558_4f43_4841_494e));

pub fn governance_group_public_key() -> [u8; 32] {
    GOVERNANCE_KEYS
        .public_key_package
        .verifying_key()
        .serialize()
        .expect("FROST group public key")
        .try_into()
        .expect("32-byte FROST group public key")
}

pub fn governance_group_public_key_for_seed(seed: u64) -> [u8; 32] {
    frost_test_keys(seed)
        .public_key_package
        .verifying_key()
        .serialize()
        .expect("alternate FROST group public key")
        .try_into()
        .expect("32-byte alternate FROST group public key")
}

pub fn configure_governance(config: &mut AnchorStoreConfig) {
    config.governance_frost_group_public_key = governance_group_public_key();
    config.governance_frost_key_epoch = GOVERNANCE_KEY_EPOCH;
}

pub fn provisioning_authorization(
    config: &AnchorStoreConfig,
    provisioning: &AuthorityProvisioningV1,
    sequence: u64,
    prior_authorization_hash: Hash256,
    authorization_id_byte: u8,
    signing_seed: u64,
) -> AuthorityGovernanceAuthorizationV1 {
    let binding = &provisioning.scope_binding;
    signed_authorization(
        config,
        AuthorityLifecycleEventV1::Provision,
        binding.authority_did.clone(),
        binding.authority_key_id.clone(),
        binding.key_epoch,
        binding.scope_alias,
        Hash256::digest(&provisioning.to_cbor_bytes().expect("provisioning CBOR")),
        sequence,
        prior_authorization_hash,
        binding.valid_from_ms,
        authorization_id_byte,
        signing_seed,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn retirement_authorization(
    config: &AnchorStoreConfig,
    retirement: &AuthorityRetirementV1,
    scope_alias: [u8; 32],
    lifecycle_event: AuthorityLifecycleEventV1,
    sequence: u64,
    prior_authorization_hash: Hash256,
    authorization_id_byte: u8,
    signing_seed: u64,
) -> AuthorityGovernanceAuthorizationV1 {
    signed_authorization(
        config,
        lifecycle_event,
        retirement.authority_did.clone(),
        retirement.authority_key_id.clone(),
        retirement.key_epoch,
        scope_alias,
        Hash256::digest(&retirement.to_cbor_bytes().expect("retirement CBOR")),
        sequence,
        prior_authorization_hash,
        retirement.retired_at_ms,
        authorization_id_byte,
        signing_seed,
    )
}

pub fn resign_authorization(
    authorization: &mut AuthorityGovernanceAuthorizationV1,
    signing_seed: u64,
) {
    authorization.signature = frost_sign(
        &GOVERNANCE_KEYS,
        &authorization
            .signing_preimage()
            .expect("governance signing preimage"),
        &authorization.signer_ids,
        signing_seed,
    );
}

#[allow(clippy::too_many_arguments)]
fn signed_authorization(
    config: &AnchorStoreConfig,
    lifecycle_event: AuthorityLifecycleEventV1,
    authority_did: Did,
    authority_key_id: String,
    authority_key_epoch: u64,
    scope_alias: [u8; 32],
    package_hash: Hash256,
    authorization_sequence: u64,
    prior_authorization_hash: Hash256,
    effective_at_ms: u64,
    authorization_id_byte: u8,
    signing_seed: u64,
) -> AuthorityGovernanceAuthorizationV1 {
    let signer_ids: Vec<u16> = (1..=CROSSCHECKED_GOVERNANCE_THRESHOLD).collect();
    let mut authorization = AuthorityGovernanceAuthorizationV1 {
        protocol_version: 1,
        authorization_id: [authorization_id_byte; 32],
        ceremony_id: [authorization_id_byte.wrapping_add(0x40); 32],
        governance_key_epoch: config.governance_frost_key_epoch,
        threshold: CROSSCHECKED_GOVERNANCE_THRESHOLD,
        participant_count: CROSSCHECKED_GOVERNANCE_PARTICIPANTS,
        signer_ids,
        lifecycle_event,
        authority_did,
        authority_key_id,
        authority_key_epoch,
        scope_alias,
        package_hash,
        node_policy_hash: anchor_node_policy_hash(config).expect("node policy hash"),
        authorization_sequence,
        prior_authorization_hash,
        valid_from_ms: effective_at_ms.saturating_sub(1_000),
        valid_until_ms: effective_at_ms.saturating_add(300_000),
        signature_algorithm: GOVERNANCE_SIGNATURE_ALGORITHM.to_owned(),
        signature: Vec::new(),
    };
    authorization.signature = frost_sign(
        &GOVERNANCE_KEYS,
        &authorization
            .signing_preimage()
            .expect("governance signing preimage"),
        &authorization.signer_ids,
        signing_seed,
    );
    authorization
}

fn frost_test_keys(seed: u64) -> GovernanceTestKeys {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut round1_secrets = BTreeMap::new();
    let mut round1_public = BTreeMap::new();
    for value in 1..=CROSSCHECKED_GOVERNANCE_PARTICIPANTS {
        let identifier = frost::Identifier::try_from(value).expect("FROST identifier");
        let (secret, package) = frost::keys::dkg::part1(
            identifier,
            CROSSCHECKED_GOVERNANCE_PARTICIPANTS,
            CROSSCHECKED_GOVERNANCE_THRESHOLD,
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

fn frost_sign(keys: &GovernanceTestKeys, message: &[u8], signer_ids: &[u16], seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let selected: BTreeMap<_, _> = signer_ids
        .iter()
        .map(|value| {
            let identifier = frost::Identifier::try_from(*value).expect("FROST identifier");
            (identifier, keys.key_packages[&identifier].clone())
        })
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
