#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use exo_authority::permission::Permission;
use exo_core::{Did, Hash256, PublicKey, SecretKey, Signature, Timestamp, crypto::KeyPair};
use exo_root::{
    CeremonyEnvelope, CeremonyEnvelopeDraft, CeremonyPayloadKind, CeremonyPhase, CertifierContact,
    GenesisCeremonyConfig, PairwiseEncryptedPayload, PortalStore, RootDkgOutput,
    RootIssuerDelegation, RootParticipantDkgOutput, SealedShare, assemble_root_bundle,
    build_final_key_confirmation, build_signing_package, decrypt_pairwise_payload,
    dkg_finalize_participant, dkg_round1, dkg_round2, encode_final_key_confirmation_payload,
    encrypt_pairwise_payload, run_complete_dkg, seal_share, sign_commit, sign_share,
    threshold_sign, unseal_share, verify_root_bundle, verify_root_signature,
};
use rand::{SeedableRng, rngs::StdRng};
use zeroize::Zeroizing;

fn did(index: u16) -> Did {
    Did::new(&format!("did:exo:certifier-{index:02}")).expect("valid did")
}

fn keypair(index: u8) -> KeyPair {
    KeyPair::from_secret_bytes([index; 32]).expect("valid keypair")
}

fn certifier(index: u16) -> (CertifierContact, SecretKey, [u8; 32]) {
    let kp = keypair(u8::try_from(index).expect("index fits u8"));
    let did = did(index);
    let transport_secret = [u8::try_from(index).expect("index fits u8"); 32];
    let transport_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(transport_secret));
    (
        CertifierContact {
            did,
            frost_identifier: index,
            signing_public_key: *kp.public_key(),
            transport_public_key: *transport_public.as_bytes(),
        },
        kp.secret_key().clone(),
        transport_secret,
    )
}

fn envelope_draft(
    ceremony_id: impl Into<String>,
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    sender_did: Did,
    recipient_did: Option<Did>,
    sequence: u64,
    payload_bytes: Vec<u8>,
) -> CeremonyEnvelopeDraft {
    CeremonyEnvelopeDraft {
        ceremony_id: ceremony_id.into(),
        phase,
        payload_kind,
        sender_did,
        recipient_did,
        sequence,
        payload_bytes,
    }
}

fn encrypted_payload_bytes(ciphertext: impl Into<Vec<u8>>) -> Vec<u8> {
    let payload = PairwiseEncryptedPayload {
        nonce: [7u8; 24],
        ciphertext: ciphertext.into(),
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&payload, &mut bytes).expect("encrypted payload encoding");
    bytes
}

#[allow(clippy::too_many_arguments)]
fn sign_envelope(
    config: &GenesisCeremonyConfig,
    signing_secrets: &BTreeMap<Did, SecretKey>,
    sender_identifier: u16,
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    recipient_identifier: Option<u16>,
    sequence: u64,
    payload_bytes: Vec<u8>,
) -> CeremonyEnvelope {
    let sender = config
        .certifier_by_identifier(sender_identifier)
        .expect("sender");
    let recipient = recipient_identifier.map(|identifier| {
        config
            .certifier_by_identifier(identifier)
            .expect("recipient")
            .did
            .clone()
    });
    let signing_secret = signing_secrets.get(&sender.did).expect("secret");
    CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            phase,
            payload_kind,
            sender.did.clone(),
            recipient,
            sequence,
            payload_bytes,
        ),
        signing_secret,
    )
    .expect("signed envelope")
}

fn submit_complete_dkg_transcript(
    store: &mut PortalStore,
    config: &GenesisCeremonyConfig,
    signing_secrets: &BTreeMap<Did, SecretKey>,
    rng: &mut StdRng,
) -> Hash256 {
    for certifier in &config.certifiers {
        let round1 = dkg_round1(config, certifier.frost_identifier, rng)
            .expect("round one")
            .round1_package;
        store
            .submit(sign_envelope(
                config,
                signing_secrets,
                certifier.frost_identifier,
                CeremonyPhase::Round1,
                CeremonyPayloadKind::Round1Package,
                None,
                10,
                round1,
            ))
            .expect("submit round one");
    }
    for sender in &config.certifiers {
        for recipient in &config.certifiers {
            if sender.frost_identifier == recipient.frost_identifier {
                continue;
            }
            let sequence = 1_000
                + u64::from(sender.frost_identifier) * 100
                + u64::from(recipient.frost_identifier);
            store
                .submit(sign_envelope(
                    config,
                    signing_secrets,
                    sender.frost_identifier,
                    CeremonyPhase::Round2,
                    CeremonyPayloadKind::Round2EncryptedPackage,
                    Some(recipient.frost_identifier),
                    sequence,
                    encrypted_payload_bytes(format!(
                        "round2-{}-{}",
                        sender.frost_identifier, recipient.frost_identifier
                    )),
                ))
                .expect("submit round two");
        }
    }
    store.dkg_transcript_hash().expect("dkg transcript hash")
}

fn take_key_packages(
    dkg: &mut RootDkgOutput,
    count: usize,
) -> BTreeMap<u16, exo_root::RootKeyPackage> {
    let identifiers: Vec<u16> = dkg.key_packages.keys().take(count).copied().collect();
    identifiers
        .into_iter()
        .map(|identifier| {
            let package = dkg
                .key_packages
                .remove(&identifier)
                .expect("selected key package");
            (identifier, package)
        })
        .collect()
}

fn participant_output(dkg: &mut RootDkgOutput, identifier: u16) -> RootParticipantDkgOutput {
    RootParticipantDkgOutput {
        key_package: dkg
            .key_packages
            .remove(&identifier)
            .expect("participant key package"),
        public_key_package: dkg.public_key_package.clone(),
    }
}

fn final_key_confirmation_payload(
    config: &GenesisCeremonyConfig,
    dkg: &mut RootDkgOutput,
    identifier: u16,
    dkg_transcript_hash: Hash256,
) -> Vec<u8> {
    let confirmation = build_final_key_confirmation(
        config,
        &participant_output(dkg, identifier),
        dkg_transcript_hash,
    )
    .expect("final key confirmation");
    encode_final_key_confirmation_payload(&confirmation).expect("confirmation payload")
}

fn submit_final_key_confirmations(
    store: &mut PortalStore,
    config: &GenesisCeremonyConfig,
    signing_secrets: &BTreeMap<Did, SecretKey>,
    dkg: &mut RootDkgOutput,
    dkg_transcript_hash: Hash256,
    count: u16,
) {
    for identifier in 1..=count {
        submit_final_key_confirmation(
            store,
            config,
            signing_secrets,
            dkg,
            dkg_transcript_hash,
            identifier,
        );
    }
}

fn submit_final_key_confirmation(
    store: &mut PortalStore,
    config: &GenesisCeremonyConfig,
    signing_secrets: &BTreeMap<Did, SecretKey>,
    dkg: &mut RootDkgOutput,
    dkg_transcript_hash: Hash256,
    identifier: u16,
) {
    store
        .submit(sign_envelope(
            config,
            signing_secrets,
            identifier,
            CeremonyPhase::Finalize,
            CeremonyPayloadKind::FinalKeyConfirmation,
            None,
            5_000 + u64::from(identifier),
            final_key_confirmation_payload(config, dkg, identifier, dkg_transcript_hash),
        ))
        .expect("submit final key confirmation");
}

fn config() -> (
    GenesisCeremonyConfig,
    BTreeMap<Did, SecretKey>,
    BTreeMap<Did, [u8; 32]>,
) {
    let mut certifiers = Vec::new();
    let mut signing_secrets = BTreeMap::new();
    let mut transport_secrets = BTreeMap::new();
    for index in 1..=13 {
        let (contact, signing_secret, transport_secret) = certifier(index);
        signing_secrets.insert(contact.did.clone(), signing_secret);
        transport_secrets.insert(contact.did.clone(), transport_secret);
        certifiers.push(contact);
    }
    (
        GenesisCeremonyConfig {
            ceremony_id: "exo-root-genesis-2026".into(),
            network_id: "exochain-main".into(),
            repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".into(),
            constitution_hash: Hash256::digest(b"constitution"),
            threshold: 7,
            max_signers: 13,
            created_at: Timestamp::new(1_785_000_000_000, 0),
            certifiers,
            signing_set: (1..=7).collect(),
        },
        signing_secrets,
        transport_secrets,
    )
}

#[test]
fn ceremony_config_requires_institutional_7_of_13_roster() {
    let (config, _, _) = config();
    config.validate().expect("7 of 13 roster should validate");
    assert_eq!(config.threshold, 7);
    assert_eq!(config.max_signers, 13);
    assert_eq!(config.certifiers.len(), 13);

    let mut too_small = config.clone();
    too_small.threshold = 6;
    assert!(too_small.validate().is_err());

    let mut too_few = config;
    too_few.certifiers.pop();
    assert!(too_few.validate().is_err());
}

#[test]
fn ceremony_config_rejects_all_roster_policy_malformed_inputs() {
    let (config, _, _) = config();

    let mut bad_max = config.clone();
    bad_max.max_signers = 12;
    assert!(bad_max.validate().is_err());

    let mut empty_ceremony = config.clone();
    empty_ceremony.ceremony_id = " ".into();
    assert!(empty_ceremony.validate().is_err());

    let mut empty_network = config.clone();
    empty_network.network_id = " ".into();
    assert!(empty_network.validate().is_err());

    let mut bad_commit = config.clone();
    bad_commit.repo_commit = "not-a-commit".into();
    assert!(bad_commit.validate().is_err());

    let mut bad_identifier = config.clone();
    bad_identifier.certifiers[0].frost_identifier = 0;
    assert!(bad_identifier.validate().is_err());

    let mut duplicate_did = config.clone();
    duplicate_did.certifiers[1].did = duplicate_did.certifiers[0].did.clone();
    assert!(duplicate_did.validate().is_err());

    let mut duplicate_identifier = config.clone();
    duplicate_identifier.certifiers[1].frost_identifier =
        duplicate_identifier.certifiers[0].frost_identifier;
    assert!(duplicate_identifier.validate().is_err());

    let mut duplicate_signing_key = config.clone();
    duplicate_signing_key.certifiers[1].signing_public_key =
        duplicate_signing_key.certifiers[0].signing_public_key;
    assert!(duplicate_signing_key.validate().is_err());

    let mut duplicate_transport_key = config;
    duplicate_transport_key.certifiers[1].transport_public_key =
        duplicate_transport_key.certifiers[0].transport_public_key;
    assert!(duplicate_transport_key.validate().is_err());
}

#[test]
fn frost_dkg_signs_with_7_of_13_and_rejects_6_of_13() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(42);
    let mut dkg = run_complete_dkg(&config, &mut rng).expect("dkg");

    let selected = take_key_packages(&mut dkg, 7);
    let message = b"exo root artifact";
    let signature = threshold_sign(
        &config,
        &dkg.public_key_package,
        selected,
        message,
        &mut rng,
    )
    .expect("7 signer signature");
    verify_root_signature(
        &dkg.public_key_package.root_public_key,
        message,
        &signature.signature,
    )
    .expect("root signature verifies");
    assert!(
        verify_root_signature(
            &dkg.public_key_package.root_public_key,
            b"different root artifact",
            &signature.signature,
        )
        .is_err(),
        "a well-formed root signature must bind exactly to its artifact bytes"
    );

    let mut too_few_rng = StdRng::seed_from_u64(42);
    let mut too_few_dkg = run_complete_dkg(&config, &mut too_few_rng).expect("second dkg");
    let too_few = take_key_packages(&mut too_few_dkg, 6);
    assert!(
        threshold_sign(&config, &dkg.public_key_package, too_few, message, &mut rng).is_err(),
        "6 signers must not satisfy a 7-of-13 root threshold"
    );
}

#[test]
fn threshold_signing_rejects_malformed_public_key_package_and_signer_set() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(43);
    let mut dkg = run_complete_dkg(&config, &mut rng).expect("dkg");

    let mut malformed_public = dkg.public_key_package.clone();
    malformed_public.public_key_package = b"not a public package".to_vec();
    let malformed_public_shares = take_key_packages(&mut dkg, 7);
    assert!(
        threshold_sign(
            &config,
            &malformed_public,
            malformed_public_shares,
            b"artifact",
            &mut rng
        )
        .is_err()
    );

    let mut nonrostered_rng = StdRng::seed_from_u64(43);
    let mut nonrostered_dkg =
        run_complete_dkg(&config, &mut nonrostered_rng).expect("nonrostered dkg");
    let mut nonrostered = take_key_packages(&mut nonrostered_dkg, 7);
    let replacement = nonrostered.remove(&1).expect("share");
    nonrostered.insert(99, replacement);
    assert!(
        threshold_sign(
            &config,
            &dkg.public_key_package,
            nonrostered,
            b"artifact",
            &mut rng
        )
        .is_err()
    );

    let mut mismatched_rng = StdRng::seed_from_u64(43);
    let mut mismatched_dkg =
        run_complete_dkg(&config, &mut mismatched_rng).expect("mismatched dkg");
    let mut mismatched = take_key_packages(&mut mismatched_dkg, 7);
    let mut share = mismatched.remove(&1).expect("share");
    share.frost_identifier = 2;
    mismatched.insert(1, share);
    assert!(
        threshold_sign(
            &config,
            &dkg.public_key_package,
            mismatched,
            b"artifact",
            &mut rng
        )
        .is_err()
    );

    let mut malformed_rng = StdRng::seed_from_u64(43);
    let mut malformed_dkg = run_complete_dkg(&config, &mut malformed_rng).expect("malformed dkg");
    let mut malformed_share = take_key_packages(&mut malformed_dkg, 7);
    malformed_share.get_mut(&1).expect("share").key_package = b"not a key package".to_vec().into();
    assert!(
        threshold_sign(
            &config,
            &dkg.public_key_package,
            malformed_share,
            b"artifact",
            &mut rng
        )
        .is_err()
    );

    let mut internal_rng = StdRng::seed_from_u64(43);
    let mut internal_dkg =
        run_complete_dkg(&config, &mut internal_rng).expect("internal mismatch dkg");
    let mut replacement = internal_dkg.key_packages.remove(&2).expect("share 2");
    let mut internal_mismatch = take_key_packages(&mut internal_dkg, 7);
    internal_mismatch.get_mut(&1).expect("share 1").key_package =
        std::mem::take(&mut replacement.key_package);
    assert!(
        threshold_sign(
            &config,
            &dkg.public_key_package,
            internal_mismatch,
            b"artifact",
            &mut rng
        )
        .is_err()
    );

    assert!(verify_root_signature(b"not a key", b"artifact", b"signature").is_err());
    assert!(
        verify_root_signature(
            &dkg.public_key_package.root_public_key,
            b"artifact",
            b"bad sig"
        )
        .is_err()
    );
}

#[test]
fn threshold_signing_rejects_foreign_valid_dkg_share_set() {
    let (config, _, _) = config();
    let mut first_rng = StdRng::seed_from_u64(4301);
    let first_dkg = run_complete_dkg(&config, &mut first_rng).expect("first dkg");
    let mut second_rng = StdRng::seed_from_u64(4302);
    let mut second_dkg = run_complete_dkg(&config, &mut second_rng).expect("second dkg");
    let foreign_shares = take_key_packages(&mut second_dkg, 7);

    assert!(
        threshold_sign(
            &config,
            &first_dkg.public_key_package,
            foreign_shares,
            b"artifact",
            &mut second_rng,
        )
        .is_err(),
        "shares from a different valid DKG must not aggregate under the root public package"
    );
}

#[test]
fn dkg_round_wrappers_complete_all_thirteen_and_reject_missing_peer_packages() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(77);
    let mut round1_outputs = BTreeMap::new();
    let mut round1_public = BTreeMap::new();
    for certifier in &config.certifiers {
        let output = dkg_round1(&config, certifier.frost_identifier, &mut rng).expect("round1");
        round1_public.insert(certifier.frost_identifier, output.round1_package.clone());
        round1_outputs.insert(certifier.frost_identifier, output);
    }

    let first = round1_outputs.get(&1).expect("round1 output");
    let mut missing = round1_public.clone();
    missing.remove(&2);
    assert!(
        dkg_round2(
            &config,
            1,
            &first.round1_secret_package,
            missing.into_iter().filter(|(id, _)| *id != 1).collect(),
        )
        .is_err()
    );

    let mut round2_outputs = BTreeMap::new();
    let mut round2_by_recipient: BTreeMap<u16, BTreeMap<u16, Zeroizing<Vec<u8>>>> = BTreeMap::new();
    for (identifier, round1_output) in &round1_outputs {
        let peer_round1 = round1_public
            .iter()
            .filter(|(peer, _)| *peer != identifier)
            .map(|(peer, package)| (*peer, package.clone()))
            .collect();
        let round2 = dkg_round2(
            &config,
            *identifier,
            &round1_output.round1_secret_package,
            peer_round1,
        )
        .expect("round2");
        for (recipient, package) in &round2.round2_packages {
            round2_by_recipient
                .entry(*recipient)
                .or_default()
                .insert(*identifier, package.clone());
        }
        round2_outputs.insert(*identifier, round2);
    }

    let mut root_public_keys = BTreeMap::new();
    for (identifier, round2_output) in &round2_outputs {
        let peer_round1 = round1_public
            .iter()
            .filter(|(peer, _)| *peer != identifier)
            .map(|(peer, package)| (*peer, package.clone()))
            .collect();
        let peer_round2 = round2_by_recipient
            .get(identifier)
            .expect("recipient packages")
            .clone();
        let participant = dkg_finalize_participant(
            &config,
            *identifier,
            &round2_output.round2_secret_package,
            peer_round1,
            peer_round2,
        )
        .expect("finalize");
        root_public_keys.insert(
            *identifier,
            participant.public_key_package.root_public_key.clone(),
        );
    }

    let expected = root_public_keys.get(&1).expect("first key");
    assert!(root_public_keys.values().all(|key| key == expected));
}

#[test]
fn dkg_round_wrappers_reject_valid_but_misbound_peer_packages() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(878);
    let mut round1_outputs = BTreeMap::new();
    let mut round1_public = BTreeMap::new();
    for certifier in &config.certifiers {
        let output = dkg_round1(&config, certifier.frost_identifier, &mut rng).expect("round1");
        round1_public.insert(certifier.frost_identifier, output.round1_package.clone());
        round1_outputs.insert(certifier.frost_identifier, output);
    }

    let first = round1_outputs.get(&1).expect("round1 output");
    let peer_round1 = round1_public
        .iter()
        .filter(|(peer, _)| **peer != 1)
        .map(|(peer, package)| (*peer, package.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut misbound_round1 = peer_round1.clone();
    misbound_round1.insert(2, peer_round1.get(&3).expect("peer 3 package").clone());
    assert!(
        dkg_round2(&config, 1, &first.round1_secret_package, misbound_round1).is_err(),
        "round two must reject a valid CBOR package bound to a different FROST sender"
    );

    let mut round2_outputs = BTreeMap::new();
    let mut round2_by_recipient: BTreeMap<u16, BTreeMap<u16, Zeroizing<Vec<u8>>>> = BTreeMap::new();
    for (identifier, round1_output) in &round1_outputs {
        let participant_peer_round1 = round1_public
            .iter()
            .filter(|(peer, _)| *peer != identifier)
            .map(|(peer, package)| (*peer, package.clone()))
            .collect();
        let round2 = dkg_round2(
            &config,
            *identifier,
            &round1_output.round1_secret_package,
            participant_peer_round1,
        )
        .expect("round2");
        for (recipient, package) in &round2.round2_packages {
            round2_by_recipient
                .entry(*recipient)
                .or_default()
                .insert(*identifier, package.clone());
        }
        round2_outputs.insert(*identifier, round2);
    }

    let mut misbound_round2 = round2_by_recipient.get(&1).expect("recipient 1").clone();
    let peer_three_for_one = misbound_round2.get(&3).expect("peer 3 package").clone();
    misbound_round2.insert(2, peer_three_for_one);
    let first_round2 = round2_outputs.get(&1).expect("round2 output");
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            &first_round2.round2_secret_package,
            peer_round1,
            misbound_round2,
        )
        .is_err(),
        "finalize must reject a valid CBOR package bound to a different FROST sender"
    );
}

#[test]
fn dkg_round_wrappers_reject_malformed_or_misaddressed_packages() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(88);
    let mut round1_outputs = BTreeMap::new();
    let mut round1_public = BTreeMap::new();
    for certifier in &config.certifiers {
        let output = dkg_round1(&config, certifier.frost_identifier, &mut rng).expect("round1");
        round1_public.insert(certifier.frost_identifier, output.round1_package.clone());
        round1_outputs.insert(certifier.frost_identifier, output);
    }

    assert!(dkg_round1(&config, 99, &mut rng).is_err());

    let first = round1_outputs.get(&1).expect("round1 output");
    let peer_round1 = round1_public
        .iter()
        .filter(|(peer, _)| **peer != 1)
        .map(|(peer, package)| (*peer, package.clone()))
        .collect::<BTreeMap<_, _>>();
    assert!(
        dkg_round2(
            &config,
            99,
            &first.round1_secret_package,
            peer_round1.clone()
        )
        .is_err(),
        "round two must reject an unrostered participant identifier"
    );
    assert!(dkg_round2(&config, 1, b"not a round1 secret", peer_round1.clone()).is_err());

    let mut self_round1 = peer_round1.clone();
    self_round1.insert(1, first.round1_package.clone());
    self_round1.remove(&2);
    assert!(dkg_round2(&config, 1, &first.round1_secret_package, self_round1).is_err());

    let mut nonrostered_round1 = peer_round1.clone();
    nonrostered_round1.remove(&2);
    nonrostered_round1.insert(99, round1_public.get(&2).expect("peer package").clone());
    assert!(dkg_round2(&config, 1, &first.round1_secret_package, nonrostered_round1).is_err());

    let mut malformed_round1 = peer_round1.clone();
    malformed_round1.insert(2, b"not a round1 package".to_vec());
    assert!(dkg_round2(&config, 1, &first.round1_secret_package, malformed_round1).is_err());

    let round2 = dkg_round2(
        &config,
        1,
        &first.round1_secret_package,
        peer_round1.clone(),
    )
    .expect("round2");
    assert!(
        dkg_finalize_participant(
            &config,
            99,
            &round2.round2_secret_package,
            peer_round1.clone(),
            round2.round2_packages.clone(),
        )
        .is_err(),
        "finalize must reject an unrostered participant identifier"
    );
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            b"not a round2 secret",
            peer_round1.clone(),
            round2.round2_packages.clone(),
        )
        .is_err()
    );

    let mut missing_round1 = peer_round1.clone();
    missing_round1.remove(&2);
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            &round2.round2_secret_package,
            missing_round1,
            round2.round2_packages.clone(),
        )
        .is_err()
    );

    let mut missing_round2 = round2.round2_packages.clone();
    missing_round2.remove(&2);
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            &round2.round2_secret_package,
            peer_round1.clone(),
            missing_round2,
        )
        .is_err()
    );

    let mut malformed_round2 = round2.round2_packages.clone();
    malformed_round2.insert(2, Zeroizing::new(b"not a round2 package".to_vec()));
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            &round2.round2_secret_package,
            peer_round1.clone(),
            malformed_round2,
        )
        .is_err()
    );

    let mut self_round2 = round2.round2_packages.clone();
    let peer_two_package = self_round2.remove(&2).expect("round2 peer package");
    self_round2.insert(1, peer_two_package);
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            &round2.round2_secret_package,
            peer_round1.clone(),
            self_round2.clone(),
        )
        .is_err()
    );

    let mut nonrostered_round2 = round2.round2_packages;
    nonrostered_round2.remove(&2);
    nonrostered_round2.insert(99, self_round2.remove(&1).expect("round2 package"));
    assert!(
        dkg_finalize_participant(
            &config,
            1,
            &round2.round2_secret_package,
            peer_round1,
            nonrostered_round2,
        )
        .is_err()
    );
}

#[test]
fn root_bundle_verification_rejects_tampered_delegation() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(99);
    let mut dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
    let delegation = RootIssuerDelegation {
        issuer_did: Did::new("did:exo:avc-issuer").expect("valid did"),
        issuer_public_key: PublicKey::from_bytes([0x44; 32]),
        granted_permissions: vec![Permission::Govern, Permission::Delegate],
        effective_at: Timestamp::new(1_785_000_010_000, 0),
        expires_at: None,
        purpose: "Delegate operational AVC issuing authority".into(),
    };
    let transcript_hash = Hash256::digest(b"transcript");
    let signing_packages = take_key_packages(&mut dkg, 7);
    let root_signature = threshold_sign(
        &config,
        &dkg.public_key_package,
        signing_packages,
        &delegation
            .root_artifact_payload(&config, &dkg.public_key_package, transcript_hash)
            .expect("payload"),
        &mut rng,
    )
    .expect("signature");
    let bundle = assemble_root_bundle(
        config.clone(),
        dkg.public_key_package.clone(),
        delegation.clone(),
        transcript_hash,
        root_signature,
    )
    .expect("bundle");
    verify_root_bundle(&bundle).expect("bundle verifies");

    let mut tampered = bundle;
    tampered.issuer_delegation.purpose = "widened authority".into();
    assert!(verify_root_bundle(&tampered).is_err());
}

#[test]
fn root_bundle_rejects_public_key_package_metadata_mismatch() {
    let (config, _, _) = config();
    let mut first_rng = StdRng::seed_from_u64(301);
    let mut second_rng = StdRng::seed_from_u64(302);
    let first_dkg = run_complete_dkg(&config, &mut first_rng).expect("first dkg");
    let mut second_dkg = run_complete_dkg(&config, &mut second_rng).expect("second dkg");
    let mut mixed_public = second_dkg.public_key_package.clone();
    mixed_public.public_key_package = first_dkg.public_key_package.public_key_package;
    let delegation = RootIssuerDelegation {
        issuer_did: Did::new("did:exo:avc-issuer").expect("valid did"),
        issuer_public_key: PublicKey::from_bytes([0x46; 32]),
        granted_permissions: vec![Permission::Govern],
        effective_at: Timestamp::new(1_785_000_010_000, 0),
        expires_at: None,
        purpose: "Delegate operational AVC issuing authority".into(),
    };
    let transcript_hash = Hash256::digest(b"transcript");
    let payload = delegation
        .root_artifact_payload(&config, &mixed_public, transcript_hash)
        .expect("payload");
    let mut signing_rng = StdRng::seed_from_u64(303);
    let signing_packages = take_key_packages(&mut second_dkg, 7);
    let root_signature = threshold_sign(
        &config,
        &second_dkg.public_key_package,
        signing_packages,
        &payload,
        &mut signing_rng,
    )
    .expect("signature");

    assert!(
        assemble_root_bundle(
            config,
            mixed_public,
            delegation,
            transcript_hash,
            root_signature,
        )
        .is_err(),
        "bundle must reject root key metadata that does not derive from the serialized FROST public package"
    );
}

#[test]
fn root_artifact_payload_rejects_unbounded_delegation() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(98);
    let dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
    let mut delegation = RootIssuerDelegation {
        issuer_did: Did::new("did:exo:avc-issuer").expect("valid did"),
        issuer_public_key: PublicKey::from_bytes([0x45; 32]),
        granted_permissions: vec![Permission::Govern],
        effective_at: Timestamp::new(1_785_000_010_000, 0),
        expires_at: None,
        purpose: "Delegate operational AVC issuing authority".into(),
    };

    delegation.purpose = " ".into();
    assert!(
        delegation
            .root_artifact_payload(&config, &dkg.public_key_package, Hash256::digest(b"tx"))
            .is_err()
    );

    delegation.purpose = "Delegate operational AVC issuing authority".into();
    delegation.granted_permissions.clear();
    assert!(
        delegation
            .root_artifact_payload(&config, &dkg.public_key_package, Hash256::digest(b"tx"))
            .is_err()
    );
}

#[test]
fn root_bundle_verification_rejects_tampered_config_transcript_signature_and_id() {
    let (config, _, _) = config();
    let mut rng = StdRng::seed_from_u64(100);
    let mut dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
    let delegation = RootIssuerDelegation {
        issuer_did: Did::new("did:exo:avc-issuer").expect("valid did"),
        issuer_public_key: PublicKey::from_bytes([0x55; 32]),
        granted_permissions: vec![Permission::Govern, Permission::Delegate],
        effective_at: Timestamp::new(1_785_000_010_000, 0),
        expires_at: Some(Timestamp::new(1_900_000_000_000, 0)),
        purpose: "Delegate operational AVC issuing authority".into(),
    };
    let transcript_hash = Hash256::digest(b"transcript");
    let payload = delegation
        .root_artifact_payload(&config, &dkg.public_key_package, transcript_hash)
        .expect("payload");
    let signing_packages = take_key_packages(&mut dkg, 7);
    let root_signature = threshold_sign(
        &config,
        &dkg.public_key_package,
        signing_packages,
        &payload,
        &mut rng,
    )
    .expect("signature");
    let bundle = assemble_root_bundle(
        config,
        dkg.public_key_package,
        delegation,
        transcript_hash,
        root_signature,
    )
    .expect("bundle");

    let mut tampered_config = bundle.clone();
    tampered_config.config.network_id = "wrong-network".into();
    assert!(verify_root_bundle(&tampered_config).is_err());

    let mut tampered_transcript = bundle.clone();
    tampered_transcript.transcript_hash = Hash256::digest(b"changed transcript");
    assert!(verify_root_bundle(&tampered_transcript).is_err());

    let mut tampered_signature = bundle.clone();
    tampered_signature.root_signature.signature[0] ^= 0x01;
    assert!(verify_root_bundle(&tampered_signature).is_err());

    let mut tampered_signer_set = bundle.clone();
    tampered_signer_set.root_signature.signer_ids = vec![1, 2, 3, 4, 5, 6, 9];
    assert!(verify_root_bundle(&tampered_signer_set).is_err());

    let mut tampered_id = bundle;
    tampered_id.bundle_id = Hash256::digest(b"wrong bundle id");
    assert!(verify_root_bundle(&tampered_id).is_err());
}

#[test]
fn portal_rejects_replay_plaintext_round2_and_wrong_phase_envelopes() {
    let (config, signing_secrets, _) = config();
    let sender = config.certifiers[0].did.clone();
    let recipient = config.certifiers[1].did.clone();
    let signing_secret = signing_secrets.get(&sender).expect("secret");
    let mut store = PortalStore::new(config.clone());

    let encrypted = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(recipient.clone()),
            1,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("envelope");
    store.submit(encrypted.clone()).expect("first submit");
    assert!(store.submit(encrypted).is_err(), "replay must be rejected");

    let plaintext = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2PlaintextPackage,
            sender.clone(),
            Some(recipient.clone()),
            2,
            b"plaintext share".to_vec(),
        ),
        signing_secret,
    )
    .expect("plaintext envelope");
    assert!(store.submit(plaintext).is_err());

    let mislabeled_plaintext = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(recipient.clone()),
            4,
            b"plaintext share".to_vec(),
        ),
        signing_secret,
    )
    .expect("mislabeled plaintext envelope");
    assert!(
        store.submit(mislabeled_plaintext).is_err(),
        "round-two plaintext bytes mislabeled as encrypted must be rejected"
    );

    let empty_ciphertext = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(recipient.clone()),
            5,
            encrypted_payload_bytes(Vec::new()),
        ),
        signing_secret,
    )
    .expect("empty ciphertext envelope");
    assert!(
        store.submit(empty_ciphertext).is_err(),
        "round-two encrypted package must carry ciphertext"
    );

    let wrong_phase = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round1,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender,
            None,
            3,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("wrong phase envelope");
    assert!(store.submit(wrong_phase).is_err());
}

#[test]
fn portal_rejects_unsigned_wrong_certifier_oversized_and_malformed_envelopes() {
    let (config, signing_secrets, _) = config();
    let sender = config.certifiers[0].did.clone();
    let recipient = config.certifiers[1].did.clone();
    let signing_secret = signing_secrets.get(&sender).expect("secret");
    let mut store = PortalStore::new(config.clone());

    let mut unsigned = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(recipient.clone()),
            10,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("envelope");
    unsigned.signature = Signature::Empty;
    assert!(store.submit(unsigned).is_err());

    let wrong_certifier = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            Did::new("did:exo:not-rostered").expect("valid did"),
            Some(recipient.clone()),
            11,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("wrong certifier envelope");
    assert!(store.submit(wrong_certifier).is_err());

    let oversized = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(recipient.clone()),
            12,
            vec![0xAB; 64 * 1024 + 1],
        ),
        signing_secret,
    )
    .expect("oversized envelope");
    assert!(store.submit(oversized).is_err());

    let mut malformed = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender,
            Some(recipient),
            13,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("malformed envelope");
    malformed.payload_bytes = b"changed".to_vec();
    assert!(store.submit(malformed).is_err());
}

#[test]
fn portal_rejects_wrong_ceremony_bad_recipient_self_target_and_bad_broadcasts() {
    let (config, signing_secrets, _) = config();
    let sender = config.certifiers[0].did.clone();
    let recipient = config.certifiers[1].did.clone();
    let signing_secret = signing_secrets.get(&sender).expect("secret");
    let mut store = PortalStore::new(config.clone());

    let wrong_ceremony = CeremonyEnvelope::sign(
        envelope_draft(
            "wrong-ceremony",
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(recipient.clone()),
            20,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("envelope");
    assert!(store.submit(wrong_ceremony).is_err());

    let wrong_recipient = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(Did::new("did:exo:not-rostered").expect("valid did")),
            21,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("envelope");
    assert!(store.submit(wrong_recipient).is_err());

    let self_target = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender.clone(),
            Some(sender.clone()),
            22,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("envelope");
    assert!(store.submit(self_target).is_err());

    let bad_broadcast = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round1,
            CeremonyPayloadKind::Round1Package,
            sender.clone(),
            Some(recipient),
            23,
            b"round1".to_vec(),
        ),
        signing_secret,
    )
    .expect("envelope");
    assert!(store.submit(bad_broadcast).is_err());

    let no_round2_recipient = CeremonyEnvelope::sign(
        envelope_draft(
            &config.ceremony_id,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            sender,
            None,
            24,
            encrypted_payload_bytes(b"ciphertext"),
        ),
        signing_secret,
    )
    .expect("envelope");
    assert!(store.submit(no_round2_recipient).is_err());
}

#[test]
fn portal_schema_validates_dkg_kinds_and_keeps_unratified_kinds_disabled() {
    let (config, signing_secrets, _) = config();
    let mut rng = StdRng::seed_from_u64(2026);
    let round1_package = dkg_round1(&config, 1, &mut rng)
        .expect("round one")
        .round1_package;
    let mut store = PortalStore::new(config.clone());

    store
        .submit(sign_envelope(
            &config,
            &signing_secrets,
            1,
            CeremonyPhase::Round1,
            CeremonyPayloadKind::Round1Package,
            None,
            30,
            round1_package.clone(),
        ))
        .expect("round-one package accepted");
    store
        .submit(sign_envelope(
            &config,
            &signing_secrets,
            1,
            CeremonyPhase::Round2,
            CeremonyPayloadKind::Round2EncryptedPackage,
            Some(2),
            31,
            encrypted_payload_bytes(b"ciphertext"),
        ))
        .expect("round-two encrypted package accepted");
    assert_eq!(store.envelope_count(), 2);

    // FinalKeyConfirmation is ratified, but it still fails closed until the
    // complete DKG transcript exists and the typed payload verifies.
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::Finalize,
                CeremonyPayloadKind::FinalKeyConfirmation,
                None,
                32,
                vec![1, 2, 3],
            ))
            .is_err()
    );

    // Round-one set attestation remains disabled because it still has no
    // ratified producer/schema/verifier.
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::Round1SetAttestation,
                CeremonyPayloadKind::Round1SetAttestation,
                None,
                33,
                vec![1, 2, 3],
            ))
            .is_err()
    );

    // A structurally invalid round-one package fails schema validation.
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                2,
                CeremonyPhase::Round1,
                CeremonyPayloadKind::Round1Package,
                None,
                35,
                b"not a round-one package".to_vec(),
            ))
            .is_err()
    );

    // A broadcast kind may not carry a recipient.
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                3,
                CeremonyPhase::Round1,
                CeremonyPayloadKind::Round1Package,
                Some(2),
                36,
                round1_package,
            ))
            .is_err()
    );
}

#[test]
fn final_key_confirmation_gates_root_signing_and_final_transcript_hash() {
    let (config, signing_secrets, _) = config();
    let mut rng = StdRng::seed_from_u64(2126);
    let dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
    let mut confirmation_rng = StdRng::seed_from_u64(2126);
    let mut confirmation_dkg =
        run_complete_dkg(&config, &mut confirmation_rng).expect("confirmation dkg");
    let mut store = PortalStore::new(config.clone());
    let dkg_transcript_hash =
        submit_complete_dkg_transcript(&mut store, &config, &signing_secrets, &mut rng);

    let (commitment, signer_nonces) =
        sign_commit(&config, &dkg.key_packages[&1], b"artifact", &mut rng).expect("commit");
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::RootSigning,
                CeremonyPayloadKind::RootSigningCommitment,
                None,
                6_001,
                commitment.commitments.clone(),
            ))
            .is_err(),
        "root signing must be blocked before final key confirmations"
    );

    submit_final_key_confirmations(
        &mut store,
        &config,
        &signing_secrets,
        &mut confirmation_dkg,
        dkg_transcript_hash,
        12,
    );
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::RootSigning,
                CeremonyPayloadKind::RootSigningCommitment,
                None,
                6_002,
                commitment.commitments.clone(),
            ))
            .is_err(),
        "root signing must wait for all thirteen confirmations"
    );

    submit_final_key_confirmation(
        &mut store,
        &config,
        &signing_secrets,
        &mut confirmation_dkg,
        dkg_transcript_hash,
        13,
    );
    let final_transcript_hash = store
        .final_transcript_hash()
        .expect("final transcript hash");
    assert_ne!(final_transcript_hash, dkg_transcript_hash);

    store
        .submit(sign_envelope(
            &config,
            &signing_secrets,
            1,
            CeremonyPhase::RootSigning,
            CeremonyPayloadKind::RootSigningCommitment,
            None,
            6_003,
            commitment.commitments,
        ))
        .expect("root signing commitment accepted after all confirmations");

    let mut nonces_shaped_payload = Vec::new();
    ciborium::into_writer(&signer_nonces, &mut nonces_shaped_payload).expect("encode nonces");
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                2,
                CeremonyPhase::RootSigning,
                CeremonyPayloadKind::RootSigningCommitment,
                None,
                6_004,
                nonces_shaped_payload,
            ))
            .is_err(),
        "RootSigningNonces bytes must not be accepted as a public commitment"
    );

    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for identifier in 1..=7u16 {
        let (commitment, signer_nonces) = sign_commit(
            &config,
            &dkg.key_packages[&identifier],
            b"artifact",
            &mut rng,
        )
        .expect("commit");
        commitments.insert(identifier, commitment.commitments);
        nonces.insert(identifier, signer_nonces);
    }
    let package = build_signing_package(&config, commitments, b"artifact").expect("package");
    let share_payload = sign_share(
        &config,
        &dkg.key_packages[&1],
        &nonces[&1],
        &package,
        b"artifact",
    )
    .expect("share")
    .signature_share;
    store
        .submit(sign_envelope(
            &config,
            &signing_secrets,
            1,
            CeremonyPhase::RootSigning,
            CeremonyPayloadKind::RootSignatureShare,
            None,
            6_005,
            share_payload.clone(),
        ))
        .expect("signature share accepted after all confirmations");
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::RootSigning,
                CeremonyPayloadKind::RootSignatureShare,
                None,
                6_006,
                share_payload,
            ))
            .is_err(),
        "a second signature share from one signer is rejected"
    );

    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::Round2,
                CeremonyPayloadKind::Round2EncryptedPackage,
                Some(2),
                6_007,
                encrypted_payload_bytes(b"late dkg mutation"),
            ))
            .is_err(),
        "the DKG transcript is frozen after final confirmations begin"
    );
}

#[test]
fn final_key_confirmation_rejects_sender_hash_and_duplicate_mismatches() {
    let (config, signing_secrets, _) = config();
    let mut rng = StdRng::seed_from_u64(2226);
    let mut dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
    let mut accepted_rng = StdRng::seed_from_u64(2226);
    let mut accepted_dkg =
        run_complete_dkg(&config, &mut accepted_rng).expect("accepted confirmation dkg");
    let mut duplicate_rng = StdRng::seed_from_u64(2226);
    let mut duplicate_dkg =
        run_complete_dkg(&config, &mut duplicate_rng).expect("duplicate confirmation dkg");
    let mut store = PortalStore::new(config.clone());
    let dkg_transcript_hash =
        submit_complete_dkg_transcript(&mut store, &config, &signing_secrets, &mut rng);

    // Payload certifier DID/FROST id must match the signed envelope sender.
    let id1_payload = final_key_confirmation_payload(&config, &mut dkg, 1, dkg_transcript_hash);
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                2,
                CeremonyPhase::Finalize,
                CeremonyPayloadKind::FinalKeyConfirmation,
                None,
                5_002,
                id1_payload,
            ))
            .is_err()
    );

    submit_final_key_confirmation(
        &mut store,
        &config,
        &signing_secrets,
        &mut accepted_dkg,
        dkg_transcript_hash,
        1,
    );
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                1,
                CeremonyPhase::Finalize,
                CeremonyPayloadKind::FinalKeyConfirmation,
                None,
                5_101,
                final_key_confirmation_payload(
                    &config,
                    &mut duplicate_dkg,
                    1,
                    dkg_transcript_hash,
                ),
            ))
            .is_err(),
        "at most one final key confirmation is accepted per certifier"
    );

    let mut tampered = build_final_key_confirmation(
        &config,
        &participant_output(&mut dkg, 2),
        dkg_transcript_hash,
    )
    .expect("confirmation");
    tampered.root_public_key_hash = Hash256::digest(b"wrong root key hash");
    assert!(
        store
            .submit(sign_envelope(
                &config,
                &signing_secrets,
                2,
                CeremonyPhase::Finalize,
                CeremonyPayloadKind::FinalKeyConfirmation,
                None,
                5_102,
                encode_final_key_confirmation_payload(&tampered).expect("tampered payload"),
            ))
            .is_err(),
        "semantic hash mismatches must fail closed"
    );
}

#[test]
fn share_sealing_and_pairwise_payload_encryption_fail_closed() {
    let (config, _, transport_secrets) = config();
    let sender = &config.certifiers[0];
    let recipient = &config.certifiers[1];
    let sender_secret = transport_secrets.get(&sender.did).expect("sender secret");
    let recipient_secret = transport_secrets
        .get(&recipient.did)
        .expect("recipient secret");

    let encrypted = encrypt_pairwise_payload(
        sender_secret,
        &recipient.transport_public_key,
        b"round2 package",
        b"exo-root-round2",
        &[7u8; 24],
    )
    .expect("encrypted");
    let decrypted = decrypt_pairwise_payload(
        recipient_secret,
        &sender.transport_public_key,
        &encrypted,
        b"exo-root-round2",
    )
    .expect("decrypted");
    assert_eq!(decrypted, b"round2 package");
    assert!(
        decrypt_pairwise_payload(
            recipient_secret,
            &sender.transport_public_key,
            &encrypted,
            b"wrong aad",
        )
        .is_err()
    );

    let sealed = seal_share(
        b"root key package",
        b"correct horse battery staple",
        b"exo-root-share",
        &[9u8; 16],
        &[10u8; 24],
    )
    .expect("sealed");
    let opened =
        unseal_share(&sealed, b"correct horse battery staple", b"exo-root-share").expect("opened");
    assert_eq!(opened, b"root key package");
    assert!(unseal_share(&sealed, b"wrong passphrase", b"exo-root-share").is_err());
    assert!(unseal_share(&sealed, b"correct horse battery staple", b"wrong aad").is_err());

    let mut corrupted = sealed.clone();
    corrupted.ciphertext[0] ^= 0x01;
    assert!(
        unseal_share(
            &corrupted,
            b"correct horse battery staple",
            b"exo-root-share"
        )
        .is_err()
    );

    let invalid_salt = SealedShare {
        salt: Vec::new(),
        nonce: [10u8; 24],
        ciphertext: sealed.ciphertext,
    };
    assert!(
        unseal_share(
            &invalid_salt,
            b"correct horse battery staple",
            b"exo-root-share"
        )
        .is_err()
    );
}

#[test]
fn source_guards_reject_nondeterministic_patterns() {
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/bundle.rs"),
        include_str!("../src/ceremony.rs"),
        include_str!("../src/dkg.rs"),
        include_str!("../src/error.rs"),
        include_str!("../src/portal.rs"),
        include_str!("../src/seal.rs"),
        include_str!("../src/signing.rs"),
    ];
    let banned_map = ["Hash", "Map"].concat();
    let banned_set = ["Hash", "Set"].concat();
    for source in sources {
        let production = source.split("#[cfg(test)]").next().expect("split");
        assert!(!production.contains(&banned_map));
        assert!(!production.contains(&banned_set));
        assert!(!production.contains(": f32"));
        assert!(!production.contains(": f64"));
        assert!(!production.contains("SystemTime::now"));
        assert!(!production.contains("Instant::now"));
        assert!(!production.contains("unsafe"));
    }
}
