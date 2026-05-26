//! Root genesis CLI command implementation.

use std::{collections::BTreeMap, fs, io::Write, net::SocketAddr};

use exo_core::{Did, Hash256, SecretKey, Timestamp, crypto::KeyPair};
use exo_root::{
    CeremonyEnvelope, CeremonyEnvelopeDraft, CeremonyPayloadKind, CeremonyPhase, CertifierContact,
    GenesisCeremonyConfig, PairwiseEncryptedPayload, RootIssuerDelegation, RootKeyPackage,
    RootPublicKeyPackage, RootTrustBundle, aggregate_signature, assemble_root_bundle,
    build_signing_package, decrypt_pairwise_payload, dkg_finalize_participant, dkg_round1,
    dkg_round2, encrypt_pairwise_payload, seal_share, sign_commit, sign_share, threshold_sign,
    unseal_share, verify_root_bundle,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    cli::{
        GenesisCeremonyCommand, GenesisCeremonyInitArgs, GenesisCertifierCommand,
        GenesisCertifierInitArgs, GenesisCommand, GenesisIoArgs, GenesisPortalArgs,
        GenesisPullEnvelopesArgs, GenesisSignEnvelopeArgs, GenesisSubmitEnvelopeArgs,
    },
    root_genesis::{RootGenesisApiState, root_genesis_router},
};

/// Portal HTTP path that accepts signed ceremony envelopes.
const PORTAL_ENVELOPES_PATH: &str = "/api/v1/root-genesis/portal/envelopes";

/// Domain separator for the PROVISIONAL round-one set attestation statement.
///
/// The canonical shape of a `Round1SetAttestation` payload is not defined or
/// validated anywhere in `exo-root` (the portal treats the bytes as opaque).
/// This encoding is a deterministic best-effort proposal and is NOT ratified;
/// the `V0_UNRATIFIED` suffix must change once the exo-root maintainer confirms
/// the intended shape. See `run_build_round1_attestation`.
const ROUND1_SET_ATTESTATION_DOMAIN: &str = "EXOCHAIN_ROOT_ROUND1_SET_ATTESTATION_V0_UNRATIFIED";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateCertifierMaterial {
    did: Did,
    frost_identifier: u16,
    signing_secret_hex: String,
    transport_secret_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Round1CommandInput {
    config: GenesisCeremonyConfig,
    frost_identifier: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Round2CommandInput {
    config: GenesisCeremonyConfig,
    frost_identifier: u16,
    round1_secret_package_hex: String,
    round1_packages_hex: BTreeMapStringBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FinalizeDkgCommandInput {
    config: GenesisCeremonyConfig,
    frost_identifier: u16,
    round2_secret_package_hex: String,
    round1_packages_hex: BTreeMapStringBytes,
    round2_packages_hex: BTreeMapStringBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignRootArtifactCommandInput {
    config: GenesisCeremonyConfig,
    public_key_package: RootPublicKeyPackage,
    key_packages: BTreeMap<u16, RootKeyPackage>,
    artifact_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AssembleBundleCommandInput {
    config: GenesisCeremonyConfig,
    public_key_package: RootPublicKeyPackage,
    issuer_delegation: RootIssuerDelegation,
    transcript_hash: Hash256,
    root_signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifyBundleCommandInput {
    bundle: RootTrustBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SealShareCommandInput {
    share_hex: String,
    passphrase_hex: String,
    associated_data_hex: String,
    salt_hex: String,
    nonce_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnsealShareCommandInput {
    sealed: exo_root::SealedShare,
    passphrase_hex: String,
    associated_data_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HexBytesOutput {
    bytes_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignEnvelopeCommandInput {
    ceremony_id: String,
    phase: CeremonyPhase,
    payload_kind: CeremonyPayloadKind,
    sender_did: Did,
    #[serde(default)]
    recipient_did: Option<Did>,
    sequence: u64,
    payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EncryptPairwiseCommandInput {
    plaintext: Vec<u8>,
    sender_transport_secret_hex: String,
    recipient_transport_pubkey_hex: String,
    associated_data_hex: String,
    nonce_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DecryptPairwiseCommandInput {
    encrypted: PairwiseEncryptedPayload,
    recipient_transport_secret_hex: String,
    sender_transport_pubkey_hex: String,
    associated_data_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EmitArtifactBytesCommandInput {
    config: GenesisCeremonyConfig,
    public_key_package: RootPublicKeyPackage,
    issuer_delegation: RootIssuerDelegation,
    transcript_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BuildRound1AttestationCommandInput {
    round1_envelopes: Vec<CeremonyEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArtifactBytesOutput {
    artifact_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlaintextOutput {
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Round1AttestationOutput {
    /// Bytes to place in the `payload_bytes` field of a `Round1SetAttestation`
    /// envelope (then sign with `sign-envelope`). PROVISIONAL encoding.
    payload_hex: String,
    /// blake3 of `payload_hex` — a convenience digest of the attested set.
    attestation_hash_hex: String,
    /// Number of round-one packages bound by this attestation.
    entry_count: usize,
}

/// One `(sender, round1-package-hash)` binding inside the provisional
/// round-one set attestation statement, canonicalised in sorted order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Round1SetAttestationEntry {
    sender_did: Did,
    round1_package_hash: Hash256,
}

/// Provisional canonical statement bound by a `Round1SetAttestation` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Round1SetAttestationStatement<'a> {
    domain: &'static str,
    ceremony_id: &'a str,
    entry_count: usize,
    entries: &'a [Round1SetAttestationEntry],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EncodeEncryptedPayloadCommandInput {
    encrypted: PairwiseEncryptedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DecodeEncryptedPayloadCommandInput {
    payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PayloadBytesOutput {
    payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignCommitCommandInput {
    config: GenesisCeremonyConfig,
    key_package: RootKeyPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BuildSigningPackageCommandInput {
    config: GenesisCeremonyConfig,
    commitments_hex: BTreeMapStringBytes,
    artifact_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignShareCommandInput {
    config: GenesisCeremonyConfig,
    key_package: RootKeyPackage,
    nonces_hex: String,
    signing_package_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AggregateSignatureCommandInput {
    config: GenesisCeremonyConfig,
    public_key_package: RootPublicKeyPackage,
    signing_package_hex: String,
    shares_hex: BTreeMapStringBytes,
    artifact_hex: String,
}

type BTreeMapStringBytes = BTreeMap<u16, String>;

/// Execute a root genesis CLI command.
pub async fn run_genesis_command(command: GenesisCommand) -> anyhow::Result<()> {
    match command {
        GenesisCommand::Certifier { command } => run_certifier_command(command),
        GenesisCommand::Ceremony { command } => run_ceremony_command(command),
        GenesisCommand::Portal(args) => serve_portal(args).await,
        GenesisCommand::Round1(args) => run_round1(args),
        GenesisCommand::Round2(args) => run_round2(args),
        GenesisCommand::FinalizeDkg(args) => run_finalize_dkg(args),
        GenesisCommand::SignRootArtifact(args) => run_sign_root_artifact(args),
        GenesisCommand::AssembleBundle(args) => run_assemble_bundle(args),
        GenesisCommand::VerifyBundle(args) => run_verify_bundle(args),
        GenesisCommand::SealShare(args) => run_seal_share(args),
        GenesisCommand::UnsealShare(args) => run_unseal_share(args),
        GenesisCommand::SignEnvelope(args) => run_sign_envelope(args),
        GenesisCommand::EncryptPairwise(args) => run_encrypt_pairwise(args),
        GenesisCommand::DecryptPairwise(args) => run_decrypt_pairwise(args),
        GenesisCommand::EmitArtifactBytes(args) => run_emit_artifact_bytes(args),
        GenesisCommand::BuildRound1Attestation(args) => run_build_round1_attestation(args),
        GenesisCommand::SubmitEnvelope(args) => run_submit_envelope(args).await,
        GenesisCommand::PullEnvelopes(args) => run_pull_envelopes(args).await,
        GenesisCommand::EncodeEncryptedPayload(args) => run_encode_encrypted_payload(args),
        GenesisCommand::DecodeEncryptedPayload(args) => run_decode_encrypted_payload(args),
        GenesisCommand::SignCommit(args) => run_sign_commit(args),
        GenesisCommand::BuildSigningPackage(args) => run_build_signing_package(args),
        GenesisCommand::SignShare(args) => run_sign_share(args),
        GenesisCommand::AggregateSignature(args) => run_aggregate_signature(args),
    }
}

fn run_certifier_command(command: GenesisCertifierCommand) -> anyhow::Result<()> {
    match command {
        GenesisCertifierCommand::Init(args) => init_certifier(args),
    }
}

fn run_ceremony_command(command: GenesisCeremonyCommand) -> anyhow::Result<()> {
    match command {
        GenesisCeremonyCommand::Init(args) => init_ceremony(args),
    }
}

fn init_certifier(args: GenesisCertifierInitArgs) -> anyhow::Result<()> {
    let did = Did::new(&args.did)?;
    let mut signing_seed = [0u8; 32];
    let mut transport_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut signing_seed);
    rand::rngs::OsRng.fill_bytes(&mut transport_secret);
    let signing_keypair = KeyPair::from_secret_bytes(signing_seed)?;
    let transport_public = X25519PublicKey::from(&StaticSecret::from(transport_secret));
    let contact = CertifierContact {
        did: did.clone(),
        frost_identifier: args.frost_identifier,
        signing_public_key: *signing_keypair.public_key(),
        transport_public_key: *transport_public.as_bytes(),
    };
    let private = PrivateCertifierMaterial {
        did,
        frost_identifier: args.frost_identifier,
        signing_secret_hex: hex::encode(signing_seed),
        transport_secret_hex: hex::encode(transport_secret),
    };
    write_json(&args.certifier_out, &contact)?;
    write_json(&args.private_out, &private)?;
    Ok(())
}

fn init_ceremony(args: GenesisCeremonyInitArgs) -> anyhow::Result<()> {
    let certifiers: Vec<CertifierContact> = read_json(&args.roster)?;
    let constitution_hash = parse_hash_hex(&args.constitution_hash)?;
    let config = GenesisCeremonyConfig {
        ceremony_id: args.ceremony_id,
        network_id: args.network_id,
        repo_commit: args.repo_commit,
        constitution_hash,
        threshold: exo_root::ROOT_GENESIS_THRESHOLD,
        max_signers: exo_root::ROOT_GENESIS_SIGNERS,
        created_at: Timestamp::new(args.created_physical_ms, 0),
        certifiers,
    };
    config.validate()?;
    write_json(&args.out, &config)?;
    Ok(())
}

async fn serve_portal(args: GenesisPortalArgs) -> anyhow::Result<()> {
    let config: GenesisCeremonyConfig = read_json(&args.config)?;
    config.validate()?;
    let address = args.bind.parse::<SocketAddr>()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let router = root_genesis_router(RootGenesisApiState::new(config));
    axum::serve(listener, router).await?;
    Ok(())
}

fn run_round1(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: Round1CommandInput = read_json(&required_input(&args)?)?;
    input.config.validate()?;
    let mut rng = rand::rngs::OsRng;
    let output = dkg_round1(&input.config, input.frost_identifier, &mut rng)?;
    write_secret_output(&args, &output)
}

fn run_round2(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: Round2CommandInput = read_json(&required_input(&args)?)?;
    let output = dkg_round2(
        &input.config,
        input.frost_identifier,
        decode_hex(&input.round1_secret_package_hex)?.as_slice(),
        decode_package_map(input.round1_packages_hex)?,
    )?;
    write_secret_output(&args, &output)
}

fn run_finalize_dkg(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: FinalizeDkgCommandInput = read_json(&required_input(&args)?)?;
    let output = dkg_finalize_participant(
        &input.config,
        input.frost_identifier,
        decode_hex(&input.round2_secret_package_hex)?.as_slice(),
        decode_package_map(input.round1_packages_hex)?,
        decode_package_map(input.round2_packages_hex)?,
    )?;
    write_secret_output(&args, &output)
}

fn run_sign_root_artifact(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: SignRootArtifactCommandInput = read_json(&required_input(&args)?)?;
    let artifact = decode_hex(&input.artifact_hex)?;
    let mut rng = rand::rngs::OsRng;
    let signature = threshold_sign(
        &input.config,
        &input.public_key_package,
        input.key_packages,
        artifact.as_slice(),
        &mut rng,
    )?;
    write_output(&args, &signature)
}

fn run_assemble_bundle(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: AssembleBundleCommandInput = read_json(&required_input(&args)?)?;
    let bundle = assemble_root_bundle(
        input.config,
        input.public_key_package,
        input.issuer_delegation,
        input.transcript_hash,
        decode_hex(&input.root_signature_hex)?,
    )?;
    write_output(&args, &bundle)
}

fn run_verify_bundle(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: VerifyBundleCommandInput = read_json(&required_input(&args)?)?;
    verify_root_bundle(&input.bundle)?;
    write_output(&args, &serde_json::json!({ "verified": true }))
}

fn run_seal_share(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: SealShareCommandInput = read_json(&required_input(&args)?)?;
    let salt = decode_fixed_16(&input.salt_hex)?;
    let nonce = decode_fixed_24(&input.nonce_hex)?;
    let sealed = seal_share(
        decode_hex(&input.share_hex)?.as_slice(),
        decode_hex(&input.passphrase_hex)?.as_slice(),
        decode_hex(&input.associated_data_hex)?.as_slice(),
        &salt,
        &nonce,
    )?;
    write_secret_output(&args, &sealed)
}

fn run_unseal_share(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: UnsealShareCommandInput = read_json(&required_input(&args)?)?;
    let opened = unseal_share(
        &input.sealed,
        decode_hex(&input.passphrase_hex)?.as_slice(),
        decode_hex(&input.associated_data_hex)?.as_slice(),
    )?;
    write_secret_output(
        &args,
        &HexBytesOutput {
            bytes_hex: hex::encode(opened),
        },
    )
}

fn run_sign_envelope(args: GenesisSignEnvelopeArgs) -> anyhow::Result<()> {
    let io = GenesisIoArgs {
        input: args.input.clone(),
        output: args.output.clone(),
    };
    let input: SignEnvelopeCommandInput = read_json(&required_input(&io)?)?;
    let signing_secret = SecretKey::from_bytes(decode_fixed_32(&args.signing_key_hex)?);
    let draft = CeremonyEnvelopeDraft {
        ceremony_id: input.ceremony_id,
        phase: input.phase,
        payload_kind: input.payload_kind,
        sender_did: input.sender_did,
        recipient_did: input.recipient_did,
        sequence: input.sequence,
        payload_bytes: input.payload_bytes,
    };
    let envelope = CeremonyEnvelope::sign(draft, &signing_secret)?;
    write_output(&io, &envelope)
}

fn run_encrypt_pairwise(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: EncryptPairwiseCommandInput = read_json(&required_input(&args)?)?;
    let sender_secret = decode_fixed_32(&input.sender_transport_secret_hex)?;
    let recipient_public = decode_fixed_32(&input.recipient_transport_pubkey_hex)?;
    let nonce = decode_fixed_24(&input.nonce_hex)?;
    let associated_data = decode_hex(&input.associated_data_hex)?;
    let encrypted = encrypt_pairwise_payload(
        &sender_secret,
        &recipient_public,
        input.plaintext.as_slice(),
        associated_data.as_slice(),
        &nonce,
    )?;
    write_output(&args, &encrypted)
}

fn run_decrypt_pairwise(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: DecryptPairwiseCommandInput = read_json(&required_input(&args)?)?;
    let recipient_secret = decode_fixed_32(&input.recipient_transport_secret_hex)?;
    let sender_public = decode_fixed_32(&input.sender_transport_pubkey_hex)?;
    let associated_data = decode_hex(&input.associated_data_hex)?;
    let plaintext = decrypt_pairwise_payload(
        &recipient_secret,
        &sender_public,
        &input.encrypted,
        associated_data.as_slice(),
    )?;
    write_secret_output(&args, &PlaintextOutput { plaintext })
}

fn run_emit_artifact_bytes(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: EmitArtifactBytesCommandInput = read_json(&required_input(&args)?)?;
    let transcript_hash = parse_hash_hex(&input.transcript_hash_hex)?;
    let artifact = input.issuer_delegation.root_artifact_payload(
        &input.config,
        &input.public_key_package,
        transcript_hash,
    )?;
    write_output(
        &args,
        &ArtifactBytesOutput {
            artifact_hex: hex::encode(artifact),
        },
    )
}

/// Build a PROVISIONAL round-one set attestation payload.
///
/// `exo-root` defines no canonical shape for `Round1SetAttestation` payloads —
/// the portal accepts the bytes opaquely (see `portal.rs::validate_phase_policy`,
/// which only checks phase/kind/recipient, never content). This command emits a
/// deterministic statement binding the sorted set of
/// `(sender_did, round1_package_hash)` pairs taken from the round-one
/// broadcast envelopes, domain-separated by [`ROUND1_SET_ATTESTATION_DOMAIN`]
/// and CBOR-encoded with the same canonical encoder the library uses for its
/// own signing payloads.
///
/// This encoding is UNRATIFIED. Do not rely on it for the production ceremony
/// until the exo-root maintainer confirms the intended shape; if they choose a
/// different one (for example a bare digest, or keying on `frost_identifier`
/// instead of `sender_did`), only this function and the domain tag change.
fn run_build_round1_attestation(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: BuildRound1AttestationCommandInput = read_json(&required_input(&args)?)?;
    if input.round1_envelopes.is_empty() {
        anyhow::bail!("round1 set must contain at least one envelope");
    }
    let ceremony_id = input.round1_envelopes[0].ceremony_id.clone();
    let mut entries = Vec::with_capacity(input.round1_envelopes.len());
    for envelope in &input.round1_envelopes {
        if envelope.ceremony_id != ceremony_id {
            anyhow::bail!("round1 set mixes ceremony identifiers");
        }
        if envelope.phase != CeremonyPhase::Round1
            || envelope.payload_kind != CeremonyPayloadKind::Round1Package
        {
            anyhow::bail!("round1 set contains a non-Round1Package envelope");
        }
        entries.push(Round1SetAttestationEntry {
            sender_did: envelope.sender_did.clone(),
            round1_package_hash: envelope.payload_hash,
        });
    }
    entries.sort_by(|left, right| left.sender_did.cmp(&right.sender_did));
    for pair in entries.windows(2) {
        if pair[0].sender_did == pair[1].sender_did {
            anyhow::bail!(
                "round1 set contains duplicate sender {}",
                pair[0].sender_did
            );
        }
    }
    let statement = Round1SetAttestationStatement {
        domain: ROUND1_SET_ATTESTATION_DOMAIN,
        ceremony_id: &ceremony_id,
        entry_count: entries.len(),
        entries: entries.as_slice(),
    };
    let mut payload = Vec::new();
    ciborium::into_writer(&statement, &mut payload)
        .map_err(|error| anyhow::anyhow!("round1 attestation encoding failed: {error}"))?;
    let attestation_hash = Hash256::digest(payload.as_slice());
    write_output(
        &args,
        &Round1AttestationOutput {
            payload_hex: hex::encode(payload.as_slice()),
            attestation_hash_hex: hex::encode(attestation_hash.as_bytes()),
            entry_count: entries.len(),
        },
    )
}

async fn run_submit_envelope(args: GenesisSubmitEnvelopeArgs) -> anyhow::Result<()> {
    let io = GenesisIoArgs {
        input: args.input.clone(),
        output: None,
    };
    let envelope: CeremonyEnvelope = read_json(&required_input(&io)?)?;
    let url = portal_envelopes_url(&args.portal_url);
    let response = reqwest::Client::new()
        .post(url)
        .json(&envelope)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    println!("{body}");
    if !status.is_success() {
        anyhow::bail!("portal rejected envelope: HTTP {status}");
    }
    Ok(())
}

async fn run_pull_envelopes(args: GenesisPullEnvelopesArgs) -> anyhow::Result<()> {
    let url = portal_envelopes_url(&args.portal_url);
    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(phase) = &args.phase {
        params.push(("phase", phase.clone()));
    }
    if let Some(kind) = &args.payload_kind {
        params.push(("payload_kind", kind.clone()));
    }
    if let Some(recipient) = &args.recipient_did {
        params.push(("recipient_did", recipient.clone()));
    }
    let response = reqwest::Client::new()
        .get(url)
        .query(&params)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("portal pull failed: HTTP {status}: {body}");
    }
    let envelopes: Vec<CeremonyEnvelope> = serde_json::from_str(&body)?;
    let io = GenesisIoArgs {
        input: None,
        output: args.output.clone(),
    };
    write_output(&io, &envelopes)
}

fn run_encode_encrypted_payload(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: EncodeEncryptedPayloadCommandInput = read_json(&required_input(&args)?)?;
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&input.encrypted, &mut payload_bytes)
        .map_err(|error| anyhow::anyhow!("encrypted payload encoding failed: {error}"))?;
    write_output(&args, &PayloadBytesOutput { payload_bytes })
}

fn run_decode_encrypted_payload(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: DecodeEncryptedPayloadCommandInput = read_json(&required_input(&args)?)?;
    let encrypted: PairwiseEncryptedPayload = ciborium::from_reader(input.payload_bytes.as_slice())
        .map_err(|error| anyhow::anyhow!("encrypted payload decoding failed: {error}"))?;
    write_output(&args, &encrypted)
}

fn run_sign_commit(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: SignCommitCommandInput = read_json(&required_input(&args)?)?;
    let mut rng = rand::rngs::OsRng;
    let output = sign_commit(&input.config, &input.key_package, &mut rng)?;
    // Contains secret signing nonces — never print to stdout.
    write_secret_output(&args, &output)
}

fn run_build_signing_package(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: BuildSigningPackageCommandInput = read_json(&required_input(&args)?)?;
    let message = decode_hex(&input.artifact_hex)?;
    let output = build_signing_package(
        &input.config,
        decode_package_map(input.commitments_hex)?,
        message.as_slice(),
    )?;
    write_output(&args, &output)
}

fn run_sign_share(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: SignShareCommandInput = read_json(&required_input(&args)?)?;
    let output = sign_share(
        &input.config,
        &input.key_package,
        decode_hex(&input.nonces_hex)?.as_slice(),
        decode_hex(&input.signing_package_hex)?.as_slice(),
    )?;
    write_output(&args, &output)
}

fn run_aggregate_signature(args: GenesisIoArgs) -> anyhow::Result<()> {
    let input: AggregateSignatureCommandInput = read_json(&required_input(&args)?)?;
    let message = decode_hex(&input.artifact_hex)?;
    let output = aggregate_signature(
        &input.config,
        &input.public_key_package,
        decode_hex(&input.signing_package_hex)?.as_slice(),
        decode_package_map(input.shares_hex)?,
        message.as_slice(),
    )?;
    write_output(&args, &output)
}

/// Append the portal envelopes path to a base URL unless it is already present.
fn portal_envelopes_url(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with(PORTAL_ENVELOPES_PATH) {
        trimmed.to_owned()
    } else {
        format!("{trimmed}{PORTAL_ENVELOPES_PATH}")
    }
}

fn parse_hash_hex(value: &str) -> anyhow::Result<Hash256> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        anyhow::bail!("constitution hash must be 32 bytes");
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(hash))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &std::path::Path) -> anyhow::Result<T> {
    let bytes = fs::read(path)?;
    let value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

fn write_json<T: Serialize>(path: &std::path::Path, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_json_bytes(path, bytes.as_slice())?;
    Ok(())
}

#[cfg(unix)]
fn write_json_bytes(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_json_bytes(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn required_input(args: &GenesisIoArgs) -> anyhow::Result<std::path::PathBuf> {
    args.input
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--input is required for this command"))
}

fn write_output<T: Serialize>(args: &GenesisIoArgs, value: &T) -> anyhow::Result<()> {
    match &args.output {
        Some(path) => write_json(path, value),
        None => {
            println!("{}", serde_json::to_string_pretty(value)?);
            Ok(())
        }
    }
}

fn write_secret_output<T: Serialize>(args: &GenesisIoArgs, value: &T) -> anyhow::Result<()> {
    if args.output.is_none() {
        anyhow::bail!(
            "--output is required for secret root genesis material; refusing to print to stdout"
        );
    }
    write_output(args, value)
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(value)?)
}

fn decode_fixed_16(value: &str) -> anyhow::Result<[u8; 16]> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 16 {
        anyhow::bail!("expected 16 bytes");
    }
    let mut result = [0u8; 16];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn decode_fixed_24(value: &str) -> anyhow::Result<[u8; 24]> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 24 {
        anyhow::bail!("expected 24 bytes");
    }
    let mut result = [0u8; 24];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn decode_fixed_32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes");
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn decode_package_map(packages: BTreeMapStringBytes) -> anyhow::Result<BTreeMap<u16, Vec<u8>>> {
    let mut decoded = BTreeMap::new();
    for (identifier, package_hex) in packages {
        decoded.insert(identifier, decode_hex(&package_hex)?);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use exo_authority::permission::Permission;
    use exo_core::PublicKey;
    use exo_root::PortalStore;
    use tempfile::tempdir;

    use super::*;

    fn certifier(identifier: u16) -> CertifierContact {
        let byte = u8::try_from(identifier).expect("identifier fits in byte");
        CertifierContact {
            did: Did::new(&format!("did:exo:root-cli-{identifier:02}")).expect("valid DID"),
            frost_identifier: identifier,
            signing_public_key: PublicKey::from_bytes([byte; 32]),
            transport_public_key: [byte; 32],
        }
    }

    fn io_args(input: PathBuf, output: PathBuf) -> GenesisIoArgs {
        GenesisIoArgs {
            input: Some(input),
            output: Some(output),
        }
    }

    /// Build a fully valid 13-certifier config whose signing keys are derived
    /// from `[index; 32]`, so envelopes signed with that secret verify against
    /// the rostered public key (unlike the lighter `certifier` helper above).
    fn rostered_config() -> GenesisCeremonyConfig {
        let certifiers = (1..=13u16)
            .map(|index| {
                let seed = u8::try_from(index).expect("index fits u8");
                let keypair = KeyPair::from_secret_bytes([seed; 32]).expect("valid keypair");
                let transport_secret = [seed.wrapping_add(64); 32];
                let transport_public = X25519PublicKey::from(&StaticSecret::from(transport_secret));
                CertifierContact {
                    did: Did::new(&format!("did:exo:root-cli-signed-{index:02}")).expect("did"),
                    frost_identifier: index,
                    signing_public_key: *keypair.public_key(),
                    transport_public_key: *transport_public.as_bytes(),
                }
            })
            .collect();
        let config = GenesisCeremonyConfig {
            ceremony_id: "root-cli-signed-ceremony".to_owned(),
            network_id: "exo-mainnet".to_owned(),
            repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".to_owned(),
            constitution_hash: Hash256::digest(b"constitution"),
            threshold: exo_root::ROOT_GENESIS_THRESHOLD,
            max_signers: exo_root::ROOT_GENESIS_SIGNERS,
            created_at: Timestamp::new(1_785_000_000_000, 0),
            certifiers,
        };
        config.validate().expect("rostered config is valid");
        config
    }

    fn round1_broadcast(
        config: &GenesisCeremonyConfig,
        certifier_index: usize,
        sequence: u64,
        payload_bytes: Vec<u8>,
    ) -> CeremonyEnvelope {
        let signer = &config.certifiers[certifier_index];
        let seed = u8::try_from(certifier_index + 1).expect("index fits u8");
        let secret = SecretKey::from_bytes([seed; 32]);
        CeremonyEnvelope::sign(
            CeremonyEnvelopeDraft {
                ceremony_id: config.ceremony_id.clone(),
                phase: CeremonyPhase::Round1,
                payload_kind: CeremonyPayloadKind::Round1Package,
                sender_did: signer.did.clone(),
                recipient_did: None,
                sequence,
                payload_bytes,
            },
            &secret,
        )
        .expect("signed round1 envelope")
    }

    #[test]
    fn init_ceremony_writes_valid_institutional_config() {
        let directory = tempdir().expect("temporary directory");
        let roster_path = directory.path().join("roster.json");
        let config_path = directory.path().join("ceremony.json");
        let roster: Vec<_> = (1..=13).map(certifier).collect();
        write_json(&roster_path, &roster).expect("write roster");

        init_ceremony(GenesisCeremonyInitArgs {
            ceremony_id: "root-cli-ceremony".to_owned(),
            network_id: "exo-mainnet".to_owned(),
            repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".to_owned(),
            constitution_hash: hex::encode([7u8; 32]),
            created_physical_ms: 42,
            roster: roster_path,
            out: config_path.clone(),
        })
        .expect("ceremony init");

        let config: GenesisCeremonyConfig = read_json(&config_path).expect("read config");
        assert_eq!(config.threshold, exo_root::ROOT_GENESIS_THRESHOLD);
        assert_eq!(config.max_signers, exo_root::ROOT_GENESIS_SIGNERS);
        assert_eq!(
            config.certifiers.len(),
            usize::from(exo_root::ROOT_GENESIS_SIGNERS)
        );
        assert_eq!(config.created_at, Timestamp::new(42, 0));
        config.validate().expect("valid root genesis config");
    }

    #[test]
    fn seal_and_unseal_share_commands_round_trip_hex_output() {
        let directory = tempdir().expect("temporary directory");
        let seal_input_path = directory.path().join("seal-input.json");
        let sealed_path = directory.path().join("sealed.json");
        let unseal_input_path = directory.path().join("unseal-input.json");
        let opened_path = directory.path().join("opened.json");
        let share = b"certifier-share-material";
        let associated_data = b"root-genesis-share-v1";
        let passphrase = b"long offline passphrase";
        write_json(
            &seal_input_path,
            &SealShareCommandInput {
                share_hex: hex::encode(share),
                passphrase_hex: hex::encode(passphrase),
                associated_data_hex: hex::encode(associated_data),
                salt_hex: hex::encode([2u8; 16]),
                nonce_hex: hex::encode([3u8; 24]),
            },
        )
        .expect("write seal input");

        run_seal_share(io_args(seal_input_path, sealed_path.clone())).expect("seal share");
        let sealed: exo_root::SealedShare = read_json(&sealed_path).expect("read sealed share");
        write_json(
            &unseal_input_path,
            &UnsealShareCommandInput {
                sealed,
                passphrase_hex: hex::encode(passphrase),
                associated_data_hex: hex::encode(associated_data),
            },
        )
        .expect("write unseal input");

        run_unseal_share(io_args(unseal_input_path, opened_path.clone())).expect("unseal share");
        let opened: HexBytesOutput = read_json(&opened_path).expect("read opened share");
        assert_eq!(opened.bytes_hex, hex::encode(share));
    }

    #[test]
    fn unseal_share_refuses_to_print_plaintext_share_to_stdout() {
        let directory = tempdir().expect("temporary directory");
        let unseal_input_path = directory.path().join("unseal-input.json");
        let share = b"certifier-share-material";
        let associated_data = b"root-genesis-share-v1";
        let passphrase = b"long offline passphrase";
        let sealed = seal_share(share, passphrase, associated_data, &[2u8; 16], &[3u8; 24])
            .expect("seal share");
        write_json(
            &unseal_input_path,
            &UnsealShareCommandInput {
                sealed,
                passphrase_hex: hex::encode(passphrase),
                associated_data_hex: hex::encode(associated_data),
            },
        )
        .expect("write unseal input");

        let err = run_unseal_share(GenesisIoArgs {
            input: Some(unseal_input_path),
            output: None,
        })
        .expect_err("plaintext share output must require --output");
        assert!(err.to_string().contains("--output is required"));
    }

    #[test]
    fn command_helpers_fail_closed_on_missing_input_and_bad_hex() {
        let missing_input = GenesisIoArgs {
            input: None,
            output: None,
        };
        assert!(
            required_input(&missing_input)
                .expect_err("input must be required")
                .to_string()
                .contains("--input is required")
        );
        assert!(
            parse_hash_hex("abcd")
                .expect_err("short hash must fail")
                .to_string()
                .contains("constitution hash must be 32 bytes")
        );
        assert!(
            decode_fixed_16("abcd")
                .expect_err("short salt must fail")
                .to_string()
                .contains("expected 16 bytes")
        );
        assert!(
            decode_fixed_24("abcd")
                .expect_err("short nonce must fail")
                .to_string()
                .contains("expected 24 bytes")
        );
        let mut packages = BTreeMap::new();
        packages.insert(7, "not-hex".to_owned());
        assert!(decode_package_map(packages).is_err());
    }

    #[test]
    fn sign_envelope_output_is_accepted_by_the_portal() {
        let config = rostered_config();
        let signer = config.certifiers[0].clone();
        let directory = tempdir().expect("temporary directory");
        let input_path = directory.path().join("draft.json");
        let output_path = directory.path().join("envelope.json");
        write_json(
            &input_path,
            &SignEnvelopeCommandInput {
                ceremony_id: config.ceremony_id.clone(),
                phase: CeremonyPhase::Round1,
                payload_kind: CeremonyPayloadKind::Round1Package,
                sender_did: signer.did.clone(),
                recipient_did: None,
                sequence: 1,
                payload_bytes: b"round1 package bytes".to_vec(),
            },
        )
        .expect("write draft");

        run_sign_envelope(GenesisSignEnvelopeArgs {
            input: Some(input_path),
            output: Some(output_path.clone()),
            signing_key_hex: hex::encode([1u8; 32]),
        })
        .expect("sign envelope");

        let envelope: CeremonyEnvelope = read_json(&output_path).expect("read envelope");
        assert_eq!(envelope.sender_did, signer.did);
        let mut store = PortalStore::new(config);
        store
            .submit(envelope)
            .expect("portal accepts the signed envelope");
    }

    #[test]
    fn encrypt_then_decrypt_pairwise_round_trips() {
        let directory = tempdir().expect("temporary directory");
        let sender_secret = [5u8; 32];
        let recipient_secret = [6u8; 32];
        let sender_public = *X25519PublicKey::from(&StaticSecret::from(sender_secret)).as_bytes();
        let recipient_public =
            *X25519PublicKey::from(&StaticSecret::from(recipient_secret)).as_bytes();
        let associated_data = b"exo-root-round2";
        let nonce = [7u8; 24];
        let plaintext = b"round2 secret package".to_vec();

        let encrypt_in = directory.path().join("encrypt-in.json");
        let encrypt_out = directory.path().join("encrypt-out.json");
        write_json(
            &encrypt_in,
            &EncryptPairwiseCommandInput {
                plaintext: plaintext.clone(),
                sender_transport_secret_hex: hex::encode(sender_secret),
                recipient_transport_pubkey_hex: hex::encode(recipient_public),
                associated_data_hex: hex::encode(associated_data),
                nonce_hex: hex::encode(nonce),
            },
        )
        .expect("write encrypt input");
        run_encrypt_pairwise(io_args(encrypt_in, encrypt_out.clone())).expect("encrypt pairwise");
        let encrypted: PairwiseEncryptedPayload =
            read_json(&encrypt_out).expect("read encrypted payload");
        assert_eq!(encrypted.nonce, nonce);

        let decrypt_in = directory.path().join("decrypt-in.json");
        let decrypt_out = directory.path().join("decrypt-out.json");
        write_json(
            &decrypt_in,
            &DecryptPairwiseCommandInput {
                encrypted,
                recipient_transport_secret_hex: hex::encode(recipient_secret),
                sender_transport_pubkey_hex: hex::encode(sender_public),
                associated_data_hex: hex::encode(associated_data),
            },
        )
        .expect("write decrypt input");
        run_decrypt_pairwise(io_args(decrypt_in, decrypt_out.clone())).expect("decrypt pairwise");
        let opened: PlaintextOutput = read_json(&decrypt_out).expect("read plaintext");
        assert_eq!(opened.plaintext, plaintext);
    }

    #[test]
    fn decrypt_pairwise_refuses_to_print_plaintext_to_stdout() {
        let directory = tempdir().expect("temporary directory");
        let sender_secret = [5u8; 32];
        let recipient_secret = [6u8; 32];
        let sender_public = *X25519PublicKey::from(&StaticSecret::from(sender_secret)).as_bytes();
        let recipient_public =
            *X25519PublicKey::from(&StaticSecret::from(recipient_secret)).as_bytes();
        let encrypted = encrypt_pairwise_payload(
            &sender_secret,
            &recipient_public,
            b"round2 secret package",
            b"exo-root-round2",
            &[7u8; 24],
        )
        .expect("encrypted");
        let decrypt_in = directory.path().join("decrypt-in.json");
        write_json(
            &decrypt_in,
            &DecryptPairwiseCommandInput {
                encrypted,
                recipient_transport_secret_hex: hex::encode(recipient_secret),
                sender_transport_pubkey_hex: hex::encode(sender_public),
                associated_data_hex: hex::encode(b"exo-root-round2"),
            },
        )
        .expect("write decrypt input");

        let error = run_decrypt_pairwise(GenesisIoArgs {
            input: Some(decrypt_in),
            output: None,
        })
        .expect_err("decrypted round-two material must require --output");
        assert!(error.to_string().contains("--output is required"));
    }

    #[test]
    fn emit_artifact_bytes_matches_the_library_signing_payload() {
        let config = rostered_config();
        let public_key_package = RootPublicKeyPackage {
            public_key_package: b"public-key-package-bytes".to_vec(),
            root_public_key: b"root-public-key".to_vec(),
            verifying_shares: (1..=13u16)
                .map(|id| (id, vec![u8::try_from(id).expect("id fits u8")]))
                .collect(),
        };
        let delegation = RootIssuerDelegation {
            issuer_did: Did::new("did:exo:avc-issuer").expect("valid did"),
            issuer_public_key: PublicKey::from_bytes([0x44; 32]),
            granted_permissions: vec![Permission::Govern, Permission::Delegate],
            effective_at: Timestamp::new(1_785_000_010_000, 0),
            expires_at: None,
            purpose: "Delegate operational AVC issuing authority".to_owned(),
        };
        let transcript_hash = Hash256::digest(b"transcript");
        let expected = delegation
            .root_artifact_payload(&config, &public_key_package, transcript_hash)
            .expect("library artifact payload");

        let directory = tempdir().expect("temporary directory");
        let input_path = directory.path().join("artifact-in.json");
        let output_path = directory.path().join("artifact-out.json");
        write_json(
            &input_path,
            &EmitArtifactBytesCommandInput {
                config: config.clone(),
                public_key_package: public_key_package.clone(),
                issuer_delegation: delegation.clone(),
                transcript_hash_hex: hex::encode(transcript_hash.as_bytes()),
            },
        )
        .expect("write artifact input");
        run_emit_artifact_bytes(io_args(input_path, output_path.clone()))
            .expect("emit artifact bytes");
        let output: ArtifactBytesOutput = read_json(&output_path).expect("read artifact output");
        assert_eq!(output.artifact_hex, hex::encode(expected.as_slice()));
    }

    #[test]
    fn build_round1_attestation_is_order_independent_and_portal_submittable() {
        let config = rostered_config();
        let envelopes = vec![
            round1_broadcast(&config, 0, 1, b"round1-a".to_vec()),
            round1_broadcast(&config, 1, 1, b"round1-b".to_vec()),
            round1_broadcast(&config, 2, 1, b"round1-c".to_vec()),
        ];

        let directory = tempdir().expect("temporary directory");
        let forward_in = directory.path().join("attest-forward-in.json");
        let forward_out = directory.path().join("attest-forward-out.json");
        write_json(
            &forward_in,
            &BuildRound1AttestationCommandInput {
                round1_envelopes: envelopes.clone(),
            },
        )
        .expect("write forward input");
        run_build_round1_attestation(io_args(forward_in, forward_out.clone()))
            .expect("build attestation (forward)");

        let mut reversed = envelopes;
        reversed.reverse();
        let reversed_in = directory.path().join("attest-reversed-in.json");
        let reversed_out = directory.path().join("attest-reversed-out.json");
        write_json(
            &reversed_in,
            &BuildRound1AttestationCommandInput {
                round1_envelopes: reversed,
            },
        )
        .expect("write reversed input");
        run_build_round1_attestation(io_args(reversed_in, reversed_out.clone()))
            .expect("build attestation (reversed)");

        let forward: Round1AttestationOutput =
            read_json(&forward_out).expect("read forward output");
        let reversed: Round1AttestationOutput =
            read_json(&reversed_out).expect("read reversed output");
        assert_eq!(
            forward, reversed,
            "attestation must be canonical regardless of input order"
        );
        assert_eq!(forward.entry_count, 3);

        let payload_bytes = hex::decode(forward.payload_hex.as_str()).expect("hex payload");
        let attestation_secret = SecretKey::from_bytes([1u8; 32]);
        let attestation = CeremonyEnvelope::sign(
            CeremonyEnvelopeDraft {
                ceremony_id: config.ceremony_id.clone(),
                phase: CeremonyPhase::Round1SetAttestation,
                payload_kind: CeremonyPayloadKind::Round1SetAttestation,
                sender_did: config.certifiers[0].did.clone(),
                recipient_did: None,
                sequence: 100,
                payload_bytes,
            },
            &attestation_secret,
        )
        .expect("sign attestation envelope");
        let mut store = PortalStore::new(config);
        store
            .submit(attestation)
            .expect("portal accepts the attestation envelope");
    }

    #[test]
    fn distributed_signing_handlers_produce_a_verifiable_signature() {
        let config = rostered_config();
        let dkg = exo_root::run_complete_dkg(&config, &mut rand::rngs::OsRng).expect("dkg");
        let message = b"distributed root artifact";
        let artifact_hex = hex::encode(message);
        let directory = tempdir().expect("temporary directory");
        let signers: Vec<u16> = (1..=7).collect();

        let mut commitments_hex = BTreeMap::new();
        let mut nonces_hex = BTreeMap::new();
        for id in &signers {
            let in_path = directory.path().join(format!("commit-in-{id}.json"));
            let out_path = directory.path().join(format!("commit-out-{id}.json"));
            write_json(
                &in_path,
                &SignCommitCommandInput {
                    config: config.clone(),
                    key_package: dkg.key_packages[id].clone(),
                },
            )
            .expect("write commit input");
            run_sign_commit(io_args(in_path, out_path.clone())).expect("sign-commit");
            let commit: exo_root::RootSigningCommitment =
                read_json(&out_path).expect("read commitment");
            commitments_hex.insert(*id, hex::encode(&commit.commitments));
            nonces_hex.insert(*id, hex::encode(&commit.nonces));
        }

        let pkg_in = directory.path().join("pkg-in.json");
        let pkg_out = directory.path().join("pkg-out.json");
        write_json(
            &pkg_in,
            &BuildSigningPackageCommandInput {
                config: config.clone(),
                commitments_hex,
                artifact_hex: artifact_hex.clone(),
            },
        )
        .expect("write package input");
        run_build_signing_package(io_args(pkg_in, pkg_out.clone())).expect("build-signing-package");
        let package: exo_root::RootSigningPackage = read_json(&pkg_out).expect("read package");
        let signing_package_hex = hex::encode(&package.signing_package);

        let mut shares_hex = BTreeMap::new();
        for id in &signers {
            let in_path = directory.path().join(format!("share-in-{id}.json"));
            let out_path = directory.path().join(format!("share-out-{id}.json"));
            write_json(
                &in_path,
                &SignShareCommandInput {
                    config: config.clone(),
                    key_package: dkg.key_packages[id].clone(),
                    nonces_hex: nonces_hex[id].clone(),
                    signing_package_hex: signing_package_hex.clone(),
                },
            )
            .expect("write share input");
            run_sign_share(io_args(in_path, out_path.clone())).expect("sign-share");
            let share: exo_root::RootSignatureShareOutput =
                read_json(&out_path).expect("read share");
            shares_hex.insert(*id, hex::encode(&share.signature_share));
        }

        let agg_in = directory.path().join("agg-in.json");
        let agg_out = directory.path().join("agg-out.json");
        write_json(
            &agg_in,
            &AggregateSignatureCommandInput {
                config: config.clone(),
                public_key_package: dkg.public_key_package.clone(),
                signing_package_hex,
                shares_hex,
                artifact_hex,
            },
        )
        .expect("write aggregate input");
        run_aggregate_signature(io_args(agg_in, agg_out.clone())).expect("aggregate-signature");
        let signature: exo_root::RootSignature = read_json(&agg_out).expect("read signature");
        assert_eq!(signature.signer_ids.len(), 7);
        exo_root::verify_root_signature(
            &dkg.public_key_package.root_public_key,
            message,
            &signature.signature,
        )
        .expect("distributed signature verifies against the root key");
    }

    #[test]
    fn encrypted_payload_codec_round_trips_through_the_cli() {
        let payload = PairwiseEncryptedPayload {
            nonce: [5u8; 24],
            ciphertext: b"recipient-bound ciphertext".to_vec(),
        };
        let directory = tempdir().expect("temporary directory");
        let enc_in = directory.path().join("encode-in.json");
        let enc_out = directory.path().join("encode-out.json");
        write_json(
            &enc_in,
            &EncodeEncryptedPayloadCommandInput {
                encrypted: payload.clone(),
            },
        )
        .expect("write encode input");
        run_encode_encrypted_payload(io_args(enc_in, enc_out.clone())).expect("encode");
        let encoded: PayloadBytesOutput = read_json(&enc_out).expect("read encoded");

        let dec_in = directory.path().join("decode-in.json");
        let dec_out = directory.path().join("decode-out.json");
        write_json(
            &dec_in,
            &DecodeEncryptedPayloadCommandInput {
                payload_bytes: encoded.payload_bytes,
            },
        )
        .expect("write decode input");
        run_decode_encrypted_payload(io_args(dec_in, dec_out.clone())).expect("decode");
        let decoded: PairwiseEncryptedPayload = read_json(&dec_out).expect("read decoded");
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn submit_envelope_posts_signed_envelope_to_running_portal() {
        let config = rostered_config();
        let envelope = round1_broadcast(&config, 0, 1, b"round1 package bytes".to_vec());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind portal listener");
        let address = listener.local_addr().expect("portal address");
        let router = root_genesis_router(RootGenesisApiState::new(config));
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve portal");
        });

        let directory = tempdir().expect("temporary directory");
        let input_path = directory.path().join("envelope.json");
        write_json(&input_path, &envelope).expect("write envelope");

        run_submit_envelope(GenesisSubmitEnvelopeArgs {
            portal_url: format!("http://{address}"),
            input: Some(input_path),
        })
        .await
        .expect("portal accepts submitted envelope");
    }

    #[test]
    fn portal_envelopes_url_appends_path_at_most_once() {
        let expected = "http://127.0.0.1:3017/api/v1/root-genesis/portal/envelopes";
        assert_eq!(portal_envelopes_url("http://127.0.0.1:3017"), expected);
        assert_eq!(portal_envelopes_url("http://127.0.0.1:3017/"), expected);
        assert_eq!(portal_envelopes_url(expected), expected);
    }

    #[cfg(unix)]
    #[test]
    fn json_outputs_are_create_new_owner_only_and_refuse_existing_paths() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().expect("temporary directory");
        let output_path = directory.path().join("private-material.json");
        write_json(
            &output_path,
            &HexBytesOutput {
                bytes_hex: hex::encode(b"secret"),
            },
        )
        .expect("write output");

        let mode = fs::metadata(&output_path)
            .expect("output metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            write_json(
                &output_path,
                &HexBytesOutput {
                    bytes_hex: hex::encode(b"replacement"),
                },
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn json_outputs_refuse_existing_symlink_paths() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory");
        let target_path = directory.path().join("target.json");
        let output_path = directory.path().join("private-material.json");
        fs::write(&target_path, b"do not overwrite").expect("seed symlink target");
        symlink(&target_path, &output_path).expect("create output symlink");

        assert!(
            write_json(
                &output_path,
                &HexBytesOutput {
                    bytes_hex: hex::encode(b"secret"),
                },
            )
            .is_err()
        );
        assert_eq!(
            fs::read(&target_path).expect("read symlink target"),
            b"do not overwrite"
        );
    }

    #[cfg(unix)]
    #[test]
    fn json_outputs_refuse_existing_regular_files_without_rewriting() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().expect("temporary directory");
        let output_path = directory.path().join("private-material.json");
        fs::write(&output_path, b"previous material").expect("seed existing file");
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o644))
            .expect("make existing file too broad");

        assert!(
            write_json(
                &output_path,
                &HexBytesOutput {
                    bytes_hex: hex::encode(b"secret"),
                },
            )
            .is_err()
        );

        assert_eq!(
            fs::read(&output_path).expect("read existing output"),
            b"previous material"
        );
        let mode = fs::metadata(&output_path)
            .expect("output metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }
}
