//! Root genesis CLI command implementation.

use std::{collections::BTreeMap, fs, io::Write, net::SocketAddr};

use exo_core::{Did, Hash256, Timestamp, crypto::KeyPair};
use exo_root::{
    CertifierContact, GenesisCeremonyConfig, RootIssuerDelegation, RootKeyPackage,
    RootPublicKeyPackage, RootTrustBundle, assemble_root_bundle, dkg_finalize_participant,
    dkg_round1, dkg_round2, seal_share, threshold_sign, unseal_share, verify_root_bundle,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    cli::{
        GenesisCeremonyCommand, GenesisCeremonyInitArgs, GenesisCertifierCommand,
        GenesisCertifierInitArgs, GenesisCommand, GenesisIoArgs, GenesisPortalArgs,
    },
    root_genesis::{RootGenesisApiState, root_genesis_router},
};

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

    use exo_core::PublicKey;
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
