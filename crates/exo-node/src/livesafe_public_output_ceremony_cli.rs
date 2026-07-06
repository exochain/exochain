//! LiveSafe public-output AVC ceremony CLI implementation.

use std::{fs, io::Write, path::Path};

use exo_authority::permission::Permission;
use exo_core::{Did, Timestamp, crypto::KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{
    AvcCommand, LivesafePublicOutputCeremonyCommand, LivesafePublicOutputCeremonyPrepareArgs,
    LivesafePublicOutputCeremonyRegisterArgs,
};

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
struct IssuerSigningMaterial {
    #[zeroize(skip)]
    issuer_did: Did,
    signing_secret_hex: String,
}

#[derive(Serialize)]
struct RegistrationCommandOutput {
    credential_id: exo_core::Hash256,
    authorization_request: exo_avc::LivesafePublicOutputAuthorizationRequestMaterial,
    http_status: u16,
    response_body: String,
}

pub async fn run_avc_command(command: AvcCommand) -> anyhow::Result<()> {
    match command {
        AvcCommand::LivesafePublicOutputCeremony { command } => match command {
            LivesafePublicOutputCeremonyCommand::Prepare(args) => run_prepare(args),
            LivesafePublicOutputCeremonyCommand::Register(args) => run_register(args).await,
        },
    }
}

fn run_prepare(args: LivesafePublicOutputCeremonyPrepareArgs) -> anyhow::Result<()> {
    let issuer_did = Did::new(&args.issuer_did)
        .map_err(|error| anyhow::anyhow!("invalid issuer DID: {error}"))?;
    let signing_material = read_signing_material(&args.issuer_secret_input)?;
    if signing_material.issuer_did != issuer_did {
        anyhow::bail!(
            "issuer signing material DID {} does not match --issuer-did {}",
            signing_material.issuer_did,
            issuer_did
        );
    }
    let signing_secret = decode_fixed_32(signing_material.signing_secret_hex.as_str())?;
    let issuer_keypair = KeyPair::from_secret_bytes(*signing_secret)
        .map_err(|error| anyhow::anyhow!("issuer signing key is invalid: {error}"))?;
    if let Some(path) = &args.evidence_input {
        require_non_empty_evidence_file(path)?;
    }
    let evidence_hash = exo_avc::parse_livesafe_public_output_evidence_sha256(&args.evidence_hash)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let input = exo_avc::LivesafePublicOutputCredentialCeremonyInput {
        issuer_did,
        issuer_authority_scope: livesafe_public_output_scope(),
        credential_subject_did: Did::new(
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID,
        )
        .map_err(|error| anyhow::anyhow!("invalid LiveSafe credential subject DID: {error}"))?,
        public_subject: exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
        public_audience: exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE.into(),
        allowed_claim_names: vec![
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
        ],
        evidence: exo_avc::LivesafePublicOutputCredentialCeremonyEvidence {
            sha256_hash: evidence_hash,
        },
        not_before: Timestamp::new(args.not_before_physical_ms, 0),
        expires_at: Timestamp::new(args.expires_at_physical_ms, 0),
        idempotency_key: args.idempotency_key,
    };
    let output = exo_avc::issue_livesafe_public_output_credential_ceremony(input, |payload| {
        issuer_keypair.sign(payload)
    })
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    write_output(args.output.as_deref(), &output)
}

async fn run_register(args: LivesafePublicOutputCeremonyRegisterArgs) -> anyhow::Result<()> {
    let package: exo_avc::LivesafePublicOutputCredentialCeremonyOutput = read_json(&args.input)?;
    let bearer = read_admin_bearer(&args)?;
    let url = avc_issue_url(&args.node_url);
    let response = reqwest::Client::new()
        .post(url)
        .bearer_auth(bearer.as_str())
        .json(&package.issue_request)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    let sanitized_body = redact_token(&body, bearer.as_str());
    let output = RegistrationCommandOutput {
        credential_id: package.credential_id,
        authorization_request: package.authorization_request,
        http_status: status.as_u16(),
        response_body: sanitized_body,
    };
    if !status.is_success() {
        anyhow::bail!(
            "LiveSafe public-output credential registration failed: HTTP {}: {}",
            output.http_status,
            output.response_body
        );
    }
    write_output(args.output.as_deref(), &output)
}

fn livesafe_public_output_scope() -> exo_avc::AuthorityScope {
    exo_avc::AuthorityScope {
        permissions: vec![Permission::Read],
        tools: vec![exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into()],
        data_classes: vec![exo_avc::DataClass::Public],
        counterparties: vec![],
        jurisdictions: vec!["US".into()],
    }
}

fn avc_issue_url(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/api/v1/avc/issue") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/api/v1/avc/issue")
    }
}

fn read_admin_bearer(
    args: &LivesafePublicOutputCeremonyRegisterArgs,
) -> anyhow::Result<Zeroizing<String>> {
    let token = match (&args.admin_bearer_env, &args.admin_bearer_file) {
        (Some(env_name), None) => Zeroizing::new(std::env::var(env_name).map_err(|error| {
            anyhow::anyhow!("admin bearer env var {env_name} is unavailable: {error}")
        })?),
        (None, Some(path)) => {
            let raw = fs::read_to_string(path).map_err(|error| {
                anyhow::anyhow!(
                    "admin bearer file {} is unavailable: {error}",
                    path.display()
                )
            })?;
            Zeroizing::new(raw)
        }
        _ => anyhow::bail!("exactly one admin bearer source is required"),
    };
    let trimmed = token.trim();
    if trimmed.is_empty() {
        anyhow::bail!("admin bearer source is empty");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

fn require_non_empty_evidence_file(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to inspect evidence input {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!("evidence input {} is not a file", path.display());
    }
    if metadata.len() == 0 {
        anyhow::bail!("evidence input {} is empty", path.display());
    }
    Ok(())
}

fn redact_token(text: &str, token: &str) -> String {
    text.replace(token, "[redacted-admin-bearer]")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let bytes = fs::read(path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("failed to parse JSON {}: {error}", path.display()))
}

fn read_signing_material(path: &Path) -> anyhow::Result<IssuerSigningMaterial> {
    let bytes = Zeroizing::new(
        fs::read(path)
            .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?,
    );
    serde_json::from_slice(bytes.as_slice())
        .map_err(|error| anyhow::anyhow!("failed to parse JSON {}: {error}", path.display()))
}

fn write_output<T: Serialize>(path: Option<&Path>, value: &T) -> anyhow::Result<()> {
    match path {
        Some(path) => write_json(path, value),
        None => {
            println!("{}", serde_json::to_string_pretty(value)?);
            Ok(())
        }
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_json_bytes(path, bytes.as_slice())
}

#[cfg(unix)]
fn write_json_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
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
fn write_json_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn decode_fixed_32(value: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(hex::decode(value.trim())?);
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte signing secret");
    }
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(bytes.as_slice());
    Ok(result)
}
