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

//! Node API surface for Autonomous Volition Credentials.
//!
//! Routes are merged into the gateway's axum router via the same
//! `serve_with_extra_routes` pattern used by governance, passport, and
//! provenance. Mutating endpoints (`POST`) inherit bearer-token auth
//! from the merged write guard; ordinary AVC denials return HTTP `200`
//! with `decision: Deny` rather than `403` so callers see structured
//! reason codes.
//!
//! ## Routes
//!
//! | Method | Path | Purpose |
//! |--------|------|---------|
//! | `POST` | `/api/v1/avc/issue` | Register a signed credential. |
//! | `POST` | `/api/v1/avc/validate` | Validate a credential and optional action. |
//! | `POST` | `/api/v1/avc/receipts/emit` | Validate a subject-signed action and mint a node-signed receipt. |
//! | `POST` | `/api/v1/avc/delegate` | Register a signed child credential. |
//! | `POST` | `/api/v1/avc/revoke` | Register a signed revocation. |
//! | `GET`  | `/api/v1/avc/:id` | Fetch a registered credential by hex ID. |
//! | `GET`  | `/api/v1/agents/:did/avcs` | List credentials for a subject DID. |
//!
//! ## State
//!
//! The handlers operate against a shared [`AvcApiState`] that wraps an
//! `InMemoryAvcRegistry` behind `Arc<Mutex<_>>`. All synchronous store
//! access is performed inside `tokio::task::spawn_blocking` so async
//! workers are not held under the registry lock.

use std::{
    fs::{self, File},
    io::Write,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_avc::{
    AutonomousVolitionCredential, AvcActionRequest, AvcDecision, AvcRegistryDurableState,
    AvcRegistryRead, AvcRegistryWrite, AvcRevocation, AvcTrustReceipt, AvcValidationRequest,
    AvcValidationResult, InMemoryAvcRegistry, avc_action_signature_payload, create_trust_receipt,
    validate_avc,
};
use exo_core::{Did, ExoError, Hash256, PublicKey, Signature, Timestamp, crypto, hlc::HybridClock};
use exo_root::{RootTrustBundle, verify_root_bundle};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tower::limit::ConcurrencyLimitLayer;

const MAX_AVC_API_BODY_BYTES: usize = 64 * 1024;
const MAX_AVC_API_CONCURRENT_REQUESTS: usize = 64;
pub const AVC_ROOT_TRUST_BUNDLE_ENV: &str = "EXO_AVC_ROOT_TRUST_BUNDLE";
pub const AVC_ROOT_TRUST_CEREMONY_ID: &str = "avc-exo-ceremony-2026";
pub const AVC_ROOT_TRUST_BUNDLE_ID_HEX: &str =
    "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58";
pub const AVC_ROOT_TRUST_ISSUER_DID: &str = "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX";
pub const AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX: &str =
    "6b765381964de7f74e77e4f9d265105f415e58722d19ff71603f62c31d5aff32";
pub const AVC_RECEIPT_HLC_PHYSICAL_MS_FILE_ENV: &str = "EXO_AVC_RECEIPT_HLC_PHYSICAL_MS_FILE";
const AVC_REGISTRY_DURABLE_STATE_FILE: &str = "avc-registry.cbor";
const AVC_REGISTRY_POSTGRES_TABLE: &str = "avc_registry_state";
const AVC_REGISTRY_POSTGRES_KEY: &str = "default";
const AVC_REGISTRY_POSTGRES_LOCK_KEY: i64 = 0x4156_435F_5245_4749;

pub type AvcReceiptSigner = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;
type AvcReceiptTimestampSource = Arc<dyn Fn() -> anyhow::Result<Timestamp> + Send + Sync>;

#[derive(Clone)]
enum AvcRegistryDurability {
    #[cfg(test)]
    None,
    File(Arc<PathBuf>),
    Postgres(PgPool),
}

/// Shared state for AVC route handlers.
#[derive(Clone)]
pub struct AvcApiState {
    pub registry: Arc<Mutex<InMemoryAvcRegistry>>,
    validator_did: Did,
    receipt_signer: AvcReceiptSigner,
    receipt_timestamp_source: AvcReceiptTimestampSource,
    durability: AvcRegistryDurability,
}

impl AvcApiState {
    /// Wrap a fresh registry in the standard `Arc<Mutex<_>>` envelope.
    #[cfg(test)]
    #[must_use]
    pub fn new(validator_did: Did, receipt_signer: AvcReceiptSigner) -> Self {
        Self::new_with_receipt_timestamp_source(
            validator_did,
            receipt_signer,
            receipt_timestamp_source_from_clock(HybridClock::new()),
        )
    }

    #[cfg(test)]
    fn new_with_receipt_timestamp_source(
        validator_did: Did,
        receipt_signer: AvcReceiptSigner,
        receipt_timestamp_source: AvcReceiptTimestampSource,
    ) -> Self {
        Self {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
            validator_did,
            receipt_signer,
            receipt_timestamp_source,
            durability: AvcRegistryDurability::None,
        }
    }

    /// Open the AVC registry with durable runtime-record persistence.
    ///
    /// Credentials, revocations, and receipts are restored from the configured
    /// Postgres database when available, otherwise from the node data directory.
    /// Public-key trust anchors are intentionally reloaded separately from
    /// verified startup configuration.
    pub async fn with_durable_registry(
        data_dir: &FsPath,
        validator_did: Did,
        receipt_signer: AvcReceiptSigner,
        database_pool: Option<PgPool>,
    ) -> anyhow::Result<Self> {
        let durable_state_path = data_dir.join(AVC_REGISTRY_DURABLE_STATE_FILE);
        let (registry, durability) = match database_pool {
            Some(pool) => {
                let registry =
                    load_postgres_durable_registry_or_import_file(&pool, &durable_state_path)
                        .await?;
                (registry, AvcRegistryDurability::Postgres(pool))
            }
            None => (
                load_file_durable_registry(&durable_state_path)?,
                AvcRegistryDurability::File(Arc::new(durable_state_path)),
            ),
        };
        Self::with_durable_registry_and_receipt_timestamp_source(
            registry,
            durability,
            validator_did,
            receipt_signer,
            configured_receipt_timestamp_source()?,
        )
    }

    fn with_durable_registry_and_receipt_timestamp_source(
        registry: InMemoryAvcRegistry,
        durability: AvcRegistryDurability,
        validator_did: Did,
        receipt_signer: AvcReceiptSigner,
        receipt_timestamp_source: AvcReceiptTimestampSource,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            registry: Arc::new(Mutex::new(registry)),
            validator_did,
            receipt_signer,
            receipt_timestamp_source,
            durability,
        })
    }
}

fn configured_receipt_timestamp_source() -> anyhow::Result<AvcReceiptTimestampSource> {
    match std::env::var(AVC_RECEIPT_HLC_PHYSICAL_MS_FILE_ENV) {
        Ok(raw_path) => {
            let trimmed_path = raw_path.trim();
            if trimmed_path.is_empty() {
                anyhow::bail!(
                    "{AVC_RECEIPT_HLC_PHYSICAL_MS_FILE_ENV} must name a trusted HLC physical-ms file"
                );
            }
            Ok(receipt_timestamp_source_from_physical_ms_file(
                PathBuf::from(trimmed_path),
            ))
        }
        Err(std::env::VarError::NotPresent) => {
            #[cfg(test)]
            {
                Ok(receipt_timestamp_source_from_clock(HybridClock::new()))
            }
            #[cfg(not(test))]
            {
                anyhow::bail!(
                    "trusted AVC receipt HLC source unavailable; set \
                    {AVC_RECEIPT_HLC_PHYSICAL_MS_FILE_ENV} to a file containing current trusted HLC physical milliseconds"
                );
            }
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{AVC_RECEIPT_HLC_PHYSICAL_MS_FILE_ENV} is not valid Unicode");
        }
    }
}

fn receipt_timestamp_source_from_physical_ms_file(path: PathBuf) -> AvcReceiptTimestampSource {
    receipt_timestamp_source_from_clock(HybridClock::with_fallible_wall_clock(move || {
        let raw = fs::read_to_string(&path).map_err(|error| ExoError::ClockUnavailable {
            reason: format!(
                "failed to read AVC receipt HLC physical-ms file at {}: {error}",
                path.display()
            ),
        })?;
        let physical_ms =
            raw.trim()
                .parse::<u64>()
                .map_err(|error| ExoError::ClockUnavailable {
                    reason: format!(
                        "failed to parse AVC receipt HLC physical milliseconds from {}: {error}",
                        path.display()
                    ),
                })?;
        if physical_ms == 0 {
            return Err(ExoError::ClockUnavailable {
                reason: format!(
                    "AVC receipt HLC physical-ms file at {} must contain a nonzero value",
                    path.display()
                ),
            });
        }
        Ok(physical_ms)
    }))
}

fn receipt_timestamp_source_from_clock(clock: HybridClock) -> AvcReceiptTimestampSource {
    let clock = Arc::new(Mutex::new(clock));
    Arc::new(move || {
        let mut clock = clock
            .lock()
            .map_err(|_| anyhow::anyhow!("AVC receipt HLC mutex poisoned"))?;
        clock
            .now()
            .map_err(|error| anyhow::anyhow!("AVC receipt HLC unavailable: {error}"))
    })
}

fn load_file_durable_registry(path: &FsPath) -> anyhow::Result<InMemoryAvcRegistry> {
    if !path.exists() {
        return Ok(InMemoryAvcRegistry::new());
    }
    let bytes = fs::read(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to read AVC durable registry at {}: {error}",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        anyhow::bail!("AVC durable registry at {} is empty", path.display());
    }
    decode_durable_registry_bytes(&bytes, &format!("{}", path.display()))
}

fn decode_durable_registry_bytes(
    bytes: &[u8],
    location: &str,
) -> anyhow::Result<InMemoryAvcRegistry> {
    let state: AvcRegistryDurableState = ciborium::from_reader(bytes).map_err(|error| {
        anyhow::anyhow!("failed to decode AVC durable registry at {location}: {error}")
    })?;
    InMemoryAvcRegistry::from_durable_state(state).map_err(|error| {
        anyhow::anyhow!("failed to validate AVC durable registry at {location}: {error}")
    })
}

fn durable_state_has_runtime_records(state: &AvcRegistryDurableState) -> bool {
    !(state.credentials.is_empty() && state.revocations.is_empty() && state.receipts.is_empty())
}

fn encode_durable_registry_state(state: &AvcRegistryDurableState) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(state, &mut bytes)
        .map_err(|error| anyhow::anyhow!("failed to encode AVC durable registry: {error}"))?;
    Ok(bytes)
}

fn persist_file_durable_registry_state(
    state: &AvcRegistryDurableState,
    path: &FsPath,
) -> anyhow::Result<()> {
    let bytes = encode_durable_registry_state(state)?;

    let tmp_path = path.with_extension("cbor.tmp");
    {
        let mut file = File::create(&tmp_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to create AVC durable registry temp file at {}: {error}",
                tmp_path.display()
            )
        })?;
        file.write_all(&bytes).map_err(|error| {
            anyhow::anyhow!(
                "failed to write AVC durable registry temp file at {}: {error}",
                tmp_path.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            anyhow::anyhow!(
                "failed to sync AVC durable registry temp file at {}: {error}",
                tmp_path.display()
            )
        })?;
    }

    fs::rename(&tmp_path, path).map_err(|error| {
        anyhow::anyhow!(
            "failed to install AVC durable registry at {}: {error}",
            path.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        let dir = File::open(parent).map_err(|error| {
            anyhow::anyhow!(
                "failed to open AVC durable registry directory {}: {error}",
                parent.display()
            )
        })?;
        dir.sync_all().map_err(|error| {
            anyhow::anyhow!(
                "failed to sync AVC durable registry directory {}: {error}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

async fn begin_postgres_registry_transaction(
    pool: &PgPool,
) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await.map_err(|error| {
        anyhow::anyhow!("failed to begin AVC Postgres registry transaction: {error}")
    })?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AVC_REGISTRY_POSTGRES_LOCK_KEY)
        .execute(&mut *transaction)
        .await
        .map_err(|error| anyhow::anyhow!("failed to lock AVC Postgres registry state: {error}"))?;
    Ok(transaction)
}

async fn load_postgres_durable_registry_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<Option<InMemoryAvcRegistry>> {
    let statement = format!(
        "SELECT state_cbor FROM {AVC_REGISTRY_POSTGRES_TABLE} WHERE registry_key = $1 FOR UPDATE"
    );
    let Some(row) = sqlx::query(&statement)
        .bind(AVC_REGISTRY_POSTGRES_KEY)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| anyhow::anyhow!("failed to load AVC Postgres registry state: {error}"))?
    else {
        return Ok(None);
    };

    let bytes: Vec<u8> = row.try_get("state_cbor").map_err(|error| {
        anyhow::anyhow!("failed to read AVC Postgres registry state bytes: {error}")
    })?;
    if bytes.is_empty() {
        anyhow::bail!("AVC Postgres registry state is empty");
    }
    decode_durable_registry_bytes(&bytes, AVC_REGISTRY_POSTGRES_TABLE).map(Some)
}

async fn persist_postgres_durable_registry_state_in_transaction(
    state: &AvcRegistryDurableState,
    transaction: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<()> {
    let bytes = encode_durable_registry_state(state)?;
    let statement = format!(
        "INSERT INTO {AVC_REGISTRY_POSTGRES_TABLE} (registry_key, state_cbor)
         VALUES ($1, $2)
         ON CONFLICT (registry_key)
         DO UPDATE SET state_cbor = EXCLUDED.state_cbor"
    );
    sqlx::query(&statement)
        .bind(AVC_REGISTRY_POSTGRES_KEY)
        .bind(bytes)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            anyhow::anyhow!("failed to persist AVC Postgres registry state: {error}")
        })?;
    Ok(())
}

async fn persist_postgres_durable_registry_state(
    state: &AvcRegistryDurableState,
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut transaction = begin_postgres_registry_transaction(pool).await?;
    persist_postgres_durable_registry_state_in_transaction(state, &mut transaction).await?;
    transaction.commit().await.map_err(|error| {
        anyhow::anyhow!("failed to commit AVC Postgres registry state: {error}")
    })?;
    Ok(())
}

async fn load_postgres_durable_registry_or_import_file(
    pool: &PgPool,
    file_path: &FsPath,
) -> anyhow::Result<InMemoryAvcRegistry> {
    let mut transaction = begin_postgres_registry_transaction(pool).await?;
    if let Some(registry) = load_postgres_durable_registry_in_transaction(&mut transaction).await? {
        transaction.commit().await.map_err(|error| {
            anyhow::anyhow!("failed to commit AVC Postgres registry load: {error}")
        })?;
        return Ok(registry);
    }

    let registry = load_file_durable_registry(file_path)?;
    let state = registry.durable_state();
    if durable_state_has_runtime_records(&state) {
        persist_postgres_durable_registry_state_in_transaction(&state, &mut transaction).await?;
        tracing::info!(
            path = %file_path.display(),
            table = AVC_REGISTRY_POSTGRES_TABLE,
            "Imported existing AVC file registry state into Postgres"
        );
    }
    transaction.commit().await.map_err(|error| {
        anyhow::anyhow!("failed to commit AVC Postgres registry import: {error}")
    })?;
    Ok(registry)
}

fn persist_durable_registry(
    registry: &InMemoryAvcRegistry,
    durability: &AvcRegistryDurability,
) -> anyhow::Result<()> {
    let state = registry.durable_state();
    match durability {
        #[cfg(test)]
        AvcRegistryDurability::None => Ok(()),
        AvcRegistryDurability::File(path) => persist_file_durable_registry_state(&state, path),
        AvcRegistryDurability::Postgres(pool) => tokio::runtime::Handle::current()
            .block_on(persist_postgres_durable_registry_state(&state, pool)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTrustIssuerRegistration {
    pub bundle_id: Hash256,
    pub ceremony_id: String,
    pub issuer_did: Did,
    pub issuer_public_key: PublicKey,
}

fn parse_expected_hash(hex_value: &str, label: &str) -> anyhow::Result<Hash256> {
    let bytes = hex::decode(hex_value)
        .map_err(|error| anyhow::anyhow!("invalid {label} hex constant: {error}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "invalid {label} hex constant: expected 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(buf))
}

fn parse_expected_public_key(hex_value: &str, label: &str) -> anyhow::Result<PublicKey> {
    let bytes = hex::decode(hex_value)
        .map_err(|error| anyhow::anyhow!("invalid {label} hex constant: {error}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "invalid {label} hex constant: expected 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(buf))
}

/// Load the configured AVC root trust bundle, verify it in-process, and
/// register the delegated operational issuer public key.
///
/// If `EXO_AVC_ROOT_TRUST_BUNDLE` is absent, no registration is performed.
/// If it is present, any read, parse, verification, or expected-identity
/// mismatch error is fatal to preserve fail-closed production startup.
pub fn load_configured_root_trust_bundle(
    state: &AvcApiState,
) -> anyhow::Result<Option<RootTrustIssuerRegistration>> {
    let Some(path) = std::env::var_os(AVC_ROOT_TRUST_BUNDLE_ENV) else {
        return Ok(None);
    };
    if path.is_empty() {
        anyhow::bail!("{AVC_ROOT_TRUST_BUNDLE_ENV} is set but empty");
    }
    load_root_trust_bundle_from_path(state, FsPath::new(&path)).map(Some)
}

pub fn load_root_trust_bundle_from_path(
    state: &AvcApiState,
    path: &FsPath,
) -> anyhow::Result<RootTrustIssuerRegistration> {
    let bytes = std::fs::read(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to read AVC root trust bundle at {}: {error}",
            path.display()
        )
    })?;
    let bundle: RootTrustBundle = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse AVC root trust bundle at {}: {error}",
            path.display()
        )
    })?;
    verify_root_bundle(&bundle).map_err(|error| {
        anyhow::anyhow!(
            "AVC root trust bundle verification failed for {}: {error}",
            path.display()
        )
    })?;

    if bundle.config.ceremony_id != AVC_ROOT_TRUST_CEREMONY_ID {
        anyhow::bail!(
            "AVC root trust bundle ceremony mismatch: expected {}, got {}",
            AVC_ROOT_TRUST_CEREMONY_ID,
            bundle.config.ceremony_id
        );
    }

    let expected_bundle_id =
        parse_expected_hash(AVC_ROOT_TRUST_BUNDLE_ID_HEX, "AVC root trust bundle id")?;
    if bundle.bundle_id != expected_bundle_id {
        anyhow::bail!(
            "AVC root trust bundle id mismatch: expected {}, got {}",
            expected_bundle_id,
            bundle.bundle_id
        );
    }

    let expected_issuer_did = Did::new(AVC_ROOT_TRUST_ISSUER_DID)
        .map_err(|error| anyhow::anyhow!("invalid AVC root trust issuer DID constant: {error}"))?;
    if bundle.issuer_delegation.issuer_did != expected_issuer_did {
        anyhow::bail!(
            "AVC root trust issuer DID mismatch: expected {}, got {}",
            expected_issuer_did,
            bundle.issuer_delegation.issuer_did
        );
    }

    let expected_public_key = parse_expected_public_key(
        AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX,
        "AVC root trust issuer public key",
    )?;
    if bundle.issuer_delegation.issuer_public_key != expected_public_key {
        anyhow::bail!(
            "AVC root trust issuer public key mismatch for {}",
            expected_issuer_did
        );
    }

    let registration = RootTrustIssuerRegistration {
        bundle_id: bundle.bundle_id,
        ceremony_id: bundle.config.ceremony_id.clone(),
        issuer_did: bundle.issuer_delegation.issuer_did.clone(),
        issuer_public_key: bundle.issuer_delegation.issuer_public_key,
    };

    let mut registry = state.registry.lock().map_err(|_| {
        anyhow::anyhow!("AVC registry unavailable while registering root trust issuer")
    })?;
    registry.put_public_key(
        registration.issuer_did.clone(),
        registration.issuer_public_key,
    );

    Ok(registration)
}

// ---------------------------------------------------------------------------
// Request / Response shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueRequest {
    pub credential: AutonomousVolitionCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueResponse {
    pub credential_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateRequest {
    pub child_credential: AutonomousVolitionCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateResponse {
    pub credential_id: String,
    pub parent_avc_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub revocation: AvcRevocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeResponse {
    pub credential_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmitReceiptRequest {
    pub validation: AvcValidationRequest,
    pub subject_signature: Signature,
    /// Optional subject public key for did:exo values derived from a key.
    /// If the registry already has a trusted key for the actor DID, that
    /// registered key wins and this field is ignored.
    pub subject_public_key: Option<PublicKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmitReceiptResponse {
    pub receipt_hash: String,
    pub receipt: AvcTrustReceipt,
    pub validation: AvcValidationResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvcSummary {
    pub credential_id: String,
    pub subject_did: String,
    pub issuer_did: String,
    pub principal_did: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAvcResponse {
    pub did: String,
    pub credentials: Vec<AvcSummary>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type ApiError = (StatusCode, String);
type ApiResult<T> = Result<T, ApiError>;

fn parse_did(raw: &str) -> ApiResult<Did> {
    Did::new(raw).map_err(|err| {
        tracing::warn!(%err, "rejected malformed AVC DID");
        (StatusCode::BAD_REQUEST, "Invalid DID".into())
    })
}

fn parse_hash(raw: &str) -> ApiResult<Hash256> {
    if !raw
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "credential id must be lowercase hex".into(),
        ));
    }
    let bytes = hex::decode(raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "credential id must be lowercase hex".into(),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "credential id must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(buf))
}

fn persistence_error(err: anyhow::Error) -> ApiError {
    tracing::error!(err = %err, "AVC registry persistence failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "AVC registry persistence failed".into(),
    )
}

fn receipt_timestamp_error(err: anyhow::Error) -> ApiError {
    tracing::error!(err = %err, "AVC receipt timestamp unavailable");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "AVC receipt timestamp unavailable".into(),
    )
}

fn trusted_receipt_timestamp(state: &AvcApiState) -> ApiResult<Timestamp> {
    (state.receipt_timestamp_source)().map_err(receipt_timestamp_error)
}

fn mutate_postgres_registry_blocking<T, F>(
    pool: &PgPool,
    guard: &mut InMemoryAvcRegistry,
    op: F,
) -> ApiResult<T>
where
    F: FnOnce(&mut InMemoryAvcRegistry) -> ApiResult<T>,
{
    let handle = tokio::runtime::Handle::current();
    let mut transaction = handle
        .block_on(begin_postgres_registry_transaction(pool))
        .map_err(persistence_error)?;
    if let Some(fresh_registry) = handle
        .block_on(load_postgres_durable_registry_in_transaction(
            &mut transaction,
        ))
        .map_err(persistence_error)?
    {
        guard
            .apply_durable_state(fresh_registry.durable_state())
            .map_err(|error| {
                persistence_error(anyhow::anyhow!(
                    "failed to apply AVC Postgres registry state: {error}"
                ))
            })?;
    }

    let rollback = guard.clone();
    let result = match op(guard) {
        Ok(result) => result,
        Err(err) => {
            *guard = rollback;
            if let Err(rollback_error) = handle.block_on(transaction.rollback()) {
                tracing::error!(
                    err = %rollback_error,
                    "failed to roll back AVC Postgres registry transaction after rejected operation"
                );
            }
            return Err(err);
        }
    };

    let state = guard.durable_state();
    handle
        .block_on(async {
            persist_postgres_durable_registry_state_in_transaction(&state, &mut transaction)
                .await?;
            transaction.commit().await.map_err(|error| {
                anyhow::anyhow!("failed to commit AVC Postgres registry state: {error}")
            })?;
            Ok::<(), anyhow::Error>(())
        })
        .map_err(|err| {
            *guard = rollback;
            persistence_error(err)
        })?;
    Ok(result)
}

async fn with_registry_blocking<T, F>(
    state: Arc<AvcApiState>,
    persist_after: bool,
    op: F,
) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut InMemoryAvcRegistry) -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut guard = state.registry.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "AVC registry unavailable".into(),
            )
        })?;
        if persist_after {
            if let AvcRegistryDurability::Postgres(pool) = &state.durability {
                return mutate_postgres_registry_blocking(pool, &mut guard, op);
            }
        }
        let rollback = guard.clone();
        let result = match op(&mut guard) {
            Ok(result) => result,
            Err(err) => {
                *guard = rollback;
                return Err(err);
            }
        };
        if persist_after {
            persist_durable_registry(&guard, &state.durability).map_err(|err| {
                *guard = rollback;
                persistence_error(err)
            })?;
        }
        Ok(result)
    })
    .await
    .map_err(|err| {
        tracing::error!(err = %err, "AVC registry task failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "AVC registry task failed".into(),
        )
    })?
}

fn map_avc_error(err: exo_avc::AvcError) -> ApiError {
    tracing::warn!(?err, "AVC operation rejected");
    match err {
        exo_avc::AvcError::EmptyField { .. }
        | exo_avc::AvcError::UnsupportedSchema { .. }
        | exo_avc::AvcError::BasisPointOutOfRange { .. }
        | exo_avc::AvcError::InvalidTimestamp { .. }
        | exo_avc::AvcError::DelegationWidens { .. }
        | exo_avc::AvcError::DelegationRejected { .. }
        | exo_avc::AvcError::InvalidInput { .. } => (StatusCode::BAD_REQUEST, err.to_string()),
        exo_avc::AvcError::Registry { .. } | exo_avc::AvcError::Serialization { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "AVC error".into())
        }
    }
}

fn summary_of(credential: &AutonomousVolitionCredential) -> ApiResult<AvcSummary> {
    let id = credential.id().map_err(map_avc_error)?;
    Ok(AvcSummary {
        credential_id: format!("{id}"),
        subject_did: credential.subject_did.to_string(),
        issuer_did: credential.issuer_did.to_string(),
        principal_did: credential.principal_did.to_string(),
    })
}

fn require_action(request: &AvcValidationRequest) -> ApiResult<&AvcActionRequest> {
    request.action.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "receipt emission requires an action".into(),
    ))
}

fn resolve_subject_public_key(
    registry: &InMemoryAvcRegistry,
    action: &AvcActionRequest,
    supplied_public_key: Option<PublicKey>,
) -> ApiResult<PublicKey> {
    if let Some(public_key) = registry.resolve_public_key(&action.actor_did) {
        return Ok(public_key);
    }

    let Some(public_key) = supplied_public_key else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subject public key is unresolved".into(),
        ));
    };
    let derived_did = crate::identity::did_from_public_key(&public_key).map_err(|err| {
        tracing::warn!(%err, "rejected AVC receipt action public key");
        (
            StatusCode::UNAUTHORIZED,
            "subject public key is not a valid did:exo actor key".into(),
        )
    })?;
    if derived_did != action.actor_did {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subject public key does not match action actor DID".into(),
        ));
    }
    Ok(public_key)
}

fn verify_subject_action_signature(
    registry: &InMemoryAvcRegistry,
    request: &AvcValidationRequest,
    subject_signature: &Signature,
    subject_public_key: Option<PublicKey>,
) -> ApiResult<()> {
    if subject_signature.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "subject action signature must not be empty".into(),
        ));
    }
    let action = require_action(request)?;
    let public_key = resolve_subject_public_key(registry, action, subject_public_key)?;
    let payload = avc_action_signature_payload(&request.credential, action, &request.now)
        .map_err(map_avc_error)?;
    if !crypto::verify(&payload, subject_signature, &public_key) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "subject action signature is invalid".into(),
        ));
    }
    Ok(())
}

fn require_registered_credential(
    registry: &InMemoryAvcRegistry,
    request: &AvcValidationRequest,
) -> ApiResult<Hash256> {
    let credential_id = request.credential.id().map_err(map_avc_error)?;
    let registered = registry
        .get_credential(&credential_id)
        .ok_or((StatusCode::NOT_FOUND, "credential is not registered".into()))?;
    if registered != request.credential {
        return Err((
            StatusCode::BAD_REQUEST,
            "credential does not match registered AVC".into(),
        ));
    }
    Ok(credential_id)
}

fn store_receipt_idempotent(
    registry: &mut InMemoryAvcRegistry,
    receipt: AvcTrustReceipt,
) -> ApiResult<()> {
    let receipt_id = receipt.receipt_id;
    match registry.put_receipt(receipt.clone()) {
        Ok(()) => Ok(()),
        Err(exo_avc::AvcError::Registry { .. })
            if registry.get_receipt(&receipt_id).as_ref() == Some(&receipt) =>
        {
            Ok(())
        }
        Err(err) => Err(map_avc_error(err)),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_issue(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<IssueRequest>,
) -> ApiResult<Json<IssueResponse>> {
    let credential = payload.credential;
    let id = with_registry_blocking(state, true, move |registry| {
        registry.put_credential(credential).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(IssueResponse {
        credential_id: format!("{id}"),
        status: "registered".into(),
    }))
}

async fn handle_validate(
    State(state): State<Arc<AvcApiState>>,
    Json(request): Json<AvcValidationRequest>,
) -> ApiResult<Json<AvcValidationResult>> {
    let result = with_registry_blocking(state, false, move |registry| {
        validate_avc(&request, registry).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(result))
}

async fn handle_emit_receipt(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<EmitReceiptRequest>,
) -> ApiResult<Json<EmitReceiptResponse>> {
    let validator_did = state.validator_did.clone();
    let receipt_signer = Arc::clone(&state.receipt_signer);
    let trusted_now = trusted_receipt_timestamp(&state)?;
    let response = with_registry_blocking(state, true, move |registry| {
        let submitted_request = payload.validation;
        let action_id = require_action(&submitted_request)?.action_id;
        require_registered_credential(registry, &submitted_request)?;
        verify_subject_action_signature(
            registry,
            &submitted_request,
            &payload.subject_signature,
            payload.subject_public_key,
        )?;
        let mut validation_request = submitted_request;
        validation_request.now = trusted_now;
        let validation = validate_avc(&validation_request, registry).map_err(map_avc_error)?;
        if validation.decision != AvcDecision::Allow {
            return Err((
                StatusCode::FORBIDDEN,
                format!("AVC validation denied: {:?}", validation.reason_codes),
            ));
        }
        let receipt = create_trust_receipt(
            &validation,
            Some(action_id),
            validator_did,
            trusted_now,
            |bytes| (receipt_signer)(bytes),
        )
        .map_err(map_avc_error)?;
        store_receipt_idempotent(registry, receipt.clone())?;
        Ok(EmitReceiptResponse {
            receipt_hash: format!("{}", receipt.receipt_id),
            receipt,
            validation,
        })
    })
    .await?;
    Ok(Json(response))
}

async fn handle_delegate(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<DelegateRequest>,
) -> ApiResult<Json<DelegateResponse>> {
    let credential = payload.child_credential;
    let parent_avc_id = credential.parent_avc_id.map(|h| format!("{h}"));
    let id = with_registry_blocking(state, true, move |registry| {
        registry.put_credential(credential).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(DelegateResponse {
        credential_id: format!("{id}"),
        parent_avc_id,
        status: "registered".into(),
    }))
}

async fn handle_revoke(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<RevokeRequest>,
) -> ApiResult<Json<RevokeResponse>> {
    let revocation = payload.revocation;
    let id = revocation.credential_id;
    with_registry_blocking(state, true, move |registry| {
        registry.put_revocation(revocation).map_err(map_avc_error)
    })
    .await?;
    Ok(Json(RevokeResponse {
        credential_id: format!("{id}"),
        status: "revoked".into(),
    }))
}

async fn handle_get(
    State(state): State<Arc<AvcApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<AutonomousVolitionCredential>> {
    let hash = parse_hash(&id)?;
    let credential = with_registry_blocking(state, false, move |registry| {
        registry
            .get_credential(&hash)
            .ok_or((StatusCode::NOT_FOUND, "credential not found".into()))
    })
    .await?;
    Ok(Json(credential))
}

async fn handle_list_for_subject(
    State(state): State<Arc<AvcApiState>>,
    Path(did_str): Path<String>,
) -> ApiResult<Json<ListAvcResponse>> {
    let did = parse_did(&did_str)?;
    let did_for_response = did.to_string();
    let did_for_lookup = did.clone();
    let credentials = with_registry_blocking(state, false, move |registry| {
        let creds = registry.list_credentials_for_subject(&did_for_lookup);
        let mut summaries = Vec::with_capacity(creds.len());
        for c in &creds {
            summaries.push(summary_of(c)?);
        }
        // Deterministic ordering by credential ID.
        summaries.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
        Ok(summaries)
    })
    .await?;
    Ok(Json(ListAvcResponse {
        did: did_for_response,
        credentials,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the AVC API router. POST routes inherit bearer-token auth
/// from the merged write guard in `main.rs`. The validation route returns
/// ordinary AVC denials as `200 OK` with `decision: Deny`; receipt emission
/// returns `403` because no receipt is minted for a denied action.
pub fn avc_router(state: Arc<AvcApiState>) -> Router {
    Router::new()
        .route("/api/v1/avc/issue", post(handle_issue))
        .route("/api/v1/avc/validate", post(handle_validate))
        .route("/api/v1/avc/receipts/emit", post(handle_emit_receipt))
        .route("/api/v1/avc/delegate", post(handle_delegate))
        .route("/api/v1/avc/revoke", post(handle_revoke))
        .route("/api/v1/avc/:id", get(handle_get))
        .route("/api/v1/agents/:did/avcs", get(handle_list_for_subject))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_AVC_API_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_AVC_API_CONCURRENT_REQUESTS))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::{
        body::{self, Body},
        http::{Method, Request},
    };
    use exo_authority::permission::Permission;
    use exo_avc::{
        AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel, AvcActionRequest, AvcConstraints,
        AvcDecision, AvcDraft, AvcReasonCode, AvcRevocationReason, AvcSubjectKind, DelegatedIntent,
        issue_avc, revoke_avc,
    };
    use exo_core::{Hash256, Signature, Timestamp, crypto, crypto::KeyPair};
    use tower::ServiceExt;

    use super::*;

    const ISSUER_SEED: [u8; 32] = [0x11; 32];
    const SUBJECT_SEED: [u8; 32] = [0x22; 32];
    const VALIDATOR_SEED: [u8; 32] = [0x33; 32];

    fn issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ISSUER_SEED).expect("valid seed")
    }

    fn subject_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(SUBJECT_SEED).expect("valid seed")
    }

    fn validator_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(VALIDATOR_SEED).expect("valid seed")
    }

    fn validator_did() -> Did {
        Did::new("did:exo:validator").unwrap()
    }

    fn seed_avc_trust_keys(state: &AvcApiState) {
        let kp = issuer_keypair();
        let did = Did::new("did:exo:issuer").unwrap();
        let mut registry = state.registry.lock().unwrap();
        registry.put_public_key(did, kp.public);
        registry.put_public_key(Did::new("did:exo:agent").unwrap(), subject_keypair().public);
    }

    fn fixed_receipt_timestamp_source(timestamp: Timestamp) -> AvcReceiptTimestampSource {
        Arc::new(move || Ok(timestamp))
    }

    fn fresh_state() -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::new_with_receipt_timestamp_source(
            validator_did(),
            signer,
            fixed_receipt_timestamp_source(Timestamp::new(1_600_000, 0)),
        );
        // Seed the issuer key so validate paths succeed.
        seed_avc_trust_keys(&state);
        Arc::new(state)
    }

    async fn fresh_durable_state(data_dir: &FsPath) -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::with_durable_registry(data_dir, validator_did(), signer, None)
            .await
            .expect("durable AVC state");
        seed_avc_trust_keys(&state);
        Arc::new(state)
    }

    fn fresh_durable_state_with_receipt_timestamp_source(
        data_dir: &FsPath,
        receipt_timestamp_source: AvcReceiptTimestampSource,
    ) -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::with_durable_registry_and_receipt_timestamp_source(
            InMemoryAvcRegistry::new(),
            AvcRegistryDurability::File(Arc::new(data_dir.join(AVC_REGISTRY_DURABLE_STATE_FILE))),
            validator_did(),
            signer,
            receipt_timestamp_source,
        )
        .expect("durable AVC state with trusted receipt timestamp source");
        seed_avc_trust_keys(&state);
        Arc::new(state)
    }

    async fn clear_postgres_avc_registry_state(pool: &PgPool) -> Result<(), sqlx::Error> {
        let statement =
            format!("DELETE FROM {AVC_REGISTRY_POSTGRES_TABLE} WHERE registry_key = $1");
        sqlx::query(&statement)
            .bind(AVC_REGISTRY_POSTGRES_KEY)
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn postgres_avc_test_pool() -> Option<PgPool> {
        if std::env::var("EXO_TEST_AVC_POSTGRES_DURABILITY")
            .ok()
            .as_deref()
            != Some("1")
        {
            return None;
        }
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let pool = exo_gateway::db::init_pool(&database_url).await.ok()?;
        clear_postgres_avc_registry_state(&pool).await.ok()?;
        Some(pool)
    }

    fn baseline_draft() -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: Did::new("did:exo:issuer").unwrap(),
            principal_did: Did::new("did:exo:issuer").unwrap(),
            subject_did: Did::new("did:exo:agent").unwrap(),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: None,
            },
            created_at: Timestamp::new(1_000_000, 0),
            expires_at: Some(Timestamp::new(2_000_000, 0)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([0xAA; 32]),
                purpose: "research".into(),
                allowed_objectives: vec!["primary".into()],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::Draft,
                delegation_allowed: false,
            },
            authority_scope: AuthorityScope {
                permissions: vec![Permission::Read],
                tools: vec![],
                data_classes: vec![],
                counterparties: vec![],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints::permissive(),
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        }
    }

    fn baseline_credential() -> AutonomousVolitionCredential {
        let kp = issuer_keypair();
        issue_avc(baseline_draft(), |bytes| kp.sign(bytes)).unwrap()
    }

    fn credential_for_subject(subject_did: Did) -> AutonomousVolitionCredential {
        let mut draft = baseline_draft();
        draft.subject_did = subject_did;
        let kp = issuer_keypair();
        issue_avc(draft, |bytes| kp.sign(bytes)).unwrap()
    }

    fn credential_with_purpose(purpose: &str) -> AutonomousVolitionCredential {
        let mut draft = baseline_draft();
        draft.delegated_intent.purpose = purpose.into();
        let kp = issuer_keypair();
        issue_avc(draft, |bytes| kp.sign(bytes)).unwrap()
    }

    fn credential_expiring_at(expires_at: Timestamp) -> AutonomousVolitionCredential {
        let mut draft = baseline_draft();
        draft.expires_at = Some(expires_at);
        let kp = issuer_keypair();
        issue_avc(draft, |bytes| kp.sign(bytes)).unwrap()
    }

    fn baseline_action(actor_did: Did) -> AvcActionRequest {
        AvcActionRequest {
            action_id: Hash256::from_bytes([0x55; 32]),
            actor_did,
            requested_permission: Permission::Read,
            tool: None,
            target_did: None,
            data_class: None,
            estimated_budget_minor_units: None,
            estimated_risk_bp: None,
            human_approval: None,
            requires_human_approval: false,
            action_name: None,
        }
    }

    fn sign_action(request: &AvcValidationRequest, keypair: &KeyPair) -> Signature {
        let action = request.action.as_ref().unwrap();
        let payload =
            exo_avc::avc_action_signature_payload(&request.credential, action, &request.now)
                .unwrap();
        keypair.sign(&payload)
    }

    async fn read_body(response: axum::response::Response) -> Vec<u8> {
        body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    fn unreachable_postgres_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://exochain:test@127.0.0.1:1/exochain_test")
            .unwrap()
    }

    async fn issue_credential(app: Router, credential: AutonomousVolitionCredential) -> StatusCode {
        let body = serde_json::to_vec(&IssueRequest { credential }).unwrap();
        app.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/avc/issue")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[test]
    fn durable_state_runtime_record_detection_covers_each_record_kind() {
        assert!(!durable_state_has_runtime_records(
            &AvcRegistryDurableState::default()
        ));

        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
        let mut credential_state = AvcRegistryDurableState::default();
        credential_state
            .credentials
            .insert(credential_id, credential.clone());
        assert!(durable_state_has_runtime_records(&credential_state));

        let mut revocation_state = AvcRegistryDurableState::default();
        revocation_state.revocations.insert(
            credential_id,
            AvcRevocation {
                schema_version: AVC_SCHEMA_VERSION,
                credential_id,
                revoker_did: Did::new("did:exo:issuer").unwrap(),
                reason: AvcRevocationReason::IssuerRevoked,
                created_at: Timestamp::new(2, 0),
                signature: Signature::from_bytes([0x44; 64]),
            },
        );
        assert!(durable_state_has_runtime_records(&revocation_state));

        let validation = AvcValidationResult {
            credential_id,
            decision: AvcDecision::Allow,
            reason_codes: Vec::new(),
            normalized_holder_did: credential.subject_did.clone(),
            valid_until: credential.expires_at,
            receipt: None,
        };
        let receipt = create_trust_receipt(
            &validation,
            None,
            validator_did(),
            Timestamp::new(1_500_000, 0),
            |bytes| validator_keypair().sign(bytes),
        )
        .unwrap();
        let mut receipt_state = AvcRegistryDurableState::default();
        receipt_state.receipts.insert(receipt.receipt_id, receipt);
        assert!(durable_state_has_runtime_records(&receipt_state));
    }

    #[test]
    fn file_durable_registry_round_trips_records_and_rejects_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(AVC_REGISTRY_DURABLE_STATE_FILE);
        let mut registry = InMemoryAvcRegistry::new();
        registry.put_public_key(Did::new("did:exo:issuer").unwrap(), issuer_keypair().public);
        let credential = baseline_credential();
        let credential_id = registry.put_credential(credential.clone()).unwrap();
        let state = registry.durable_state();

        persist_file_durable_registry_state(&state, &path).unwrap();
        let loaded = load_file_durable_registry(&path).unwrap();
        assert_eq!(loaded.credential_count(), 1);
        assert_eq!(loaded.get_credential(&credential_id), Some(credential));
        assert_eq!(
            loaded.resolve_public_key(&Did::new("did:exo:issuer").unwrap()),
            None,
            "durable files must not persist trust anchors"
        );

        let empty_path = dir.path().join("empty.cbor");
        std::fs::write(&empty_path, []).unwrap();
        let empty_error = load_file_durable_registry(&empty_path)
            .unwrap_err()
            .to_string();
        assert!(empty_error.contains("is empty"));

        let corrupt_path = dir.path().join("corrupt.cbor");
        std::fs::write(&corrupt_path, b"not cbor").unwrap();
        let corrupt_error = load_file_durable_registry(&corrupt_path)
            .unwrap_err()
            .to_string();
        assert!(corrupt_error.contains("failed to decode AVC durable registry"));

        let mut invalid_state = AvcRegistryDurableState::default();
        invalid_state
            .credentials
            .insert(Hash256::from_bytes([0x99; 32]), baseline_credential());
        let invalid_bytes = encode_durable_registry_state(&invalid_state).unwrap();
        let invalid_error = decode_durable_registry_bytes(&invalid_bytes, "invalid")
            .unwrap_err()
            .to_string();
        assert!(invalid_error.contains("failed to validate AVC durable registry"));
    }

    #[tokio::test]
    async fn issue_registers_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let cred_id = credential.id().unwrap();
        let body = serde_json::to_vec(&IssueRequest { credential }).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_bytes = read_body(response).await;
        let parsed: IssueResponse = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(parsed.credential_id, format!("{cred_id}"));
        assert_eq!(parsed.status, "registered");
    }

    #[tokio::test]
    async fn durable_registry_restores_issued_credentials_for_receipt_emit_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let state = fresh_durable_state(dir.path()).await;
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
        let body = serde_json::to_vec(&IssueRequest {
            credential: credential.clone(),
        })
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let restarted = fresh_durable_state(dir.path()).await;
        assert_eq!(restarted.registry.lock().unwrap().credential_count(), 1);
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let action_id = request.action.as_ref().unwrap().action_id;
        let body = serde_json::to_vec(&EmitReceiptRequest {
            subject_signature: sign_action(&request, &subject_keypair()),
            validation: request,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&restarted));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: EmitReceiptResponse =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.receipt.credential_id, credential_id);
        assert_eq!(parsed.receipt.action_id, Some(action_id));

        let restarted_again = fresh_durable_state(dir.path()).await;
        assert_eq!(
            restarted_again.registry.lock().unwrap().credential_count(),
            1
        );
        assert_eq!(restarted_again.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn durable_registry_startup_rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(AVC_REGISTRY_DURABLE_STATE_FILE), []).unwrap();
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));

        let error =
            match AvcApiState::with_durable_registry(dir.path(), validator_did(), signer, None)
                .await
            {
                Ok(_) => panic!("empty AVC durable registry file must fail closed at startup"),
                Err(error) => error.to_string(),
            };

        assert!(error.contains("AVC durable registry"));
        assert!(error.contains("is empty"));
    }

    #[tokio::test]
    async fn durable_registry_file_wrapper_restores_successful_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let state = fresh_durable_state(dir.path()).await;
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();

        let stored_id = with_registry_blocking(Arc::clone(&state), true, move |registry| {
            registry.put_credential(credential).map_err(map_avc_error)
        })
        .await
        .unwrap();

        assert_eq!(stored_id, credential_id);
        let reloaded = fresh_durable_state(dir.path()).await;
        let registry = reloaded.registry.lock().unwrap();
        assert_eq!(registry.credential_count(), 1);
        assert!(
            registry.get_credential(&credential_id).is_some(),
            "file durability wrapper must persist accepted registry mutations"
        );
        assert_eq!(
            registry.resolve_public_key(&Did::new("did:exo:issuer").unwrap()),
            Some(issuer_keypair().public),
            "startup trust seeding remains separate from durable records"
        );
    }

    #[tokio::test]
    async fn durable_registry_read_only_access_does_not_create_runtime_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = fresh_durable_state(dir.path()).await;
        let file_path = dir.path().join(AVC_REGISTRY_DURABLE_STATE_FILE);

        let count = with_registry_blocking(Arc::clone(&state), false, |registry| {
            Ok(registry.credential_count())
        })
        .await
        .unwrap();

        assert_eq!(count, 0);
        assert!(
            !file_path.exists(),
            "read-only registry access must not create an empty durable runtime file"
        );
    }

    #[tokio::test]
    async fn postgres_durable_registry_fails_closed_when_database_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let pool = unreachable_postgres_pool();
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let startup_error = match AvcApiState::with_durable_registry(
            dir.path(),
            validator_did(),
            Arc::clone(&signer),
            Some(pool.clone()),
        )
        .await
        {
            Ok(_) => panic!("unreachable Postgres pool must fail closed at AVC startup"),
            Err(error) => error.to_string(),
        };
        assert!(startup_error.contains("failed to begin AVC Postgres registry transaction"));

        let state = AvcApiState {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
            validator_did: validator_did(),
            receipt_signer: signer,
            receipt_timestamp_source: fixed_receipt_timestamp_source(Timestamp::new(1_600_000, 0)),
            durability: AvcRegistryDurability::Postgres(pool.clone()),
        };
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
        let app = avc_router(Arc::clone(&state));
        assert_eq!(
            issue_credential(app, baseline_credential()).await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(state.registry.lock().unwrap().credential_count(), 0);

        let persist_error = tokio::task::spawn_blocking(move || {
            persist_durable_registry(
                &InMemoryAvcRegistry::new(),
                &AvcRegistryDurability::Postgres(pool),
            )
            .unwrap_err()
            .to_string()
        })
        .await
        .unwrap();
        assert!(persist_error.contains("failed to begin AVC Postgres registry transaction"));
    }

    #[tokio::test]
    async fn postgres_durable_registry_preserves_trust_anchors_across_multiple_mutations() {
        let pool = match postgres_avc_test_pool().await {
            Some(pool) => pool,
            None => return,
        };
        let dir = tempfile::tempdir().unwrap();
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::with_durable_registry(
            dir.path(),
            validator_did(),
            Arc::clone(&signer),
            Some(pool.clone()),
        )
        .await
        .expect("Postgres AVC state");
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
        let app = avc_router(Arc::clone(&state));

        let first = credential_with_purpose("postgres anchor persistence one");
        let second = credential_with_purpose("postgres anchor persistence two");
        assert_eq!(
            issue_credential(app.clone(), first).await,
            StatusCode::OK,
            "first Postgres-backed issue must persist"
        );
        assert_eq!(
            issue_credential(app.clone(), second.clone()).await,
            StatusCode::OK,
            "second Postgres-backed issue must not wipe issuer trust anchors"
        );

        {
            let registry = state.registry.lock().unwrap();
            assert_eq!(registry.credential_count(), 2);
            assert_eq!(
                registry.resolve_public_key(&Did::new("did:exo:issuer").unwrap()),
                Some(issuer_keypair().public)
            );
            assert_eq!(
                registry.resolve_public_key(&Did::new("did:exo:agent").unwrap()),
                Some(subject_keypair().public)
            );
        }

        let request = AvcValidationRequest {
            credential: second,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "receipt emission after the second Postgres mutation must still resolve subject keys"
        );

        let reloaded = AvcApiState::with_durable_registry(
            dir.path(),
            validator_did(),
            signer,
            Some(pool.clone()),
        )
        .await
        .expect("reloaded Postgres AVC state");
        seed_avc_trust_keys(&reloaded);
        assert_eq!(reloaded.registry.lock().unwrap().credential_count(), 2);
        assert_eq!(reloaded.registry.lock().unwrap().receipt_count(), 1);
        clear_postgres_avc_registry_state(&pool)
            .await
            .expect("clean up Postgres AVC state");
    }

    #[tokio::test]
    async fn durable_registry_rolls_back_issue_when_persistence_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = fresh_durable_state(dir.path()).await;
        std::fs::remove_dir_all(dir.path()).unwrap();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let body = serde_json::to_vec(&IssueRequest { credential }).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            state.registry.lock().unwrap().credential_count(),
            0,
            "failed persistence must not leave an in-memory credential that callers think was rejected"
        );
    }

    #[tokio::test]
    async fn registry_operation_error_rolls_back_in_memory_mutation() {
        let state = fresh_state();
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
        let error = with_registry_blocking(Arc::clone(&state), false, move |registry| {
            registry.put_credential(credential).unwrap();
            Err::<(), _>((StatusCode::BAD_REQUEST, "synthetic rejection".into()))
        })
        .await
        .unwrap_err();

        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(
            state
                .registry
                .lock()
                .unwrap()
                .get_credential(&credential_id)
                .is_none()
        );
    }

    #[tokio::test]
    async fn registry_task_fails_closed_when_mutex_is_poisoned() {
        let state = fresh_state();
        let registry = Arc::clone(&state.registry);
        let _ = std::panic::catch_unwind(move || {
            let _guard = registry.lock().unwrap();
            panic!("poison AVC registry mutex for fail-closed test");
        });

        let error = with_registry_blocking(state, false, |_registry| Ok(()))
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.1, "AVC registry unavailable");
    }

    #[tokio::test]
    async fn registry_task_panic_fails_closed() {
        let state = fresh_state();
        let error = with_registry_blocking(state, false, |_registry| -> ApiResult<()> {
            panic!("synthetic AVC registry worker panic")
        })
        .await
        .unwrap_err();

        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.1, "AVC registry task failed");
    }

    #[tokio::test]
    async fn issue_rejects_invalid_issuer_signature_without_storing_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let mut credential = baseline_credential();
        credential.delegated_intent.purpose = "tampered after signing".into();
        let forged_id = credential.id().unwrap();
        let body = serde_json::to_vec(&IssueRequest { credential }).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let registry = state.registry.lock().unwrap();
        assert_eq!(
            registry.credential_count(),
            0,
            "invalid issuer signatures must not be stored"
        );
        assert!(
            registry.get_credential(&forged_id).is_none(),
            "forged credential id must remain absent"
        );
    }

    #[tokio::test]
    async fn issue_rejects_unknown_issuer_without_storing_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let mut credential = baseline_credential();
        credential.issuer_did = Did::new("did:exo:unknown-issuer").unwrap();
        let forged_id = credential.id().unwrap();
        let body = serde_json::to_vec(&IssueRequest { credential }).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let registry = state.registry.lock().unwrap();
        assert_eq!(
            registry.credential_count(),
            0,
            "unresolved issuers must not be stored"
        );
        assert!(
            registry.get_credential(&forged_id).is_none(),
            "unknown-issuer credential id must remain absent"
        );
    }

    #[tokio::test]
    async fn delegate_rejects_invalid_child_signature_without_storing_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let mut credential = baseline_credential();
        credential.parent_avc_id = Some(Hash256::from_bytes([0x42; 32]));
        credential.delegated_intent.purpose = "tampered delegated purpose".into();
        let forged_id = credential.id().unwrap();
        let body = serde_json::to_vec(&DelegateRequest {
            child_credential: credential,
        })
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/delegate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let registry = state.registry.lock().unwrap();
        assert_eq!(
            registry.credential_count(),
            0,
            "invalid delegated credentials must not be stored"
        );
        assert!(
            registry.get_credential(&forged_id).is_none(),
            "forged delegated credential id must remain absent"
        );
    }

    #[tokio::test]
    async fn delegate_registers_valid_child_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let mut draft = baseline_draft();
        let parent_id = Hash256::from_bytes([0x42; 32]);
        draft.parent_avc_id = Some(parent_id);
        let credential = {
            let kp = issuer_keypair();
            issue_avc(draft, |bytes| kp.sign(bytes)).unwrap()
        };
        let credential_id = credential.id().unwrap();
        let body = serde_json::to_vec(&DelegateRequest {
            child_credential: credential,
        })
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/delegate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: DelegateResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.credential_id, format!("{credential_id}"));
        assert_eq!(parsed.parent_avc_id, Some(format!("{parent_id}")));
        assert_eq!(parsed.status, "registered");
        assert_eq!(state.registry.lock().unwrap().credential_count(), 1);
    }

    #[tokio::test]
    async fn delegate_response_omits_parent_when_credential_is_root() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
        let body = serde_json::to_vec(&DelegateRequest {
            child_credential: credential,
        })
        .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/delegate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: DelegateResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.credential_id, format!("{credential_id}"));
        assert_eq!(parsed.parent_avc_id, None);
        assert_eq!(parsed.status, "registered");
    }

    #[tokio::test]
    async fn validate_returns_allow_for_valid_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_bytes = read_body(response).await;
        let parsed: AvcValidationResult = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(parsed.decision, AvcDecision::Allow);
    }

    #[tokio::test]
    async fn validate_returns_structured_deny_for_unsigned_credential() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let mut credential = baseline_credential();
        credential.signature = Signature::empty();
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&request).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: AvcValidationResult =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.decision, AvcDecision::Deny);
    }

    #[tokio::test]
    async fn receipt_emit_mints_and_stores_node_signed_receipt_for_registered_credential() {
        let state = fresh_state();
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let action_id = request.action.as_ref().unwrap().action_id;
        let subject_signature = sign_action(&request, &subject_keypair());
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request,
            subject_signature,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: EmitReceiptResponse =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(
            parsed.receipt_hash,
            format!("{}", parsed.receipt.receipt_id)
        );
        assert_eq!(parsed.receipt.credential_id, credential_id);
        assert_eq!(parsed.receipt.action_id, Some(action_id));
        assert_eq!(parsed.receipt.validator_did, validator_did());
        assert_eq!(parsed.validation.decision, AvcDecision::Allow);
        assert!(parsed.receipt.verify_id().unwrap());
        let signing_payload = parsed.receipt.signing_payload().unwrap();
        assert!(crypto::verify(
            &signing_payload,
            &parsed.receipt.signature,
            validator_keypair().public_key()
        ));
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn receipt_emit_does_not_stamp_receipt_with_caller_validation_time() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let caller_supplied_now = Timestamp::new(1_500_000, 0);
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: caller_supplied_now,
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: EmitReceiptResponse =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert!(
            parsed.receipt.created_at > caller_supplied_now,
            "node-signed receipts must use a trusted node HLC timestamp, not caller validation.now"
        );
    }

    #[tokio::test]
    async fn receipt_emit_rejects_credential_expired_at_trusted_node_time() {
        let state = fresh_state();
        let credential = credential_expiring_at(Timestamp::new(1_550_000, 0));
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let backdated_now = Timestamp::new(1_500_000, 0);
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: backdated_now,
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn durable_receipt_emit_rejects_backdated_request_with_configured_hlc_file_source() {
        let dir = tempfile::tempdir().unwrap();
        let clock_path = dir.path().join("trusted-avc-receipt-hlc-ms");
        std::fs::write(&clock_path, "1600000\n").unwrap();
        let state = fresh_durable_state_with_receipt_timestamp_source(
            dir.path(),
            receipt_timestamp_source_from_physical_ms_file(clock_path),
        );
        let credential = credential_expiring_at(Timestamp::new(1_550_000, 0));
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let backdated_now = Timestamp::new(1_500_000, 0);
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: backdated_now,
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[test]
    fn receipt_timestamp_source_reads_operator_hlc_physical_ms_file() {
        let dir = tempfile::tempdir().unwrap();
        let clock_path = dir.path().join("trusted-avc-receipt-hlc-ms");
        std::fs::write(&clock_path, "1600000\n").unwrap();
        let source = receipt_timestamp_source_from_physical_ms_file(clock_path.clone());

        assert_eq!(source().unwrap(), Timestamp::new(1_600_000, 0));
        std::fs::write(&clock_path, "1700000\n").unwrap();
        assert_eq!(source().unwrap(), Timestamp::new(1_700_000, 0));
        std::fs::write(&clock_path, "0\n").unwrap();
        let error = source().unwrap_err().to_string();
        assert!(error.contains("AVC receipt HLC unavailable"));
        assert!(error.contains("must contain a nonzero value"));
    }

    #[tokio::test]
    async fn receipt_emit_is_idempotent_for_identical_request() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();
        let app = avc_router(Arc::clone(&state));

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            state.registry.lock().unwrap().receipt_count(),
            1,
            "identical receipt emission requests must remain idempotent"
        );
    }

    #[tokio::test]
    async fn receipt_emit_accepts_derived_subject_public_key_when_registry_key_absent() {
        let state = fresh_state();
        let subject = crate::identity::did_from_public_key(subject_keypair().public_key()).unwrap();
        let credential = credential_for_subject(subject.clone());
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(subject)),
            now: Timestamp::new(1_500_000, 0),
        };
        let subject_signature = sign_action(&request, &subject_keypair());
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request,
            subject_signature,
            subject_public_key: Some(*subject_keypair().public_key()),
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[test]
    fn duplicate_same_receipt_is_idempotent() {
        let mut registry = InMemoryAvcRegistry::new();
        registry.put_public_key(Did::new("did:exo:issuer").unwrap(), issuer_keypair().public);
        let credential = baseline_credential();
        let credential_id = registry.put_credential(credential).unwrap();
        let validation = AvcValidationResult {
            credential_id,
            decision: AvcDecision::Allow,
            reason_codes: Vec::new(),
            normalized_holder_did: Did::new("did:exo:agent").unwrap(),
            valid_until: Some(Timestamp::new(2_000_000, 0)),
            receipt: None,
        };
        let receipt = create_trust_receipt(
            &validation,
            Some(Hash256::from_bytes([0x55; 32])),
            validator_did(),
            Timestamp::new(1_500_000, 0),
            |bytes| validator_keypair().sign(bytes),
        )
        .unwrap();

        store_receipt_idempotent(&mut registry, receipt.clone()).unwrap();
        store_receipt_idempotent(&mut registry, receipt).unwrap();
        assert_eq!(registry.receipt_count(), 1);
    }

    #[test]
    fn invalid_receipt_storage_maps_to_client_error_without_state_change() {
        let validation = AvcValidationResult {
            credential_id: Hash256::from_bytes([0x88; 32]),
            decision: AvcDecision::Allow,
            reason_codes: Vec::new(),
            normalized_holder_did: Did::new("did:exo:agent").unwrap(),
            valid_until: Some(Timestamp::new(2_000_000, 0)),
            receipt: None,
        };
        let receipt = create_trust_receipt(
            &validation,
            None,
            validator_did(),
            Timestamp::new(1_500_000, 0),
            |bytes| validator_keypair().sign(bytes),
        )
        .unwrap();
        let mut registry = InMemoryAvcRegistry::new();

        let error = store_receipt_idempotent(&mut registry, receipt).unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(registry.receipt_count(), 0);
    }

    #[test]
    fn internal_avc_errors_are_redacted_for_clients() {
        let registry_error = map_avc_error(exo_avc::AvcError::Registry {
            reason: "duplicate".into(),
        });
        assert_eq!(
            registry_error,
            (StatusCode::INTERNAL_SERVER_ERROR, "AVC error".into())
        );

        let serialization_error = map_avc_error(exo_avc::AvcError::Serialization {
            reason: "cbor".into(),
        });
        assert_eq!(
            serialization_error,
            (StatusCode::INTERNAL_SERVER_ERROR, "AVC error".into())
        );
    }

    #[test]
    fn client_avc_errors_preserve_rejection_context() {
        let cases = vec![
            exo_avc::AvcError::EmptyField { field: "purpose" },
            exo_avc::AvcError::UnsupportedSchema {
                got: 99,
                supported: 1,
            },
            exo_avc::AvcError::BasisPointOutOfRange {
                field: "risk",
                value: 10_001,
            },
            exo_avc::AvcError::InvalidTimestamp {
                reason: "expired".into(),
            },
            exo_avc::AvcError::DelegationWidens {
                dimension: "permissions",
            },
            exo_avc::AvcError::DelegationRejected {
                reason: "missing parent".into(),
            },
            exo_avc::AvcError::InvalidInput {
                reason: "malformed".into(),
            },
        ];

        for err in cases {
            let (status, body) = map_avc_error(err);
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!body.is_empty());
        }
    }

    #[test]
    fn hash_parser_requires_canonical_lowercase_hex() {
        let uppercase_id = "AA".repeat(32);
        let uppercase_error = parse_hash(&uppercase_id).unwrap_err();
        assert_eq!(
            uppercase_error,
            (
                StatusCode::BAD_REQUEST,
                "credential id must be lowercase hex".into()
            )
        );

        let short_error = parse_hash("11").unwrap_err();
        assert_eq!(
            short_error,
            (
                StatusCode::BAD_REQUEST,
                "credential id must be 32 bytes (64 hex chars)".into()
            )
        );
    }

    #[test]
    fn receipt_signature_requires_action_before_key_resolution() {
        let request = AvcValidationRequest {
            credential: baseline_credential(),
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let registry = InMemoryAvcRegistry::new();

        let error = verify_subject_action_signature(
            &registry,
            &request,
            &Signature::from_bytes([0x44; 64]),
            None,
        )
        .unwrap_err();

        assert_eq!(
            error,
            (
                StatusCode::BAD_REQUEST,
                "receipt emission requires an action".into()
            )
        );
    }

    #[test]
    fn api_error_helpers_are_deterministic_and_redacted() {
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        let summary = summary_of(&credential).unwrap();
        assert_eq!(summary.credential_id, format!("{id}"));
        assert_eq!(summary.subject_did, "did:exo:agent");
        assert_eq!(summary.issuer_did, "did:exo:issuer");
        assert_eq!(summary.principal_did, "did:exo:issuer");

        let persistence = persistence_error(anyhow::anyhow!("database DSN"));
        assert_eq!(
            persistence,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "AVC registry persistence failed".into()
            )
        );
    }

    #[tokio::test]
    async fn receipt_emit_registry_subject_key_wins_over_supplied_public_key() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let attacker_keypair = KeyPair::from_secret_bytes([0x44; 32]).unwrap();
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &attacker_keypair),
            subject_public_key: Some(*attacker_keypair.public_key()),
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_missing_action_without_receipt() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request,
            subject_signature: Signature::from_bytes([0x77; 64]),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_missing_subject_public_key_without_receipt() {
        let state = fresh_state();
        let subject = crate::identity::did_from_public_key(subject_keypair().public_key()).unwrap();
        let credential = credential_for_subject(subject.clone());
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(subject)),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request,
            subject_signature: Signature::from_bytes([0x77; 64]),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_mismatched_supplied_subject_key_without_receipt() {
        let state = fresh_state();
        let subject = Did::new("did:exo:detached-agent").unwrap();
        let credential = credential_for_subject(subject.clone());
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(subject)),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: Some(*subject_keypair().public_key()),
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_unregistered_credential_without_receipt() {
        let state = fresh_state();
        let credential = baseline_credential();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            subject_signature: sign_action(&request, &subject_keypair()),
            validation: request,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_invalid_subject_signature_without_receipt() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request,
            subject_signature: Signature::from_bytes([0x99; 64]),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_empty_subject_signature_without_receipt() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = AvcValidationRequest {
            credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request,
            subject_signature: Signature::empty(),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_denied_validation_without_receipt() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut action = baseline_action(Did::new("did:exo:agent").unwrap());
        action.requested_permission = Permission::Write;
        let request = AvcValidationRequest {
            credential,
            action: Some(action),
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&EmitReceiptRequest {
            subject_signature: sign_action(&request, &subject_keypair()),
            validation: request,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn validate_rejects_caller_claimed_human_approval_without_evidence() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let mut draft = baseline_draft();
        draft.constraints.human_approval_required = true;
        let credential = {
            let kp = issuer_keypair();
            issue_avc(draft, |bytes| kp.sign(bytes)).unwrap()
        };
        let action = AvcActionRequest {
            action_id: Hash256::from_bytes([0x55; 32]),
            actor_did: credential.subject_did.clone(),
            requested_permission: Permission::Read,
            tool: None,
            target_did: None,
            data_class: None,
            estimated_budget_minor_units: None,
            estimated_risk_bp: None,
            human_approval: None,
            requires_human_approval: true,
            action_name: None,
        };
        let request = AvcValidationRequest {
            credential,
            action: Some(action),
            now: Timestamp::new(1_500_000, 0),
        };
        let mut body_value = serde_json::to_value(&request).unwrap();
        body_value
            .get_mut("action")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("human_approval");
        let body = serde_json::to_vec(&body_value).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: AvcValidationResult =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.decision, AvcDecision::HumanApprovalRequired);
        assert_eq!(
            parsed.reason_codes,
            vec![AvcReasonCode::HumanApprovalMissing]
        );
    }

    #[tokio::test]
    async fn validate_returns_200_with_deny_for_revoked() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        // Pre-register and revoke.
        {
            let kp = issuer_keypair();
            let mut reg = state.registry.lock().unwrap();
            reg.put_credential(credential.clone()).unwrap();
            let revocation = revoke_avc(
                id,
                Did::new("did:exo:issuer").unwrap(),
                AvcRevocationReason::IssuerRevoked,
                Timestamp::new(2, 0),
                |bytes| kp.sign(bytes),
            )
            .unwrap();
            reg.put_revocation(revocation).unwrap();
        }
        let request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let body = serde_json::to_vec(&request).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: AvcValidationResult =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.decision, AvcDecision::Deny);
    }

    #[tokio::test]
    async fn revoke_marks_credential_revoked() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        // Pre-register so we can revoke.
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential)
            .unwrap();
        let kp = issuer_keypair();
        let revocation = revoke_avc(
            id,
            Did::new("did:exo:issuer").unwrap(),
            AvcRevocationReason::IssuerRevoked,
            Timestamp::new(2, 0),
            |bytes| kp.sign(bytes),
        )
        .unwrap();
        let body = serde_json::to_vec(&RevokeRequest { revocation }).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.registry.lock().unwrap().is_revoked(&id));
    }

    #[tokio::test]
    async fn revoke_rejects_unsigned_revocation_without_marking_credential_revoked() {
        let state = fresh_state();
        let app = avc_router(Arc::clone(&state));
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential)
            .unwrap();
        let kp = issuer_keypair();
        let mut revocation = revoke_avc(
            id,
            Did::new("did:exo:issuer").unwrap(),
            AvcRevocationReason::IssuerRevoked,
            Timestamp::new(2, 0),
            |bytes| kp.sign(bytes),
        )
        .unwrap();
        revocation.signature = Signature::empty();

        let body = serde_json::to_vec(&RevokeRequest { revocation }).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !state.registry.lock().unwrap().is_revoked(&id),
            "unsigned revocation must not create a tombstone"
        );
    }

    #[tokio::test]
    async fn get_returns_404_when_unknown() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/{}", "11".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_returns_400_for_short_hex() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_returns_credential_when_known() {
        let state = fresh_state();
        let credential = baseline_credential();
        let id = credential.id().unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: AutonomousVolitionCredential =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed, credential);
    }

    #[tokio::test]
    async fn get_returns_400_for_bad_hex() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_returns_400_for_uppercase_hex() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/{}", "AA".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_returns_400_for_invalid_did() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/agents/not-a-did/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_returns_empty_credentials_for_subject_without_records() {
        let state = fresh_state();
        let app = avc_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/agents/did:exo:agent/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: ListAvcResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.did, "did:exo:agent");
        assert!(parsed.credentials.is_empty());
    }

    #[tokio::test]
    async fn list_returns_credentials_for_subject() {
        let state = fresh_state();
        let credential = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/agents/did:exo:agent/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: ListAvcResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.did, "did:exo:agent");
        assert_eq!(parsed.credentials.len(), 1);
    }

    #[tokio::test]
    async fn list_returns_credentials_in_deterministic_id_order() {
        let state = fresh_state();
        let first = credential_with_purpose("deterministic order first");
        let second = credential_with_purpose("deterministic order second");
        let first_id = first.id().unwrap();
        let second_id = second.id().unwrap();
        {
            let mut registry = state.registry.lock().unwrap();
            registry.put_credential(second).unwrap();
            registry.put_credential(first).unwrap();
        }
        let app = avc_router(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/agents/did:exo:agent/avcs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: ListAvcResponse = serde_json::from_slice(&read_body(response).await).unwrap();
        let mut expected = vec![format!("{first_id}"), format!("{second_id}")];
        expected.sort();
        let actual = parsed
            .credentials
            .into_iter()
            .map(|summary| summary.credential_id)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn expected_root_trust_constants_reject_wrong_lengths() {
        let hash_error = parse_expected_hash("00", "test hash")
            .unwrap_err()
            .to_string();
        assert!(hash_error.contains("expected 32 bytes"));
        let key_error = parse_expected_public_key("00", "test key")
            .unwrap_err()
            .to_string();
        assert!(key_error.contains("expected 32 bytes"));
    }

    #[test]
    fn router_uses_blocking_store_access() {
        let source = include_str!("avc.rs");
        let production = source
            .split("\n// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "AVC handlers must isolate synchronous registry access from Tokio workers"
        );
        assert!(
            production.contains("DefaultBodyLimit::max(MAX_AVC_API_BODY_BYTES)"),
            "AVC router must cap request body size locally"
        );
        assert!(
            production.contains("ConcurrencyLimitLayer::new(MAX_AVC_API_CONCURRENT_REQUESTS)"),
            "AVC router must apply local request admission control"
        );
    }

    #[test]
    fn durable_registry_prefers_postgres_and_keeps_file_fallback() {
        let source = include_str!("avc.rs");
        let production = source
            .split("\n// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        assert!(
            production.contains("database_pool: Option<PgPool>"),
            "AVC durable registry must accept the existing gateway Postgres pool"
        );
        assert!(
            production.contains("AvcRegistryDurability::Postgres(pool)"),
            "AVC durable registry must persist to Postgres when DATABASE_URL is configured"
        );
        assert!(
            production.contains("pg_advisory_xact_lock"),
            "AVC Postgres mutations must use a database transaction lock"
        );
        assert!(
            production.contains("load_postgres_durable_registry_in_transaction"),
            "AVC Postgres mutations must reload current durable state inside the lock"
        );
        assert!(
            production.contains(".apply_durable_state(fresh_registry.durable_state())"),
            "AVC Postgres reload must merge durable records without wiping trust anchors"
        );
        assert!(
            !production.contains("*guard = fresh_registry"),
            "AVC Postgres reload must not replace the full registry and drop startup trust anchors"
        );
        assert!(
            production.contains("load_postgres_durable_registry_or_import_file"),
            "AVC startup must import any existing file-backed state into Postgres"
        );
        assert!(
            production.contains("AvcRegistryDurability::File"),
            "AVC durable registry must keep a no-DATABASE_URL file fallback for local nodes"
        );
        assert!(
            production.contains("configured_receipt_timestamp_source()"),
            "AVC durable registry must use an explicit trusted receipt HLC source"
        );
        assert!(
            production.contains("AVC_RECEIPT_HLC_PHYSICAL_MS_FILE_ENV"),
            "AVC durable registry must expose operator configuration for trusted receipt HLC physical time"
        );
        assert!(
            !production.contains(
                "receipt_timestamp_source: receipt_timestamp_source_from_clock(HybridClock::new())"
            ),
            "AVC durable registry must not use the deterministic default HLC as trusted receipt time"
        );
    }
}

#[cfg(test)]
mod avc_root_trust_tests {
    use exo_avc::AvcRegistryRead;

    use super::*;

    fn avc_state_for_root_trust_test() -> AvcApiState {
        let signer: AvcReceiptSigner = Arc::new(|_| Signature::empty());
        AvcApiState::new(
            Did::new("did:exo:test-validator").expect("test DID"),
            signer,
        )
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crate has workspace root")
            .to_path_buf()
    }

    fn installed_bundle_path() -> std::path::PathBuf {
        repo_root().join("artifacts/trust/avc-exo-ceremony-2026/root-trust-bundle.canonical.json")
    }

    #[test]
    fn avc_root_trust_bundle_loader_registers_expected_issuer() {
        let state = avc_state_for_root_trust_test();
        let registration = load_root_trust_bundle_from_path(&state, &installed_bundle_path())
            .expect("load bundle");
        let expected_did = Did::new(AVC_ROOT_TRUST_ISSUER_DID).expect("expected issuer DID");
        let expected_public_key =
            parse_expected_public_key(AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX, "expected issuer key")
                .expect("expected issuer key");

        assert_eq!(registration.ceremony_id, AVC_ROOT_TRUST_CEREMONY_ID);
        assert_eq!(registration.issuer_did, expected_did);
        assert_eq!(registration.issuer_public_key, expected_public_key);

        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(
            registry.resolve_public_key(&expected_did),
            Some(expected_public_key)
        );
    }

    #[test]
    fn avc_root_trust_bundle_tamper_fails_closed_without_registering_issuer() {
        let mut bundle: RootTrustBundle =
            serde_json::from_slice(&std::fs::read(installed_bundle_path()).expect("read bundle"))
                .expect("parse bundle");
        bundle.transcript_hash = Hash256::from_bytes([42u8; 32]);
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        serde_json::to_writer(temp.as_file(), &bundle).expect("write tampered bundle");

        let state = avc_state_for_root_trust_test();
        let error = load_root_trust_bundle_from_path(&state, temp.path())
            .expect_err("tampered bundle must fail");
        assert!(
            error
                .to_string()
                .contains("AVC root trust bundle verification failed")
        );

        let expected_did = Did::new(AVC_ROOT_TRUST_ISSUER_DID).expect("expected issuer DID");
        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(registry.resolve_public_key(&expected_did), None);
    }

    #[test]
    fn avc_root_trust_bundle_missing_required_path_fails_closed() {
        let state = avc_state_for_root_trust_test();
        let missing = repo_root().join("artifacts/trust/avc-exo-ceremony-2026/missing.json");
        let error = load_root_trust_bundle_from_path(&state, &missing)
            .expect_err("missing configured bundle path must fail");
        assert!(
            error
                .to_string()
                .contains("failed to read AVC root trust bundle")
        );
    }

    #[test]
    fn avc_root_trust_bundle_malformed_json_fails_closed() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(temp.path(), b"not json").expect("write malformed bundle");

        let state = avc_state_for_root_trust_test();
        let error = load_root_trust_bundle_from_path(&state, temp.path())
            .expect_err("malformed configured bundle must fail");
        assert!(
            error
                .to_string()
                .contains("failed to parse AVC root trust bundle")
        );
    }
}
