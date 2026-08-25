// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed HTTP boundary for commitment-only CrossChecked recording.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use exo_api::crosschecked_anchor::{ANCHOR_PATH, MAX_REQUEST_BODY_BYTES};
use exo_core::types::{Hash256, PublicKey, Signature, Timestamp};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::json;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::crosschecked_anchor_store::{
    AnchorConflictKind, AnchorNodeIdentity, AnchorRecordDisposition, AnchorStore,
    AnchorStoreConfig, AnchorStoreError, DurableAnchorSigner, SignOnceError, SubmissionContext,
};

pub const CROSSCHECKED_ANCHOR_BEARER_ENV: &str = "EXOCHAIN_CROSSCHECKED_ANCHOR_BEARER_TOKEN";
pub const CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV: &str =
    "EXOCHAIN_CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE";
pub const CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV: &str =
    "EXOCHAIN_CROSSCHECKED_ANCHOR_INTERMEDIATE_DID";
pub const CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV: &str =
    "EXOCHAIN_CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID";
pub const CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV: &str =
    "EXOCHAIN_CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_HEX";
pub const CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV: &str =
    "EXOCHAIN_CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_HEX";
pub const CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV: &str =
    "EXOCHAIN_CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH";
pub const CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV: &str = "EXOCHAIN_CROSSCHECKED_ANCHOR_NODE_KEY_ID";

const SOURCE_CODE: &str = "crosschecked";
const SIGNER_SCHEMA_VERSION: &str = "crosschecked_anchor_signer_v1";
const BEARER_VERIFIER_CONTEXT: &str = "exochain.crosschecked.anchor.transport_bearer_verifier.v1";

type Clock = Arc<dyn Fn() -> Result<Timestamp, String> + Send + Sync>;
type SignFunction = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;

/// Domain-separated, fixed-size verifier retained instead of the transport
/// bearer. CrossChecked owns the random 256-bit bearer; EXOCHAIN hashes it at
/// startup and never places its plaintext in route or middleware state.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCheckedBearerVerifier([u8; 32]);

impl fmt::Debug for CrossCheckedBearerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossCheckedBearerVerifier([REDACTED])")
    }
}

impl CrossCheckedBearerVerifier {
    /// Derive a verifier from an exact lowercase-hex 256-bit bearer.
    #[must_use]
    pub fn from_bearer(bearer: &str) -> Option<Self> {
        if !is_valid_bearer(bearer) {
            return None;
        }
        Some(Self(blake3::derive_key(
            BEARER_VERIFIER_CONTEXT,
            bearer.as_bytes(),
        )))
    }

    /// Hash a presented bearer under the same domain and compare only the
    /// fixed-size verifiers in constant time.
    #[must_use]
    pub fn verifies(&self, bearer: &str) -> bool {
        let mut candidate = blake3::derive_key(BEARER_VERIFIER_CONTEXT, bearer.as_bytes());
        let matches = constant_time_eq(&candidate, &self.0);
        candidate.zeroize();
        matches
    }
}

#[derive(Clone)]
pub struct CrossCheckedAnchorHttpState {
    store: AnchorStore,
    signer: Arc<dyn DurableAnchorSigner>,
    bearer_verifier: CrossCheckedBearerVerifier,
    clock: Clock,
}

impl fmt::Debug for CrossCheckedAnchorHttpState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCheckedAnchorHttpState")
            .field("store", &self.store)
            .field("signer_identity", &self.signer.identity())
            .field("bearer_verifier", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl CrossCheckedAnchorHttpState {
    /// Construct route state from a verifier after the raw bearer is dropped.
    pub fn new(
        store: AnchorStore,
        signer: Arc<dyn DurableAnchorSigner>,
        bearer_verifier: CrossCheckedBearerVerifier,
        clock: Clock,
    ) -> Self {
        Self {
            store,
            signer,
            bearer_verifier,
            clock,
        }
    }
}

/// Parsed runtime configuration. All fields are required together; an all-
/// absent configuration keeps the route disabled.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCheckedAnchorStartupConfig {
    bearer_verifier: CrossCheckedBearerVerifier,
    expected_audience: String,
    intermediate_did: String,
    intermediate_key_id: String,
    intermediate_public_key: PublicKey,
    governance_frost_group_public_key: [u8; 32],
    governance_frost_key_epoch: u64,
    node_key_id: String,
}

impl fmt::Debug for CrossCheckedAnchorStartupConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossCheckedAnchorStartupConfig")
            .field("bearer_verifier", &"[REDACTED]")
            .field("expected_audience", &self.expected_audience)
            .field("intermediate_did", &self.intermediate_did)
            .field("intermediate_key_id", &self.intermediate_key_id)
            .field("intermediate_public_key", &self.intermediate_public_key)
            .field(
                "governance_frost_key_epoch",
                &self.governance_frost_key_epoch,
            )
            .field("node_key_id", &self.node_key_id)
            .finish()
    }
}

impl CrossCheckedAnchorStartupConfig {
    /// Parse a complete environment snapshot without reading process-global
    /// environment state, making startup policy deterministic and testable.
    ///
    /// # Errors
    /// Fails closed if any field is missing, malformed, or reuses the admin
    /// bearer.
    pub fn from_values(
        admin_bearer: &str,
        values: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, CrossCheckedAnchorStartupError> {
        let names = required_environment_names();
        let present = names
            .iter()
            .filter(|name| values.contains_key(**name))
            .count();
        if present == 0 {
            return Ok(None);
        }
        if present != names.len() {
            return Err(CrossCheckedAnchorStartupError::IncompleteConfiguration);
        }

        let value = |name: &str| {
            values
                .get(name)
                .cloned()
                .ok_or(CrossCheckedAnchorStartupError::IncompleteConfiguration)
        };
        let bearer = Zeroizing::new(value(CROSSCHECKED_ANCHOR_BEARER_ENV)?);
        let bearer_verifier = CrossCheckedBearerVerifier::from_bearer(&bearer)
            .ok_or(CrossCheckedAnchorStartupError::InvalidBearer)?;
        if constant_time_eq(bearer.as_bytes(), admin_bearer.as_bytes()) {
            return Err(CrossCheckedAnchorStartupError::AdminBearerReuse);
        }

        let expected_audience = value(CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV)?;
        if !is_closed_identifier(&expected_audience, 128) {
            return Err(CrossCheckedAnchorStartupError::InvalidField("audience"));
        }
        let intermediate_did = value(CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV)?;
        let intermediate_key_id = value(CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV)?;
        validate_key_id(
            &intermediate_did,
            &intermediate_key_id,
            "intermediate_key_id",
        )?;
        let public_key_hex = value(CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV)?;
        let intermediate_public_key = PublicKey::from_bytes(decode_exact_hex::<32>(
            &public_key_hex,
            "intermediate_public_key",
        )?);
        let governance_frost_group_public_key = decode_exact_hex::<32>(
            &value(CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV)?,
            "governance_frost_group_public_key",
        )?;
        frost_ed25519::VerifyingKey::deserialize(&governance_frost_group_public_key).map_err(
            |_| CrossCheckedAnchorStartupError::InvalidField("governance_frost_group_public_key"),
        )?;
        let governance_frost_key_epoch = value(CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV)?
            .parse::<u64>()
            .map_err(|_| {
                CrossCheckedAnchorStartupError::InvalidField("governance_frost_key_epoch")
            })?;
        if governance_frost_key_epoch == 0 {
            return Err(CrossCheckedAnchorStartupError::InvalidField(
                "governance_frost_key_epoch",
            ));
        }
        let node_key_id = value(CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV)?;
        if node_key_id.is_empty() || node_key_id.len() > 321 {
            return Err(CrossCheckedAnchorStartupError::InvalidField("node_key_id"));
        }

        Ok(Some(Self {
            bearer_verifier,
            expected_audience,
            intermediate_did,
            intermediate_key_id,
            intermediate_public_key,
            governance_frost_group_public_key,
            governance_frost_key_epoch,
            node_key_id,
        }))
    }

    #[must_use]
    pub fn bearer_verifier(&self) -> CrossCheckedBearerVerifier {
        self.bearer_verifier.clone()
    }

    #[must_use]
    pub fn node_key_id(&self) -> &str {
        &self.node_key_id
    }

    #[must_use]
    pub fn store_config(&self, node_did: String, node_public_key: PublicKey) -> AnchorStoreConfig {
        AnchorStoreConfig {
            expected_audience: self.expected_audience.clone(),
            crosschecked_intermediate_did: self.intermediate_did.clone(),
            crosschecked_intermediate_key_id: self.intermediate_key_id.clone(),
            crosschecked_intermediate_public_key: self.intermediate_public_key,
            governance_frost_group_public_key: self.governance_frost_group_public_key,
            governance_frost_key_epoch: self.governance_frost_key_epoch,
            node_identity: AnchorNodeIdentity {
                did: node_did,
                key_id: self.node_key_id.clone(),
                public_key: node_public_key,
            },
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CrossCheckedAnchorStartupError {
    #[error("CrossChecked anchor configuration is incomplete")]
    IncompleteConfiguration,
    #[error("CrossChecked anchor bearer must be exactly 256-bit lowercase hex")]
    InvalidBearer,
    #[error("CrossChecked anchor bearer must not reuse the admin bearer")]
    AdminBearerReuse,
    #[error("invalid CrossChecked anchor configuration field: {0}")]
    InvalidField(&'static str),
}

/// Build the exact commitment-only POST and authenticated readback routes.
pub fn crosschecked_anchor_router(state: CrossCheckedAnchorHttpState) -> Router {
    Router::new()
        .route(ANCHOR_PATH, post(post_anchor))
        .route(&format!("{ANCHOR_PATH}/:action_hash"), get(readback_anchor))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

async fn post_anchor(
    State(state): State<CrossCheckedAnchorHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(status) = authorize(&headers, &state.bearer_verifier) {
        return status.into_response();
    }
    if single_header(&headers, header::CONTENT_TYPE) != Some("application/cbor") {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_content_type");
    }

    let store = state.store.clone();
    let signer = Arc::clone(&state.signer);
    let clock = Arc::clone(&state.clock);
    let body = body.to_vec();
    let result = tokio::task::spawn_blocking(move || {
        let now = clock().map_err(|_| AnchorStoreError::Storage("clock unavailable".into()))?;
        store.record(
            SubmissionContext {
                method: "POST",
                path: ANCHOR_PATH,
                content_type: "application/cbor",
                body: &body,
                now,
            },
            signer.as_ref(),
        )
    })
    .await;

    match result {
        Ok(Ok(record)) => {
            let status = match record.disposition {
                AnchorRecordDisposition::Created => StatusCode::CREATED,
                AnchorRecordDisposition::Replayed => StatusCode::OK,
            };
            (
                status,
                [(header::CONTENT_TYPE, "application/cbor")],
                record.response_body,
            )
                .into_response()
        }
        Ok(Err(error)) => store_error_response(error),
        Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable"),
    }
}

async fn readback_anchor(
    State(state): State<CrossCheckedAnchorHttpState>,
    AxumPath(action_hash): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = authorize(&headers, &state.bearer_verifier) {
        return status.into_response();
    }
    let action_hash = match decode_exact_hex::<32>(&action_hash, "action_hash") {
        Ok(action_hash) => action_hash,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_action_hash"),
    };
    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || store.readback_action(SOURCE_CODE, &action_hash))
        .await
    {
        Ok(Ok(Some(readback))) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/cbor")],
            readback.response_body,
        )
            .into_response(),
        Ok(Ok(None)) => error_response(StatusCode::NOT_FOUND, "anchor_not_found"),
        Ok(Err(_)) | Err(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "readback_unavailable")
        }
    }
}

fn authorize(headers: &HeaderMap, verifier: &CrossCheckedBearerVerifier) -> Result<(), StatusCode> {
    let Some(value) = single_header(headers, header::AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if verifier.verifies(provided) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn store_error_response(error: AnchorStoreError) -> Response {
    match error {
        AnchorStoreError::Conflict(AnchorConflictKind::IdempotencyKey) => {
            error_response(StatusCode::CONFLICT, "idempotency_key_conflict")
        }
        AnchorStoreError::Conflict(AnchorConflictKind::ActionHash) => {
            error_response(StatusCode::CONFLICT, "action_hash_conflict")
        }
        AnchorStoreError::Codec(_) => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        AnchorStoreError::AuthorityValidation(_)
        | AnchorStoreError::AuthorityNotFound
        | AnchorStoreError::AuthorityNotYetValid
        | AnchorStoreError::AuthorityExpired
        | AnchorStoreError::AuthorityRetired => {
            error_response(StatusCode::FORBIDDEN, "authority_rejected")
        }
        AnchorStoreError::Signer(_)
        | AnchorStoreError::Storage(_)
        | AnchorStoreError::GovernanceAuthorization(_)
        | AnchorStoreError::GovernanceAuthorizationConflict
        | AnchorStoreError::ReadbackValidation(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "recording_unavailable")
        }
    }
}

fn error_response(status: StatusCode, error_code: &'static str) -> Response {
    (status, Json(json!({ "error_code": error_code }))).into_response()
}

/// SQLite signature journal binding each operation to one payload and one
/// signature across process restarts.
pub struct SqliteDurableAnchorSigner {
    path: PathBuf,
    identity: AnchorNodeIdentity,
    sign: SignFunction,
}

impl fmt::Debug for SqliteDurableAnchorSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteDurableAnchorSigner")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .field("sign", &"[NON-EXPORTABLE CALLBACK]")
            .finish()
    }
}

impl SqliteDurableAnchorSigner {
    /// Open or create a durable signature journal pinned to one node identity.
    ///
    /// # Errors
    /// Fails closed on inaccessible storage or identity-policy mismatch.
    pub fn open(
        path: impl AsRef<Path>,
        identity: AnchorNodeIdentity,
        sign: SignFunction,
    ) -> Result<Self, SignOnceError> {
        let signer = Self {
            path: path.as_ref().to_path_buf(),
            identity,
            sign,
        };
        signer.initialize()?;
        Ok(signer)
    }

    fn connection(&self) -> Result<Connection, SignOnceError> {
        let connection = Connection::open(&self.path).map_err(signer_storage)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(30))
            .map_err(signer_storage)?;
        connection
            .execute_batch("PRAGMA synchronous = FULL;")
            .map_err(signer_storage)?;
        Ok(connection)
    }

    fn initialize(&self) -> Result<(), SignOnceError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(signer_storage)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS crosschecked_anchor_signer_config (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    node_did TEXT NOT NULL,
                    node_key_id TEXT NOT NULL,
                    node_public_key BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS crosschecked_anchor_signatures (
                    operation_id BLOB PRIMARY KEY,
                    payload_hash BLOB NOT NULL,
                    signature BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS crosschecked_anchor_recorded_at_reservations (
                    request_hash BLOB PRIMARY KEY CHECK (length(request_hash) = 32),
                    node_recorded_physical_ms INTEGER NOT NULL
                        CHECK (node_recorded_physical_ms >= 0),
                    node_recorded_logical INTEGER NOT NULL
                        CHECK (node_recorded_logical >= 0)
                 );",
            )
            .map_err(signer_storage)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO crosschecked_anchor_signer_config
                 (singleton, schema_version, node_did, node_key_id, node_public_key)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    SIGNER_SCHEMA_VERSION,
                    self.identity.did,
                    self.identity.key_id,
                    self.identity.public_key.as_bytes().as_slice(),
                ],
            )
            .map_err(signer_storage)?;
        let stored: (String, String, String, Vec<u8>) = transaction
            .query_row(
                "SELECT schema_version, node_did, node_key_id, node_public_key
                 FROM crosschecked_anchor_signer_config WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(signer_storage)?;
        if stored.0 != SIGNER_SCHEMA_VERSION
            || stored.1 != self.identity.did
            || stored.2 != self.identity.key_id
            || stored.3 != self.identity.public_key.as_bytes()
        {
            return Err(SignOnceError::Unavailable(
                "persistent signer identity policy mismatch".into(),
            ));
        }
        transaction.commit().map_err(signer_storage)
    }
}

impl DurableAnchorSigner for SqliteDurableAnchorSigner {
    fn identity(&self) -> AnchorNodeIdentity {
        self.identity.clone()
    }

    fn reserved_recorded_at(
        &self,
        request_hash: Hash256,
    ) -> Result<Option<Timestamp>, SignOnceError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT node_recorded_physical_ms, node_recorded_logical
                 FROM crosschecked_anchor_recorded_at_reservations
                 WHERE request_hash = ?1",
                [request_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(signer_storage)?
            .map(|(physical_ms, logical)| signer_timestamp(physical_ms, logical))
            .transpose()
    }

    fn reserve_recorded_at(
        &self,
        request_hash: Hash256,
        proposed: Timestamp,
    ) -> Result<Timestamp, SignOnceError> {
        let physical_ms = i64::try_from(proposed.physical_ms).map_err(|_| {
            SignOnceError::Unavailable(
                "node recorded physical timestamp exceeds SQLite INTEGER".into(),
            )
        })?;
        let logical = i64::from(proposed.logical);
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(signer_storage)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO crosschecked_anchor_recorded_at_reservations
                 (request_hash, node_recorded_physical_ms, node_recorded_logical)
                 VALUES (?1, ?2, ?3)",
                params![request_hash.as_bytes().as_slice(), physical_ms, logical],
            )
            .map_err(signer_storage)?;
        let stored = transaction
            .query_row(
                "SELECT node_recorded_physical_ms, node_recorded_logical
                 FROM crosschecked_anchor_recorded_at_reservations
                 WHERE request_hash = ?1",
                [request_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(signer_storage)?;
        let reserved = signer_timestamp(stored.0, stored.1)?;
        transaction.commit().map_err(signer_storage)?;
        Ok(reserved)
    }

    fn sign_once(&self, operation_id: Hash256, payload: &[u8]) -> Result<Signature, SignOnceError> {
        let payload_hash = Hash256::digest(payload);
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(signer_storage)?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT payload_hash, signature FROM crosschecked_anchor_signatures
                 WHERE operation_id = ?1",
                [operation_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(signer_storage)?;
        if let Some((stored_hash, stored_signature)) = existing {
            if stored_hash != payload_hash.as_bytes() {
                return Err(SignOnceError::OperationPayloadConflict);
            }
            let signature = exact_array::<64>(stored_signature, "stored signature")?;
            transaction.commit().map_err(signer_storage)?;
            return Ok(Signature::from_bytes(signature));
        }

        let signature = (self.sign)(payload);
        let signature_bytes = signature.ed25519_bytes().ok_or_else(|| {
            SignOnceError::Unavailable("node signer did not return an Ed25519 signature".into())
        })?;
        transaction
            .execute(
                "INSERT INTO crosschecked_anchor_signatures
                 (operation_id, payload_hash, signature) VALUES (?1, ?2, ?3)",
                params![
                    operation_id.as_bytes().as_slice(),
                    payload_hash.as_bytes().as_slice(),
                    signature_bytes.as_slice(),
                ],
            )
            .map_err(signer_storage)?;
        transaction.commit().map_err(signer_storage)?;
        Ok(signature)
    }
}

fn required_environment_names() -> [&'static str; 8] {
    [
        CROSSCHECKED_ANCHOR_BEARER_ENV,
        CROSSCHECKED_ANCHOR_EXPECTED_AUDIENCE_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_DID_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_KEY_ID_ENV,
        CROSSCHECKED_ANCHOR_INTERMEDIATE_PUBLIC_KEY_ENV,
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_PUBLIC_KEY_ENV,
        CROSSCHECKED_ANCHOR_GOVERNANCE_FROST_KEY_EPOCH_ENV,
        CROSSCHECKED_ANCHOR_NODE_KEY_ID_ENV,
    ]
}

fn is_valid_bearer(bearer: &str) -> bool {
    bearer.len() == 64
        && bearer
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_key_id(
    did: &str,
    key_id: &str,
    field: &'static str,
) -> Result<(), CrossCheckedAnchorStartupError> {
    let prefix = format!("{did}#");
    let fragment = key_id
        .strip_prefix(&prefix)
        .ok_or(CrossCheckedAnchorStartupError::InvalidField(field))?;
    if did.is_empty()
        || did.len() > 256
        || fragment.is_empty()
        || fragment.len() > 64
        || !fragment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CrossCheckedAnchorStartupError::InvalidField(field));
    }
    Ok(())
}

fn is_closed_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn decode_exact_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], CrossCheckedAnchorStartupError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CrossCheckedAnchorStartupError::InvalidField(field));
    }
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| CrossCheckedAnchorStartupError::InvalidField(field))?;
    Ok(bytes)
}

fn exact_array<const N: usize>(bytes: Vec<u8>, field: &str) -> Result<[u8; N], SignOnceError> {
    bytes.try_into().map_err(|_| {
        SignOnceError::Unavailable(format!("{field} has an invalid persistent byte length"))
    })
}

fn signer_storage(error: rusqlite::Error) -> SignOnceError {
    SignOnceError::Unavailable(error.to_string())
}

fn signer_timestamp(physical_ms: i64, logical: i64) -> Result<Timestamp, SignOnceError> {
    let physical_ms = u64::try_from(physical_ms).map_err(|_| {
        SignOnceError::Unavailable("stored node recorded physical timestamp is negative".into())
    })?;
    let logical = u32::try_from(logical).map_err(|_| {
        SignOnceError::Unavailable("stored node recorded logical timestamp is invalid".into())
    })?;
    Ok(Timestamp::new(physical_ms, logical))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}
