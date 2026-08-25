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

//! Persistent, fail-closed CrossChecked commitment recording.
//!
//! This module is intentionally not registered as an HTTP route. It provides
//! the durable authority, idempotency, signature-journal, and authenticated
//! readback boundary required before a route can be activated in a later,
//! separately reviewed change.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use ciborium::Value;
use exo_api::crosschecked_anchor::{
    ANCHOR_PATH, CrossCheckedAnchorResponseV1, RequestValidationContext, ResponseValidationContext,
    decode_and_validate_request, decode_and_validate_response, decode_unverified_replay_locator,
};
use exo_authority::{
    AuthorityChain, Permission,
    chain::{has_permission, verify_chain},
};
use exo_core::{
    crypto,
    types::{Did, Hash256, PublicKey, ReceiptOutcome, Signature, Timestamp, TrustReceipt},
};
use exo_identity::{
    did::{DidDocument, VerificationMethod},
    did_verification::validate_verification_method_document_binding,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCOPE_BINDING_DOMAIN: &str = "exo.crosschecked.scope_binding.v1";
const AUTHORITY_CHAIN_DOMAIN: &str = "exo.crosschecked.authority_chain.v1";
const AUTHORITY_CHAIN_HASH_DOMAIN: &str = "exo.crosschecked.authority_chain_hash.v1";
const RETIREMENT_DOMAIN: &str = "exo.crosschecked.authority_retirement.v1";
const SIGNING_OPERATION_DOMAIN: &str = "exo.crosschecked.signing_operation.v1";
const RECEIPT_ACTION_TYPE: &str = "crosschecked.receipt_commitment.record.v1";
const ANCHOR_PERMISSION_CODE: &str = "anchor_receipt_commitment";
const STORE_SCHEMA_VERSION: &str = "crosschecked_anchor_store_v1";

/// Node identity pinned into both receipt and response signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorNodeIdentity {
    pub did: String,
    pub key_id: String,
    pub public_key: PublicKey,
}

/// Immutable runtime policy persisted at store creation and checked on reopen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorStoreConfig {
    pub expected_audience: String,
    pub crosschecked_intermediate_did: String,
    pub crosschecked_intermediate_key_id: String,
    pub crosschecked_intermediate_public_key: PublicKey,
    pub node_identity: AnchorNodeIdentity,
}

/// Signed binding between one child authority and one opaque workspace scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCheckedScopeBindingV1 {
    pub protocol_version: u16,
    pub authority_did: Did,
    pub authority_key_id: String,
    pub grant_id: [u8; 32],
    pub scope_alias: [u8; 32],
    pub audience: String,
    pub permission: Permission,
    pub key_epoch: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub chain_fingerprint: Hash256,
    pub binding_signer_did: Did,
    pub binding_signer_key_id: String,
    pub signature: Signature,
}

impl CrossCheckedScopeBindingV1 {
    /// Deterministic, map-free CBOR preimage signed by the CrossChecked
    /// intermediate authority.
    ///
    /// # Errors
    /// Returns a serialization error if canonical CBOR encoding fails.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, AnchorStoreError> {
        encode_value(&Value::Array(vec![
            text(SCOPE_BINDING_DOMAIN),
            unsigned(u64::from(self.protocol_version)),
            text(self.authority_did.as_str()),
            text(&self.authority_key_id),
            bytes(&self.grant_id),
            bytes(&self.scope_alias),
            text(&self.audience),
            text(permission_code(self.permission)?),
            unsigned(self.key_epoch),
            unsigned(self.valid_from_ms),
            unsigned(self.valid_until_ms),
            bytes(self.chain_fingerprint.as_bytes()),
            text(self.binding_signer_did.as_str()),
            text(&self.binding_signer_key_id),
        ]))
    }
}

/// Complete owner-authorized provisioning package persisted as one snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityProvisioningV1 {
    pub protocol_version: u16,
    pub did_documents: Vec<DidDocument>,
    pub authority_chain: AuthorityChain,
    pub scope_binding: CrossCheckedScopeBindingV1,
}

impl AuthorityProvisioningV1 {
    /// Encode the exact CBOR bytes persisted by [`AnchorStore::provision_authority`].
    ///
    /// # Errors
    /// Returns a serialization error if CBOR encoding fails.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, AnchorStoreError> {
        encode_serde(self)
    }
}

/// Signed retirement of one exact authority key epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRetirementV1 {
    pub protocol_version: u16,
    pub authority_did: Did,
    pub authority_key_id: String,
    pub key_epoch: u64,
    pub retired_at_ms: u64,
    pub signer_did: Did,
    pub signer_key_id: String,
    pub signature: Signature,
}

impl AuthorityRetirementV1 {
    /// Deterministic, map-free CBOR retirement preimage.
    ///
    /// # Errors
    /// Returns a serialization error if canonical CBOR encoding fails.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, AnchorStoreError> {
        encode_value(&Value::Array(vec![
            text(RETIREMENT_DOMAIN),
            unsigned(u64::from(self.protocol_version)),
            text(self.authority_did.as_str()),
            text(&self.authority_key_id),
            unsigned(self.key_epoch),
            unsigned(self.retired_at_ms),
            text(self.signer_did.as_str()),
            text(&self.signer_key_id),
        ]))
    }

    /// Encode the exact CBOR bytes persisted by [`AnchorStore::retire_authority`].
    ///
    /// # Errors
    /// Returns a serialization error if CBOR encoding fails.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, AnchorStoreError> {
        encode_serde(self)
    }
}

/// A transport-bound submission supplied by a future route adapter.
#[derive(Clone, Copy, Debug)]
pub struct SubmissionContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: &'a str,
    pub body: &'a [u8],
    pub now: Timestamp,
}

/// Whether a response was newly committed or returned from exact durable replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorRecordDisposition {
    Created,
    Replayed,
}

/// Cryptographically validated record returned after commit or exact replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    pub disposition: AnchorRecordDisposition,
    pub request_hash: Hash256,
    pub action_hash: Hash256,
    pub response: CrossCheckedAnchorResponseV1,
    pub response_body: Vec<u8>,
}

/// Cryptographically authenticated stored record returned by readback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedAnchorReadback {
    pub request_body: Vec<u8>,
    pub response: CrossCheckedAnchorResponseV1,
    pub response_body: Vec<u8>,
}

/// Stable idempotency conflict categories suitable for later HTTP 409 mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorConflictKind {
    IdempotencyKey,
    ActionHash,
}

/// Errors from a signer that durably binds one operation ID to one payload.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SignOnceError {
    #[error("durable signer unavailable: {0}")]
    Unavailable(String),
    #[error("signing operation ID was already bound to another payload")]
    OperationPayloadConflict,
}

/// Signer boundary required by the persistence service.
///
/// Implementations must durably journal `operation_id -> payload hash ->
/// signature` before returning. Repeating the same operation and payload must
/// return the same Ed25519 signature without a second signing ceremony;
/// repeating an operation with another payload must fail closed.
pub trait DurableAnchorSigner: Send + Sync {
    fn identity(&self) -> AnchorNodeIdentity;
    fn reserved_recorded_at(
        &self,
        request_hash: Hash256,
    ) -> Result<Option<Timestamp>, SignOnceError>;
    fn reserve_recorded_at(
        &self,
        request_hash: Hash256,
        proposed: Timestamp,
    ) -> Result<Timestamp, SignOnceError>;
    fn sign_once(&self, operation_id: Hash256, payload: &[u8]) -> Result<Signature, SignOnceError>;
}

/// Closed storage and authorization errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AnchorStoreError {
    #[error("anchor codec rejected request or response: {0}")]
    Codec(String),
    #[error("authority validation failed: {0}")]
    AuthorityValidation(String),
    #[error("authority binding was not found")]
    AuthorityNotFound,
    #[error("authority binding is not yet valid")]
    AuthorityNotYetValid,
    #[error("authority binding is expired")]
    AuthorityExpired,
    #[error("authority key epoch is retired")]
    AuthorityRetired,
    #[error("anchor conflict: {0:?}")]
    Conflict(AnchorConflictKind),
    #[error("durable signer failed: {0}")]
    Signer(SignOnceError),
    #[error("storage failure: {0}")]
    Storage(String),
    #[error("authenticated readback failed: {0}")]
    ReadbackValidation(String),
}

/// SQLite-backed store. Each operation opens its own connection so callers
/// may safely share the store across worker threads.
#[derive(Clone, Debug)]
pub struct AnchorStore {
    path: PathBuf,
    config: AnchorStoreConfig,
}

#[derive(Clone, Debug)]
struct ValidatedProvisioning {
    authority_public_key: PublicKey,
    authority_chain_hash: Hash256,
}

#[derive(Clone, Debug)]
struct StoredAuthority {
    provisioning: AuthorityProvisioningV1,
    provisioning_cbor: Vec<u8>,
    authority_public_key: PublicKey,
    authority_chain_hash: Hash256,
    retired_at_ms: Option<u64>,
    retirement_cbor: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct StoredAnchorRow {
    authority_did: String,
    authority_key_id: String,
    idempotency_key: [u8; 32],
    source_code: String,
    action_hash: [u8; 32],
    request_hash: Hash256,
    request_body: Vec<u8>,
    receipt_body: Vec<u8>,
    response_body: Vec<u8>,
    authority_chain_hash: Hash256,
    authority_public_key: PublicKey,
    node_recorded_at: Timestamp,
}

impl AnchorStore {
    /// Open or create the store and bind it to immutable runtime policy.
    ///
    /// # Errors
    /// Fails closed when the path, schema, or previously persisted runtime
    /// policy is unavailable or inconsistent.
    pub fn open(
        path: impl AsRef<Path>,
        config: AnchorStoreConfig,
    ) -> Result<Self, AnchorStoreError> {
        validate_config(&config)?;
        let store = Self {
            path: path.as_ref().to_path_buf(),
            config,
        };
        let connection = store.connection()?;
        initialize_schema(&connection, &store.config)?;
        Ok(store)
    }

    /// Validate and persist a signed DID/chain/scope authority snapshot.
    /// Identical provisioning is idempotent; any replacement under the same
    /// DID/key ID is rejected.
    ///
    /// # Errors
    /// Fails for invalid identity documents, delegation signatures, scope,
    /// key epoch, audience, validity, or persistent conflicts.
    pub fn provision_authority(
        &self,
        provisioning: &AuthorityProvisioningV1,
    ) -> Result<(), AnchorStoreError> {
        let validated = validate_provisioning(&self.config, provisioning)?;
        let provisioning_cbor = provisioning.to_cbor_bytes()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT provisioning_cbor FROM crosschecked_anchor_authorities
                 WHERE authority_did = ?1 AND authority_key_id = ?2",
                params![
                    provisioning.scope_binding.authority_did.as_str(),
                    provisioning.scope_binding.authority_key_id
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(existing) = existing {
            if existing == provisioning_cbor {
                transaction.commit().map_err(storage)?;
                return Ok(());
            }
            return Err(AnchorStoreError::AuthorityValidation(
                "authority DID/key ID already has different provisioning".into(),
            ));
        }

        let max_epoch: Option<i64> = transaction
            .query_row(
                "SELECT MAX(key_epoch) FROM crosschecked_anchor_authorities
                 WHERE authority_did = ?1",
                [provisioning.scope_binding.authority_did.as_str()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if max_epoch.is_some_and(|epoch| {
            u64::try_from(epoch)
                .ok()
                .is_some_and(|epoch| provisioning.scope_binding.key_epoch <= epoch)
        }) {
            return Err(AnchorStoreError::AuthorityValidation(
                "key epoch must increase monotonically".into(),
            ));
        }

        transaction
            .execute(
                "INSERT INTO crosschecked_anchor_authorities (
                    authority_did, authority_key_id, grant_id, scope_alias,
                    audience, permission_code, key_epoch, valid_from_ms,
                    valid_until_ms, retired_at_ms, authority_public_key,
                    authority_chain_hash, provisioning_cbor, retirement_cbor
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12, NULL)",
                params![
                    provisioning.scope_binding.authority_did.as_str(),
                    provisioning.scope_binding.authority_key_id,
                    provisioning.scope_binding.grant_id.as_slice(),
                    provisioning.scope_binding.scope_alias.as_slice(),
                    provisioning.scope_binding.audience,
                    ANCHOR_PERMISSION_CODE,
                    to_i64(provisioning.scope_binding.key_epoch, "key_epoch")?,
                    to_i64(provisioning.scope_binding.valid_from_ms, "valid_from_ms")?,
                    to_i64(provisioning.scope_binding.valid_until_ms, "valid_until_ms")?,
                    validated.authority_public_key.as_bytes().as_slice(),
                    validated.authority_chain_hash.as_bytes().as_slice(),
                    provisioning_cbor,
                ],
            )
            .map_err(|error| {
                AnchorStoreError::AuthorityValidation(format!(
                    "persistent authority uniqueness rejected provisioning: {error}"
                ))
            })?;
        transaction.commit().map_err(storage)
    }

    /// Persist a signed key-epoch retirement. Identical retirement is
    /// idempotent; conflicting retirement evidence is rejected.
    ///
    /// # Errors
    /// Fails if the retirement is not signed by the configured intermediate,
    /// targets another authority epoch, predates the binding, or conflicts
    /// with existing evidence.
    pub fn retire_authority(
        &self,
        retirement: &AuthorityRetirementV1,
    ) -> Result<(), AnchorStoreError> {
        let retirement_cbor = retirement.to_cbor_bytes()?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let authority = load_authority(
            &transaction,
            retirement.authority_did.as_str(),
            &retirement.authority_key_id,
        )?
        .ok_or(AnchorStoreError::AuthorityNotFound)?;
        validate_stored_authority(&self.config, &authority)?;
        validate_retirement(&self.config, &authority.provisioning, retirement)?;

        if let Some(existing_retired_at) = authority.retired_at_ms {
            let existing: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT retirement_cbor FROM crosschecked_anchor_authorities
                     WHERE authority_did = ?1 AND authority_key_id = ?2",
                    params![
                        retirement.authority_did.as_str(),
                        retirement.authority_key_id
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            if existing_retired_at == retirement.retired_at_ms
                && existing.as_deref() == Some(retirement_cbor.as_slice())
            {
                transaction.commit().map_err(storage)?;
                return Ok(());
            }
            return Err(AnchorStoreError::AuthorityValidation(
                "authority epoch already has different retirement evidence".into(),
            ));
        }

        transaction
            .execute(
                "UPDATE crosschecked_anchor_authorities
                 SET retired_at_ms = ?1, retirement_cbor = ?2
                 WHERE authority_did = ?3 AND authority_key_id = ?4",
                params![
                    to_i64(retirement.retired_at_ms, "retired_at_ms")?,
                    retirement_cbor,
                    retirement.authority_did.as_str(),
                    retirement.authority_key_id,
                ],
            )
            .map_err(storage)?;
        transaction.commit().map_err(storage)
    }

    /// Validate, authorize, sign exactly once, and atomically commit one
    /// request/idempotency/receipt/response record. Exact durable replay is
    /// checked before live authority expiry or retirement.
    ///
    /// # Errors
    /// Fails closed for invalid protocol bytes, authority state, conflicts,
    /// signer errors, persistence errors, or failed self-verification.
    pub fn record(
        &self,
        submission: SubmissionContext<'_>,
        signer: &dyn DurableAnchorSigner,
    ) -> Result<AnchorRecord, AnchorStoreError> {
        let locator = decode_unverified_replay_locator(
            submission.body,
            submission.method,
            submission.path,
            submission.content_type,
        )
        .map_err(codec)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;

        if let Some(stored) = load_anchor_by_idempotency(
            &transaction,
            &locator.authority_did,
            &locator.idempotency_key,
        )? {
            if stored.request_body != submission.body {
                return Err(AnchorStoreError::Conflict(
                    AnchorConflictKind::IdempotencyKey,
                ));
            }
            let readback = validate_stored_anchor(&transaction, &self.config, &stored)?;
            transaction.commit().map_err(storage)?;
            return Ok(AnchorRecord {
                disposition: AnchorRecordDisposition::Replayed,
                request_hash: stored.request_hash,
                action_hash: Hash256::from_bytes(stored.action_hash),
                response: readback.response,
                response_body: readback.response_body,
            });
        }

        if load_anchor_by_action(&transaction, &locator.source_code, &locator.action_hash)?
            .is_some()
        {
            return Err(AnchorStoreError::Conflict(AnchorConflictKind::ActionHash));
        }

        let authority = load_authority(
            &transaction,
            &locator.authority_did,
            &locator.authority_key_id,
        )?
        .ok_or(AnchorStoreError::AuthorityNotFound)?;
        validate_stored_authority(&self.config, &authority)?;
        let signer_identity = signer.identity();
        if signer_identity != self.config.node_identity {
            return Err(AnchorStoreError::Signer(SignOnceError::Unavailable(
                "signer identity does not match store policy".into(),
            )));
        }

        let recorded_at = match signer
            .reserved_recorded_at(locator.request_hash)
            .map_err(AnchorStoreError::Signer)?
        {
            Some(recorded_at) => recorded_at,
            None => {
                validate_authority_time(&authority, &locator, submission.now.physical_ms)?;
                let live_validated = decode_and_validate_request(
                    submission.body,
                    RequestValidationContext {
                        method: submission.method,
                        path: submission.path,
                        content_type: submission.content_type,
                        expected_audience: &self.config.expected_audience,
                        now_ms: submission.now.physical_ms,
                        authority_public_key: &authority.authority_public_key,
                    },
                )
                .map_err(codec)?;
                validate_request_binding(
                    &live_validated.request,
                    &authority.provisioning.scope_binding,
                )?;
                signer
                    .reserve_recorded_at(locator.request_hash, submission.now)
                    .map_err(AnchorStoreError::Signer)?
            }
        };

        validate_authority_time(&authority, &locator, recorded_at.physical_ms)?;
        let validated = decode_and_validate_request(
            submission.body,
            RequestValidationContext {
                method: submission.method,
                path: submission.path,
                content_type: submission.content_type,
                expected_audience: &self.config.expected_audience,
                now_ms: recorded_at.physical_ms,
                authority_public_key: &authority.authority_public_key,
            },
        )
        .map_err(codec)?;
        validate_request_binding(&validated.request, &authority.provisioning.scope_binding)?;

        let action_hash = Hash256::from_bytes(validated.request.action_hash);
        let mut receipt = TrustReceipt::new(
            Did::new(&signer_identity.did).map_err(|error| {
                AnchorStoreError::Signer(SignOnceError::Unavailable(error.to_string()))
            })?,
            authority.authority_chain_hash,
            None,
            RECEIPT_ACTION_TYPE.to_owned(),
            action_hash,
            ReceiptOutcome::Executed,
            recorded_at,
            &|_| Signature::empty(),
        )
        .map_err(|error| AnchorStoreError::Signer(SignOnceError::Unavailable(error.to_string())))?;
        let receipt_payload = receipt.signing_payload().map_err(|error| {
            AnchorStoreError::Signer(SignOnceError::Unavailable(error.to_string()))
        })?;
        let receipt_operation = signing_operation_id(validated.request_hash, "receipt")?;
        receipt.signature = signer
            .sign_once(receipt_operation, &receipt_payload)
            .map_err(AnchorStoreError::Signer)?;
        if !receipt
            .verify_signature(&signer_identity.public_key)
            .map_err(|error| {
                AnchorStoreError::Signer(SignOnceError::Unavailable(error.to_string()))
            })?
        {
            return Err(AnchorStoreError::Signer(SignOnceError::Unavailable(
                "receipt signature did not verify with pinned node key".into(),
            )));
        }

        let mut response = CrossCheckedAnchorResponseV1 {
            protocol_version: 1,
            request_hash: validated.request_hash,
            action_hash,
            exochain_receipt: receipt.clone(),
            recording_status: "node_recorded".to_owned(),
            consensus_finality: "not_asserted".to_owned(),
            node_did: signer_identity.did.clone(),
            node_key_id: signer_identity.key_id.clone(),
            node_recorded_at: recorded_at,
            wrapper_signature: [0; 64],
        };
        let wrapper_payload = response.signing_preimage().map_err(codec)?;
        let wrapper_operation = signing_operation_id(validated.request_hash, "response")?;
        response.wrapper_signature = ed25519_bytes(
            signer
                .sign_once(wrapper_operation, &wrapper_payload)
                .map_err(AnchorStoreError::Signer)?,
        )?;
        let response_body = response.to_canonical_cbor().map_err(codec)?;
        let verified_response = decode_and_validate_response(
            &response_body,
            ResponseValidationContext {
                expected_request_hash: validated.request_hash,
                expected_action_hash: action_hash,
                expected_authority_chain_hash: authority.authority_chain_hash,
                expected_node_did: &signer_identity.did,
                expected_node_key_id: &signer_identity.key_id,
                expected_node_recorded_at: recorded_at,
                expected_node_public_key: &signer_identity.public_key,
            },
        )
        .map_err(codec)?;
        let receipt_body = encode_serde(&receipt)?;

        insert_atomic_record(
            &transaction,
            &validated,
            &authority,
            recorded_at,
            &receipt,
            &receipt_body,
            &response_body,
            receipt_operation,
            &receipt_payload,
            wrapper_operation,
            &wrapper_payload,
        )?;
        transaction.commit().map_err(storage)?;

        Ok(AnchorRecord {
            disposition: AnchorRecordDisposition::Created,
            request_hash: validated.request_hash,
            action_hash,
            response: verified_response.response,
            response_body,
        })
    }

    /// Read and cryptographically authenticate one stored action record.
    ///
    /// # Errors
    /// Returns a readback error if any persisted request, receipt, response,
    /// signature journal, authority snapshot, or binding commitment changed.
    pub fn readback_action(
        &self,
        source_code: &str,
        action_hash: &[u8; 32],
    ) -> Result<Option<AuthenticatedAnchorReadback>, AnchorStoreError> {
        let connection = self.connection()?;
        let Some(stored) = load_anchor_by_action(&connection, source_code, action_hash)? else {
            return Ok(None);
        };
        validate_stored_anchor(&connection, &self.config, &stored).map(Some)
    }

    fn connection(&self) -> Result<Connection, AnchorStoreError> {
        let connection = Connection::open(&self.path).map_err(storage)?;
        connection
            .busy_timeout(Duration::from_secs(30))
            .map_err(storage)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;")
            .map_err(storage)?;
        Ok(connection)
    }
}

/// Hash the complete ordered delegation chain through its signed link IDs.
///
/// # Errors
/// Fails when a link ID or CBOR payload cannot be encoded.
pub fn authority_chain_fingerprint(chain: &AuthorityChain) -> Result<Hash256, AnchorStoreError> {
    if chain.links.is_empty() {
        return Err(AnchorStoreError::AuthorityValidation(
            "authority chain must not be empty".into(),
        ));
    }
    let mut values = vec![text(AUTHORITY_CHAIN_DOMAIN)];
    for link in &chain.links {
        let link_id = link.id().map_err(authority)?;
        let signature = link.signature.ed25519_bytes().ok_or_else(|| {
            AnchorStoreError::AuthorityValidation(
                "authority chain link signature must be Ed25519".into(),
            )
        })?;
        values.push(Value::Array(vec![
            bytes(link_id.as_bytes()),
            bytes(signature),
        ]));
    }
    Ok(Hash256::digest(&encode_value(&Value::Array(values))?))
}

fn validate_config(config: &AnchorStoreConfig) -> Result<(), AnchorStoreError> {
    validate_did_key_id(&config.node_identity.did, &config.node_identity.key_id)?;
    validate_did_key_id(
        &config.crosschecked_intermediate_did,
        &config.crosschecked_intermediate_key_id,
    )?;
    if config.expected_audience.is_empty()
        || config.expected_audience.len() > 128
        || !config.expected_audience.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "invalid configured audience".into(),
        ));
    }
    if config
        .node_identity
        .public_key
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "node public key must be non-zero".into(),
        ));
    }
    if config
        .crosschecked_intermediate_public_key
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "intermediate public key must be non-zero".into(),
        ));
    }
    Ok(())
}

fn validate_did_key_id(did: &str, key_id: &str) -> Result<(), AnchorStoreError> {
    Did::new(did)
        .map_err(|error| AnchorStoreError::AuthorityValidation(format!("invalid DID: {error}")))?;
    let prefix = format!("{did}#");
    let fragment = key_id.strip_prefix(&prefix).ok_or_else(|| {
        AnchorStoreError::AuthorityValidation("key ID is not rooted at DID".into())
    })?;
    if fragment.is_empty()
        || fragment.len() > 64
        || !fragment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "invalid key ID fragment".into(),
        ));
    }
    Ok(())
}

fn validate_provisioning(
    config: &AnchorStoreConfig,
    provisioning: &AuthorityProvisioningV1,
) -> Result<ValidatedProvisioning, AnchorStoreError> {
    if provisioning.protocol_version != 1 || provisioning.scope_binding.protocol_version != 1 {
        return Err(AnchorStoreError::AuthorityValidation(
            "unsupported provisioning protocol version".into(),
        ));
    }
    let binding = &provisioning.scope_binding;
    validate_did_key_id(binding.authority_did.as_str(), &binding.authority_key_id)?;
    validate_did_key_id(
        binding.binding_signer_did.as_str(),
        &binding.binding_signer_key_id,
    )?;
    if binding.permission != Permission::AnchorReceiptCommitment {
        return Err(AnchorStoreError::AuthorityValidation(
            "scope binding lacks AnchorReceiptCommitment permission".into(),
        ));
    }
    if binding.audience != config.expected_audience {
        return Err(AnchorStoreError::AuthorityValidation(
            "scope binding audience mismatch".into(),
        ));
    }
    if binding.grant_id.iter().all(|byte| *byte == 0)
        || binding.scope_alias.iter().all(|byte| *byte == 0)
        || binding.key_epoch == 0
        || binding.valid_from_ms >= binding.valid_until_ms
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "invalid scope binding identifiers, epoch, or validity".into(),
        ));
    }
    if binding.binding_signer_did.as_str() != config.crosschecked_intermediate_did {
        return Err(AnchorStoreError::AuthorityValidation(
            "scope binding signer is not configured CrossChecked intermediate".into(),
        ));
    }
    if binding.binding_signer_key_id != config.crosschecked_intermediate_key_id {
        return Err(AnchorStoreError::AuthorityValidation(
            "scope binding signer key is not the pinned intermediate key".into(),
        ));
    }
    if provisioning.authority_chain.leaf() != Some(&binding.authority_did) {
        return Err(AnchorStoreError::AuthorityValidation(
            "authority chain leaf does not match scope-bound authority".into(),
        ));
    }
    let Some(last_link) = provisioning.authority_chain.links.last() else {
        return Err(AnchorStoreError::AuthorityValidation(
            "authority chain is empty".into(),
        ));
    };
    if last_link.delegator_did.as_str() != config.crosschecked_intermediate_did {
        return Err(AnchorStoreError::AuthorityValidation(
            "child authority is not directly beneath configured intermediate".into(),
        ));
    }
    if !has_permission(
        &provisioning.authority_chain,
        &Permission::AnchorReceiptCommitment,
    ) {
        return Err(AnchorStoreError::AuthorityValidation(
            "verified chain lacks AnchorReceiptCommitment permission".into(),
        ));
    }
    let fingerprint = authority_chain_fingerprint(&provisioning.authority_chain)?;
    if fingerprint != binding.chain_fingerprint {
        return Err(AnchorStoreError::AuthorityValidation(
            "authority chain fingerprint mismatch".into(),
        ));
    }

    let documents = document_map(&provisioning.did_documents)?;
    let authority_document = documents
        .get(binding.authority_did.as_str())
        .ok_or_else(|| {
            AnchorStoreError::AuthorityValidation("authority DID document missing".into())
        })?;
    let authority_method = exact_method(authority_document, &binding.authority_key_id)?;
    if authority_method.version != binding.key_epoch
        || authority_method.valid_from > binding.valid_from_ms
        || authority_method.revoked_at.is_some()
        || !authority_method.active
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "authority key epoch or lifecycle does not cover binding".into(),
        ));
    }
    let authority_public_key =
        validate_verification_method_document_binding(authority_document, authority_method)
            .map_err(identity)?;

    let mut chain_keys = BTreeMap::new();
    for link in &provisioning.authority_chain.links {
        if link.created.physical_ms > binding.valid_from_ms
            || link
                .expires
                .is_none_or(|expires| expires.physical_ms < binding.valid_until_ms)
        {
            return Err(AnchorStoreError::AuthorityValidation(
                "delegation link does not cover complete binding validity".into(),
            ));
        }
        let document = documents.get(link.delegator_did.as_str()).ok_or_else(|| {
            AnchorStoreError::AuthorityValidation(format!(
                "delegator DID document missing for {}",
                link.delegator_did
            ))
        })?;
        let active: Vec<&VerificationMethod> = document
            .verification_methods
            .iter()
            .filter(|method| {
                method.active
                    && method.revoked_at.is_none()
                    && method.valid_from <= binding.valid_from_ms
            })
            .collect();
        if active.len() != 1 {
            return Err(AnchorStoreError::AuthorityValidation(format!(
                "delegator {} must have exactly one active binding-time Ed25519 key",
                link.delegator_did
            )));
        }
        let key =
            validate_verification_method_document_binding(document, active[0]).map_err(identity)?;
        chain_keys.insert(link.delegator_did.as_str().to_owned(), key);
    }
    let verify_at = Timestamp::new(binding.valid_from_ms, 0);
    verify_chain(&provisioning.authority_chain, &verify_at, |did| {
        chain_keys.get(did.as_str()).copied()
    })
    .map_err(authority)?;

    let signer_document = documents
        .get(binding.binding_signer_did.as_str())
        .ok_or_else(|| {
            AnchorStoreError::AuthorityValidation("binding signer DID document missing".into())
        })?;
    let signer_method = exact_method(signer_document, &binding.binding_signer_key_id)?;
    if signer_method.valid_from > binding.valid_from_ms {
        return Err(AnchorStoreError::AuthorityValidation(
            "binding signer key is not valid at binding start".into(),
        ));
    }
    let signer_key = validate_verification_method_document_binding(signer_document, signer_method)
        .map_err(identity)?;
    if signer_key != config.crosschecked_intermediate_public_key {
        return Err(AnchorStoreError::AuthorityValidation(
            "scope binding intermediate public key substitution".into(),
        ));
    }
    if !crypto::verify(
        &binding.signing_preimage()?,
        &binding.signature,
        &signer_key,
    ) {
        return Err(AnchorStoreError::AuthorityValidation(
            "scope binding signature is invalid".into(),
        ));
    }
    let authority_chain_hash = authority_chain_hash(&provisioning.authority_chain, binding)?;
    Ok(ValidatedProvisioning {
        authority_public_key,
        authority_chain_hash,
    })
}

fn validate_retirement(
    config: &AnchorStoreConfig,
    provisioning: &AuthorityProvisioningV1,
    retirement: &AuthorityRetirementV1,
) -> Result<(), AnchorStoreError> {
    let binding = &provisioning.scope_binding;
    if retirement.protocol_version != 1
        || retirement.authority_did != binding.authority_did
        || retirement.authority_key_id != binding.authority_key_id
        || retirement.key_epoch != binding.key_epoch
        || retirement.signer_did.as_str() != config.crosschecked_intermediate_did
        || retirement.signer_key_id != config.crosschecked_intermediate_key_id
        || retirement.retired_at_ms < binding.valid_from_ms
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "retirement target, signer, epoch, or time mismatch".into(),
        ));
    }
    validate_did_key_id(retirement.signer_did.as_str(), &retirement.signer_key_id)?;
    let documents = document_map(&provisioning.did_documents)?;
    let signer_document = documents
        .get(retirement.signer_did.as_str())
        .ok_or_else(|| {
            AnchorStoreError::AuthorityValidation("retirement signer document missing".into())
        })?;
    let signer_method = exact_method(signer_document, &retirement.signer_key_id)?;
    let signer_key = validate_verification_method_document_binding(signer_document, signer_method)
        .map_err(identity)?;
    if signer_key != config.crosschecked_intermediate_public_key {
        return Err(AnchorStoreError::AuthorityValidation(
            "retirement intermediate public key substitution".into(),
        ));
    }
    if !crypto::verify(
        &retirement.signing_preimage()?,
        &retirement.signature,
        &signer_key,
    ) {
        return Err(AnchorStoreError::AuthorityValidation(
            "retirement signature is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_stored_authority(
    config: &AnchorStoreConfig,
    authority: &StoredAuthority,
) -> Result<(), AnchorStoreError> {
    if encode_serde(&authority.provisioning)? != authority.provisioning_cbor {
        return Err(AnchorStoreError::ReadbackValidation(
            "authority provisioning bytes are not exact".into(),
        ));
    }
    let validated = validate_provisioning(config, &authority.provisioning)?;
    if validated.authority_public_key != authority.authority_public_key
        || validated.authority_chain_hash != authority.authority_chain_hash
    {
        return Err(AnchorStoreError::ReadbackValidation(
            "authority derived commitments changed".into(),
        ));
    }
    match (
        authority.retired_at_ms,
        authority.retirement_cbor.as_deref(),
    ) {
        (None, None) => {}
        (Some(retired_at_ms), Some(retirement_cbor)) => {
            let retirement: AuthorityRetirementV1 = decode_serde(retirement_cbor)?;
            if encode_serde(&retirement)? != retirement_cbor
                || retirement.retired_at_ms != retired_at_ms
            {
                return Err(AnchorStoreError::ReadbackValidation(
                    "authority retirement bytes do not match persisted state".into(),
                ));
            }
            validate_retirement(config, &authority.provisioning, &retirement)?;
        }
        _ => {
            return Err(AnchorStoreError::ReadbackValidation(
                "authority retirement state is incomplete".into(),
            ));
        }
    }
    Ok(())
}

fn validate_authority_time(
    authority: &StoredAuthority,
    locator: &exo_api::crosschecked_anchor::UnverifiedAnchorReplayLocatorV1,
    now_ms: u64,
) -> Result<(), AnchorStoreError> {
    let binding = &authority.provisioning.scope_binding;
    if binding.valid_from_ms > now_ms || locator.issued_at_ms < binding.valid_from_ms {
        return Err(AnchorStoreError::AuthorityNotYetValid);
    }
    if binding.valid_until_ms <= now_ms || locator.expires_at_ms > binding.valid_until_ms {
        return Err(AnchorStoreError::AuthorityExpired);
    }
    if authority
        .retired_at_ms
        .is_some_and(|retired_at| retired_at <= now_ms || retired_at <= locator.issued_at_ms)
    {
        return Err(AnchorStoreError::AuthorityRetired);
    }
    Ok(())
}

fn validate_request_binding(
    request: &exo_api::crosschecked_anchor::CrossCheckedAnchorRequestV1,
    binding: &CrossCheckedScopeBindingV1,
) -> Result<(), AnchorStoreError> {
    if request.authority_did != binding.authority_did.as_str()
        || request.authority_key_id != binding.authority_key_id
        || request.grant_id != binding.grant_id
        || request.scope_alias != binding.scope_alias
        || request.audience != binding.audience
    {
        return Err(AnchorStoreError::AuthorityValidation(
            "request does not match persistent authority scope binding".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_atomic_record(
    transaction: &Transaction<'_>,
    validated: &exo_api::crosschecked_anchor::ValidatedCrossCheckedAnchorRequestV1,
    authority: &StoredAuthority,
    recorded_at: Timestamp,
    receipt: &TrustReceipt,
    receipt_body: &[u8],
    response_body: &[u8],
    receipt_operation: Hash256,
    receipt_payload: &[u8],
    wrapper_operation: Hash256,
    wrapper_payload: &[u8],
) -> Result<(), AnchorStoreError> {
    let request = &validated.request;
    transaction
        .execute(
            "INSERT INTO crosschecked_anchor_requests (
                request_hash, authority_did, authority_key_id, source_code,
                action_hash, canonical_request_body, accepted_physical_ms,
                accepted_logical
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                validated.request_hash.as_bytes().as_slice(),
                request.authority_did,
                request.authority_key_id,
                request.source_code,
                request.action_hash.as_slice(),
                validated.canonical_body,
                to_i64(recorded_at.physical_ms, "accepted_physical_ms")?,
                i64::from(recorded_at.logical),
            ],
        )
        .map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO crosschecked_anchor_idempotency (
                authority_did, idempotency_key, request_hash
             ) VALUES (?1, ?2, ?3)",
            params![
                request.authority_did,
                request.idempotency_key.as_slice(),
                validated.request_hash.as_bytes().as_slice(),
            ],
        )
        .map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO crosschecked_anchor_receipts (
                receipt_hash, request_hash, authority_chain_hash,
                canonical_receipt_body
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.receipt_hash.as_bytes().as_slice(),
                validated.request_hash.as_bytes().as_slice(),
                authority.authority_chain_hash.as_bytes().as_slice(),
                receipt_body,
            ],
        )
        .map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO crosschecked_anchor_signatures (
                operation_id, request_hash, purpose_code, payload_hash, signature
             ) VALUES (?1, ?2, 'receipt', ?3, ?4),
                      (?5, ?2, 'response', ?6, ?7)",
            params![
                receipt_operation.as_bytes().as_slice(),
                validated.request_hash.as_bytes().as_slice(),
                Hash256::digest(receipt_payload).as_bytes().as_slice(),
                ed25519_bytes(receipt.signature.clone())?.as_slice(),
                wrapper_operation.as_bytes().as_slice(),
                Hash256::digest(wrapper_payload).as_bytes().as_slice(),
                response_wrapper_signature(response_body)?.as_slice(),
            ],
        )
        .map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO crosschecked_anchor_responses (
                request_hash, receipt_hash, canonical_response_body,
                node_did, node_key_id, node_recorded_physical_ms,
                node_recorded_logical
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                validated.request_hash.as_bytes().as_slice(),
                receipt.receipt_hash.as_bytes().as_slice(),
                response_body,
                receipt.actor_did.as_str(),
                // The response was self-verified before this insertion. The
                // immutable store policy contains the exact node key ID.
                authority_node_key_id(transaction)?,
                to_i64(recorded_at.physical_ms, "node_recorded_physical_ms")?,
                i64::from(recorded_at.logical),
            ],
        )
        .map_err(storage)?;
    Ok(())
}

fn authority_node_key_id(transaction: &Transaction<'_>) -> Result<String, AnchorStoreError> {
    transaction
        .query_row(
            "SELECT node_key_id FROM crosschecked_anchor_store_config WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)
}

fn validate_stored_anchor(
    connection: &Connection,
    config: &AnchorStoreConfig,
    stored: &StoredAnchorRow,
) -> Result<AuthenticatedAnchorReadback, AnchorStoreError> {
    let authority = load_authority(connection, &stored.authority_did, &stored.authority_key_id)?
        .ok_or_else(|| {
            AnchorStoreError::ReadbackValidation("stored authority is missing".into())
        })?;
    validate_stored_authority(config, &authority)?;
    if stored.authority_chain_hash != authority.authority_chain_hash
        || stored.authority_public_key != authority.authority_public_key
    {
        return Err(AnchorStoreError::ReadbackValidation(
            "stored authority commitments do not match receipt row".into(),
        ));
    }
    let locator = decode_unverified_replay_locator(
        &stored.request_body,
        "POST",
        ANCHOR_PATH,
        "application/cbor",
    )
    .map_err(readback_codec)?;
    if locator.request_hash != stored.request_hash
        || locator.source_code != stored.source_code
        || locator.action_hash != stored.action_hash
        || locator.idempotency_key != stored.idempotency_key
    {
        return Err(AnchorStoreError::ReadbackValidation(
            "stored request indexes do not match canonical request".into(),
        ));
    }
    let validated_request = decode_and_validate_request(
        &stored.request_body,
        RequestValidationContext {
            method: "POST",
            path: ANCHOR_PATH,
            content_type: "application/cbor",
            expected_audience: &config.expected_audience,
            now_ms: locator.issued_at_ms,
            authority_public_key: &stored.authority_public_key,
        },
    )
    .map_err(readback_codec)?;
    validate_request_binding(
        &validated_request.request,
        &authority.provisioning.scope_binding,
    )?;
    if authority
        .retired_at_ms
        .is_some_and(|retired_at| retired_at <= locator.issued_at_ms)
    {
        return Err(AnchorStoreError::ReadbackValidation(
            "authority was retired before stored request issuance".into(),
        ));
    }
    let response = decode_and_validate_response(
        &stored.response_body,
        ResponseValidationContext {
            expected_request_hash: stored.request_hash,
            expected_action_hash: Hash256::from_bytes(stored.action_hash),
            expected_authority_chain_hash: stored.authority_chain_hash,
            expected_node_did: &config.node_identity.did,
            expected_node_key_id: &config.node_identity.key_id,
            expected_node_recorded_at: stored.node_recorded_at,
            expected_node_public_key: &config.node_identity.public_key,
        },
    )
    .map_err(readback_codec)?;
    let stored_receipt: TrustReceipt = decode_serde(&stored.receipt_body)?;
    if stored_receipt != response.response.exochain_receipt
        || encode_serde(&stored_receipt)? != stored.receipt_body
    {
        return Err(AnchorStoreError::ReadbackValidation(
            "stored TrustReceipt is not the exact signed response receipt".into(),
        ));
    }
    validate_signature_journal(connection, stored.request_hash, &response.response)?;
    Ok(AuthenticatedAnchorReadback {
        request_body: stored.request_body.clone(),
        response: response.response,
        response_body: response.canonical_body,
    })
}

fn validate_signature_journal(
    connection: &Connection,
    request_hash: Hash256,
    response: &CrossCheckedAnchorResponseV1,
) -> Result<(), AnchorStoreError> {
    let receipt_payload = response
        .exochain_receipt
        .signing_payload()
        .map_err(|error| AnchorStoreError::ReadbackValidation(error.to_string()))?;
    let wrapper_payload = response.signing_preimage().map_err(readback_codec)?;
    for (purpose, operation, payload, signature) in [
        (
            "receipt",
            signing_operation_id(request_hash, "receipt")?,
            receipt_payload,
            ed25519_bytes(response.exochain_receipt.signature.clone())?,
        ),
        (
            "response",
            signing_operation_id(request_hash, "response")?,
            wrapper_payload,
            response.wrapper_signature,
        ),
    ] {
        let journal: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT operation_id, payload_hash, signature
                 FROM crosschecked_anchor_signatures
                 WHERE request_hash = ?1 AND purpose_code = ?2",
                params![request_hash.as_bytes().as_slice(), purpose],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let Some((stored_operation, stored_payload_hash, stored_signature)) = journal else {
            return Err(AnchorStoreError::ReadbackValidation(format!(
                "missing {purpose} signing journal"
            )));
        };
        if stored_operation != operation.as_bytes()
            || stored_payload_hash != Hash256::digest(&payload).as_bytes()
            || stored_signature != signature
        {
            return Err(AnchorStoreError::ReadbackValidation(format!(
                "{purpose} signing journal mismatch"
            )));
        }
    }
    Ok(())
}

fn initialize_schema(
    connection: &Connection,
    config: &AnchorStoreConfig,
) -> Result<(), AnchorStoreError> {
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_store_config (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 schema_version TEXT NOT NULL,
                 expected_audience TEXT NOT NULL,
                 intermediate_did TEXT NOT NULL,
                 intermediate_key_id TEXT NOT NULL,
                 intermediate_public_key BLOB NOT NULL CHECK (length(intermediate_public_key) = 32),
                 node_did TEXT NOT NULL,
                 node_key_id TEXT NOT NULL,
                 node_public_key BLOB NOT NULL CHECK (length(node_public_key) = 32)
             );
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_authorities (
                 authority_did TEXT NOT NULL,
                 authority_key_id TEXT NOT NULL,
                 grant_id BLOB NOT NULL UNIQUE CHECK (length(grant_id) = 32),
                 scope_alias BLOB NOT NULL CHECK (length(scope_alias) = 32),
                 audience TEXT NOT NULL,
                 permission_code TEXT NOT NULL CHECK (permission_code = 'anchor_receipt_commitment'),
                 key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
                 valid_from_ms INTEGER NOT NULL CHECK (valid_from_ms >= 0),
                 valid_until_ms INTEGER NOT NULL CHECK (valid_until_ms > valid_from_ms),
                 retired_at_ms INTEGER,
                 authority_public_key BLOB NOT NULL CHECK (length(authority_public_key) = 32),
                 authority_chain_hash BLOB NOT NULL CHECK (length(authority_chain_hash) = 32),
                 provisioning_cbor BLOB NOT NULL,
                 retirement_cbor BLOB,
                 PRIMARY KEY (authority_did, authority_key_id),
                 UNIQUE (authority_did, key_epoch)
             );
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_requests (
                 request_hash BLOB PRIMARY KEY CHECK (length(request_hash) = 32),
                 authority_did TEXT NOT NULL,
                 authority_key_id TEXT NOT NULL,
                 source_code TEXT NOT NULL CHECK (source_code = 'crosschecked'),
                 action_hash BLOB NOT NULL CHECK (length(action_hash) = 32),
                 canonical_request_body BLOB NOT NULL,
                 accepted_physical_ms INTEGER NOT NULL CHECK (accepted_physical_ms >= 0),
                 accepted_logical INTEGER NOT NULL CHECK (accepted_logical >= 0),
                 UNIQUE (source_code, action_hash),
                 FOREIGN KEY (authority_did, authority_key_id)
                     REFERENCES crosschecked_anchor_authorities(authority_did, authority_key_id)
             );
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_idempotency (
                 authority_did TEXT NOT NULL,
                 idempotency_key BLOB NOT NULL CHECK (length(idempotency_key) = 32),
                 request_hash BLOB NOT NULL UNIQUE,
                 PRIMARY KEY (authority_did, idempotency_key),
                 FOREIGN KEY (request_hash) REFERENCES crosschecked_anchor_requests(request_hash)
             );
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_receipts (
                 receipt_hash BLOB PRIMARY KEY CHECK (length(receipt_hash) = 32),
                 request_hash BLOB NOT NULL UNIQUE,
                 authority_chain_hash BLOB NOT NULL CHECK (length(authority_chain_hash) = 32),
                 canonical_receipt_body BLOB NOT NULL,
                 FOREIGN KEY (request_hash) REFERENCES crosschecked_anchor_requests(request_hash)
             );
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_signatures (
                 operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 32),
                 request_hash BLOB NOT NULL,
                 purpose_code TEXT NOT NULL CHECK (purpose_code IN ('receipt', 'response')),
                 payload_hash BLOB NOT NULL CHECK (length(payload_hash) = 32),
                 signature BLOB NOT NULL CHECK (length(signature) = 64),
                 UNIQUE (request_hash, purpose_code),
                 FOREIGN KEY (request_hash) REFERENCES crosschecked_anchor_requests(request_hash)
             );
             CREATE TABLE IF NOT EXISTS crosschecked_anchor_responses (
                 request_hash BLOB PRIMARY KEY,
                 receipt_hash BLOB NOT NULL UNIQUE,
                 canonical_response_body BLOB NOT NULL,
                 node_did TEXT NOT NULL,
                 node_key_id TEXT NOT NULL,
                 node_recorded_physical_ms INTEGER NOT NULL CHECK (node_recorded_physical_ms >= 0),
                 node_recorded_logical INTEGER NOT NULL CHECK (node_recorded_logical >= 0),
                 FOREIGN KEY (request_hash) REFERENCES crosschecked_anchor_requests(request_hash),
                 FOREIGN KEY (receipt_hash) REFERENCES crosschecked_anchor_receipts(receipt_hash)
             );",
        )
        .map_err(storage)?;
    connection
        .execute(
            "INSERT OR IGNORE INTO crosschecked_anchor_store_config (
                singleton, schema_version, expected_audience, intermediate_did,
                intermediate_key_id, intermediate_public_key, node_did,
                node_key_id, node_public_key
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                STORE_SCHEMA_VERSION,
                config.expected_audience,
                config.crosschecked_intermediate_did,
                config.crosschecked_intermediate_key_id,
                config
                    .crosschecked_intermediate_public_key
                    .as_bytes()
                    .as_slice(),
                config.node_identity.did,
                config.node_identity.key_id,
                config.node_identity.public_key.as_bytes().as_slice(),
            ],
        )
        .map_err(storage)?;
    let persisted: (
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT schema_version, expected_audience, intermediate_did,
                    intermediate_key_id, intermediate_public_key, node_did,
                    node_key_id, node_public_key
             FROM crosschecked_anchor_store_config WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(storage)?;
    if persisted.0 != STORE_SCHEMA_VERSION
        || persisted.1 != config.expected_audience
        || persisted.2 != config.crosschecked_intermediate_did
        || persisted.3 != config.crosschecked_intermediate_key_id
        || persisted.4 != config.crosschecked_intermediate_public_key.as_bytes()
        || persisted.5 != config.node_identity.did
        || persisted.6 != config.node_identity.key_id
        || persisted.7 != config.node_identity.public_key.as_bytes()
    {
        return Err(AnchorStoreError::Storage(
            "persisted store policy differs from requested policy".into(),
        ));
    }
    Ok(())
}

fn load_authority(
    connection: &Connection,
    authority_did: &str,
    authority_key_id: &str,
) -> Result<Option<StoredAuthority>, AnchorStoreError> {
    connection
        .query_row(
            "SELECT provisioning_cbor, authority_public_key,
                    authority_chain_hash, retired_at_ms, retirement_cbor
             FROM crosschecked_anchor_authorities
             WHERE authority_did = ?1 AND authority_key_id = ?2",
            params![authority_did, authority_key_id],
            |row| {
                let provisioning_cbor: Vec<u8> = row.get(0)?;
                let authority_public_key: Vec<u8> = row.get(1)?;
                let authority_chain_hash: Vec<u8> = row.get(2)?;
                let retired_at_ms: Option<i64> = row.get(3)?;
                let retirement_cbor: Option<Vec<u8>> = row.get(4)?;
                Ok((
                    provisioning_cbor,
                    authority_public_key,
                    authority_chain_hash,
                    retired_at_ms,
                    retirement_cbor,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .map(
            |(provisioning_cbor, public_key, chain_hash, retired_at, retirement_cbor)| {
                Ok(StoredAuthority {
                    provisioning: decode_serde(&provisioning_cbor)?,
                    provisioning_cbor,
                    authority_public_key: PublicKey::from_bytes(exact_bytes(
                        public_key,
                        "authority public key",
                    )?),
                    authority_chain_hash: Hash256::from_bytes(exact_bytes(
                        chain_hash,
                        "authority chain hash",
                    )?),
                    retired_at_ms: retired_at
                        .map(|value| from_i64(value, "retired_at_ms"))
                        .transpose()?,
                    retirement_cbor,
                })
            },
        )
        .transpose()
}

fn load_anchor_by_idempotency(
    connection: &Connection,
    authority_did: &str,
    idempotency_key: &[u8; 32],
) -> Result<Option<StoredAnchorRow>, AnchorStoreError> {
    query_anchor(
        connection,
        "WHERE i.authority_did = ?1 AND i.idempotency_key = ?2",
        params![authority_did, idempotency_key.as_slice()],
    )
}

fn load_anchor_by_action(
    connection: &Connection,
    source_code: &str,
    action_hash: &[u8; 32],
) -> Result<Option<StoredAnchorRow>, AnchorStoreError> {
    query_anchor(
        connection,
        "WHERE q.source_code = ?1 AND q.action_hash = ?2",
        params![source_code, action_hash.as_slice()],
    )
}

fn query_anchor<P: rusqlite::Params>(
    connection: &Connection,
    predicate: &str,
    query_params: P,
) -> Result<Option<StoredAnchorRow>, AnchorStoreError> {
    let sql = format!(
        "SELECT q.authority_did, q.authority_key_id, i.idempotency_key,
                q.source_code, q.action_hash, q.request_hash,
                q.canonical_request_body, c.canonical_receipt_body,
                s.canonical_response_body, c.authority_chain_hash,
                a.authority_public_key, s.node_recorded_physical_ms,
                s.node_recorded_logical
         FROM crosschecked_anchor_requests q
         JOIN crosschecked_anchor_idempotency i ON i.request_hash = q.request_hash
         JOIN crosschecked_anchor_receipts c ON c.request_hash = q.request_hash
         JOIN crosschecked_anchor_responses s ON s.request_hash = q.request_hash
         JOIN crosschecked_anchor_authorities a
           ON a.authority_did = q.authority_did
          AND a.authority_key_id = q.authority_key_id
         {predicate}"
    );
    connection
        .query_row(&sql, query_params, |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
            ))
        })
        .optional()
        .map_err(storage)?
        .map(
            |(
                authority_did,
                authority_key_id,
                idempotency_key,
                source_code,
                action_hash,
                request_hash,
                request_body,
                receipt_body,
                response_body,
                authority_chain_hash,
                authority_public_key,
                physical_ms,
                logical,
            )| {
                Ok(StoredAnchorRow {
                    authority_did,
                    authority_key_id,
                    idempotency_key: exact_bytes(idempotency_key, "idempotency key")?,
                    source_code,
                    action_hash: exact_bytes(action_hash, "action hash")?,
                    request_hash: Hash256::from_bytes(exact_bytes(request_hash, "request hash")?),
                    request_body,
                    receipt_body,
                    response_body,
                    authority_chain_hash: Hash256::from_bytes(exact_bytes(
                        authority_chain_hash,
                        "authority chain hash",
                    )?),
                    authority_public_key: PublicKey::from_bytes(exact_bytes(
                        authority_public_key,
                        "authority public key",
                    )?),
                    node_recorded_at: Timestamp::new(
                        from_i64(physical_ms, "node recorded physical")?,
                        u32::try_from(logical).map_err(|_| {
                            AnchorStoreError::ReadbackValidation(
                                "node recorded logical timestamp is invalid".into(),
                            )
                        })?,
                    ),
                })
            },
        )
        .transpose()
}

fn document_map(
    documents: &[DidDocument],
) -> Result<BTreeMap<&str, &DidDocument>, AnchorStoreError> {
    let mut by_did = BTreeMap::new();
    for document in documents {
        if document.revoked {
            return Err(AnchorStoreError::AuthorityValidation(format!(
                "DID document {} is revoked",
                document.id
            )));
        }
        if by_did.insert(document.id.as_str(), document).is_some() {
            return Err(AnchorStoreError::AuthorityValidation(format!(
                "duplicate DID document {}",
                document.id
            )));
        }
    }
    Ok(by_did)
}

fn exact_method<'a>(
    document: &'a DidDocument,
    key_id: &str,
) -> Result<&'a VerificationMethod, AnchorStoreError> {
    let matches: Vec<&VerificationMethod> = document
        .verification_methods
        .iter()
        .filter(|method| method.id == key_id)
        .collect();
    if matches.len() != 1 {
        return Err(AnchorStoreError::AuthorityValidation(format!(
            "DID document must contain exactly one method {key_id}"
        )));
    }
    Ok(matches[0])
}

fn authority_chain_hash(
    chain: &AuthorityChain,
    binding: &CrossCheckedScopeBindingV1,
) -> Result<Hash256, AnchorStoreError> {
    let signature = ed25519_bytes(binding.signature.clone())?;
    let encoded = encode_value(&Value::Array(vec![
        text(AUTHORITY_CHAIN_HASH_DOMAIN),
        bytes(authority_chain_fingerprint(chain)?.as_bytes()),
        bytes(Hash256::digest(&binding.signing_preimage()?).as_bytes()),
        bytes(&signature),
    ]))?;
    Ok(Hash256::digest(&encoded))
}

fn signing_operation_id(request_hash: Hash256, purpose: &str) -> Result<Hash256, AnchorStoreError> {
    Ok(Hash256::digest(&encode_value(&Value::Array(vec![
        text(SIGNING_OPERATION_DOMAIN),
        bytes(request_hash.as_bytes()),
        text(purpose),
    ]))?))
}

fn response_wrapper_signature(body: &[u8]) -> Result<[u8; 64], AnchorStoreError> {
    let value: Value = ciborium::from_reader(body)
        .map_err(|error| AnchorStoreError::Storage(format!("response CBOR decode: {error}")))?;
    let Value::Map(fields) = value else {
        return Err(AnchorStoreError::Storage(
            "response CBOR root is not map".into(),
        ));
    };
    for (key, value) in fields {
        if key == text("wrapper_signature") {
            let Value::Bytes(signature) = value else {
                return Err(AnchorStoreError::Storage(
                    "wrapper signature is not bytes".into(),
                ));
            };
            return exact_bytes(signature, "wrapper signature");
        }
    }
    Err(AnchorStoreError::Storage(
        "wrapper signature field missing".into(),
    ))
}

fn ed25519_bytes(signature: Signature) -> Result<[u8; 64], AnchorStoreError> {
    signature.ed25519_bytes().copied().ok_or_else(|| {
        AnchorStoreError::Signer(SignOnceError::Unavailable(
            "signer returned a non-Ed25519 signature".into(),
        ))
    })
}

fn permission_code(permission: Permission) -> Result<&'static str, AnchorStoreError> {
    match permission {
        Permission::AnchorReceiptCommitment => Ok(ANCHOR_PERMISSION_CODE),
        _ => Err(AnchorStoreError::AuthorityValidation(
            "permission is not AnchorReceiptCommitment".into(),
        )),
    }
}

fn encode_serde<T: Serialize>(value: &T) -> Result<Vec<u8>, AnchorStoreError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)
        .map_err(|error| AnchorStoreError::Storage(format!("CBOR encode: {error}")))?;
    Ok(encoded)
}

fn decode_serde<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AnchorStoreError> {
    ciborium::from_reader(bytes)
        .map_err(|error| AnchorStoreError::ReadbackValidation(format!("CBOR decode: {error}")))
}

fn encode_value(value: &Value) -> Result<Vec<u8>, AnchorStoreError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)
        .map_err(|error| AnchorStoreError::Storage(format!("canonical CBOR encode: {error}")))?;
    Ok(encoded)
}

fn exact_bytes<const N: usize>(bytes: Vec<u8>, name: &str) -> Result<[u8; N], AnchorStoreError> {
    bytes.try_into().map_err(|_| {
        AnchorStoreError::ReadbackValidation(format!("{name} has invalid byte length"))
    })
}

fn to_i64(value: u64, name: &str) -> Result<i64, AnchorStoreError> {
    i64::try_from(value)
        .map_err(|_| AnchorStoreError::Storage(format!("{name} exceeds SQLite INTEGER")))
}

fn from_i64(value: i64, name: &str) -> Result<u64, AnchorStoreError> {
    u64::try_from(value)
        .map_err(|_| AnchorStoreError::ReadbackValidation(format!("{name} is negative in storage")))
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

fn storage(error: rusqlite::Error) -> AnchorStoreError {
    AnchorStoreError::Storage(error.to_string())
}

fn codec(error: exo_api::crosschecked_anchor::AnchorCodecError) -> AnchorStoreError {
    AnchorStoreError::Codec(error.to_string())
}

fn readback_codec(error: exo_api::crosschecked_anchor::AnchorCodecError) -> AnchorStoreError {
    AnchorStoreError::ReadbackValidation(error.to_string())
}

fn identity(error: exo_identity::did_verification::DidVerificationError) -> AnchorStoreError {
    AnchorStoreError::AuthorityValidation(error.to_string())
}

fn authority(error: exo_authority::AuthorityError) -> AnchorStoreError {
    AnchorStoreError::AuthorityValidation(error.to_string())
}
