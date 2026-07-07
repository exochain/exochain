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

//! 0dentity score and claim store.
//!
//! This module provides the shared state accessor for 0dentity scoring data.
//! It integrates with `exo_identity` to provide cryptographic standing via `LocalDidRegistry`
//! and handles the `VerificationCeremony` state for identity onboarding.
//!
//! While currently a robust in-memory implementation for rapid consensus and state management,
//! the integration path for SQLite persistence remains available.
//!
//! All inner maps use `BTreeMap` (never `HashMap`) for deterministic iteration.
//! Evidence vectors are canonicalized on read before callers perform scoring.
//!
//! Spec reference: §9, §12.1.

// VCG-009: OnceLock is only used by the device/behavioral ingestion-service
// keypair helper, which is gated behind the axes feature.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    path::Path,
    sync::{Arc, Mutex},
};

// `ConsentGate` types the always-present `device_behavioral_consent_gate`
// store field (kept ungated so the struct keeps deriving `Default`); the rest
// of the consent machinery is compiled only under the axes feature.
use exo_consent::gatekeeper::ConsentGate;
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
use exo_consent::{
    ConsentDecision, ConsentPolicy, ConsentRequirement,
    bailment::{self, BailmentType},
};
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
use exo_core::crypto::KeyPair;
use exo_core::types::{Did, Hash256, ReceiptOutcome, Signature, Timestamp, TrustReceipt};
use exo_dag::dag::{DagNode, compute_node_hash};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{PgPool, Postgres, Row, Transaction};

use super::types::{
    BehavioralSample, ClaimStatus, DeviceFingerprint, IdentityClaim, IdentitySession, OtpChallenge,
    OtpChannel, OtpState, PeerAttestation, ZerodentityScore,
};

pub type ReceiptSigner = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;

/// Production 0dentity startup uses DAG DB-backed persistence.
pub const ZERODENTITY_STORE_PERSISTENCE_READY: bool = true;
/// Maximum future skew allowed between a caller-signed erasure timestamp and
/// the trusted validation timestamp supplied by the runtime.
pub const ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS: u64 = 500;

/// Startup warning emitted if a caller chooses the test/dev in-memory store.
pub const ZERODENTITY_STORE_PERSISTENCE_WARNING: &str =
    "0dentity production startup requires DAG DB-backed persistence";

// ---------------------------------------------------------------------------
// Device/behavioral consent scoping (VCG-009)
// ---------------------------------------------------------------------------

/// `exo_consent` action type gating persistence of client-collected device
/// fingerprint and behavioral biometric samples. Only registered under
/// `unaudited-zerodentity-device-behavioral-axes`; the feature-off path never
/// consults consent because it never reaches the ingestion branch at all.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
pub const DEVICE_BEHAVIORAL_CONSENT_ACTION: &str = "zerodentity.device_behavioral_ingest";
/// Consent policy role required of the subject granting device/behavioral
/// ingestion consent over their own claim.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
const DEVICE_BEHAVIORAL_CONSENT_ROLE: &str = "subject";
/// Minimum clearance level for the device/behavioral ingestion consent grant.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
const DEVICE_BEHAVIORAL_CONSENT_CLEARANCE: u32 = 1;
/// Fixed DID for the in-process 0dentity device/behavioral ingestion service.
/// This is the bailee in every self-consent bailment a subject grants over
/// their own device/behavioral samples: the subject (bailor) entrusts THIS
/// service with processing rights over evidence it is about to persist.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
const DEVICE_BEHAVIORAL_INGESTION_SERVICE_DID: &str =
    "did:exo:zerodentity-device-behavioral-ingestion-service";
/// Deterministic seed for the ingestion service's Ed25519 keypair. The
/// service signs its own bailment acceptance (it is the bailee); there is no
/// secret-material exposure here because this key only ever authorizes the
/// service to receive consent grants, never to act on a subject's behalf.
#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
const DEVICE_BEHAVIORAL_INGESTION_SERVICE_KEY_SEED: [u8; 32] = [0x0d; 32];

#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
fn device_behavioral_ingestion_service_keypair() -> anyhow::Result<&'static KeyPair> {
    static KEYPAIR: OnceLock<anyhow::Result<KeyPair>> = OnceLock::new();
    KEYPAIR
        .get_or_init(|| {
            KeyPair::from_secret_bytes(DEVICE_BEHAVIORAL_INGESTION_SERVICE_KEY_SEED).map_err(
                |error| {
                    anyhow::anyhow!("0dentity ingestion service keypair seed rejected: {error}")
                },
            )
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
fn device_behavioral_ingestion_service_did() -> anyhow::Result<Did> {
    Did::new(DEVICE_BEHAVIORAL_INGESTION_SERVICE_DID)
        .map_err(|error| anyhow::anyhow!("0dentity ingestion service DID malformed: {error}"))
}

#[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
fn device_behavioral_consent_policy() -> ConsentPolicy {
    ConsentPolicy {
        id: "zerodentity-device-behavioral-v1".into(),
        name: "0dentity device/behavioral ingestion consent".into(),
        deny_by_default: true,
        required_consents: vec![ConsentRequirement {
            action_type: DEVICE_BEHAVIORAL_CONSENT_ACTION.into(),
            required_role: DEVICE_BEHAVIORAL_CONSENT_ROLE.into(),
            min_clearance_level: DEVICE_BEHAVIORAL_CONSENT_CLEARANCE,
        }],
    }
}

#[derive(Debug, Clone, Default)]
enum ZerodentityStoreBackend {
    #[default]
    Memory,
    DagDb(PostgresZerodentityStore),
}

#[derive(Debug, Clone)]
struct PostgresZerodentityStore {
    pool: PgPool,
    tenant_id: String,
    namespace: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZerodentityRecordFamily {
    Claim,
    Score,
    PreviousScore,
    ScoreHistory,
    DeviceFingerprint,
    BehavioralSample,
    OtpChallenge,
    OtpLockout,
    Attestation,
    IdentitySession,
    SessionNonce,
    DagNode,
    TrustReceipt,
}

impl ZerodentityRecordFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Score => "score",
            Self::PreviousScore => "previous_score",
            Self::ScoreHistory => "score_history",
            Self::DeviceFingerprint => "device_fingerprint",
            Self::BehavioralSample => "behavioral_sample",
            Self::OtpChallenge => "otp_challenge",
            Self::OtpLockout => "otp_lockout",
            Self::Attestation => "attestation",
            Self::IdentitySession => "identity_session",
            Self::SessionNonce => "session_nonce",
            Self::DagNode => "dag_node",
            Self::TrustReceipt => "trust_receipt",
        }
    }

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "claim" => Ok(Self::Claim),
            "score" => Ok(Self::Score),
            "previous_score" => Ok(Self::PreviousScore),
            "score_history" => Ok(Self::ScoreHistory),
            "device_fingerprint" => Ok(Self::DeviceFingerprint),
            "behavioral_sample" => Ok(Self::BehavioralSample),
            "otp_challenge" => Ok(Self::OtpChallenge),
            "otp_lockout" => Ok(Self::OtpLockout),
            "attestation" => Ok(Self::Attestation),
            "identity_session" => Ok(Self::IdentitySession),
            "session_nonce" => Ok(Self::SessionNonce),
            "dag_node" => Ok(Self::DagNode),
            "trust_receipt" => Ok(Self::TrustReceipt),
            _ => anyhow::bail!("unknown 0dentity DAG DB state family {value}"),
        }
    }
}

#[derive(Debug, Clone)]
struct ZerodentityPersistedRow {
    family: ZerodentityRecordFamily,
    subject_did: String,
    record_key: String,
    secondary_key: String,
    cbor_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OtpChallengeRecord {
    challenge_id: String,
    subject_did: Did,
    channel: OtpChannel,
    hmac_secret_digest: Hash256,
    dispatched_ms: u64,
    ttl_ms: u64,
    attempts: u32,
    max_attempts: u32,
    state: OtpState,
}

impl From<&OtpChallenge> for OtpChallengeRecord {
    fn from(challenge: &OtpChallenge) -> Self {
        Self {
            challenge_id: challenge.challenge_id.clone(),
            subject_did: challenge.subject_did.clone(),
            channel: challenge.channel.clone(),
            hmac_secret_digest: otp_hmac_secret_digest(challenge.hmac_secret.expose_secret()),
            dispatched_ms: challenge.dispatched_ms,
            ttl_ms: challenge.ttl_ms,
            attempts: challenge.attempts,
            max_attempts: challenge.max_attempts,
            state: challenge.state.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OtpLockoutRecord {
    subject_did: Did,
    timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentitySessionRecord {
    session_token_digest: String,
    subject_did: Did,
    public_key: Vec<u8>,
    created_ms: u64,
    last_active_ms: u64,
    revoked: bool,
}

impl From<&IdentitySession> for IdentitySessionRecord {
    fn from(session: &IdentitySession) -> Self {
        Self {
            session_token_digest: session_token_digest(&session.session_token),
            subject_did: session.subject_did.clone(),
            public_key: session.public_key.clone(),
            created_ms: session.created_ms,
            last_active_ms: session.last_active_ms,
            revoked: session.revoked,
        }
    }
}

impl From<IdentitySessionRecord> for IdentitySession {
    fn from(record: IdentitySessionRecord) -> Self {
        Self {
            session_token: record.session_token_digest,
            subject_did: record.subject_did,
            public_key: record.public_key,
            created_ms: record.created_ms,
            last_active_ms: record.last_active_ms,
            revoked: record.revoked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionNonceRecord {
    session_token_digest: String,
    nonce_digest: String,
}

#[derive(Clone)]
pub struct ReceiptSigningContext {
    actor_did: Did,
    signer: ReceiptSigner,
}

impl ReceiptSigningContext {
    #[must_use]
    pub fn new(actor_did: Did, signer: ReceiptSigner) -> Self {
        Self { actor_did, signer }
    }
}

impl fmt::Debug for ReceiptSigningContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptSigningContext")
            .field("actor_did", &self.actor_did)
            .field("signer", &"<receipt signer>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSaveEvidence {
    pub dag_node_hash: Hash256,
    pub receipt_hash: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureEvidence {
    pub claims_revoked: u32,
    pub dag_node_hash: Hash256,
    pub action_hash: Hash256,
    pub receipt_hash: Hash256,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZerodentityReadFailure {
    Claims,
    Fingerprints,
    Behavioral,
}

fn canonicalize_claim_entries(claims: &mut [(String, IdentityClaim)]) {
    claims.sort_by(|(left_id, left), (right_id, right)| {
        left.created_ms
            .cmp(&right.created_ms)
            .then(left.verified_ms.cmp(&right.verified_ms))
            .then(left.claim_hash.as_bytes().cmp(right.claim_hash.as_bytes()))
            .then(left_id.cmp(right_id))
    });
}

fn canonicalize_fingerprints(fingerprints: &mut [DeviceFingerprint]) {
    fingerprints.sort_by(|left, right| {
        left.captured_ms
            .cmp(&right.captured_ms)
            .then(
                left.composite_hash
                    .as_bytes()
                    .cmp(right.composite_hash.as_bytes()),
            )
            .then(left.consistency_score_bp.cmp(&right.consistency_score_bp))
    });
}

fn canonicalize_behavioral_samples(samples: &mut [BehavioralSample]) {
    samples.sort_by(|left, right| {
        left.captured_ms
            .cmp(&right.captured_ms)
            .then(
                left.sample_hash
                    .as_bytes()
                    .cmp(right.sample_hash.as_bytes()),
            )
            .then(
                left.baseline_similarity_bp
                    .cmp(&right.baseline_similarity_bp),
            )
    });
}

fn persisted_auth_digest(domain: &str, material: &[u8]) -> Hash256 {
    let mut payload = Vec::with_capacity(domain.len() + 1 + material.len());
    payload.extend_from_slice(domain.as_bytes());
    payload.push(0);
    payload.extend_from_slice(material);
    Hash256::digest(&payload)
}

fn otp_hmac_secret_digest(secret: &[u8; 32]) -> Hash256 {
    persisted_auth_digest("exo.zerodentity.persisted_otp_hmac_secret.v1", secret)
}

fn session_token_digest(token: &str) -> String {
    persisted_auth_digest(
        "exo.zerodentity.persisted_session_token.v1",
        token.as_bytes(),
    )
    .to_string()
}

fn session_nonce_digest(nonce: &str) -> String {
    persisted_auth_digest(
        "exo.zerodentity.persisted_session_nonce.v1",
        nonce.as_bytes(),
    )
    .to_string()
}

pub(crate) fn otp_challenge_expired(challenge: &OtpChallenge, now_ms: u64) -> bool {
    challenge
        .dispatched_ms
        .checked_add(challenge.ttl_ms)
        .is_none_or(|expires_at| now_ms >= expires_at)
}

fn block_on_zerodentity<T, F>(future: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: Future<Output = anyhow::Result<T>> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(_) => std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| anyhow::anyhow!("0dentity DAG DB runtime: {error}"))?;
            runtime.block_on(future)
        })
        .join()
        .map_err(|_| anyhow::anyhow!("0dentity DAG DB worker panicked"))?,
        Err(_) => {
            let runtime = tokio::runtime::Runtime::new()
                .map_err(|error| anyhow::anyhow!("0dentity DAG DB runtime: {error}"))?;
            runtime.block_on(future)
        }
    }
}

fn decode_cbor<T: DeserializeOwned>(bytes: &[u8], field: &str) -> anyhow::Result<T> {
    ciborium::from_reader(bytes)
        .map_err(|error| anyhow::anyhow!("{field} CBOR decode failed: {error}"))
}

fn payload_hash(payload: &[u8]) -> Vec<u8> {
    Hash256::digest(payload).as_bytes().to_vec()
}

fn hash_key(hash: Hash256) -> String {
    hex::encode(hash.as_bytes())
}

fn score_history_key(score: &ZerodentityScore) -> String {
    format!(
        "{:020}:{}",
        score.computed_ms,
        hex::encode(score.dag_state_hash.as_bytes())
    )
}

fn fingerprint_key(fp: &DeviceFingerprint) -> String {
    format!(
        "{:020}:{}",
        fp.captured_ms,
        hex::encode(fp.composite_hash.as_bytes())
    )
}

fn behavioral_key(sample: &BehavioralSample) -> String {
    format!(
        "{:020}:{}",
        sample.captured_ms,
        hex::encode(sample.sample_hash.as_bytes())
    )
}

impl PostgresZerodentityStore {
    fn new(pool: PgPool, tenant_id: String, namespace: String) -> Self {
        Self {
            pool,
            tenant_id,
            namespace,
        }
    }

    async fn bind_tenant(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> std::result::Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('exo.tenant_id', $1, true)")
            .bind(&self.tenant_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn begin(&self) -> anyhow::Result<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await.map_err(|error| {
            anyhow::anyhow!("0dentity DAG DB transaction begin failed: {error}")
        })?;
        self.bind_tenant(&mut tx)
            .await
            .map_err(|error| anyhow::anyhow!("0dentity DAG DB tenant binding failed: {error}"))?;
        Ok(tx)
    }

    async fn verify_schema(&self) -> anyhow::Result<()> {
        let mut tx = self.begin().await?;
        let present: bool =
            sqlx::query_scalar("SELECT to_regclass('dagdb_zerodentity_records') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("0dentity DAG DB schema lookup failed: {error}")
                })?;
        tx.commit().await.map_err(|error| {
            anyhow::anyhow!("0dentity DAG DB schema check commit failed: {error}")
        })?;
        if !present {
            anyhow::bail!("DAG DB 0dentity schema is missing dagdb_zerodentity_records");
        }
        Ok(())
    }

    async fn load_rows(&self) -> anyhow::Result<Vec<ZerodentityPersistedRow>> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query(
            "SELECT state_family, subject_did, record_key, secondary_key, cbor_payload \
             FROM dagdb_zerodentity_records \
             WHERE tenant_id = $1 AND namespace = $2 \
             ORDER BY state_family ASC, subject_did ASC, record_key ASC, secondary_key ASC",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| anyhow::anyhow!("0dentity DAG DB reload failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| anyhow::anyhow!("0dentity DAG DB reload commit failed: {error}"))?;

        rows.into_iter()
            .map(|row| {
                Ok(ZerodentityPersistedRow {
                    family: ZerodentityRecordFamily::from_str(row.try_get("state_family")?)?,
                    subject_did: row.try_get("subject_did")?,
                    record_key: row.try_get("record_key")?,
                    secondary_key: row.try_get("secondary_key")?,
                    cbor_payload: row.try_get("cbor_payload")?,
                })
            })
            .collect()
    }

    async fn upsert_payload(
        &self,
        family: ZerodentityRecordFamily,
        subject_did: String,
        record_key: String,
        secondary_key: String,
        cbor_payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO dagdb_zerodentity_records \
             (tenant_id, namespace, state_family, subject_did, record_key, secondary_key, cbor_payload, payload_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (tenant_id, namespace, state_family, record_key, secondary_key) \
             DO UPDATE SET subject_did = EXCLUDED.subject_did, \
                           cbor_payload = EXCLUDED.cbor_payload, \
                           payload_hash = EXCLUDED.payload_hash",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(family.as_str())
        .bind(subject_did)
        .bind(record_key)
        .bind(secondary_key)
        .bind(&cbor_payload)
        .bind(payload_hash(&cbor_payload))
        .execute(&mut *tx)
        .await
        .map_err(|error| anyhow::anyhow!("0dentity DAG DB upsert failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| anyhow::anyhow!("0dentity DAG DB upsert commit failed: {error}"))?;
        Ok(())
    }

    async fn delete_record(
        &self,
        family: ZerodentityRecordFamily,
        record_key: String,
        secondary_key: String,
    ) -> anyhow::Result<()> {
        let mut tx = self.begin().await?;
        sqlx::query(
            "DELETE FROM dagdb_zerodentity_records \
             WHERE tenant_id = $1 AND namespace = $2 AND state_family = $3 \
               AND record_key = $4 AND secondary_key = $5",
        )
        .bind(&self.tenant_id)
        .bind(&self.namespace)
        .bind(family.as_str())
        .bind(record_key)
        .bind(secondary_key)
        .execute(&mut *tx)
        .await
        .map_err(|error| anyhow::anyhow!("0dentity DAG DB delete failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| anyhow::anyhow!("0dentity DAG DB delete commit failed: {error}"))?;
        Ok(())
    }

    async fn delete_subject_families(
        &self,
        subject_did: String,
        families: Vec<ZerodentityRecordFamily>,
    ) -> anyhow::Result<()> {
        let mut tx = self.begin().await?;
        for family in families {
            sqlx::query(
                "DELETE FROM dagdb_zerodentity_records \
                 WHERE tenant_id = $1 AND namespace = $2 AND state_family = $3 AND subject_did = $4",
            )
            .bind(&self.tenant_id)
            .bind(&self.namespace)
            .bind(family.as_str())
            .bind(&subject_did)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                anyhow::anyhow!("0dentity DAG DB subject-family delete failed: {error}")
            })?;
        }
        tx.commit().await.map_err(|error| {
            anyhow::anyhow!("0dentity DAG DB subject-family delete commit failed: {error}")
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ZerodentityStore
// ---------------------------------------------------------------------------

/// In-memory 0dentity store.
///
/// Keyed by DID string for O(log n) lookup.  All inner maps use `BTreeMap`
/// (never `HashMap`) for deterministic iteration order.
///
/// APE-72 replaces this with a SQLite-backed implementation; the public
/// interface must remain stable.
#[derive(Debug, Default)]
pub struct ZerodentityStore {
    /// In-memory DID registry for cryptographic standing.
    #[allow(dead_code)] // Used via trait methods in verification ceremony.
    pub did_registry: exo_identity::registry::LocalDidRegistry,
    /// Active verification ceremonies by session token.
    #[allow(dead_code)] // Used via trait methods in verification ceremony.
    pub ceremonies: BTreeMap<String, exo_identity::verification::VerificationCeremony>,
    /// Latest score snapshot per DID.
    scores: BTreeMap<String, ZerodentityScore>,
    /// Previous score snapshot per DID (one level of history).
    prev_scores: BTreeMap<String, ZerodentityScore>,
    /// All score history per DID.
    score_history: BTreeMap<String, Vec<ZerodentityScore>>,
    /// Identity claims per DID: (claim_id, claim).
    claims: BTreeMap<String, Vec<(String, IdentityClaim)>>,
    /// Device fingerprints per DID.
    fingerprints: BTreeMap<String, Vec<DeviceFingerprint>>,
    /// Behavioral samples per DID.
    behavioral: BTreeMap<String, Vec<BehavioralSample>>,
    /// OTP lockout event timestamps (epoch ms) per DID.
    otp_lockouts: BTreeMap<String, Vec<u64>>,
    /// Active OTP challenges by challenge_id.
    otp_challenges: BTreeMap<String, OtpChallenge>,
    /// Peer attestations: (attester_did_str, target_did_str) → attestation.
    attestations: BTreeMap<(String, String), PeerAttestation>,
    /// Identity sessions by session token.
    sessions: BTreeMap<String, IdentitySession>,
    /// Consumed request nonces keyed by `(session_token, nonce)`.
    session_request_nonces: BTreeSet<(String, String)>,
    /// DAG nodes recorded for claim operations (APE-72).
    dag_nodes: Vec<DagNode>,
    /// Trust receipts emitted for claim verification events (APE-72).
    trust_receipts: Vec<TrustReceipt>,
    /// Persistence backend used by production startup and test/dev helpers.
    backend: ZerodentityStoreBackend,
    /// Node identity signer used to emit verifiable trust receipts.
    receipt_signing: Option<ReceiptSigningContext>,
    /// Consent gate for device/behavioral sample ingestion (VCG-009).
    /// Lazily constructed on first use so `ZerodentityStore` can keep
    /// deriving `Default`; see `consent_gate_mut`.
    #[allow(dead_code)]
    device_behavioral_consent_gate: Option<ConsentGate>,
    /// Bailment ids already registered per `(subject_did, receipt_id)` so a
    /// replayed submit does not re-propose/re-accept a fresh bailment for an
    /// already-granted receipt.
    #[allow(dead_code)]
    device_behavioral_consent_receipts: BTreeSet<(String, String)>,
    #[cfg(test)]
    fail_claim_reads: bool,
    #[cfg(test)]
    fail_fingerprint_reads: bool,
    #[cfg(test)]
    fail_behavioral_reads: bool,
}

impl ZerodentityStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the current store implementation is durable across restarts.
    #[must_use]
    pub const fn persistence_ready() -> bool {
        ZERODENTITY_STORE_PERSISTENCE_READY
    }

    /// Operator-facing warning for the current persistence posture.
    #[must_use]
    pub const fn persistence_warning() -> &'static str {
        ZERODENTITY_STORE_PERSISTENCE_WARNING
    }

    /// Configure the node identity used to sign store-emitted trust receipts.
    pub fn set_receipt_signer(&mut self, actor_did: Did, signer: ReceiptSigner) {
        self.receipt_signing = Some(ReceiptSigningContext::new(actor_did, signer));
    }

    #[cfg(test)]
    pub(crate) fn inject_read_failure(&mut self, failure: ZerodentityReadFailure) {
        match failure {
            ZerodentityReadFailure::Claims => {
                self.fail_claim_reads = true;
            }
            ZerodentityReadFailure::Fingerprints => {
                self.fail_fingerprint_reads = true;
            }
            ZerodentityReadFailure::Behavioral => {
                self.fail_behavioral_reads = true;
            }
        }
    }

    /// Open the 0dentity store.
    ///
    /// This compatibility entry point is reserved for tests and dev-only
    /// callers. Production startup uses `open_dagdb`.
    #[allow(dead_code)]
    pub fn open(_data_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self::new())
    }

    /// Open the production 0dentity store from DAG DB and reload durable state.
    pub async fn open_dagdb(
        pool: PgPool,
        tenant_id: String,
        namespace: String,
    ) -> anyhow::Result<Self> {
        let backend = PostgresZerodentityStore::new(pool, tenant_id, namespace);
        backend.verify_schema().await?;
        let rows = backend.load_rows().await?;
        let mut store = Self {
            backend: ZerodentityStoreBackend::DagDb(backend),
            ..Self::default()
        };
        store.load_dagdb_rows(rows)?;
        Ok(store)
    }

    fn dagdb(&self) -> Option<&PostgresZerodentityStore> {
        match &self.backend {
            ZerodentityStoreBackend::Memory => None,
            ZerodentityStoreBackend::DagDb(store) => Some(store),
        }
    }

    fn load_dagdb_rows(&mut self, rows: Vec<ZerodentityPersistedRow>) -> anyhow::Result<()> {
        for row in rows {
            debug_assert!(row.secondary_key.is_ascii());
            match row.family {
                ZerodentityRecordFamily::Claim => {
                    let claim: IdentityClaim = decode_cbor(&row.cbor_payload, "0dentity claim")?;
                    self.claims
                        .entry(row.subject_did)
                        .or_default()
                        .push((row.record_key, claim));
                }
                ZerodentityRecordFamily::Score => {
                    let score: ZerodentityScore = decode_cbor(&row.cbor_payload, "0dentity score")?;
                    self.scores.insert(row.subject_did, score);
                }
                ZerodentityRecordFamily::PreviousScore => {
                    let score: ZerodentityScore =
                        decode_cbor(&row.cbor_payload, "0dentity previous score")?;
                    self.prev_scores.insert(row.subject_did, score);
                }
                ZerodentityRecordFamily::ScoreHistory => {
                    let score: ZerodentityScore =
                        decode_cbor(&row.cbor_payload, "0dentity score history")?;
                    self.score_history
                        .entry(row.subject_did)
                        .or_default()
                        .push(score);
                }
                ZerodentityRecordFamily::DeviceFingerprint => {
                    let fingerprint: DeviceFingerprint =
                        decode_cbor(&row.cbor_payload, "0dentity device fingerprint")?;
                    self.fingerprints
                        .entry(row.subject_did)
                        .or_default()
                        .push(fingerprint);
                }
                ZerodentityRecordFamily::BehavioralSample => {
                    let sample: BehavioralSample =
                        decode_cbor(&row.cbor_payload, "0dentity behavioral sample")?;
                    self.behavioral
                        .entry(row.subject_did)
                        .or_default()
                        .push(sample);
                }
                ZerodentityRecordFamily::OtpChallenge => {
                    let _persisted: OtpChallengeRecord =
                        decode_cbor(&row.cbor_payload, "0dentity OTP challenge")?;
                    // Persisted OTP rows intentionally carry only a digest of
                    // the HMAC secret. Pending challenges that survive a
                    // process restart fail closed instead of rehydrating live
                    // verifier secret material from DAG DB.
                }
                ZerodentityRecordFamily::OtpLockout => {
                    let lockout: OtpLockoutRecord =
                        decode_cbor(&row.cbor_payload, "0dentity OTP lockout")?;
                    self.otp_lockouts
                        .entry(row.subject_did)
                        .or_default()
                        .push(lockout.timestamp_ms);
                }
                ZerodentityRecordFamily::Attestation => {
                    let attestation: PeerAttestation =
                        decode_cbor(&row.cbor_payload, "0dentity attestation")?;
                    self.attestations.insert(
                        (
                            attestation.attester_did.as_str().to_owned(),
                            attestation.target_did.as_str().to_owned(),
                        ),
                        attestation,
                    );
                }
                ZerodentityRecordFamily::IdentitySession => {
                    let persisted: IdentitySessionRecord =
                        decode_cbor(&row.cbor_payload, "0dentity identity session")?;
                    let session = IdentitySession::from(persisted);
                    self.sessions.insert(session.session_token.clone(), session);
                }
                ZerodentityRecordFamily::SessionNonce => {
                    let nonce: SessionNonceRecord =
                        decode_cbor(&row.cbor_payload, "0dentity session nonce")?;
                    self.session_request_nonces
                        .insert((nonce.session_token_digest, nonce.nonce_digest));
                }
                ZerodentityRecordFamily::DagNode => {
                    let node: DagNode = decode_cbor(&row.cbor_payload, "0dentity DAG node")?;
                    self.dag_nodes.push(node);
                }
                ZerodentityRecordFamily::TrustReceipt => {
                    let receipt: TrustReceipt =
                        decode_cbor(&row.cbor_payload, "0dentity trust receipt")?;
                    self.trust_receipts.push(receipt);
                }
            }
        }

        for claims in self.claims.values_mut() {
            canonicalize_claim_entries(claims);
        }
        for fingerprints in self.fingerprints.values_mut() {
            canonicalize_fingerprints(fingerprints);
        }
        for samples in self.behavioral.values_mut() {
            canonicalize_behavioral_samples(samples);
        }
        self.dag_nodes.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then(left.hash.as_bytes().cmp(right.hash.as_bytes()))
        });
        self.trust_receipts.sort_by(|left, right| {
            left.timestamp.cmp(&right.timestamp).then(
                left.receipt_hash
                    .as_bytes()
                    .cmp(right.receipt_hash.as_bytes()),
            )
        });
        Ok(())
    }

    fn persist_payload<T: Serialize + Send + 'static>(
        &self,
        family: ZerodentityRecordFamily,
        subject_did: String,
        record_key: String,
        secondary_key: String,
        value: &T,
    ) -> anyhow::Result<()> {
        let Some(dagdb) = self.dagdb().cloned() else {
            return Ok(());
        };
        let payload = canonical_cbor(value)?;
        block_on_zerodentity(async move {
            dagdb
                .upsert_payload(family, subject_did, record_key, secondary_key, payload)
                .await
        })
    }

    fn delete_dagdb_record(
        &self,
        family: ZerodentityRecordFamily,
        record_key: String,
        secondary_key: String,
    ) -> anyhow::Result<()> {
        let Some(dagdb) = self.dagdb().cloned() else {
            return Ok(());
        };
        block_on_zerodentity(
            async move { dagdb.delete_record(family, record_key, secondary_key).await },
        )
    }

    fn delete_subject_families(
        &self,
        subject_did: String,
        families: Vec<ZerodentityRecordFamily>,
    ) -> anyhow::Result<()> {
        let Some(dagdb) = self.dagdb().cloned() else {
            return Ok(());
        };
        block_on_zerodentity(
            async move { dagdb.delete_subject_families(subject_did, families).await },
        )
    }

    fn persist_claim(
        &self,
        subject_did: &Did,
        claim_id: &str,
        claim: &IdentityClaim,
    ) -> anyhow::Result<()> {
        self.persist_payload(
            ZerodentityRecordFamily::Claim,
            subject_did.as_str().to_owned(),
            claim_id.to_owned(),
            String::new(),
            claim,
        )
    }

    fn persist_score_snapshot(
        &self,
        family: ZerodentityRecordFamily,
        score: &ZerodentityScore,
        secondary_key: String,
    ) -> anyhow::Result<()> {
        self.persist_payload(
            family,
            score.subject_did.as_str().to_owned(),
            score.subject_did.as_str().to_owned(),
            secondary_key,
            score,
        )
    }

    fn persist_otp_challenge(&self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        let record = OtpChallengeRecord::from(challenge);
        self.persist_payload(
            ZerodentityRecordFamily::OtpChallenge,
            challenge.subject_did.as_str().to_owned(),
            challenge.challenge_id.clone(),
            String::new(),
            &record,
        )
    }

    fn persist_dag_node(&self, node: &DagNode) -> anyhow::Result<()> {
        self.persist_payload(
            ZerodentityRecordFamily::DagNode,
            node.creator_did.as_str().to_owned(),
            hash_key(node.hash),
            String::new(),
            node,
        )
    }

    fn persist_trust_receipt(&self, receipt: &TrustReceipt) -> anyhow::Result<()> {
        self.persist_payload(
            ZerodentityRecordFamily::TrustReceipt,
            receipt.actor_did.as_str().to_owned(),
            hash_key(receipt.receipt_hash),
            String::new(),
            receipt,
        )
    }

    fn trust_receipt(
        &self,
        action_type: &str,
        action_hash: Hash256,
        outcome: ReceiptOutcome,
        timestamp: Timestamp,
    ) -> anyhow::Result<TrustReceipt> {
        let Some(context) = &self.receipt_signing else {
            anyhow::bail!("0dentity trust receipt signer is not configured");
        };
        Ok(TrustReceipt::new(
            context.actor_did.clone(),
            Hash256::ZERO,
            None,
            action_type.to_owned(),
            action_hash,
            outcome,
            timestamp,
            &*context.signer,
        )?)
    }

    fn next_dag_parents(&self) -> Vec<Hash256> {
        self.dag_nodes
            .last()
            .map_or_else(Vec::new, |parent| vec![parent.hash])
    }

    fn validate_next_dag_timestamp(
        &self,
        timestamp: Timestamp,
        label: &'static str,
    ) -> anyhow::Result<()> {
        if timestamp.physical_ms == 0 {
            anyhow::bail!("{label} timestamp must be greater than 0");
        }
        if let Some(parent) = self.dag_nodes.last() {
            if timestamp <= parent.timestamp {
                anyhow::bail!("{label} timestamp must strictly exceed latest DAG parent timestamp");
            }
        }
        Ok(())
    }

    fn next_claim_dag_timestamp(&self, created_ms: u64) -> anyhow::Result<Timestamp> {
        if created_ms == 0 {
            anyhow::bail!("0dentity claim DAG timestamp must be greater than 0");
        }
        if let Some(parent) = self.dag_nodes.last() {
            if created_ms < parent.timestamp.physical_ms {
                anyhow::bail!(
                    "0dentity claim DAG timestamp must not be older than latest DAG parent timestamp"
                );
            }
            if created_ms == parent.timestamp.physical_ms {
                let logical = parent.timestamp.logical.checked_add(1).ok_or_else(|| {
                    anyhow::anyhow!("0dentity claim DAG logical timestamp overflow")
                })?;
                return Ok(Timestamp::new(created_ms, logical));
            }
        }
        Ok(Timestamp::new(created_ms, 0))
    }

    /// Compute the next claim DAG node hash without mutating the store.
    pub fn next_claim_dag_node_hash(
        &self,
        payload_hash: Hash256,
        created_ms: u64,
    ) -> anyhow::Result<Hash256> {
        let Some(context) = &self.receipt_signing else {
            anyhow::bail!("0dentity DAG node signer is not configured");
        };
        let timestamp = self.next_claim_dag_timestamp(created_ms)?;
        self.validate_next_dag_timestamp(timestamp, "0dentity claim DAG")?;
        Ok(compute_node_hash(
            &self.next_dag_parents(),
            &payload_hash,
            &context.actor_did,
            &timestamp,
        )?)
    }

    fn signed_dag_node(
        &self,
        payload_hash: Hash256,
        timestamp: Timestamp,
    ) -> anyhow::Result<DagNode> {
        let Some(context) = &self.receipt_signing else {
            anyhow::bail!("0dentity DAG node signer is not configured");
        };
        self.validate_next_dag_timestamp(timestamp, "0dentity DAG node")?;
        let parents = self.next_dag_parents();
        let hash = compute_node_hash(&parents, &payload_hash, &context.actor_did, &timestamp)?;
        let signature = (context.signer)(hash.as_bytes());
        if signature.is_empty() {
            anyhow::bail!("0dentity DAG node signer produced an empty signature");
        }
        Ok(DagNode {
            hash,
            parents,
            payload_hash,
            creator_did: context.actor_did.clone(),
            timestamp,
            signature,
        })
    }

    fn validate_erasure_timestamp(
        &self,
        timestamp: Timestamp,
        validation_time: Timestamp,
    ) -> anyhow::Result<()> {
        if timestamp.physical_ms == 0 {
            anyhow::bail!("0dentity erasure timestamp must be greater than 0");
        }
        if validation_time.physical_ms == 0 {
            anyhow::bail!("0dentity erasure validation timestamp must be greater than 0");
        }
        if timestamp.physical_ms
            > validation_time
                .physical_ms
                .saturating_add(ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS)
        {
            anyhow::bail!("0dentity erasure timestamp exceeds trusted erasure clock tolerance");
        }
        if let Some(parent) = self.dag_nodes.last() {
            if timestamp <= parent.timestamp {
                anyhow::bail!(
                    "0dentity erasure timestamp must strictly exceed latest DAG parent timestamp"
                );
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — claims
    // -----------------------------------------------------------------------

    /// Store an identity claim under the given claim ID.
    #[allow(dead_code)]
    pub fn insert_claim(&mut self, claim_id: &str, claim: &IdentityClaim) -> anyhow::Result<()> {
        self.persist_claim(&claim.subject_did, claim_id, claim)?;
        self.claims
            .entry(claim.subject_did.as_str().to_owned())
            .or_default()
            .push((claim_id.to_owned(), claim.clone()));
        Ok(())
    }

    /// Append a claim for a DID (mutable convenience method).
    #[allow(dead_code)]
    pub fn put_claim(&mut self, claim: IdentityClaim) -> anyhow::Result<()> {
        let key = claim.subject_did.as_str().to_owned();
        let claim_id = hex::encode(claim.claim_hash.as_bytes());
        self.persist_claim(&claim.subject_did, &claim_id, &claim)?;
        self.claims.entry(key).or_default().push((claim_id, claim));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — fingerprints / behavioral
    // -----------------------------------------------------------------------

    /// Append a device fingerprint for a DID.
    #[allow(dead_code)]
    pub fn put_fingerprint(&mut self, did: &Did, fp: DeviceFingerprint) -> anyhow::Result<()> {
        self.persist_payload(
            ZerodentityRecordFamily::DeviceFingerprint,
            did.as_str().to_owned(),
            did.as_str().to_owned(),
            fingerprint_key(&fp),
            &fp,
        )?;
        self.fingerprints
            .entry(did.as_str().to_owned())
            .or_default()
            .push(fp);
        Ok(())
    }

    /// Append a behavioral sample for a DID.
    #[allow(dead_code)]
    pub fn put_behavioral(&mut self, did: &Did, sample: BehavioralSample) -> anyhow::Result<()> {
        self.persist_payload(
            ZerodentityRecordFamily::BehavioralSample,
            did.as_str().to_owned(),
            did.as_str().to_owned(),
            behavioral_key(&sample),
            &sample,
        )?;
        self.behavioral
            .entry(did.as_str().to_owned())
            .or_default()
            .push(sample);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Consent — device/behavioral ingestion (VCG-009)
    // -----------------------------------------------------------------------

    /// Lazily construct the device/behavioral consent gate.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    fn device_behavioral_consent_gate(&mut self) -> &mut ConsentGate {
        self.device_behavioral_consent_gate
            .get_or_insert_with(|| ConsentGate::new(device_behavioral_consent_policy()))
    }

    /// Whether `did` currently holds at least one active (non-revoked,
    /// unexpired) session at `now_ms`.
    ///
    /// Consent to persist device/behavioral evidence is scoped to a subject
    /// who has already proven control of the DID through OTP-verified
    /// session bootstrap; a DID with no live session has no basis to
    /// self-consent to anything.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    fn has_active_session_for(&self, did: &Did, now_ms: u64) -> bool {
        self.sessions.values().any(|session| {
            session.subject_did == *did
                && !session.revoked
                && now_ms >= session.created_ms
                && !session.is_expired_at(now_ms)
        })
    }

    /// Register (idempotently) and check a self-consent grant for the
    /// subject to allow the 0dentity device/behavioral ingestion service to
    /// persist client-collected samples for their own scoring.
    ///
    /// Returns `Ok(true)` only when:
    /// - `receipt_id` is non-empty, AND
    /// - the subject holds an active session at `now_ms` (proof they control
    ///   this DID), AND
    /// - `exo_consent::gatekeeper::ConsentGate::check` returns `Granted` for
    ///   the `zerodentity.device_behavioral_ingest` action.
    ///
    /// A subject with no active session can register nothing: no bailment is
    /// proposed/accepted and the gate is never granted, so callers must
    /// treat `Ok(false)` as "reject and persist nothing" (default-deny).
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    pub fn check_device_behavioral_consent(
        &mut self,
        subject_did: &Did,
        receipt_id: &str,
        now_ms: u64,
    ) -> anyhow::Result<bool> {
        if receipt_id.trim().is_empty() {
            return Ok(false);
        }
        if !self.has_active_session_for(subject_did, now_ms) {
            return Ok(false);
        }

        let receipt_key = (subject_did.as_str().to_owned(), receipt_id.to_owned());
        if !self
            .device_behavioral_consent_receipts
            .contains(&receipt_key)
        {
            self.register_device_behavioral_consent_bailment(subject_did, receipt_id, now_ms)?;
            self.device_behavioral_consent_receipts.insert(receipt_key);
        }

        let now = Timestamp::new(now_ms, 0);
        let decision = self
            .device_behavioral_consent_gate()
            .check(subject_did, DEVICE_BEHAVIORAL_CONSENT_ACTION, &now)
            .map_err(|error| anyhow::anyhow!("device/behavioral consent check failed: {error}"))?;
        Ok(matches!(decision, ConsentDecision::Granted { .. }))
    }

    /// Propose, self-accept (by the fixed ingestion-service bailee key), and
    /// register a bailment granting the 0dentity device/behavioral
    /// ingestion service processing rights over `subject_did`'s own
    /// client-collected samples for the given `receipt_id`.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    fn register_device_behavioral_consent_bailment(
        &mut self,
        subject_did: &Did,
        receipt_id: &str,
        now_ms: u64,
    ) -> anyhow::Result<()> {
        let bailee_did = device_behavioral_ingestion_service_did()?;
        let bailment_id = format!(
            "zerodentity-device-behavioral-consent:{}:{receipt_id}",
            subject_did.as_str()
        );
        let created = Timestamp::new(now_ms.max(1), 0);
        let mut bailment = bailment::propose(
            subject_did,
            &bailee_did,
            receipt_id.as_bytes(),
            BailmentType::Processing,
            bailment_id,
            created,
        )
        .map_err(|error| anyhow::anyhow!("device/behavioral bailment proposal failed: {error}"))?;

        let keypair = device_behavioral_ingestion_service_keypair()?;
        let payload = bailment::signing_payload(&bailment)
            .map_err(|error| anyhow::anyhow!("bailment signing payload failed: {error}"))?;
        let signature = keypair.sign(&payload);
        bailment::accept(
            &mut bailment,
            |did| (*did == bailee_did).then_some(*keypair.public_key()),
            &signature,
        )
        .map_err(|error| {
            anyhow::anyhow!("device/behavioral bailment acceptance failed: {error}")
        })?;

        let gate = self.device_behavioral_consent_gate();
        gate.register_bailment(bailment.clone()).map_err(|error| {
            anyhow::anyhow!("device/behavioral bailment registration failed: {error}")
        })?;
        gate.register_consent(
            subject_did,
            DEVICE_BEHAVIORAL_CONSENT_ACTION,
            DEVICE_BEHAVIORAL_CONSENT_ROLE,
            DEVICE_BEHAVIORAL_CONSENT_CLEARANCE,
            bailment,
        )
        .map_err(|error| {
            anyhow::anyhow!("device/behavioral consent registration failed: {error}")
        })?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — scores
    // -----------------------------------------------------------------------

    /// Store a new score snapshot, shifting the current to `prev_scores`.
    #[allow(dead_code)]
    pub fn put_score(&mut self, score: ZerodentityScore) -> anyhow::Result<()> {
        let key = score.subject_did.as_str().to_owned();
        let previous = self.scores.get(&key).cloned();
        if let Some(existing) = &previous {
            self.persist_score_snapshot(
                ZerodentityRecordFamily::PreviousScore,
                existing,
                String::new(),
            )?;
        }
        self.persist_score_snapshot(ZerodentityRecordFamily::Score, &score, String::new())?;
        self.persist_score_snapshot(
            ZerodentityRecordFamily::ScoreHistory,
            &score,
            score_history_key(&score),
        )?;
        if let Some(existing) = self.scores.remove(&key) {
            self.prev_scores.insert(key.clone(), existing);
        }
        self.score_history
            .entry(key.clone())
            .or_default()
            .push(score.clone());
        self.scores.insert(key, score);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — OTP
    // -----------------------------------------------------------------------

    /// Record an OTP lockout event at `timestamp_ms` for a DID.
    #[allow(dead_code)]
    pub fn record_otp_lockout(&mut self, did: &Did, timestamp_ms: u64) -> anyhow::Result<()> {
        let record = OtpLockoutRecord {
            subject_did: did.clone(),
            timestamp_ms,
        };
        self.persist_payload(
            ZerodentityRecordFamily::OtpLockout,
            did.as_str().to_owned(),
            did.as_str().to_owned(),
            format!("{timestamp_ms:020}"),
            &record,
        )?;
        self.otp_lockouts
            .entry(did.as_str().to_owned())
            .or_default()
            .push(timestamp_ms);
        Ok(())
    }

    /// Persist an OTP challenge.
    pub fn insert_otp_challenge(&mut self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        self.persist_otp_challenge(challenge)?;
        self.otp_challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(())
    }

    /// Update the state of an existing OTP challenge.
    pub fn update_otp_challenge(&mut self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        if self.otp_challenges.contains_key(&challenge.challenge_id) {
            self.persist_otp_challenge(challenge)?;
            self.otp_challenges
                .insert(challenge.challenge_id.clone(), challenge.clone());
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write — attestations
    // -----------------------------------------------------------------------

    /// Persist a peer attestation.
    pub fn insert_attestation(&mut self, att: &PeerAttestation) -> anyhow::Result<()> {
        let key = (
            att.attester_did.as_str().to_owned(),
            att.target_did.as_str().to_owned(),
        );
        self.persist_payload(
            ZerodentityRecordFamily::Attestation,
            att.target_did.as_str().to_owned(),
            key.0.clone(),
            key.1.clone(),
            att,
        )?;
        self.attestations.insert(key, att.clone());
        Ok(())
    }

    /// Return a stored peer attestation by attester and target.
    pub fn get_attestation(
        &self,
        attester: &Did,
        target: &Did,
    ) -> anyhow::Result<Option<PeerAttestation>> {
        let key = (attester.as_str().to_owned(), target.as_str().to_owned());
        Ok(self.attestations.get(&key).cloned())
    }

    // -----------------------------------------------------------------------
    // Write — sessions
    // -----------------------------------------------------------------------

    /// Persist an identity session.
    pub fn insert_session(&mut self, session: &IdentitySession) -> anyhow::Result<()> {
        let persisted = IdentitySessionRecord::from(session);
        self.persist_payload(
            ZerodentityRecordFamily::IdentitySession,
            session.subject_did.as_str().to_owned(),
            persisted.session_token_digest.clone(),
            String::new(),
            &persisted,
        )?;
        self.sessions
            .insert(session.session_token.clone(), session.clone());
        Ok(())
    }

    /// Consume a session request nonce.
    ///
    /// Returns `true` when the nonce was new and is now consumed. Returns
    /// `false` when the same session already used the nonce.
    pub fn consume_session_nonce(
        &mut self,
        session_token: &str,
        nonce: &str,
    ) -> anyhow::Result<bool> {
        let nonce_key = (session_token.to_owned(), nonce.to_owned());
        let persisted_nonce_key = (
            session_token_digest(session_token),
            session_nonce_digest(nonce),
        );
        if self.session_request_nonces.contains(&nonce_key)
            || self.session_request_nonces.contains(&persisted_nonce_key)
        {
            return Ok(false);
        }
        let subject_did = self
            .sessions
            .get(session_token)
            .or_else(|| self.sessions.get(&persisted_nonce_key.0))
            .map_or_else(
                || "unbound-session-nonce".to_owned(),
                |session| session.subject_did.as_str().to_owned(),
            );
        let record = SessionNonceRecord {
            session_token_digest: persisted_nonce_key.0.clone(),
            nonce_digest: persisted_nonce_key.1.clone(),
        };
        self.persist_payload(
            ZerodentityRecordFamily::SessionNonce,
            subject_did,
            persisted_nonce_key.0.clone(),
            persisted_nonce_key.1.clone(),
            &record,
        )?;
        self.session_request_nonces.insert(nonce_key);
        self.session_request_nonces.insert(persisted_nonce_key);
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Read — claims
    // -----------------------------------------------------------------------

    /// Return all claims for a DID with their claim IDs.
    ///
    /// Returns an empty `Vec` (not an error) when the DID has no claims.
    pub fn get_claims(&self, did: &Did) -> anyhow::Result<Vec<(String, IdentityClaim)>> {
        #[cfg(test)]
        if self.fail_claim_reads {
            anyhow::bail!("injected 0dentity claims read failure");
        }
        let mut claims = self.claims.get(did.as_str()).cloned().unwrap_or_default();
        canonicalize_claim_entries(&mut claims);
        Ok(claims)
    }

    /// Return all claims for a DID as a plain slice (no claim IDs).
    ///
    /// Convenience method for callers that only need the claims themselves
    /// (e.g., sentinels and scoring).
    #[allow(dead_code)]
    pub fn get_claims_slice(&self, did: &Did) -> anyhow::Result<Vec<IdentityClaim>> {
        self.get_claims(did)
            .map(|entries| entries.into_iter().map(|(_, c)| c).collect())
    }

    // -----------------------------------------------------------------------
    // Read — fingerprints / behavioral
    // -----------------------------------------------------------------------

    /// Return all device fingerprints for a DID.
    pub fn get_fingerprints(&self, did: &Did) -> anyhow::Result<Vec<DeviceFingerprint>> {
        #[cfg(test)]
        if self.fail_fingerprint_reads {
            anyhow::bail!("injected 0dentity fingerprint read failure");
        }
        let mut fingerprints = self
            .fingerprints
            .get(did.as_str())
            .cloned()
            .unwrap_or_default();
        canonicalize_fingerprints(&mut fingerprints);
        Ok(fingerprints)
    }

    /// Return all behavioral samples for a DID.
    pub fn get_behavioral_samples(&self, did: &Did) -> anyhow::Result<Vec<BehavioralSample>> {
        #[cfg(test)]
        if self.fail_behavioral_reads {
            anyhow::bail!("injected 0dentity behavioral read failure");
        }
        let mut samples = self
            .behavioral
            .get(did.as_str())
            .cloned()
            .unwrap_or_default();
        canonicalize_behavioral_samples(&mut samples);
        Ok(samples)
    }

    // -----------------------------------------------------------------------
    // Read — scores
    // -----------------------------------------------------------------------

    /// Return the latest score for a DID, or `None` if not yet scored.
    #[must_use]
    pub fn get_score(&self, did: &Did) -> Option<&ZerodentityScore> {
        self.scores.get(did.as_str())
    }

    /// Return the previous score snapshot for a DID, or `None`.
    #[must_use]
    pub fn get_previous_score(&self, did: &Did) -> Option<&ZerodentityScore> {
        self.prev_scores.get(did.as_str())
    }

    /// Return score history for a DID, optionally filtered by time range.
    pub fn get_score_history(
        &self,
        did: &Did,
        from_ms: Option<u64>,
        to_ms: Option<u64>,
    ) -> anyhow::Result<Vec<ZerodentityScore>> {
        let history = self
            .score_history
            .get(did.as_str())
            .map_or(&[][..], Vec::as_slice);
        let filtered: Vec<ZerodentityScore> = history
            .iter()
            .filter(|s| {
                let after = from_ms.is_none_or(|f| s.computed_ms >= f);
                let before = to_ms.is_none_or(|t| s.computed_ms <= t);
                after && before
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    // -----------------------------------------------------------------------
    // Read — OTP
    // -----------------------------------------------------------------------

    /// Return `true` if there is any OTP lockout event for `did` at or after
    /// `since_ms`.
    #[must_use]
    pub fn has_otp_lockout_since(&self, did: &Did, since_ms: u64) -> bool {
        self.otp_lockouts
            .get(did.as_str())
            .is_some_and(|events| events.iter().any(|&t| t >= since_ms))
    }

    /// Retrieve an OTP challenge by ID.
    pub fn get_otp_challenge(&self, challenge_id: &str) -> anyhow::Result<Option<OtpChallenge>> {
        Ok(self.otp_challenges.get(challenge_id).cloned())
    }

    // -----------------------------------------------------------------------
    // Read — attestations
    // -----------------------------------------------------------------------

    /// Return `true` if an attestation from `attester` to `target` already exists.
    pub fn attestation_exists(&self, attester: &Did, target: &Did) -> anyhow::Result<bool> {
        Ok(self.get_attestation(attester, target)?.is_some())
    }

    // -----------------------------------------------------------------------
    // Read — sessions
    // -----------------------------------------------------------------------

    /// Retrieve an identity session by token at a trusted timestamp.
    ///
    /// Returns `None` if no matching session exists or if the session has been
    /// revoked or expired.
    pub fn get_session(&self, token: &str, now_ms: u64) -> anyhow::Result<Option<IdentitySession>> {
        let token_digest = session_token_digest(token);
        Ok(self
            .sessions
            .get(token)
            .or_else(|| self.sessions.get(&token_digest))
            .filter(|s| !s.revoked && now_ms >= s.created_ms && !s.is_expired_at(now_ms))
            .cloned())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Sample up to `n` DIDs that have at least one stored score.
    ///
    /// Returns DIDs in sorted order (deterministic) — the sentinel picks
    /// entries from the front for repeatable verification.
    #[must_use]
    pub fn sample_scored_dids(&self, n: usize) -> Vec<Did> {
        self.scores
            .keys()
            .take(n)
            .filter_map(|k| Did::new(k).ok())
            .collect()
    }

    /// Return a bounded page of scored DIDs after the optional cursor.
    ///
    /// Pages are sorted by DID and strictly greater than `after` when a cursor
    /// is provided, so callers can scan the full deterministic keyspace without
    /// holding the store lock for the entire scan.
    #[must_use]
    pub fn scored_dids_page_after(&self, after: Option<&Did>, n: usize) -> Vec<Did> {
        if n == 0 {
            return Vec::new();
        }

        let bounds = match after {
            Some(did) => (
                std::ops::Bound::Excluded(did.as_str().to_owned()),
                std::ops::Bound::Unbounded,
            ),
            None => (std::ops::Bound::Unbounded, std::ops::Bound::Unbounded),
        };

        self.scores
            .range(bounds)
            .take(n)
            .filter_map(|(k, _)| Did::new(k).ok())
            .collect()
    }

    /// Return the count of distinct scored DIDs.
    #[must_use]
    pub fn scored_did_count(&self) -> usize {
        self.scores.len()
    }

    // -----------------------------------------------------------------------
    // APE-72 — CRUD API + DAG/TrustReceipt integration
    // -----------------------------------------------------------------------

    /// Run schema migrations — no-op for the in-memory implementation.
    ///
    /// Idempotent; always returns `Ok(())`.
    #[allow(dead_code)]
    pub fn run_migrations(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Persist a claim, record a DAG node entry, and optionally emit a
    /// `TrustReceipt` when the claim is already `Verified`.
    ///
    /// - A `DagNode` is appended to `self.dag_nodes` on every call.
    /// - A `TrustReceipt` (outcome `Executed`) is pushed to
    ///   `self.trust_receipts` when `claim.status == Verified`.
    #[allow(dead_code)]
    pub fn save_claim(&mut self, claim_id: &str, claim: &IdentityClaim) -> anyhow::Result<()> {
        self.save_claim_with_evidence(claim_id, claim).map(|_| ())
    }

    /// Persist a claim and return the signed DAG / receipt evidence produced.
    pub fn save_claim_with_evidence(
        &mut self,
        claim_id: &str,
        claim: &IdentityClaim,
    ) -> anyhow::Result<ClaimSaveEvidence> {
        let timestamp = self.next_claim_dag_timestamp(claim.created_ms)?;
        let node = self.signed_dag_node(claim.claim_hash, timestamp)?;
        let receipt = if claim.status == ClaimStatus::Verified {
            let verified_ms = claim.verified_ms.unwrap_or(claim.created_ms);
            Some(self.trust_receipt(
                "zerodentity.claim_verified",
                claim.claim_hash,
                ReceiptOutcome::Executed,
                Timestamp::new(verified_ms, 0),
            )?)
        } else {
            None
        };

        let dag_node_hash = node.hash;
        let mut stored_claim = claim.clone();
        stored_claim.dag_node_hash = dag_node_hash;
        self.persist_claim(&stored_claim.subject_did, claim_id, &stored_claim)?;
        self.persist_dag_node(&node)?;
        if let Some(receipt) = &receipt {
            self.persist_trust_receipt(receipt)?;
        }
        self.claims
            .entry(stored_claim.subject_did.as_str().to_owned())
            .or_default()
            .push((claim_id.to_owned(), stored_claim));
        self.dag_nodes.push(node);

        // Emit TrustReceipt for verified claims.
        let receipt_hash = receipt.as_ref().map(|receipt| receipt.receipt_hash);
        if let Some(receipt) = receipt {
            self.trust_receipts.push(receipt);
        }

        Ok(ClaimSaveEvidence {
            dag_node_hash,
            receipt_hash,
        })
    }

    /// Persist an OTP challenge (APE-72 alias for `insert_otp_challenge`).
    #[allow(dead_code)]
    pub fn save_otp(&mut self, challenge: &OtpChallenge) -> anyhow::Result<()> {
        self.insert_otp_challenge(challenge)
    }

    /// Retrieve an OTP challenge by ID (APE-72 alias for `get_otp_challenge`).
    #[allow(dead_code)]
    pub fn get_otp(&self, challenge_id: &str) -> anyhow::Result<Option<OtpChallenge>> {
        self.get_otp_challenge(challenge_id)
    }

    /// Persist a new score snapshot (APE-72 alias for `put_score`).
    #[allow(dead_code)]
    pub fn save_score(&mut self, score: ZerodentityScore) -> anyhow::Result<()> {
        self.put_score(score)
    }

    /// Return all recorded DAG nodes (APE-72 audit accessor).
    #[must_use]
    #[allow(dead_code)]
    pub fn dag_nodes(&self) -> &[DagNode] {
        &self.dag_nodes
    }

    /// Return all recorded trust receipts (APE-72 audit accessor).
    #[must_use]
    #[allow(dead_code)]
    pub fn trust_receipts(&self) -> &[TrustReceipt] {
        &self.trust_receipts
    }

    // -----------------------------------------------------------------------
    // Write — erasure (§11.4 Right to Erasure)
    // -----------------------------------------------------------------------

    /// Erase all stored 0dentity data for `did` and return the signed evidence
    /// emitted for the erasure.
    ///
    /// Implements §11.4 — right to erasure:
    /// 1. Revoke all sessions for this DID.
    /// 2. Mark all claims as `Revoked`.
    /// 3. Remove score snapshots (current, previous, history).
    /// 4. Remove fingerprints and behavioral samples.
    /// 5. Remove OTP challenges belonging to this DID.
    /// 6. Tombstone DAG nodes — zero payload hash, keep structural links.
    /// 7. Emit an erasure receipt.
    pub fn erase_did_with_evidence(
        &mut self,
        did: &Did,
        timestamp: Timestamp,
        validation_time: Timestamp,
    ) -> anyhow::Result<ErasureEvidence> {
        if self.receipt_signing.is_none() {
            anyhow::bail!("0dentity trust receipt signer is not configured");
        }
        self.validate_erasure_timestamp(timestamp, validation_time)?;

        let key = did.as_str().to_owned();
        let mut revoked_count = 0u32;

        // 1. Revoke sessions
        for session in self.sessions.values_mut() {
            if session.subject_did.as_str() == did.as_str() {
                session.revoked = true;
            }
        }

        // 2. Mark claims Revoked
        if let Some(claims) = self.claims.get_mut(&key) {
            for (_, claim) in claims.iter_mut() {
                if claim.status != ClaimStatus::Revoked {
                    claim.status = ClaimStatus::Revoked;
                    revoked_count += 1;
                }
            }
        }

        // 3. Zero score snapshots
        self.scores.remove(&key);
        self.prev_scores.remove(&key);
        self.score_history.remove(&key);

        // 4. Remove fingerprints and behavioral samples
        self.fingerprints.remove(&key);
        self.behavioral.remove(&key);

        // 5. Remove OTP challenges for this DID
        self.otp_challenges
            .retain(|_, ch| ch.subject_did.as_str() != did.as_str());

        // 6. Emit erasure receipt and append a signed erasure DAG node. The
        // existing claim nodes remain append-only; erasure is represented as a
        // new tombstone event.
        let erasure_hash = erasure_action_hash(did)?;
        let receipt = self.trust_receipt(
            "zerodentity.identity_erased",
            erasure_hash,
            ReceiptOutcome::Executed,
            timestamp,
        )?;
        let erasure_node = self.signed_dag_node(erasure_hash, timestamp)?;
        let dag_node_hash = erasure_node.hash;
        let receipt_hash = receipt.receipt_hash;
        self.delete_subject_families(
            key.clone(),
            vec![
                ZerodentityRecordFamily::Claim,
                ZerodentityRecordFamily::Score,
                ZerodentityRecordFamily::PreviousScore,
                ZerodentityRecordFamily::ScoreHistory,
                ZerodentityRecordFamily::DeviceFingerprint,
                ZerodentityRecordFamily::BehavioralSample,
                ZerodentityRecordFamily::OtpChallenge,
                ZerodentityRecordFamily::OtpLockout,
                ZerodentityRecordFamily::IdentitySession,
            ],
        )?;
        if let Some(claims) = self.claims.get(&key) {
            for (claim_id, claim) in claims {
                self.persist_claim(did, claim_id, claim)?;
            }
        }
        for session in self
            .sessions
            .values()
            .filter(|session| session.subject_did.as_str() == did.as_str())
        {
            let persisted = IdentitySessionRecord::from(session);
            self.persist_payload(
                ZerodentityRecordFamily::IdentitySession,
                session.subject_did.as_str().to_owned(),
                persisted.session_token_digest.clone(),
                String::new(),
                &persisted,
            )?;
        }
        self.persist_dag_node(&erasure_node)?;
        self.persist_trust_receipt(&receipt)?;
        self.dag_nodes.push(erasure_node);
        self.trust_receipts.push(receipt);

        Ok(ErasureEvidence {
            claims_revoked: revoked_count,
            dag_node_hash,
            action_hash: erasure_hash,
            receipt_hash,
        })
    }

    // -----------------------------------------------------------------------
    // Read — OTP challenges (sentinel support)
    // -----------------------------------------------------------------------

    /// Return all OTP challenges (for sentinel cleanup checks).
    #[must_use]
    pub fn all_otp_challenges(&self) -> Vec<&OtpChallenge> {
        self.otp_challenges.values().collect()
    }

    /// Remove expired OTP challenges that are still in `Pending` state.
    ///
    /// Returns the number of challenges cleaned up.
    pub fn cleanup_expired_otp(&mut self, now_ms: u64) -> anyhow::Result<usize> {
        let expired_pending_ids: Vec<String> = self
            .otp_challenges
            .iter()
            .filter_map(|(challenge_id, challenge)| {
                let expired = otp_challenge_expired(challenge, now_ms);
                let pending = challenge.state == super::types::OtpState::Pending;
                (expired && pending).then(|| challenge_id.clone())
            })
            .collect();
        for challenge_id in &expired_pending_ids {
            self.delete_dagdb_record(
                ZerodentityRecordFamily::OtpChallenge,
                challenge_id.clone(),
                String::new(),
            )?;
        }
        let before = self.otp_challenges.len();
        self.otp_challenges.retain(|_, ch| {
            let expired = otp_challenge_expired(ch, now_ms);
            let pending = ch.state == super::types::OtpState::Pending;
            // Remove if both expired and still pending
            !(expired && pending)
        });
        Ok(before - self.otp_challenges.len())
    }
}

/// Thread-safe shared handle to the 0dentity store.
pub type SharedZerodentityStore = Arc<Mutex<ZerodentityStore>>;

/// Create a new empty shared store.
#[must_use]
#[allow(dead_code)]
pub fn new_shared_store() -> SharedZerodentityStore {
    Arc::new(Mutex::new(ZerodentityStore::new()))
}

fn canonical_cbor<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

/// Domain-separated canonical action hash for a 0dentity erasure event.
pub fn erasure_action_hash(did: &Did) -> anyhow::Result<Hash256> {
    let payload = ("exo.zerodentity.identity_erased.v1", did.as_str());
    Ok(Hash256::digest(&canonical_cbor(&payload)?))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use exo_core::{
        crypto::{KeyPair, verify},
        types::{Did, Hash256, PublicKey, Signature, Timestamp},
    };

    use super::*;
    use crate::zerodentity::types::{
        ClaimStatus, ClaimType, IdentityClaim, OtpHmacSecret, PolarAxes, ZerodentityScore,
    };

    fn did(s: &str) -> Did {
        Did::new(s).unwrap()
    }

    fn h() -> Hash256 {
        Hash256::digest(b"t")
    }

    fn otp_secret(seed: u8) -> OtpHmacSecret {
        OtpHmacSecret::new([seed; 32]).unwrap()
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn signed_store(seed: u8) -> (ZerodentityStore, Did, PublicKey) {
        let keypair = KeyPair::from_secret_bytes([seed; 32]).unwrap();
        let public_key = *keypair.public_key();
        let actor_did = did(&format!("did:exo:receipt-node-{seed}"));
        let signer = Arc::new(move |payload: &[u8]| keypair.sign(payload));
        let mut store = ZerodentityStore::new();
        store.set_receipt_signer(actor_did.clone(), signer);
        (store, actor_did, public_key)
    }

    fn score_for(subject_did: Did, composite: u32) -> ZerodentityScore {
        ZerodentityScore {
            subject_did,
            axes: PolarAxes {
                communication: composite,
                credential_depth: composite,
                device_trust: composite,
                behavioral_signature: composite,
                network_reputation: composite,
                temporal_stability: composite,
                cryptographic_strength: composite,
                constitutional_standing: composite,
            },
            composite,
            computed_ms: 1_000_000,
            dag_state_hash: h(),
            claim_count: 0,
            symmetry: 10_000,
        }
    }

    fn claim(d: &Did, ct: ClaimType) -> IdentityClaim {
        IdentityClaim {
            claim_hash: h(),
            subject_did: d.clone(),
            claim_type: ct,
            status: ClaimStatus::Verified,
            created_ms: 1000,
            verified_ms: Some(2000),
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: h(),
        }
    }

    #[test]
    fn persisted_otp_challenge_record_redacts_hmac_secret() {
        let raw_secret = [0x42; 32];
        let challenge = OtpChallenge {
            challenge_id: "otp-persist-redaction".into(),
            subject_did: did("did:exo:otp-redaction"),
            channel: OtpChannel::Email,
            hmac_secret: OtpHmacSecret::new(raw_secret).unwrap(),
            dispatched_ms: 1_000,
            ttl_ms: OtpChannel::Email.ttl_ms(),
            attempts: 0,
            max_attempts: 3,
            state: OtpState::Pending,
        };

        let record = OtpChallengeRecord::from(&challenge);
        let encoded = canonical_cbor(&record).unwrap();

        assert_ne!(record.hmac_secret_digest.as_bytes(), &raw_secret);
        assert!(
            !bytes_contain(&encoded, &raw_secret),
            "persisted OTP challenge CBOR must not contain raw HMAC secret bytes"
        );
    }

    #[test]
    fn persisted_session_and_nonce_records_redact_bearer_material() {
        let token = "session-token-must-not-hit-dagdb";
        let nonce = "nonce-must-not-hit-dagdb";
        let session = IdentitySession {
            session_token: token.into(),
            subject_did: did("did:exo:session-redaction"),
            public_key: vec![7; 32],
            created_ms: 1_000,
            last_active_ms: 1_000,
            revoked: false,
        };

        let session_record = IdentitySessionRecord::from(&session);
        let session_encoded = canonical_cbor(&session_record).unwrap();
        let nonce_record = SessionNonceRecord {
            session_token_digest: session_token_digest(token),
            nonce_digest: session_nonce_digest(nonce),
        };
        let nonce_encoded = canonical_cbor(&nonce_record).unwrap();

        assert_ne!(session_record.session_token_digest, token);
        assert!(!bytes_contain(&session_encoded, token.as_bytes()));
        assert!(!bytes_contain(&nonce_encoded, token.as_bytes()));
        assert!(!bytes_contain(&nonce_encoded, nonce.as_bytes()));
    }

    #[test]
    fn persisted_session_digest_lookup_accepts_presented_token() {
        let token = "presented-session-token";
        let session = IdentitySession {
            session_token: session_token_digest(token),
            subject_did: did("did:exo:session-digest-lookup"),
            public_key: vec![8; 32],
            created_ms: 1_000,
            last_active_ms: 1_000,
            revoked: false,
        };
        let mut store = ZerodentityStore::new();
        store
            .sessions
            .insert(session.session_token.clone(), session.clone());

        let loaded = store.get_session(token, 2_000).unwrap();

        assert_eq!(loaded.map(|s| s.subject_did), Some(session.subject_did));
    }

    #[test]
    fn persisted_nonce_digest_blocks_replay_with_presented_token() {
        let token = "nonce-replay-session-token";
        let nonce = "nonce-replay-value";
        let mut store = ZerodentityStore::new();
        store
            .session_request_nonces
            .insert((session_token_digest(token), session_nonce_digest(nonce)));

        assert!(!store.consume_session_nonce(token, nonce).unwrap());
    }

    #[test]
    fn erasure_action_hash_is_deterministic_and_did_bound() {
        let did_a = did("did:exo:erase-a");
        let did_b = did("did:exo:erase-b");

        let first = erasure_action_hash(&did_a).expect("erasure hash");

        assert_eq!(erasure_action_hash(&did_a).expect("erasure hash"), first);
        assert_ne!(erasure_action_hash(&did_b).expect("erasure hash"), first);
    }

    #[test]
    fn erasure_path_does_not_use_ad_hoc_format_hashes() {
        let source = include_str!("store.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let ad_hoc_erasure_hash = format!("{}{}", "format!(\"erase", ":");

        assert!(!production.contains(&ad_hoc_erasure_hash));
    }

    #[test]
    fn empty_store_returns_none() {
        let store = ZerodentityStore::new();
        assert!(store.get_score(&did("did:exo:a")).is_none());
        assert_eq!(store.get_claims(&did("did:exo:a")).unwrap(), vec![]);
        assert_eq!(store.sample_scored_dids(5), vec![]);
    }

    #[test]
    fn production_claim_slice_reads_do_not_squash_store_errors() {
        let source = include_str!("store.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section");
        let claim_slice = production
            .split("pub fn get_claims_slice")
            .nth(1)
            .expect("get_claims_slice definition")
            .split("pub fn get_fingerprints")
            .next()
            .expect("get_claims_slice body");

        assert!(
            claim_slice.contains("anyhow::Result<Vec<IdentityClaim>>"),
            "claim slice reads must expose the underlying store read error"
        );
        assert!(
            !claim_slice.contains(".unwrap_or_default()"),
            "claim slice reads must not convert store read failures into empty claim sets"
        );
    }

    #[test]
    fn get_claims_slice_propagates_claim_read_failures() {
        let mut store = ZerodentityStore::new();
        store.inject_read_failure(ZerodentityReadFailure::Claims);

        let err = store
            .get_claims_slice(&did("did:exo:claims-slice-failure"))
            .expect_err("claim slice reads must fail closed on store read errors");

        assert!(err.to_string().contains("claims read failure"));
    }

    #[test]
    fn production_store_declares_dagdb_persistence_ready() {
        assert!(ZerodentityStore::persistence_ready());
        assert!(
            ZerodentityStore::persistence_warning().contains("DAG DB"),
            "startup warning must plainly identify the required durable store"
        );
    }

    #[test]
    fn put_and_get_score() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:alice");
        store.put_score(score_for(d.clone(), 5000)).unwrap();
        assert_eq!(store.get_score(&d).unwrap().composite, 5000);
    }

    #[test]
    fn previous_score_after_update() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:bob");
        store.put_score(score_for(d.clone(), 4000)).unwrap();
        store.put_score(score_for(d.clone(), 6000)).unwrap();
        assert_eq!(store.get_score(&d).unwrap().composite, 6000);
        assert_eq!(store.get_previous_score(&d).unwrap().composite, 4000);
    }

    #[test]
    fn score_history_returns_all_snapshots() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:carol");
        store.put_score(score_for(d.clone(), 1000)).unwrap();
        store.put_score(score_for(d.clone(), 2000)).unwrap();
        store.put_score(score_for(d.clone(), 3000)).unwrap();
        let h = store.get_score_history(&d, None, None).unwrap();
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn sample_scored_dids_returns_sorted() {
        let mut store = ZerodentityStore::new();
        store.put_score(score_for(did("did:exo:c"), 1000)).unwrap();
        store.put_score(score_for(did("did:exo:a"), 2000)).unwrap();
        store.put_score(score_for(did("did:exo:b"), 3000)).unwrap();
        let sampled = store.sample_scored_dids(10);
        assert_eq!(sampled.len(), 3);
        assert_eq!(sampled[0].as_str(), "did:exo:a");
    }

    #[test]
    fn scored_dids_page_after_returns_successive_bounded_pages() {
        let mut store = ZerodentityStore::new();
        for did_str in ["did:exo:a", "did:exo:b", "did:exo:c"] {
            store.put_score(score_for(did(did_str), 1000)).unwrap();
        }

        let first_page = store.scored_dids_page_after(None, 2);
        assert_eq!(
            first_page
                .iter()
                .map(|did| did.as_str())
                .collect::<Vec<_>>(),
            vec!["did:exo:a", "did:exo:b"]
        );

        let second_page = store.scored_dids_page_after(first_page.last(), 2);
        assert_eq!(
            second_page
                .iter()
                .map(|did| did.as_str())
                .collect::<Vec<_>>(),
            vec!["did:exo:c"]
        );
    }

    #[test]
    fn otp_lockout_detection() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:dave");
        let now_ms: u64 = 86_400_000;
        let day_ago = now_ms - 86_400_000;
        store.record_otp_lockout(&d, now_ms - 3_600_000).unwrap();
        assert!(store.has_otp_lockout_since(&d, day_ago));
        assert!(!store.has_otp_lockout_since(&d, now_ms + 1));
    }

    #[test]
    fn put_claim_and_retrieve() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:eve");
        store.put_claim(claim(&d, ClaimType::Email)).unwrap();
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.claim_type, ClaimType::Email);
    }

    #[test]
    fn insert_claim_and_retrieve() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:frank");
        let c = claim(&d, ClaimType::Phone);
        store.insert_claim("test-claim-001", &c).unwrap();
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "test-claim-001");
    }

    #[test]
    fn open_returns_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ZerodentityStore::open(tmp.path()).unwrap();
        assert_eq!(store.scored_did_count(), 0);
    }

    // ---- APE-72 tests ----

    #[test]
    fn run_migrations_is_idempotent() {
        let store = ZerodentityStore::new();
        store.run_migrations().unwrap();
        store.run_migrations().unwrap();
    }

    #[test]
    fn save_claim_stores_claim_and_dag_node() {
        let (mut store, node_did, _) = signed_store(3);
        let d = did("did:exo:grace");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-001", &c).unwrap();

        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "apg-001");

        assert_eq!(store.dag_nodes().len(), 1);
        assert_eq!(store.dag_nodes()[0].payload_hash, c.claim_hash);
        assert_eq!(store.dag_nodes()[0].creator_did, node_did);
    }

    #[test]
    fn save_claim_binds_stored_claim_to_signed_dag_node_hash() {
        let (mut store, _, _) = signed_store(34);
        let d = did("did:exo:dag-bound-claim");
        let mut c = claim(&d, ClaimType::Email);
        c.dag_node_hash = Hash256::digest(b"caller-controlled-dag-pointer");

        let evidence = store
            .save_claim_with_evidence("apg-dag-bound-001", &c)
            .unwrap();

        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.dag_node_hash, evidence.dag_node_hash);
        assert_eq!(claims[0].1.dag_node_hash, store.dag_nodes()[0].hash);
        assert_ne!(claims[0].1.dag_node_hash, c.dag_node_hash);
    }

    #[test]
    fn save_claim_dag_node_is_signed_by_node_identity() {
        let (mut store, node_did, node_public_key) = signed_store(31);
        let d = did("did:exo:dag-signed-claim");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-dag-signed-001", &c).unwrap();

        let node = &store.dag_nodes()[0];
        assert_eq!(node.creator_did, node_did);
        assert!(!node.signature.is_empty());
        assert!(verify(
            node.hash.as_bytes(),
            &node.signature,
            &node_public_key
        ));
    }

    #[test]
    fn save_claim_without_node_signer_is_refused() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:dag-unsigned-refusal");
        let c = claim(&d, ClaimType::Email);

        let err = store.save_claim("apg-dag-unsigned-001", &c).unwrap_err();

        assert!(
            err.to_string().contains("DAG node signer"),
            "expected DAG signer refusal, got {err}"
        );
        assert!(store.dag_nodes().is_empty());
        assert!(store.get_claims(&d).unwrap().is_empty());
    }

    #[test]
    fn save_claim_chains_dag_nodes_to_previous_node() {
        let (mut store, _, node_public_key) = signed_store(32);
        let d = did("did:exo:dag-chain");
        let first = claim(&d, ClaimType::Email);
        let mut second = claim(&d, ClaimType::Phone);
        second.created_ms = first.created_ms + 1;
        second.verified_ms = Some(first.created_ms + 2);

        store.save_claim("apg-dag-chain-001", &first).unwrap();
        store.save_claim("apg-dag-chain-002", &second).unwrap();

        let nodes = store.dag_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].parents.is_empty());
        assert_eq!(nodes[1].parents, vec![nodes[0].hash]);
        assert!(verify(
            nodes[0].hash.as_bytes(),
            &nodes[0].signature,
            &node_public_key
        ));
        assert!(verify(
            nodes[1].hash.as_bytes(),
            &nodes[1].signature,
            &node_public_key
        ));
    }

    #[test]
    fn save_claim_advances_logical_time_for_same_millisecond_writes() {
        let (mut store, _, node_public_key) = signed_store(37);
        let d = did("did:exo:dag-same-ms");
        let first = claim(&d, ClaimType::Email);
        let mut second = claim(&d, ClaimType::Phone);
        second.claim_hash = Hash256::digest(b"same-ms-second-claim");
        second.created_ms = first.created_ms;
        second.verified_ms = Some(first.created_ms);

        store.save_claim("apg-dag-same-ms-001", &first).unwrap();
        store.save_claim("apg-dag-same-ms-002", &second).unwrap();

        let nodes = store.dag_nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].timestamp.physical_ms, first.created_ms);
        assert_eq!(nodes[0].timestamp.logical, 0);
        assert_eq!(nodes[1].timestamp.physical_ms, first.created_ms);
        assert_eq!(nodes[1].timestamp.logical, 1);
        assert_eq!(nodes[1].parents, vec![nodes[0].hash]);
        assert!(verify(
            nodes[1].hash.as_bytes(),
            &nodes[1].signature,
            &node_public_key
        ));

        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 2);
        let saved_second = claims
            .iter()
            .find(|(claim_id, _)| claim_id == "apg-dag-same-ms-002")
            .unwrap();
        assert_eq!(saved_second.1.dag_node_hash, nodes[1].hash);
    }

    #[test]
    fn next_claim_hash_matches_saved_same_millisecond_dag_node() {
        let (mut store, _, _) = signed_store(38);
        let d = did("did:exo:dag-same-ms-precompute");
        let first = claim(&d, ClaimType::Email);
        let mut second = claim(&d, ClaimType::Phone);
        second.claim_hash = Hash256::digest(b"same-ms-precomputed-second-claim");
        second.created_ms = first.created_ms;
        second.verified_ms = Some(first.created_ms);

        store
            .save_claim("apg-dag-same-ms-precompute-001", &first)
            .unwrap();
        let precomputed = store
            .next_claim_dag_node_hash(second.claim_hash, second.created_ms)
            .unwrap();
        let evidence = store
            .save_claim_with_evidence("apg-dag-same-ms-precompute-002", &second)
            .unwrap();

        assert_eq!(evidence.dag_node_hash, precomputed);
        assert_eq!(store.dag_nodes()[1].timestamp.logical, 1);
    }

    #[test]
    fn save_claim_rejects_backdated_timestamp_before_latest_dag_node() {
        let (mut store, _, _) = signed_store(35);
        let d = did("did:exo:dag-causality-claim");
        let first = claim(&d, ClaimType::Email);
        let mut second = claim(&d, ClaimType::Phone);
        second.claim_hash = Hash256::digest(b"backdated-second-claim");
        second.created_ms = first.created_ms - 1;
        second.verified_ms = Some(second.created_ms);

        store.save_claim("apg-dag-causal-001", &first).unwrap();
        let err = store.save_claim("apg-dag-causal-002", &second).unwrap_err();

        assert!(
            err.to_string().contains("must not be older"),
            "expected claim DAG backdating refusal, got {err}"
        );
        assert_eq!(store.dag_nodes().len(), 1);
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "apg-dag-causal-001");
    }

    #[test]
    fn erase_did_appends_signed_erasure_node_without_mutating_claim_node() {
        let (mut store, node_did, node_public_key) = signed_store(33);
        let d = did("did:exo:dag-erasure");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("apg-dag-erasure-001", &c).unwrap();
        let claim_node = store.dag_nodes()[0].clone();

        store
            .erase_did_with_evidence(&d, Timestamp::new(6_000, 0), Timestamp::new(6_000, 0))
            .unwrap();

        let nodes = store.dag_nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0], claim_node);
        assert_eq!(nodes[1].creator_did, node_did);
        assert_eq!(nodes[1].parents, vec![claim_node.hash]);
        assert_ne!(nodes[1].payload_hash, Hash256::ZERO);
        assert!(!nodes[1].signature.is_empty());
        assert!(verify(
            nodes[1].hash.as_bytes(),
            &nodes[1].signature,
            &node_public_key
        ));
    }

    #[test]
    fn save_verified_claim_emits_trust_receipt() {
        let (mut store, node_did, node_public_key) = signed_store(5);
        let d = did("did:exo:heidi");
        let c = claim(&d, ClaimType::Phone); // claim() sets status=Verified
        store.save_claim("apg-002", &c).unwrap();

        assert_eq!(store.trust_receipts().len(), 1);
        let r = &store.trust_receipts()[0];
        assert_eq!(r.actor_did, node_did);
        assert_eq!(r.action_hash, c.claim_hash);
        assert_eq!(r.action_type, "zerodentity.claim_verified");
        assert!(
            r.verify_signature(&node_public_key)
                .expect("verify trust receipt signature")
        );
    }

    #[test]
    fn save_verified_claim_emits_node_signed_trust_receipt() {
        let (mut store, node_did, node_public_key) = signed_store(11);
        let d = did("did:exo:signed-claim");
        let c = claim(&d, ClaimType::Phone);
        store.save_claim("apg-signed-001", &c).unwrap();

        let receipt = &store.trust_receipts()[0];
        assert_eq!(receipt.actor_did, node_did);
        assert_eq!(receipt.action_hash, c.claim_hash);
        assert_eq!(receipt.action_type, "zerodentity.claim_verified");
        assert!(!receipt.signature.is_empty());
        assert!(receipt.verify_hash().expect("verify trust receipt hash"));
        assert!(
            receipt
                .verify_signature(&node_public_key)
                .expect("verify trust receipt signature")
        );
    }

    #[test]
    fn save_pending_claim_no_trust_receipt() {
        let (mut store, _, _) = signed_store(13);
        let d = did("did:exo:ivan");
        let mut c = claim(&d, ClaimType::GovernmentId);
        c.status = ClaimStatus::Pending;
        store.save_claim("apg-003", &c).unwrap();

        assert_eq!(store.dag_nodes().len(), 1);
        assert_eq!(store.trust_receipts().len(), 0);
    }

    #[test]
    fn save_and_get_otp() {
        use crate::zerodentity::types::{OtpChannel, OtpState};
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:judy");
        let challenge = super::OtpChallenge {
            challenge_id: "ch-001".to_string(),
            subject_did: d,
            channel: OtpChannel::Email,
            hmac_secret: otp_secret(1),
            dispatched_ms: 1_000_000,
            ttl_ms: 600_000,
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.save_otp(&challenge).unwrap();
        let fetched = store.get_otp("ch-001").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().challenge_id, "ch-001");
    }

    #[test]
    fn save_score_and_retrieve() {
        let mut store = ZerodentityStore::new();
        let d = did("did:exo:karen");
        store.save_score(score_for(d.clone(), 7500)).unwrap();
        assert_eq!(store.get_score(&d).unwrap().composite, 7500);
    }

    // ---- Erasure tests (§11.4) ----

    #[test]
    fn erase_did_revokes_claims_and_zeroes_scores() {
        use crate::zerodentity::types::IdentitySession;

        let (mut store, _, _) = signed_store(7);
        let d = did("did:exo:eraseme");

        // Set up: claim, score, session
        store.put_claim(claim(&d, ClaimType::Email)).unwrap();
        store.put_claim(claim(&d, ClaimType::Phone)).unwrap();
        store.put_score(score_for(d.clone(), 7000)).unwrap();
        store
            .insert_session(&IdentitySession {
                session_token: "tok-erase".into(),
                subject_did: d.clone(),
                public_key: vec![],
                created_ms: 0,
                last_active_ms: 0,
                revoked: false,
            })
            .unwrap();

        // Erase
        let evidence = store
            .erase_did_with_evidence(&d, Timestamp::new(7_000, 0), Timestamp::new(7_000, 0))
            .unwrap();
        assert_eq!(evidence.claims_revoked, 2);

        // Score gone
        assert!(store.get_score(&d).is_none());
        assert!(store.get_previous_score(&d).is_none());
        assert!(store.get_score_history(&d, None, None).unwrap().is_empty());

        // Claims still exist but all Revoked
        let claims = store.get_claims(&d).unwrap();
        assert_eq!(claims.len(), 2);
        for (_, c) in &claims {
            assert_eq!(c.status, ClaimStatus::Revoked);
        }

        // Session revoked
        assert!(store.get_session("tok-erase", 7_000).unwrap().is_none());

        // Erasure receipt emitted
        let receipts: Vec<_> = store
            .trust_receipts()
            .iter()
            .filter(|r| r.action_type == "zerodentity.identity_erased")
            .collect();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn erase_did_emits_node_signed_erasure_receipt() {
        let (mut store, node_did, node_public_key) = signed_store(17);
        let d = did("did:exo:signed-erase");
        store.put_claim(claim(&d, ClaimType::Email)).unwrap();

        let evidence = store
            .erase_did_with_evidence(&d, Timestamp::new(8_000, 0), Timestamp::new(8_000, 0))
            .unwrap();
        assert_eq!(evidence.claims_revoked, 1);

        let receipt = store
            .trust_receipts()
            .iter()
            .find(|r| r.action_type == "zerodentity.identity_erased")
            .unwrap();
        assert_eq!(receipt.actor_did, node_did);
        assert!(!receipt.signature.is_empty());
        assert!(receipt.verify_hash().expect("verify trust receipt hash"));
        assert!(
            receipt
                .verify_signature(&node_public_key)
                .expect("verify trust receipt signature")
        );
    }

    #[test]
    fn erase_did_rejects_zero_timestamp() {
        let (mut store, _, _) = signed_store(18);
        let d = did("did:exo:zero-erase");
        store.put_claim(claim(&d, ClaimType::Email)).unwrap();

        let err = store
            .erase_did_with_evidence(&d, Timestamp::new(0, 0), Timestamp::new(8_000, 0))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("erasure timestamp must be greater than 0")
        );
    }

    #[test]
    fn erase_did_rejects_timestamp_not_after_latest_dag_node() {
        let (mut store, _, _) = signed_store(34);
        let d = did("did:exo:old-erase");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("old-erase-claim", &c).unwrap();

        let err = store
            .erase_did_with_evidence(
                &d,
                Timestamp::new(c.created_ms, 0),
                Timestamp::new(c.created_ms, 0),
            )
            .unwrap_err();

        assert!(
            err.to_string().contains("strictly exceed"),
            "expected parent-causality rejection, got {err}"
        );
        assert_eq!(store.dag_nodes().len(), 1);
    }

    #[test]
    fn erase_did_rejects_timestamp_beyond_validation_clock_tolerance() {
        let (mut store, _, _) = signed_store(35);
        let d = did("did:exo:future-erase");
        store.put_claim(claim(&d, ClaimType::Email)).unwrap();

        let err = store
            .erase_did_with_evidence(
                &d,
                Timestamp::new(10_000, 0),
                Timestamp::new(10_000 - ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS - 1, 0),
            )
            .unwrap_err();

        assert!(
            err.to_string().contains("clock tolerance"),
            "expected future-skew rejection, got {err}"
        );
        assert!(store.dag_nodes().is_empty());
    }

    #[test]
    fn erase_did_write_path_does_not_fabricate_runtime_time() {
        let source = include_str!("store.rs");
        let erasure_section = source
            .split("// Write — erasure")
            .nth(1)
            .and_then(|section| section.split("// Read — OTP challenges").next())
            .unwrap();

        assert!(!erasure_section.contains("now_ms()"));
    }

    #[test]
    fn erase_did_removes_fingerprints_and_behavioral() {
        use std::collections::BTreeMap;

        use crate::zerodentity::types::{
            BehavioralSample, BehavioralSignalType, DeviceFingerprint,
        };

        let (mut store, _, _) = signed_store(19);
        let d = did("did:exo:fptest");

        store
            .put_fingerprint(
                &d,
                DeviceFingerprint {
                    composite_hash: h(),
                    signal_hashes: BTreeMap::new(),
                    captured_ms: 1000,
                    consistency_score_bp: Some(9500),
                },
            )
            .unwrap();
        store
            .put_behavioral(
                &d,
                BehavioralSample {
                    sample_hash: h(),
                    signal_type: BehavioralSignalType::KeystrokeDynamics,
                    captured_ms: 1000,
                    baseline_similarity_bp: Some(8000),
                },
            )
            .unwrap();

        assert!(!store.get_fingerprints(&d).unwrap().is_empty());
        assert!(!store.get_behavioral_samples(&d).unwrap().is_empty());

        store
            .erase_did_with_evidence(&d, Timestamp::new(9_000, 0), Timestamp::new(9_000, 0))
            .unwrap();

        assert!(store.get_fingerprints(&d).unwrap().is_empty());
        assert!(store.get_behavioral_samples(&d).unwrap().is_empty());
    }

    #[test]
    fn erase_did_appends_erasure_dag_node() {
        let (mut store, _, _) = signed_store(23);
        let d = did("did:exo:dagtest");
        let c = claim(&d, ClaimType::Email);
        store.save_claim("dag-001", &c).unwrap();

        let claim_node = store.dag_nodes()[0].clone();
        store
            .erase_did_with_evidence(&d, Timestamp::new(10_000, 0), Timestamp::new(10_000, 0))
            .unwrap();
        assert_eq!(store.dag_nodes().len(), 2);
        assert_eq!(store.dag_nodes()[0], claim_node);
        assert_eq!(store.dag_nodes()[1].parents, vec![claim_node.hash]);
        assert_ne!(store.dag_nodes()[1].payload_hash, Hash256::ZERO);
    }

    // ---- OTP cleanup tests ----

    #[test]
    fn cleanup_expired_otp_removes_pending() {
        use crate::zerodentity::types::{OtpChannel, OtpState};

        let mut store = ZerodentityStore::new();
        let d = did("did:exo:otptest");

        // Expired pending challenge
        let expired = OtpChallenge {
            challenge_id: "exp-001".into(),
            subject_did: d.clone(),
            channel: OtpChannel::Email,
            hmac_secret: otp_secret(2),
            dispatched_ms: 1_000_000,
            ttl_ms: 300_000, // 5 min
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.insert_otp_challenge(&expired).unwrap();

        // Non-expired pending challenge
        let fresh = OtpChallenge {
            challenge_id: "fresh-001".into(),
            subject_did: d.clone(),
            channel: OtpChannel::Sms,
            hmac_secret: otp_secret(3),
            dispatched_ms: 100_000_000, // far future
            ttl_ms: 300_000,
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.insert_otp_challenge(&fresh).unwrap();

        // Verified challenge (should not be removed even if "expired")
        let verified = OtpChallenge {
            challenge_id: "ver-001".into(),
            subject_did: d,
            channel: OtpChannel::Email,
            hmac_secret: otp_secret(4),
            dispatched_ms: 1_000_000,
            ttl_ms: 300_000,
            attempts: 1,
            max_attempts: 5,
            state: OtpState::Verified,
        };
        store.insert_otp_challenge(&verified).unwrap();

        let cleaned = store.cleanup_expired_otp(2_000_000).unwrap();
        assert_eq!(cleaned, 1); // Only expired + pending

        assert!(store.get_otp_challenge("exp-001").unwrap().is_none());
        assert!(store.get_otp_challenge("fresh-001").unwrap().is_some());
        assert!(store.get_otp_challenge("ver-001").unwrap().is_some());
    }

    #[test]
    fn cleanup_expired_otp_removes_pending_when_expiry_overflows() {
        use crate::zerodentity::types::{OtpChannel, OtpState};

        let mut store = ZerodentityStore::new();
        let challenge = OtpChallenge {
            challenge_id: "overflow-001".into(),
            subject_did: did("did:exo:otpoverflow"),
            channel: OtpChannel::Email,
            hmac_secret: otp_secret(5),
            dispatched_ms: u64::MAX,
            ttl_ms: 1,
            attempts: 0,
            max_attempts: 5,
            state: OtpState::Pending,
        };
        store.insert_otp_challenge(&challenge).unwrap();

        let cleaned = store.cleanup_expired_otp(1_000).unwrap();

        assert_eq!(cleaned, 1);
        assert!(store.get_otp_challenge("overflow-001").unwrap().is_none());
    }
}
