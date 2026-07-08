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
//! | `POST` | `/api/v1/avc/llm-usage/receipts/emit` | Validate subject-signed EXOCHAIN LYNK Protocol evidence and mint a node-signed receipt. |
//! | `POST` | `/api/v1/avc/livesafe/public-adapter-output-authorization` | Mint/export the redacted LiveSafe public adapter-output authorization proof. |
//! | `GET`  | `/api/v1/avc/receipts/:hash` | Fetch a stored AVC trust receipt by hash. |
//! | `GET`  | `/api/v1/avc/receipts?actor=<did>&limit=N` | List stored AVC trust receipts for a subject DID. |
//! | `GET`  | `/api/v1/avc/protocol` | Discover node AVC protocol compatibility metadata. |
//! | `POST` | `/api/v1/avc/delegate` | Register a signed child credential. |
//! | `POST` | `/api/v1/avc/revoke` | Register a signed revocation. |
//! | `POST` | `/api/v1/avc/issuers` | Register/rotate an issuer DID+public key at runtime; requires a DelegationRegistry-backed authority chain granting `Permission::Govern` (D3), not just the bearer token. |
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
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_authority::permission::Permission;
use exo_avc::{
    AVC_MAX_SUPPORTED_PROTOCOL_VERSION, AVC_MIN_SUPPORTED_PROTOCOL_VERSION,
    AVC_PROTOCOL_DEPRECATION_WINDOW_DAYS, AVC_PROTOCOL_VERSION, AVC_SCHEMA_VERSION,
    AutonomousVolitionCredential, AvcActionDescriptor, AvcActionRequest, AvcDecision,
    AvcReceiptEvidenceSubject, AvcReceiptExternalTimestampProof, AvcReceiptRfc3161TimestampProof,
    AvcReceiptRfc3161TrustAnchorKind, AvcReceiptTimestampProvenance, AvcRegistryDurableState,
    AvcRegistryRead, AvcRegistryWrite, AvcRevocation, AvcTrustReceipt, AvcTrustReceiptEvidence,
    AvcValidationRequest, AvcValidationResult, InMemoryAvcRegistry,
    LivesafePublicAdapterOutputAuthorizationDraft,
    LivesafePublicAdapterOutputAuthorizationEnvelope, LlmUsageEvidenceEnvelope,
    avc_action_commitment_hash, avc_action_descriptor_hash, avc_action_signature_payload,
    avc_llm_usage_action_request, create_trust_receipt_with_evidence,
    livesafe_public_adapter_output_authorization_action_commitment_hash,
    livesafe_public_adapter_output_authorization_action_request,
    livesafe_public_adapter_output_authorization_idempotency_hash, llm_usage_evidence_hash,
    llm_usage_evidence_signature_payload, mint_livesafe_public_adapter_output_authorization_proof,
    require_supported_avc_protocol_version, validate_avc,
    validate_livesafe_public_adapter_output_authorization,
};
use exo_core::{
    Did, Hash256, PublicKey, Signature, Timestamp, crypto,
    hash::hash_structured,
    hlc::HybridClock,
    types::{ReceiptOutcome, TrustReceipt},
};
use exo_dag::dag::{DagNode, compute_node_hash};
use exo_root::{RootSignature, RootTrustBundle, verify_root_bundle, verify_root_signature};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tower::limit::ConcurrencyLimitLayer;

const MAX_AVC_API_BODY_BYTES: usize = 64 * 1024;
const MAX_AVC_API_CONCURRENT_REQUESTS: usize = 64;
const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const AVC_RFC3161_TIMESTAMP_FETCH_RETRY_DELAYS: [Duration; 2] =
    [Duration::from_millis(250), Duration::from_millis(1_000)];
#[cfg(test)]
const AVC_RFC3161_TIMESTAMP_FETCH_RETRY_DELAYS: [Duration; 2] =
    [Duration::from_millis(0), Duration::from_millis(0)];
pub const AVC_ROOT_TRUST_BUNDLE_ENV: &str = "EXO_AVC_ROOT_TRUST_BUNDLE";
pub const AVC_REQUIRE_POSTGRES_DURABILITY_ENV: &str = "EXO_AVC_REQUIRE_POSTGRES_DURABILITY";
pub const AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV: &str =
    "EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY";
pub const AVC_ROOT_TRUST_CEREMONY_ID: &str = "avc-exo-ceremony-2026";
pub const AVC_ROOT_TRUST_BUNDLE_ID_HEX: &str =
    "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58";
pub const AVC_ROOT_TRUST_ISSUER_DID: &str = "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX";
pub const AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX: &str =
    "6b765381964de7f74e77e4f9d265105f415e58722d19ff71603f62c31d5aff32";

// VCG-006b / #734: hermetic conformance-test root-trust constants. These are
// an ADDITIVE alternate path — a separately-named constant set that only
// exists when `conformance-test-root` is compiled in — and are never
// substituted for the production `AVC_ROOT_TRUST_*` constants above. The
// production constants are referenced unconditionally, verbatim, exactly
// once each, regardless of whether this feature is enabled; see
// `conformance_test_root_feature_does_not_alter_production_root_trust`.
#[cfg(feature = "conformance-test-root")]
pub const AVC_CONFORMANCE_ROOT_TRUST_CEREMONY_ID: &str = "avc-exo-conformance-ceremony-2026";
#[cfg(feature = "conformance-test-root")]
pub const AVC_CONFORMANCE_ROOT_TRUST_BUNDLE_ID_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000000000";
#[cfg(feature = "conformance-test-root")]
pub const AVC_CONFORMANCE_ROOT_TRUST_ISSUER_DID: &str =
    "did:exo:conformance-test-root-issuer-0000000000000000000000000";
#[cfg(feature = "conformance-test-root")]
pub const AVC_CONFORMANCE_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000000001";

/// Env var that opts a `conformance-test-root`-enabled binary into resolving
/// root trust against the conformance constants instead of production.
///
/// This is deliberately a *second* gate on top of the Cargo feature: simply
/// compiling the feature in must not silently change production behavior
/// for any binary that does not also set this variable at runtime. Only the
/// conjunction of (feature compiled in) AND (env var set) swaps the
/// resolved constants.
#[cfg(feature = "conformance-test-root")]
pub const AVC_CONFORMANCE_ROOT_TRUST_ENV: &str = "EXO_AVC_CONFORMANCE_ROOT_TRUST";

/// Effective root-trust constants after conformance resolution.
struct AvcRootTrustConstants {
    ceremony_id: &'static str,
    bundle_id_hex: &'static str,
    issuer_did: &'static str,
    issuer_public_key_hex: &'static str,
}

/// Resolve the root-trust constants to use for bundle verification.
///
/// Production behavior is unchanged unconditionally: this returns the real
/// `AVC_ROOT_TRUST_*` constants unless the `conformance-test-root` feature is
/// compiled in AND `EXO_AVC_CONFORMANCE_ROOT_TRUST` is set at runtime, in
/// which case it returns the separately-named conformance constants. The
/// production constants themselves are never edited, wrapped, or replaced —
/// only this resolver's return value branches.
fn resolve_avc_root_trust_constants() -> AvcRootTrustConstants {
    #[cfg(feature = "conformance-test-root")]
    {
        if std::env::var_os(AVC_CONFORMANCE_ROOT_TRUST_ENV).is_some() {
            return AvcRootTrustConstants {
                ceremony_id: AVC_CONFORMANCE_ROOT_TRUST_CEREMONY_ID,
                bundle_id_hex: AVC_CONFORMANCE_ROOT_TRUST_BUNDLE_ID_HEX,
                issuer_did: AVC_CONFORMANCE_ROOT_TRUST_ISSUER_DID,
                issuer_public_key_hex: AVC_CONFORMANCE_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX,
            };
        }
    }
    AvcRootTrustConstants {
        ceremony_id: AVC_ROOT_TRUST_CEREMONY_ID,
        bundle_id_hex: AVC_ROOT_TRUST_BUNDLE_ID_HEX,
        issuer_did: AVC_ROOT_TRUST_ISSUER_DID,
        issuer_public_key_hex: AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX,
    }
}
pub const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV: &str =
    "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL";
pub const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV: &str =
    "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND";
pub const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519: &str = "json-ed25519";
pub const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161: &str = "rfc3161";
pub const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV: &str =
    "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID";
pub const AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV: &str =
    "EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX";
pub const AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV: &str = "EXO_AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX";
pub const AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV: &str = "EXO_AVC_RFC3161_TIMESTAMP_POLICY_OID";
/// DID to grant runtime AVC issuer-registration authority (`Permission::Govern`
/// per D3) to at startup, so operators can call `POST /api/v1/avc/issuers`
/// with a real DelegationRegistry-backed chain instead of relying solely on
/// the bare admin bearer token (VCG-006b / #736). Optional: when unset, no
/// operator delegation is granted and the endpoint refuses every request
/// until one is granted through some other channel (for example, a future
/// governance-approved delegation flow).
pub const AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV: &str =
    "EXO_AVC_ISSUER_REGISTRATION_OPERATOR_DID";
/// Unix-seconds expiry for the startup-granted issuer-registration
/// delegation. Required whenever `AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV`
/// is set.
pub const AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS_ENV: &str =
    "EXO_AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS";
const AVC_REGISTRY_DURABLE_STATE_FILE: &str = "avc-registry.cbor";
const AVC_REGISTRY_POSTGRES_TABLE: &str = "avc_registry_state";
const AVC_REGISTRY_POSTGRES_KEY: &str = "default";
const AVC_REGISTRY_POSTGRES_LOCK_KEY: i64 = 0x4156_435F_5245_4749;
const AVC_ROOT_BUNDLE_RECEIPT_SCHEMA_VERSION: &str = "dagdb_root_bundle_verification_receipt_v1";
const AVC_ROOT_BUNDLE_RECEIPT_VERIFIER_VERSION: &str = "exo-node-avc-root-trust-loader-v1";
const AVC_EXOCHAIN_FINALITY_DAG_DOMAIN: &str = "exo.avc.receipt.exochain_finality.v1";
const AVC_EXOCHAIN_FINALITY_ACTION_TYPE: &str = "avc.receipt.exochain_finality";
const DEFAULT_AVC_RECEIPT_LIST_LIMIT: u32 = 50;
const MAX_AVC_RECEIPT_LIST_LIMIT: u32 = 500;
const WASM_PACKAGE_NAME: &str = "@exochain/exochain-wasm";
const WASM_PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub type AvcReceiptSigner = Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>;

#[derive(Clone)]
enum AvcReceiptExternalTimestampSource {
    Unconfigured,
    HttpJson {
        endpoint: Arc<String>,
        authority_did: Did,
        authority_public_key: PublicKey,
        client: reqwest::Client,
    },
    Rfc3161 {
        endpoint: Arc<String>,
        authority_did: Did,
        authority_public_key_spki_der_hexes: Arc<Vec<String>>,
        issuing_ca_spki_der_hexes: Arc<Vec<String>>,
        policy_oid: Arc<String>,
        client: reqwest::Client,
    },
    #[cfg(test)]
    Fixed {
        authority_did: Did,
        authority_public_key: PublicKey,
        issued_at: Timestamp,
        signer: AvcReceiptSigner,
    },
    #[cfg(test)]
    FixedRfc3161 {
        authority_did: Did,
        issued_at: Timestamp,
        token_der_base64: String,
        policy_oid: String,
        serial_number_hex: String,
        nonce_hex: String,
        tsa_subject: String,
        tsa_public_key_spki_der_hex: String,
    },
}

impl core::fmt::Debug for AvcReceiptExternalTimestampSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unconfigured => f.write_str("AvcReceiptExternalTimestampSource::Unconfigured"),
            Self::HttpJson {
                endpoint,
                authority_did,
                ..
            } => f
                .debug_struct("AvcReceiptExternalTimestampSource::HttpJson")
                .field("endpoint", endpoint)
                .field("authority_did", authority_did)
                .finish_non_exhaustive(),
            Self::Rfc3161 {
                endpoint,
                authority_did,
                policy_oid,
                ..
            } => f
                .debug_struct("AvcReceiptExternalTimestampSource::Rfc3161")
                .field("endpoint", endpoint)
                .field("authority_did", authority_did)
                .field("policy_oid", policy_oid)
                .finish_non_exhaustive(),
            #[cfg(test)]
            Self::Fixed {
                authority_did,
                issued_at,
                ..
            } => f
                .debug_struct("AvcReceiptExternalTimestampSource::Fixed")
                .field("authority_did", authority_did)
                .field("issued_at", issued_at)
                .finish_non_exhaustive(),
            #[cfg(test)]
            Self::FixedRfc3161 {
                authority_did,
                issued_at,
                policy_oid,
                ..
            } => f
                .debug_struct("AvcReceiptExternalTimestampSource::FixedRfc3161")
                .field("authority_did", authority_did)
                .field("issued_at", issued_at)
                .field("policy_oid", policy_oid)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Serialize)]
struct AvcExternalTimestampRequest {
    schema_version: u16,
    domain: &'static str,
    subject_hash: String,
}

#[derive(Deserialize)]
struct AvcExternalTimestampResponse {
    authority_did: String,
    subject_hash: String,
    issued_at_physical_ms: u64,
    issued_at_logical: u32,
    signature_hex: String,
}

#[derive(Debug, thiserror::Error)]
enum AvcExternalTimestampFailure {
    #[error(
        "AVC external timestamp authority is not configured; set {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV}, {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV}, and {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV}"
    )]
    Unconfigured,
    #[error("AVC external timestamp authority is unreachable: {reason}")]
    Unreachable { reason: String },
    #[error("AVC external timestamp authority returned non-success status {status}")]
    Rejected { status: String },
    #[error("AVC external timestamp authority response was invalid: {reason}")]
    InvalidResponse { reason: String },
    #[error("AVC external timestamp authority proof was invalid: {reason}")]
    InvalidProof { reason: String },
}

impl AvcExternalTimestampFailure {
    const fn operator_class(&self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Unreachable { .. } => "unreachable",
            Self::Rejected { .. } => "rejected",
            Self::InvalidResponse { .. } => "invalid_response",
            Self::InvalidProof { .. } => "invalid_proof",
        }
    }
}

fn external_timestamp_error_class(err: &anyhow::Error) -> &'static str {
    err.downcast_ref::<AvcExternalTimestampFailure>()
        .map_or("unknown", AvcExternalTimestampFailure::operator_class)
}

fn rfc3161_fetch_status_is_retryable(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

fn rfc3161_fetch_retry_delay(attempt_index: usize) -> Option<Duration> {
    AVC_RFC3161_TIMESTAMP_FETCH_RETRY_DELAYS
        .get(attempt_index)
        .copied()
}

async fn wait_before_rfc3161_fetch_retry(delay: Duration) {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

async fn fetch_rfc3161_timestamp_response(
    client: &reqwest::Client,
    endpoint: &str,
    request_der: &[u8],
) -> Result<Vec<u8>, AvcExternalTimestampFailure> {
    let max_attempts = AVC_RFC3161_TIMESTAMP_FETCH_RETRY_DELAYS.len() + 1;
    for attempt_index in 0..max_attempts {
        let attempt = attempt_index + 1;
        let response = client
            .post(endpoint)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(request_der.to_vec())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                if let Some(delay) = rfc3161_fetch_retry_delay(attempt_index) {
                    tracing::warn!(
                        attempt = attempt,
                        max_attempts = max_attempts,
                        err = %error,
                        "retrying RFC 3161 timestamp authority fetch after transport failure"
                    );
                    wait_before_rfc3161_fetch_retry(delay).await;
                    continue;
                }
                return Err(AvcExternalTimestampFailure::Unreachable {
                    reason: format!("after {attempt} attempts: {error}"),
                });
            }
        };

        let status = response.status();
        if status.is_success() {
            return response
                .bytes()
                .await
                .map(|bytes| bytes.to_vec())
                .map_err(|error| AvcExternalTimestampFailure::InvalidResponse {
                    reason: error.to_string(),
                });
        }
        if rfc3161_fetch_status_is_retryable(status) {
            if let Some(delay) = rfc3161_fetch_retry_delay(attempt_index) {
                tracing::warn!(
                    attempt = attempt,
                    max_attempts = max_attempts,
                    status = %status,
                    "retrying RFC 3161 timestamp authority fetch after transient status"
                );
                wait_before_rfc3161_fetch_retry(delay).await;
                continue;
            }
        }
        return Err(AvcExternalTimestampFailure::Rejected {
            status: status.to_string(),
        });
    }
    Err(AvcExternalTimestampFailure::Unreachable {
        reason: format!("exhausted {max_attempts} RFC 3161 timestamp fetch attempts"),
    })
}

impl AvcReceiptExternalTimestampSource {
    async fn issue_proof(
        &self,
        evidence_subject: &AvcReceiptEvidenceSubject,
    ) -> anyhow::Result<AvcReceiptExternalTimestampProof> {
        let subject_hash = evidence_subject.hash().map_err(|error| {
            anyhow::anyhow!("AVC timestamp evidence subject hash failed: {error}")
        })?;
        match self {
            Self::Unconfigured => Err(AvcExternalTimestampFailure::Unconfigured.into()),
            Self::HttpJson {
                endpoint,
                authority_did,
                authority_public_key,
                client,
            } => {
                let request = AvcExternalTimestampRequest {
                    schema_version: AVC_SCHEMA_VERSION,
                    domain: exo_avc::AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN,
                    subject_hash: subject_hash.to_string(),
                };
                let response = client
                    .post(endpoint.as_str())
                    .json(&request)
                    .send()
                    .await
                    .map_err(|error| AvcExternalTimestampFailure::Unreachable {
                        reason: error.to_string(),
                    })?;
                let status = response.status();
                if !status.is_success() {
                    return Err(AvcExternalTimestampFailure::Rejected {
                        status: status.to_string(),
                    }
                    .into());
                }
                let wire: AvcExternalTimestampResponse =
                    response.json().await.map_err(|error| {
                        AvcExternalTimestampFailure::InvalidResponse {
                            reason: error.to_string(),
                        }
                    })?;
                let proof = external_timestamp_proof_from_wire(wire).map_err(|error| {
                    AvcExternalTimestampFailure::InvalidResponse {
                        reason: error.to_string(),
                    }
                })?;
                validate_external_timestamp_proof(
                    &proof,
                    subject_hash,
                    authority_did,
                    authority_public_key,
                )
                .map_err(|error| AvcExternalTimestampFailure::InvalidProof {
                    reason: error.to_string(),
                })?;
                Ok(proof)
            }
            Self::Rfc3161 {
                endpoint,
                authority_did,
                authority_public_key_spki_der_hexes,
                issuing_ca_spki_der_hexes,
                policy_oid,
                client,
            } => {
                let request = crate::avc_rfc3161::build_timestamp_request(
                    evidence_subject,
                    policy_oid.as_str(),
                )
                .map_err(|error| AvcExternalTimestampFailure::InvalidProof {
                    reason: error.to_string(),
                })?;
                let response_der =
                    fetch_rfc3161_timestamp_response(client, endpoint.as_str(), &request.der)
                        .await?;
                let trust_anchors = crate::avc_rfc3161::Rfc3161TrustAnchors::new(
                    authority_public_key_spki_der_hexes.as_ref().clone(),
                    issuing_ca_spki_der_hexes.as_ref().clone(),
                )
                .map_err(|error| AvcExternalTimestampFailure::InvalidProof {
                    reason: error.to_string(),
                })?;
                let verified = crate::avc_rfc3161::verify_timestamp_response_with_trust_anchors(
                    &response_der,
                    subject_hash,
                    request.message_imprint_sha256,
                    &request.nonce_hex,
                    policy_oid.as_str(),
                    &trust_anchors,
                )
                .map_err(|error| AvcExternalTimestampFailure::InvalidProof {
                    reason: error.to_string(),
                })?;
                let (tsa_trust_anchor_kind, tsa_issuer_subject) = match verified.trust_anchor.kind {
                    crate::avc_rfc3161::Rfc3161TrustAnchorKind::SignerSpki => {
                        (AvcReceiptRfc3161TrustAnchorKind::SignerSpki, None)
                    }
                    crate::avc_rfc3161::Rfc3161TrustAnchorKind::IssuingCaSpki => (
                        AvcReceiptRfc3161TrustAnchorKind::IssuingCaSpki,
                        Some(verified.trust_anchor.subject.clone()),
                    ),
                };
                Ok(AvcReceiptExternalTimestampProof::rfc3161(
                    authority_did.clone(),
                    verified.subject_hash,
                    verified.issued_at,
                    AvcReceiptRfc3161TimestampProof {
                        message_imprint_sha256_hex: verified.message_imprint_sha256_hex,
                        token_der_base64: verified.token_der_base64,
                        policy_oid: verified.policy_oid,
                        serial_number_hex: verified.serial_number_hex,
                        nonce_hex: verified.nonce_hex,
                        tsa_subject: verified.tsa_subject,
                        tsa_public_key_spki_der_hex: verified.tsa_public_key_spki_der_hex,
                        tsa_trust_anchor_kind: Some(tsa_trust_anchor_kind),
                        tsa_trust_anchor_spki_der_hex: Some(verified.trust_anchor.spki_der_hex),
                        tsa_issuer_subject,
                    },
                ))
            }
            #[cfg(test)]
            Self::Fixed {
                authority_did,
                authority_public_key,
                issued_at,
                signer,
            } => {
                let proof = AvcReceiptExternalTimestampProof::signed(
                    authority_did.clone(),
                    subject_hash,
                    *issued_at,
                    |bytes| signer(bytes),
                )
                .map_err(|error| {
                    anyhow::anyhow!("fixed AVC external timestamp proof failed: {error}")
                })?;
                validate_external_timestamp_proof(
                    &proof,
                    subject_hash,
                    authority_did,
                    authority_public_key,
                )
                .map_err(|error| AvcExternalTimestampFailure::InvalidProof {
                    reason: error.to_string(),
                })?;
                Ok(proof)
            }
            #[cfg(test)]
            Self::FixedRfc3161 {
                authority_did,
                issued_at,
                token_der_base64,
                policy_oid,
                serial_number_hex,
                nonce_hex,
                tsa_subject,
                tsa_public_key_spki_der_hex,
            } => Ok(AvcReceiptExternalTimestampProof::rfc3161(
                authority_did.clone(),
                subject_hash,
                *issued_at,
                AvcReceiptRfc3161TimestampProof {
                    message_imprint_sha256_hex: hex::encode(
                        evidence_subject
                            .rfc3161_sha256_message_imprint()
                            .map_err(|error| AvcExternalTimestampFailure::InvalidProof {
                                reason: error.to_string(),
                            })?,
                    ),
                    token_der_base64: token_der_base64.clone(),
                    policy_oid: policy_oid.clone(),
                    serial_number_hex: serial_number_hex.clone(),
                    nonce_hex: nonce_hex.clone(),
                    tsa_subject: tsa_subject.clone(),
                    tsa_public_key_spki_der_hex: tsa_public_key_spki_der_hex.clone(),
                    tsa_trust_anchor_kind: Some(AvcReceiptRfc3161TrustAnchorKind::SignerSpki),
                    tsa_trust_anchor_spki_der_hex: Some(tsa_public_key_spki_der_hex.clone()),
                    tsa_issuer_subject: None,
                },
            )),
        }
    }
}

fn external_timestamp_proof_from_wire(
    wire: AvcExternalTimestampResponse,
) -> anyhow::Result<AvcReceiptExternalTimestampProof> {
    let authority_did = Did::new(&wire.authority_did).map_err(|error| {
        anyhow::anyhow!("invalid AVC external timestamp authority DID: {error}")
    })?;
    let subject_hash = parse_hash_anyhow(&wire.subject_hash, "AVC timestamp subject hash")?;
    let signature = parse_signature_hex(&wire.signature_hex, "AVC timestamp signature")?;
    let mut proof = AvcReceiptExternalTimestampProof::unsigned(
        authority_did,
        subject_hash,
        Timestamp::new(wire.issued_at_physical_ms, wire.issued_at_logical),
    );
    proof.signature = signature;
    Ok(proof)
}

fn validate_external_timestamp_proof(
    proof: &AvcReceiptExternalTimestampProof,
    expected_subject_hash: Hash256,
    expected_authority_did: &Did,
    authority_public_key: &PublicKey,
) -> anyhow::Result<()> {
    if proof.subject_hash != expected_subject_hash {
        anyhow::bail!(
            "AVC external timestamp proof subject {} did not match expected {}",
            proof.subject_hash,
            expected_subject_hash
        );
    }
    if proof.authority_did != *expected_authority_did {
        anyhow::bail!(
            "AVC external timestamp proof authority {} did not match expected {}",
            proof.authority_did,
            expected_authority_did
        );
    }
    let verified = proof
        .verify_signature(authority_public_key)
        .map_err(|error| {
            anyhow::anyhow!("AVC external timestamp signature payload failed: {error}")
        })?;
    if !verified {
        anyhow::bail!("AVC external timestamp proof signature is invalid");
    }
    Ok(())
}

fn parse_hash_anyhow(raw: &str, label: &str) -> anyhow::Result<Hash256> {
    let bytes = hex::decode(raw).map_err(|error| anyhow::anyhow!("{label} is not hex: {error}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} must be 32 bytes, got {}", bytes.len());
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(buf))
}

fn parse_signature_hex(raw: &str, label: &str) -> anyhow::Result<Signature> {
    let bytes = hex::decode(raw).map_err(|error| anyhow::anyhow!("{label} is not hex: {error}"))?;
    if bytes.len() != 64 {
        anyhow::bail!("{label} must be 64 bytes, got {}", bytes.len());
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(buf))
}

#[derive(Serialize)]
struct AvcReceiptFinalityPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    receipt: &'a AvcTrustReceipt,
    external_timestamp_subject_hash: Option<&'a Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AvcExochainFinalityCommitment {
    finality_hash: Hash256,
    finality_height: u64,
    finality_receipt_hash: Hash256,
}

fn avc_receipt_finality_payload_hash(receipt: &AvcTrustReceipt) -> anyhow::Result<Hash256> {
    let external_timestamp_subject_hash = receipt
        .external_timestamp_proof
        .as_ref()
        .map(|proof| &proof.subject_hash);
    hash_structured(&AvcReceiptFinalityPayload {
        domain: AVC_EXOCHAIN_FINALITY_DAG_DOMAIN,
        schema_version: AVC_SCHEMA_VERSION,
        receipt,
        external_timestamp_subject_hash,
    })
    .map_err(|error| anyhow::anyhow!("AVC EXOCHAIN finality payload hash failed: {error}"))
}

fn build_exochain_finality_node_and_receipt(
    receipt: &AvcTrustReceipt,
    validator_did: &Did,
    receipt_signer: &AvcReceiptSigner,
) -> anyhow::Result<(DagNode, TrustReceipt)> {
    let payload_hash = avc_receipt_finality_payload_hash(receipt)?;
    let parents = receipt
        .previous_receipt_hash
        .iter()
        .copied()
        .collect::<Vec<_>>();
    let node_hash = compute_node_hash(&parents, &payload_hash, validator_did, &receipt.created_at)
        .map_err(|error| anyhow::anyhow!("AVC EXOCHAIN finality node hash failed: {error}"))?;
    let node = DagNode {
        hash: node_hash,
        parents,
        payload_hash,
        creator_did: validator_did.clone(),
        timestamp: receipt.created_at,
        signature: (receipt_signer)(node_hash.as_bytes()),
    };
    let finality_receipt = TrustReceipt::new(
        validator_did.clone(),
        receipt.receipt_id,
        None,
        AVC_EXOCHAIN_FINALITY_ACTION_TYPE.to_owned(),
        node.hash,
        ReceiptOutcome::Executed,
        receipt.created_at,
        &|bytes| (receipt_signer)(bytes),
    )
    .map_err(|error| anyhow::anyhow!("AVC EXOCHAIN finality trust receipt failed: {error}"))?;
    Ok((node, finality_receipt))
}

fn commit_exochain_finality(
    finality_store: &Option<Arc<Mutex<crate::store::SqliteDagStore>>>,
    receipt: &AvcTrustReceipt,
    validator_did: &Did,
    receipt_signer: &AvcReceiptSigner,
) -> anyhow::Result<Option<AvcExochainFinalityCommitment>> {
    let Some(finality_store) = finality_store else {
        return Ok(None);
    };
    let (node, finality_receipt) =
        build_exochain_finality_node_and_receipt(receipt, validator_did, receipt_signer)?;
    let mut store = finality_store
        .lock()
        .map_err(|_| anyhow::anyhow!("AVC EXOCHAIN finality store mutex poisoned"))?;
    let finality_height = match store.committed_height_for(&node.hash)? {
        Some(height) => height,
        None => store
            .committed_height_value()?
            .checked_add(1)
            .ok_or_else(|| {
                anyhow::anyhow!("AVC EXOCHAIN finality height overflow for {}", node.hash)
            })?,
    };
    store.put_committed_node_with_receipt_sync(&node, finality_height, &finality_receipt)?;
    Ok(Some(AvcExochainFinalityCommitment {
        finality_hash: node.hash,
        finality_height,
        finality_receipt_hash: finality_receipt.receipt_hash,
    }))
}

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
    external_timestamp_source: AvcReceiptExternalTimestampSource,
    receipt_clock: Arc<Mutex<HybridClock>>,
    require_external_timestamp: bool,
    finality_store: Option<Arc<Mutex<crate::store::SqliteDagStore>>>,
    durability: AvcRegistryDurability,
    /// `exo-authority` DelegationRegistry backing runtime issuer-registration
    /// authority (VCG-006b / #736, D3 one-authority-model rule). This is the
    /// single authority species for granting and verifying who may mutate the
    /// AVC issuer allow-list at runtime — the bare admin bearer token is
    /// deliberately insufficient on its own.
    authority: Arc<Mutex<exo_authority::delegation::DelegationRegistry>>,
}

impl AvcApiState {
    /// Wrap a fresh registry in the standard `Arc<Mutex<_>>` envelope.
    #[cfg(test)]
    #[must_use]
    pub fn new(validator_did: Did, receipt_signer: AvcReceiptSigner) -> Self {
        Self::new_with_external_timestamp_source(
            validator_did,
            receipt_signer,
            AvcReceiptExternalTimestampSource::Unconfigured,
        )
    }

    #[cfg(test)]
    fn new_with_external_timestamp_source(
        validator_did: Did,
        receipt_signer: AvcReceiptSigner,
        external_timestamp_source: AvcReceiptExternalTimestampSource,
    ) -> Self {
        Self::new_with_external_timestamp_source_and_finality_store(
            validator_did,
            receipt_signer,
            external_timestamp_source,
            None,
        )
    }

    #[cfg(test)]
    fn new_with_external_timestamp_source_and_finality_store(
        validator_did: Did,
        receipt_signer: AvcReceiptSigner,
        external_timestamp_source: AvcReceiptExternalTimestampSource,
        finality_store: Option<Arc<Mutex<crate::store::SqliteDagStore>>>,
    ) -> Self {
        Self {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
            validator_did,
            receipt_signer,
            external_timestamp_source,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: false,
            finality_store,
            durability: AvcRegistryDurability::None,
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
        }
    }

    /// Open the AVC registry with durable runtime-record persistence.
    ///
    /// Credentials, revocations, and receipts are restored from the configured
    /// Postgres database when available, otherwise from the node data directory.
    /// Public-key trust anchors are intentionally reloaded separately from
    /// verified startup configuration.
    ///
    /// When `require_postgres_durability` is `true` and no `database_pool` is
    /// supplied, startup fails closed with an `Err` instead of silently
    /// falling back to the local file-backed registry (VCG-006a / #735).
    pub async fn with_durable_registry(
        data_dir: &FsPath,
        validator_did: Did,
        receipt_signer: AvcReceiptSigner,
        database_pool: Option<PgPool>,
        finality_store: Option<Arc<Mutex<crate::store::SqliteDagStore>>>,
        require_postgres_durability: bool,
    ) -> anyhow::Result<Self> {
        let durable_state_path = data_dir.join(AVC_REGISTRY_DURABLE_STATE_FILE);
        let (registry, durability) = match database_pool {
            Some(pool) => {
                let registry =
                    load_postgres_durable_registry_or_import_file(&pool, &durable_state_path)
                        .await?;
                (registry, AvcRegistryDurability::Postgres(pool.clone()))
            }
            None => {
                if require_postgres_durability {
                    anyhow::bail!(
                        "{} is set but no Postgres database pool is configured; \
                         refusing to fall back to the local AVC file registry \
                         for production durability",
                        AVC_REQUIRE_POSTGRES_DURABILITY_ENV
                    );
                }
                tracing::warn!(
                    path = %durable_state_path.display(),
                    "AVC registry using local file fallback without Postgres-backed durability; set DATABASE_URL for production AVC registry durability"
                );
                (
                    load_file_durable_registry(&durable_state_path)?,
                    AvcRegistryDurability::File(Arc::new(durable_state_path)),
                )
            }
        };
        Ok(Self {
            registry: Arc::new(Mutex::new(registry)),
            validator_did,
            receipt_signer,
            external_timestamp_source: configured_external_timestamp_source_from_env()?,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: configured_require_external_timestamp_from_env()?,
            finality_store,
            durability,
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
        })
    }

    pub fn register_validator_public_keys<I>(&self, public_keys: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = (Did, PublicKey)>,
    {
        let mut registry = self.registry.lock().map_err(|_| {
            anyhow::anyhow!("AVC registry unavailable while registering validator public key")
        })?;
        let mut candidate = registry.clone();
        for (did, public_key) in public_keys {
            candidate.put_receipt_validator_public_key(did, public_key);
        }
        candidate.validate_loaded_receipts().map_err(|error| {
            anyhow::anyhow!(
                "AVC durable receipt validation failed after validator public key registration: {error}"
            )
        })?;
        *registry = candidate;
        Ok(())
    }

    /// Grant `Permission::Govern` issuer-registration authority from this
    /// node's `validator_did` to `delegate_did`, recorded in this node's own
    /// `exo-authority` DelegationRegistry (VCG-006b / #736, D3
    /// one-authority-model rule).
    ///
    /// This is the operator-facing side of the runtime issuer allow-list: it
    /// is how a real authority grant comes to exist in the first place, so
    /// that `POST /api/v1/avc/issuers` requests presenting the resulting
    /// signed `AuthorityChain` (obtained via `find_delegated_issuer_registration_chain`)
    /// can be verified against an actively-granted delegation rather than an
    /// unverifiable, self-asserted claim.
    ///
    /// `sign_fn` must sign with the private key corresponding to
    /// `validator_public_key` for `validator_did`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delegation grant itself fails validation
    /// (for example, a non-monotonic expiry or an invalid signature).
    pub fn grant_issuer_registration_authority(
        &self,
        delegate_did: Did,
        delegate_kind: exo_authority::DelegateeKind,
        validator_public_key: &PublicKey,
        expires: Timestamp,
        now: &Timestamp,
        sign_fn: impl FnOnce(&[u8]) -> Signature,
    ) -> anyhow::Result<exo_authority::AuthorityLink> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| anyhow::anyhow!("AVC authority registry unavailable"))?;
        authority
            .delegate(
                exo_authority::delegation::DelegationGrant {
                    from: &self.validator_did,
                    to: &delegate_did,
                    scope: &[Permission::Govern],
                    expires,
                    now,
                    parent_link_id: None,
                    delegatee_kind: delegate_kind,
                    delegator_public_key: validator_public_key,
                },
                sign_fn,
            )
            .map_err(|error| {
                anyhow::anyhow!("failed to grant AVC issuer-registration authority: {error}")
            })
    }

    /// Look up the actively-granted `AuthorityChain` from this node's
    /// `validator_did` to `delegate_did`, if one exists in this node's own
    /// `exo-authority` DelegationRegistry.
    ///
    /// Callers registering or rotating an AVC issuer at runtime attach this
    /// chain as `RegisterIssuerRequest::authority_chain` so the handler can
    /// verify it against the same registry that granted it.
    #[must_use]
    pub fn find_delegated_issuer_registration_chain(
        &self,
        delegate_did: &Did,
    ) -> Option<exo_authority::AuthorityChain> {
        let authority = self.authority.lock().ok()?;
        authority.find_chain(&self.validator_did, delegate_did)
    }

    /// Restore durable per-issuer runtime registrations (VCG-006b / #736
    /// hard requirement (a)) after a restart, re-verifying each stored
    /// `exo-authority` DelegationRegistry chain before admitting its key.
    ///
    /// Call this at startup AFTER every verified startup-config trust
    /// anchor that could be a chain root has been registered (validator
    /// public keys, the root-trust bundle issuer, etc.) — a stored chain
    /// can only re-verify once its root delegator's public key is
    /// resolvable. A stored record whose chain no longer verifies is
    /// rejected and its key never becomes resolvable, so restart can never
    /// resurrect an unauthorized key.
    ///
    /// Availability corrective (VCG-006b): a record that fails
    /// re-verification is skipped and logged at `warn` level — it is NOT
    /// fatal to startup. Before this fix, the very first legitimate
    /// `POST /api/v1/avc/issuers` registration made every subsequent restart
    /// fail outright, because the production validator key lives in
    /// `receipt_validator_public_keys`, never in the general resolvable
    /// `public_keys` map, so `validator_did`-rooted chains could never
    /// re-verify and the propagated error aborted the whole node. Only the
    /// per-record trust decision is unchanged: an unverifiable/tampered/
    /// expired key still never becomes resolvable.
    ///
    /// Returns an error only for genuine registry unavailability (e.g. a
    /// poisoned mutex), never for a record that simply failed
    /// re-verification.
    pub fn restore_registered_issuer_keys(&self, now: &Timestamp) -> anyhow::Result<()> {
        let mut registry = self.registry.lock().map_err(|_| {
            anyhow::anyhow!("AVC registry unavailable while restoring registered issuer keys")
        })?;
        let mut candidate = registry.clone();
        let skipped = candidate.restore_registered_issuer_keys(now);
        for (issuer_did, reason) in &skipped {
            tracing::warn!(
                issuer_did = %issuer_did,
                error = %reason,
                "skipped restoring a durable AVC registered issuer key: authority chain failed \
                 re-verification; the key remains unresolvable but node startup continues"
            );
        }
        *registry = candidate;
        Ok(())
    }
}

fn configured_external_timestamp_source_from_env()
-> anyhow::Result<AvcReceiptExternalTimestampSource> {
    configured_external_timestamp_source_from_reader(|name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be valid UTF-8"),
    })
}

fn clean_optional_env_value(
    value: Option<String>,
    name: &'static str,
) -> anyhow::Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                anyhow::bail!("{name} must not be empty");
            }
            Ok(Some(trimmed.to_owned()))
        }
        None => Ok(None),
    }
}

fn require_optional_env_value(value: Option<String>, name: &'static str) -> anyhow::Result<String> {
    clean_optional_env_value(value, name)?
        .ok_or_else(|| anyhow::anyhow!("{name} is required for RFC 3161 AVC timestamp authority"))
}

fn parse_non_empty_hex_string(raw: &str, label: &str) -> anyhow::Result<String> {
    let bytes = hex::decode(raw)
        .map_err(|error| anyhow::anyhow!("invalid {label} hex constant: {error}"))?;
    if bytes.is_empty() {
        anyhow::bail!("invalid {label} hex constant: expected non-empty DER bytes");
    }
    Ok(hex::encode(bytes))
}

fn parse_non_empty_hex_string_set(raw: &str, label: &str) -> anyhow::Result<Vec<String>> {
    let mut pins = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, part) in raw.split(',').enumerate() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            anyhow::bail!(
                "invalid {label} hex constant list: member {} is empty",
                index + 1
            );
        }
        let pin = parse_non_empty_hex_string(trimmed, label)?;
        if !seen.insert(pin.clone()) {
            anyhow::bail!(
                "invalid {label} hex constant list: duplicate member {}",
                index + 1
            );
        }
        pins.push(pin);
    }
    if pins.is_empty() {
        anyhow::bail!("invalid {label} hex constant list: expected at least one member");
    }
    Ok(pins)
}

fn external_timestamp_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_TIMEOUT)
        .build()
        .map_err(|error| anyhow::anyhow!("AVC external timestamp HTTP client failed: {error}"))
}

fn configured_external_timestamp_source_from_reader<F>(
    read: F,
) -> anyhow::Result<AvcReceiptExternalTimestampSource>
where
    F: Fn(&'static str) -> anyhow::Result<Option<String>>,
{
    let kind = clean_optional_env_value(
        read(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV)?,
        AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
    )?;
    let endpoint = clean_optional_env_value(
        read(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV)?,
        AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
    )?;
    let authority_did = clean_optional_env_value(
        read(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV)?,
        AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
    )?;
    let authority_public_key = clean_optional_env_value(
        read(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV)?,
        AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
    )?;
    let issuing_ca_spki = clean_optional_env_value(
        read(AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV)?,
        AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
    )?;
    let policy_oid = clean_optional_env_value(
        read(AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV)?,
        AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
    )?;

    if kind.is_none()
        && endpoint.is_none()
        && authority_did.is_none()
        && authority_public_key.is_none()
        && issuing_ca_spki.is_none()
        && policy_oid.is_none()
    {
        tracing::warn!(
            kind_env = AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
            url_env = AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
            did_env = AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
            key_env = AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
            ca_env = AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
            policy_env = AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
            require_env = AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV,
            "AVC external timestamp authority is not configured; receipt emission will use local EXOCHAIN HLC finality unless external timestamp proof is explicitly required"
        );
        return Ok(AvcReceiptExternalTimestampSource::Unconfigured);
    }

    let kind =
        kind.unwrap_or_else(|| AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519.to_owned());
    match kind.as_str() {
        AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519 => {
            if endpoint.is_none() || authority_did.is_none() || authority_public_key.is_none() {
                anyhow::bail!(
                    "AVC external timestamp authority configuration is incomplete for {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519}; set {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV}, {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV}, and {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV} together"
                );
            }
            if policy_oid.is_some() {
                anyhow::bail!(
                    "{AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV} is only valid with {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV}={AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161}"
                );
            }
            if issuing_ca_spki.is_some() {
                anyhow::bail!(
                    "{AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV} is only valid with {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV}={AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161}"
                );
            }
            let endpoint = endpoint.unwrap_or_default();
            let authority_did_raw = authority_did.unwrap_or_default();
            let authority_did = Did::new(&authority_did_raw).map_err(|error| {
                anyhow::anyhow!(
                    "{AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV} is not a valid DID: {error}"
                )
            })?;
            let authority_public_key = parse_expected_public_key(
                &authority_public_key.unwrap_or_default(),
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
            )?;
            Ok(AvcReceiptExternalTimestampSource::HttpJson {
                endpoint: Arc::new(endpoint),
                authority_did,
                authority_public_key,
                client: external_timestamp_http_client()?,
            })
        }
        AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161 => {
            let endpoint =
                require_optional_env_value(endpoint, AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV)?;
            let authority_did_raw = require_optional_env_value(
                authority_did,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
            )?;
            if authority_public_key.is_none() && issuing_ca_spki.is_none() {
                anyhow::bail!(
                    "RFC 3161 AVC timestamp authority requires at least one trust anchor; set either {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV} for signer leaf SPKI pins or {AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV} for issuing CA SPKI pins"
                );
            }
            let authority_public_key_spki_der_hexes = match authority_public_key {
                Some(authority_public_key) => parse_non_empty_hex_string_set(
                    &authority_public_key,
                    AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                )?,
                None => Vec::new(),
            };
            let issuing_ca_spki_der_hexes = match issuing_ca_spki {
                Some(issuing_ca_spki) => parse_non_empty_hex_string_set(
                    &issuing_ca_spki,
                    AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
                )?,
                None => Vec::new(),
            };
            crate::avc_rfc3161::Rfc3161TrustAnchors::new(
                authority_public_key_spki_der_hexes.clone(),
                issuing_ca_spki_der_hexes.clone(),
            )?;
            let policy_oid =
                require_optional_env_value(policy_oid, AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV)?;
            let authority_did = Did::new(&authority_did_raw).map_err(|error| {
                anyhow::anyhow!(
                    "{AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV} is not a valid DID: {error}"
                )
            })?;
            Ok(AvcReceiptExternalTimestampSource::Rfc3161 {
                endpoint: Arc::new(endpoint),
                authority_did,
                authority_public_key_spki_der_hexes: Arc::new(authority_public_key_spki_der_hexes),
                issuing_ca_spki_der_hexes: Arc::new(issuing_ca_spki_der_hexes),
                policy_oid: Arc::new(policy_oid),
                client: external_timestamp_http_client()?,
            })
        }
        _ => anyhow::bail!(
            "{AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV} must be {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519} or {AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161}"
        ),
    }
}

fn configured_require_external_timestamp_from_env() -> anyhow::Result<bool> {
    let value = match std::env::var(AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV} must be valid UTF-8");
        }
    };
    if value == "1" || value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value == "0" || value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    anyhow::bail!("{AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV} must be true/false or 1/0")
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
    pub granted_permissions: Vec<Permission>,
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

#[derive(Serialize)]
struct LegacyRootArtifactPayload<'a> {
    domain: &'static str,
    config_hash: Hash256,
    public_key_package_hash: Hash256,
    transcript_hash: Hash256,
    issuer_delegation_hash: Hash256,
    issuer_did: &'a Did,
}

#[derive(Serialize)]
struct LegacyRootBundleIdPayload<'a> {
    domain: &'static str,
    artifact_payload_hash: Hash256,
    root_signature: &'a RootSignature,
}

fn avc_root_canonical_bytes<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|error| anyhow::anyhow!("AVC root trust canonical encoding failed: {error}"))?;
    Ok(bytes)
}

fn avc_root_structured_hash<T: Serialize>(value: &T) -> anyhow::Result<Hash256> {
    hash_structured(value)
        .map_err(|error| anyhow::anyhow!("AVC root trust structured hash failed: {error}"))
}

fn legacy_avc_root_artifact_payload(bundle: &RootTrustBundle) -> anyhow::Result<Vec<u8>> {
    let payload = LegacyRootArtifactPayload {
        domain: "EXOCHAIN_ROOT_ARTIFACT_V1",
        config_hash: avc_root_structured_hash(&bundle.config)?,
        public_key_package_hash: avc_root_structured_hash(&bundle.public_key_package)?,
        transcript_hash: bundle.transcript_hash,
        issuer_delegation_hash: avc_root_structured_hash(&bundle.issuer_delegation)?,
        issuer_did: &bundle.issuer_delegation.issuer_did,
    };
    avc_root_canonical_bytes(&payload)
}

fn legacy_avc_root_bundle_id(bundle: &RootTrustBundle) -> anyhow::Result<Hash256> {
    let artifact_payload = legacy_avc_root_artifact_payload(bundle)?;
    let payload = LegacyRootBundleIdPayload {
        domain: "EXOCHAIN_ROOT_BUNDLE_V1",
        artifact_payload_hash: Hash256::digest(&artifact_payload),
        root_signature: &bundle.root_signature,
    };
    avc_root_structured_hash(&payload)
}

fn verify_pinned_legacy_avc_root_bundle(
    bundle: &RootTrustBundle,
    expected_bundle_id: Hash256,
) -> anyhow::Result<()> {
    if bundle.bundle_id != expected_bundle_id {
        anyhow::bail!(
            "legacy AVC root trust bundle id mismatch: expected {}, got {}",
            expected_bundle_id,
            bundle.bundle_id
        );
    }
    bundle
        .config
        .validate()
        .map_err(|error| anyhow::anyhow!("legacy AVC root trust config invalid: {error}"))?;
    if bundle.root_signature.signer_ids != bundle.config.signing_set {
        anyhow::bail!(
            "legacy AVC root trust signer metadata mismatch: root_signature.signer_ids must equal config.signing_set"
        );
    }
    let recomputed_bundle_id = legacy_avc_root_bundle_id(bundle)?;
    if recomputed_bundle_id != expected_bundle_id {
        anyhow::bail!(
            "legacy AVC root trust recomputed bundle id mismatch: expected {}, got {}",
            expected_bundle_id,
            recomputed_bundle_id
        );
    }
    let payload = legacy_avc_root_artifact_payload(bundle)?;
    verify_root_signature(
        &bundle.public_key_package.root_public_key,
        &payload,
        bundle.root_signature.signature.as_slice(),
    )
    .map_err(|error| anyhow::anyhow!("legacy AVC root trust signature rejected: {error}"))
}

fn verify_current_or_pinned_legacy_avc_root_bundle(
    bundle: &RootTrustBundle,
    expected_bundle_id: Hash256,
) -> anyhow::Result<()> {
    match verify_root_bundle(bundle) {
        Ok(()) => Ok(()),
        Err(strict_error) => {
            verify_pinned_legacy_avc_root_bundle(bundle, expected_bundle_id).map_err(
                |legacy_error| {
                    anyhow::anyhow!(
                        "strict root trust verification failed: {strict_error}; pinned legacy AVC root trust verification failed: {legacy_error}"
                    )
                },
            )
        }
    }
}

#[derive(Serialize)]
struct RootBundleReceiptHashMaterial<'a> {
    schema_version: &'static str,
    bundle_id: Hash256,
    root_bundle_hash: Hash256,
    ceremony_id: &'a str,
    issuer_did: &'a Did,
    issuer_public_key_hash: Hash256,
    signing_set_hash: Hash256,
    quorum_threshold: u16,
    verifier_version: &'static str,
    verified_at: Timestamp,
}

struct RootBundleReceiptRecord {
    root_bundle_hash: Hash256,
    issuer_public_key_hash: Hash256,
    signing_set_hash: Hash256,
    verification_receipt_hash: Hash256,
    verification_receipt_body: serde_json::Value,
    verified_at: Timestamp,
    created_at: Timestamp,
}

fn root_bundle_receipt_record(bundle: &RootTrustBundle) -> anyhow::Result<RootBundleReceiptRecord> {
    let root_bundle_hash = hash_structured(bundle)
        .map_err(|error| anyhow::anyhow!("AVC root bundle receipt hash failed: {error}"))?;
    let issuer_public_key_hash =
        Hash256::digest(bundle.issuer_delegation.issuer_public_key.as_bytes());
    let signing_set_hash = hash_structured(&bundle.config.signing_set)
        .map_err(|error| anyhow::anyhow!("AVC root bundle signing set hash failed: {error}"))?;
    let verified_at = bundle.issuer_delegation.effective_at;
    let material = RootBundleReceiptHashMaterial {
        schema_version: AVC_ROOT_BUNDLE_RECEIPT_SCHEMA_VERSION,
        bundle_id: bundle.bundle_id,
        root_bundle_hash,
        ceremony_id: &bundle.config.ceremony_id,
        issuer_did: &bundle.issuer_delegation.issuer_did,
        issuer_public_key_hash,
        signing_set_hash,
        quorum_threshold: bundle.config.threshold,
        verifier_version: AVC_ROOT_BUNDLE_RECEIPT_VERIFIER_VERSION,
        verified_at,
    };
    let verification_receipt_hash = hash_structured(&material).map_err(|error| {
        anyhow::anyhow!("AVC root bundle verification receipt hash failed: {error}")
    })?;
    let verification_receipt_body = serde_json::json!({
        "schema_version": AVC_ROOT_BUNDLE_RECEIPT_SCHEMA_VERSION,
        "bundle_id": bundle.bundle_id.to_string(),
        "root_bundle_hash": root_bundle_hash.to_string(),
        "ceremony_id": bundle.config.ceremony_id,
        "issuer_did": bundle.issuer_delegation.issuer_did.to_string(),
        "issuer_public_key_hash": issuer_public_key_hash.to_string(),
        "signing_set_hash": signing_set_hash.to_string(),
        "quorum_threshold": bundle.config.threshold,
        "verifier_version": AVC_ROOT_BUNDLE_RECEIPT_VERIFIER_VERSION,
        "verified_at": {
            "physical_ms": verified_at.physical_ms,
            "logical": verified_at.logical
        },
    });

    Ok(RootBundleReceiptRecord {
        root_bundle_hash,
        issuer_public_key_hash,
        signing_set_hash,
        verification_receipt_hash,
        verification_receipt_body,
        verified_at,
        created_at: verified_at,
    })
}

async fn insert_root_bundle_receipt(
    pool: &PgPool,
    bundle: &RootTrustBundle,
    record: RootBundleReceiptRecord,
) -> anyhow::Result<()> {
    let verified_at_logical = i32::try_from(record.verified_at.logical).map_err(|_| {
        anyhow::anyhow!("AVC root bundle verified_at logical counter is out of SQL range")
    })?;
    let created_at_logical = i32::try_from(record.created_at.logical).map_err(|_| {
        anyhow::anyhow!("AVC root bundle created_at logical counter is out of SQL range")
    })?;
    sqlx::query(
        "INSERT INTO dagdb_root_bundle_receipts \
         (bundle_id, root_bundle_hash, ceremony_id, issuer_did, issuer_public_key_hash, \
          signing_set_hash, quorum_threshold, verifier_version, verification_receipt_hash, \
          verification_receipt_body, verified_at_physical_ms, verified_at_logical, \
          created_at_physical_ms, created_at_logical, immutable) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true) \
         ON CONFLICT (bundle_id) DO NOTHING",
    )
    .bind(bundle.bundle_id.as_bytes().to_vec())
    .bind(record.root_bundle_hash.as_bytes().to_vec())
    .bind(&bundle.config.ceremony_id)
    .bind(bundle.issuer_delegation.issuer_did.to_string())
    .bind(record.issuer_public_key_hash.as_bytes().to_vec())
    .bind(record.signing_set_hash.as_bytes().to_vec())
    .bind(i32::from(bundle.config.threshold))
    .bind(AVC_ROOT_BUNDLE_RECEIPT_VERIFIER_VERSION)
    .bind(record.verification_receipt_hash.as_bytes().to_vec())
    .bind(record.verification_receipt_body)
    .bind(i64::try_from(record.verified_at.physical_ms).map_err(|_| {
        anyhow::anyhow!("AVC root bundle verified_at physical_ms is out of SQL range")
    })?)
    .bind(verified_at_logical)
    .bind(i64::try_from(record.created_at.physical_ms).map_err(|_| {
        anyhow::anyhow!("AVC root bundle created_at physical_ms is out of SQL range")
    })?)
    .bind(created_at_logical)
    .execute(pool)
    .await
    .map_err(|error| {
        anyhow::anyhow!("failed to persist AVC root bundle DAG DB receipt: {error}")
    })?;
    Ok(())
}

fn persist_verified_root_bundle_receipt(
    state: &AvcApiState,
    bundle: &RootTrustBundle,
) -> anyhow::Result<()> {
    let AvcRegistryDurability::Postgres(pool) = &state.durability else {
        return Ok(());
    };
    let record = root_bundle_receipt_record(bundle)?;
    let pool = pool.clone();
    let bundle = bundle.clone();
    match tokio::runtime::Handle::try_current() {
        Ok(_) => std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().map_err(|error| {
                anyhow::anyhow!("failed to create AVC root bundle receipt runtime: {error}")
            })?;
            runtime.block_on(insert_root_bundle_receipt(&pool, &bundle, record))
        })
        .join()
        .map_err(|_| anyhow::anyhow!("AVC root bundle receipt worker panicked"))?,
        Err(_) => {
            let runtime = tokio::runtime::Runtime::new().map_err(|error| {
                anyhow::anyhow!("failed to create AVC root bundle receipt runtime: {error}")
            })?;
            runtime.block_on(insert_root_bundle_receipt(&pool, &bundle, record))
        }
    }
}

/// Grant the configured operator DID runtime AVC issuer-registration
/// authority (`Permission::Govern`) from this node's own `validator_did`,
/// signed with this node's own operational key (VCG-006b / #736, D3
/// one-authority-model rule).
///
/// If `EXO_AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV` is absent, no grant is
/// made and `POST /api/v1/avc/issuers` refuses every request until a grant
/// is created through some other channel (see
/// `AvcApiState::grant_issuer_registration_authority`). If it is present,
/// `EXO_AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS_ENV` is required, and
/// any missing/malformed configuration or delegation-grant failure is fatal
/// to preserve fail-closed production startup — the same posture as
/// `load_configured_root_trust_bundle`.
pub fn configure_issuer_registration_authority_from_env(
    state: &AvcApiState,
    validator_public_key: &PublicKey,
    now: &Timestamp,
    sign_fn: impl FnOnce(&[u8]) -> Signature,
) -> anyhow::Result<Option<Did>> {
    let Some(operator_did_raw) = std::env::var_os(AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV) else {
        return Ok(None);
    };
    let operator_did_raw = operator_did_raw.to_string_lossy();
    if operator_did_raw.is_empty() {
        anyhow::bail!("{AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV} is set but empty");
    }
    let operator_did = Did::new(&operator_did_raw).map_err(|error| {
        anyhow::anyhow!("{AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV} is not a valid DID: {error}")
    })?;

    let expires_raw =
        std::env::var(AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS_ENV).map_err(|_| {
            anyhow::anyhow!(
                "{AVC_ISSUER_REGISTRATION_OPERATOR_DID_ENV} is set but \
                 {AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS_ENV} is not configured"
            )
        })?;
    let expires_seconds: u64 = expires_raw.trim().parse().map_err(|error| {
        anyhow::anyhow!(
            "{AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS_ENV} must be an unsigned integer \
             number of seconds: {error}"
        )
    })?;
    let expires = Timestamp::new(
        expires_seconds.checked_mul(1000).ok_or_else(|| {
            anyhow::anyhow!(
                "{AVC_ISSUER_REGISTRATION_EXPIRES_UNIX_SECONDS_ENV} overflows milliseconds"
            )
        })?,
        0,
    );

    state.grant_issuer_registration_authority(
        operator_did.clone(),
        exo_authority::DelegateeKind::Human,
        validator_public_key,
        expires,
        now,
        sign_fn,
    )?;
    Ok(Some(operator_did))
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
        let registry = state.registry.lock().map_err(|_| {
            anyhow::anyhow!("AVC registry unavailable while checking durable revocations")
        })?;
        if registry.revocation_count() > 0 {
            anyhow::bail!(
                "AVC durable registry contains revocations but {AVC_ROOT_TRUST_BUNDLE_ENV} is not configured; durable revocation signatures cannot be verified"
            );
        }
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
    let root_trust = resolve_avc_root_trust_constants();
    let expected_bundle_id =
        parse_expected_hash(root_trust.bundle_id_hex, "AVC root trust bundle id")?;
    verify_current_or_pinned_legacy_avc_root_bundle(&bundle, expected_bundle_id).map_err(
        |error| {
            anyhow::anyhow!(
                "AVC root trust bundle verification failed for {}: {error}",
                path.display()
            )
        },
    )?;

    if bundle.config.ceremony_id != root_trust.ceremony_id {
        anyhow::bail!(
            "AVC root trust bundle ceremony mismatch: expected {}, got {}",
            root_trust.ceremony_id,
            bundle.config.ceremony_id
        );
    }

    if bundle.bundle_id != expected_bundle_id {
        anyhow::bail!(
            "AVC root trust bundle id mismatch: expected {}, got {}",
            expected_bundle_id,
            bundle.bundle_id
        );
    }

    let expected_issuer_did = Did::new(root_trust.issuer_did)
        .map_err(|error| anyhow::anyhow!("invalid AVC root trust issuer DID constant: {error}"))?;
    if bundle.issuer_delegation.issuer_did != expected_issuer_did {
        anyhow::bail!(
            "AVC root trust issuer DID mismatch: expected {}, got {}",
            expected_issuer_did,
            bundle.issuer_delegation.issuer_did
        );
    }

    let expected_public_key = parse_expected_public_key(
        root_trust.issuer_public_key_hex,
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
        granted_permissions: bundle.issuer_delegation.granted_permissions.clone(),
    };

    let mut registry = state.registry.lock().map_err(|_| {
        anyhow::anyhow!("AVC registry unavailable while registering root trust issuer")
    })?;
    let mut candidate = registry.clone();
    candidate.put_public_key(
        registration.issuer_did.clone(),
        registration.issuer_public_key,
    );
    candidate.put_issuer_permission_grant(
        registration.issuer_did.clone(),
        registration.granted_permissions.clone(),
    );
    candidate.validate_loaded_revocations().map_err(|error| {
        anyhow::anyhow!(
            "AVC durable revocation validation failed after root trust issuer registration: {error}"
        )
    })?;
    persist_verified_root_bundle_receipt(state, &bundle)?;
    *registry = candidate;

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
#[serde(deny_unknown_fields)]
pub struct LlmUsageReceiptEmitRequest {
    pub validation: AvcValidationRequest,
    pub subject_signature: Signature,
    /// Optional subject public key for did:exo values derived from a key.
    /// If the registry already has a trusted key for the actor DID, that
    /// registered key wins and this field is ignored.
    pub subject_public_key: Option<PublicKey>,
    pub llm_usage_evidence: LlmUsageEvidenceEnvelope,
    pub adapter_signature: Signature,
    /// Optional adapter public key for did:exo values derived from a key.
    /// If the registry already has a trusted key for the adapter DID, that
    /// registered key wins and this field is ignored.
    pub adapter_public_key: Option<PublicKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmitReceiptResponse {
    pub receipt_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exochain_finality_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exochain_finality_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exochain_finality_receipt_hash: Option<String>,
    pub receipt: AvcTrustReceipt,
    pub validation: AvcValidationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputAuthorizationRequest {
    pub credential_id: Hash256,
    pub subject: String,
    pub audience: String,
    pub evidence_hash: Hash256,
    pub idempotency_key: String,
    pub expires_at: Timestamp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListAvcReceiptsResponse {
    pub did: String,
    pub receipts: Vec<AvcTrustReceipt>,
}

/// Runtime AVC issuer allow-list registration/rotation request
/// (VCG-006b / #736).
///
/// `authority_chain` must carry a real `exo-authority` DelegationRegistry
/// chain — verified against this node's own DelegationRegistry and
/// cryptographically re-verified against `resolve_key` — granting
/// `Permission::Govern` from this node's `validator_did` down to the
/// caller. The bare admin bearer token that gates every mutating AVC route
/// is necessary but not sufficient authority for this specific mutation
/// per the D3 one-authority-model rule (GAP-REGISTRY.md D3): absent,
/// malformed, or under-scoped chain evidence is rejected with
/// `StatusCode::FORBIDDEN` and never mutates the registry.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterIssuerRequest {
    pub issuer_did: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub authority_chain: Option<exo_authority::AuthorityChain>,
    #[serde(default)]
    pub granted_permissions: Vec<Permission>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterIssuerResponse {
    pub issuer_did: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct ListAvcReceiptsQuery {
    actor: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AvcProtocolQuery {
    protocol_version: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct IssuerRegistrationAuthorityQuery {
    operator_did: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvcProtocolInfo {
    pub protocol_version: u16,
    pub min_supported_protocol_version: u16,
    pub max_supported_protocol_version: u16,
    pub schema_version: u16,
    pub wasm_package_name: String,
    pub wasm_package_version: String,
    pub deprecation_window_days: u16,
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

fn external_timestamp_error(err: anyhow::Error) -> ApiError {
    let error_class = external_timestamp_error_class(&err);
    tracing::error!(
        err = %err,
        error_class = error_class,
        "AVC external timestamp proof could not be obtained"
    );
    // Surface the stable operator class in the PUBLIC message too. Callers (the
    // emit smoke, operators) often see only the response, not the node logs, and
    // a blanket "authority unavailable" misreads a signer-SPKI pin rejection
    // (class=invalid_proof) or a TSA-returned error status (class=rejected) as
    // upstream downtime (class=unreachable) — exactly the misdiagnosis we hit in
    // production. The class tokens are already the sanctioned operator-facing
    // classification, so this leaks no response detail.
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("AVC external timestamp proof could not be obtained (class: {error_class})"),
    )
}

fn exochain_finality_error(err: anyhow::Error) -> ApiError {
    tracing::error!(err = %err, "AVC EXOCHAIN finality persistence failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "AVC EXOCHAIN finality persistence failed".into(),
    )
}

fn local_hlc_timestamp_error(err: anyhow::Error) -> ApiError {
    tracing::error!(err = %err, "AVC local HLC timestamp failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "AVC local HLC timestamp failed".into(),
    )
}

struct AvcReceiptTimestampEvidence {
    trusted_now: Timestamp,
    provenance: AvcReceiptTimestampProvenance,
    external_timestamp_proof: Option<AvcReceiptExternalTimestampProof>,
}

/// This node's own trusted local hybrid-logical-clock timestamp.
///
/// Shared by AVC receipt emission and startup-time authority-grant
/// configuration (`configure_issuer_registration_authority_from_env`) as the
/// single source of "now" — never a direct `SystemTime`/`Instant` read.
pub fn trusted_local_hlc_timestamp(state: &AvcApiState) -> anyhow::Result<Timestamp> {
    let mut clock = state
        .receipt_clock
        .lock()
        .map_err(|_| anyhow::anyhow!("AVC receipt HLC mutex poisoned"))?;
    clock
        .now()
        .map_err(|error| anyhow::anyhow!("AVC receipt HLC could not advance: {error}"))
}

async fn trusted_external_timestamp_proof(
    state: &AvcApiState,
    evidence_subject: &AvcReceiptEvidenceSubject,
) -> ApiResult<AvcReceiptExternalTimestampProof> {
    state
        .external_timestamp_source
        .issue_proof(evidence_subject)
        .await
        .map_err(external_timestamp_error)
}

async fn trusted_receipt_timestamp_evidence(
    state: &AvcApiState,
    evidence_subject: &AvcReceiptEvidenceSubject,
) -> ApiResult<AvcReceiptTimestampEvidence> {
    if matches!(
        state.external_timestamp_source,
        AvcReceiptExternalTimestampSource::Unconfigured
    ) && !state.require_external_timestamp
    {
        let trusted_now = trusted_local_hlc_timestamp(state).map_err(local_hlc_timestamp_error)?;
        return Ok(AvcReceiptTimestampEvidence {
            trusted_now,
            provenance: AvcReceiptTimestampProvenance::LocalHybridLogicalClock,
            external_timestamp_proof: None,
        });
    }

    let external_timestamp_proof =
        trusted_external_timestamp_proof(state, evidence_subject).await?;
    Ok(AvcReceiptTimestampEvidence {
        trusted_now: external_timestamp_proof.issued_at,
        provenance: AvcReceiptTimestampProvenance::ExternalTimestampAuthority,
        external_timestamp_proof: Some(external_timestamp_proof),
    })
}

fn avc_receipt_list_limit(limit: Option<u32>) -> usize {
    let capped = limit
        .unwrap_or(DEFAULT_AVC_RECEIPT_LIST_LIMIT)
        .min(MAX_AVC_RECEIPT_LIST_LIMIT);
    match usize::try_from(capped) {
        Ok(value) => value,
        Err(_) => usize::from(u16::MAX),
    }
}

fn emit_receipt_response(
    receipt: AvcTrustReceipt,
    validation: AvcValidationResult,
) -> EmitReceiptResponse {
    EmitReceiptResponse {
        receipt_hash: format!("{}", receipt.receipt_id),
        exochain_finality_hash: None,
        exochain_finality_height: None,
        exochain_finality_receipt_hash: None,
        receipt,
        validation,
    }
}

fn attach_exochain_finality(
    response: &mut EmitReceiptResponse,
    commitment: Option<AvcExochainFinalityCommitment>,
) {
    if let Some(commitment) = commitment {
        response.exochain_finality_hash = Some(format!("{}", commitment.finality_hash));
        response.exochain_finality_height = Some(commitment.finality_height);
        response.exochain_finality_receipt_hash =
            Some(format!("{}", commitment.finality_receipt_hash));
    }
}

fn avc_protocol_info() -> AvcProtocolInfo {
    AvcProtocolInfo {
        protocol_version: AVC_PROTOCOL_VERSION,
        min_supported_protocol_version: AVC_MIN_SUPPORTED_PROTOCOL_VERSION,
        max_supported_protocol_version: AVC_MAX_SUPPORTED_PROTOCOL_VERSION,
        schema_version: AVC_SCHEMA_VERSION,
        wasm_package_name: WASM_PACKAGE_NAME.into(),
        wasm_package_version: WASM_PACKAGE_VERSION.into(),
        deprecation_window_days: AVC_PROTOCOL_DEPRECATION_WINDOW_DAYS,
    }
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
        | exo_avc::AvcError::UnsupportedProtocol { .. }
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

fn require_matching_llm_usage_action(
    request: &AvcValidationRequest,
    expected_action: &AvcActionRequest,
) -> ApiResult<()> {
    let submitted_action = require_action(request)?;
    if submitted_action != expected_action {
        return Err((
            StatusCode::BAD_REQUEST,
            "LLM usage receipt validation action must match canonical evidence-derived action"
                .into(),
        ));
    }
    Ok(())
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

fn resolve_did_public_key(
    registry: &InMemoryAvcRegistry,
    did: &Did,
    supplied_public_key: Option<PublicKey>,
    unresolved_message: &'static str,
    mismatch_message: &'static str,
) -> ApiResult<PublicKey> {
    if let Some(public_key) = registry.resolve_public_key(did) {
        return Ok(public_key);
    }

    let Some(public_key) = supplied_public_key else {
        return Err((StatusCode::UNAUTHORIZED, unresolved_message.into()));
    };
    let derived_did = crate::identity::did_from_public_key(&public_key).map_err(|err| {
        tracing::warn!(%err, "rejected AVC DID-bound public key");
        (StatusCode::UNAUTHORIZED, mismatch_message.into())
    })?;
    if &derived_did != did {
        return Err((StatusCode::UNAUTHORIZED, mismatch_message.into()));
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

fn verify_llm_usage_evidence_signature(
    registry: &InMemoryAvcRegistry,
    envelope: &LlmUsageEvidenceEnvelope,
    adapter_signature: &Signature,
    adapter_public_key: Option<PublicKey>,
) -> ApiResult<()> {
    if adapter_signature.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "LLM usage adapter signature must not be empty".into(),
        ));
    }
    let public_key = resolve_did_public_key(
        registry,
        &envelope.adapter_did,
        adapter_public_key,
        "LLM usage adapter public key is unresolved",
        "LLM usage adapter public key does not match adapter DID",
    )?;
    let payload = llm_usage_evidence_signature_payload(envelope).map_err(map_avc_error)?;
    if !crypto::verify(&payload, adapter_signature, &public_key) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "LLM usage adapter signature is invalid".into(),
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

fn validate_idempotent_receipt_hit(
    receipt: &AvcTrustReceipt,
    credential_id: Hash256,
    action_id: Hash256,
    action_commitment_hash: Hash256,
    expected_llm_usage_evidence_hash: Option<Hash256>,
    validation: &AvcValidationResult,
) -> ApiResult<()> {
    let validation_hash = hash_structured(validation)
        .map_err(exo_avc::AvcError::from)
        .map_err(map_avc_error)?;
    if receipt.credential_id == credential_id
        && receipt.action_id == Some(action_id)
        && receipt.action_commitment_hash == Some(action_commitment_hash)
        && receipt.llm_usage_evidence_hash == expected_llm_usage_evidence_hash
        && receipt.validation_hash == validation_hash
        && receipt.decision == validation.decision
        && receipt.reason_codes == validation.reason_codes
    {
        return Ok(());
    }

    if expected_llm_usage_evidence_hash.is_some()
        && receipt.credential_id == credential_id
        && receipt.action_id == Some(action_id)
        && receipt.action_commitment_hash == Some(action_commitment_hash)
        && receipt.llm_usage_evidence_hash != expected_llm_usage_evidence_hash
    {
        tracing::warn!(
            receipt_id = %receipt.receipt_id,
            stored_llm_usage_evidence_hash = ?receipt.llm_usage_evidence_hash,
            expected_llm_usage_evidence_hash = ?expected_llm_usage_evidence_hash,
            "AVC LYNK idempotency evidence conflict"
        );
        return Err((
            StatusCode::CONFLICT,
            "AVC LYNK idempotency evidence conflict".into(),
        ));
    }

    tracing::error!(
        receipt_id = %receipt.receipt_id,
        stored_credential_id = %receipt.credential_id,
        expected_credential_id = %credential_id,
        stored_action_id = ?receipt.action_id,
        expected_action_id = %action_id,
        action_commitment_hash = %action_commitment_hash,
        "AVC receipt action commitment conflict"
    );
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        "AVC receipt action commitment conflict".into(),
    ))
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
    let submitted_request = payload.validation.clone();
    let action = require_action(&submitted_request)?;
    let action_id = action.action_id;
    let action_commitment_hash = avc_action_commitment_hash(
        &submitted_request.credential,
        action,
        &submitted_request.now,
    )
    .map_err(map_avc_error)?;
    let action_descriptor = AvcActionDescriptor::from_action(action);
    let action_descriptor_hash =
        avc_action_descriptor_hash(&action_descriptor).map_err(map_avc_error)?;
    let subject_signature = payload.subject_signature.clone();
    let subject_public_key = payload.subject_public_key;
    let preflight_request = submitted_request.clone();
    let preflight_signature = subject_signature.clone();
    let preflight = with_registry_blocking(Arc::clone(&state), false, move |registry| {
        let credential_id = require_registered_credential(registry, &preflight_request)?;
        verify_subject_action_signature(
            registry,
            &preflight_request,
            &preflight_signature,
            subject_public_key,
        )?;
        Ok((credential_id, registry.receipt_chain_head()))
    })
    .await?;
    let (credential_id, previous_receipt_hash) = preflight;
    let evidence_subject = AvcReceiptEvidenceSubject {
        credential_id,
        action_id,
        action_commitment_hash,
        action_descriptor_hash,
        previous_receipt_hash,
    };
    let timestamp_evidence = trusted_receipt_timestamp_evidence(&state, &evidence_subject).await?;
    let trusted_now = timestamp_evidence.trusted_now;
    let state_for_registry = Arc::clone(&state);
    let mut response = with_registry_blocking(state_for_registry, true, move |registry| {
        let credential_id = require_registered_credential(registry, &submitted_request)?;
        verify_subject_action_signature(
            registry,
            &submitted_request,
            &subject_signature,
            subject_public_key,
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
        if let Some(receipt) = registry.get_receipt_by_action_commitment(&action_commitment_hash) {
            validate_idempotent_receipt_hit(
                &receipt,
                credential_id,
                action_id,
                action_commitment_hash,
                None,
                &validation,
            )?;
            return Ok(emit_receipt_response(receipt, validation));
        }
        if registry.receipt_chain_head() != previous_receipt_hash {
            return Err((
                StatusCode::CONFLICT,
                "AVC receipt chain advanced during external timestamp attestation".into(),
            ));
        }
        let receipt = create_trust_receipt_with_evidence(
            &validation,
            Some(action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(action_commitment_hash),
                action_descriptor: Some(action_descriptor),
                llm_usage_evidence_hash: None,
                previous_receipt_hash,
                timestamp_provenance: Some(timestamp_evidence.provenance),
                external_timestamp_proof: timestamp_evidence.external_timestamp_proof,
            },
            validator_did,
            trusted_now,
            |bytes| (receipt_signer)(bytes),
        )
        .map_err(map_avc_error)?;
        store_receipt_idempotent(registry, receipt.clone())?;
        Ok(emit_receipt_response(receipt, validation))
    })
    .await?;
    let finality = commit_exochain_finality(
        &state.finality_store,
        &response.receipt,
        &state.validator_did,
        &state.receipt_signer,
    )
    .map_err(exochain_finality_error)?;
    attach_exochain_finality(&mut response, finality);
    Ok(Json(response))
}

async fn handle_llm_usage_emit_receipt(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<LlmUsageReceiptEmitRequest>,
) -> ApiResult<Json<EmitReceiptResponse>> {
    let validator_did = state.validator_did.clone();
    let receipt_signer = Arc::clone(&state.receipt_signer);
    let envelope = payload.llm_usage_evidence.clone();
    let llm_evidence_hash = llm_usage_evidence_hash(&envelope.evidence).map_err(map_avc_error)?;
    let evidence_action =
        avc_llm_usage_action_request(&envelope.evidence).map_err(map_avc_error)?;
    let submitted_request = payload.validation.clone();
    require_matching_llm_usage_action(&submitted_request, &evidence_action)?;
    let action_id = evidence_action.action_id;
    let action_commitment_hash = avc_action_commitment_hash(
        &submitted_request.credential,
        &evidence_action,
        &submitted_request.now,
    )
    .map_err(map_avc_error)?;
    let action_descriptor = AvcActionDescriptor::from_action(&evidence_action);
    let action_descriptor_hash =
        avc_action_descriptor_hash(&action_descriptor).map_err(map_avc_error)?;
    let subject_signature = payload.subject_signature.clone();
    let subject_public_key = payload.subject_public_key;
    let adapter_signature = payload.adapter_signature.clone();
    let adapter_public_key = payload.adapter_public_key;
    let preflight_request = submitted_request.clone();
    let preflight_subject_signature = subject_signature.clone();
    let preflight_adapter_signature = adapter_signature.clone();
    let preflight_envelope = envelope.clone();
    let preflight = with_registry_blocking(Arc::clone(&state), false, move |registry| {
        let credential_id = require_registered_credential(registry, &preflight_request)?;
        verify_llm_usage_evidence_signature(
            registry,
            &preflight_envelope,
            &preflight_adapter_signature,
            adapter_public_key,
        )?;
        verify_subject_action_signature(
            registry,
            &preflight_request,
            &preflight_subject_signature,
            subject_public_key,
        )?;
        Ok((credential_id, registry.receipt_chain_head()))
    })
    .await?;
    let (credential_id, previous_receipt_hash) = preflight;
    let evidence_subject = AvcReceiptEvidenceSubject {
        credential_id,
        action_id,
        action_commitment_hash,
        action_descriptor_hash,
        previous_receipt_hash,
    };
    let timestamp_evidence = trusted_receipt_timestamp_evidence(&state, &evidence_subject).await?;
    let trusted_now = timestamp_evidence.trusted_now;
    let state_for_registry = Arc::clone(&state);
    let mut response = with_registry_blocking(state_for_registry, true, move |registry| {
        let credential_id = require_registered_credential(registry, &submitted_request)?;
        verify_llm_usage_evidence_signature(
            registry,
            &envelope,
            &adapter_signature,
            adapter_public_key,
        )?;
        verify_subject_action_signature(
            registry,
            &submitted_request,
            &subject_signature,
            subject_public_key,
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
        if let Some(receipt) = registry.get_receipt_by_action_commitment(&action_commitment_hash) {
            validate_idempotent_receipt_hit(
                &receipt,
                credential_id,
                action_id,
                action_commitment_hash,
                Some(llm_evidence_hash),
                &validation,
            )?;
            return Ok(emit_receipt_response(receipt, validation));
        }
        if registry.receipt_chain_head() != previous_receipt_hash {
            return Err((
                StatusCode::CONFLICT,
                "AVC receipt chain advanced during external timestamp attestation".into(),
            ));
        }
        let receipt = create_trust_receipt_with_evidence(
            &validation,
            Some(action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(action_commitment_hash),
                action_descriptor: Some(action_descriptor),
                llm_usage_evidence_hash: Some(llm_evidence_hash),
                previous_receipt_hash,
                timestamp_provenance: Some(timestamp_evidence.provenance),
                external_timestamp_proof: timestamp_evidence.external_timestamp_proof,
            },
            validator_did,
            trusted_now,
            |bytes| (receipt_signer)(bytes),
        )
        .map_err(map_avc_error)?;
        store_receipt_idempotent(registry, receipt.clone())?;
        Ok(emit_receipt_response(receipt, validation))
    })
    .await?;
    let finality = commit_exochain_finality(
        &state.finality_store,
        &response.receipt,
        &state.validator_did,
        &state.receipt_signer,
    )
    .map_err(exochain_finality_error)?;
    attach_exochain_finality(&mut response, finality);
    Ok(Json(response))
}

async fn handle_public_output_authorization(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<PublicOutputAuthorizationRequest>,
) -> ApiResult<Json<LivesafePublicAdapterOutputAuthorizationEnvelope>> {
    let validator_did = state.validator_did.clone();
    let receipt_signer = Arc::clone(&state.receipt_signer);
    let idempotency_key_hash =
        livesafe_public_adapter_output_authorization_idempotency_hash(&payload.idempotency_key)
            .map_err(map_avc_error)?;
    let credential_id = payload.credential_id;
    let subject = payload.subject;
    let audience = payload.audience;
    let evidence_hash = payload.evidence_hash;
    let expires_at = payload.expires_at;
    let state_for_clock = Arc::clone(&state);

    let envelope = with_registry_blocking(state, true, move |registry| {
        let credential = registry.get_credential(&credential_id).ok_or((
            StatusCode::NOT_FOUND,
            "public output authorization credential is not registered".into(),
        ))?;
        let action = livesafe_public_adapter_output_authorization_action_request(
            &credential,
            &subject,
            &audience,
            evidence_hash,
            idempotency_key_hash,
            &expires_at,
        )
        .map_err(map_avc_error)?;

        if let Some(existing) = registry.get_receipt_by_action_id(&idempotency_key_hash) {
            let action_commitment_hash =
                livesafe_public_adapter_output_authorization_action_commitment_hash(
                    &credential,
                    &subject,
                    &audience,
                    evidence_hash,
                    idempotency_key_hash,
                    &existing.created_at,
                    &expires_at,
                )
                .map_err(map_avc_error)?;
            if existing.credential_id != credential_id
                || existing.action_commitment_hash != Some(action_commitment_hash)
            {
                return Err((
                    StatusCode::CONFLICT,
                    "public output authorization idempotency key conflict".into(),
                ));
            }
            let draft = LivesafePublicAdapterOutputAuthorizationDraft {
                credential,
                subject,
                audience,
                evidence_hash,
                credential_id: Some(credential_id),
                receipt_id: existing.receipt_id,
                action_commitment_hash,
                idempotency_key_hash,
                issued_at: existing.created_at,
                expires_at,
                signer_did: validator_did,
            };
            return mint_livesafe_public_adapter_output_authorization_proof(
                draft,
                registry,
                |bytes| (receipt_signer)(bytes),
            )
            .map_err(map_avc_error);
        }

        let issued_at =
            trusted_local_hlc_timestamp(&state_for_clock).map_err(local_hlc_timestamp_error)?;
        let action_commitment_hash =
            livesafe_public_adapter_output_authorization_action_commitment_hash(
                &credential,
                &subject,
                &audience,
                evidence_hash,
                idempotency_key_hash,
                &issued_at,
                &expires_at,
            )
            .map_err(map_avc_error)?;
        let action_descriptor = AvcActionDescriptor::from_action(&action);
        let previous_receipt_hash = registry.receipt_chain_head();
        let pre_receipt_draft = LivesafePublicAdapterOutputAuthorizationDraft {
            credential: credential.clone(),
            subject: subject.clone(),
            audience: audience.clone(),
            evidence_hash,
            credential_id: Some(credential_id),
            receipt_id: Hash256::ZERO,
            action_commitment_hash,
            idempotency_key_hash,
            issued_at,
            expires_at,
            signer_did: validator_did.clone(),
        };
        let validation =
            validate_livesafe_public_adapter_output_authorization(&pre_receipt_draft, registry)
                .map_err(map_avc_error)?;
        let receipt = create_trust_receipt_with_evidence(
            &validation,
            Some(action.action_id),
            AvcTrustReceiptEvidence {
                action_commitment_hash: Some(action_commitment_hash),
                action_descriptor: Some(action_descriptor),
                llm_usage_evidence_hash: None,
                previous_receipt_hash,
                timestamp_provenance: Some(AvcReceiptTimestampProvenance::LocalHybridLogicalClock),
                external_timestamp_proof: None,
            },
            validator_did.clone(),
            issued_at,
            |bytes| (receipt_signer)(bytes),
        )
        .map_err(map_avc_error)?;
        store_receipt_idempotent(registry, receipt.clone())?;

        let draft = LivesafePublicAdapterOutputAuthorizationDraft {
            credential,
            subject,
            audience,
            evidence_hash,
            credential_id: Some(credential_id),
            receipt_id: receipt.receipt_id,
            action_commitment_hash,
            idempotency_key_hash,
            issued_at,
            expires_at,
            signer_did: validator_did,
        };
        mint_livesafe_public_adapter_output_authorization_proof(draft, registry, |bytes| {
            (receipt_signer)(bytes)
        })
        .map_err(map_avc_error)
    })
    .await?;
    Ok(Json(envelope))
}

async fn handle_get_receipt(
    State(state): State<Arc<AvcApiState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<AvcTrustReceipt>> {
    let hash = parse_hash(&id)?;
    let receipt = with_registry_blocking(state, false, move |registry| {
        registry
            .get_receipt(&hash)
            .ok_or((StatusCode::NOT_FOUND, "receipt not found".into()))
    })
    .await?;
    Ok(Json(receipt))
}

async fn handle_list_receipts(
    State(state): State<Arc<AvcApiState>>,
    Query(query): Query<ListAvcReceiptsQuery>,
) -> ApiResult<Json<ListAvcReceiptsResponse>> {
    let actor = query.actor.ok_or((
        StatusCode::BAD_REQUEST,
        "actor query parameter is required".into(),
    ))?;
    let did = parse_did(&actor)?;
    let did_for_response = did.to_string();
    let did_for_lookup = did.clone();
    let limit = avc_receipt_list_limit(query.limit);
    let receipts = with_registry_blocking(state, false, move |registry| {
        Ok(registry.list_receipts_for_subject(&did_for_lookup, limit))
    })
    .await?;
    Ok(Json(ListAvcReceiptsResponse {
        did: did_for_response,
        receipts,
    }))
}

async fn handle_protocol_info(
    Query(query): Query<AvcProtocolQuery>,
) -> ApiResult<Json<AvcProtocolInfo>> {
    if query.protocol_version.is_none() {
        tracing::info!(
            protocol_version = AVC_PROTOCOL_VERSION,
            "served legacy AVC protocol discovery without explicit requested version"
        );
    }
    require_supported_avc_protocol_version(query.protocol_version).map_err(map_avc_error)?;
    Ok(Json(avc_protocol_info()))
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

/// Verify that `chain` is a genuine, cryptographically-valid
/// `exo-authority` DelegationRegistry chain rooted at `state.validator_did`
/// that grants `Permission::Govern` to its leaf delegate, per the D3
/// one-authority-model rule.
///
/// Three independent checks all must pass, and none is satisfied by shape
/// alone:
///
/// 1. The chain's root must be this node's own `validator_did`.
/// 2. `state.authority` — this node's own `exo-authority` DelegationRegistry
///    (the single authority species per D3) — must have an actively granted
///    chain from that root to the issuer DID being registered (`find_chain`). A
///    syntactically valid, self-signed chain the caller fabricates out of
///    band, without ever having been granted a delegation by this node,
///    is rejected here even if its signatures independently verify.
/// 3. That registered chain must cryptographically verify
///    (`exo_authority::chain::verify_chain`, real Ed25519 verification over
///    every link, resolved against the AVC registry's own trusted-key
///    resolution) and must grant `Permission::Govern` at every link
///    (`exo_authority::chain::has_permission`).
fn verify_issuer_registration_authority(
    state: &AvcApiState,
    chain: &exo_authority::AuthorityChain,
) -> ApiResult<()> {
    let Some(root) = chain.root() else {
        return Err((
            StatusCode::FORBIDDEN,
            "issuer registration authority chain is empty".into(),
        ));
    };
    if root != &state.validator_did {
        return Err((
            StatusCode::FORBIDDEN,
            "issuer registration authority chain is not rooted at this node's validator DID".into(),
        ));
    }
    let Some(leaf) = chain.leaf() else {
        return Err((
            StatusCode::FORBIDDEN,
            "issuer registration authority chain has no leaf delegate".into(),
        ));
    };

    let authority = state.authority.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "AVC authority registry unavailable while verifying issuer registration authority"
                .into(),
        )
    })?;
    let registered_chain = authority.find_chain(root, leaf).ok_or_else(|| {
        tracing::warn!(
            %root,
            %leaf,
            "rejected AVC issuer registration: no actively granted DelegationRegistry chain \
             from validator to caller"
        );
        (
            StatusCode::FORBIDDEN,
            "no actively granted DelegationRegistry chain exists from this node's validator \
             DID to the caller; a bare admin bearer token or a self-fabricated chain is not \
             sufficient authority"
                .into(),
        )
    })?;
    if &registered_chain != chain {
        return Err((
            StatusCode::FORBIDDEN,
            "presented authority chain does not match this node's actively granted \
             DelegationRegistry chain"
                .into(),
        ));
    }

    let now = trusted_local_hlc_timestamp(state).map_err(local_hlc_timestamp_error)?;
    let registry = state.registry.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "AVC registry unavailable while verifying issuer registration authority".into(),
        )
    })?;
    exo_authority::chain::verify_chain(chain, &now, |did| {
        registry
            .resolve_public_key(did)
            .or_else(|| registry.resolve_receipt_validator_public_key(did))
    })
    .map_err(|error| {
        tracing::warn!(
            %error,
            "rejected AVC issuer registration: authority chain failed verification"
        );
        (
            StatusCode::FORBIDDEN,
            "issuer registration authority chain failed verification".into(),
        )
    })?;

    if !exo_authority::chain::has_permission(chain, &Permission::Govern) {
        return Err((
            StatusCode::FORBIDDEN,
            "issuer registration authority chain does not grant Permission::Govern".into(),
        ));
    }

    Ok(())
}

/// `POST /api/v1/avc/issuers` — register or rotate an AVC issuer's DID and
/// public key on the running node, usable for issuance and validation
/// immediately, with no restart or gateway redeploy (VCG-006b / #736).
///
/// This route sits behind the same bearer-token write guard as every other
/// mutating AVC route, but the bearer token alone is deliberately
/// insufficient here: per the ratified D3 one-authority-model decision
/// (GAP-REGISTRY.md), the request must also carry a real, cryptographically
/// verified `exo-authority` DelegationRegistry chain rooted at this node's
/// validator DID and granting `Permission::Govern`. A request presenting
/// only the bare admin bearer token — with no authority chain, or an
/// invalid/under-scoped one — is rejected with `StatusCode::FORBIDDEN`
/// before any registry mutation.
async fn handle_register_issuer(
    State(state): State<Arc<AvcApiState>>,
    Json(payload): Json<RegisterIssuerRequest>,
) -> ApiResult<Json<RegisterIssuerResponse>> {
    let issuer_did = parse_did(&payload.issuer_did)?;
    let public_key = parse_expected_public_key(&payload.public_key_hex, "AVC issuer public key")
        .map_err(|error| {
            tracing::warn!(%error, "rejected AVC issuer registration: malformed public key");
            (StatusCode::BAD_REQUEST, "invalid public_key_hex".into())
        })?;

    let Some(chain) = payload.authority_chain.as_ref() else {
        return Err((
            StatusCode::FORBIDDEN,
            "issuer registration requires a real DelegationRegistry-backed authority chain \
             (D3 one-authority-model rule); the bare admin bearer token is not sufficient"
                .into(),
        ));
    };
    if chain.leaf() != Some(&issuer_did) {
        return Err((
            StatusCode::FORBIDDEN,
            "issuer registration authority chain leaf must match issuer_did".into(),
        ));
    }
    verify_issuer_registration_authority(&state, chain)?;

    if payload.granted_permissions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "issuer registration requires a non-empty granted_permissions cap".into(),
        ));
    }
    let granted_permissions: BTreeSet<Permission> =
        payload.granted_permissions.iter().copied().collect();

    let registered_at = trusted_local_hlc_timestamp(&state).map_err(local_hlc_timestamp_error)?;
    let record = exo_avc::RegisteredIssuerKey {
        public_key,
        authority_chain: chain.clone(),
        registered_at,
        granted_permissions,
    };
    let issuer_did_for_registry = issuer_did.clone();
    with_registry_blocking(state, true, move |registry| {
        registry.put_registered_issuer_key(issuer_did_for_registry, record);
        Ok(())
    })
    .await?;

    Ok(Json(RegisterIssuerResponse {
        issuer_did: issuer_did.to_string(),
        status: "registered".into(),
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

async fn handle_get_issuer_registration_authority_chain(
    State(state): State<Arc<AvcApiState>>,
    Query(query): Query<IssuerRegistrationAuthorityQuery>,
) -> ApiResult<Json<exo_authority::AuthorityChain>> {
    let operator_did_raw = query.operator_did.ok_or((
        StatusCode::BAD_REQUEST,
        "operator_did query parameter is required".into(),
    ))?;
    let operator_did = parse_did(&operator_did_raw)?;
    let chain = state
        .find_delegated_issuer_registration_chain(&operator_did)
        .ok_or((
            StatusCode::NOT_FOUND,
            "no active issuer-registration authority grant for that operator_did".into(),
        ))?;
    Ok(Json(chain))
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
        .route(
            "/api/v1/avc/llm-usage/receipts/emit",
            post(handle_llm_usage_emit_receipt),
        )
        .route(
            "/api/v1/avc/livesafe/public-adapter-output-authorization",
            post(handle_public_output_authorization),
        )
        .route("/api/v1/avc/receipts", get(handle_list_receipts))
        .route("/api/v1/avc/receipts/:hash", get(handle_get_receipt))
        .route("/api/v1/avc/protocol", get(handle_protocol_info))
        .route("/api/v1/avc/delegate", post(handle_delegate))
        .route("/api/v1/avc/revoke", post(handle_revoke))
        .route("/api/v1/avc/issuers", post(handle_register_issuer))
        .route(
            "/api/v1/avc/issuer-registration-authority",
            get(handle_get_issuer_registration_authority_chain),
        )
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
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        body::{self, Body},
        http::{Method, Request},
        response::IntoResponse,
    };
    use exo_authority::permission::Permission;
    use exo_avc::{
        AVC_LLM_USAGE_EVIDENCE_DOMAIN, AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel,
        AvcActionDescriptor, AvcActionRequest, AvcConstraints, AvcDecision, AvcDraft,
        AvcReasonCode, AvcReceiptEvidenceSubject, AvcReceiptExternalTimestampProofKind,
        AvcRevocationReason, AvcSubjectKind, DataClass, DelegatedIntent, EncryptedPayloadRef,
        LlmUsageCustodyMode, LlmUsageEvidence, LlmUsageEvidenceEnvelope, ProviderUsageMetrics,
        avc_action_descriptor_hash, avc_llm_usage_action_request, create_trust_receipt, issue_avc,
        llm_usage_evidence_hash, llm_usage_evidence_signature_payload, revoke_avc,
    };
    use exo_core::{Hash256, Signature, Timestamp, crypto, crypto::KeyPair};
    use tower::ServiceExt;

    use super::*;

    const ISSUER_SEED: [u8; 32] = [0x11; 32];
    const SUBJECT_SEED: [u8; 32] = [0x22; 32];
    const VALIDATOR_SEED: [u8; 32] = [0x33; 32];
    const TIMESTAMP_AUTHORITY_SEED: [u8; 32] = [0x44; 32];
    const LYNK_ADAPTER_SEED: [u8; 32] = [0x66; 32];
    const LYNK_RECEIPT_URI: &str = "/api/v1/avc/llm-usage/receipts/emit";
    const MICROSOFT_PUBLIC_RSA_TSA_DID: &str = "did:exo:microsoft-public-rsa-tsa";
    const MICROSOFT_FIXTURE_SIGNER_SPKI_HEX: &str = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100b4a59f9bfba5d36eff77c4656fc327fe0d1052fbcba98d95b32ded23c536b454aca53668999383dc11d3f0b911f91ae130981bd558c0285372b1a2bd70b49789f3c648806b3c282cf4fe32db896b2449ab57a439cf8066a8c8483eb66112f6675a9092e073bb8d849e8bf9f1982effd44afe9792e0dcf992c5bf1dd8855c011c52c350789b107a5c8d2791e97dc1ad5d61bdb07c6a687eb6859b164ec53f5e361b782c7d1105256e79b6ba64da634bfd20b5f9bbaa2222c8fea9e8f4734d36cc9d5aac1e757f77fad6d331f1f90f90359e7052a2a64d9241f6153ce77fb6a57e6b0df2b7dae358f7f5813809b36ea82911d4246e231abd43325034a19b2708be01dd4274b6d3bb138fc33e9092f7b4e75a84fb8fa8cc2c6820a075fc30431d0ef5329eec54af6c0118b3502795d0a5fca1c6642395bd436a8f22f5d092ded3ff860fdff29ea5c6585a573a36ae9ef67f70a44e8633783397bac71d1bda68aa70f8a2e3f8a2d9985e29a9652444fb08a96915286cdf0ca0e85fdfa2343142f3e76d60f8372c7a9618d68f09a82dcc7ac351520ad6af2c2972df704b452953538a8a53169af1ded837b12aa67f573b4498d2e98ebca157ad61fbaf197ef626a2722b5d9d34e4b009d18ef7a474a4f7960ee544c7e67d953cbd73623745182734fd123aa3466d2e37f874a17c4f84d7cf62a7856f23d7186c73698533eb3c77a9370203010001";
    const MICROSOFT_LIVE_SIGNER_SPKI_HEX_20260627: &str = "30820222300d06092a864886f70d01010105000382020f003082020a02820201009d7834a47690ecf5409659fe1d966b24570ba0a6de9215b5c8bf9034152014552c8d920a6aaa8de28209b09337a6cd2b24d48eee7742351b990d7d9682eaf7024efb797ae5a015ea6663ba6555de0cd4422e5756e00d3f35f8f327b5d791d1218ebf358215c4a51ef30bec1b68d37eb0f4b1ccb01905e89b0c53fb5f0b39c17d19b48b0dd5adbe5eae5bbd6a77911332b70b244e3ba746078b64bfed069db7ec955d44f14043d8d844aa42a94068fefd718c12d1095dcf6a52a39c67dbdcc37853b8d5caa89f1474a17275b9084451a019946bab32803cc54abf1ede0f774cf34b1548af504d0698b7db5f971e0f51add45719eb1fc92d5013ce4e7e0561db331c092159153d3a9248c8d0e8a4ca75c9eade91f4738005269fe096f729ab453d7f36488c9186bdda62b2195197bed142d5214a3c47bc29f72c2ff1a904303874900ec1a1e8d5f60f445fb12c84b53001c8069efb6c351c1c930d372695334b12e40b7828f580d05d2168f458e6320ed8e343ff224d663a7b2d6f6fda87963223e478089dd4f93fd318936560d9eee129464d04d6c0fe1b2006cba867e217f3d5af8c437d69b17dd52e0e255ba29e62ac2cefcc2db9e5ee292e0f474dea803461ec320d09dcb35dac33d1ceb6eef6400fd366579fbd6f2bf71b4c5c06284257068ec93c5b851cedc7ea56a6c83e376873c6710732dc5dc5723f8a797322f0be430203010001";
    const MICROSOFT_FIXTURE_CA_SPKI_HEX: &str = "30820222300d06092a864886f70d01010105000382020f003082020a02820201009e7ce75263fde0c59f057d63b50622a31c1ed7e79733d11305bd6546477791c15d706f7fb2ab43970c4aa1521c6aa0dbfa89858a8e431c2e1105c6f24078d70b0324fe5dd3398b60a018f19c6fde5624b8b0ec7ccb8812abc660e3d44401fe61b9784891044a7b7431b3c4a0a74d8a1c0ce711afd2b1a87c9d6a39849335c739e446c14fbbaadf0c7799786d566b5c084af964a4e428a1350b166f34f59d1962543c2e9ee2e45f58722165c802b09faca337f911e1f92ab9459f1a6328a4dabf07c53fa5da199196506f1365a893a20468025a9c7af6e2aa2a14cf562de0544ae773faa2f9d47c036322033d243749e1ed2a883466e6c39388442d04b19df5585dd4c69dc6819c1eb442b12e6b3bdca1bf67e3247ae6950d042179a9e0384306278a50647e799e02344ddcb56e2ebd20d055e4a9f61d5268f57c51611fc93c601a33ac46979ec48bde47530f4d57fb82df2163ae1734f3ba8b2506b0482df1cd8fc45f3b13e08eec0dbc4e98cdab978b8a2ba784a6ead176e390da14e4986d614ae59806e9c518dbf6d4ab78376d002a66deb929c69ec04277672344a1bbf7e4d7fac4de85ac0ea317de38efe347bc28de58b09067733c9607827279e14c5b72417dd7802a1ce88457bc539c3d5aebdc3f513c708c4ba0a483cc20813aed2159d8f328dbbc6394b007596de5d421001632cd1dddc443bf4f52bf055177ad5ebd0203010001";
    const MICROSOFT_FIXTURE_TSA_SUBJECT: &str = "C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, OU=Microsoft America Operations, OU=nShield TSS ESN:A500-05E0-D947, CN=Microsoft Public RSA Time Stamping Authority";

    #[derive(Clone, Copy)]
    enum TestTimestampAuthorityMode {
        Valid,
        NonSuccess,
        InvalidJson,
        WrongSubject,
        WrongAuthority,
        BadSignature,
    }

    fn issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ISSUER_SEED).expect("valid seed")
    }

    fn subject_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(SUBJECT_SEED).expect("valid seed")
    }

    fn validator_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(VALIDATOR_SEED).expect("valid seed")
    }

    fn timestamp_authority_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(TIMESTAMP_AUTHORITY_SEED).expect("valid seed")
    }

    fn lynk_adapter_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(LYNK_ADAPTER_SEED).expect("valid seed")
    }

    fn validator_did() -> Did {
        Did::new("did:exo:validator").unwrap()
    }

    fn timestamp_authority_did() -> Did {
        Did::new("did:exo:timestamp-authority").unwrap()
    }

    fn seed_avc_trust_keys(state: &AvcApiState) {
        let kp = issuer_keypair();
        let did = Did::new("did:exo:issuer").unwrap();
        let mut registry = state.registry.lock().unwrap();
        registry.put_public_key(did, kp.public);
        registry.put_public_key(Did::new("did:exo:agent").unwrap(), subject_keypair().public);
        registry.put_receipt_validator_public_key(validator_did(), validator_keypair().public);
    }

    fn fixed_external_timestamp_source(timestamp: Timestamp) -> AvcReceiptExternalTimestampSource {
        let signer: AvcReceiptSigner =
            Arc::new(|payload: &[u8]| timestamp_authority_keypair().sign(payload));
        AvcReceiptExternalTimestampSource::Fixed {
            authority_did: timestamp_authority_did(),
            authority_public_key: timestamp_authority_keypair().public,
            issued_at: timestamp,
            signer,
        }
    }

    fn http_external_timestamp_source(endpoint: String) -> AvcReceiptExternalTimestampSource {
        AvcReceiptExternalTimestampSource::HttpJson {
            endpoint: Arc::new(endpoint),
            authority_did: timestamp_authority_did(),
            authority_public_key: timestamp_authority_keypair().public,
            client: reqwest::Client::new(),
        }
    }

    fn rfc3161_external_timestamp_source(endpoint: String) -> AvcReceiptExternalTimestampSource {
        AvcReceiptExternalTimestampSource::Rfc3161 {
            endpoint: Arc::new(endpoint),
            authority_did: Did::new(MICROSOFT_PUBLIC_RSA_TSA_DID).unwrap(),
            authority_public_key_spki_der_hexes: Arc::new(vec![
                MICROSOFT_FIXTURE_SIGNER_SPKI_HEX.to_owned(),
            ]),
            issuing_ca_spki_der_hexes: Arc::new(Vec::new()),
            policy_oid: Arc::new(
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID.to_owned(),
            ),
            client: reqwest::Client::new(),
        }
    }

    fn fixed_rfc3161_external_timestamp_source() -> AvcReceiptExternalTimestampSource {
        AvcReceiptExternalTimestampSource::FixedRfc3161 {
            authority_did: Did::new(MICROSOFT_PUBLIC_RSA_TSA_DID).unwrap(),
            issued_at: Timestamp::new(1_782_571_620_539, 0),
            token_der_base64: crate::avc_rfc3161::microsoft_fixture_timestamp_token_der_base64()
                .unwrap(),
            policy_oid: crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID.to_owned(),
            serial_number_hex: "6a1c57054080".to_owned(),
            nonce_hex: "a173ce171bc853e8".to_owned(),
            tsa_subject: MICROSOFT_FIXTURE_TSA_SUBJECT.to_owned(),
            tsa_public_key_spki_der_hex: MICROSOFT_FIXTURE_SIGNER_SPKI_HEX.to_owned(),
        }
    }

    fn fresh_state() -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::new_with_external_timestamp_source(
            validator_did(),
            signer,
            fixed_external_timestamp_source(Timestamp::new(1_600_000, 0)),
        );
        // Seed the issuer key so validate paths succeed.
        seed_avc_trust_keys(&state);
        Arc::new(state)
    }

    fn fresh_state_with_finality_store(
        finality_store: Arc<Mutex<crate::store::SqliteDagStore>>,
    ) -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::new_with_external_timestamp_source_and_finality_store(
            validator_did(),
            signer,
            fixed_external_timestamp_source(Timestamp::new(1_600_000, 0)),
            Some(finality_store),
        );
        seed_avc_trust_keys(&state);
        Arc::new(state)
    }

    async fn fresh_durable_state(data_dir: &FsPath) -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let mut state = AvcApiState::with_durable_registry(
            data_dir,
            validator_did(),
            signer,
            None,
            None,
            false,
        )
        .await
        .expect("durable AVC state");
        state.external_timestamp_source =
            fixed_external_timestamp_source(Timestamp::new(1_600_000, 0));
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

    fn lynk_credential() -> AutonomousVolitionCredential {
        lynk_credential_for_subject(Did::new("did:exo:agent").unwrap())
    }

    fn lynk_credential_for_subject(subject_did: Did) -> AutonomousVolitionCredential {
        let mut draft = baseline_draft();
        draft.subject_did = subject_did;
        draft.delegated_intent.purpose = "EXOCHAIN LYNK Protocol usage receipts".into();
        draft.delegated_intent.allowed_objectives = vec![exo_avc::AVC_LLM_USAGE_ACTION_NAME.into()];
        draft.authority_scope.permissions = vec![Permission::Execute];
        draft.authority_scope.tools = vec![AVC_LLM_USAGE_EVIDENCE_DOMAIN.into()];
        draft.authority_scope.data_classes = vec![
            DataClass::Internal,
            DataClass::Confidential,
            DataClass::Restricted,
        ];
        let kp = issuer_keypair();
        issue_avc(draft, |bytes| kp.sign(bytes)).unwrap()
    }

    fn test_hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn lynk_encrypted_payload_ref() -> EncryptedPayloadRef {
        EncryptedPayloadRef {
            ref_id_hash: test_hash(0xA0),
            ciphertext_hash: test_hash(0xA1),
            storage_policy_hash: test_hash(0xA2),
            key_policy_hash: test_hash(0xA3),
            payload_kind: "provider_exchange".into(),
            byte_length: 512,
        }
    }

    fn lynk_usage_evidence(custody_mode: LlmUsageCustodyMode) -> LlmUsageEvidence {
        lynk_usage_evidence_for_actor(Did::new("did:exo:agent").unwrap(), custody_mode)
    }

    fn lynk_usage_evidence_for_actor(
        actor_did: Did,
        custody_mode: LlmUsageCustodyMode,
    ) -> LlmUsageEvidence {
        let encrypted_payload_refs = match custody_mode {
            LlmUsageCustodyMode::ExternalPayloadRef => vec![lynk_encrypted_payload_ref()],
            LlmUsageCustodyMode::ReceiptMinimized | LlmUsageCustodyMode::DagDbCustody => Vec::new(),
        };
        LlmUsageEvidence {
            schema_version: AVC_SCHEMA_VERSION,
            tenant_id: "tenant-alpha".into(),
            namespace: "default".into(),
            actor_did,
            provider: "openai".into(),
            provider_endpoint: "responses".into(),
            model_id: "gpt-4.1-mini".into(),
            provider_request_id_hash: Some(test_hash(0x80)),
            session_id_hash: Some(test_hash(0x81)),
            idempotency_key_hash: test_hash(0x82),
            action_id: test_hash(0x83),
            prompt_hash: test_hash(0x84),
            completion_hash: Some(test_hash(0x85)),
            tool_call_hash: None,
            tool_result_hash: None,
            usage: ProviderUsageMetrics {
                input_tokens: 321,
                output_tokens: 89,
                total_tokens: 410,
                cached_input_tokens: Some(21),
                reasoning_tokens: Some(13),
                cost_minor_units: Some(7),
                cost_currency: Some("USD".into()),
                usage_complete: true,
            },
            custody_mode,
            encrypted_payload_refs,
            custody_policy_hash: test_hash(0x86),
            created_at: Timestamp::new(1_500_100, 0),
        }
    }

    fn lynk_envelope(evidence: LlmUsageEvidence) -> LlmUsageEvidenceEnvelope {
        let adapter_did =
            crate::identity::did_from_public_key(lynk_adapter_keypair().public_key()).unwrap();
        LlmUsageEvidenceEnvelope {
            schema_version: AVC_SCHEMA_VERSION,
            adapter_did,
            issued_at: Timestamp::new(1_500_200, 0),
            evidence,
        }
    }

    fn sign_lynk_envelope(envelope: &LlmUsageEvidenceEnvelope, keypair: &KeyPair) -> Signature {
        let payload = llm_usage_evidence_signature_payload(envelope).unwrap();
        keypair.sign(&payload)
    }

    fn lynk_emit_request_for_evidence(
        credential: AutonomousVolitionCredential,
        evidence: LlmUsageEvidence,
    ) -> LlmUsageReceiptEmitRequest {
        let envelope = lynk_envelope(evidence);
        let action = avc_llm_usage_action_request(&envelope.evidence).unwrap();
        let validation = AvcValidationRequest {
            credential,
            action: Some(action),
            now: Timestamp::new(1_500_000, 0),
        };
        LlmUsageReceiptEmitRequest {
            validation: validation.clone(),
            subject_signature: sign_action(&validation, &subject_keypair()),
            subject_public_key: None,
            adapter_signature: sign_lynk_envelope(&envelope, &lynk_adapter_keypair()),
            adapter_public_key: Some(lynk_adapter_keypair().public),
            llm_usage_evidence: envelope,
        }
    }

    async fn post_lynk_emit_request(
        app: Router,
        request: &LlmUsageReceiptEmitRequest,
    ) -> axum::response::Response {
        let body = serde_json::to_vec(request).unwrap();
        app.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LYNK_RECEIPT_URI)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn post_lynk_emit_json(app: Router, body: serde_json::Value) -> axum::response::Response {
        app.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LYNK_RECEIPT_URI)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
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

    async fn serve_test_timestamp_authority(
        mode: TestTimestampAuthorityMode,
    ) -> (String, tokio::task::JoinHandle<()>) {
        #[derive(Deserialize)]
        struct CapturedExternalTimestampRequest {
            schema_version: u16,
            domain: String,
            subject_hash: String,
        }

        async fn issue_timestamp(
            State(mode): State<TestTimestampAuthorityMode>,
            axum::Json(request): axum::Json<CapturedExternalTimestampRequest>,
        ) -> axum::response::Response {
            assert_eq!(request.schema_version, AVC_SCHEMA_VERSION);
            assert_eq!(request.domain, exo_avc::AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN);
            if matches!(mode, TestTimestampAuthorityMode::NonSuccess) {
                return (StatusCode::BAD_GATEWAY, "timestamp authority unavailable")
                    .into_response();
            }
            if matches!(mode, TestTimestampAuthorityMode::InvalidJson) {
                return (StatusCode::OK, "not-json").into_response();
            }
            let subject_hash =
                parse_hash_anyhow(&request.subject_hash, "test timestamp subject hash").unwrap();
            let signed_subject_hash = match mode {
                TestTimestampAuthorityMode::WrongSubject => Hash256::from_bytes([0xAB; 32]),
                _ => subject_hash,
            };
            let authority_did = match mode {
                TestTimestampAuthorityMode::WrongAuthority => {
                    Did::new("did:exo:wrong-timestamp-authority").unwrap()
                }
                _ => timestamp_authority_did(),
            };
            let issued_at = Timestamp::new(1_700_000, 7);
            let mut proof = AvcReceiptExternalTimestampProof::signed(
                authority_did,
                signed_subject_hash,
                issued_at,
                |bytes| timestamp_authority_keypair().sign(bytes),
            )
            .unwrap();
            if matches!(mode, TestTimestampAuthorityMode::BadSignature) {
                proof.signature = Signature::empty();
            }

            axum::Json(serde_json::json!({
                "authority_did": proof.authority_did.to_string(),
                "subject_hash": proof.subject_hash.to_string(),
                "issued_at_physical_ms": proof.issued_at.physical_ms,
                "issued_at_logical": proof.issued_at.logical,
                "signature_hex": proof.signature.to_string(),
            }))
            .into_response()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(issue_timestamp))
            .with_state(mode);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), handle)
    }

    async fn serve_test_rfc3161_timestamp_authority(
        status: StatusCode,
        response_der: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        async fn issue_timestamp(
            State((status, response_der)): State<(StatusCode, Vec<u8>)>,
            headers: axum::http::HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            assert_eq!(
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok()),
                Some("application/timestamp-query")
            );
            assert!(!body.is_empty(), "RFC 3161 request body must be DER");
            (
                status,
                [("content-type", "application/timestamp-reply")],
                response_der,
            )
                .into_response()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", post(issue_timestamp))
            .with_state((status, response_der));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), handle)
    }

    async fn serve_test_rfc3161_timestamp_authority_sequence(
        responses: Vec<(StatusCode, Vec<u8>)>,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        async fn issue_timestamp(
            State((responses, attempts)): State<(
                Arc<Mutex<VecDeque<(StatusCode, Vec<u8>)>>>,
                Arc<AtomicUsize>,
            )>,
            headers: axum::http::HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            assert_eq!(
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok()),
                Some("application/timestamp-query")
            );
            assert!(!body.is_empty(), "RFC 3161 request body must be DER");
            attempts.fetch_add(1, Ordering::SeqCst);
            let (status, response_der) = responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, Vec::new()));
            (
                status,
                [("content-type", "application/timestamp-reply")],
                response_der,
            )
                .into_response()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/", post(issue_timestamp))
            .with_state((responses, Arc::clone(&attempts)));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), attempts, handle)
    }

    async fn emit_baseline_receipt_with_source(
        external_timestamp_source: AvcReceiptExternalTimestampSource,
    ) -> (StatusCode, Arc<AvcApiState>, Vec<u8>) {
        emit_baseline_receipt_with_source_and_strict(external_timestamp_source, false).await
    }

    async fn emit_baseline_receipt_with_source_and_strict(
        external_timestamp_source: AvcReceiptExternalTimestampSource,
        require_external_timestamp: bool,
    ) -> (StatusCode, Arc<AvcApiState>, Vec<u8>) {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let mut state = AvcApiState::new_with_external_timestamp_source(
            validator_did(),
            signer,
            external_timestamp_source,
        );
        state.require_external_timestamp = require_external_timestamp;
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
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

        let response = avc_router(Arc::clone(&state))
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
        let status = response.status();
        let response_body = read_body(response).await;
        (status, state, response_body)
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

        let directory_error = load_file_durable_registry(dir.path())
            .unwrap_err()
            .to_string();
        assert!(directory_error.contains("failed to read AVC durable registry"));

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
            .clone()
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

        let error = match AvcApiState::with_durable_registry(
            dir.path(),
            validator_did(),
            signer,
            None,
            None,
            false,
        )
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
            None,
            false,
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
            external_timestamp_source: AvcReceiptExternalTimestampSource::Unconfigured,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: false,
            finality_store: None,
            durability: AvcRegistryDurability::Postgres(pool.clone()),
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
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
        let mut state = AvcApiState::with_durable_registry(
            dir.path(),
            validator_did(),
            Arc::clone(&signer),
            Some(pool.clone()),
            None,
            false,
        )
        .await
        .expect("Postgres AVC state");
        let trusted_now = Timestamp::new(1_600_000, 0);
        state.external_timestamp_source = fixed_external_timestamp_source(trusted_now);
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
        let app = avc_router(Arc::clone(&state));

        let mut first_draft = baseline_draft();
        first_draft.delegated_intent.purpose = "postgres anchor persistence one".into();
        first_draft.expires_at = Some(Timestamp::new(trusted_now.physical_ms + 1_000_000, 0));
        let first = {
            let kp = issuer_keypair();
            issue_avc(first_draft, |bytes| kp.sign(bytes)).unwrap()
        };
        let mut second_draft = baseline_draft();
        second_draft.delegated_intent.purpose = "postgres anchor persistence two".into();
        second_draft.expires_at = Some(Timestamp::new(trusted_now.physical_ms + 1_000_000, 0));
        let second = {
            let kp = issuer_keypair();
            issue_avc(second_draft, |bytes| kp.sign(bytes)).unwrap()
        };
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
            .clone()
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
            None,
            false,
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
        let action_commitment_hash = avc_action_commitment_hash(
            &request.credential,
            request.action.as_ref().unwrap(),
            &request.now,
        )
        .unwrap();
        let subject_signature = sign_action(&request, &subject_keypair());
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let response = app
            .clone()
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
        assert_eq!(
            parsed.receipt.action_commitment_hash,
            Some(action_commitment_hash)
        );
        assert_eq!(parsed.receipt.previous_receipt_hash, None);
        assert_eq!(
            parsed.receipt.timestamp_provenance,
            Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority)
        );
        let action_descriptor =
            AvcActionDescriptor::from_action(request.action.as_ref().expect("receipt action"));
        let action_descriptor_hash = avc_action_descriptor_hash(&action_descriptor).unwrap();
        assert_eq!(parsed.receipt.action_descriptor, Some(action_descriptor));
        assert_eq!(
            parsed.receipt.action_descriptor_hash,
            Some(action_descriptor_hash)
        );
        let evidence_subject = AvcReceiptEvidenceSubject {
            credential_id,
            action_id,
            action_commitment_hash,
            action_descriptor_hash,
            previous_receipt_hash: None,
        };
        let evidence_subject_hash = evidence_subject.hash().unwrap();
        let external_timestamp_proof = parsed
            .receipt
            .external_timestamp_proof
            .as_ref()
            .expect("receipt must carry external timestamp proof");
        assert_eq!(
            external_timestamp_proof.authority_did,
            timestamp_authority_did()
        );
        assert_eq!(external_timestamp_proof.subject_hash, evidence_subject_hash);
        assert!(
            external_timestamp_proof
                .verify_signature(timestamp_authority_keypair().public_key())
                .unwrap()
        );
        assert_eq!(
            parsed.receipt.created_at,
            external_timestamp_proof.issued_at
        );
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
    async fn avc_llm_usage_receipts_emit_accepts_valid_openai_style_evidence() {
        let state = fresh_state();
        let credential = lynk_credential();
        let credential_id = credential.id().unwrap();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        let expected_evidence_hash =
            llm_usage_evidence_hash(&request.llm_usage_evidence.evidence).unwrap();

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let response_body = read_body(response).await;
        let response_text = String::from_utf8(response_body.clone()).unwrap();
        assert!(!response_text.contains("secret-prompt"));
        assert!(!response_text.contains("secret-output"));
        assert!(!response_text.contains("provider_api_key"));
        assert!(!response_text.contains("bearer"));
        assert!(!response_text.contains("raw_prompt"));
        assert!(!response_text.contains("raw_output"));
        assert!(!response_text.contains("response_text"));
        assert!(!response_text.contains("kms_key"));
        assert!(!response_text.contains("https://customer.example"));
        let parsed: EmitReceiptResponse = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(parsed.validation.decision, AvcDecision::Allow);
        assert_eq!(parsed.receipt.credential_id, credential_id);
        assert_eq!(
            parsed.receipt.llm_usage_evidence_hash,
            Some(expected_evidence_hash)
        );
        let action_descriptor = parsed
            .receipt
            .action_descriptor
            .as_ref()
            .expect("LYNK receipt must carry action descriptor");
        assert_eq!(action_descriptor.requested_permission, Permission::Execute);
        assert_eq!(
            action_descriptor.tool.as_deref(),
            Some(AVC_LLM_USAGE_EVIDENCE_DOMAIN)
        );
        assert_eq!(action_descriptor.data_class, Some(DataClass::Internal));
        assert_eq!(
            action_descriptor.action_name.as_deref(),
            Some(exo_avc::AVC_LLM_USAGE_ACTION_NAME)
        );
        assert_eq!(
            parsed.receipt.timestamp_provenance,
            Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority)
        );
        assert!(parsed.receipt.verify_id().unwrap());
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_uses_registry_adapter_key() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        {
            let mut registry = state.registry.lock().unwrap();
            registry.put_public_key(
                request.llm_usage_evidence.adapter_did.clone(),
                lynk_adapter_keypair().public,
            );
        }
        request.adapter_public_key = None;

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_uses_supplied_subject_key() {
        let state = fresh_state();
        let subject = crate::identity::did_from_public_key(subject_keypair().public_key()).unwrap();
        let credential = lynk_credential_for_subject(subject.clone());
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence_for_actor(subject, LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.subject_public_key = Some(*subject_keypair().public_key());

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_validation_action_mismatch() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request
            .validation
            .action
            .as_mut()
            .unwrap()
            .requested_permission = Permission::Read;

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_missing_avc_credential() {
        let state = fresh_state();
        let request = lynk_emit_request_for_evidence(
            lynk_credential(),
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_revoked_avc_credential() {
        let state = fresh_state();
        let credential = lynk_credential();
        let credential_id = credential.id().unwrap();
        {
            let kp = issuer_keypair();
            let mut registry = state.registry.lock().unwrap();
            registry.put_credential(credential.clone()).unwrap();
            let revocation = revoke_avc(
                credential_id,
                Did::new("did:exo:issuer").unwrap(),
                AvcRevocationReason::IssuerRevoked,
                Timestamp::new(1_100_000, 0),
                |bytes| kp.sign(bytes),
            )
            .unwrap();
            registry.put_revocation(revocation).unwrap();
        }
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_empty_adapter_evidence_signature() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.adapter_signature = Signature::empty();

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_bad_adapter_evidence_signature() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.adapter_signature = Signature::from_bytes([0x8A; 64]);

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_unresolved_adapter_public_key() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.adapter_public_key = None;

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_mismatched_adapter_public_key() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.adapter_public_key = Some(subject_keypair().public);

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_bad_subject_signature() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.subject_signature = Signature::from_bytes([0x8B; 64]);

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_unresolved_subject_public_key() {
        let state = fresh_state();
        let subject = crate::identity::did_from_public_key(subject_keypair().public_key()).unwrap();
        let credential = lynk_credential_for_subject(subject.clone());
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence_for_actor(subject, LlmUsageCustodyMode::ReceiptMinimized),
        );

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_mismatched_supplied_subject_key() {
        let state = fresh_state();
        let subject = Did::new("did:exo:detached-agent").unwrap();
        let credential = lynk_credential_for_subject(subject.clone());
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence_for_actor(subject, LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.subject_public_key = Some(*subject_keypair().public_key());

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_missing_idempotency_hash() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.llm_usage_evidence.evidence.idempotency_key_hash = Hash256::ZERO;

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_raw_payload_json_keys() {
        for forbidden_key in [
            "prompt",
            "messages",
            "completion",
            "response_text",
            "raw_output",
            "raw_prompt",
            "provider_api_key",
            "bearer_token",
            "kms_key",
            "object_uri",
        ] {
            let state = fresh_state();
            let credential = lynk_credential();
            state
                .registry
                .lock()
                .unwrap()
                .put_credential(credential.clone())
                .unwrap();
            let request = lynk_emit_request_for_evidence(
                credential,
                lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
            );
            let mut body = serde_json::to_value(&request).unwrap();
            body["llm_usage_evidence"]["evidence"][forbidden_key] =
                serde_json::Value::String("secret-prompt".into());

            let response = post_lynk_emit_json(avc_router(Arc::clone(&state)), body).await;

            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "forbidden LYNK evidence key `{forbidden_key}` must be rejected before receipt storage"
            );
            assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        }
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_external_payload_ref_without_refs() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut evidence = lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized);
        evidence.custody_mode = LlmUsageCustodyMode::ExternalPayloadRef;
        evidence.encrypted_payload_refs = Vec::new();
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        let mut body = serde_json::to_value(&request).unwrap();
        body["llm_usage_evidence"]["evidence"] = serde_json::to_value(evidence).unwrap();

        let response = post_lynk_emit_json(avc_router(Arc::clone(&state)), body).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_dagdb_custody_without_policy_hash() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut evidence = lynk_usage_evidence(LlmUsageCustodyMode::DagDbCustody);
        evidence.custody_policy_hash = Hash256::ZERO;
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        let mut body = serde_json::to_value(&request).unwrap();
        body["llm_usage_evidence"]["evidence"] = serde_json::to_value(evidence).unwrap();

        let response = post_lynk_emit_json(avc_router(Arc::clone(&state)), body).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_duplicate_idempotency_with_different_evidence_hash()
     {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let first_request = lynk_emit_request_for_evidence(
            credential.clone(),
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        let mut changed_evidence = lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized);
        changed_evidence.model_id = "gpt-4.1".into();
        let second_request = lynk_emit_request_for_evidence(credential, changed_evidence);
        assert_eq!(
            first_request.validation.action, second_request.validation.action,
            "model metadata must change evidence hash without changing the action commitment"
        );

        let app = avc_router(Arc::clone(&state));
        let first_response = post_lynk_emit_request(app.clone(), &first_request).await;
        let second_response = post_lynk_emit_request(app, &second_request).await;

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(second_response.status(), StatusCode::CONFLICT);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn avc_llm_usage_receipts_emit_rejects_chain_advance_during_timestamp_attestation() {
        async fn timestamp_and_advance_chain(
            State((state, credential_id)): State<(Arc<AvcApiState>, Hash256)>,
            axum::Json(request): axum::Json<serde_json::Value>,
        ) -> axum::response::Response {
            let subject_hash = request
                .get("subject_hash")
                .and_then(serde_json::Value::as_str)
                .and_then(|raw| parse_hash_anyhow(raw, "test LYNK timestamp subject hash").ok())
                .unwrap();
            {
                let mut registry = state.registry.lock().unwrap();
                let validation = AvcValidationResult {
                    credential_id,
                    decision: AvcDecision::Allow,
                    reason_codes: Vec::new(),
                    normalized_holder_did: Did::new("did:exo:agent").unwrap(),
                    valid_until: Some(Timestamp::new(2_000_000, 0)),
                    receipt: None,
                };
                let advancing_receipt = create_trust_receipt_with_evidence(
                    &validation,
                    None,
                    AvcTrustReceiptEvidence {
                        action_commitment_hash: None,
                        action_descriptor: None,
                        llm_usage_evidence_hash: None,
                        previous_receipt_hash: None,
                        timestamp_provenance: Some(
                            AvcReceiptTimestampProvenance::FixedTestTimestamp,
                        ),
                        external_timestamp_proof: None,
                    },
                    validator_did(),
                    Timestamp::new(1_599_999, 0),
                    |bytes| validator_keypair().sign(bytes),
                )
                .unwrap();
                registry.put_receipt(advancing_receipt).unwrap();
            }
            let issued_at = Timestamp::new(1_700_000, 0);
            let proof = AvcReceiptExternalTimestampProof::signed(
                timestamp_authority_did(),
                subject_hash,
                issued_at,
                |bytes| timestamp_authority_keypair().sign(bytes),
            )
            .unwrap();

            axum::Json(serde_json::json!({
                "authority_did": proof.authority_did.to_string(),
                "subject_hash": proof.subject_hash.to_string(),
                "issued_at_physical_ms": proof.issued_at.physical_ms,
                "issued_at_logical": proof.issued_at.logical,
                "signature_hex": proof.signature.to_string(),
            }))
            .into_response()
        }

        let mut state_inner = AvcApiState::new_with_external_timestamp_source(
            validator_did(),
            Arc::new(|payload: &[u8]| validator_keypair().sign(payload)),
            fixed_external_timestamp_source(Timestamp::new(1_600_000, 0)),
        );
        seed_avc_trust_keys(&state_inner);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        state_inner.external_timestamp_source =
            http_external_timestamp_source(format!("http://{address}"));
        let state = Arc::new(state_inner);
        let credential = lynk_credential();
        let credential_id = credential.id().unwrap();
        let timestamp_server = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                let app = Router::new()
                    .route("/", post(timestamp_and_advance_chain))
                    .with_state((state, credential_id));
                axum::serve(listener, app).await.unwrap();
            }
        });
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );

        let response = post_lynk_emit_request(avc_router(Arc::clone(&state)), &request).await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
        timestamp_server.abort();
    }

    #[tokio::test]
    async fn receipt_emit_commits_exochain_finality_node_and_trust_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let finality_store = Arc::new(Mutex::new(
            crate::store::SqliteDagStore::open(dir.path()).unwrap(),
        ));
        let state = fresh_state_with_finality_store(Arc::clone(&finality_store));
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
        let response = app
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

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: EmitReceiptResponse =
            serde_json::from_slice(&read_body(response).await).unwrap();
        let finality_hash = parse_hash_anyhow(
            parsed
                .exochain_finality_hash
                .as_deref()
                .expect("configured AVC receipt emission must return EXOCHAIN finality hash"),
            "AVC EXOCHAIN finality hash",
        )
        .unwrap();
        let finality_height = parsed
            .exochain_finality_height
            .expect("configured AVC receipt emission must return EXOCHAIN finality height");
        let finality_receipt_hash = parse_hash_anyhow(
            parsed.exochain_finality_receipt_hash.as_deref().expect(
                "configured AVC receipt emission must return EXOCHAIN finality receipt hash",
            ),
            "AVC EXOCHAIN finality receipt hash",
        )
        .unwrap();

        {
            let store = finality_store.lock().unwrap();
            assert!(
                store.contains_sync(&finality_hash).unwrap(),
                "EXOCHAIN finality DAG node must be durably stored"
            );
            assert_eq!(store.committed_height_sync().unwrap(), finality_height);
            let finality_receipt = store
                .load_receipt(&finality_receipt_hash)
                .unwrap()
                .expect("EXOCHAIN finality trust receipt must be durably stored");
            assert_eq!(finality_receipt.actor_did, validator_did());
            assert_eq!(
                finality_receipt.action_type,
                "avc.receipt.exochain_finality"
            );
            assert_eq!(finality_receipt.action_hash, finality_hash);
            assert!(finality_receipt.verify_hash().unwrap());
            assert!(crypto::verify(
                &finality_receipt.signing_payload().unwrap(),
                &finality_receipt.signature,
                validator_keypair().public_key()
            ));
        }

        let replay = app
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
        assert_eq!(replay.status(), StatusCode::OK);
        let replayed: EmitReceiptResponse =
            serde_json::from_slice(&read_body(replay).await).unwrap();
        assert_eq!(replayed.receipt_hash, parsed.receipt_hash);
        assert_eq!(
            replayed.exochain_finality_hash,
            parsed.exochain_finality_hash
        );
        assert_eq!(
            replayed.exochain_finality_height,
            parsed.exochain_finality_height
        );
        assert_eq!(
            replayed.exochain_finality_receipt_hash,
            parsed.exochain_finality_receipt_hash
        );
        assert_eq!(
            finality_store
                .lock()
                .unwrap()
                .committed_height_sync()
                .unwrap(),
            finality_height
        );
    }

    #[tokio::test]
    async fn receipt_emit_strict_rfc3161_attaches_microsoft_proof_action_meaning_and_finality() {
        let dir = tempfile::tempdir().unwrap();
        let finality_store = Arc::new(Mutex::new(
            crate::store::SqliteDagStore::open(dir.path()).unwrap(),
        ));
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let mut state = AvcApiState::new_with_external_timestamp_source_and_finality_store(
            validator_did(),
            signer,
            fixed_rfc3161_external_timestamp_source(),
            Some(Arc::clone(&finality_store)),
        );
        state.require_external_timestamp = true;
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
        let credential = credential_expiring_at(Timestamp::new(1_900_000_000_000, 0));
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
        let action = request.action.as_ref().unwrap();
        let action_id = action.action_id;
        let action_commitment_hash =
            avc_action_commitment_hash(&request.credential, action, &request.now).unwrap();
        let action_descriptor = AvcActionDescriptor::from_action(action);
        let action_descriptor_hash = avc_action_descriptor_hash(&action_descriptor).unwrap();
        let body = serde_json::to_vec(&EmitReceiptRequest {
            validation: request.clone(),
            subject_signature: sign_action(&request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();

        let response = avc_router(Arc::clone(&state))
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
            parsed.receipt.timestamp_provenance,
            Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority)
        );
        assert_eq!(parsed.receipt.action_descriptor, Some(action_descriptor));
        assert_eq!(
            parsed.receipt.action_descriptor_hash,
            Some(action_descriptor_hash)
        );
        assert_eq!(
            parsed.receipt.action_commitment_hash,
            Some(action_commitment_hash)
        );
        assert_eq!(parsed.receipt.previous_receipt_hash, None);
        let evidence_subject = AvcReceiptEvidenceSubject {
            credential_id,
            action_id,
            action_commitment_hash,
            action_descriptor_hash,
            previous_receipt_hash: None,
        };
        let evidence_subject_hash = evidence_subject.hash().unwrap();
        let external_timestamp_proof = parsed.receipt.external_timestamp_proof.as_ref().unwrap();
        assert_eq!(
            external_timestamp_proof.authority_did,
            Did::new(MICROSOFT_PUBLIC_RSA_TSA_DID).unwrap()
        );
        assert_eq!(external_timestamp_proof.subject_hash, evidence_subject_hash);
        assert_eq!(
            external_timestamp_proof.proof_kind,
            AvcReceiptExternalTimestampProofKind::Rfc3161
        );
        let rfc3161 = external_timestamp_proof.rfc3161.as_ref().unwrap();
        assert_eq!(
            rfc3161.message_imprint_sha256_hex,
            hex::encode(evidence_subject.rfc3161_sha256_message_imprint().unwrap())
        );
        assert_eq!(
            rfc3161.token_der_base64,
            crate::avc_rfc3161::microsoft_fixture_timestamp_token_der_base64().unwrap()
        );
        assert_eq!(
            rfc3161.policy_oid,
            crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID
        );
        assert_eq!(rfc3161.serial_number_hex, "6a1c57054080");
        assert_eq!(rfc3161.nonce_hex, "a173ce171bc853e8");
        assert_eq!(rfc3161.tsa_subject, MICROSOFT_FIXTURE_TSA_SUBJECT);
        assert_eq!(
            rfc3161.tsa_public_key_spki_der_hex,
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX
        );
        assert_eq!(
            parsed.receipt.created_at,
            external_timestamp_proof.issued_at
        );
        assert!(parsed.exochain_finality_hash.is_some());
        assert_eq!(parsed.exochain_finality_height, Some(1));
        assert!(parsed.exochain_finality_receipt_hash.is_some());
        let finality_hash = parse_hash_anyhow(
            parsed.exochain_finality_hash.as_deref().unwrap(),
            "strict RFC 3161 finality hash",
        )
        .unwrap();
        assert!(
            finality_store
                .lock()
                .unwrap()
                .contains_sync(&finality_hash)
                .unwrap()
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn receipt_emit_uses_local_hlc_finality_when_external_timestamp_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let finality_store = Arc::new(Mutex::new(
            crate::store::SqliteDagStore::open(dir.path()).unwrap(),
        ));
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
            validator_did: validator_did(),
            receipt_signer: signer,
            external_timestamp_source: AvcReceiptExternalTimestampSource::Unconfigured,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: false,
            finality_store: Some(Arc::clone(&finality_store)),
            durability: AvcRegistryDurability::None,
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
        };
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
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

        let response = avc_router(Arc::clone(&state))
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
            parsed.receipt.timestamp_provenance,
            Some(AvcReceiptTimestampProvenance::LocalHybridLogicalClock)
        );
        assert_eq!(parsed.receipt.external_timestamp_proof, None);
        assert_eq!(parsed.receipt.created_at, Timestamp::new(1_000_000, 0));
        let finality_hash = parse_hash_anyhow(
            parsed
                .exochain_finality_hash
                .as_deref()
                .expect("local EXOCHAIN finality receipt must return finality hash"),
            "AVC EXOCHAIN finality hash",
        )
        .unwrap();
        let finality_receipt_hash = parse_hash_anyhow(
            parsed
                .exochain_finality_receipt_hash
                .as_deref()
                .expect("local EXOCHAIN finality receipt must return finality receipt hash"),
            "AVC EXOCHAIN finality receipt hash",
        )
        .unwrap();

        let store = finality_store.lock().unwrap();
        assert!(
            store.contains_sync(&finality_hash).unwrap(),
            "local-HLC AVC receipt must still commit an EXOCHAIN finality DAG node"
        );
        let finality_receipt = store
            .load_receipt(&finality_receipt_hash)
            .unwrap()
            .expect("local-HLC AVC finality trust receipt must be durably stored");
        assert_eq!(finality_receipt.action_hash, finality_hash);
        assert!(finality_receipt.verify_hash().unwrap());
    }

    #[tokio::test]
    async fn receipt_emit_links_sequential_receipts_to_previous_avc_receipt_hash() {
        let state = fresh_state();
        let first_credential = credential_with_purpose("first linked receipt");
        let second_credential = credential_with_purpose("second linked receipt");
        {
            let mut registry = state.registry.lock().unwrap();
            registry.put_credential(first_credential.clone()).unwrap();
            registry.put_credential(second_credential.clone()).unwrap();
        }

        let first_request = AvcValidationRequest {
            credential: first_credential,
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let mut second_action = baseline_action(Did::new("did:exo:agent").unwrap());
        second_action.action_id = Hash256::from_bytes([0x56; 32]);
        let second_request = AvcValidationRequest {
            credential: second_credential,
            action: Some(second_action),
            now: Timestamp::new(1_500_000, 0),
        };
        let first_body = serde_json::to_vec(&EmitReceiptRequest {
            validation: first_request.clone(),
            subject_signature: sign_action(&first_request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();
        let second_body = serde_json::to_vec(&EmitReceiptRequest {
            validation: second_request.clone(),
            subject_signature: sign_action(&second_request, &subject_keypair()),
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router(Arc::clone(&state));
        let first_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(first_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/receipts/emit")
                    .header("content-type", "application/json")
                    .body(Body::from(second_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(second_response.status(), StatusCode::OK);
        let first: EmitReceiptResponse =
            serde_json::from_slice(&read_body(first_response).await).unwrap();
        let second: EmitReceiptResponse =
            serde_json::from_slice(&read_body(second_response).await).unwrap();

        assert_eq!(first.receipt.previous_receipt_hash, None);
        assert_eq!(
            second.receipt.previous_receipt_hash,
            Some(first.receipt.receipt_id)
        );
        assert_ne!(
            first.receipt.action_commitment_hash,
            second.receipt.action_commitment_hash
        );
        assert_eq!(
            state.registry.lock().unwrap().receipt_chain_head(),
            Some(second.receipt.receipt_id)
        );
    }

    #[tokio::test]
    async fn receipt_readback_returns_stored_avc_receipt_by_hash() {
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
        let emitted = app
            .clone()
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
        assert_eq!(emitted.status(), StatusCode::OK);
        let emitted: EmitReceiptResponse =
            serde_json::from_slice(&read_body(emitted).await).unwrap();

        let read_back = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/receipts/{}", emitted.receipt_hash))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_back.status(), StatusCode::OK);
        let parsed: AvcTrustReceipt = serde_json::from_slice(&read_body(read_back).await).unwrap();
        assert_eq!(parsed, emitted.receipt);

        let non_avc_receipt_route = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/receipts/{}", emitted.receipt_hash))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            non_avc_receipt_route.status(),
            StatusCode::NOT_FOUND,
            "AVC receipt read-back must not fall through to the DAG receipt store route"
        );
    }

    #[tokio::test]
    async fn receipt_readback_rejects_invalid_and_unknown_hashes() {
        let state = fresh_state();
        let app = avc_router(state);

        let invalid = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/receipts/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

        let uppercase = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/receipts/{}", "AA".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(uppercase.status(), StatusCode::BAD_REQUEST);

        let unknown = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/avc/receipts/{}", "11".repeat(32)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn receipt_list_filters_by_actor_caps_limit_and_orders_deterministically() {
        let state = fresh_state();
        let first = credential_with_purpose("receipt list first");
        let second = credential_with_purpose("receipt list second");
        let other = credential_for_subject(Did::new("did:exo:other-agent").unwrap());
        let first_id = first.id().unwrap();
        let second_id = second.id().unwrap();
        let other_id = other.id().unwrap();

        let make_receipt = |credential_id: Hash256, action_byte: u8| {
            let validation = AvcValidationResult {
                credential_id,
                decision: AvcDecision::Allow,
                reason_codes: Vec::new(),
                normalized_holder_did: Did::new("did:exo:agent").unwrap(),
                valid_until: Some(Timestamp::new(2_000_000, 0)),
                receipt: None,
            };
            create_trust_receipt(
                &validation,
                Some(Hash256::from_bytes([action_byte; 32])),
                validator_did(),
                Timestamp::new(1_600_000, 0),
                |bytes| validator_keypair().sign(bytes),
            )
            .unwrap()
        };
        let first_receipt = make_receipt(first_id, 0x21);
        let second_receipt = make_receipt(second_id, 0x22);
        let other_receipt = make_receipt(other_id, 0x23);
        {
            let mut registry = state.registry.lock().unwrap();
            registry.put_credential(second).unwrap();
            registry.put_credential(other).unwrap();
            registry.put_credential(first).unwrap();
            registry.put_receipt(second_receipt.clone()).unwrap();
            registry.put_receipt(other_receipt).unwrap();
            registry.put_receipt(first_receipt.clone()).unwrap();
        }

        let app = avc_router(Arc::clone(&state));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/receipts?actor=did:exo:agent&limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: ListAvcReceiptsResponse =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(parsed.did, "did:exo:agent");
        assert_eq!(parsed.receipts.len(), 1);
        let mut expected = [first_receipt, second_receipt];
        expected.sort_by_key(|receipt| receipt.receipt_id);
        assert_eq!(parsed.receipts[0], expected[0]);

        let missing_actor = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_actor.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn protocol_discovery_accepts_legacy_and_current_rejects_future_version() {
        let state = fresh_state();
        let app = avc_router(state);

        let legacy = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/protocol")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy.status(), StatusCode::OK);
        let legacy_info: AvcProtocolInfo =
            serde_json::from_slice(&read_body(legacy).await).unwrap();
        assert_eq!(legacy_info.protocol_version, AVC_PROTOCOL_VERSION);
        assert_eq!(
            legacy_info.min_supported_protocol_version,
            AVC_MIN_SUPPORTED_PROTOCOL_VERSION
        );
        assert_eq!(legacy_info.wasm_package_name, WASM_PACKAGE_NAME);

        let current = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/api/v1/avc/protocol?protocol_version={AVC_PROTOCOL_VERSION}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(current.status(), StatusCode::OK);

        let future = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/api/v1/avc/protocol?protocol_version={}",
                        AVC_MAX_SUPPORTED_PROTOCOL_VERSION + 1
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(future.status(), StatusCode::BAD_REQUEST);
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
    async fn receipt_emit_accepts_http_external_timestamp_authority_proof() {
        let (endpoint, timestamp_authority) =
            serve_test_timestamp_authority(TestTimestampAuthorityMode::Valid).await;
        let request = AvcValidationRequest {
            credential: baseline_credential(),
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let credential_id = request.credential.id().unwrap();
        let action_id = request.action.as_ref().unwrap().action_id;
        let action_commitment_hash = avc_action_commitment_hash(
            &request.credential,
            request.action.as_ref().unwrap(),
            &request.now,
        )
        .unwrap();
        let action_descriptor = AvcActionDescriptor::from_action(request.action.as_ref().unwrap());
        let action_descriptor_hash = avc_action_descriptor_hash(&action_descriptor).unwrap();
        let (status, state, response_body) =
            emit_baseline_receipt_with_source(http_external_timestamp_source(endpoint)).await;

        assert_eq!(status, StatusCode::OK);
        let parsed: EmitReceiptResponse = serde_json::from_slice(&response_body).unwrap();
        let proof = parsed.receipt.external_timestamp_proof.as_ref().unwrap();
        let evidence_subject_hash = AvcReceiptEvidenceSubject {
            credential_id,
            action_id,
            action_commitment_hash,
            action_descriptor_hash,
            previous_receipt_hash: None,
        }
        .hash()
        .unwrap();
        assert_eq!(proof.authority_did, timestamp_authority_did());
        assert_eq!(proof.subject_hash, evidence_subject_hash);
        assert_eq!(parsed.receipt.created_at, Timestamp::new(1_700_000, 7));
        assert_eq!(
            parsed.receipt.timestamp_provenance,
            Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority)
        );
        assert!(
            proof
                .verify_signature(timestamp_authority_keypair().public_key())
                .unwrap()
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_http_external_timestamp_non_success_status() {
        let (endpoint, timestamp_authority) =
            serve_test_timestamp_authority(TestTimestampAuthorityMode::NonSuccess).await;

        let (status, state, _) =
            emit_baseline_receipt_with_source(http_external_timestamp_source(endpoint)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_http_external_timestamp_invalid_json() {
        let (endpoint, timestamp_authority) =
            serve_test_timestamp_authority(TestTimestampAuthorityMode::InvalidJson).await;

        let (status, state, _) =
            emit_baseline_receipt_with_source(http_external_timestamp_source(endpoint)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_http_external_timestamp_wrong_subject() {
        let (endpoint, timestamp_authority) =
            serve_test_timestamp_authority(TestTimestampAuthorityMode::WrongSubject).await;

        let (status, state, _) =
            emit_baseline_receipt_with_source(http_external_timestamp_source(endpoint)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_http_external_timestamp_wrong_authority() {
        let (endpoint, timestamp_authority) =
            serve_test_timestamp_authority(TestTimestampAuthorityMode::WrongAuthority).await;

        let (status, state, _) =
            emit_baseline_receipt_with_source(http_external_timestamp_source(endpoint)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_http_external_timestamp_bad_signature() {
        let (endpoint, timestamp_authority) =
            serve_test_timestamp_authority(TestTimestampAuthorityMode::BadSignature).await;

        let (status, state, _) =
            emit_baseline_receipt_with_source(http_external_timestamp_source(endpoint)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_unreachable_http_external_timestamp_authority() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let (status, state, _) = emit_baseline_receipt_with_source(http_external_timestamp_source(
            format!("http://{address}"),
        ))
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_for_strict_rfc3161_malformed_der_before_storage() {
        let (endpoint, timestamp_authority) =
            serve_test_rfc3161_timestamp_authority(StatusCode::OK, vec![0x30, 0x03, 0x02]).await;

        let (status, state, _) = emit_baseline_receipt_with_source_and_strict(
            rfc3161_external_timestamp_source(endpoint),
            true,
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn rfc3161_timestamp_fetch_retries_transient_status_before_success() {
        let (endpoint, attempts, timestamp_authority) =
            serve_test_rfc3161_timestamp_authority_sequence(vec![
                (StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
                (StatusCode::TOO_MANY_REQUESTS, Vec::new()),
                (StatusCode::OK, vec![0x30, 0x00]),
            ])
            .await;

        let response_der = fetch_rfc3161_timestamp_response(
            &reqwest::Client::new(),
            endpoint.as_str(),
            &[0x30, 0x01, 0x00],
        )
        .await
        .unwrap();

        assert_eq!(response_der, vec![0x30, 0x00]);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        timestamp_authority.abort();
    }

    #[tokio::test]
    async fn receipt_emit_does_not_retry_rfc3161_verification_failures() {
        let (endpoint, attempts, timestamp_authority) =
            serve_test_rfc3161_timestamp_authority_sequence(vec![(
                StatusCode::OK,
                vec![0x30, 0x03, 0x02],
            )])
            .await;

        let (status, state, _) = emit_baseline_receipt_with_source_and_strict(
            rfc3161_external_timestamp_source(endpoint),
            true,
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        timestamp_authority.abort();
    }

    #[test]
    fn external_timestamp_diagnostics_distinguish_unconfigured_from_unreachable() {
        let source = include_str!("avc.rs");
        let production = source
            .split("\n// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        assert!(
            production.contains("AvcExternalTimestampFailure::Unconfigured"),
            "operator diagnostics must keep missing TSA configuration distinct from runtime reachability failures"
        );
        assert!(
            production.contains("AvcExternalTimestampFailure::Unreachable"),
            "operator diagnostics must classify configured-but-unreachable TSA failures separately"
        );
        assert!(
            production.contains("external_timestamp_error_class"),
            "the 503 path must attach a stable operator-facing TSA error class before returning the generic public error"
        );
    }

    #[test]
    fn external_timestamp_error_surfaces_operator_class_in_public_message() {
        // A signer-SPKI pin rejection (the production misdiagnosis) must not read
        // as a generic "authority unavailable": the public 503 message carries the
        // stable operator class so callers seeing only the response — not the node
        // logs — can tell a verification/config failure from upstream downtime.
        // Cover every failure class so each operator_class arm is exercised.
        let cases = [
            (AvcExternalTimestampFailure::Unconfigured, "unconfigured"),
            (
                AvcExternalTimestampFailure::Unreachable {
                    reason: "connection refused".to_owned(),
                },
                "unreachable",
            ),
            (
                AvcExternalTimestampFailure::Rejected {
                    status: "503 Service Unavailable".to_owned(),
                },
                "rejected",
            ),
            (
                AvcExternalTimestampFailure::InvalidResponse {
                    reason: "malformed DER".to_owned(),
                },
                "invalid_response",
            ),
            (
                AvcExternalTimestampFailure::InvalidProof {
                    reason: "RFC 3161 TSA signer public key did not match any pinned SPKI DER"
                        .to_owned(),
                },
                "invalid_proof",
            ),
        ];
        for (failure, expected_class) in cases {
            let err: anyhow::Error = failure.into();
            let (status, message) = external_timestamp_error(err);
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                message.contains(expected_class),
                "public TSA error must carry operator class '{expected_class}', got: {message}"
            );
        }
    }

    #[tokio::test]
    async fn receipt_emit_fails_closed_when_external_timestamp_authority_is_required_but_unconfigured()
     {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
            validator_did: validator_did(),
            receipt_signer: signer,
            external_timestamp_source: AvcReceiptExternalTimestampSource::Unconfigured,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: true,
            finality_store: None,
            durability: AvcRegistryDurability::None,
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
        };
        seed_avc_trust_keys(&state);
        let state = Arc::new(state);
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

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
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

    fn livesafe_public_output_credential() -> AutonomousVolitionCredential {
        livesafe_public_output_credential_for_evidence(Hash256::from_bytes([0xE1; 32]))
    }

    fn livesafe_public_output_credential_for_evidence(
        evidence_hash: Hash256,
    ) -> AutonomousVolitionCredential {
        livesafe_public_output_credential_with_window_for_evidence(
            Timestamp::new(1_000_000, 0),
            Timestamp::new(2_000_000, 0),
            evidence_hash,
        )
    }

    fn livesafe_public_output_credential_with_window_for_evidence(
        created_at: Timestamp,
        expires_at: Timestamp,
        evidence_hash: Hash256,
    ) -> AutonomousVolitionCredential {
        exo_avc::issue_livesafe_public_output_credential_ceremony(
            exo_avc::LivesafePublicOutputCredentialCeremonyInput {
                issuer_did: Did::new("did:exo:issuer").unwrap(),
                issuer_authority_scope: AuthorityScope {
                    permissions: vec![Permission::Read],
                    tools: vec![
                        exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
                    ],
                    data_classes: vec![exo_avc::DataClass::Public],
                    counterparties: vec![],
                    jurisdictions: vec!["US".into()],
                },
                credential_subject_did: Did::new(
                    exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID,
                )
                .unwrap(),
                public_subject: exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT
                    .into(),
                public_audience: exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE
                    .into(),
                allowed_claim_names: vec![
                    exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
                ],
                evidence: exo_avc::LivesafePublicOutputCredentialCeremonyEvidence {
                    sha256_hash: evidence_hash,
                },
                not_before: created_at,
                expires_at,
                idempotency_key: "node-test-livesafe-public-output".into(),
            },
            |bytes| issuer_keypair().sign(bytes),
        )
        .unwrap()
        .credential
    }

    fn store_livesafe_public_output_credential_for_evidence(
        state: &AvcApiState,
        evidence_hash: Hash256,
    ) -> Hash256 {
        store_livesafe_public_output_credential(
            state,
            livesafe_public_output_credential_for_evidence(evidence_hash),
        )
    }

    fn store_livesafe_public_output_credential(
        state: &AvcApiState,
        credential: AutonomousVolitionCredential,
    ) -> Hash256 {
        let credential_id = credential.id().unwrap();
        let mut registry = state.registry.lock().unwrap();
        registry.put_issuer_permission_grant(
            Did::new("did:exo:issuer").unwrap(),
            vec![Permission::Read],
        );
        registry.put_credential(credential).unwrap();
        credential_id
    }

    fn public_output_authorization_request(
        credential_id: Hash256,
        idempotency_key: &str,
        evidence_hash: Hash256,
        audience: &str,
    ) -> PublicOutputAuthorizationRequest {
        PublicOutputAuthorizationRequest {
            credential_id,
            subject: exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
            audience: audience.into(),
            evidence_hash,
            idempotency_key: idempotency_key.into(),
            expires_at: Timestamp::new(1_700_000, 0),
        }
    }

    async fn post_public_output_authorization(
        app: Router,
        request: PublicOutputAuthorizationRequest,
        bearer: Option<&str>,
    ) -> axum::response::Response {
        post_public_output_authorization_json(app, serde_json::to_value(request).unwrap(), bearer)
            .await
    }

    async fn post_public_output_authorization_json(
        app: Router,
        request: serde_json::Value,
        bearer: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/avc/livesafe/public-adapter-output-authorization")
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        app.oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn public_output_authorization_bearer_required() {
        let state = fresh_state();
        let credential_id =
            store_livesafe_public_output_credential(&state, livesafe_public_output_credential());
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = public_output_authorization_request(
            credential_id,
            "public-output-idem-1",
            Hash256::from_bytes([0xE1; 32]),
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );

        let response = post_public_output_authorization(app, request, None).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn livesafe_public_output_scoped_bearer_accepts_public_output_authorization_when_configured()
     {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xF1; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = public_output_authorization_request(
            credential_id,
            "public-output-scoped-bearer-idem",
            evidence_hash,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );

        let response = post_public_output_authorization(
            app,
            request,
            Some("livesafe-public-output-scoped-token"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let envelope: exo_avc::LivesafePublicAdapterOutputAuthorizationEnvelope =
            serde_json::from_slice(&read_body(response).await).unwrap();
        assert_eq!(envelope.proof.credential_id, credential_id);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn public_output_authorization_exports_redacted_proof_happy_path() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xE2; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = public_output_authorization_request(
            credential_id,
            "public-output-idem-2",
            evidence_hash,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );

        let response =
            post_public_output_authorization(app, request, Some("vcg-006a-admin-token")).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        let envelope: exo_avc::LivesafePublicAdapterOutputAuthorizationEnvelope =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(
            envelope.proof.subject,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT
        );
        assert_eq!(
            envelope.proof.audience,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE
        );
        assert_eq!(envelope.proof.credential_id, credential_id);
        assert!(
            !String::from_utf8(body).unwrap().contains("livesafe-issuer"),
            "redacted proof envelope must not return raw credential internals"
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn public_output_authorization_uses_trusted_local_hlc_for_proof_and_receipt_time() {
        let state = fresh_state();
        let trusted_floor = trusted_local_hlc_timestamp(&state).unwrap();
        let evidence_hash = Hash256::from_bytes([0xD1; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let caller_supplied_time = Timestamp::new(1_500_000, 0);
        let request = serde_json::json!({
            "credential_id": credential_id,
            "subject": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
            "audience": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
            "evidence_hash": evidence_hash,
            "idempotency_key": "public-output-idem-trusted-hlc",
            "issued_at": caller_supplied_time,
            "expires_at": Timestamp::new(1_700_000, 0)
        });

        let response =
            post_public_output_authorization_json(app, request, Some("vcg-006a-admin-token")).await;

        assert_eq!(response.status(), StatusCode::OK);
        let envelope: exo_avc::LivesafePublicAdapterOutputAuthorizationEnvelope =
            serde_json::from_slice(&read_body(response).await).unwrap();
        let receipt = state
            .registry
            .lock()
            .unwrap()
            .get_receipt(&envelope.proof.receipt_id)
            .unwrap();
        assert_ne!(envelope.proof.issued_at, caller_supplied_time);
        assert!(
            envelope.proof.issued_at > trusted_floor,
            "public-output proof time must come from this node's trusted local HLC"
        );
        assert_eq!(receipt.created_at, envelope.proof.issued_at);
    }

    #[tokio::test]
    async fn public_output_authorization_rejects_backdated_resurrection_of_expired_credential() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xD2; 32]);
        let credential = livesafe_public_output_credential_with_window_for_evidence(
            Timestamp::new(900_000, 0),
            Timestamp::new(1_000_000, 0),
            evidence_hash,
        );
        let credential_id = store_livesafe_public_output_credential(&state, credential);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = serde_json::json!({
            "credential_id": credential_id,
            "subject": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
            "audience": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
            "evidence_hash": evidence_hash,
            "idempotency_key": "public-output-idem-backdate-expired",
            "issued_at": Timestamp::new(950_000, 0),
            "expires_at": Timestamp::new(999_000, 0)
        });

        let response =
            post_public_output_authorization_json(app, request, Some("vcg-006a-admin-token")).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn public_output_authorization_rejects_future_dated_premature_not_yet_valid_credential() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xD3; 32]);
        let credential = livesafe_public_output_credential_with_window_for_evidence(
            Timestamp::new(1_100_000, 0),
            Timestamp::new(1_700_000, 0),
            evidence_hash,
        );
        let credential_id = store_livesafe_public_output_credential(&state, credential);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = serde_json::json!({
            "credential_id": credential_id,
            "subject": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
            "audience": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
            "evidence_hash": evidence_hash,
            "idempotency_key": "public-output-idem-future-date-not-yet-valid",
            "issued_at": Timestamp::new(1_200_000, 0),
            "expires_at": Timestamp::new(1_500_000, 0)
        });

        let response =
            post_public_output_authorization_json(app, request, Some("vcg-006a-admin-token")).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn public_output_authorization_replay_omits_caller_time_and_reuses_trusted_receipt() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xD4; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = serde_json::json!({
            "credential_id": credential_id,
            "subject": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
            "audience": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
            "evidence_hash": evidence_hash,
            "idempotency_key": "public-output-idem-no-caller-time",
            "expires_at": Timestamp::new(1_700_000, 0)
        });

        let first = post_public_output_authorization_json(
            app.clone(),
            request.clone(),
            Some("vcg-006a-admin-token"),
        )
        .await;
        let second =
            post_public_output_authorization_json(app, request, Some("vcg-006a-admin-token")).await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(read_body(first).await, read_body(second).await);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn public_output_authorization_replay_same_body_returns_same_proof() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xE3; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = public_output_authorization_request(
            credential_id,
            "public-output-idem-3",
            evidence_hash,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );

        let first = post_public_output_authorization(
            app.clone(),
            request.clone(),
            Some("vcg-006a-admin-token"),
        )
        .await;
        let second =
            post_public_output_authorization(app, request, Some("vcg-006a-admin-token")).await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(read_body(first).await, read_body(second).await);
        assert_eq!(
            state.registry.lock().unwrap().receipt_count(),
            1,
            "same public-output authorization body must reuse the same receipt/proof"
        );
    }

    #[tokio::test]
    async fn public_output_authorization_conflicts_on_idempotency_key_reuse_with_changed_expiry() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xE7; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let first_request = public_output_authorization_request(
            credential_id,
            "public-output-idem-expiry-conflict",
            evidence_hash,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );
        let mut changed_expiry = first_request.clone();
        changed_expiry.expires_at = Timestamp::new(1_800_000, 0);

        let first = post_public_output_authorization(
            app.clone(),
            first_request,
            Some("vcg-006a-admin-token"),
        )
        .await;
        let first_body = read_body(first).await;
        let first_proof: exo_avc::LivesafePublicAdapterOutputAuthorizationEnvelope =
            serde_json::from_slice(&first_body).unwrap();
        let changed =
            post_public_output_authorization(app, changed_expiry, Some("vcg-006a-admin-token"))
                .await;

        assert_eq!(changed.status(), StatusCode::CONFLICT);
        assert_eq!(
            state.registry.lock().unwrap().receipt_count(),
            1,
            "changed expires_at under the same idempotency key must not mint a second proof/receipt"
        );
        assert!(
            state
                .registry
                .lock()
                .unwrap()
                .get_receipt(&first_proof.proof.receipt_id)
                .is_some(),
            "original receipt must remain the only replay target"
        );
    }

    #[tokio::test]
    async fn public_output_authorization_conflicts_on_idempotency_key_reuse() {
        let state = fresh_state();
        let evidence_hash = Hash256::from_bytes([0xE4; 32]);
        let credential_id =
            store_livesafe_public_output_credential_for_evidence(&state, evidence_hash);
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let first_request = public_output_authorization_request(
            credential_id,
            "public-output-idem-4",
            evidence_hash,
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );
        let changed_evidence = public_output_authorization_request(
            credential_id,
            "public-output-idem-4",
            Hash256::from_bytes([0xE5; 32]),
            exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        );
        let changed_audience = public_output_authorization_request(
            credential_id,
            "public-output-idem-4",
            Hash256::from_bytes([0xE4; 32]),
            "https://example.invalid/api/trust/status",
        );

        let first = post_public_output_authorization(
            app.clone(),
            first_request,
            Some("vcg-006a-admin-token"),
        )
        .await;
        let evidence_conflict = post_public_output_authorization(
            app.clone(),
            changed_evidence,
            Some("vcg-006a-admin-token"),
        )
        .await;
        let audience_conflict =
            post_public_output_authorization(app, changed_audience, Some("vcg-006a-admin-token"))
                .await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(evidence_conflict.status(), StatusCode::CONFLICT);
        assert_eq!(audience_conflict.status(), StatusCode::CONFLICT);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn public_output_authorization_is_not_receipts_emit_subject_signature_carve_out() {
        let state = fresh_state();
        let credential_id =
            store_livesafe_public_output_credential(&state, livesafe_public_output_credential());
        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let request = serde_json::json!({
            "credential_id": credential_id,
            "subject": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
            "audience": exo_avc::LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
            "evidence_hash": Hash256::from_bytes([0xE6; 32]),
            "idempotency_key": "public-output-idem-5",
            "issued_at": Timestamp::new(1_500_000, 0),
            "expires_at": Timestamp::new(1_700_000, 0),
            "subject_signature": Signature::from_bytes([0x7A; 64])
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/livesafe/public-adapter-output-authorization")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "only /api/v1/avc/receipts/emit may use the subject-signature carve-out"
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn receipt_emit_rejects_conflicting_stored_action_commitment() {
        let state = fresh_state();
        let credential = baseline_credential();
        let request = AvcValidationRequest {
            credential: credential.clone(),
            action: Some(baseline_action(Did::new("did:exo:agent").unwrap())),
            now: Timestamp::new(1_500_000, 0),
        };
        let action_commitment_hash = avc_action_commitment_hash(
            &request.credential,
            request.action.as_ref().unwrap(),
            &request.now,
        )
        .unwrap();
        {
            let mut registry = state.registry.lock().unwrap();
            registry.put_credential(credential).unwrap();
            let mut trusted_request = request.clone();
            trusted_request.now = Timestamp::new(1_600_000, 0);
            let validation = validate_avc(&trusted_request, &*registry).unwrap();
            let conflicting_receipt = create_trust_receipt_with_evidence(
                &validation,
                Some(Hash256::from_bytes([0x99; 32])),
                AvcTrustReceiptEvidence {
                    action_commitment_hash: Some(action_commitment_hash),
                    action_descriptor: None,
                    llm_usage_evidence_hash: None,
                    previous_receipt_hash: None,
                    timestamp_provenance: Some(AvcReceiptTimestampProvenance::FixedTestTimestamp),
                    external_timestamp_proof: None,
                },
                validator_did(),
                Timestamp::new(1_600_000, 0),
                |bytes| validator_keypair().sign(bytes),
            )
            .unwrap();
            registry.put_receipt(conflicting_receipt).unwrap();
        }
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

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
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
        registry.put_receipt_validator_public_key(validator_did(), validator_keypair().public);
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
    fn avc_registry_validator_key_registration_does_not_create_issuer_trust() {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::new(validator_did(), signer);

        state
            .register_validator_public_keys([(validator_did(), validator_keypair().public)])
            .unwrap();

        assert_eq!(
            state
                .registry
                .lock()
                .unwrap()
                .resolve_public_key(&validator_did()),
            None
        );
    }

    #[test]
    fn avc_registry_validator_key_registration_errors_when_mutex_is_poisoned() {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::new(validator_did(), signer);
        let registry = Arc::clone(&state.registry);
        let _ = std::panic::catch_unwind(move || {
            let _guard = registry.lock().unwrap();
            panic!("poison AVC registry mutex for validator key registration test");
        });

        let error = state
            .register_validator_public_keys([(validator_did(), validator_keypair().public)])
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "AVC registry unavailable while registering validator public key"
        );
    }

    #[test]
    fn avc_registry_validator_key_registration_rejects_loaded_receipt_without_swapping_state() {
        let other_validator_keypair = KeyPair::from_secret_bytes([0x44; 32]).unwrap();
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
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
            None,
            validator_did(),
            Timestamp::new(1_500_000, 0),
            |bytes| other_validator_keypair.sign(bytes),
        )
        .unwrap();
        let mut durable_state = AvcRegistryDurableState::default();
        durable_state.credentials.insert(credential_id, credential);
        durable_state.receipts.insert(receipt.receipt_id, receipt);
        let loaded_registry = InMemoryAvcRegistry::from_durable_state(durable_state).unwrap();

        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));
        let state = AvcApiState::new(validator_did(), signer);
        *state.registry.lock().unwrap() = loaded_registry;

        let error = state
            .register_validator_public_keys([(validator_did(), validator_keypair().public)])
            .unwrap_err();
        let error = error.to_string();
        assert!(error.contains("AVC durable receipt validation failed"));
        assert!(error.contains("signature"));

        let post_failure_error = {
            let registry = state.registry.lock().unwrap();
            registry.validate_loaded_receipts().unwrap_err()
        };
        assert_eq!(
            post_failure_error.to_string(),
            "AVC invalid input: receipt validator public key for did:exo:validator is unresolved",
            "failed validator key registration must not replace the live registry with the candidate"
        );
    }

    #[test]
    fn avc_registry_registered_credential_mismatch_is_rejected() {
        let credential = baseline_credential();
        let credential_id = credential.id().unwrap();
        let mut submitted_credential = credential.clone();
        submitted_credential.signature = Signature::from_bytes([0x44; 64]);
        assert_eq!(submitted_credential.id().unwrap(), credential_id);

        let mut registry = InMemoryAvcRegistry::new();
        registry.put_public_key(Did::new("did:exo:issuer").unwrap(), issuer_keypair().public);
        registry.put_credential(credential).unwrap();
        let request = AvcValidationRequest {
            credential: submitted_credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };

        let error = require_registered_credential(&registry, &request).unwrap_err();

        assert_eq!(
            error,
            (
                StatusCode::BAD_REQUEST,
                "credential does not match registered AVC".into()
            )
        );
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
            exo_avc::AvcError::UnsupportedProtocol {
                got: 99,
                min_supported: 1,
                max_supported: 1,
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
    async fn receipt_emit_rejects_registered_credential_mismatch_without_receipt() {
        let state = fresh_state();
        let registered = baseline_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(registered.clone())
            .unwrap();
        let mut submitted = registered;
        submitted.signature = Signature::empty();
        let request = AvcValidationRequest {
            credential: submitted,
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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

    fn external_timestamp_source_from_pairs(
        pairs: Vec<(&'static str, &str)>,
    ) -> anyhow::Result<AvcReceiptExternalTimestampSource> {
        let values = pairs
            .iter()
            .copied()
            .collect::<std::collections::BTreeMap<_, _>>();
        configured_external_timestamp_source_from_reader(|name| {
            Ok(values.get(name).map(|value| (*value).to_owned()))
        })
    }

    #[test]
    fn rfc3161_env_config_requires_kind_triplet_policy_and_pinned_spki() {
        let err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                "30820122300d06092a864886f70d01010105000382010f",
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains(AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV));

        let microsoft_tsa_pin_set = format!(
            "{MICROSOFT_FIXTURE_SIGNER_SPKI_HEX},{MICROSOFT_LIVE_SIGNER_SPKI_HEX_20260627}"
        );
        let source = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                microsoft_tsa_pin_set.as_str(),
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap();

        match source {
            AvcReceiptExternalTimestampSource::Rfc3161 {
                endpoint,
                authority_did,
                authority_public_key_spki_der_hexes,
                policy_oid,
                ..
            } => {
                assert_eq!(endpoint.as_str(), "http://timestamp.acs.microsoft.com");
                assert_eq!(
                    authority_did.to_string(),
                    "did:exo:microsoft-public-rsa-tsa"
                );
                assert_eq!(
                    authority_public_key_spki_der_hexes.as_slice(),
                    &[
                        MICROSOFT_FIXTURE_SIGNER_SPKI_HEX.to_owned(),
                        MICROSOFT_LIVE_SIGNER_SPKI_HEX_20260627.to_owned(),
                    ]
                );
                assert_eq!(
                    policy_oid.as_str(),
                    crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID
                );
            }
            _ => panic!("rfc3161 kind must construct the RFC 3161 timestamp source"),
        }

        let duplicate_pin_set =
            format!("{MICROSOFT_FIXTURE_SIGNER_SPKI_HEX},{MICROSOFT_FIXTURE_SIGNER_SPKI_HEX}");
        let duplicate_pin_err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                duplicate_pin_set.as_str(),
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(duplicate_pin_err.contains("duplicate member"));

        let empty_pin_set = format!("{MICROSOFT_FIXTURE_SIGNER_SPKI_HEX},");
        let empty_pin_err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                empty_pin_set.as_str(),
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(empty_pin_err.contains("member 2 is empty"));
    }

    #[test]
    fn rfc3161_env_config_accepts_explicit_pinned_issuing_ca_without_leaf_pin() {
        let source = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
                MICROSOFT_FIXTURE_CA_SPKI_HEX,
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap();

        match source {
            AvcReceiptExternalTimestampSource::Rfc3161 {
                authority_public_key_spki_der_hexes,
                issuing_ca_spki_der_hexes,
                ..
            } => {
                assert!(authority_public_key_spki_der_hexes.is_empty());
                assert_eq!(
                    issuing_ca_spki_der_hexes.as_slice(),
                    &[MICROSOFT_FIXTURE_CA_SPKI_HEX.to_owned()]
                );
            }
            _ => panic!("rfc3161 kind must construct the RFC 3161 timestamp source"),
        }
    }

    #[test]
    fn external_timestamp_source_debug_redacts_transport_clients_and_pin_material() {
        let rfc3161 = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
                MICROSOFT_FIXTURE_CA_SPKI_HEX,
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap();
        let rfc3161_debug = format!("{rfc3161:?}");
        assert!(rfc3161_debug.contains("AvcReceiptExternalTimestampSource::Rfc3161"));
        assert!(rfc3161_debug.contains("http://timestamp.acs.microsoft.com"));
        assert!(rfc3161_debug.contains("did:exo:microsoft-public-rsa-tsa"));
        assert!(rfc3161_debug.contains(crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID));
        assert!(!rfc3161_debug.contains(MICROSOFT_FIXTURE_CA_SPKI_HEX));
        assert!(!rfc3161_debug.contains("client"));

        let http = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://127.0.0.1:3000",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:timestamp-authority",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                &timestamp_authority_keypair().public.to_string(),
            ),
        ])
        .unwrap();
        let http_debug = format!("{http:?}");
        assert!(http_debug.contains("AvcReceiptExternalTimestampSource::HttpJson"));
        assert!(http_debug.contains("http://127.0.0.1:3000"));
        assert!(http_debug.contains("did:exo:timestamp-authority"));
        assert!(!http_debug.contains(&timestamp_authority_keypair().public.to_string()));
        assert!(!http_debug.contains("client"));

        assert_eq!(
            format!("{:?}", AvcReceiptExternalTimestampSource::Unconfigured),
            "AvcReceiptExternalTimestampSource::Unconfigured"
        );

        let fixed = fixed_external_timestamp_source(Timestamp::new(1_600_000, 0));
        let fixed_debug = format!("{fixed:?}");
        assert!(fixed_debug.contains("AvcReceiptExternalTimestampSource::Fixed"));
        assert!(fixed_debug.contains("did:exo:timestamp-authority"));
        assert!(fixed_debug.contains("issued_at"));

        let fixed_rfc3161 = fixed_rfc3161_external_timestamp_source();
        let fixed_rfc3161_debug = format!("{fixed_rfc3161:?}");
        assert!(fixed_rfc3161_debug.contains("AvcReceiptExternalTimestampSource::FixedRfc3161"));
        assert!(fixed_rfc3161_debug.contains("did:exo:microsoft-public-rsa-tsa"));
        assert!(
            fixed_rfc3161_debug.contains(crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID)
        );
        assert!(!fixed_rfc3161_debug.contains(MICROSOFT_FIXTURE_SIGNER_SPKI_HEX));
    }

    #[test]
    fn rfc3161_env_config_rejects_missing_leaf_and_ca_trust_anchors() {
        let err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap_err()
        .to_string();

        assert!(err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV));
        assert!(err.contains(AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV));
    }

    #[test]
    fn external_timestamp_env_config_rejects_cross_protocol_and_malformed_values() {
        let json_ca_err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://127.0.0.1:3000",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:timestamp-authority",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                &timestamp_authority_keypair().public.to_string(),
            ),
            (
                AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
                MICROSOFT_FIXTURE_CA_SPKI_HEX,
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(json_ca_err.contains(AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV));
        assert!(json_ca_err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161));

        let json_did_err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://127.0.0.1:3000",
            ),
            (AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV, "not-a-did"),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                &timestamp_authority_keypair().public.to_string(),
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(json_did_err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV));

        let rfc3161_missing_endpoint_err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:microsoft-public-rsa-tsa",
            ),
            (
                AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
                MICROSOFT_FIXTURE_CA_SPKI_HEX,
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(rfc3161_missing_endpoint_err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV));

        let rfc3161_did_err = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161,
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://timestamp.acs.microsoft.com",
            ),
            (AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV, "not-a-did"),
            (
                AVC_RFC3161_TIMESTAMP_CA_SPKI_HEX_ENV,
                MICROSOFT_FIXTURE_CA_SPKI_HEX,
            ),
            (
                AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
                crate::avc_rfc3161::MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(rfc3161_did_err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV));

        let unknown_kind_err = external_timestamp_source_from_pairs(vec![(
            AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
            "not-a-supported-kind",
        )])
        .unwrap_err()
        .to_string();
        assert!(unknown_kind_err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_JSON_ED25519));
        assert!(unknown_kind_err.contains(AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161));
    }

    #[test]
    fn json_ed25519_env_config_remains_backward_compatible_without_kind() {
        let source = external_timestamp_source_from_pairs(vec![
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
                "http://127.0.0.1:3000",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV,
                "did:exo:timestamp-authority",
            ),
            (
                AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                &timestamp_authority_keypair().public.to_string(),
            ),
        ])
        .unwrap();

        match source {
            AvcReceiptExternalTimestampSource::HttpJson { .. } => {}
            _ => panic!("missing kind must preserve the legacy JSON Ed25519 adapter"),
        }
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
            production.contains("AvcRegistryDurability::Postgres(pool.clone())"),
            "AVC durable registry must persist to Postgres when DATABASE_URL is configured"
        );
        assert!(
            production.contains("configured_external_timestamp_source_from_env()?"),
            "AVC runtime receipt emission must load the external timestamp authority from explicit environment configuration"
        );
        assert!(
            production.contains("validate_external_timestamp_proof(")
                && production.contains("AVC_RECEIPT_EVIDENCE_SUBJECT_DOMAIN"),
            "AVC production receipt timestamps must verify a signed external evidence-subject proof"
        );
        assert!(
            !production.contains("SystemTime::now") && !production.contains("Instant::now"),
            "AVC production receipt emission must not read Rust system time directly"
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
        let file_fallback = production
            .split("None => {")
            .nth(1)
            .and_then(|section| section.split("Ok(Self").next())
            .expect("AVC file fallback branch present");
        assert!(
            file_fallback.contains("tracing::warn!"),
            "AVC file fallback startup must warn operators that Postgres durability is unavailable"
        );
        assert!(
            production.contains("AvcRegistryDurability::File"),
            "AVC durable registry must keep a no-DATABASE_URL file fallback for local nodes"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-006a RED — #735 Postgres durability requirement is inert
    // -----------------------------------------------------------------------
    //
    // `avc_require_postgres_durability_from_env()` is parsed at
    // `main.rs:514` but its `bool` result is discarded — the flag never
    // reaches `AvcApiState::with_durable_registry`, so a deployment that sets
    // `EXO_AVC_REQUIRE_POSTGRES_DURABILITY=true` without `DATABASE_URL`
    // silently falls back to the local file-backed registry instead of
    // failing closed at startup.
    //
    // This test is COMPILE-RED today: `with_durable_registry` has no
    // parameter through which to express "Postgres durability is required."
    // The fix must thread a `require_postgres_durability: bool` (or
    // equivalent) into `with_durable_registry`'s signature so that
    // `database_pool: None` plus `require_postgres_durability: true` returns
    // `Err` instead of constructing a file-backed registry. Until that
    // parameter exists, this call site fails to compile — that compile
    // failure IS the red evidence for #735.
    #[tokio::test]
    async fn avc_startup_fails_closed_when_durability_required_without_pool() {
        let dir = tempfile::tempdir().expect("temp data dir");
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_keypair().sign(payload));

        let result = AvcApiState::with_durable_registry(
            dir.path(),
            validator_did(),
            signer,
            None, // database_pool
            None, // finality_store
            true, // require_postgres_durability — parameter does not exist yet
        )
        .await;

        assert!(
            result.is_err(),
            "startup must fail closed when Postgres durability is required but no database pool is configured"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-006a RED — #737 subject-signed /receipts/emit blocked by admin bearer gate
    // -----------------------------------------------------------------------
    //
    // `handle_emit_receipt` already fully verifies the subject's Ed25519
    // signature over the requested action (see
    // `verify_subject_action_signature` calls at ~2282 and ~2304). The gap is
    // purely in the router wiring: `main.rs:1127-1136` merges `avc_router`
    // into `extra_router` and layers `auth::require_bearer_on_writes`
    // uniformly over the whole merged router with no carve-out for
    // subject-signed AVC writes — unlike the existing
    // `is_zerodentity_local_signed_write` carve-out for 0dentity attest/delete.
    //
    // These tests build the SAME middleware stack production uses (avc_router
    // wrapped in `require_bearer_on_writes`, not a bare handler call) so they
    // prove something about the wired stack, not just the handler in
    // isolation.
    fn avc_router_with_bearer_gate(state: Arc<AvcApiState>) -> Router {
        let auth = crate::auth::BearerAuth {
            token: Arc::new(zeroize::Zeroizing::new("vcg-006a-admin-token".to_string())),
        };
        let scoped_auth =
            crate::auth::ScopedBearerAuth::livesafe_public_adapter_output_authorization(
                zeroize::Zeroizing::new("livesafe-public-output-scoped-token".to_string()),
            );
        avc_router(state).layer(axum::middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            let scoped_auth = scoped_auth.clone();
            crate::auth::require_bearer_on_writes_with_scoped_bearers(auth, scoped_auth, req, next)
        }))
    }

    #[tokio::test]
    async fn avc_receipts_emit_accepts_subject_signature_without_bearer() {
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
            subject_signature: sign_action(&request, &subject_keypair()),
            validation: request,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                // Deliberately NO Authorization header — only a valid subject
                // Ed25519 signature over the action authorizes this write.
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
            "a request bearing a valid subject Ed25519 signature over the action must be \
             admitted through the production require_bearer_on_writes gate without an admin \
             bearer token, mirroring the existing is_zerodentity_local_signed_write carve-out"
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn avc_receipts_emit_lynk_accepts_subject_signature_without_bearer() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );

        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let response = post_lynk_emit_request(app, &request).await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a LYNK receipt request with a genuine subject signature must be admitted through \
             the production bearer gate without an admin bearer token"
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 1);
    }

    #[tokio::test]
    async fn avc_receipts_emit_still_rejects_unsigned_without_bearer() {
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
        // No genuine subject signature (empty signature, no admin bearer
        // token) — this must NOT be admitted. Proves the carve-out only
        // exempts genuinely subject-signed emits and never opens an
        // unauthenticated hole.
        let body = serde_json::to_vec(&EmitReceiptRequest {
            subject_signature: Signature::empty(),
            validation: request,
            subject_public_key: None,
        })
        .unwrap();

        let app = avc_router_with_bearer_gate(Arc::clone(&state));
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
            StatusCode::UNAUTHORIZED,
            "an unsigned write with no admin bearer token must still be rejected by the \
             production require_bearer_on_writes gate"
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }

    #[tokio::test]
    async fn avc_receipts_emit_lynk_still_rejects_unsigned_without_bearer() {
        let state = fresh_state();
        let credential = lynk_credential();
        state
            .registry
            .lock()
            .unwrap()
            .put_credential(credential.clone())
            .unwrap();
        let mut request = lynk_emit_request_for_evidence(
            credential,
            lynk_usage_evidence(LlmUsageCustodyMode::ReceiptMinimized),
        );
        request.subject_signature = Signature::empty();

        let app = avc_router_with_bearer_gate(Arc::clone(&state));
        let response = post_lynk_emit_request(app, &request).await;

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a LYNK receipt request with no admin bearer and no genuine subject signature must \
             stay outside the carve-out"
        );
        assert_eq!(state.registry.lock().unwrap().receipt_count(), 0);
    }
}

#[cfg(test)]
mod avc_root_trust_tests {
    use exo_authority::permission::Permission;
    use exo_avc::{
        AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel, AvcConstraints, AvcDraft,
        AvcRegistryDurableState, AvcRegistryRead, AvcRevocationReason, AvcSubjectKind,
        DelegatedIntent, issue_avc, revoke_avc,
    };

    use super::*;

    fn avc_state_for_root_trust_test() -> AvcApiState {
        let signer: AvcReceiptSigner = Arc::new(|_| Signature::empty());
        AvcApiState::new(
            Did::new("did:exo:test-validator").expect("test DID"),
            signer,
        )
    }

    fn avc_state_with_registry(registry: InMemoryAvcRegistry) -> AvcApiState {
        let signer: AvcReceiptSigner = Arc::new(|_| Signature::empty());
        AvcApiState {
            registry: Arc::new(Mutex::new(registry)),
            validator_did: Did::new("did:exo:test-validator").expect("test DID"),
            receipt_signer: signer,
            external_timestamp_source: AvcReceiptExternalTimestampSource::Unconfigured,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: false,
            finality_store: None,
            durability: AvcRegistryDurability::None,
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
        }
    }

    fn avc_state_with_unreachable_postgres() -> AvcApiState {
        let signer: AvcReceiptSigner = Arc::new(|_| Signature::empty());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://exochain:test@127.0.0.1:1/exochain_test")
            .expect("unreachable Postgres pool");
        AvcApiState {
            registry: Arc::new(Mutex::new(InMemoryAvcRegistry::new())),
            validator_did: Did::new("did:exo:test-validator").expect("test DID"),
            receipt_signer: signer,
            external_timestamp_source: AvcReceiptExternalTimestampSource::Unconfigured,
            receipt_clock: Arc::new(Mutex::new(HybridClock::new())),
            require_external_timestamp: false,
            finality_store: None,
            durability: AvcRegistryDurability::Postgres(pool),
            authority: Arc::new(Mutex::new(
                exo_authority::delegation::DelegationRegistry::new(),
            )),
        }
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

    fn root_issuer_did() -> Did {
        Did::new(AVC_ROOT_TRUST_ISSUER_DID).expect("expected issuer DID")
    }

    fn forged_root_issuer_revocation_registry() -> InMemoryAvcRegistry {
        let issuer_did = root_issuer_did();
        let credential = issue_avc(
            AvcDraft {
                schema_version: AVC_SCHEMA_VERSION,
                issuer_did: issuer_did.clone(),
                principal_did: issuer_did.clone(),
                subject_did: Did::new("did:exo:agent").expect("agent DID"),
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
            },
            |_| Signature::from_bytes([0x41; 64]),
        )
        .expect("test credential");
        let credential_id = credential.id().expect("credential id");
        let forged_revocation = revoke_avc(
            credential_id,
            issuer_did,
            AvcRevocationReason::IssuerRevoked,
            Timestamp::new(1_100_000, 0),
            |_| Signature::from_bytes([0x42; 64]),
        )
        .expect("forged revocation");

        let mut durable_state = AvcRegistryDurableState::default();
        durable_state
            .credentials
            .insert(credential_id, credential.clone());
        durable_state
            .revocations
            .insert(credential_id, forged_revocation);
        InMemoryAvcRegistry::from_durable_state(durable_state)
            .expect("current durable structural checks accept forged signature")
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
        let expected_permissions = vec![
            Permission::Read,
            Permission::Write,
            Permission::Execute,
            Permission::Delegate,
        ];

        assert_eq!(registration.ceremony_id, AVC_ROOT_TRUST_CEREMONY_ID);
        assert_eq!(registration.issuer_did, expected_did);
        assert_eq!(registration.issuer_public_key, expected_public_key);
        assert_eq!(registration.granted_permissions, expected_permissions);

        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(
            registry.resolve_public_key(&expected_did),
            Some(expected_public_key)
        );
        assert_eq!(
            registry.resolve_issuer_permission_grant(&expected_did),
            Some(expected_permissions)
        );
    }

    #[tokio::test]
    async fn avc_root_trust_valid_bundle_requires_dagdb_receipt_before_registering_issuer() {
        let state = avc_state_with_unreachable_postgres();
        let error = load_root_trust_bundle_from_path(&state, &installed_bundle_path())
            .expect_err("valid bundle must not register without durable DAG DB receipt");
        assert!(
            error
                .to_string()
                .contains("failed to persist AVC root bundle DAG DB receipt"),
            "expected DAG DB receipt persistence failure, got: {error}"
        );

        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(registry.resolve_public_key(&root_issuer_did()), None);
        assert_eq!(
            registry.resolve_issuer_permission_grant(&root_issuer_did()),
            None
        );
    }

    #[test]
    fn avc_root_trust_loader_records_dagdb_receipt_after_verification_before_registry_commit() {
        let source = include_str!("avc.rs");
        let function_start = source
            .find("pub fn load_root_trust_bundle_from_path(")
            .expect("root bundle loader function present");
        let function_tail = &source[function_start..];
        let function_end = function_tail
            .find(
                "\n// ---------------------------------------------------------------------------",
            )
            .expect("root bundle loader section ends before response shapes");
        let loader_source = &function_tail[..function_end];
        let verification_position = loader_source
            .find("verify_current_or_pinned_legacy_avc_root_bundle(&bundle, expected_bundle_id)")
            .expect("root bundle verification call present");
        let receipt_position = loader_source
            .find("persist_verified_root_bundle_receipt(state, &bundle)")
            .expect("DAG DB root bundle receipt persistence call present");
        let registry_commit_position = loader_source
            .find("*registry = candidate;")
            .expect("root issuer registry commit present");

        assert!(
            verification_position < receipt_position,
            "root bundle DAG DB receipt must be recorded only after verification"
        );
        assert!(
            receipt_position < registry_commit_position,
            "root bundle DAG DB receipt must be recorded before the issuer registry commit"
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
        assert_eq!(
            registry.resolve_issuer_permission_grant(&expected_did),
            None
        );
    }

    #[tokio::test]
    async fn avc_root_trust_tamper_fails_before_dagdb_receipt_insert() {
        let mut bundle: RootTrustBundle =
            serde_json::from_slice(&std::fs::read(installed_bundle_path()).expect("read bundle"))
                .expect("parse bundle");
        bundle.transcript_hash = Hash256::from_bytes([42u8; 32]);
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        serde_json::to_writer(temp.as_file(), &bundle).expect("write tampered bundle");

        let state = avc_state_with_unreachable_postgres();
        let error = load_root_trust_bundle_from_path(&state, temp.path())
            .expect_err("tampered bundle must fail before DAG DB receipt insert");
        let message = error.to_string();
        assert!(
            message.contains("AVC root trust bundle verification failed"),
            "expected verification failure, got: {error}"
        );
        assert!(
            !message.contains("failed to persist AVC root bundle DAG DB receipt"),
            "tampered bundle must not reach DAG DB receipt persistence: {error}"
        );

        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(registry.resolve_public_key(&root_issuer_did()), None);
        assert_eq!(
            registry.resolve_issuer_permission_grant(&root_issuer_did()),
            None
        );
    }

    #[test]
    fn avc_root_trust_legacy_bundle_rejects_relabelled_signer_metadata() {
        let mut bundle: RootTrustBundle =
            serde_json::from_slice(&std::fs::read(installed_bundle_path()).expect("read bundle"))
                .expect("parse bundle");
        bundle.root_signature.signer_ids = vec![1, 2, 3, 4, 5, 6, 8];
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        serde_json::to_writer(temp.as_file(), &bundle).expect("write relabelled bundle");

        let state = avc_state_for_root_trust_test();
        let error = load_root_trust_bundle_from_path(&state, temp.path())
            .expect_err("legacy compatibility must not accept relabelled signer metadata");
        assert!(
            error.to_string().contains("signer metadata"),
            "expected signer metadata rejection, got: {error}"
        );

        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(registry.resolve_public_key(&root_issuer_did()), None);
        assert_eq!(
            registry.resolve_issuer_permission_grant(&root_issuer_did()),
            None
        );
    }

    #[test]
    fn avc_root_trust_bundle_loader_revalidates_loaded_durable_revocations() {
        let state = avc_state_with_registry(forged_root_issuer_revocation_registry());
        let error = load_root_trust_bundle_from_path(&state, &installed_bundle_path())
            .expect_err("forged durable revocation must fail closed after issuer key registration");
        assert!(
            error.to_string().contains("revocation signature"),
            "root trust startup must surface durable revocation signature validation failure: {error}"
        );

        let registry = state.registry.lock().expect("registry lock");
        assert_eq!(
            registry.resolve_public_key(&root_issuer_did()),
            None,
            "root trust issuer key registration must roll back when durable revocation validation fails"
        );
        assert_eq!(
            registry.resolve_issuer_permission_grant(&root_issuer_did()),
            None,
            "root trust issuer permission grant must roll back when durable revocation validation fails"
        );
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

// ---------------------------------------------------------------------------
// VCG-006b conformance tests — #736 (runtime issuer allow-list
// registration/rotation) and #734 (conformance-test-root feature source
// guard).
//
// `avc_issuer_registered_at_runtime_is_usable_without_restart` and
// `avc_issuer_registration_requires_real_authority` both exercise the real,
// D3-compliant `/api/v1/avc/issuers` route: registering (or rotating) an
// issuer succeeds ONLY when the request carries a genuine `exo-authority`
// DelegationRegistry-backed authority chain (granted via
// `AvcApiState::grant_issuer_registration_authority`, mirroring the pattern
// proven end-to-end in `avc_issuer_registration_authority_tests` below); a
// bare admin bearer token with no such chain must be rejected with
// `StatusCode::FORBIDDEN` and must never mutate the registry.
// `conformance_test_root_feature_does_not_alter_production_root_trust`
// (#734) proves the `conformance-test-root` Cargo feature only ADDS an
// alternate root-trust-constants path without altering the production
// `AVC_ROOT_TRUST_*` constants' compiled values when the feature is off.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod avc_issuer_conformance_tests {
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use exo_authority::{DelegateeKind, permission::Permission};
    use exo_avc::{
        AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel, AvcConstraints, AvcDraft,
        AvcSubjectKind, DelegatedIntent, issue_avc,
    };
    use exo_core::crypto::KeyPair;
    use tower::ServiceExt;

    use super::*;

    async fn read_body(response: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    const NEW_ISSUER_SEED: [u8; 32] = [0x77; 32];
    const LOCAL_VALIDATOR_SEED: [u8; 32] = [0x33; 32];

    fn new_issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(NEW_ISSUER_SEED).expect("valid seed")
    }

    fn new_issuer_did() -> Did {
        Did::new("did:exo:rotated-issuer").expect("valid DID")
    }

    fn validator_did() -> Did {
        Did::new("did:exo:validator").expect("valid DID")
    }

    /// Fresh `AvcApiState` local to this test module (the sibling `tests`
    /// module's `fresh_state` helper is private to that module).
    fn fresh_state() -> Arc<AvcApiState> {
        let validator_kp =
            KeyPair::from_secret_bytes(LOCAL_VALIDATOR_SEED).expect("valid validator seed");
        let signer: AvcReceiptSigner = Arc::new(move |payload: &[u8]| validator_kp.sign(payload));
        let state = AvcApiState::new(validator_did(), signer);
        Arc::new(state)
    }

    fn draft_for_issuer(issuer_did: Did) -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: issuer_did.clone(),
            principal_did: issuer_did,
            subject_did: Did::new("did:exo:agent").expect("agent DID"),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: None,
            },
            created_at: Timestamp::new(1_000_000, 0),
            expires_at: Some(Timestamp::new(2_000_000, 0)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([0xAB; 32]),
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

    fn issuer_router_with_bearer_gate(state: Arc<AvcApiState>) -> Router {
        let auth = crate::auth::BearerAuth {
            token: Arc::new(zeroize::Zeroizing::new("vcg-006b-admin-token".to_string())),
        };
        avc_router(state).layer(axum::middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            crate::auth::require_bearer_on_writes(auth, req, next)
        }))
    }

    /// #736(a): a brand-new issuer DID+public key, registered at runtime
    /// through the real, D3-compliant issuer allow-list endpoint, must be
    /// usable to issue and validate an AVC credential on the SAME running
    /// node — no restart, no gateway redeploy.
    ///
    /// Registration itself requires a genuine `exo-authority`
    /// DelegationRegistry-backed authority chain (D3 one-authority-model
    /// rule) — the same requirement its sibling test,
    /// `avc_issuer_registration_requires_real_authority`, proves is
    /// enforced when that chain is ABSENT. This test supplies a real chain
    /// (granted via `AvcApiState::grant_issuer_registration_authority`,
    /// mirroring `avc_issuer_registration_authority_tests`) so the two
    /// tests are logically consistent: registration without authority is
    /// rejected (403), and registration WITH genuine authority succeeds
    /// (200) and is immediately usable.
    #[tokio::test]
    async fn avc_issuer_registered_at_runtime_is_usable_without_restart() {
        let state = fresh_state();
        let issuer_did = new_issuer_did();
        let issuer_kp = new_issuer_keypair();
        let validator_kp =
            KeyPair::from_secret_bytes(LOCAL_VALIDATOR_SEED).expect("valid validator seed");

        // Seed trust for the issuer-registration delegator key resolution, exactly
        // as `issuer_registration_with_genuine_delegated_authority_succeeds`
        // does: the chain-verification resolver in
        // `verify_issuer_registration_authority` resolves each link's
        // delegator public key via the AVC registry's `resolve_public_key`.
        state
            .registry
            .lock()
            .unwrap()
            .put_public_key(validator_did(), validator_kp.public);

        // Grant real, signed, auditable authority from this node's validator
        // to the issuer DID — the D3-compliant way authority comes to
        // exist, as opposed to a bare bearer token.
        let now = Timestamp::new(1_000, 0);
        let expires = Timestamp::new(9_000_000, 0);
        state
            .grant_issuer_registration_authority(
                issuer_did.clone(),
                DelegateeKind::Human,
                &validator_kp.public,
                expires,
                &now,
                |payload| validator_kp.sign(payload),
            )
            .expect("grant issuer-registration authority");
        let chain = state
            .find_delegated_issuer_registration_chain(&issuer_did)
            .expect("delegated issuer-registration chain must be resolvable after granting");

        // Register the new issuer's DID + public key through the runtime
        // endpoint, presenting the genuine authority chain obtained above.
        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": chain,
            "granted_permissions": ["Read", "Write"],
        });
        let app = issuer_router_with_bearer_gate(Arc::clone(&state));
        let register_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-admin-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let register_status = register_response.status();
        if register_status != StatusCode::OK {
            let body = read_body(register_response).await;
            panic!(
                "expected OK registering an issuer with a genuine delegated authority \
                 chain, got {register_status}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        // Now issue a credential signed by the newly-registered issuer and
        // confirm it validates successfully on this same running instance —
        // proving the issuer is usable without a restart or redeploy.
        let credential = issue_avc(draft_for_issuer(issuer_did.clone()), |bytes| {
            issuer_kp.sign(bytes)
        })
        .expect("issue credential from newly registered issuer");

        let issue_app = issuer_router_with_bearer_gate(Arc::clone(&state));
        let issue_response = issue_app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-admin-token")
                    .body(Body::from(
                        serde_json::to_vec(&IssueRequest {
                            credential: credential.clone(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            issue_response.status(),
            StatusCode::OK,
            "issuing a credential from the newly-registered issuer must succeed"
        );

        let validate_request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let validate_app = issuer_router_with_bearer_gate(Arc::clone(&state));
        let validate_response = validate_app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-admin-token")
                    .body(Body::from(serde_json::to_vec(&validate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(validate_response.status(), StatusCode::OK);
        let body = read_body(validate_response).await;
        let result: AvcValidationResult =
            serde_json::from_slice(&body).expect("validation result body");
        assert_eq!(
            result.decision,
            AvcDecision::Allow,
            "a credential signed by an issuer registered at runtime (no restart) \
             must resolve its issuer key and validate successfully; decision \
             was {:?}",
            result.decision
        );
    }

    /// #736(b): the issuer registration endpoint must require real authority
    /// (an `exo-authority` DelegationRegistry-backed grant per D3's
    /// one-authority-model rule — GAP-REGISTRY.md D3, "Applies to VCG-007 and
    /// issue #736"), not merely the bare admin bearer token. A caller
    /// presenting only the admin bearer token (no delegated issuer-registration
    /// authority) must be rejected — this is the frozen counterpart to
    /// `avc_issuer_registered_at_runtime_is_usable_without_restart`, which
    /// proves the opposite: registration WITH a genuine authority chain
    /// succeeds.
    #[tokio::test]
    async fn avc_issuer_registration_requires_real_authority() {
        let state = fresh_state();
        let issuer_did = new_issuer_did();
        let issuer_kp = new_issuer_keypair();

        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
        });

        // Only the bare admin bearer token is presented — no delegated
        // issuer-registration authority (no DelegationRegistry grant/chain
        // evidence of any kind is attached to this request). Per D3, the
        // admin bearer token alone must NOT be sufficient authority to
        // register an issuer.
        let app = issuer_router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-admin-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // The endpoint must exist AND must reject this request specifically
        // because it lacks real delegated authority — StatusCode::FORBIDDEN,
        // the same signal `verify_bearer_header` uses for "authenticated
        // caller, insufficient authority" elsewhere in this crate. A bare
        // route-absence rejection (404 Not Found / 405 Method Not Allowed)
        // must NOT satisfy this assertion — that would be a false green for
        // the wrong reason, proving nothing about a real authority check.
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "issuer registration must be refused with FORBIDDEN specifically \
             because the request carries only the bare admin bearer token and \
             no real DelegationRegistry-backed authority grant (D3 \
             one-authority-model rule) — not merely because the route is \
             absent (got {}). The endpoint must not be an unauthenticated (or \
             under-authenticated) hole.",
            response.status()
        );
        assert_eq!(
            state
                .registry
                .lock()
                .unwrap()
                .resolve_public_key(&issuer_did),
            None,
            "an issuer registration lacking real delegated authority must never \
             mutate the registry"
        );
    }

    /// #734: a `conformance-test-root` Cargo feature must let hermetic
    /// conformance nodes swap in test root-trust constants, while a source
    /// guard proves the production `AVC_ROOT_TRUST_*` constants are referenced
    /// identically whether or not the feature is enabled — the feature may
    /// only ADD an alternate path, never replace or weaken the production
    /// constants' compiled values when off.
    ///
    /// Expected RED: `crates/exo-node/Cargo.toml` has no `conformance-test-root`
    /// feature entry yet, so this assertion fails today.
    #[test]
    fn conformance_test_root_feature_does_not_alter_production_root_trust() {
        let cargo_toml = include_str!("../Cargo.toml");
        assert!(
            cargo_toml.contains("conformance-test-root"),
            "crates/exo-node/Cargo.toml must declare a `conformance-test-root` \
             feature (#734); none exists yet"
        );

        let source = include_str!("avc.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("tests marker present");

        // The production root-trust constants must appear, verbatim, exactly
        // once each, regardless of whether `conformance-test-root` is
        // compiled in. A `#[cfg(feature = "conformance-test-root")]` swap that
        // replaces these definitions (rather than adding an alternate,
        // separately-named path) would change or duplicate these occurrences.
        let production_constants = [
            (
                "AVC_ROOT_TRUST_CEREMONY_ID",
                "pub const AVC_ROOT_TRUST_CEREMONY_ID: &str = \"avc-exo-ceremony-2026\";",
            ),
            (
                "AVC_ROOT_TRUST_BUNDLE_ID_HEX",
                &format!(
                    "pub const AVC_ROOT_TRUST_BUNDLE_ID_HEX: &str =\n    \"{AVC_ROOT_TRUST_BUNDLE_ID_HEX}\";"
                ),
            ),
            (
                "AVC_ROOT_TRUST_ISSUER_DID",
                &format!(
                    "pub const AVC_ROOT_TRUST_ISSUER_DID: &str = \"{AVC_ROOT_TRUST_ISSUER_DID}\";"
                ),
            ),
            (
                "AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX",
                &format!(
                    "pub const AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX: &str =\n    \"{AVC_ROOT_TRUST_ISSUER_PUBLIC_KEY_HEX}\";"
                ),
            ),
        ];

        for (label, needle) in production_constants {
            assert_eq!(
                production.matches(needle).count(),
                1,
                "production AVC_ROOT_TRUST constant {label} must appear exactly \
                 once, unconditionally (not behind a feature-gated swap) — the \
                 conformance-test-root feature (#734) must only ADD an \
                 alternate path, never replace the production constant's \
                 compiled value when the feature is off"
            );
        }

        // The conformance path, once it exists, must be additive: it should
        // be introduced under its own explicitly-named cfg attribute rather
        // than wrapping the production constants themselves in a feature
        // gate. This is a placeholder guard that will need the real
        // conformance constant names once #734 lands; it currently fails
        // because no such names exist yet.
        assert!(
            source.contains("cfg(feature = \"conformance-test-root\")"),
            "avc.rs must contain a cfg(feature = \"conformance-test-root\") \
             alternate path for conformance root-trust constants (#734); none \
             exists yet"
        );
    }
}

// ---------------------------------------------------------------------------
// VCG-006b additional GREEN coverage — #736 genuine-authority happy path.
//
// The frozen red-stage tests in `avc_issuer_conformance_tests` establish two
// invariants in isolation: (a) a runtime issuer-registration endpoint must
// exist and admit a properly-authorized registration, and (b) the bare
// admin bearer token alone must never be sufficient authority for that
// endpoint. This module adds the missing end-to-end proof that a request
// presenting a REAL `exo-authority` DelegationRegistry-backed grant (created
// via `AvcApiState::grant_issuer_registration_authority`, per D3) succeeds,
// closing the loop between those two invariants without touching either
// frozen test.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod avc_issuer_registration_authority_tests {
    use axum::{
        body::Body,
        http::{Method, Request},
    };
    use exo_authority::{DelegateeKind, permission::Permission};
    use exo_avc::{
        AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel, AvcConstraints, AvcDraft,
        AvcSubjectKind, DelegatedIntent, issue_avc,
    };
    use exo_core::crypto::KeyPair;
    use tower::ServiceExt;

    use super::*;

    async fn read_body(response: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }

    const VALIDATOR_SEED: [u8; 32] = [0x33; 32];
    const NEW_ISSUER_SEED: [u8; 32] = [0x77; 32];

    fn validator_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(VALIDATOR_SEED).expect("valid validator seed")
    }

    fn new_issuer_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(NEW_ISSUER_SEED).expect("valid issuer seed")
    }

    fn validator_did() -> Did {
        Did::new("did:exo:validator").expect("valid DID")
    }

    fn operator_did() -> Did {
        Did::new("did:exo:issuer-registration-operator").expect("valid DID")
    }

    fn new_issuer_did() -> Did {
        Did::new("did:exo:genuinely-authorized-issuer").expect("valid DID")
    }

    fn fresh_state() -> Arc<AvcApiState> {
        let validator_kp = validator_keypair();
        let signer: AvcReceiptSigner = Arc::new(move |payload: &[u8]| validator_kp.sign(payload));
        Arc::new(AvcApiState::new(validator_did(), signer))
    }

    fn router_with_bearer_gate(state: Arc<AvcApiState>) -> Router {
        let auth = crate::auth::BearerAuth {
            token: Arc::new(zeroize::Zeroizing::new(
                "vcg-006b-authority-test-token".to_string(),
            )),
        };
        avc_router(state).layer(axum::middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            crate::auth::require_bearer_on_writes(auth, req, next)
        }))
    }

    fn draft_for_issuer(issuer_did: Did) -> AvcDraft {
        AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: issuer_did.clone(),
            principal_did: issuer_did,
            subject_did: Did::new("did:exo:agent").expect("agent DID"),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: None,
            },
            created_at: Timestamp::new(1_000_000, 0),
            expires_at: Some(Timestamp::new(2_000_000, 0)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([0xCD; 32]),
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

    /// A request carrying a genuine `exo-authority` DelegationRegistry chain
    /// — granted via `grant_issuer_registration_authority` and resolved via
    /// `find_delegated_issuer_registration_chain`, exactly the operator-facing
    /// API a real deployment would use — succeeds, and the resulting issuer
    /// is immediately usable for issuance and validation without a restart.
    #[tokio::test]
    async fn issuer_registration_with_genuine_delegated_authority_succeeds() {
        let state = fresh_state();
        let validator_kp = validator_keypair();
        let issuer_did = new_issuer_did();
        let issuer_kp = new_issuer_keypair();

        // Seed trust for the operator's own delegator key resolution: the
        // chain-verification resolver in `verify_issuer_registration_authority`
        // resolves each link's delegator public key via the AVC registry's
        // `resolve_public_key`, so the validator's own key must be resolvable
        // there (mirrors how root trust bundles register the node's own
        // operational keys at startup).
        state
            .registry
            .lock()
            .unwrap()
            .put_public_key(validator_did(), validator_kp.public);

        // Grant real, signed, auditable authority from this node's validator
        // to the operator DID — the D3-compliant way authority comes to
        // exist, as opposed to a bare bearer token.
        let now = Timestamp::new(1_000, 0);
        let expires = Timestamp::new(9_000_000, 0);
        state
            .grant_issuer_registration_authority(
                issuer_did.clone(),
                DelegateeKind::Human,
                &validator_kp.public,
                expires,
                &now,
                |payload| validator_kp.sign(payload),
            )
            .expect("grant issuer-registration authority");

        let chain = state
            .find_delegated_issuer_registration_chain(&issuer_did)
            .expect("delegated issuer-registration chain must be resolvable after granting");

        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": chain,
            "granted_permissions": ["Read", "Write"],
        });
        let app = router_with_bearer_gate(Arc::clone(&state));
        let register_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = register_response.status();
        if status != StatusCode::OK {
            let body = read_body(register_response).await;
            panic!(
                "expected OK registering an issuer with genuine delegated authority, got {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        let credential = issue_avc(draft_for_issuer(issuer_did.clone()), |bytes| {
            issuer_kp.sign(bytes)
        })
        .expect("issue credential from newly registered issuer");

        let issue_app = router_with_bearer_gate(Arc::clone(&state));
        let issue_response = issue_app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issue")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(
                        serde_json::to_vec(&IssueRequest {
                            credential: credential.clone(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(issue_response.status(), StatusCode::OK);

        let validate_request = AvcValidationRequest {
            credential,
            action: None,
            now: Timestamp::new(1_500_000, 0),
        };
        let validate_app = router_with_bearer_gate(Arc::clone(&state));
        let validate_response = validate_app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/validate")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&validate_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(validate_response.status(), StatusCode::OK);
        let body = read_body(validate_response).await;
        let result: AvcValidationResult =
            serde_json::from_slice(&body).expect("validation result body");
        assert_eq!(result.decision, AvcDecision::Allow);
    }

    #[tokio::test]
    async fn issuer_registration_authority_verifies_against_startup_validator_key_set() {
        let state = fresh_state();
        let validator_kp = validator_keypair();
        let issuer_did = new_issuer_did();
        let issuer_kp = new_issuer_keypair();

        state
            .register_validator_public_keys([(validator_did(), validator_kp.public)])
            .expect("startup validator public keys register");

        let now = Timestamp::new(1_000, 0);
        let expires = Timestamp::new(9_000_000, 0);
        state
            .grant_issuer_registration_authority(
                issuer_did.clone(),
                DelegateeKind::Human,
                &validator_kp.public,
                expires,
                &now,
                |payload| validator_kp.sign(payload),
            )
            .expect("grant issuer-registration authority");
        let chain = state
            .find_delegated_issuer_registration_chain(&issuer_did)
            .expect("delegated issuer-registration chain must be exportable");

        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": chain,
            "granted_permissions": ["Read", "Write"],
        });
        let app = router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        if status != StatusCode::OK {
            let body = read_body(response).await;
            panic!(
                "expected startup validator key set to verify issuer-registration authority, got {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
    }

    /// A chain that verifies cryptographically but was never actually
    /// granted through this node's own `exo-authority` DelegationRegistry
    /// must be rejected — proving `find_chain` cross-checking (not merely
    /// signature verification) is load-bearing.
    #[tokio::test]
    async fn issuer_registration_rejects_chain_never_granted_by_this_node() {
        let state = fresh_state();
        let validator_kp = validator_keypair();
        let issuer_did = new_issuer_did();
        let issuer_kp = new_issuer_keypair();

        state
            .registry
            .lock()
            .unwrap()
            .put_public_key(validator_did(), validator_kp.public);

        // Build a syntactically valid link and chain out of band — signed
        // correctly, but never recorded via
        // `grant_issuer_registration_authority`, so it exists nowhere in
        // `state.authority`.
        let mut registry = exo_authority::delegation::DelegationRegistry::new();
        let link = registry
            .delegate(
                exo_authority::delegation::DelegationGrant {
                    from: &validator_did(),
                    to: &operator_did(),
                    scope: &[Permission::Govern],
                    expires: Timestamp::new(9_000_000, 0),
                    now: &Timestamp::new(1_000, 0),
                    parent_link_id: None,
                    delegatee_kind: DelegateeKind::Human,
                    delegator_public_key: &validator_kp.public,
                },
                |payload| validator_kp.sign(payload),
            )
            .expect("out-of-band grant construction");
        let fabricated_chain = exo_authority::AuthorityChain {
            links: vec![link],
            max_depth: exo_authority::chain::DEFAULT_MAX_DEPTH,
        };

        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": fabricated_chain,
        });
        let app = router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            state
                .registry
                .lock()
                .unwrap()
                .resolve_public_key(&issuer_did),
            None
        );
    }

    fn state_with_granted_operator() -> (Arc<AvcApiState>, exo_authority::AuthorityChain) {
        let state = fresh_state();
        let validator_kp = validator_keypair();
        state
            .registry
            .lock()
            .unwrap()
            .put_public_key(validator_did(), validator_kp.public);
        let now = Timestamp::new(1_000, 0);
        let expires = Timestamp::new(9_000_000, 0);
        state
            .grant_issuer_registration_authority(
                operator_did(),
                DelegateeKind::Human,
                &validator_kp.public,
                expires,
                &now,
                |payload| validator_kp.sign(payload),
            )
            .expect("grant issuer-registration authority");
        let chain = state
            .find_delegated_issuer_registration_chain(&operator_did())
            .expect("chain resolvable after grant");
        (state, chain)
    }

    #[tokio::test]
    async fn issuer_registration_rejects_empty_permission_cap() {
        let (state, chain) = state_with_granted_operator();
        let issuer_did = operator_did();
        let issuer_kp = new_issuer_keypair();
        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": chain,
            "granted_permissions": [],
        });
        let app = router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            state
                .registry
                .lock()
                .unwrap()
                .resolve_public_key(&issuer_did),
            None,
            "a rejected registration must not register the key"
        );
    }

    #[tokio::test]
    async fn issuer_registration_rejects_authority_chain_leaf_that_differs_from_issuer_did() {
        let (state, chain) = state_with_granted_operator();
        let issuer_did = new_issuer_did();
        let issuer_kp = new_issuer_keypair();
        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": chain,
            "granted_permissions": ["Read", "Write"],
        });
        let app = router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            state
                .registry
                .lock()
                .unwrap()
                .resolve_public_key(&issuer_did),
            None,
            "a rejected issuer/authority leaf mismatch must not register the key"
        );
    }

    #[tokio::test]
    async fn issuer_registration_applies_permission_cap() {
        let (state, chain) = state_with_granted_operator();
        let issuer_did = operator_did();
        let issuer_kp = new_issuer_keypair();
        let register_body = serde_json::json!({
            "issuer_did": issuer_did.to_string(),
            "public_key_hex": hex::encode(issuer_kp.public.as_bytes()),
            "authority_chain": chain,
            "granted_permissions": ["Read", "Write"],
        });
        let app = router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/issuers")
                    .header("content-type", "application/json")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::from(serde_json::to_vec(&register_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            state
                .registry
                .lock()
                .unwrap()
                .resolve_issuer_permission_grant(&issuer_did),
            Some(vec![Permission::Read, Permission::Write]),
            "the registered issuer must be capped to exactly the granted permissions"
        );
    }

    #[tokio::test]
    async fn issuer_registration_authority_chain_export_returns_granted_chain() {
        let (state, chain) = state_with_granted_operator();
        let app = router_with_bearer_gate(Arc::clone(&state));
        let uri = format!(
            "/api/v1/avc/issuer-registration-authority?operator_did={}",
            operator_did()
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_body(response).await;
        let exported: exo_authority::AuthorityChain =
            serde_json::from_slice(&body).expect("export body is an AuthorityChain");
        assert_eq!(exported, chain);
    }

    #[tokio::test]
    async fn issuer_registration_authority_chain_export_requires_operator_did() {
        let (state, _chain) = state_with_granted_operator();
        let app = router_with_bearer_gate(Arc::clone(&state));
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/avc/issuer-registration-authority")
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn issuer_registration_authority_chain_export_absent_grant_is_not_found() {
        let state = fresh_state();
        let app = router_with_bearer_gate(Arc::clone(&state));
        let uri = format!(
            "/api/v1/avc/issuer-registration-authority?operator_did={}",
            operator_did()
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header("Authorization", "Bearer vcg-006b-authority-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn issuer_registration_authority_chain_export_requires_bearer() {
        let (state, _chain) = state_with_granted_operator();
        let app = router_with_bearer_gate(Arc::clone(&state));
        let uri = format!(
            "/api/v1/avc/issuer-registration-authority?operator_did={}",
            operator_did()
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
